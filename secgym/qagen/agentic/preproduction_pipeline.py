# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Bounded, source-bound candidate stages; completed roles are never resampled."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager, ExitStack
import fcntl
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time
from typing import Literal, TypeVar
import zipfile

import mysql.connector as mysql_connector
import sqlglot
from sqlglot import exp

from .canonical_facts import (
    CanonicalFactReview, SourceFactProposal, SourceFactResolver, canonical_fact_footprint,
)
from .contracts import (
    Contract, Digest, EvaluationRecord, PublicCitation, QualifiedWitnessProgram, TaskRecord, Text,
    ValidationReport, fingerprint,
)
from .difficulty_curation import _restore_inspections, curate_difficulty
from .evidence import EvidenceVerifier, Finding
from .fact_curation import CURATION_VERSION, CURATOR_INSTRUCTIONS, REVIEWER_INSTRUCTIONS, FactInspectionTools
from .footprints import build_unit_footprints
from .generation import BlindSolution, DiscoveryTools, RoleAbstained, TaskDraft, run_role
from .grading_review import ReviewedEvidenceVerifier, load_reviewed_grading
from .ledger import file_sha256
from .model_panel import ConfiguredClient, _native_replay, captured_actions, immutable_json
from .pilot import BLIND_INSTRUCTIONS
from .pilot_evaluation import private_pilot_validation
from .preproduction import PreproductionPlan, configured_model_binding, locked_run, safe_unfinished_roles
from .preproduction_admission import (
    AdmissionFiles, FinalReview, NativeBinding, NativeStudentImport, NATIVE_RUNTIME_FILES, ObjectiveReview,
    admitted_receipts, admitted_task, native_import_artifacts, objective_inventory, record_admission,
    validate_admitted_contract_revision, validate_native_import,
)
from .preproduction_revisions import ORCHESTRATION_MODULES, _validate_repair, current_source, effective_runtime
from .quality import validate_quality_gate
from .query import PublicQueryEngine
from .question_splits import QuestionFiles, SplitInputs, load_questions
from .robustness import ROBUSTNESS_VERSION, RobustnessPlan, RobustnessReport, run_robustness, validate_plan_expectations
from .secrl_adapter import Submission
from .similarity import EvidenceFootprint


VERSION = "preproduction-candidate-pipeline-v1"
FACT_RUNTIME_FILES = (
    "canonical_facts.py", "fact_curation.py", "contracts.py", "evidence.py",
    "qualified_witnesses.py", "generation.py", "query.py",
)
T = TypeVar("T", bound=Contract)
ROBUSTNESS_AUTHOR_CONTEXT_KEYS = frozenset({
    "previous_plan", "previous_review", "revision_feedback", "revision_instructions", "recorded_task",
})


class StageResult(Contract):
    status: Literal["pass", "held"]
    reason: Text


class StageReceipt(Contract):
    result: StageResult
    artifacts_sha256: dict[str, Digest]


def _json_hashes(directory: Path, *, excluded: tuple[str, ...] = ()) -> dict[str, str]:
    return {str(path.relative_to(directory)): file_sha256(path)
            for path in sorted(directory.rglob("*.json")) if str(path.relative_to(directory)) not in excluded}


def _continuation(parent: Path, archive: Path, binding: dict, run: Path, pipeline_root: Path,
                  seen: frozenset[Path] = frozenset()) -> dict:
    parent, archive = parent.resolve(), archive.resolve()
    if parent.parent != pipeline_root.resolve() or parent in seen or not archive.is_relative_to(run.resolve()):
        raise ValueError("annotation continuation must use an acyclic, same-attempt parent and an owned runtime archive")
    report = json.loads((parent / "pipeline-report.json").read_bytes())
    old_binding = json.loads((parent / "binding.json").read_bytes())
    if report["artifacts_sha256"] != _json_hashes(parent, excluded=("pipeline-report.json",)):
        raise ValueError("held parent pipeline artifacts changed")
    prefixes = {
        "robustness": ("grading", "native", "baseline"),
        "canonical": ("grading", "native", "baseline", "robustness"),
        "difficulty": ("grading", "native", "baseline", "robustness", "canonical"),
    }
    held_stage = report.get("stage")
    if report["status"] != "held" or held_stage not in prefixes or report["task_fingerprint"] != binding["task_fingerprint"]:
        raise ValueError("annotation-only continuation requires a held supported annotation stage on the unchanged task")
    for key in ("version", "task_fingerprint", "plan_fingerprint", "source_outcome_fingerprint", "grading_policy_fingerprint"):
        if old_binding[key] != binding[key]:
            raise ValueError("annotation continuation changed task, source, model plan or grading policy")
    if old_binding.get("native_import") is not None:
        retained = NativeStudentImport.model_validate(old_binding["native_import"])
        if (retained.task_fingerprint, retained.plan_fingerprint) != (binding["task_fingerprint"], binding["plan_fingerprint"]) or (
            retained.source_artifacts_sha256 != native_import_artifacts(
                run, pipeline_root.parent.name, Path(retained.parent_pipeline),
                Path(retained.recorded_task), Path(retained.runtime_archive),
            )
        ):
            raise ValueError("annotation continuation's retained native dependencies changed")
    replaceable = {"preproduction_pipeline.py", "difficulty_curation.py",
                   *(ORCHESTRATION_MODULES - {"preproduction_admission.py"})}
    if held_stage == "robustness":
        replaceable.update(("robustness.py", "preproduction_admission.py"))
    if (run / "native-index-amendments").exists():
        from .preproduction_revisions import native_index_history
        plan = PreproductionPlan.model_validate_json((run / "plan.json").read_bytes())
        if len(native_index_history(plan, run)) > 1:
            replaceable.add("preproduction_admission.py")
    if any((run / "runtime-amendments").glob("*.json")):
        from .preproduction_revisions import EMPTY_ARRAY_AMENDMENT, RuntimeAmendment
        amendments = [RuntimeAmendment.model_validate_json(p.read_bytes())
                      for p in sorted((run / "runtime-amendments").glob("*.json"))]
        policies = {amendment.policy_version for amendment in amendments}
        if policies & {"preproduction-annotation-context-amendment-v2", EMPTY_ARRAY_AMENDMENT}:
            plan = PreproductionPlan.model_validate_json((run / "plan.json").read_bytes())
            approved = effective_runtime(plan, run)
            replaceable.update(("quality.py", "preproduction_admission.py"))
            if held_stage in ("robustness", "canonical") and EMPTY_ARRAY_AMENDMENT in policies:
                states = [plan.implementation_sha256, *(a.current_runtime_sha256 for a in amendments)]
                fact_modules = ("canonical_facts.py", "fact_curation.py")
                if any(binding["implementation_sha256"].get(name) != approved.get(name) for name in fact_modules) or not any(
                    all(old_binding["implementation_sha256"].get(name) == state.get(name) for name in fact_modules)
                    for state in states
                ):
                    raise ValueError("canonical continuation requires exact approved old and current producers")
                replaceable.update(("canonical_facts.py", "fact_curation.py"))
    protected = lambda values: {name: digest for name, digest in values.items() if name not in replaceable}
    if (old_binding["implementation_sha256"].keys() != binding["implementation_sha256"].keys()
        or protected(old_binding["implementation_sha256"]) != protected(binding["implementation_sha256"])):
        raise ValueError("annotation continuation cannot change protected generation, grading or curation kernels")
    with zipfile.ZipFile(archive) as saved:
        for name, digest in old_binding["implementation_sha256"].items():
            if hashlib.sha256(saved.read(name)).hexdigest() != digest:
                raise ValueError("parent runtime archive does not preserve its exact producer")
    previous = old_binding.get("continuation")
    if previous is not None:
        restored = _continuation(Path(previous["parent_pipeline"]), Path(previous["runtime_archive"]), binding,
                                 run, pipeline_root, seen | {parent})
        if restored != previous:
            raise ValueError("earlier annotation continuation provenance changed")
        paths = {name: restored["imported_stage_paths"].get(name, str(parent / name)) for name in prefixes[held_stage]}
    else:
        paths = {name: str(parent / name) for name in prefixes[held_stage]}
    for name in (*prefixes[held_stage], held_stage):
        directory = parent / name if name == held_stage else Path(paths[name])
        receipt_path = directory / "stage-receipt.json"
        receipt = StageReceipt.model_validate_json(receipt_path.read_bytes())
        if (file_sha256(receipt_path) != report["stage_receipts"][name]
            or receipt.artifacts_sha256 != _json_hashes(directory, excluded=("stage-receipt.json",))
            or receipt.result.status != ("held" if name == held_stage else "pass")):
            raise ValueError("annotation continuation must preserve verified completed stages and the original hold")
    return {
        "parent_pipeline": str(parent), "parent_report_sha256": file_sha256(parent / "pipeline-report.json"),
        "runtime_archive": str(archive), "runtime_archive_sha256": file_sha256(archive),
        "imported_stage_paths": paths,
    }


def _validate_plan_revision(previous: RobustnessPlan, revised: RobustnessPlan, *,
                            control_repairs: dict[str, str] | None = None) -> None:
    repairs = control_repairs or {}
    if set(repairs) - {case.case_id for case in previous.cases} or any(not reason.strip() for reason in repairs.values()):
        raise ValueError("control repairs require exact original case IDs and source-backed reasons")
    fixture_changed = previous.extra_source_records != revised.extra_source_records
    if previous.task_fingerprint != revised.task_fingerprint or (
        fixture_changed and (not repairs or not set(previous.extra_source_records) <= set(revised.extra_source_records))
    ):
        raise ValueError("a robustness annotation revision cannot change task or fixture membership")
    if fingerprint(previous) == fingerprint(revised):
        raise ValueError("a completed held robustness plan cannot be resampled unchanged")
    by_id = {case.case_id: case for case in revised.cases}
    if previous.policy_version != revised.policy_version and revised.policy_version != ROBUSTNESS_VERSION:
        raise ValueError("a robustness revision cannot downgrade measurement semantics")
    changed = (len(revised.cases) != len(previous.cases) or previous.policy_version != revised.policy_version
               or set(previous.extra_source_records) != set(revised.extra_source_records))
    for old in previous.cases:
        new = by_id.get(old.case_id)
        if new is None or new.scope != old.scope or (
            (new.edits, new.removed_records) != (old.edits, old.removed_records) and old.case_id not in repairs
        ):
            raise ValueError("a robustness annotation revision cannot remove or weaken the original interventions")
        changed |= (frozenset(new.edits), frozenset(new.removed_records)) != (frozenset(old.edits), frozenset(old.removed_records))
        changed |= {item.claim_id: item for item in new.expected} != {item.claim_id: item for item in old.expected}
        changed |= old.case_id in repairs and new.rationale != old.rationale
    if not changed:
        raise ValueError("a robustness revision must change expectations or add controls, not merely reword a held proposal")


def _context_fingerprint(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _executable_contract(task: TaskRecord) -> dict:
    claims = {"final": task.private_gold.final, **{c.checkpoint_id: c.claim for c in task.private_gold.checkpoints}}
    result = {}
    for name, claim in claims.items():
        result[name] = {}
        for kind, selected in (("answers", claim.programs), ("witnesses", claim.witness_programs)):
            programs = []
            for program in selected:
                data = program.model_dump(mode="json", exclude={"program_id"})
                for key in ("query", "obligations_query", "candidates_query"):
                    if key in data:
                        tree = sqlglot.parse_one(data[key], read=program.engine)
                        for node in tree.walk():
                            node.pop_comments()
                        data[key] = tree.sql(dialect=program.engine)
                programs.append(data)
            result[name][kind] = sorted(programs, key=lambda value: json.dumps(value, sort_keys=True))
    return result


class QualifiedSupportRecoveryApproval(Contract):
    policy_version: Literal["qualified-support-review-recovery-v1"] = "qualified-support-review-recovery-v1"
    plan_fingerprint: Digest
    task_fingerprint: Digest
    previous_request_sha256: Digest
    previous_review_sha256: Digest
    previous_plan_sha256: Digest
    diagnostic_report: Text
    diagnostic_report_sha256: Digest
    reason: Text
    approved: Literal[True]


def _recover_qualified_support_review(run: Path, previous: Path, output: Path, task: TaskRecord,
                                      matrix: RobustnessPlan, approval_path: Path) -> None:
    from .robustness import RUNTIME_FILES

    attempt = (run / "attempts" / task.task_id / "pipeline").resolve()
    if any(not path.resolve().is_relative_to(run.resolve()) for path in (previous, output, approval_path)) or (
        not previous.resolve().is_relative_to(attempt) or not output.resolve().is_relative_to(attempt)
        or previous.resolve() == output.resolve()
    ):
        raise ValueError("qualified-support recovery must stay inside its explicitly owned task and run")
    approval = QualifiedSupportRecoveryApproval.model_validate_json(approval_path.read_bytes())
    report_path = Path(approval.diagnostic_report).resolve()
    if not report_path.is_relative_to(run.resolve()) or file_sha256(report_path) != approval.diagnostic_report_sha256:
        raise ValueError("qualified-support diagnostic evidence changed or escaped its run")
    plan = PreproductionPlan.model_validate_json((run / "plan.json").read_bytes())
    request_path = previous / "reviewer/0000-request.json"
    if (approval.plan_fingerprint, approval.task_fingerprint, approval.previous_request_sha256,
        approval.previous_review_sha256, approval.previous_plan_sha256) != (
        fingerprint(plan), fingerprint(task), file_sha256(request_path),
        file_sha256(previous / "review.json"), file_sha256(previous / "proposed-plan.json"),
    ):
        raise ValueError("qualified-support approval does not bind the exact held task, review and plan")
    request = json.loads(request_path.read_bytes())
    context = json.loads(request["messages"][1]["content"])
    old = RobustnessPlan.model_validate_json((previous / "proposed-plan.json").read_bytes())
    review = FinalReview.model_validate_json((previous / "review.json").read_bytes())
    diagnostic = RobustnessReport.model_validate_json(report_path.read_bytes())
    if request["role"] != "robustness-reviewer" or matrix != old or matrix.task_fingerprint != fingerprint(task) or (
        review.recommendation != "revise" or review.task_fingerprint != fingerprint(task)
        or review.subject_fingerprint != fingerprint(matrix)
        or context["task_fingerprint"] != fingerprint(task)
        or context["subject_fingerprint"] != fingerprint(matrix)
        or RobustnessPlan.model_validate_json(json.dumps(context["plan"])) != matrix
        or "Qualified support additionally executes its obligations/candidates." not in context["measurement_semantics"]
    ):
        raise ValueError("qualified-support recovery requires the exact ambiguous prior support context and unchanged plan")
    expected_runtime = {name: file_sha256(Path(__file__).with_name(name)) for name in RUNTIME_FILES}
    if (diagnostic.task_fingerprint, diagnostic.plan_fingerprint, diagnostic.serving_view_id,
        diagnostic.policy_version, diagnostic.status, diagnostic.implementation_sha256) != (
        fingerprint(task), fingerprint(matrix), task.serving_view_id, ROBUSTNESS_VERSION, "pass", expected_runtime,
    ) or diagnostic.query_limits != plan.query_limits.model_copy(update={
        "timeout_ms": plan.grader_timeout_ms or plan.query_limits.timeout_ms,
    }) or diagnostic.cases_not_run or any(check.status != "pass" or check.observed is None for check in diagnostic.checks):
        raise ValueError("qualified-support recovery requires the unchanged passing actual backend diagnostic")
    claims = {"final": task.private_gold.final, **{c.checkpoint_id: c.claim for c in task.private_gold.checkpoints}}
    expected_checks = {(case, claim, engine) for case in ("baseline", *(c.case_id for c in matrix.cases))
                       for claim in claims for engine in ("duckdb", "mysql")}
    if len(diagnostic.checks) != len(expected_checks) or {
        (check.case_id, check.claim_id, check.engine) for check in diagnostic.checks
    } != expected_checks:
        raise ValueError("qualified-support diagnostic does not cover every case, claim and backend")
    counterexamples = []
    for check in diagnostic.checks:
        if check.case_id != "baseline" or check.observed is None or not any(
            isinstance(p, QualifiedWitnessProgram) for p in claims[check.claim_id].witness_programs
        ):
            continue
        if len(check.observed.support) != len(diagnostic.probes):
            raise ValueError("qualified-support diagnostic probe coverage changed")
        for index, (available, supported) in enumerate(zip(diagnostic.probes, check.observed.support)):
            if supported and not any(set(group.citations) <= set(available) for group in check.observed.witnesses):
                counterexamples.append({"engine": check.engine, "claim_id": check.claim_id, "probe_index": index})
    if {example["engine"] for example in counterexamples} != {"duckdb", "mysql"}:
        raise ValueError("qualified-support recovery needs actual counterexamples to representative containment on both backends")
    certificate = {
        "policy_version": approval.policy_version, "approval": str(approval_path.resolve()),
        "output": str(output.resolve()),
        "approval_sha256": file_sha256(approval_path), "task_fingerprint": fingerprint(task),
        "plan_fingerprint": fingerprint(matrix), "previous_request_sha256": file_sha256(request_path),
        "diagnostic_report_sha256": file_sha256(report_path), "counterexamples": counterexamples,
        "plan_changed": False, "student_calls": 0, "fresh_review_and_backend_measurement_required": True,
        "diagnostic_outcomes_supplied_to_reviewer": False,
    }
    with locked_run(run, wait=True):
        directory = run / "robustness-review-recoveries"
        directory.mkdir(mode=0o700, exist_ok=True)
        immutable_json(directory / (certificate["previous_request_sha256"] + ".json"), certificate)
        immutable_json(output / "review-only-recovery.json", certificate)


def robustness_review_context(context: dict, matrix: RobustnessPlan, previous: RobustnessPlan | None) -> dict:
    current = {key: value for key, value in context.items() if key not in ROBUSTNESS_AUTHOR_CONTEXT_KEYS}
    current.update(plan=matrix.model_dump(mode="json"), subject_fingerprint=fingerprint(matrix))
    if previous is not None:
        current["preserved_control_ids"] = [case.case_id for case in previous.cases]
        authorized = context.get("authorized_control_repairs", {})
        current["previous_authorized_interventions"] = [
            case.model_dump(mode="json", exclude={"expected"})
            for case in previous.cases if case.case_id in authorized
        ]
    return current


def _recover_contaminated_robustness_review(run: Path, previous: Path, output: Path, matrix: RobustnessPlan) -> None:
    if not previous.resolve().is_relative_to(run.resolve()) or not output.resolve().is_relative_to(run.resolve()):
        raise ValueError("review-only recovery must stay inside its owning run")
    request_path = previous / "reviewer/0000-request.json"
    request = json.loads(request_path.read_bytes())
    context = json.loads(request["messages"][1]["content"])
    prior = RobustnessPlan.model_validate_json((previous / "proposed-plan.json").read_bytes())
    review = FinalReview.model_validate_json((previous / "review.json").read_bytes())
    captured = RobustnessPlan.model_validate_json(json.dumps(context["plan"]))
    leaked = sorted(ROBUSTNESS_AUTHOR_CONTEXT_KEYS.intersection(context))
    if request["role"] != "robustness-reviewer" or not leaked or matrix != prior or captured != prior or (
        matrix.policy_version != ROBUSTNESS_VERSION or review.recommendation != "revise"
        or review.task_fingerprint != matrix.task_fingerprint or context.get("task_fingerprint") != matrix.task_fingerprint
        or review.subject_fingerprint != fingerprint(matrix) or context.get("subject_fingerprint") != fingerprint(matrix)
    ):
        raise ValueError("review-only recovery requires a proven contaminated review of the unchanged current-policy plan")
    recovery = {
        "policy_version": "contaminated-robustness-review-recovery-v1",
        "task_fingerprint": matrix.task_fingerprint, "plan_fingerprint": fingerprint(matrix),
        "previous_request_sha256": file_sha256(request_path), "previous_review_sha256": file_sha256(previous / "review.json"),
        "previous_plan_sha256": file_sha256(previous / "proposed-plan.json"),
        "removed_author_context_keys": leaked, "output": str(output.resolve()),
        "implementation_sha256": file_sha256(Path(__file__)),
        "plan_changed": False, "student_calls": 0, "fresh_review_and_backend_measurement_required": True,
    }
    with locked_run(run, wait=True):
        directory = run / "robustness-review-recoveries"
        directory.mkdir(mode=0o700, exist_ok=True)
        immutable_json(directory / (recovery["previous_request_sha256"] + ".json"), recovery)
        immutable_json(output / "review-only-recovery.json", recovery)


def run_stage(directory: Path, binding: dict, action: Callable[[Path], StageResult]) -> StageResult:
    """A completed hold is as immutable as a pass; an interrupted stage retains all artifacts."""
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    immutable_json(directory / "stage-binding.json", binding)
    destination = directory / "stage-receipt.json"
    if destination.exists():
        receipt = StageReceipt.model_validate_json(destination.read_bytes())
        if receipt.artifacts_sha256 != _json_hashes(directory, excluded=("stage-receipt.json",)):
            raise ValueError("completed pipeline stage artifacts changed")
        return receipt.result
    try:
        result = StageResult.model_validate(action(directory))
    except RoleAbstained as error:
        result = StageResult(status="held", reason="Recorded role abstention: " + str(error))
    except (ValueError, RuntimeError, OSError) as error:
        errors = directory / "errors"
        errors.mkdir(exist_ok=True)
        sequence = len(list(errors.glob("*.json")))
        immutable_json(errors / f"{sequence:04d}.json", {
            "status": "operational_error", "error_type": type(error).__name__, "detail": str(error),
            "retry_requires_exact_binding_and_safe_role_boundary": True,
        })
        raise
    immutable_json(destination, StageReceipt(
        result=result, artifacts_sha256=_json_hashes(directory, excluded=("stage-receipt.json",)),
    ))
    return result


def inspected_role(client: ConfiguredClient, verifier: EvidenceVerifier, directory: Path, role: str,
                   instructions: str, context: dict, response_type: type[T],
                   validate: Callable[[T, FactInspectionTools], None]) -> T:
    tools = FactInspectionTools(SourceFactResolver(verifier))
    if directory.exists():
        safe_unfinished_roles(directory)
        _restore_inspections(tools, directory)
    return run_role(client, tools, role, instructions, context, response_type, directory,
                    resume=directory.exists(), validate_result=lambda value: validate(value, tools))


def _citations(task: TaskRecord) -> frozenset[PublicCitation]:
    return frozenset(PublicCitation(table=ref.table, record_id=ref.public_record_id) for ref in task.evidence)


def _native_student_roots(plan: PreproductionPlan, task: TaskRecord, run: Path, native: Path) -> set[Path]:
    roots = {(native / "student").resolve()}
    certificate = native / "retained-student.json"
    if certificate.exists():
        retained = NativeStudentImport.model_validate_json(certificate.read_bytes())
        validate_native_import(retained, plan, task, run)
        roots.add((Path(retained.parent_pipeline) / "native/student").resolve())
    return roots


def _review_validator(task: TaskRecord, subject: str, required: frozenset[PublicCitation]):
    def validate(value: FinalReview, tools: FactInspectionTools) -> None:
        if (value.task_fingerprint, value.subject_fingerprint) != (fingerprint(task), subject):
            raise ValueError("review binds a different task or subject")
        if value.recommendation == "pass" and required - tools.observed:
            raise ValueError("a passing reviewer must inspect all required actual source records")
    return validate


def contract_proof_diagnostics(task: TaskRecord, source: EvidenceVerifier) -> dict:
    proofs = source.preflight(task)
    claims = {"final": task.private_gold.final, **{c.checkpoint_id: c.claim for c in task.private_gold.checkpoints}}
    diagnostics = {}
    for name, claim in claims.items():
        qualified = any(isinstance(p, QualifiedWitnessProgram) for p in claim.witness_programs)
        available = frozenset().union(*proofs[name])
        ordered = tuple(sorted(available, key=lambda c: (c.table, c.record_id)))
        probes = []
        for omitted in (None, *ordered):
            selected = available if omitted is None else available - {omitted}
            finding = Finding(answer=claim.expected, citations=tuple(sorted(selected, key=lambda c: (c.table, c.record_id))), step=0)
            accepted = source.evidence_matches(finding, proofs[name], claim=claim)
            observed = source.complete_witness_observed(claim, proofs[name], selected)
            probes.append({
                "omitted": omitted.model_dump(mode="json") if omitted is not None else None,
                "accepted_by_actual_verifier": accepted,
                "complete_proof_observed": observed,
                "rejection_category": "qualified_citation_relevance" if qualified and selected and observed and not accepted else None,
            })
        diagnostics[name] = {
            "diagnostic_policy_version": "actual-proof-observation-and-relevance-v2",
            "witness_policy": "source-qualified-obligations-v1" if qualified else "enumerated",
            "requires_behavior_or_security_control": claim.requires_behavior_evidence,
            "representative_proofs": [
                [c.model_dump(mode="json") for c in sorted(group, key=lambda c: (c.table, c.record_id))]
                for group in proofs[name]
            ],
            "omission_probes": probes,
            "all_possible_equivalent_proofs_enumerated": False,
        }
    return diagnostics


def native_text_semantics(plan: PreproductionPlan, task: TaskRecord, native: EvidenceVerifier) -> dict:
    if native.engine.engine != "mysql" or native.engine.serving_view_id != task.serving_view_id or (
        task.serving_view_id != plan.serving_view_id or plan.native_snapshot_sha256 is None
    ):
        raise ValueError("native text metadata requires the exact verified MySQL snapshot")
    tables = set()
    for claim in (task.private_gold.final, *(c.claim for c in task.private_gold.checkpoints)):
        for program in (*claim.programs, *claim.witness_programs):
            if program.engine != "mysql":
                continue
            queries = [program.query]
            if isinstance(program, QualifiedWitnessProgram):
                queries.extend((program.obligations_query, program.candidates_query))
            for query in queries:
                tables.update(table.name for table in sqlglot.parse_one(query, read="mysql").find_all(exp.Table)
                              if table.name in native.tables)
    if not tables:
        raise ValueError("native text metadata requires actual public source tables")
    cursor = native.engine.connection.cursor()
    try:
        placeholders = ",".join("%s" for _ in tables)
        cursor.execute(
            "SELECT c.TABLE_NAME,c.COLUMN_NAME,c.COLLATION_NAME,k.PAD_ATTRIBUTE "
            "FROM information_schema.COLUMNS c JOIN information_schema.COLLATIONS k "
            "ON k.COLLATION_NAME=c.COLLATION_NAME WHERE c.TABLE_SCHEMA=DATABASE() "
            f"AND c.TABLE_NAME IN ({placeholders}) ORDER BY c.TABLE_NAME,c.COLUMN_NAME",
            tuple(sorted(tables)),
        )
        rows = cursor.fetchall()
    finally:
        cursor.close()
    columns: dict[str, dict[str, list[str]]] = {}
    for row in rows:
        if len(row) != 4 or any(not isinstance(value, str) for value in row) or row[0] not in tables:
            raise ValueError("native physical text metadata is malformed or out of scope")
        table, column, collation, padding = row
        columns.setdefault(table, {}).setdefault(f"{collation} / {padding}", []).append(column)
    if set(columns) != tables:
        raise ValueError("native physical text metadata is incomplete")
    return {
        "policy_version": "native-physical-text-semantics-v1", "task_fingerprint": fingerprint(task),
        "plan_fingerprint": fingerprint(plan), "serving_view_id": task.serving_view_id,
        "native_snapshot_sha256": plan.native_snapshot_sha256, "physical_text_columns": columns,
        "scope": "Actual physical public table columns only. JSON_TABLE outputs and computed expressions do not "
                 "automatically inherit these collations. Metadata inspection is not answer-program execution.",
    }


def _validate_native_text_context(task: TaskRecord, native_context: dict | None) -> None:
    if native_context is not None and (
        native_context.get("task_fingerprint") != fingerprint(task)
        or native_context.get("serving_view_id") != task.serving_view_id
        or native_context.get("policy_version") != "native-physical-text-semantics-v1"
    ):
        raise ValueError("native review context belongs to another task or snapshot")


def review_contract(task: TaskRecord, source: EvidenceVerifier, client: ConfiguredClient, output: Path,
                    policy_directory: Path | None, *, native_context: dict | None = None) -> StageResult:
    _validate_native_text_context(task, native_context)
    if native_context is not None:
        immutable_json(output / "native-text-semantics.json", native_context)
    if policy_directory is not None:
        policy = load_reviewed_grading(policy_directory)
        if policy.policy.task_fingerprint != fingerprint(task):
            raise ValueError("reviewed grading policy belongs to another task")
        immutable_json(output / "review.json", FinalReview(
            task_fingerprint=fingerprint(task), subject_fingerprint=fingerprint(policy), recommendation="pass",
            reviewer="source-reviewed-policy-and-reflection",
            reasons=(*policy.reviewer.reasons, *policy.reflection.reasons),
        ))
        return StageResult(status="pass", reason="Task-bound source review and reflection passed.")
    subject = fingerprint(task.private_gold)
    diagnostics = contract_proof_diagnostics(task, source)
    immutable_json(output / "proof-diagnostics.json", diagnostics)
    context = {
        "task": task.model_dump(mode="json"), "task_fingerprint": fingerprint(task), "subject_fingerprint": subject,
        "actual_verifier_diagnostics": diagnostics,
        "verified_native_text_semantics": native_context,
    }
    instructions = (
        "Independently inspect the actual source and audit the complete grading contract. Check public wording "
        "against every final/checkpoint answer and proof in both SQL dialects, identity/time/role bindings, "
        "complete collection coverage and exact recorded values. Checkpoints must be meaningful intermediate "
        "objectives, not unnecessary downstream obligations. Identify unfair rejection of genuinely equivalent "
        "proofs or relevant observed supporting context; do not broaden public scope or waive core evidence. "
        "Source-qualified optional context requires an explicit reviewed policy, not informal permission. "
        "The requires_behavior_evidence flag accepts either behavior OR security_control lineage; it does not "
        "require downstream behavior records when a checkpoint is already supported by security-control evidence. "
        "Use the actual verifier diagnostics: enumerated witnesses and source-qualified representative bundles "
        "have different acceptance semantics. Do not invent a mandatory representative union when qualified "
        "alternatives are already accepted. Distinguish complete_proof_observed from submitted-citation acceptance: "
        "qualified_citation_relevance identifies extra cited context absent from the returned candidate relevance, "
        "not absence of a complete positive proof. The frozen solver requires complete candidate bundles to be "
        "available; returning a whole source-required bundle does not credit uncited records. Candidate SQL that "
        "first suppresses all incomplete comparison bundles can incorrectly narrow source-bounded relevance. "
        "Review actual SQL and mixed-context controls before blaming the solver or relaxing completeness. "
        "These finite omission probes do not certify every possible alternative "
        "or establish absence/ranking completeness. Distinguish an observed rejection from the separate source "
        "proof needed to justify a proposed alternative. "
        "Use supplied verified native physical-column collations and padding rules, not generic MySQL defaults. "
        "Binary NO PAD physical text columns already enforce exact case/trailing-space comparisons and distinctness. "
        "Do not require redundant index-defeating BINARY casts on those columns. JSON-derived/computed values "
        "need their own exactness analysis; do not assume they inherit a physical column's collation. If native "
        "metadata is absent, state that uncertainty rather than assert a case-insensitive default as a fact. "
        "Return revise/reject for an actual defect and explain a source-backed repair; do not rewrite the task "
        "or award points by opinion. No student outcomes or desired difficulty bands are supplied."
    )
    reviews = []
    for role in ("reviewer", "reflection"):
        if reviews:
            context = {**context, "prior_review": reviews[0].model_dump(mode="json"),
                       "reflection_task": "Independently retrieve sources and challenge the prior reasoning, including missed defects."}
        reviews.append(inspected_role(client, source, output / role, "contract-" + role, instructions, context,
                                      FinalReview, _review_validator(task, subject, _citations(task))))
    passed = all(review.recommendation == "pass" for review in reviews)
    immutable_json(output / "review.json", FinalReview(
        task_fingerprint=fingerprint(task), subject_fingerprint=subject,
        recommendation="pass" if passed else "revise", reviewer="independent-contract-review-and-reflection",
        reasons=tuple(reason for review in reviews for reason in review.reasons),
    ))
    return StageResult(status="pass" if passed else "held", reason="; ".join(reason for review in reviews for reason in review.reasons))


def native_candidate(plan: PreproductionPlan, candidate: Path, task: TaskRecord, source: EvidenceVerifier,
                     mysql: EvidenceVerifier, student: PublicQueryEngine, client: ConfiguredClient,
                     output: Path, policy_directory: Path | None, serving_bundle: Path, *,
                     retained_student: NativeStudentImport | None = None, run: Path | None = None) -> StageResult:
    if plan.native_snapshot_sha256 is None or plan.native_indexes_sha256 is None:
        raise ValueError("native validation requires explicit snapshot and index bindings")
    from .preproduction_revisions import effective_native_plan
    execution_plan = effective_native_plan(plan, run) if run is not None else plan
    if retained_student is not None:
        if run is None or policy_directory is not None:
            raise ValueError("retained native import requires its owning run and unchanged default grader")
        validate_native_import(retained_student, plan, task, run)
        immutable_json(output / "retained-student.json", retained_student)
    elif (output / "retained-student.json").exists():
        raise ValueError("this native stage requires its explicit retained-student import; a new student is forbidden")
    validation = private_pilot_validation(candidate, source, mysql, require_source_quality=True)
    immutable_json(output / "private-pilot-validation.json", validation)
    if validation.pilot_blockers(task):
        return StageResult(status="held", reason="; ".join(validation.pilot_blockers(task)))
    immutable_json(output / "binding.json", NativeBinding(
        task_fingerprint=fingerprint(task), plan_fingerprint=fingerprint(plan), serving_view_id=task.serving_view_id,
        native_snapshot_sha256=plan.native_snapshot_sha256, native_indexes_sha256=execution_plan.native_indexes_sha256,
        model=plan.model, student_query_limits=student.limits, grader_query_limits=mysql.engine.limits,
        implementation_sha256={name: file_sha256(Path(__file__).with_name(name)) for name in NATIVE_RUNTIME_FILES},
    ))
    recorded_native = Path(retained_student.parent_pipeline) / "native" if retained_student is not None else output
    role = recorded_native / "student"
    terminal_path = recorded_native / "student-termination.json"
    if retained_student is not None and not terminal_path.is_file():
        raise ValueError("retained native termination is missing; a new student is forbidden")
    solved = None
    if terminal_path.exists():
        terminal = json.loads(terminal_path.read_bytes())
        if terminal["artifacts_sha256"] != _json_hashes(role):
            raise ValueError("retained native student trace changed")
        if terminal["status"] == "completed":
            solved = BlindSolution.model_validate_json((role / "result.json").read_bytes())
            if terminal["result_fingerprint"] != fingerprint(solved):
                raise ValueError("retained native solution changed")
        elif terminal["status"] != "abstained":
            raise ValueError("unknown retained native termination")
    else:
        reason = None
        if role.exists():
            safe_unfinished_roles(role)
        try:
            solved = run_role(client, DiscoveryTools(student, mysql.tables, record_findings=True),
                              "native-blind", BLIND_INSTRUCTIONS, task.public_task().model_dump(mode="json"),
                              BlindSolution, role, resume=role.exists())
        except RoleAbstained as error:
            reason = str(error)
        immutable_json(terminal_path, {
            "status": "completed" if solved is not None else "abstained", "reason": reason,
            "result_fingerprint": fingerprint(solved) if solved is not None else None,
            "artifacts_sha256": _json_hashes(role),
        })
    grading = mysql
    if policy_directory is not None:
        grading = ReviewedEvidenceVerifier(serving_bundle, mysql.engine, mysql.allowed_literals,
                                           task=task, amendment=load_reviewed_grading(policy_directory))
    attempts = output / "grading-attempts"
    attempts.mkdir(exist_ok=True)
    selected_path = output / "selected-replay.json"
    try:
        if selected_path.exists():
            selected = json.loads(selected_path.read_bytes())
            replay = attempts / selected["directory"]
            if not replay.resolve().is_relative_to(attempts.resolve()) or selected["artifacts_sha256"] != _json_hashes(replay):
                raise ValueError("selected captured native replay changed")
            evaluation = EvaluationRecord.model_validate_json(json.dumps(selected["evaluation"]))
            if evaluation.task_mismatches(task) or evaluation != EvaluationRecord.model_validate_json((replay / "evaluation.json").read_bytes()):
                raise ValueError("selected native evaluation belongs to another task")
        else:
            replay = attempts / f"{len(list(attempts.iterdir())):04d}"
            replay.mkdir(mode=0o700)
            evaluation = _native_replay(
                task, validation, grading, captured_actions(role),
                Submission(answer=solved.answer, citations=solved.citations) if solved is not None else None,
                replay, task.task_id + "-pipeline-native",
            )
            immutable_json(selected_path, {"directory": replay.name, "artifacts_sha256": _json_hashes(replay),
                                           "evaluation": evaluation.model_dump(mode="json")})
    finally:
        if grading is not mysql:
            grading.close()
    for filename in ("secrl.json", "acesevals.json"):
        immutable_json(output / filename, json.loads((replay / filename).read_bytes()))
    immutable_json(output / "evaluation_report.json", {
        "status": "private_pilot_completed", "task_fingerprint": fingerprint(task), "serving_view_id": task.serving_view_id,
        "candidate_checks_passed": True, "adapter_components_equal": True,
        "student_grounded_success": evaluation.grounded_final, "checkpoint_progress": evaluation.checkpoint_progress,
        "answer_correctness": evaluation.answer_correctness.score, "reward": evaluation.aggregate_reward,
        "student_abstained": solved is None, "retained_native_student": retained_student is not None,
        "release_approved": False,
    })
    return StageResult(status="pass", reason="Actual native validation and same-captured-result SecRL/ACE grading completed.")


def robustness_candidate(task: TaskRecord, source: EvidenceVerifier, client: ConfiguredClient,
                         output: Path, mysqld: Path, workdir: Path, *, revision_from: Path | None = None,
                         prepared_plan: Path | None = None, feedback: str | None = None,
                         recorded_task: TaskRecord | None = None,
                         control_repairs: dict[str, str] | None = None,
                         review_recovery: bool = False, run: Path | None = None,
                         qualified_support_recovery: Path | None = None,
                         native_context: dict | None = None) -> StageResult:
    _validate_native_text_context(task, native_context)
    if native_context is not None:
        immutable_json(output / "native-text-semantics.json", native_context)
    recovering_review = review_recovery or qualified_support_recovery is not None
    if review_recovery and qualified_support_recovery is not None:
        raise ValueError("one robustness review cannot use two recovery authorizations")
    if recovering_review and (
        run is None or revision_from is None or prepared_plan is None or recorded_task is not None or control_repairs
    ):
        raise ValueError("review-only recovery requires an exact held parent and prepared unchanged plan")
    proofs = source.preflight(task)
    references = _citations(task) | frozenset(c for groups in proofs.values() for group in groups for c in group)
    context = {
        "task": task.model_dump(mode="json"), "task_fingerprint": fingerprint(task),
        "source_fixture_citations": [c.model_dump(mode="json") for c in sorted(references, key=lambda c: (c.table, c.record_id))],
        "source_proofs": {key: [[c.model_dump(mode="json") for c in sorted(group, key=lambda c: (c.table, c.record_id))]
                               for group in groups] for key, groups in proofs.items()},
        "probe_order": "All fixture citations; empty; then all-minus-each-citation sorted by (table, record_id). "
                       "The fixture is source_fixture_citations union extra_source_records. Support tuples cover this exact order.",
        "required_policy_version": ROBUSTNESS_VERSION,
        "verified_native_text_semantics": native_context,
        "measurement_context_version": "witness-policy-specific-support-v1",
        "program_support_policies": {
            name: {
                "witness_policy": "source-qualified-obligations-v1" if any(
                    isinstance(p, QualifiedWitnessProgram) for p in claim.witness_programs
                ) else "enumerated",
                "representative_group_containment_required": not any(
                    isinstance(p, QualifiedWitnessProgram) for p in claim.witness_programs
                ),
                "requires_behavior_or_security_control": claim.requires_behavior_evidence,
            }
            for name, claim in (
                ("final", task.private_gold.final), *((c.checkpoint_id, c.claim) for c in task.private_gold.checkpoints)
            )
        },
        "measurement_semantics": (
            "Answers, witness-query rows, and available-citation support are measured separately. Citation probes "
            "change availability, NOT physical fixture records; only declared edits/removals mutate the source. "
            "For enumerated programs, support is raw witness-group containment in the available citations, plus "
            "the required behavior/security-control lineage condition. It does NOT certify that residual rows "
            "establish a valid interval, the original typed answer or final reward in the counterfactual world. "
            "A behavior-bearing residual group can therefore have true program support while the answer is null "
            "and the original claim is rejected. Qualified programs use a DIFFERENT support algorithm: execute "
            "the full-source obligation catalog and citation-qualified complete candidate bundles, then require "
            "every obligation within at least one alternative group, all selected bundle members and coherent "
            "bindings. Qualified support does NOT additionally require containment of an emitted representative "
            "witness-query group. The representative query's rows are a separate measurement, not an exhaustive "
            "catalog of qualified proofs. A valid qualified proof can survive omission of representative-only "
            "comparison context; do not invent that omitted row as an extra prerequisite. "
            "For a behavior-required claim, a detector/context-only residual group has false program support; "
            "its raw witness rows are still measured in a counterfactual. Behavior OR security_control lineage "
            "satisfies this flag. For qualified support, test lineage in the selected complete candidate proof, "
            "not merely in the separate representative query output. Baseline behavior requirements remain strict. "
            "Zero rows are a typed empty set/list for collection answers, not null. A single NULL row is a "
            "different result; check each answer program rather than coercing every collection null. "
            "A query may return remaining cohort witnesses even when no final answer exists. Do not falsely label "
            "that output empty. The actual EvidenceVerifier.claim_witnesses first requires the answer query to "
            "match typed gold before any witness is accepted; a null answer cannot receive grounded final success."
            " Use verified_native_text_semantics for actual physical-column comparisons, not generic MySQL "
            "defaults. Its collation/padding facts do not automatically apply to JSON_TABLE or computed values."
        ),
    }
    previous_plan = None
    if control_repairs is not None and revision_from is None:
        raise ValueError("control repairs require their exact prior plan")
    if recorded_task is not None:
        _validate_repair(recorded_task, task, True)
        if (recorded_task.public_task().model_dump(exclude={"revision_id"})
            != task.public_task().model_dump(exclude={"revision_id"}) or revision_from is None):
            raise ValueError("retained robustness controls require an equivalent public task and their prior plan")
        context["recorded_task"] = recorded_task.model_dump(mode="json")
    if revision_from is not None:
        if not feedback or not feedback.strip():
            raise ValueError("annotation revision requires explicit source-backed feedback")
        previous_plan = RobustnessPlan.model_validate_json((revision_from / "proposed-plan.json").read_bytes())
        previous_review = FinalReview.model_validate_json((revision_from / "review.json").read_bytes())
        previous_task_fingerprint = fingerprint(recorded_task or task)
        if (previous_plan.task_fingerprint, previous_review.task_fingerprint, previous_review.subject_fingerprint) != (
            previous_task_fingerprint, previous_task_fingerprint, fingerprint(previous_plan),
        ):
            raise ValueError("prior robustness proposal/review is unbound")
        context.update(previous_plan=previous_plan.model_dump(mode="json"),
                       previous_review=previous_review.model_dump(mode="json"), revision_feedback=feedback,
                       revision_instructions="Retain the task and every prior intervention. Correct annotation defects "
                                             "against the actual source and measurement semantics; prior feedback is fallible.")
        if control_repairs:
            context.update(
                authorized_control_repairs=control_repairs,
                control_repair_instructions="Only named original interventions or materially incorrect rationales "
                                            "may be corrected for the supplied source-backed defects. Correct prose "
                                            "without altering already-correct expectations. Retain every case and its scope. Add "
                                            "material controls as needed; source-backed fixture records may be added "
                                            "but none removed. Independently inspect all added records. The reviewer "
                                            "must assess whether corrected controls preserve their intended coverage.",
            )
    elif prepared_plan is not None:
        raise ValueError("prepared robustness annotations require an explicit held-plan revision")

    def validate_structure(value: RobustnessPlan):
        if value.task_fingerprint != fingerprint(task):
            raise ValueError("robustness proposal belongs to another task")
        if value.policy_version != ROBUSTNESS_VERSION:
            raise ValueError("fresh robustness annotations require the current explicitly versioned measurement policy")
        if previous_plan is not None:
            comparison = previous_plan if recorded_task is None else previous_plan.model_copy(update={
                "task_fingerprint": fingerprint(task),
            })
            if recovering_review:
                if value != comparison or file_sha256(prepared_plan) != file_sha256(revision_from / "proposed-plan.json"):
                    raise ValueError("review-only recovery cannot change the prior plan")
            elif recorded_task is not None and value == comparison and (
                _executable_contract(recorded_task) != _executable_contract(task)
            ):
                immutable_json(output / "retained-control-contract-revision.json", {
                    "policy_version": "retained-controls-executable-revision-v1",
                    "recorded_task_fingerprint": fingerprint(recorded_task), "task_fingerprint": fingerprint(task),
                    "previous_plan_fingerprint": fingerprint(previous_plan), "plan_fingerprint": fingerprint(value),
                    "previous_executable_contract": _context_fingerprint(_executable_contract(recorded_task)),
                    "current_executable_contract": _context_fingerprint(_executable_contract(task)),
                    "interventions_and_expectations_changed": False, "student_calls": 0,
                    "fresh_semantic_review_and_backend_measurement_required": True,
                })
            else:
                _validate_plan_revision(comparison, value, control_repairs=control_repairs)
        fixture = references | frozenset(value.extra_source_records)
        records, behavior = {}, set()
        for citation in fixture:
            lineage, fields = source.record_values(citation)
            records[citation] = fields
            if lineage in ("behavior", "security_control"):
                behavior.add(citation)
        validate_plan_expectations(task, value, proofs, records, frozenset(behavior))

    def validate_plan(value: RobustnessPlan, tools: FactInspectionTools):
        validate_structure(value)
        if (references | frozenset(value.extra_source_records)) - tools.observed:
            raise ValueError("robustness author must inspect every actual fixture record")

    if prepared_plan is not None:
        matrix = RobustnessPlan.model_validate_json(prepared_plan.read_bytes())
        validate_structure(matrix)
        for citation in references | frozenset(matrix.extra_source_records):
            source.record_values(citation)
        immutable_json(output / "prepared-plan-binding.json", {
            "source": str(prepared_plan.resolve()), "sha256": file_sha256(prepared_plan), "author_model_calls": 0,
        })
    else:
        matrix = inspected_role(
            client, source, output / "author", "robustness-author",
            "Create a finite, source-inspected robustness plan for the exact task. Cover meaningful invariance "
            "and negative controls for relevant JSON roles/order/representation, identity joins, public time bounds, "
            "ordered or complete collection answers and independent checkpoint objectives. Baseline automatically "
            "tests complete/empty/each-missing-record citation sets. Mutations alter finite source worlds, not the "
            "question's public goals. Declare correct typed answers, actual witness-query output and every support result "
            "for those worlds; do not preserve an original answer when its decisive input changes. Do not equate "
            "a surviving alternative with every answer program succeeding: scalar/baseline expectations apply to "
            "every program. When routes differ, use answer.by_program with every answer-program ID across both "
            "dialects and its exact typed answer or null. "
            "Do not confuse censored fixtures with proof of real-world absence/completeness. Never mutate record locators. "
            "Use only actual source-backed cells and extra records, and avoid impossible/no-op interventions. "
            "Explain scope and limitations; no student results or desired difficulty bands are supplied.",
            context, RobustnessPlan, validate_plan,
        )
    immutable_json(output / "proposed-plan.json", matrix)
    if review_recovery:
        _recover_contaminated_robustness_review(run, revision_from, output, matrix)
    elif qualified_support_recovery is not None:
        _recover_qualified_support_review(run, revision_from, output, task, matrix, qualified_support_recovery)
    review = inspected_role(
        client, source, output / "reviewer", "robustness-reviewer",
        "Independently retrieve all fixture source records and assess every declared counterfactual against "
        "the exact public final and checkpoint goals. Challenge vacuous controls, false invariances, omitted "
        "proof members, unjustified expected answer/witness/support values and conflation of clocks or roles. "
        "Check every program's expected answer, including null for a removed alternative; a surviving route "
        "does not make the other programs return an answer. "
        "Require material positive/negative controls for this task, but never demand universal completeness "
        "from finite fixtures. All/empty/each-omission citation probes also run on the baseline. This is a "
        "semantic plan review before backend results, not an instruction to manufacture passing tests. "
        "Review only the supplied current plan. Historical expectation arrays and prior reviewer verdicts are "
        "deliberately excluded. Apply the stated program-support algorithm; do not replace this measured quantity "
        "with semantic claim truth or grounded final success. If an actual witness-contract defect exists, "
        "identify that separately rather than inventing different numerical availability semantics.",
        robustness_review_context(context, matrix, previous_plan),
        FinalReview, _review_validator(task, fingerprint(matrix), references | frozenset(matrix.extra_source_records)),
    )
    immutable_json(output / "review.json", review)
    if review.recommendation != "pass":
        return StageResult(status="held", reason="; ".join(review.reasons))
    results = output / "measurements"
    results.mkdir(exist_ok=True)
    complete = output / "selected-measurement.json"
    if complete.exists():
        selected = json.loads(complete.read_bytes())
        directory = results / selected["directory"]
        if not directory.resolve().is_relative_to(results.resolve()):
            raise ValueError("selected robustness report escapes its owned directory")
        report = RobustnessReport.model_validate_json((directory / "report.json").read_bytes())
        if fingerprint(report) != selected["report_fingerprint"]:
            raise ValueError("selected robustness report changed")
    else:
        directory = results / f"{len(list(results.iterdir())):04d}"
        report = run_robustness(task, source, matrix, mysqld=mysqld, workdir=workdir, output=directory)
        immutable_json(complete, {"directory": directory.name, "report_fingerprint": fingerprint(report)})
    return StageResult(status="pass" if report.status == "pass" else "held",
                       reason="Actual backend robustness status: " + report.status)


def _canonical_abstention_extension(revision_from: Path, previous_binding: dict, output: Path) -> dict:
    from .preproduction import runtime_hashes
    from .preproduction_revisions import EMPTY_ARRAY_AMENDMENT, RuntimeAmendment

    parent = revision_from.parent
    report = json.loads((parent / "pipeline-report.json").read_bytes())
    if report.get("status") != "held" or report.get("stage") != "canonical" or (
        report.get("task_fingerprint") != previous_binding["task_fingerprint"]
        or output.resolve().parent.parent != parent.resolve().parent
        or output.resolve().parent == parent.resolve()
        or output.name != "canonical"
        or report["artifacts_sha256"] != _json_hashes(parent, excluded=("pipeline-report.json",))
    ):
        raise ValueError("canonical capability recovery requires an unchanged sealed canonical hold")
    abstention = json.loads((revision_from / "curator/abstention.json").read_bytes())
    if abstention.get("status") != "no_supported_result" or (revision_from / "curator/result.json").exists() or (
        previous_binding["curation_version"], CURATION_VERSION
    ) != ("source-fact-curation-v1.1", "source-fact-curation-v1.2"):
        raise ValueError("canonical capability recovery requires the original unsupported v1.1 annotation")
    roots = [root for root in parent.resolve().parents if (root / "plan.json").is_file() and (root / "attempts").is_dir()]
    if len(roots) != 1:
        raise ValueError("canonical capability recovery requires its exact owning run")
    run, = roots
    plan = PreproductionPlan.model_validate_json((run / "plan.json").read_bytes())
    approved = effective_runtime(plan, run)
    if approved != runtime_hashes():
        raise ValueError("canonical capability recovery requires the approved current producer")
    amendments = [RuntimeAmendment.model_validate_json(p.read_bytes())
                  for p in sorted((run / "runtime-amendments").glob("*.json"))]
    matches = [a for a in amendments if a.policy_version == EMPTY_ARRAY_AMENDMENT and all(
        previous_binding["implementation_sha256"].get(name) == a.previous_runtime_sha256.get(name)
        and approved.get(name) == a.current_runtime_sha256.get(name)
        for name in ("canonical_facts.py", "fact_curation.py")
    )]
    if len(matches) != 1:
        raise ValueError("canonical capability recovery lacks its exact additive producer amendment")
    certificate = {
        "parent": str(revision_from.resolve()), "output": str(output.resolve()),
        "parent_report_sha256": file_sha256(parent / "pipeline-report.json"),
        "abstention_sha256": file_sha256(revision_from / "curator/abstention.json"),
        "runtime_amendment_fingerprint": fingerprint(matches[0]),
    }
    with locked_run(run, wait=True):
        registry = run / "canonical-extension-recoveries"
        registry.mkdir(mode=0o700, exist_ok=True)
        key = hashlib.sha256(str(revision_from.resolve()).encode()).hexdigest()
        immutable_json(registry / (key + ".json"), certificate)
    return {
        "previous_abstention": abstention,
        "approved_annotation_extension": matches[0].policy_version,
        "revision_instructions": "Reinspect the source under the explicitly approved empty-array observation extension. "
                                 "Preserve every claim and material comparison. Do not invent counts or select whole containers.",
    }


def canonical_candidate(task: TaskRecord, validation: ValidationReport, baseline: EvidenceFootprint,
                        source: EvidenceVerifier, client: ConfiguredClient, output: Path, *,
                        revision_from: Path | None = None, feedback: str | None = None) -> StageResult:
    """Reuse pinned fact semantics while adding exact-role resume at the orchestration layer."""
    resolver = SourceFactResolver(source)
    if validation.pilot_blockers(task) or baseline.task_fingerprint != fingerprint(task):
        raise ValueError("canonical inputs must bind the current validated task")
    if source.engine.engine != "duckdb" or baseline.feature_weight_version != "unit-evidence-audit-v1" or (
        baseline.snapshot_id, baseline.graph_version
    ) != (task.snapshot_id, task.graph_version):
        raise ValueError("canonical curation requires the matching source and unit-weight graph baseline")
    revision_context = {}
    revision_hashes = {}
    previous_proposal = None
    if revision_from is not None:
        if not feedback or not feedback.strip():
            raise ValueError("canonical annotation revision requires explicit source-backed feedback")
        previous_binding = json.loads((revision_from / "binding.json").read_bytes())
        if (previous_binding["task_fingerprint"], previous_binding["validation_fingerprint"],
            previous_binding["baseline_fingerprint"]) != (
            fingerprint(task), fingerprint(validation), fingerprint(baseline),
        ):
            raise ValueError("canonical annotation revision does not bind the unchanged inputs and prior hold")
        if (revision_from / "curator/abstention.json").exists() and not (revision_from / "fact_report.json").exists():
            revision_context = {**_canonical_abstention_extension(revision_from, previous_binding, output),
                               "additional_feedback": feedback}
            revision_hashes = {name: file_sha256(revision_from / name)
                              for name in ("binding.json", "curator/abstention.json")}
        else:
            previous_report = json.loads((revision_from / "fact_report.json").read_bytes())
            previous_review = CanonicalFactReview.model_validate_json((revision_from / "reviewer/result.json").read_bytes())
            if previous_report["status"] != "needs_fact_revision" or (
               previous_report["review"] != previous_review.model_dump(mode="json")
               or previous_report["bundle_fingerprint"] != previous_review.bundle_fingerprint
            ):
               raise ValueError("canonical annotation revision does not bind the unchanged inputs and prior hold")
            previous_proposal = SourceFactProposal.model_validate_json((revision_from / "curator/result.json").read_bytes())
            revision_context = {
               "previous_annotation": previous_proposal.model_dump(mode="json"),
               "revision_feedback": previous_review.model_dump(mode="json"), "additional_feedback": feedback,
               "revision_instructions": "Correct the source-property annotation, not the task or grading. Independently "
                                         "inspect the source; prior feedback is fallible. Cover every material scope, "
                                         "identity, time and role predicate for each claim without unrelated padding.",
            }
            revision_hashes = {name: file_sha256(revision_from / name) for name in (
               "binding.json", "fact_report.json", "curator/result.json", "reviewer/result.json", "canonical-facts.json",
            )}
    elif feedback is not None:
        raise ValueError("canonical feedback requires a bound prior annotation")
    immutable_json(output / "binding.json", {
        "task_fingerprint": fingerprint(task), "validation_fingerprint": fingerprint(validation),
        "baseline_fingerprint": fingerprint(baseline), "curation_version": CURATION_VERSION,
        "revision_from": str(revision_from.resolve()) if revision_from is not None else None,
        "revision_artifacts_sha256": revision_hashes,
        "implementation_sha256": {name: file_sha256(Path(__file__).with_name(name)) for name in FACT_RUNTIME_FILES},
        "orchestration_version": VERSION, "orchestration_sha256": file_sha256(Path(__file__)),
        "grading_changed": False, "release_approved": False,
    })
    claims = [("final", task.question, task.private_gold.final),
              *((c.checkpoint_id, c.objective, c.claim) for c in task.private_gold.checkpoints)]
    context = {
        "public_task": task.public_task().model_dump(mode="json"),
        "claims": [{"claim_id": name, "objective": goal, "expected": claim.expected.model_dump(mode="json"),
                    "evidence_sets": [group.model_dump(mode="json") for group in claim.evidence_sets],
                    "source_programs": [p.model_dump(mode="json") for p in claim.programs if p.engine == "duckdb"]}
                   for name, goal, claim in claims],
        "evidence": [ref.model_dump(mode="json") for ref in task.evidence],
    }

    def validate_proposal(value: SourceFactProposal, tools: FactInspectionTools):
        resolver.resolve(task, validation, value)
        if previous_proposal is not None:
            selected = lambda proposal: {claim.claim_id: {fingerprint(ref) for ref in claim.references}
                                         for claim in proposal.claims}
            if selected(value) == selected(previous_proposal):
                raise ValueError("a held canonical selection needs a material reference change, not prose-only resampling")
        if {ref.citation for claim in value.claims for ref in claim.references} - tools.observed:
            raise ValueError("canonical curator must inspect every selected source record")

    proposal = inspected_role(client, source, output / "curator", "fact-curator", CURATOR_INSTRUCTIONS,
                              {**context, **revision_context}, SourceFactProposal, validate_proposal)
    bundle = resolver.resolve(task, validation, proposal)
    immutable_json(output / "canonical-facts.json", bundle)

    def validate_review(value: CanonicalFactReview, tools: FactInspectionTools):
        if value.bundle_fingerprint != fingerprint(bundle):
            raise ValueError("canonical review binds another fact bundle")
        if value.recommendation == "pass" and {ref.citation for claim in proposal.claims for ref in claim.references} - tools.observed:
            raise ValueError("canonical reviewer must independently inspect all selected source records")

    review = inspected_role(client, source, output / "reviewer", "fact-reviewer", REVIEWER_INSTRUCTIONS,
                            {**context, "proposal": proposal.model_dump(mode="json"), "facts": bundle.model_dump(mode="json"),
                             "bundle_fingerprint": fingerprint(bundle)}, CanonicalFactReview, validate_review)
    passed = review.recommendation == "pass" and all((
        review.source_properties_relevant, review.subjects_roles_times_preserved,
        review.claim_coverage_complete, review.no_value_only_merging,
    ))
    if passed:
        immutable_json(output / "canonical-footprint.json", canonical_fact_footprint(baseline, bundle, review))
    immutable_json(output / "fact_report.json", {
        "task_id": task.task_id, "task_fingerprint": fingerprint(task),
        "status": "canonical_facts_reviewed" if passed else "needs_fact_revision",
        "fact_count": len(bundle.facts), "claim_count": len(bundle.claims), "bundle_fingerprint": fingerprint(bundle),
        "review": review.model_dump(mode="json"),
        "exact_claim_signature_ids": [feature.feature_id for feature in baseline.facts or ()],
        "grading_changed": False, "release_approved": False,
    })
    return StageResult(status="pass" if passed else "held", reason="Canonical source-fact review: " + review.recommendation)


def objective_candidate(plan: PreproductionPlan, run: Path, task: TaskRecord, source: EvidenceVerifier,
                        client: ConfiguredClient, output: Path) -> StageResult:
    inventory = objective_inventory(plan, run, excluding=task.task_id)
    tasks = list(plan.seed_questions)
    for receipt in admitted_receipts(plan, run):
        if receipt.task.task_id != task.task_id:
            tasks.append(admitted_task(run, receipt))
    if {(t.task_id, fingerprint(t)) for t in tasks} != set(inventory.questions):
        raise ValueError("objective descriptors do not match the current admitted comparison inventory")

    def describe(value: TaskRecord):
        return {"task_id": value.task_id, "task_fingerprint": fingerprint(value), "task_family": value.task_family,
                "public_task": value.public_task().model_dump(mode="json"),
                "answer_window": value.scope.answer_window.model_dump(mode="json")}

    def validate(value: ObjectiveReview, tools: FactInspectionTools):
        _review_validator(task, fingerprint(inventory), frozenset())(value, tools)
        if set(value.duplicate_task_ids) - {item.task_id for item in tasks}:
            raise ValueError("objective review names a task outside the comparison inventory")

    review = inspected_role(
        client, source, output / "reviewer", "objective-reviewer",
        "Compare the candidate's investigative objective AND scoped target against EVERY supplied question. "
        "Paraphrases of the same objective/target are duplicates; shared evidence, episodes, checkpoints or "
        "answer strings alone are not. Compare identities, roles, time scope and requested result, not lexical "
        "similarity. Inspect sources if scope/roles are ambiguous. A pass requires a genuinely new objective; "
        "otherwise return revise/reject and exact duplicate IDs. No overlap cap or desired difficulty applies.",
        {"task_fingerprint": fingerprint(task), "subject_fingerprint": fingerprint(inventory),
         "candidate": describe(task), "comparisons": [describe(value) for value in tasks]},
        ObjectiveReview, validate,
    )
    immutable_json(output / "review.json", review)
    return StageResult(status="pass" if review.recommendation == "pass" else "held", reason="; ".join(review.reasons))


def _resume_finalization(output: Path, run: Path, current: dict, archive: Path) -> dict:
    archive = archive.resolve()
    if not archive.is_relative_to(run.resolve()) or (output / "pipeline-report.json").exists():
        raise ValueError("finalization recovery requires an owned producer archive and an unfinished pipeline")
    original = json.loads((output / "binding.json").read_bytes())
    if {key: value for key, value in original.items() if key != "implementation_sha256"} != {
        key: value for key, value in current.items() if key != "implementation_sha256"
    }:
        raise ValueError("finalization recovery cannot change task, source, model, execution mode or grading policy")
    old_code, new_code = original["implementation_sha256"], current["implementation_sha256"]
    if old_code.keys() != new_code.keys() or {
        name for name in old_code if old_code[name] != new_code[name]
    } - {"preproduction_pipeline.py"}:
        raise ValueError("finalization recovery may change only pipeline orchestration, not source/grading kernels")
    with zipfile.ZipFile(archive) as saved:
        for name, digest in old_code.items():
            if hashlib.sha256(saved.read(name)).hexdigest() != digest:
                raise ValueError("finalization recovery archive does not preserve the exact original producer")
    for name in ("grading", "native", "baseline", "robustness", "canonical", "difficulty"):
        directory = output / name
        receipt = StageReceipt.model_validate_json((directory / "stage-receipt.json").read_bytes())
        if receipt.result.status != "pass" or receipt.artifacts_sha256 != _json_hashes(directory, excluded=("stage-receipt.json",)):
            raise ValueError("finalization recovery requires every earlier stage to be passed and unchanged")
        if json.loads((directory / "stage-binding.json").read_bytes())["pipeline"] != original:
            raise ValueError("a passed stage belongs to another original pipeline binding")
    if any(output.glob("objective-*/*/*-request.json")):
        raise ValueError("a started objective review requires its own boundary recovery, not finalization restart")
    safe_unfinished_roles(output)
    certificate_path = output / "finalization-resume.json"
    if certificate_path.exists():
        prior = json.loads(certificate_path.read_bytes())
        hashes = prior["original_artifacts_sha256"]
        if any(file_sha256(output / name) != digest for name, digest in hashes.items()):
            raise ValueError("original finalization inputs changed after recovery was authorized")
    else:
        hashes = _json_hashes(output)
    immutable_json(certificate_path, {
        "policy_version": "completed-prefix-finalization-resume-v1",
        "original_binding_sha256": file_sha256(output / "binding.json"),
        "original_artifacts_sha256": hashes, "original_runtime_sha256": old_code,
        "execution_runtime_sha256": new_code, "runtime_archive": str(archive),
        "runtime_archive_sha256": file_sha256(archive),
        "completed_stages_resampled": False, "original_binding_rewritten": False,
    })
    # Cached stages keep their initial binding; the appended certificate pins this execution.
    return original


def run_candidate_pipeline(
    *, plan: PreproductionPlan, run: Path, task_id: str, client: ConfiguredClient,
    source: EvidenceVerifier, mysql: EvidenceVerifier | None, student: PublicQueryEngine | None,
    serving_bundle: Path, mysql_bundle: Path, graph_bundle: Path, mysqld: Path, workdir: Path, output: Path,
    grading_policy_directory: Path | None = None, resume: bool = False,
    parent_pipeline: Path | None = None, parent_runtime_archive: Path | None = None,
    prepared_robustness_plan: Path | None = None, robustness_feedback: str | None = None,
    canonical_feedback: str | None = None, difficulty_feedback: str | None = None,
    retained_native_pipeline: Path | None = None, retained_native_task: Path | None = None,
    retained_native_runtime_archive: Path | None = None,
    native_engines: Callable[[], AbstractContextManager[tuple[EvidenceVerifier, PublicQueryEngine]]] | None = None,
    finalization_runtime_archive: Path | None = None,
    fresh_validation: bool = False,
    robustness_control_repairs: dict[str, str] | None = None,
    robustness_review_recovery: bool = False,
    qualified_support_review_recovery: Path | None = None,
    admitted_contract_revision: Path | None = None,
    native_review_context: dict | None = None,
) -> dict:
    """Caller owns read-only engines on the plan's verified native snapshot; no student rerolls."""
    from .preproduction import runtime_hashes
    from .grading_review import runtime_hashes as grading_hashes
    from .difficulty_curation import _runtime_hashes as difficulty_hashes
    from .robustness import RUNTIME_FILES as robustness_files

    if effective_runtime(plan, run) != runtime_hashes() or configured_model_binding(client) != plan.model:
        raise ValueError("pipeline source plan/runtime/model changed")
    if finalization_runtime_archive is not None and not resume:
        raise ValueError("completed-prefix finalization recovery requires explicit resume")
    if admitted_contract_revision is not None and not fresh_validation:
        raise ValueError("an admitted contract revision requires explicit fresh validation")
    if robustness_review_recovery and qualified_support_review_recovery is not None:
        raise ValueError("one robustness review cannot use two recovery authorizations")
    if (robustness_review_recovery or qualified_support_review_recovery is not None) and (
        parent_pipeline is None or prepared_robustness_plan is None or robustness_control_repairs
        or canonical_feedback is not None or difficulty_feedback is not None
    ):
        raise ValueError("review-only recovery requires a prepared robustness-only annotation continuation")
    feedbacks = [value for value in (robustness_feedback, canonical_feedback, difficulty_feedback) if value is not None]
    native_inputs = (retained_native_pipeline, retained_native_task, retained_native_runtime_archive)
    native_import_requested = any(value is not None for value in native_inputs)
    if native_import_requested and (
        not all(value is not None for value in native_inputs) or parent_pipeline is not None
        or parent_runtime_archive is not None or grading_policy_directory is not None
        or canonical_feedback is not None or difficulty_feedback is not None
        or (prepared_robustness_plan is None and not fresh_validation) or not robustness_feedback or not robustness_feedback.strip()
    ):
        raise ValueError("retained native import requires exact parent/task/archive and prepared robustness feedback, without annotation or policy overrides")
    if (parent_pipeline is None) != (parent_runtime_archive is None) or (
        parent_pipeline is None and not native_import_requested and (prepared_robustness_plan is not None or feedbacks)
    ) or (parent_pipeline is not None and (len(feedbacks) != 1 or not feedbacks[0].strip())) or (
        prepared_robustness_plan is not None and robustness_feedback is None
    ):
        raise ValueError("annotation continuation requires its parent, exact runtime archive and explicit feedback")
    if parent_pipeline is not None and parent_pipeline.resolve() == output.resolve():
        raise ValueError("annotation continuation must not overwrite its held parent")
    if retained_native_pipeline is not None and retained_native_pipeline.resolve() == output.resolve():
        raise ValueError("retained native import must not overwrite its original pipeline")
    candidate, outcome, _ = current_source(plan, run, task_id)
    if outcome is None or outcome.status != "source_ready":
        raise ValueError("pipeline requires the current source-ready logical attempt")
    task = TaskRecord.model_validate_json((candidate / "task.json").read_bytes())
    if output.resolve().parent != (run / "attempts" / task_id / "pipeline").resolve():
        raise ValueError("pipeline output must use this logical attempt's separate pipeline namespace")
    for path in output.glob("*/stage-receipt.json"):
        stage_receipt = StageReceipt.model_validate_json(path.read_bytes())
        if stage_receipt.artifacts_sha256 != _json_hashes(path.parent, excluded=("stage-receipt.json",)):
            raise ValueError("retained pipeline stage artifacts changed")
    terminal_report = output / "pipeline-report.json"
    if terminal_report.exists():
        retained = json.loads(terminal_report.read_bytes())
        if retained["artifacts_sha256"] != _json_hashes(output, excluded=("pipeline-report.json",)):
            raise ValueError("completed pipeline artifacts changed")
        if retained["task_fingerprint"] != fingerprint(task):
            raise ValueError("completed pipeline belongs to another revision")
        saved_binding = json.loads((output / "binding.json").read_bytes())
        saved_parent = saved_binding.get("continuation")
        if saved_parent is not None and _continuation(
            Path(saved_parent["parent_pipeline"]), Path(saved_parent["runtime_archive"]), saved_binding,
            run, output.parent,
        ) != saved_parent:
            raise ValueError("completed pipeline's retained-stage provenance changed")
        if saved_binding.get("native_import") is not None:
            validate_native_import(NativeStudentImport.model_validate(saved_binding["native_import"]), plan, task, run)
    previously_admitted = False
    for receipt in admitted_receipts(plan, run):
        if receipt.task.task_id == task_id:
            if receipt.task.task_fingerprint != fingerprint(task):
                if admitted_contract_revision is None:
                    raise ValueError("an accepted logical attempt cannot silently change task revision")
                validate_admitted_contract_revision(plan, run, task, admitted_contract_revision)
            previously_admitted = True
            if not fresh_validation:
                return {"task_id": task_id, "status": "already_admitted", "new_model_calls": 0, "release_approved": False}
    if admitted_contract_revision is not None and not previously_admitted:
        raise ValueError("an admitted contract authorization cannot certify an unadmitted task")
    if previously_admitted and not native_import_requested and parent_pipeline is None:
        raise ValueError("fresh validation of an admitted question requires its retained native student, never a new sample")
    if output.exists() and not resume:
        raise ValueError("pipeline output must be new unless explicitly resumed")
    attempt = run / "attempts" / task_id
    native_requests = [*attempt.glob("native*/student/*-request.json"),
                       *(attempt / "pipeline").glob("*/native/student/*-request.json")]
    native_import = None
    recorded_native_task = None
    if retained_native_pipeline is not None and retained_native_task is not None and retained_native_runtime_archive is not None:
        parent = retained_native_pipeline.resolve()
        recorded = retained_native_task.resolve()
        archive = retained_native_runtime_archive.resolve()
        artifacts = native_import_artifacts(run, task_id, parent, recorded, archive)
        recorded_native_task = TaskRecord.model_validate_json(recorded.read_bytes())
        native_import = NativeStudentImport(
            task_fingerprint=fingerprint(task), recorded_task_fingerprint=fingerprint(recorded_native_task),
            plan_fingerprint=fingerprint(plan), parent_pipeline=str(parent), recorded_task=str(recorded),
            runtime_archive=str(archive), source_artifacts_sha256=artifacts,
        )
        validate_native_import(native_import, plan, task, run)
        if output.exists() and any(output.glob("native/student/*-request.json")):
            raise ValueError("retained native import cannot replace another started student")
    allowed_students = {(output / "native/student").resolve()}
    if native_import is not None:
        allowed_students.add((Path(native_import.parent_pipeline) / "native/student").resolve())
    if parent_pipeline is None and any(path.parent.resolve() not in allowed_students for path in native_requests):
        raise ValueError("this logical attempt already has a native student; supervised retained-trace import is required, never a new student")
    draft = TaskDraft.model_validate_json((candidate / "draft.json").read_bytes())
    validate_quality_gate(candidate, task)
    from .preproduction_revisions import effective_native_plan, native_index_digest, native_index_manifest
    indexes = native_index_manifest(mysql_bundle)
    index_digest = native_index_digest(indexes)
    execution_plan = effective_native_plan(plan, run)
    if not indexes or (file_sha256(mysql_bundle / "mysql_report.json"), index_digest,
                       file_sha256(serving_bundle / "serving_report.json")) != (
        plan.native_snapshot_sha256, execution_plan.native_indexes_sha256, plan.serving_report_sha256,
    ):
        raise ValueError("verified serving/native/index artifacts changed")
    literals = frozenset(item.value for item in draft.allowed_literals)
    grader_limits = plan.query_limits.model_copy(update={"timeout_ms": plan.grader_timeout_ms or plan.query_limits.timeout_ms})
    if source.engine.engine != "duckdb" or (
        source.report["serving_view_id"] != plan.serving_view_id or source.allowed_literals != literals
        or source.engine.limits != grader_limits
        or file_sha256(graph_bundle / "graph_report.json") != plan.graph_report_sha256
        or plan.native_snapshot_sha256 is None or plan.native_indexes_sha256 is None
    ):
        raise ValueError("pipeline source/native/query/graph settings differ from the original plan")

    def validate_native(native_verifier: EvidenceVerifier, student_engine: PublicQueryEngine) -> None:
        if (native_verifier.engine.engine, student_engine.engine) != ("mysql", "mysql") or (
            source.report != native_verifier.report or student_engine.serving_view_id != plan.serving_view_id
            or native_verifier.allowed_literals != literals or native_verifier.engine.limits != grader_limits
            or student_engine.limits != plan.query_limits
        ):
            raise ValueError("pipeline source/native/query/graph settings differ from the original plan")

    if native_engines is None:
        if mysql is None or student is None:
            raise ValueError("native engines or an explicit native-stage lease are required")
        validate_native(mysql, student)
    elif mysql is not None or student is not None:
        raise ValueError("a native-stage lease cannot be combined with preopened native engines")
    implementation = {**runtime_hashes(), **grading_hashes(), **difficulty_hashes(),
                      **{name: file_sha256(Path(__file__).with_name(name)) for name in NATIVE_RUNTIME_FILES},
                      **{name: file_sha256(Path(__file__).with_name(name)) for name in robustness_files},
                      "preproduction_pipeline.py": file_sha256(Path(__file__))}
    policy = load_reviewed_grading(grading_policy_directory) if grading_policy_directory is not None else None
    binding = {"version": VERSION, "task_fingerprint": fingerprint(task), "plan_fingerprint": fingerprint(plan),
               "source_outcome_fingerprint": fingerprint(outcome), "implementation_sha256": implementation,
               "grading_policy_fingerprint": fingerprint(policy) if policy is not None else None}
    if native_review_context is not None:
        if (native_review_context.get("plan_fingerprint"), native_review_context.get("task_fingerprint"),
            native_review_context.get("native_snapshot_sha256")) != (
            fingerprint(plan), fingerprint(task), plan.native_snapshot_sha256,
        ):
            raise ValueError("native review context does not bind this plan, task and snapshot")
        binding["native_review_context_fingerprint"] = _context_fingerprint(native_review_context)
    if admitted_contract_revision is not None:
        validate_admitted_contract_revision(plan, run, task, admitted_contract_revision)
        binding["admitted_contract_revision"] = {
            "path": str(admitted_contract_revision.resolve()), "sha256": file_sha256(admitted_contract_revision),
        }
    if robustness_review_recovery:
        binding["robustness_review_recovery"] = "contaminated-robustness-review-recovery-v1"
    if qualified_support_review_recovery is not None:
        binding["qualified_support_review_recovery"] = {
            "path": str(qualified_support_review_recovery.resolve()),
            "sha256": file_sha256(qualified_support_review_recovery),
        }
    if fresh_validation:
        binding["validation_purpose"] = "fresh-checkpoint-validation"
    if robustness_control_repairs is not None:
        if parent_pipeline is None and native_import is None:
            raise ValueError("control repair authorization requires an exact prior pipeline")
        binding["robustness_control_repairs"] = robustness_control_repairs
    if native_engines is not None:
        binding["native_execution"] = "leased-stage-v1"
    if native_import is not None:
        binding["native_import"] = native_import.model_dump(mode="json")
        binding["robustness_revision"] = {
            "feedback": robustness_feedback,
            "prepared_plan_sha256": file_sha256(prepared_robustness_plan) if prepared_robustness_plan is not None else None,
        }
    imported: dict[str, str] = {}
    if parent_pipeline is not None and parent_runtime_archive is not None:
        continuation = _continuation(parent_pipeline, parent_runtime_archive, binding, run, output.parent)
        imported = continuation["imported_stage_paths"]
        if ("canonical" in imported) != (difficulty_feedback is not None) or (
            ("robustness" in imported and "canonical" not in imported) != (canonical_feedback is not None)
        ):
            raise ValueError("annotation feedback does not match the parent's held stage")
        allowed_students = {(output / "native/student").resolve()} | _native_student_roots(
            plan, task, run, Path(imported["native"]),
        )
        if any(path.parent.resolve() not in allowed_students for path in native_requests):
            raise ValueError("annotation continuation encountered an unrelated native student recording")
        binding["continuation"] = continuation
        if difficulty_feedback is not None:
            binding["difficulty_revision"] = {"feedback": difficulty_feedback}
        elif canonical_feedback is not None:
            binding["canonical_revision"] = {"feedback": canonical_feedback}
        else:
            binding["robustness_revision"] = {
                "feedback": robustness_feedback,
                "prepared_plan_sha256": file_sha256(prepared_robustness_plan) if prepared_robustness_plan is not None else None,
            }
    with ExitStack() as locks:
        lock = locks.enter_context((run / "pipeline.lock").open("a+"))
        try:
            fcntl.flock(lock, (fcntl.LOCK_SH if native_engines is not None else fcntl.LOCK_EX) | fcntl.LOCK_NB)
            task_lock = locks.enter_context((attempt / "candidate-pipeline.lock").open("a+"))
            fcntl.flock(task_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("another incompatible pipeline owns this run or logical attempt") from error
        output.mkdir(parents=True, mode=0o700, exist_ok=resume)
        if finalization_runtime_archive is not None:
            binding = _resume_finalization(output, run, binding, finalization_runtime_archive)
        immutable_json(output / "binding.json", binding)
        if terminal_report.exists():
            return retained
        completed: dict[str, str] = {}

        def stage(name: str, action: Callable[[Path], StageResult]):
            if name in imported:
                completed[name] = file_sha256(Path(imported[name]) / "stage-receipt.json")
                return None
            result = run_stage(output / name, {"pipeline": binding, "prior_stage_receipts": dict(completed)}, action)
            completed[name] = file_sha256(output / name / "stage-receipt.json")
            if result.status == "held":
                report = {"task_id": task_id, "task_fingerprint": fingerprint(task), "status": "held",
                          "stage": name, "reason": result.reason, "stage_receipts": dict(completed), "release_approved": False,
                          "artifacts_sha256": _json_hashes(output, excluded=("pipeline-report.json",))}
                immutable_json(output / "pipeline-report.json", report)
                return report
            return None

        def grading_stage(folder: Path) -> StageResult:
            context = native_review_context
            if context is None and mysql is not None:
                context = native_text_semantics(plan, task, mysql)
            return review_contract(task, source, client, folder, grading_policy_directory, native_context=context)

        held = stage("grading", grading_stage)
        if held:
            return held
        def native_stage(folder: Path) -> StageResult:
            if native_engines is not None:
                with native_engines() as (native_verifier, student_engine):
                    validate_native(native_verifier, student_engine)
                    return native_candidate(plan, candidate, task, source, native_verifier, student_engine, client,
                                            folder, grading_policy_directory, serving_bundle,
                                            retained_student=native_import, run=run)
            if mysql is None or student is None:
                raise ValueError("the previously validated native engines are unavailable")
            return native_candidate(plan, candidate, task, source, mysql, student, client,
                                    folder, grading_policy_directory, serving_bundle,
                                    retained_student=native_import, run=run)

        held = stage("native", native_stage)
        if held:
            return held
        native = Path(imported["native"]) if "native" in imported else output / "native"
        validation = ValidationReport.model_validate_json((native / "private-pilot-validation.json").read_bytes())
        def baseline_stage(folder: Path) -> StageResult:
            immutable_json(folder / "footprint.json", build_unit_footprints([(task, validation)], graph_bundle)[0])
            return StageResult(status="pass", reason="Exact task-bound graph baseline persisted.")

        stage("baseline", baseline_stage)
        baseline_path = (Path(imported["baseline"]) if "baseline" in imported else output / "baseline") / "footprint.json"
        baseline = EvidenceFootprint.model_validate_json(baseline_path.read_bytes())
        grading_directory = Path(imported["grading"]) if "grading" in imported else output / "grading"
        text_metadata = grading_directory / "native-text-semantics.json"
        robustness_native_context = native_review_context
        if robustness_native_context is None and text_metadata.exists():
            robustness_native_context = json.loads(text_metadata.read_bytes())
        held = stage("robustness", lambda folder: robustness_candidate(
            task, source, client, folder, mysqld, workdir,
            revision_from=(parent_pipeline / "robustness" if parent_pipeline is not None else
                           Path(native_import.parent_pipeline) / "robustness" if native_import is not None else None),
            prepared_plan=prepared_robustness_plan, feedback=robustness_feedback,
            recorded_task=recorded_native_task,
            control_repairs=robustness_control_repairs,
            review_recovery=robustness_review_recovery, run=run,
            qualified_support_recovery=qualified_support_review_recovery,
            native_context=robustness_native_context,
        ))
        if held:
            return held
        held = stage("canonical", lambda folder: canonical_candidate(
            task, validation, baseline, source, client, folder,
            revision_from=parent_pipeline / "canonical" if parent_pipeline is not None and canonical_feedback is not None else None,
            feedback=canonical_feedback,
        ))
        if held:
            return held
        inputs = SplitInputs(cohort_label="preproduction-pipeline-private", questions=(QuestionFiles(
            task=str((candidate / "task.json").resolve()), validation=str((native / "private-pilot-validation.json").resolve()),
            baseline=str(baseline_path.resolve()),
            annotation=str((Path(imported["canonical"]) if "canonical" in imported else output / "canonical").resolve()),
        ),))
        immutable_json(output / "inputs.json", inputs)
        question, = load_questions(output / "inputs.json").questions

        def difficulty(folder: Path) -> StageResult:
            directory = folder / "curation"
            if directory.exists():
                safe_unfinished_roles(directory)
            report = curate_difficulty(
                client=client, question=question, verifier=source, output=directory, resume=directory.exists(),
                revision_from=parent_pipeline / "difficulty/curation"
                if parent_pipeline is not None and difficulty_feedback is not None else None,
            )
            passed = report["status"] in ("difficulty_reviewed", "measurement_incomplete") and not report["task_defect_reasons"]
            return StageResult(status="pass" if passed else "held", reason="Difficulty curation: " + report["status"])

        held = stage("difficulty", difficulty)
        if held:
            return held
        with (run / "admission-finalization.lock").open("a+") as finalization:
            fcntl.flock(finalization, fcntl.LOCK_EX)
            inventory = objective_inventory(plan, run, excluding=task_id)
            objective_name = "objective-" + fingerprint(inventory)[:16]
            held = stage(objective_name, lambda folder: objective_candidate(plan, run, task, source, client, folder))
            if held:
                return held
            robust_directory = Path(imported["robustness"]) if "robustness" in imported else output / "robustness"
            selection = json.loads((robust_directory / "selected-measurement.json").read_bytes())
            files = AdmissionFiles(
                question_inputs=str((output / "inputs.json").resolve()), native_directory=str(native.resolve()),
                native_binding=str((native / "binding.json").resolve()),
                robustness_directory=str((robust_directory / "measurements" / selection["directory"]).resolve()),
                robustness_review=str((robust_directory / "review.json").resolve()),
                objective_review=str((output / objective_name / "review.json").resolve()),
                difficulty_directory=str((output / "difficulty/curation").resolve()),
                grading_review=str(((Path(imported["grading"]) if "grading" in imported else output / "grading") / "review.json").resolve()),
                grading_policy_directory=str(grading_policy_directory.resolve()) if grading_policy_directory is not None else None,
            )
            if any(file_sha256(Path(__file__).with_name(name)) != digest for name, digest in implementation.items()):
                raise ValueError("pipeline implementation changed during execution")
            if native_import is not None:
                validate_native_import(native_import, plan, task, run)
            immutable_json(output / "admission-files.json", files)
            revalidation = run / "revalidations" / task_id / (output.name + ".json") if previously_admitted else None
            receipt = record_admission(plan, run, files, revalidation_receipt=revalidation,
                                       admitted_contract_revision=admitted_contract_revision)
            report = {"task_id": task_id, "task_fingerprint": fingerprint(task),
                      "status": "revalidated" if previously_admitted else "admitted",
                      "admission_fingerprint": fingerprint(receipt), "stage_receipts": completed, "release_approved": False,
                      "artifacts_sha256": _json_hashes(output, excluded=("pipeline-report.json",))}
            immutable_json(output / "pipeline-report.json", report)
            return report


def run_owned_candidate_pipeline(
    *, run: Path, task_id: str, serving_bundle: Path, graph_bundle: Path, mysql_bundle: Path,
    env_file: Path, workdir: Path, output: Path, resume: bool = False,
    grading_policy_directory: Path | None = None,
    parent_pipeline: Path | None = None, parent_runtime_archive: Path | None = None,
    prepared_robustness_plan: Path | None = None, robustness_feedback: str | None = None,
    canonical_feedback: str | None = None, difficulty_feedback: str | None = None,
    retained_native_pipeline: Path | None = None, retained_native_task: Path | None = None,
    retained_native_runtime_archive: Path | None = None,
    fresh_validation: bool = False,
    robustness_control_repairs: dict[str, str] | None = None,
    robustness_review_recovery: bool = False,
    qualified_support_review_recovery: Path | None = None,
    admitted_contract_revision: Path | None = None,
) -> dict:
    """Own only this verified snapshot's server; never connect to an arbitrary existing service."""
    from .azure_generation import AzureGenerationClient, AzureGenerationConfig
    from .mysql_serving import open_duckdb_engine, open_mysql_engine

    plan = PreproductionPlan.model_validate_json((run / "plan.json").read_bytes())
    report_path = mysql_bundle / "mysql_report.json"
    if file_sha256(report_path) != plan.native_snapshot_sha256:
        raise ValueError("owned native snapshot report differs from the original plan")
    metadata = json.loads(report_path.read_bytes())
    serving = json.loads((serving_bundle / "serving_report.json").read_bytes())
    if (metadata["status"], metadata["serving_view_id"], metadata["verified_rows"]) != (
        "complete", plan.serving_view_id, sum(table.get("rows", 0) for table in serving["tables"]),
    ):
        raise ValueError("native snapshot lacks matching complete row verification")
    candidate, outcome, _ = current_source(plan, run, task_id)
    if outcome is None or outcome.status != "source_ready":
        raise ValueError("owned pipeline requires a current source-ready candidate")
    draft = TaskDraft.model_validate_json((candidate / "draft.json").read_bytes())
    literals = frozenset(item.value for item in draft.allowed_literals)
    limits = plan.query_limits.model_copy(update={"timeout_ms": plan.grader_timeout_ms or plan.query_limits.timeout_ms})
    client = source = mysql = source_engine = native_engine = student_engine = None
    with (mysql_bundle / "pipeline-mysql.lock").open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("the verified native snapshot already has an owning pipeline") from error
        with tempfile.TemporaryDirectory(prefix=".secrl-pipeline-", dir=workdir.resolve()) as temporary:
            folder = Path(temporary)
            socket = folder / "mysql.sock"
            if len(str(socket).encode()) > 100:
                raise ValueError("native socket path is too long; use a shorter owned scratch parent")
            credentials = json.loads((mysql_bundle / metadata["reader_credentials_file"]).read_bytes())
            server = subprocess.Popen([
                metadata["mysqld_binary"], "--no-defaults", f"--datadir={metadata['data_directory']}",
                f"--socket={socket}", "--skip-networking", "--mysqlx=OFF",
                f"--innodb-page-size={metadata['innodb_page_size']}", "--innodb-buffer-pool-size=512M",
                f"--pid-file={folder / 'mysql.pid'}", f"--log-error={folder / 'mysql.log'}",
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                for _ in range(240):
                    if server.poll() is not None:
                        log = folder / "mysql.log"
                        raise RuntimeError("owned native server failed; " + (log.read_text() if log.exists() else "no server log"))
                    try:
                        connection = mysql_connector.connect(unix_socket=str(socket), **credentials)
                        connection.close()
                        break
                    except mysql_connector.Error:
                        time.sleep(0.25)
                else:
                    raise RuntimeError("owned native server readiness timeout")
                source_engine = open_duckdb_engine(serving_bundle, limits)
                native_engine = open_mysql_engine(serving_bundle, limits=limits, unix_socket=str(socket), **credentials)
                student_engine = open_mysql_engine(serving_bundle, limits=plan.query_limits, unix_socket=str(socket), **credentials)
                source = EvidenceVerifier(serving_bundle, source_engine, literals)
                mysql = EvidenceVerifier(serving_bundle, native_engine, literals)
                client = AzureGenerationClient(AzureGenerationConfig(
                    env_file=env_file, deployment=plan.model.deployment, timeout_seconds=plan.model.request_timeout_seconds,
                    max_completion_tokens=plan.model.max_completion_tokens, reasoning_effort=plan.model.reasoning_effort,
                ))
                return run_candidate_pipeline(
                    plan=plan, run=run, task_id=task_id, client=client, source=source, mysql=mysql, student=student_engine,
                    serving_bundle=serving_bundle, mysql_bundle=mysql_bundle, graph_bundle=graph_bundle,
                    mysqld=Path(metadata["mysqld_binary"]), workdir=workdir, output=output, resume=resume,
                    grading_policy_directory=grading_policy_directory,
                    parent_pipeline=parent_pipeline, parent_runtime_archive=parent_runtime_archive,
                    prepared_robustness_plan=prepared_robustness_plan, robustness_feedback=robustness_feedback,
                    canonical_feedback=canonical_feedback, difficulty_feedback=difficulty_feedback,
                    retained_native_pipeline=retained_native_pipeline, retained_native_task=retained_native_task,
                    retained_native_runtime_archive=retained_native_runtime_archive,
                    fresh_validation=fresh_validation,
                    robustness_control_repairs=robustness_control_repairs,
                    robustness_review_recovery=robustness_review_recovery,
                    qualified_support_review_recovery=qualified_support_review_recovery,
                    admitted_contract_revision=admitted_contract_revision,
                )
            finally:
                try:
                    if client is not None:
                        client.close()
                    for verifier in (source, mysql):
                        if verifier is not None:
                            verifier.close()
                    for engine in (source_engine, native_engine, student_engine):
                        if engine is not None:
                            engine.connection.close()
                finally:
                    server.terminate()
                    try:
                        server.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait(timeout=30)
