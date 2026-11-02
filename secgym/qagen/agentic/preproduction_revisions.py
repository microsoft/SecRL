# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Immutable same-attempt source revisions and narrowly scoped orchestration upgrades."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import Literal
import zipfile

import duckdb
from pydantic import Field

from .contracts import Contract, Digest, Identifier, TaskRecord, Text, fingerprint
from .generation import RoleAbstained
from .ledger import file_sha256
from .model_panel import ConfiguredClient, immutable_json
from .pilot import run_discovery_pilot
from .preproduction import (
    PreproductionPlan, SourceOutcome, _artifacts, _check_artifacts, configured_model_binding,
    locked_run, runtime_hashes, safe_unfinished_roles,
)


ORCHESTRATION_MODULES = frozenset({"preproduction.py", "preproduction_admission.py", "preproduction_revisions.py"})
EMPTY_ARRAY_AMENDMENT = "preproduction-empty-array-facts-amendment-v1"


class RuntimeAmendment(Contract):
    policy_version: Literal[
        "preproduction-orchestration-amendment-v1", "preproduction-annotation-context-amendment-v2",
        "preproduction-empty-array-facts-amendment-v1",
    ] = "preproduction-orchestration-amendment-v1"
    plan_fingerprint: Digest
    previous_runtime_sha256: dict[str, Digest]
    current_runtime_sha256: dict[str, Digest]
    archive: Text
    archive_sha256: Digest
    reason: Text
    current_archive: Text | None = None
    current_archive_sha256: Digest | None = None
    source_and_grading_kernels_changed: Literal[False] = False


class NativeIndexAmendment(Contract):
    policy_version: Literal["preproduction-native-index-amendment-v1"] = "preproduction-native-index-amendment-v1"
    plan_fingerprint: Digest
    previous_manifest: dict[str, Digest]
    current_manifest: dict[str, Digest]
    report: Text
    approval: Text
    approval_sha256: Digest
    source_rows_modified: Literal[False] = False
    completed_students_resampled: Literal[False] = False


GRAPH_METHOD_TIME_INDEX = {
    "table": "MicrosoftGraphActivityLogs", "index": "secrl_graph_method_time_v1",
    "fields": [["RequestMethod", 16], ["TimeGenerated", None]], "non_unique": True,
}


def native_index_manifest(bundle: Path) -> dict[str, str]:
    return {path.name: file_sha256(path) for path in sorted(bundle.glob("index_report*.json"))}


def native_index_digest(manifest: dict[str, str]) -> str:
    return hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _validate_native_index_evidence(plan: PreproductionPlan, output: Path, amendment: NativeIndexAmendment) -> None:
    report_path, approval_path = _within(output, amendment.report), _within(output, amendment.approval)
    if file_sha256(report_path) != amendment.current_manifest["index_report-v7.json"] or (
        file_sha256(approval_path) != amendment.approval_sha256
    ):
        raise ValueError("native index report or approval changed")
    approval = json.loads(approval_path.read_bytes())
    report = json.loads(report_path.read_bytes())
    if approval.get("approved") is not True or report.get("policy_version") != "mysql-access-indexes-v7" or (
        report.get("added_indexes") != [GRAPH_METHOD_TIME_INDEX]
        or report.get("previous_manifest") != amendment.previous_manifest
        or report.get("serving_report_sha256") != plan.serving_report_sha256
        or report.get("native_snapshot_sha256") != plan.native_snapshot_sha256
        or report.get("source_rows_modified") is not False
        or report.get("status") != "complete"
        or report.get("verification_scope") != "all_rows_of_indexed_tables"
        or report.get("unaffected_tables_retain_original_snapshot_verification") is not True
        or type(report.get("verified_rows")) is not int
        or report["verified_rows"] <= 0
        or report.get("verified_table_rows") != {"MicrosoftGraphActivityLogs": report.get("verified_rows")}
    ):
        raise ValueError("native index upgrade lacks approved, exact-row-verified v7 provenance")


def native_index_history(plan: PreproductionPlan, output: Path) -> tuple[str, ...]:
    if plan.native_indexes_sha256 is None:
        raise ValueError("native index amendments require an originally bound native snapshot")
    history = [plan.native_indexes_sha256]
    paths = sorted((output / "native-index-amendments").glob("*.json"))
    for sequence, path in enumerate(paths):
        if path.name != f"{sequence:04d}.json":
            raise ValueError("native index amendments must form a contiguous chain")
        amendment = NativeIndexAmendment.model_validate_json(path.read_bytes())
        previous, current = amendment.previous_manifest, amendment.current_manifest
        if amendment.plan_fingerprint != fingerprint(plan) or native_index_digest(previous) != history[-1]:
            raise ValueError("native index amendment differs from its original plan or previous manifest")
        if set(current) - set(previous) != {"index_report-v7.json"} or any(
            current.get(name) != digest for name, digest in previous.items()
        ):
            raise ValueError("native index upgrade must append v7 without replacing historical manifests")
        _validate_native_index_evidence(plan, output, amendment)
        history.append(native_index_digest(current))
    return tuple(history)


def effective_native_plan(plan: PreproductionPlan, output: Path) -> PreproductionPlan:
    """Only service execution uses this view; allocation and student plans stay immutable."""
    if plan.native_indexes_sha256 is None:
        if any((output / "native-index-amendments").glob("*.json")):
            raise ValueError("native index amendments require an originally bound native snapshot")
        return plan
    return plan.model_copy(update={"native_indexes_sha256": native_index_history(plan, output)[-1]})


def record_native_index_amendment(plan: PreproductionPlan, output: Path, *, mysql_bundle: Path,
                                  serving_bundle: Path, report: Path, approval: Path) -> NativeIndexAmendment:
    from .mysql_serving import load_serving_report

    if PreproductionPlan.model_validate_json((output / "plan.json").read_bytes()) != plan:
        raise ValueError("native index amendment requires the unchanged original run plan")
    report, approval = _within(output, str(report)), _within(output, str(approval))
    with locked_run(output, wait=True):
        previous_digest = native_index_history(plan, output)[-1]
        current = native_index_manifest(mysql_bundle)
        evidence = json.loads(report.read_bytes())
        serving = load_serving_report(serving_bundle)
        affected = {t["table"]: t["rows"] for t in serving["tables"]
                    if t["status"] == "public" and t["table"] == GRAPH_METHOD_TIME_INDEX["table"]}
        if (file_sha256(mysql_bundle / "mysql_report.json"), file_sha256(serving_bundle / "serving_report.json")) != (
            plan.native_snapshot_sha256, plan.serving_report_sha256,
        ) or not affected or evidence.get("verified_table_rows") != affected:
            raise ValueError("native index verification must cover every original row of the indexed table")
        previous = evidence["previous_manifest"]
        if native_index_digest(previous) != previous_digest or (
            current != {**previous, "index_report-v7.json": file_sha256(report)}
            or "index_report-v7.json" in previous
        ):
            raise ValueError("native index upgrade changed historical reports or has not been installed")
        amendment = NativeIndexAmendment(
            plan_fingerprint=fingerprint(plan), previous_manifest=previous, current_manifest=current,
            report=str(report.relative_to(output.resolve())), approval=str(approval.relative_to(output.resolve())),
            approval_sha256=file_sha256(approval),
        )
        _validate_native_index_evidence(plan, output, amendment)
        folder = output / "native-index-amendments"
        folder.mkdir(mode=0o700, exist_ok=True)
        immutable_json(folder / f"{len(list(folder.glob('*.json'))):04d}.json", amendment)
        return amendment


class SourceRevision(Contract):
    policy_version: Literal["preproduction-source-revision-v1"] = "preproduction-source-revision-v1"
    plan_fingerprint: Digest
    task_id: Identifier
    sequence: int = Field(gt=0)
    previous_source: Text
    previous_outcome_sha256: Digest
    previous_task_fingerprint: Digest
    source_directory: Text
    source_outcome_sha256: Digest
    request_sha256: Digest
    logical_attempts_added: Literal[0] = 0


def _validate_repair(old: TaskRecord, task: TaskRecord, preserve_goals: bool) -> None:
    if (task.task_id, task.scope.mode, task.scope.incident_id, task.scope.answer_window, task.lineage_group,
        task.snapshot_id, task.serving_view_id, task.graph_version) != (
        old.task_id, old.scope.mode, old.scope.incident_id, old.scope.answer_window, old.lineage_group,
        old.snapshot_id, old.serving_view_id, old.graph_version,
    ):
        raise ValueError("source repair changed the logical identity or incident/time scope")
    if preserve_goals and (
        task.private_gold.final.expected != old.private_gold.final.expected
        or [(c.checkpoint_id, c.objective, c.claim.expected, c.depends_on) for c in task.private_gold.checkpoints]
        != [(c.checkpoint_id, c.objective, c.claim.expected, c.depends_on) for c in old.private_gold.checkpoints]
        or task.reward_policy != old.reward_policy
    ):
        raise ValueError("repair changed the explicitly preserved final/checkpoint objectives or reward")


class _RevisionClient:
    def __init__(self, client: ConfiguredClient, old: TaskRecord, source: Path, preserve_goals: bool):
        self.client, self.old, self.source, self.preserve_goals = client, old, source, preserve_goals

    @property
    def config(self):
        return self.client.config

    def complete(self, messages: list[dict], tools: list[dict]) -> dict:
        path = self.source / "task.json"
        if path.exists():
            _validate_repair(self.old, TaskRecord.model_validate_json(path.read_bytes()), self.preserve_goals)
        return self.client.complete(messages, tools)


def _within(output: Path, name: str) -> Path:
    path = (output / name).resolve()
    if not path.is_relative_to(output.resolve()):
        raise ValueError("revision/amendment artifact escapes its owning run")
    return path


def _validate_annotation_context_change(name: str, previous: bytes, current: bytes) -> None:
    old, new = ast.parse(previous), ast.parse(current)
    if name == "difficulty_curation.py":
        def without_context(tree):
            context = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_context"]
            version = [n for n in tree.body if isinstance(n, ast.Assign)
                       and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
                       and n.targets[0].id == "CURATION_VERSION"]
            if len(context) != 1 or len(version) != 1 or not isinstance(version[0].value, ast.Constant) or (
                not isinstance(version[0].value.value, str)
            ):
                raise ValueError("annotation context amendment lost its explicit context/version boundary")
            tree.body = [n for n in tree.body if n is not context[0] and n is not version[0]]
            return (ast.dump(tree), ast.dump(context[0].args), [ast.dump(n) for n in context[0].decorator_list],
                    ast.dump(context[0].returns) if context[0].returns is not None else None)
        if without_context(old) != without_context(new):
            raise ValueError("annotation context amendment changed curation or measurement kernels")
    elif name == "quality.py":
        condition = ast.parse("audit.implementation_sha256 != runtime_hashes()", mode="eval").body
        expected = ast.parse(
            "from .preproduction_revisions import validate_source_audit_runtime\n"
            "validate_source_audit_runtime(candidate, task, audit.implementation_sha256)"
        ).body
        for tree, revised in ((old, False), (new, True)):
            functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "validate_quality_gate"]
            guards = [n for f in functions for n in f.body
                      if isinstance(n, ast.If) and ast.dump(n.test) == ast.dump(condition)]
            if len(guards) != 1 or guards[0].orelse:
                raise ValueError("source metadata amendment lost its exact runtime guard")
            if revised and [ast.dump(n) for n in guards[0].body] != [ast.dump(n) for n in expected]:
                raise ValueError("source metadata amendment must use the verified producer-chain guard")
            guards[0].body = [ast.Pass()]
        if ast.dump(old) != ast.dump(new):
            raise ValueError("source metadata amendment changed source-quality semantics")
    else:
        raise ValueError("unsupported annotation context module")


def _validate_empty_array_change(name: str, previous: bytes, current: bytes) -> None:
    old, new = ast.parse(previous), ast.parse(current)
    if name == "canonical_facts.py":
        declarations = []
        for tree in (old, new):
            kinds = [n for n in tree.body if isinstance(n, ast.AnnAssign)
                     and isinstance(n.target, ast.Name) and n.target.id == "FactKind"]
            if len(kinds) != 1:
                raise ValueError("empty-array amendment lost the canonical kind declaration")
            declarations.append(kinds[0])
        for declaration, expression in zip(declarations, (
            'Literal["property_value", "json_member_presence"]',
            'Literal["property_value", "json_member_presence", "json_array_empty_v1"]',
        )):
            if declaration.value is None or ast.dump(declaration.value) != ast.dump(ast.parse(expression, mode="eval").body):
                raise ValueError("empty-array amendment changed an existing canonical kind")
        declarations[1].value = declarations[0].value
        additions = {
            ("SourceFactReference", "presence_path"): (
                'if self.kind == "json_array_empty_v1" and self.json_path is None:\n'
                '    raise ValueError("empty-array facts require an explicit JSON path, including [] for the root")'
            ),
            ("CanonicalSourceFact", "atomic_value"): (
                'if self.kind == "json_array_empty_v1" and (value is not True or self.json_path is None):\n'
                '    raise ValueError("empty-array facts require a verified true observation and an explicit JSON path")'
            ),
            (None, "source_leaf"): (
                'if kind == "json_array_empty_v1":\n'
                '    if path is None:\n'
                '        raise EvidenceFailure("empty-array facts require an explicit JSON path")\n'
                '    observed = _source_value_at(value, path)\n'
                '    if isinstance(observed, str):\n'
                '        observed = parse_json(observed)\n'
                '    if not isinstance(observed, list) or observed:\n'
                '        raise EvidenceFailure("empty-array facts require an existing source array with no elements")\n'
                '    return "true"'
            ),
        }
        for (class_name, function_name), addition in additions.items():
            containers = [new] if class_name is None else [
                n for n in new.body if isinstance(n, ast.ClassDef) and n.name == class_name
            ]
            functions = [n for container in containers for n in container.body
                         if isinstance(n, ast.FunctionDef) and n.name == function_name]
            expected_node, = ast.parse(addition).body
            matches = [(function, node) for function in functions for node in function.body
                       if ast.dump(node) == ast.dump(expected_node)]
            if len(functions) != 1 or len(matches) != 1:
                raise ValueError("empty-array amendment requires the exact source-observation guards")
            function, node = matches[0]
            function.body.remove(node)
    elif name == "fact_curation.py":
        names = {"CURATION_VERSION", "CURATOR_INSTRUCTIONS", "REVIEWER_INSTRUCTIONS"}
        for tree, version in ((old, "source-fact-curation-v1.1"), (new, "source-fact-curation-v1.2")):
            constants = {n.targets[0].id: n for n in tree.body if isinstance(n, ast.Assign)
                         and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and n.targets[0].id in names}
            if constants.keys() != names or any(
                not isinstance(n.value, ast.Constant) or not isinstance(n.value.value, str) or not n.value.value
                for n in constants.values()
            ):
                raise ValueError("empty-array amendment lost its explicit annotation context")
            if ast.literal_eval(constants["CURATION_VERSION"].value) != version:
                raise ValueError("empty-array amendment requires its versioned annotation policy")
            tree.body = [n for n in tree.body if n not in constants.values()]
    else:
        raise ValueError("unsupported empty-array annotation module")
    if ast.dump(old) != ast.dump(new):
        raise ValueError("empty-array amendment changed legacy fact identity, resolution or curation kernels")


def _validate_runtime_amendment(amendment: RuntimeAmendment, output: Path, expected: dict[str, str]) -> None:
    current = amendment.current_runtime_sha256
    changed = {name for name in expected.keys() | current.keys() if expected.get(name) != current.get(name)}
    contextual = amendment.policy_version == "preproduction-annotation-context-amendment-v2"
    structural = amendment.policy_version == EMPTY_ARRAY_AMENDMENT
    allowed = ORCHESTRATION_MODULES | ({"difficulty_curation.py", "quality.py"} if contextual else set())
    if structural:
        allowed |= {"canonical_facts.py", "fact_curation.py"}
        if not {"canonical_facts.py", "fact_curation.py"} <= changed:
            raise ValueError("empty-array amendment requires both versioned annotation producers")
    if not changed or not changed <= allowed:
        raise ValueError("orchestration amendments cannot change source, model, scoring or curation kernels")
    archive = _within(output, amendment.archive)
    if file_sha256(archive) != amendment.archive_sha256:
        raise ValueError("archived original runtime changed")
    with zipfile.ZipFile(archive) as saved:
        for name, digest in expected.items():
            if hashlib.sha256(saved.read(name)).hexdigest() != digest:
                raise ValueError("archived producer does not match the previous runtime binding")
        if contextual or structural:
            if amendment.current_archive is None or amendment.current_archive_sha256 is None:
                raise ValueError("annotation context amendment requires both exact producers")
            updated = _within(output, amendment.current_archive)
            if file_sha256(updated) != amendment.current_archive_sha256:
                raise ValueError("updated annotation producer changed")
            with zipfile.ZipFile(updated) as revised:
                for name, digest in current.items():
                    if hashlib.sha256(revised.read(name)).hexdigest() != digest:
                        raise ValueError("updated producer does not match the current runtime binding")
                for name in changed - ORCHESTRATION_MODULES:
                    validate = _validate_empty_array_change if structural else _validate_annotation_context_change
                    validate(name, saved.read(name), revised.read(name))
        elif amendment.current_archive is not None or amendment.current_archive_sha256 is not None:
            raise ValueError("orchestration-only amendments cannot silently authorize annotation context changes")


def effective_runtime(plan: PreproductionPlan, output: Path) -> dict[str, str]:
    expected = plan.implementation_sha256
    for path in sorted((output / "runtime-amendments").glob("*.json")):
        amendment = RuntimeAmendment.model_validate_json(path.read_bytes())
        if amendment.plan_fingerprint != fingerprint(plan) or amendment.previous_runtime_sha256 != expected:
            raise ValueError("runtime amendment is not a continuous chain from the original plan")
        _validate_runtime_amendment(amendment, output, expected)
        expected = amendment.current_runtime_sha256
    return dict(expected)


def record_runtime_amendment(plan: PreproductionPlan, output: Path, *, archive: Path, reason: str,
                             current_archive: Path | None = None, empty_array_facts: bool = False) -> RuntimeAmendment:
    if empty_array_facts and current_archive is None:
        raise ValueError("empty-array amendment requires both exact annotation producers")
    if PreproductionPlan.model_validate_json((output / "plan.json").read_bytes()) != plan:
        raise ValueError("runtime amendment requires the unchanged original run plan")
    archive = archive.resolve()
    if not archive.is_relative_to(output.resolve()):
        raise ValueError("runtime archive must belong to this run")
    with locked_run(output):
        previous = effective_runtime(plan, output)
        current = runtime_hashes()
        with zipfile.ZipFile(archive) as saved:
            for name, digest in previous.items():
                if hashlib.sha256(saved.read(name)).hexdigest() != digest:
                    raise ValueError("archive does not preserve the exact previous implementation")
        amendment = RuntimeAmendment(
            policy_version=EMPTY_ARRAY_AMENDMENT if empty_array_facts else (
                "preproduction-annotation-context-amendment-v2" if current_archive is not None
                else "preproduction-orchestration-amendment-v1"
            ),
            plan_fingerprint=fingerprint(plan), previous_runtime_sha256=previous, current_runtime_sha256=current,
            archive=str(archive.relative_to(output.resolve())), archive_sha256=file_sha256(archive), reason=reason,
            current_archive=str(_within(output, str(current_archive)).relative_to(output.resolve()))
            if current_archive is not None else None,
            current_archive_sha256=file_sha256(current_archive) if current_archive is not None else None,
        )
        _validate_runtime_amendment(amendment, output, previous)
        folder = output / "runtime-amendments"
        folder.mkdir(mode=0o700, exist_ok=True)
        sequence = len(list(folder.glob("*.json")))
        immutable_json(folder / f"{sequence:04d}.json", amendment)
        return amendment


def validate_source_audit_runtime(candidate: Path, task: TaskRecord, recorded: dict[str, str]) -> None:
    from .quality import runtime_hashes as quality_runtime_hashes

    current = quality_runtime_hashes()
    if set(recorded) != set(current) or {
        name for name in current if recorded[name] != current[name]
    } - {"difficulty_curation.py", "quality.py", "canonical_facts.py", "fact_curation.py"}:
        raise ValueError("source quality runtime changed; explicit revalidation is required")
    roots = [root for root in candidate.resolve().parents
             if (root / "plan.json").is_file() and (root / "attempts" / task.task_id).is_dir()]
    if len(roots) != 1 or not candidate.resolve().is_relative_to(roots[0] / "attempts" / task.task_id):
        raise ValueError("source metadata compatibility requires its exact owning preproduction run")
    run = roots[0]
    plan = PreproductionPlan.model_validate_json((run / "plan.json").read_bytes())
    if effective_runtime(plan, run) != runtime_hashes():
        raise ValueError("source metadata compatibility requires the approved current producer")
    states = [plan.implementation_sha256]
    contextual = False
    for path in sorted((run / "runtime-amendments").glob("*.json")):
        amendment = RuntimeAmendment.model_validate_json(path.read_bytes())
        contextual |= amendment.policy_version in ("preproduction-annotation-context-amendment-v2", EMPTY_ARRAY_AMENDMENT)
        states.append(amendment.current_runtime_sha256)
    if not contextual or not any({name: state.get(name) for name in recorded} == recorded for state in states):
        raise ValueError("source quality audit does not match an exact approved historical producer")


def current_source(plan: PreproductionPlan, output: Path, task_id: str) -> tuple[Path, SourceOutcome | None, int]:
    attempt = next((value for value in plan.attempts() if value.task_id == task_id), None)
    if attempt is None:
        raise ValueError("source revision has no allocated logical attempt")
    directory = output / "attempts" / task_id
    source = directory / "source"
    outcome_path = directory / "source-outcome.json"
    if not outcome_path.exists():
        return source, None, 0
    outcome = SourceOutcome.model_validate_json(outcome_path.read_bytes())
    if (outcome.plan_fingerprint, outcome.attempt, outcome.attempt_binding_sha256) != (
        fingerprint(plan), attempt, file_sha256(directory / "attempt.json"),
    ):
        raise ValueError("source outcome does not match its original allocation")
    _check_artifacts(source, outcome.artifact_sha256)
    if outcome.task_fingerprint is not None:
        task = TaskRecord.model_validate_json((source / "task.json").read_bytes())
        if fingerprint(task) != outcome.task_fingerprint or task.task_id != task_id:
            raise ValueError("original source task differs from its outcome")
    count = 0
    for receipt_path in sorted((directory / "revisions").glob("*/revision.json")):
        revision = SourceRevision.model_validate_json(receipt_path.read_bytes())
        if (revision.plan_fingerprint, revision.task_id, revision.sequence) != (fingerprint(plan), task_id, count + 1):
            raise ValueError("source revisions must form one contiguous logical-attempt history")
        if _within(output, revision.previous_source) != source.resolve() or revision.previous_outcome_sha256 != file_sha256(outcome_path):
            raise ValueError("source revision is not bound to the previous immutable outcome")
        request = receipt_path.parent / "request.json"
        if file_sha256(request) != revision.request_sha256:
            raise ValueError("revision request or feedback changed")
        previous_fp = outcome.task_fingerprint
        if previous_fp is None:
            recovery = json.loads(request.read_bytes())
            if outcome.status != "operational_error" or recovery.get("recovering_unbound_operational_task") is not True:
                raise ValueError("source revision needs an explicit recovery binding for the preceding operational error")
            previous_task = TaskRecord.model_validate_json((source / "task.json").read_bytes())
            if previous_task.task_id != task_id:
                raise ValueError("operational recovery belongs to another task")
            previous_fp = fingerprint(previous_task)
        if revision.previous_task_fingerprint != previous_fp:
            raise ValueError("source revision does not bind the preceding task")
        source = _within(output, revision.source_directory)
        if source != (receipt_path.parent / "source").resolve():
            raise ValueError("revision source directory differs from its owned output")
        outcome_path = receipt_path.parent / "source-outcome.json"
        if file_sha256(outcome_path) != revision.source_outcome_sha256:
            raise ValueError("revision outcome changed")
        outcome = SourceOutcome.model_validate_json(outcome_path.read_bytes())
        if (outcome.plan_fingerprint, outcome.attempt, outcome.attempt_binding_sha256) != (
            fingerprint(plan), attempt, file_sha256(directory / "attempt.json"),
        ):
            raise ValueError("revised outcome belongs to another allocation")
        _check_artifacts(source, outcome.artifact_sha256)
        if outcome.task_fingerprint is not None:
            task = TaskRecord.model_validate_json((source / "task.json").read_bytes())
            if fingerprint(task) != outcome.task_fingerprint or task.task_id != task_id:
                raise ValueError("revised task fingerprint or logical identity changed")
        count += 1
    return source, outcome, count


def run_source_revision(
    *, plan: PreproductionPlan, client, serving_bundle: Path, graph_bundle: Path, output: Path,
    task_id: str, feedback: str, preserve_goals: bool = True, resume: bool = False, runner=run_discovery_pilot,
) -> SourceOutcome:
    if not feedback.strip():
        raise ValueError("a source revision requires explicit defect feedback")
    if PreproductionPlan.model_validate_json((output / "plan.json").read_bytes()) != plan:
        raise ValueError("source revision requires the unchanged original plan")
    if configured_model_binding(client) != plan.model or effective_runtime(plan, output) != runtime_hashes():
        raise ValueError("source revision model/runtime differs from the explicitly pinned run")
    if (file_sha256(serving_bundle / "serving_report.json"), file_sha256(graph_bundle / "graph_report.json")) != (
        plan.serving_report_sha256, plan.graph_report_sha256,
    ):
        raise ValueError("source revision uses different serving/graph inputs")
    with locked_run(output):
        previous, outcome, count = current_source(plan, output, task_id)
        if outcome is None or outcome.task_fingerprint is None or outcome.status != "needs_revision":
            raise ValueError("automatic source revision requires a recorded question-quality hold")
        if ((previous / "blind/complete.json").exists() or any((previous / "blind").glob("*-request.json"))
            or (previous / "retained-source-student.json").exists()):
            raise ValueError("a started/completed student requires explicit equivalence/recovery; never reroll it automatically")
        old = TaskRecord.model_validate_json((previous / "task.json").read_bytes())
        directory = output / "attempts" / task_id
        revision_directory = directory / "revisions" / f"{count + 1:04d}"
        if revision_directory.exists() and not resume:
            raise ValueError("revision output already exists; explicitly resume its unfinished roles")
        revision_directory.mkdir(parents=True, mode=0o700, exist_ok=resume)
        prior = json.loads((directory / "attempt.json").read_bytes())["previous_questions"]
        request = {
            "plan_fingerprint": fingerprint(plan), "task_id": task_id, "sequence": count + 1,
            "previous_source": str(previous.resolve().relative_to(output.resolve())),
            "previous_task_fingerprint": fingerprint(old),
            "previous_outcome_sha256": file_sha256(previous.parent / "source-outcome.json"),
            "feedback": feedback, "preserve_goals": preserve_goals, "implementation_sha256": effective_runtime(plan, output),
        }
        immutable_json(revision_directory / "request.json", request)
        source = revision_directory / "source"
        revised_path = revision_directory / "source-outcome.json"
        if revised_path.exists():
            revised = SourceOutcome.model_validate_json(revised_path.read_bytes())
            _check_artifacts(source, revised.artifact_sha256)
        else:
            if source.exists():
                safe_unfinished_roles(source)
            task_fp = None
            try:
                result = runner(
                    client=_RevisionClient(client, old, source, preserve_goals),
                    serving_bundle=serving_bundle, graph_bundle=graph_bundle,
                    mode=outcome.attempt.mode, incident_id=outcome.attempt.incident_id, task_id=task_id,
                    output=source, limits=plan.query_limits, checkpoint_cap=plan.checkpoint_cap,
                    prior_questions=tuple(prior), resume=source.exists(), quality_gate=True,
                    revision_from=previous, revision_feedback=feedback,
                )
                task = TaskRecord.model_validate_json((source / "task.json").read_bytes())
                task_fp = fingerprint(task)
                _validate_repair(old, task, preserve_goals)
                if result.get("task_fingerprint") != fingerprint(task) or json.loads((source / "pilot_report.json").read_bytes()) != json.loads(json.dumps(result, allow_nan=False)):
                    raise ValueError("revised pilot report does not bind its actual task")
                if result["status"] == "candidate_for_mysql_validation":
                    from .quality import validate_quality_gate
                    validate_quality_gate(source, task)
                    status = "source_ready"
                elif result["status"] == "needs_revision":
                    status = "needs_revision"
                else:
                    raise ValueError("unknown revised source result")
                task_fp, reason = fingerprint(task), "Explicit same-attempt source repair; downstream gates remain required."
            except RoleAbstained as error:
                status, reason = "needs_revision", str(error)
                if (source / "task.json").exists():
                    task_fp = fingerprint(TaskRecord.model_validate_json((source / "task.json").read_bytes()))
            except (ValueError, RuntimeError, OSError, duckdb.Error) as error:
                status, reason = "operational_error", f"{type(error).__name__}: {error}"
                if task_fp is None and (source / "task.json").exists():
                    try:
                        task_fp = fingerprint(TaskRecord.model_validate_json((source / "task.json").read_bytes()))
                    except (ValueError, OSError) as artifact_error:
                        reason += f"; task artifact remains unbound: {type(artifact_error).__name__}: {artifact_error}"
            revised = SourceOutcome(
                plan_fingerprint=fingerprint(plan), attempt_binding_sha256=file_sha256(directory / "attempt.json"),
                attempt=outcome.attempt, status=status, task_fingerprint=task_fp, reason=reason,
                artifact_sha256=_artifacts(source),
            )
            immutable_json(revised_path, revised)
        immutable_json(revision_directory / "revision.json", SourceRevision(
            plan_fingerprint=fingerprint(plan), task_id=task_id, sequence=count + 1,
            previous_source=request["previous_source"], previous_outcome_sha256=request["previous_outcome_sha256"],
            previous_task_fingerprint=fingerprint(old),
            source_directory=str(source.resolve().relative_to(output.resolve())),
            source_outcome_sha256=file_sha256(revised_path), request_sha256=file_sha256(revision_directory / "request.json"),
        ))
        if effective_runtime(plan, output) != runtime_hashes():
            raise ValueError("source repair implementation changed during execution")
        if revised.status == "operational_error":
            raise RuntimeError("retained source-repair operational error: " + revised.reason)
        return revised
