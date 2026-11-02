# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Opt-in source quality diagnostics and independently reviewed selector semantics."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal

import duckdb
import sqlglot
from sqlglot import exp
from sqlglot.jsonpath import parse as parse_json_path

from .contracts import (
    Contract, Digest, Identifier, NonnegativeInt, PublicCitation, QualifiedWitnessProgram,
    TaskRecord, Text, TypedAnswer, fingerprint, require_unique,
)
from .evidence import EvidenceVerifier, answer_from_rows
from .generation import CompletionClient, ReviewResult, run_role
from .ledger import attach_readonly, file_sha256
from .mysql_serving import load_serving_report
from .query import Engine, PublicQueryEngine, QueryLimits
from .scoring import compare_typed_answers
from .sources import quote_identifier


QUALITY_VERSION = "source-quality-v1"
RUNTIME_FILES = (
    "quality.py", "pilot.py", "generation.py", "azure_generation.py", "discovery_context.py",
    "contracts.py", "evidence.py", "qualified_witnesses.py", "query.py", "scoring.py",
    "canonical_facts.py", "fact_curation.py", "difficulty.py", "difficulty_curation.py",
    "serving.py", "mysql_serving.py", "ledger.py", "sources.py",
)
LIMITATIONS = (
    "Proof-alone collection reproduction is a lost/extra-member diagnostic, not a general proof of "
    "sufficiency for counts, absence, ranking, common values or all source-qualified candidates. "
    "The selector scan is conservative and not a complete SQL semantic analysis. Both require "
    "independent source inspection. This source audit executes DuckDB only; actual MySQL validation "
    "and targeted semantic-preserving backend mutations remain separate requirements."
)
AUTHOR_QUALITY_INSTRUCTIONS = """
The source-quality-v1 gate runs before the blind solve. Every alternative must independently
support the WHOLE final/checkpoint collection. Private scope anchors are not implicit proof.
Select JSON entities, parameters, authentication steps and policies by their named/typed roles,
not incidental array positions. Match structured configurations independently of serialization.
Use JSON traversal for membership and role lookup. Positional selection is appropriate only
when order itself is part of the PUBLIC investigative objective; exact serialized bytes likewise
require an explicitly representation-sensitive public objective. Do not invent such wording
merely to excuse an incidental selector. Keep all original time, identity and first/next criteria.
If the proof or checkpoint is defective, rework the question and rubric; never remove checkpoints.
"""
REVIEW_QUALITY_INSTRUCTIONS = """
Return QualityAssessment, containing your ordinary independent review and additional quality checks.
The audit is diagnostic, not proof of semantic correctness. Inspect EVERY required_review_citation
with actual source _record_id and source fields, including all representative alternatives.
Review complete final/checkpoint proofs, including collection coverage, negative/count/ranking
cohorts, and source-qualified catalogs/bundles. Review every backend program, not just flagged SQL.
Do not claim MySQL execution: the available sql tool executes DuckDB.
Provide exactly one disposition for every selector issue:
- repair_required: incidental ordering, serialization or unresolved semantics; recommend revision.
- public_order: genuine publicly stated ordering, with an exact public_quote and source justification.
- public_bytes: genuine publicly stated byte/representation comparison, with an exact public_quote.
- complete_traversal: a computed JSON path visits named/typed elements, not a hidden fixed position.
- scalar_membership: text tests only an independently verified, unambiguous scalar member, not
  key order, whitespace, fixed offsets or a serialized object/configuration. Explain escaping,
  token boundaries and source types; prefer structured traversal if these are not established.
- derived_scalar: a conservative JSON-column-name/alias flag actually operates on a decoded scalar.
Do not retrofit 'first array element' or 'identical bytes' into a question that asks a semantic role.
No disposition waives a failed collection fixture. Unknown semantics require revision, not a pass.
Your review cannot see student outcomes, set difficulty bands, change the split or approve release.
"""


class SelectorIssue(Contract):
    claim_id: Identifier
    program_id: Identifier
    engine: Engine
    surface: Literal["answer", "witness", "obligations", "candidates"]
    query_sha256: Digest
    kind: Literal["positional_json_path", "computed_json_path", "raw_json_comparison", "raw_json_text"]
    expression: Text


class CollectionCheck(Contract):
    claim_id: Identifier
    program_id: Identifier
    citations: tuple[PublicCitation, ...]
    fixture: Literal["declared_evidence_union", "alternative_alone"]
    expected: TypedAnswer
    actual: TypedAnswer
    reproduces_collection: bool


class QualityAudit(Contract):
    policy_version: Literal["source-quality-v1"] = QUALITY_VERSION
    task_fingerprint: Digest
    serving_view_id: Identifier
    query_limits: QueryLimits
    implementation_sha256: dict[str, Digest]
    programs_checked: NonnegativeInt
    issues: tuple[SelectorIssue, ...]
    collections: tuple[CollectionCheck, ...]
    required_review_citations: tuple[PublicCitation, ...]
    limitations: Text = LIMITATIONS
    native_executed: Literal[False] = False
    release_approved: Literal[False] = False

    def collection_failures(self) -> tuple[CollectionCheck, ...]:
        return tuple(check for check in self.collections if not check.reproduces_collection)


class SelectorDisposition(Contract):
    issue_fingerprint: Digest
    decision: Literal[
        "repair_required", "public_order", "public_bytes", "complete_traversal",
        "scalar_membership", "derived_scalar",
    ]
    public_quote: Text | None
    source_justification: Text


class QualityAssessment(Contract):
    task_fingerprint: Digest
    audit_fingerprint: Digest
    review: ReviewResult
    whole_claim_proofs_supported: bool
    json_semantics_supported: bool
    dispositions: tuple[SelectorDisposition, ...]


def runtime_hashes() -> dict[str, str]:
    return {name: file_sha256(Path(__file__).with_name(name)) for name in RUNTIME_FILES}


def _claims(task: TaskRecord):
    return (("final", task.private_gold.final), *((c.checkpoint_id, c.claim) for c in task.private_gold.checkpoints))


def _surfaces(task: TaskRecord):
    for claim_id, claim in _claims(task):
        for surface, programs in (("answer", claim.programs), ("witness", claim.witness_programs)):
            for program in programs:
                yield claim_id, program, surface, program.query
                if isinstance(program, QualifiedWitnessProgram):
                    yield claim_id, program, "obligations", program.obligations_query
                    yield claim_id, program, "candidates", program.candidates_query


def scan_selectors(query: str, engine: Engine, json_columns: frozenset[str]) -> tuple[tuple[str, str], ...]:
    """Flag concrete patterns; disposition remains a source-inspecting semantic decision."""
    tree = sqlglot.parse_one(query, read=engine)
    names = {name.casefold() for name in json_columns}
    for node in tree.find_all(exp.JSONExtract, exp.JSONExtractScalar, exp.JSONTable):
        if isinstance(node.this, exp.Column):
            names.add(node.this.name.casefold())
    changed = True
    while changed:
        changed = False
        for node in tree.find_all(exp.Alias):
            if isinstance(node.this, exp.Column) and node.this.name.casefold() in names and node.alias.casefold() not in names:
                names.add(node.alias.casefold())
                changed = True
    found = set()
    for node in tree.walk():
        if isinstance(node, exp.JSONPathSubscript) and isinstance(node.this, int):
            found.add(("positional_json_path", node.parent.sql(dialect=engine)))
        # JSON_TABLE column paths are Literals rather than JSONPath nodes in SQLGlot 27.
        path = node.args.get("path")
        if isinstance(path, exp.Literal) and path.is_string and any(
            isinstance(part.this, int) for part in parse_json_path(path.this, dialect=engine).find_all(exp.JSONPathSubscript)
        ):
            found.add(("positional_json_path", node.sql(dialect=engine)))
        if isinstance(node, (exp.JSONExtract, exp.JSONExtractScalar)):
            if not isinstance(node.expression, exp.JSONPath):
                found.add(("computed_json_path", node.sql(dialect=engine)))
        direct_json = any(isinstance(child, exp.Column) and child.name.casefold() in names
                          for child in node.iter_expressions())
        if direct_json and isinstance(node, (exp.EQ, exp.NEQ, exp.In)):
            found.add(("raw_json_comparison", node.sql(dialect=engine)))
        if direct_json and isinstance(node, (exp.Like, exp.ILike, exp.Substring, exp.StrPosition)):
            found.add(("raw_json_text", node.sql(dialect=engine)))
    return tuple(sorted(found))


def audit_source_quality(task: TaskRecord, verifier: EvidenceVerifier, serving_bundle: Path) -> QualityAudit:
    if verifier.engine.engine != "duckdb":
        raise ValueError("source quality fixtures require a DuckDB source verifier")
    if load_serving_report(serving_bundle) != verifier.report:
        raise ValueError("source quality fixture bundle differs from its verified serving source")
    implementation = runtime_hashes()
    require_unique(tuple(name for name, _ in _claims(task)), "quality claim IDs")
    proofs = verifier.preflight(task)
    json_columns = frozenset(
        column["name"] for table in verifier.report["policy"]["tables"] for column in table["columns"]
        if column["action"] in ("json", "redact_json")
    )
    issues = []
    surfaces = tuple(_surfaces(task))
    for claim_id, program, surface, query in surfaces:
        for kind, expression in scan_selectors(query, program.engine, json_columns):
            issues.append(SelectorIssue(
                claim_id=claim_id, program_id=program.program_id, engine=program.engine, surface=surface,
                query_sha256=hashlib.sha256(query.encode()).hexdigest(), kind=kind, expression=expression,
            ))
    required = tuple(sorted(
        {PublicCitation(table=ref.table, record_id=ref.public_record_id) for ref in task.evidence}
        | {citation for groups in proofs.values() for group in groups for citation in group},
        key=lambda citation: (citation.table, citation.record_id),
    ))
    checks = []
    collection_claims = [(name, claim) for name, claim in _claims(task)
                         if isinstance(claim.expected.value, tuple) and len(claim.expected.value) > 1]
    if collection_claims:
        connection = duckdb.connect(config={"threads": 1, "memory_limit": "512MB"})
        try:
            attach_readonly(connection, serving_bundle / verifier.report["public_database"]["path"], "source")
            engine = PublicQueryEngine(connection, "duckdb", set(verifier.tables), verifier.engine.limits,
                                       verifier.engine.serving_view_id)

            def restrict(citations: tuple[PublicCitation, ...]) -> None:
                for table in verifier.tables:
                    ids = sorted({citation.record_id for citation in citations if citation.table == table})
                    predicate = "_record_id IN (" + ",".join("'" + value.replace("'", "''") + "'" for value in ids) + ")" if ids else "FALSE"
                    quoted = quote_identifier(table)
                    connection.execute(f"CREATE OR REPLACE TEMP VIEW {quoted} AS SELECT * FROM source.{quoted} WHERE {predicate}")

            for claim_id, claim in collection_claims:
                groups = [("declared_evidence_union", required)]
                groups.extend(("alternative_alone", tuple(sorted(group, key=lambda c: (c.table, c.record_id))))
                              for group in proofs[claim_id])
                for fixture, citations in groups:
                    restrict(citations)
                    for program in claim.programs:
                        if program.engine != "duckdb":
                            continue
                        result = engine.execute(program.query, gold=True,
                                                allowed_literals=verifier.allowed_literals | frozenset(verifier.tables))
                        actual = answer_from_rows(claim, result.rows)
                        if actual.format.kind == "set" and isinstance(actual.value, tuple):
                            actual = actual.model_copy(update={"value": tuple(sorted(actual.value))})
                        checks.append(CollectionCheck(
                            claim_id=claim_id, program_id=program.program_id, citations=citations, fixture=fixture,
                            expected=claim.expected, actual=actual,
                            reproduces_collection=compare_typed_answers(claim.expected, actual),
                        ))
        finally:
            connection.close()
    if runtime_hashes() != implementation:
        raise ValueError("source quality implementation changed during the audit")
    return QualityAudit(
        task_fingerprint=fingerprint(task), serving_view_id=task.serving_view_id,
        query_limits=verifier.engine.limits, implementation_sha256=implementation,
        programs_checked=len(surfaces), issues=tuple(issues), collections=tuple(checks),
        required_review_citations=required,
    )


def assessment_passes(task: TaskRecord, audit: QualityAudit, assessment: QualityAssessment) -> bool:
    if (audit.task_fingerprint, assessment.task_fingerprint, assessment.audit_fingerprint) != (
        fingerprint(task), fingerprint(task), fingerprint(audit),
    ):
        raise ValueError("source quality assessment belongs to different task/audit inputs")
    require_unique(tuple(d.issue_fingerprint for d in assessment.dispositions), "selector dispositions")
    dispositions = {d.issue_fingerprint: d for d in assessment.dispositions}
    if dispositions.keys() != {fingerprint(issue) for issue in audit.issues}:
        raise ValueError("source quality review must explicitly cover every selector issue")
    allowed = {
        "positional_json_path": {"public_order"},
        "computed_json_path": {"public_order", "complete_traversal"},
        "raw_json_comparison": {"public_bytes", "derived_scalar"},
        "raw_json_text": {"public_bytes", "scalar_membership", "derived_scalar"},
    }
    for issue in audit.issues:
        disposition = dispositions[fingerprint(issue)]
        if disposition.decision == "repair_required":
            continue
        if disposition.decision not in allowed[issue.kind]:
            raise ValueError("selector disposition does not address this kind of risk")
        if disposition.decision in ("public_order", "public_bytes") and (
            disposition.public_quote is None or not any(
                disposition.public_quote in text for text in (task.question, task.context)
            )
        ):
            raise ValueError("ordered/representation semantics require an exact public quote")
    review = assessment.review
    return not audit.collection_failures() and all((
        assessment.whole_claim_proofs_supported, assessment.json_semantics_supported,
        review.recommendation == "pass", review.scope_supported, review.evidence_independent,
        review.causal_claims_supported, review.wording_leakage_free, review.literal_justifications_supported,
        review.answer_unambiguous, review.checkpoints_distinct_and_supported,
        all(d.decision != "repair_required" for d in assessment.dispositions),
    ))


def _persist(path: Path, value: Contract | dict) -> None:
    data = value.model_dump(mode="json") if isinstance(value, Contract) else json.loads(json.dumps(value, allow_nan=False))
    if path.exists():
        if json.loads(path.read_text()) != data:
            raise ValueError(f"source quality artifact changed: {path.name}")
    else:
        with path.open("x") as stream:
            stream.write(json.dumps(data, indent=2) + "\n")


def run_quality_gate(
    *, client: CompletionClient, task: TaskRecord, verifier: EvidenceVerifier, serving_bundle: Path,
    output: Path, instructions: str, review_context: dict, resume: bool = False,
) -> tuple[dict, ReviewResult | None]:
    from .canonical_facts import SourceFactResolver
    from .difficulty_curation import _restore_inspections
    from .fact_curation import FactInspectionTools

    output.mkdir(mode=0o700, parents=True, exist_ok=resume)
    audit = audit_source_quality(task, verifier, serving_bundle)
    _persist(output / "audit.json", audit)
    assessment = None
    if not audit.collection_failures():
        tools = FactInspectionTools(SourceFactResolver(verifier))
        if resume:
            _restore_inspections(tools, output / "reviewer")

        def validate(value: QualityAssessment) -> None:
            passed = assessment_passes(task, audit, value)
            for citation in value.review.counterevidence:
                verifier.citation_lineage(citation)
            if passed and set(audit.required_review_citations) - tools.observed:
                raise ValueError("quality reviewer must inspect every required source record with actual source fields")

        assessment = run_role(
            client, tools, "quality-refuter", instructions + REVIEW_QUALITY_INSTRUCTIONS,
            {**review_context, "public_task": task.public_task().model_dump(mode="json"),
             "audit": audit.model_dump(mode="json"), "audit_fingerprint": fingerprint(audit)},
            QualityAssessment, output / "reviewer", resume=resume, validate_result=validate,
        )
    if audit.implementation_sha256 != runtime_hashes():
        raise ValueError("source quality implementation changed during review")
    gate = {
        "policy_version": QUALITY_VERSION, "task_fingerprint": fingerprint(task),
        "audit_fingerprint": fingerprint(audit),
        "assessment_fingerprint": fingerprint(assessment) if assessment is not None else None,
        "status": "pass" if assessment is not None and assessment_passes(task, audit, assessment) else "needs_revision",
        "collection_failure_count": len(audit.collection_failures()),
        "review_artifacts_sha256": {
            path.name: file_sha256(path) for path in sorted((output / "reviewer").glob("*.json"))
        },
        "release_approved": False,
    }
    _persist(output / "gate.json", gate)
    return gate, assessment.review if assessment is not None else None


def validate_quality_gate(candidate: Path, task: TaskRecord) -> None:
    """Validate opt-in source artifacts before admitting a native evaluation."""
    audit = QualityAudit.model_validate_json((candidate / "quality/audit.json").read_bytes())
    assessment = QualityAssessment.model_validate_json((candidate / "quality/reviewer/result.json").read_bytes())
    gate = json.loads((candidate / "quality/gate.json").read_text())
    complete = json.loads((candidate / "quality/reviewer/complete.json").read_text())
    policy = json.loads((candidate / "execution-policy.json").read_text())
    review = ReviewResult.model_validate_json((candidate / "refuter/result.json").read_bytes())
    if audit.implementation_sha256 != runtime_hashes():
        from .preproduction_revisions import validate_source_audit_runtime
        validate_source_audit_runtime(candidate, task, audit.implementation_sha256)
    if (policy.get("source_quality_runtime_sha256") != audit.implementation_sha256
        or policy.get("query_limits") != audit.query_limits.model_dump(mode="json")
        or gate.get("review_artifacts_sha256") != {
            path.name: file_sha256(path) for path in sorted((candidate / "quality/reviewer").glob("*.json"))
        }):
        raise ValueError("source quality execution policy or recorded review artifacts changed")
    if not assessment_passes(task, audit, assessment) or review != assessment.review or (
        gate.get("policy_version"), gate.get("task_fingerprint"), gate.get("audit_fingerprint"),
        gate.get("assessment_fingerprint"), gate.get("status"), complete.get("result_fingerprint"),
    ) != (QUALITY_VERSION, fingerprint(task), fingerprint(audit), fingerprint(assessment), "pass", fingerprint(assessment)):
        raise ValueError("source quality gate or refuter projection is not bound to the passing assessment")
