# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Explicit source-backed grading amendments with independent review and reflection."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator
from sqlglot import exp

from .canonical_facts import SourceFactReference, SourceFactResolver, source_leaf
from .contracts import (
    AnswerProgram, Contract, Digest, Identifier, PublicCitation, TaskRecord, Text, TypedAnswer,
    fingerprint, require_unique,
)
from .difficulty_curation import _restore_inspections
from .evidence import EvidenceFailure, EvidenceVerifier, Finding
from .fact_curation import FactInspectionTools
from .generation import CompletionClient, run_role
from .ledger import file_sha256
from .model_panel import immutable_json
from .query import checked_select
from .scoring import compare_checkpoint_finding


POLICY_VERSION = "source-reviewed-grading-v1"
RUNTIME_FILES = (
    "grading_review.py", "canonical_facts.py", "fact_curation.py", "difficulty_curation.py",
    "contracts.py", "evidence.py", "qualified_witnesses.py", "query.py", "scoring.py",
    "generation.py", "model_panel.py", "secrl_adapter.py", "acesevals_adapter.py",
)


class SupportingEvidenceRule(Contract):
    rule_id: Identifier
    claim_id: Identifier
    table: Identifier
    rationale: Text
    programs: tuple[AnswerProgram, ...] = Field(min_length=2, max_length=2)
    review_examples: tuple[PublicCitation, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def both_backends(self):
        if {p.engine for p in self.programs} != {"duckdb", "mysql"}:
            raise ValueError("supporting evidence needs exactly one program per backend")
        if any(c.table != self.table for c in self.review_examples):
            raise ValueError("supporting evidence examples must belong to the declared source table")
        if len(set(self.review_examples)) != len(self.review_examples):
            raise ValueError("duplicate supporting-evidence examples")
        return self


class CheckpointIdentityRule(Contract):
    rule_id: Identifier
    checkpoint_id: Identifier
    canonical: SourceFactReference
    alternative: SourceFactReference
    rationale: Text

    @model_validator(mode="after")
    def same_source_subject(self):
        a, b = self.canonical, self.alternative
        if a.citation != b.citation or a == b or a.kind != "property_value" or b.kind != "property_value":
            raise ValueError("identity alternatives require distinct atomic properties of the same source record")
        if (a.json_path is None) != (b.json_path is None):
            raise ValueError("identity alternatives must use one explicit source subject representation")
        if a.json_path is not None and (a.column != b.column or not a.json_path or not b.json_path
                                        or a.json_path[:-1] != b.json_path[:-1]):
            raise ValueError("JSON identity alternatives must belong to the same named source object")
        return self


class GradingAmendment(Contract):
    policy_version: Literal["source-reviewed-grading-v1"] = POLICY_VERSION
    task_fingerprint: Digest
    revision_id: Identifier
    supporting_evidence: tuple[SupportingEvidenceRule, ...] = ()
    checkpoint_identities: tuple[CheckpointIdentityRule, ...] = ()
    rationale: Text

    @model_validator(mode="after")
    def explicit_revision(self):
        if not self.supporting_evidence and not self.checkpoint_identities:
            raise ValueError("a grading amendment must make an explicit source-backed correction")
        require_unique(tuple(rule.rule_id for rule in (*self.supporting_evidence, *self.checkpoint_identities)), "grading rule IDs")
        return self


class GradingReview(Contract):
    task_fingerprint: Digest
    policy_fingerprint: Digest
    recommendation: Literal["pass", "revise", "reject"]
    reviewed_rule_ids: tuple[Identifier, ...]
    required_proofs_preserved: bool
    supplemental_scope_relevant: bool
    identity_roles_verified: bool
    checkpoints_preserved: bool
    reasons: tuple[Text, ...] = Field(min_length=1)


class ReviewedGradingAmendment(Contract):
    policy: GradingAmendment
    reviewer: GradingReview
    reflection: GradingReview
    implementation_sha256: dict[str, Digest]

    @model_validator(mode="after")
    def independent_passing_reviews(self):
        for review in (self.reviewer, self.reflection):
            validate_review(self.policy, review)
            if not review_passes(review):
                raise ValueError("grading amendment needs both passing review and reflection")
        return self


def runtime_hashes():
    return {name: file_sha256(Path(__file__).with_name(name)) for name in RUNTIME_FILES}


def review_passes(review: GradingReview) -> bool:
    return review.recommendation == "pass" and all((
        review.required_proofs_preserved, review.supplemental_scope_relevant,
        review.identity_roles_verified, review.checkpoints_preserved,
    ))


def validate_review(policy: GradingAmendment, review: GradingReview) -> None:
    if (review.task_fingerprint, review.policy_fingerprint) != (policy.task_fingerprint, fingerprint(policy)):
        raise ValueError("grading review is bound to another task or policy")
    require_unique(review.reviewed_rule_ids, "reviewed grading rule IDs")
    if set(review.reviewed_rule_ids) != {rule.rule_id for rule in (*policy.supporting_evidence, *policy.checkpoint_identities)}:
        raise ValueError("review must explicitly cover every grading rule")


def supporting_citations(verifier: EvidenceVerifier, rule: SupportingEvidenceRule,
                         candidates: frozenset[PublicCitation]) -> frozenset[PublicCitation]:
    selected = tuple(sorted(c.record_id for c in candidates if c.table == rule.table))
    if not selected:
        return frozenset()
    program = next(p for p in rule.programs if p.engine == verifier.engine.engine)
    tree = checked_select(program.query, program.engine, set(verifier.tables), gold=True,
                          allowed_literals=verifier.allowed_literals | frozenset(verifier.tables))
    # Apply citation availability outside the unchanged semantic scope query.
    wrapped = exp.select("*").from_(tree.subquery("qualified_context")).where(
        exp.In(this=exp.column("_record_id", table="qualified_context"),
               expressions=[exp.Literal.string(record) for record in selected])
    )
    query = wrapped.sql(dialect=program.engine, comments=False)
    result = verifier.engine.execute(query)
    if result.columns.count("_record_id") != 1 or len(result.columns) < 2:
        raise EvidenceFailure("supporting queries must return source _record_id and actual source fields")
    locator = result.columns.index("_record_id")
    returned = frozenset(PublicCitation(table=rule.table, record_id=row[locator]) for row in result.rows)
    if not returned <= candidates or returned != verifier.observed_citations(result, query):
        raise EvidenceFailure("supporting rows require exact source-record and field attribution")
    return returned


def identity_values(verifier: EvidenceVerifier, rule: CheckpointIdentityRule, task: TaskRecord) -> tuple[str, str]:
    checkpoint = next((c for c in task.private_gold.checkpoints if c.checkpoint_id == rule.checkpoint_id), None)
    if checkpoint is None or checkpoint.claim.expected.format.kind != "entity":
        raise EvidenceFailure("identity alternatives require an existing scalar entity checkpoint")
    if rule.canonical.citation not in {
        PublicCitation(table=ref.table, record_id=ref.public_record_id)
        for ref in task.evidence if any(ref.evidence_id in group.evidence_ids for group in checkpoint.claim.evidence_sets)
    }:
        raise EvidenceFailure("identity source must already belong to this checkpoint's evidence")
    _, row = verifier.record_values(rule.canonical.citation)
    values = []
    for reference in (rule.canonical, rule.alternative):
        if reference.column not in row:
            raise EvidenceFailure("identity source property is unavailable")
        value = json.loads(source_leaf(row[reference.column], reference.json_path))
        if not isinstance(value, str) or not value.strip():
            raise EvidenceFailure("identity properties must resolve to nonempty scalar strings")
        values.append(value)
    if values[0] != checkpoint.claim.expected.value or values[0] == values[1]:
        raise EvidenceFailure("identity canonical value differs from the frozen checkpoint, or is not an alternative")
    return values[0], values[1]


def validate_policy(task: TaskRecord, verifier: EvidenceVerifier, policy: GradingAmendment) -> None:
    if fingerprint(task) != policy.task_fingerprint:
        raise EvidenceFailure("grading policy belongs to another task revision")
    if (task.snapshot_id, task.serving_view_id, task.graph_version) != (
        verifier.report["snapshot_id"], verifier.report["serving_view_id"], verifier.report["graph_id"],
    ):
        raise EvidenceFailure("grading policy source snapshot differs")
    claims = {"final", *(checkpoint.checkpoint_id for checkpoint in task.private_gold.checkpoints)}
    for rule in policy.supporting_evidence:
        if rule.claim_id not in claims or rule.table not in verifier.tables:
            raise EvidenceFailure("supporting evidence has an unknown claim or source")
        for program in rule.programs:
            verifier.validate_program(program)
        examples = frozenset(rule.review_examples)
        if supporting_citations(verifier, rule, examples) != examples:
            raise EvidenceFailure("declared supporting examples do not qualify under the actual source query")
    for rule in policy.checkpoint_identities:
        identity_values(verifier, rule, task)


class ReviewedEvidenceVerifier(EvidenceVerifier):
    """Opt-in policy; never changes base verifier behavior or frozen task serialization."""

    def __init__(self, bundle, engine, allowed_literals, *, task: TaskRecord, amendment: ReviewedGradingAmendment):
        amendment = ReviewedGradingAmendment.model_validate(amendment)
        if amendment.implementation_sha256 != runtime_hashes():
            raise ValueError("reviewed grading runtime changed; explicit revalidation is required")
        super().__init__(bundle, engine, allowed_literals)
        try:
            self.task = task
            self.amendment = amendment
            self.policy = amendment.policy
            self.claim_ids = {fingerprint(task.private_gold.final): "final",
                              **{fingerprint(c.claim): c.checkpoint_id for c in task.private_gold.checkpoints}}
            if len(self.claim_ids) != len(task.private_gold.checkpoints) + 1:
                raise EvidenceFailure("ambiguous equal claims require explicit distinct objectives before amendment")
            validate_policy(task, self, self.policy)
            self.identities = [(rule, identity_values(self, rule, task)) for rule in self.policy.checkpoint_identities]
        except (ValueError, RuntimeError):
            self.close()
            raise

    def preflight(self, task):
        if fingerprint(task) != self.policy.task_fingerprint:
            raise EvidenceFailure("reviewed verifier cannot evaluate another task")
        return super().preflight(task)

    def evidence_matches(self, finding, witnesses, *, claim=None):
        if claim is None:
            return super().evidence_matches(finding, witnesses)
        claim_id = self.claim_ids.get(fingerprint(claim))
        if claim_id is None:
            raise EvidenceFailure("claim is not covered by this task-bound grading policy")
        if super().evidence_matches(finding, witnesses, claim=claim):
            return True
        citations = frozenset(finding.citations)
        if not citations or len(citations) != len(finding.citations):
            return False
        qualified = self.qualified_proofs(claim, citations)
        relevant = frozenset(c for proof in qualified for c in proof.relevant) if qualified else frozenset().union(*witnesses)
        core = citations & relevant
        if not super().evidence_matches(finding.model_copy(update={"citations": tuple(core)}), witnesses, claim=claim):
            return False
        extras = citations - core
        supported = frozenset(c for rule in self.policy.supporting_evidence if rule.claim_id == claim_id
                              for c in supporting_citations(self, rule, extras))
        return extras <= supported

    def evaluate(self, task, submission, findings, **kwargs):
        if fingerprint(task) != self.policy.task_fingerprint:
            raise EvidenceFailure("reviewed verifier cannot normalize another task's findings")
        original = tuple(findings)
        normalized = list(original)
        for rule, (canonical, alternative) in self.identities:
            checkpoint = next(c for c in task.private_gold.checkpoints if c.checkpoint_id == rule.checkpoint_id)
            expected_alternative = TypedAnswer(format=checkpoint.claim.expected.format, value=alternative)
            for finding in original:
                if rule.canonical.citation in finding.citations and compare_checkpoint_finding(expected_alternative, finding.answer):
                    normalized.append(finding.model_copy(update={
                        "answer": TypedAnswer(format=checkpoint.claim.expected.format, value=canonical),
                    }))
        result = super().evaluate(task, submission, tuple(normalized), **kwargs)
        data = result.model_dump(mode="json")
        for component in (data["answer_correctness"], data["final_evidence"], *data["checkpoints"]):
            component["evaluator_version"] = POLICY_VERSION + ":" + fingerprint(self.amendment)
            component["explanation"] += " Explicit task-bound source-reviewed grading amendment " + self.policy.revision_id + "."
        return type(result).model_validate_json(json.dumps(data))


REVIEW_INSTRUCTIONS = """Audit a proposed explicit grading correction against the real public source.
You are not grading a model by reputation and receive no model identities, successes or desired difficulty bands.
Retrieve source _record_id and actual fields for every required citation independently.
Check the full final/checkpoint goals and source scope, each SQL rule in both dialects, and each identity property.
Supplemental comparisons/context must be relevant but NEVER replace missing complete required evidence.
Do not treat proximity, membership alone or a later comparison as proof of the final result.
Same-entity aliases require the same source-bound subject/role, not coincidental equal strings.
Challenge unrelated records, wrong policy/subject/window, omitted proof members and cross-object identity splicing.
Do not loosen evidence gates, remove checkpoints, rewrite answers or approve a rule solely to improve scores.
Your recommendation can block an amendment but cannot directly override a deterministic grade.
Return a passing review only when every rule is source-supported; otherwise revise/reject with concrete reasons.
"""


def review_grading_amendment(*, task: TaskRecord, policy: GradingAmendment, verifier: EvidenceVerifier,
                             client: CompletionClient, output: Path, resume: bool = False):
    if verifier.engine.engine != "duckdb":
        raise ValueError("grading review tools require the read-only DuckDB source")
    output.mkdir(parents=True, mode=0o700, exist_ok=resume)
    implementation = runtime_hashes()
    validate_policy(task, verifier, policy)
    required = {
        PublicCitation(table=ref.table, record_id=ref.public_record_id) for ref in task.evidence
    } | {citation for rule in policy.supporting_evidence for citation in rule.review_examples}
    required.update(rule.canonical.citation for rule in policy.checkpoint_identities)
    binding = {"task_fingerprint": fingerprint(task), "policy_fingerprint": fingerprint(policy),
               "implementation_sha256": implementation, "query_limits": verifier.engine.limits.model_dump(mode="json")}
    immutable_json(output / "binding.json", binding)
    immutable_json(output / "policy.json", policy)
    context = {
        "task": task.model_dump(mode="json"), "policy": policy.model_dump(mode="json"),
        "task_fingerprint": fingerprint(task), "policy_fingerprint": fingerprint(policy),
        "required_citations": [c.model_dump(mode="json") for c in sorted(required, key=lambda c: (c.table, c.record_id))],
    }
    reviews = []
    for role in ("reviewer", "reflection"):
        tools = FactInspectionTools(SourceFactResolver(verifier))
        if resume:
            _restore_inspections(tools, output / role)

        def validate(value):
            validate_review(policy, value)
            if review_passes(value) and required - tools.observed:
                raise ValueError("reviewer/reflection must independently inspect all required actual source records")

        role_context = dict(context)
        if reviews:
            role_context["prior_review"] = reviews[0].model_dump(mode="json")
            role_context["reflection_task"] = "Second-review the prior verdict. Independently retrieve sources; challenge its reasoning and identify missed defects."
        review = run_role(client, tools, "grading-" + role, REVIEW_INSTRUCTIONS, role_context,
                          GradingReview, output / role, resume=resume, validate_result=validate)
        reviews.append(review)
    if runtime_hashes() != implementation:
        raise ValueError("grading review implementation changed during the review")
    artifact_hashes = {str(path.relative_to(output)): file_sha256(path)
                       for role in ("reviewer", "reflection") for path in sorted((output / role).glob("*.json"))}
    result = None
    if all(review_passes(review) for review in reviews):
        result = ReviewedGradingAmendment(policy=policy, reviewer=reviews[0], reflection=reviews[1],
                                         implementation_sha256=implementation)
        immutable_json(output / "reviewed-policy.json", result)
    immutable_json(output / "review-report.json", {
        "status": "reviewed" if result is not None else "needs_revision",
        "policy_fingerprint": fingerprint(policy), "task_fingerprint": fingerprint(task),
        "review_artifacts_sha256": artifact_hashes, "scores_changed": False, "release_approved": False,
    })
    return result


def load_reviewed_grading(directory: Path) -> ReviewedGradingAmendment:
    reviewed = ReviewedGradingAmendment.model_validate_json((directory / "reviewed-policy.json").read_bytes())
    report = json.loads((directory / "review-report.json").read_bytes())
    binding = json.loads((directory / "binding.json").read_bytes())
    if report["status"] != "reviewed" or binding["implementation_sha256"] != reviewed.implementation_sha256 or (
        binding["task_fingerprint"], binding["policy_fingerprint"]
    ) != (reviewed.policy.task_fingerprint, fingerprint(reviewed.policy)):
        raise ValueError("grading review did not complete under its recorded implementation")
    if reviewed.implementation_sha256 != runtime_hashes():
        raise ValueError("grading policy producer changed; explicit revalidation is required")
    if report["policy_fingerprint"] != fingerprint(reviewed.policy) or report["task_fingerprint"] != reviewed.policy.task_fingerprint:
        raise ValueError("grading review report belongs to another task or policy")
    if GradingAmendment.model_validate_json((directory / "policy.json").read_bytes()) != reviewed.policy:
        raise ValueError("reviewed grading policy changed")
    actual = {str(path.relative_to(directory)): file_sha256(path)
              for role in ("reviewer", "reflection") for path in sorted((directory / role).glob("*.json"))}
    if actual != report["review_artifacts_sha256"]:
        raise ValueError("grading review/reflection trace changed")
    for role, expected in (("reviewer", reviewed.reviewer), ("reflection", reviewed.reflection)):
        review = GradingReview.model_validate_json((directory / role / "result.json").read_bytes())
        complete = json.loads((directory / role / "complete.json").read_bytes())
        if review != expected or complete["result_fingerprint"] != fingerprint(review):
            raise ValueError("grading review does not match its completed role")
    return reviewed
