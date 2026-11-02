# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Strict I0 contracts. Structural validity is not evidence or release approval."""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime, timezone
from fractions import Fraction as Rational
from typing import Annotated, Literal, TypeAlias

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    StringConstraints,
    model_validator,
)


SELECTED_INCIDENTS = (5, 34, 36, 38, 39, 55, 133, 134, 166, 322)
REQUIRED_GATES = (
    "schema", "source_coverage", "identity_evidence", "evidence_independence",
    "scope", "executable_answer", "checkpoint_rubric", "query_integrity",
    "uniqueness", "wording_leakage", "blind_verification", "refutation",
    "serving_parity", "split_review", "release_review",
)


def nonblank(value: str) -> str:
    if not value.strip():
        raise ValueError("must not be blank")
    return value


Text = Annotated[str, AfterValidator(nonblank)]
Identifier = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")]
Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
PositiveInt = Annotated[int, Field(gt=0)]
NonnegativeInt = Annotated[int, Field(ge=0)]
PositiveFloat = Annotated[float, Field(gt=0)]
Fraction = Annotated[float, Field(ge=0, le=1)]
AnswerKind = Literal["entity", "set", "ordered_list", "number", "timestamp", "boolean"]
AnswerValue: TypeAlias = StrictStr | StrictInt | StrictFloat | StrictBool | tuple[StrictStr, ...]


def require_unique(values: tuple[str, ...], description: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"duplicate {description}")


def fingerprint(value: BaseModel) -> str:
    encoded = json.dumps(
        value.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class Contract(BaseModel):
    model_config = ConfigDict(
        extra="forbid", strict=True, frozen=True, revalidate_instances="always",
        allow_inf_nan=False,
    )


class SourceFile(Contract):
    source_id: Identifier
    path: Text
    sha256: Digest
    size_bytes: NonnegativeInt
    source_kind: Literal["tenant_duckdb", "incident_csv", "metadata", "graph_baseline"]


class SnapshotManifest(Contract):
    schema_version: Literal["1"] = "1"
    snapshot_id: Identifier
    created_at: AwareDatetime
    sources: Annotated[tuple[SourceFile, ...], Field(min_length=1)]
    provenance_limits: tuple[Text, ...]
    normalization_version: Identifier | None = None
    normalizer_sha256: Digest | None = None

    @model_validator(mode="after")
    def unique_sources(self) -> SnapshotManifest:
        if (self.normalization_version is None) != (self.normalizer_sha256 is None):
            raise ValueError("normalization version and implementation digest must be declared together")
        require_unique(tuple(s.source_id for s in self.sources), "source IDs")
        require_unique(tuple(s.path for s in self.sources), "source paths")
        return self


class EvidenceReference(Contract):
    evidence_id: Identifier
    snapshot_id: Identifier
    source_id: Identifier
    table: Identifier
    private_locator: Text
    content_sha256: Digest
    public_record_id: Identifier
    lineage: Literal["behavior", "security_control", "detector_derived", "context", "metadata"]


class PublicCitation(Contract):
    table: Identifier
    record_id: Identifier


class CaseManifest(Contract):
    schema_version: Literal["1"] = "1"
    snapshot_id: Identifier
    incident_id: PositiveInt
    latest_incident_evidence_id: Identifier
    source_classification: Text | None
    project_classification: Literal["TruePositive"] = "TruePositive"
    designation_basis: Literal["project_assumption", "source_label"]
    current_alert_ids: tuple[Identifier, ...]
    exclusions: tuple[Text, ...]

    @model_validator(mode="after")
    def selected_case(self) -> CaseManifest:
        if self.incident_id not in SELECTED_INCIDENTS:
            raise ValueError("incident is outside the ten selected benchmark scenarios")
        require_unique(self.current_alert_ids, "current alert IDs")
        required = {
            5: "missing-alert:46f3d4b8-060c-4022-c190-4d88954a6a2e",
            322: "missing-source:SquidProxy",
        }.get(self.incident_id)
        if required is not None and required not in self.exclusions:
            raise ValueError(f"case manifest must retain exclusion {required}")
        if self.designation_basis == "source_label" and self.source_classification != "TruePositive":
            raise ValueError("source-label designation requires a source TP classification")
        return self


class HistoricalMembership(Contract):
    snapshot_id: Identifier
    incident_id: PositiveInt
    alert_id: Identifier
    status: Literal["historical_removed"] = "historical_removed"
    last_present_at: AwareDatetime
    first_absent_at: AwareDatetime
    before_evidence_id: Identifier
    after_evidence_id: Identifier
    other_current_incidents: tuple[PositiveInt, ...]
    current_relevance: Literal["not_established"] = "not_established"

    @model_validator(mode="after")
    def valid_removal(self) -> HistoricalMembership:
        if self.first_absent_at <= self.last_present_at:
            raise ValueError("removal bounds must be strictly ordered")
        if self.before_evidence_id == self.after_evidence_id:
            raise ValueError("removal requires two different source observations")
        if self.incident_id in self.other_current_incidents:
            raise ValueError("a removed link cannot also be current in that incident")
        if len(set(self.other_current_incidents)) != len(self.other_current_incidents):
            raise ValueError("duplicate current incident IDs")
        return self


class TimeWindow(Contract):
    start: AwareDatetime
    end: AwareDatetime

    @model_validator(mode="after")
    def ordered(self) -> TimeWindow:
        if self.end < self.start:
            raise ValueError("end must not precede start")
        return self


class PublicScope(Contract):
    mode: Literal["tenant", "incident"]
    incident_id: PositiveInt | None

    @model_validator(mode="after")
    def scope_identity(self) -> PublicScope:
        if self.mode == "tenant" and self.incident_id is not None:
            raise ValueError("tenant scope must not declare an incident ID")
        if self.mode == "incident" and self.incident_id not in SELECTED_INCIDENTS:
            raise ValueError("incident scope requires one of the ten selected incidents")
        return self


class TaskScope(PublicScope):
    anchor_evidence_ids: tuple[Identifier, ...]
    relevance_rationale: Text
    answer_window: TimeWindow

    @model_validator(mode="after")
    def anchored(self) -> TaskScope:
        require_unique(self.anchor_evidence_ids, "anchor IDs")
        if self.mode == "incident" and not self.anchor_evidence_ids:
            raise ValueError("incident scope requires a selected incident and evidence anchors")
        return self


class AnswerFormat(Contract):
    kind: AnswerKind
    semantic_kind: Identifier
    normalization: Literal["exact", "casefold"] = "exact"
    tolerance: Annotated[float, Field(ge=0)] = 0.0
    units: Text | None = None

    @model_validator(mode="after")
    def applicable_options(self) -> AnswerFormat:
        if self.kind in ("number", "timestamp"):
            if self.normalization != "exact":
                raise ValueError("casefold normalization applies only to text answers")
            if self.units is None or (self.kind == "timestamp" and self.units != "seconds"):
                raise ValueError("numeric answers need units; timestamp tolerance uses seconds")
        elif self.units is not None or self.tolerance != 0:
            raise ValueError("units and tolerance apply only to numbers and timestamps")
        if self.kind == "boolean" and self.normalization != "exact":
            raise ValueError("boolean answers use exact normalization")
        return self


def exact_timestamp_seconds(value: str) -> Rational:
    timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("timestamp answer must include its timezone")
    delta = timestamp - datetime(1970, 1, 1, tzinfo=timezone.utc)
    result = Rational((delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds, 1000000)
    match = re.fullmatch(r"\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}[.,](\d+)(?:Z|[+-]\d{2}(?::?\d{2})?)", value)
    if match:
        result += Rational(int(match[1]), 10 ** len(match[1])) - Rational(timestamp.microsecond, 1000000)
    elif re.search(r"[.,]\d{7,}", value):
        raise ValueError("submicrosecond precision requires canonical ISO date/time with seconds and a whole-minute offset")
    return result


class TypedAnswer(Contract):
    format: AnswerFormat
    value: AnswerValue

    @model_validator(mode="after")
    def correct_value_type(self) -> TypedAnswer:
        kind, value = self.format.kind, self.value
        if kind in ("entity", "timestamp"):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{kind} answer requires a nonblank string")
            if kind == "timestamp":
                exact_timestamp_seconds(value)
        elif kind == "number":
            if type(value) not in (int, float):
                raise ValueError("number answer must be numeric, not boolean or text")
        elif kind == "boolean":
            if type(value) is not bool:
                raise ValueError("boolean answer must be a JSON boolean")
        elif kind in ("set", "ordered_list"):
            if not isinstance(value, tuple) or any(not v.strip() for v in value):
                raise ValueError("collection answer requires an array of nonblank strings")
            if kind == "set":
                normalized = tuple(v.casefold() for v in value) if self.format.normalization == "casefold" else value
                require_unique(normalized, "set answer items")
        return self


class AnswerProgram(Contract):
    program_id: Identifier
    engine: Literal["duckdb", "mysql"]
    query: Text


class QualifiedWitnessProgram(AnswerProgram):
    witness_policy: Literal["source-qualified-obligations-v1"]
    obligations_query: Text
    candidates_query: Text


WitnessProgram: TypeAlias = QualifiedWitnessProgram | AnswerProgram


class EvidenceSet(Contract):
    evidence_ids: Annotated[tuple[Identifier, ...], Field(min_length=1)]
    rationale: Text

    @model_validator(mode="after")
    def unique_evidence(self) -> EvidenceSet:
        require_unique(self.evidence_ids, "evidence IDs")
        return self


class ClaimCheck(Contract):
    expected: TypedAnswer
    programs: Annotated[tuple[AnswerProgram, ...], Field(min_length=1)]
    evidence_sets: Annotated[tuple[EvidenceSet, ...], Field(min_length=1)]
    witness_programs: tuple[WitnessProgram, ...] = ()
    requires_behavior_evidence: bool = True

    @model_validator(mode="after")
    def unique_programs(self) -> ClaimCheck:
        require_unique(tuple(p.program_id for p in self.programs), "program IDs")
        require_unique(tuple(p.program_id for p in (*self.programs, *self.witness_programs)), "claim program IDs")
        if len({isinstance(p, QualifiedWitnessProgram) for p in self.witness_programs}) > 1:
            raise ValueError("a claim cannot mix enumerated and source-qualified witness policies")
        return self


class DiscoveryCheckpoint(Contract):
    checkpoint_id: Identifier
    objective: Text
    claim: ClaimCheck
    max_score: PositiveFloat
    weight: PositiveFloat
    depends_on: tuple[Identifier, ...] = ()


class PrivateGold(Contract):
    final: ClaimCheck
    checkpoints: Annotated[tuple[DiscoveryCheckpoint, ...], Field(min_length=1)]
    solution: Annotated[tuple[Text, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def valid_dependencies(self) -> PrivateGold:
        ids = tuple(c.checkpoint_id for c in self.checkpoints)
        require_unique(ids, "checkpoint IDs")
        dependencies = {c.checkpoint_id: set(c.depends_on) for c in self.checkpoints}
        for checkpoint in self.checkpoints:
            require_unique(checkpoint.depends_on, "checkpoint dependencies")
            if set(checkpoint.depends_on) - set(ids):
                raise ValueError("checkpoint dependency does not exist")
        remaining = set(ids)
        while remaining:
            ready = {key for key in remaining if not dependencies[key] & remaining}
            if not ready:
                raise ValueError("checkpoint dependencies contain a cycle")
            remaining -= ready
        return self


class RewardPolicy(Contract):
    policy_version: Identifier
    aggregation: Literal["grounded_final_or_capped_checkpoints"] = "grounded_final_or_capped_checkpoints"
    checkpoint_cap: Annotated[float, Field(gt=0, lt=1)]


class PublicTask(Contract):
    schema_version: Literal["1"] = "1"
    task_id: Identifier
    revision_id: Identifier
    serving_view_id: Identifier
    scope: PublicScope
    context: Text
    question: Text
    answer_format: AnswerFormat


class TaskRecord(Contract):
    schema_version: Literal["1"] = "1"
    generator_version: Literal["v1"] = "v1"
    task_id: Identifier
    revision_id: Identifier
    lineage_group: Identifier
    dataset_release: Identifier
    snapshot_id: Identifier
    graph_version: Identifier
    serving_view_id: Identifier
    evaluation_profile: Identifier
    task_family: Literal[
        "attribution", "sequence", "scope_count", "configuration", "observed_outcome", "artifact_identity"
    ]
    scope: TaskScope
    context: Text
    question: Text
    evidence: Annotated[tuple[EvidenceReference, ...], Field(min_length=1)]
    private_gold: PrivateGold
    reward_policy: RewardPolicy

    @model_validator(mode="after")
    def references_resolve(self) -> TaskRecord:
        ids = tuple(e.evidence_id for e in self.evidence)
        require_unique(ids, "task evidence IDs")
        citations = tuple(f"{e.table}:{e.public_record_id}" for e in self.evidence)
        require_unique(citations, "public evidence locators")
        if any(e.snapshot_id != self.snapshot_id for e in self.evidence):
            raise ValueError("evidence snapshot differs from task snapshot")
        needed = set(self.scope.anchor_evidence_ids)
        for claim in (self.private_gold.final, *(c.claim for c in self.private_gold.checkpoints)):
            for evidence_set in claim.evidence_sets:
                needed.update(evidence_set.evidence_ids)
        if needed - set(ids):
            raise ValueError(f"unresolved evidence references: {sorted(needed - set(ids))}")
        return self

    def public_task(self) -> PublicTask:
        return PublicTask(
            task_id=self.task_id, revision_id=self.revision_id,
            serving_view_id=self.serving_view_id,
            scope=PublicScope(mode=self.scope.mode, incident_id=self.scope.incident_id),
            context=self.context, question=self.question,
            answer_format=self.private_gold.final.expected.format,
        )


class GateResult(Contract):
    gate: Identifier
    status: Literal["pass", "fail", "error", "not_applicable"]
    reason: Text
    error_code: Identifier | None = None
    artifact_refs: tuple[Text, ...] = ()

    @model_validator(mode="after")
    def explicit_errors(self) -> GateResult:
        if (self.status == "error") != (self.error_code is not None):
            raise ValueError("only error results require an error code")
        return self


class ValidationReport(Contract):
    schema_version: Literal["1"] = "1"
    task_id: Identifier
    task_fingerprint: Digest
    evaluator_version: Identifier
    gates: tuple[GateResult, ...]

    @model_validator(mode="after")
    def unique_gates(self) -> ValidationReport:
        require_unique(tuple(g.gate for g in self.gates), "gate results")
        return self

    def release_blockers(self, task: TaskRecord) -> tuple[str, ...]:
        blockers = []
        if self.task_id != task.task_id or self.task_fingerprint != fingerprint(task):
            blockers.append("validation does not match this task revision/content")
        by_name = {g.gate: g for g in self.gates}
        for name in REQUIRED_GATES:
            result = by_name.get(name)
            if result is None:
                blockers.append(f"{name}: missing")
            elif result.status != "pass":
                blockers.append(f"{name}: {result.status}: {result.reason}")
        for result in self.gates:
            if result.gate not in REQUIRED_GATES and result.status in ("fail", "error"):
                blockers.append(f"{result.gate}: {result.status}: {result.reason}")
        return tuple(blockers)

    def pilot_blockers(self, task: TaskRecord) -> tuple[str, ...]:
        """Private trials may precede split/release review, but never bypass a failed gate."""
        return tuple(blocker for blocker in self.release_blockers(task)
                     if blocker not in ("split_review: missing", "release_review: missing"))


class ScoreComponent(Contract):
    component_id: Identifier
    kind: Literal["answer_correctness", "final_evidence", "checkpoint"]
    status: Literal["complete", "incomplete", "error"]
    score: Annotated[float, Field(ge=0)] | None
    max_score: PositiveFloat
    weight: PositiveFloat
    evidence: tuple[PublicCitation, ...]
    trajectory_steps: tuple[NonnegativeInt, ...]
    first_completion_step: NonnegativeInt | None
    explanation: Text
    evaluator_version: Identifier
    error_code: Identifier | None = None

    @model_validator(mode="after")
    def score_state(self) -> ScoreComponent:
        require_unique(tuple(f"{e.table}:{e.record_id}" for e in self.evidence), "score evidence locators")
        if len(set(self.trajectory_steps)) != len(self.trajectory_steps):
            raise ValueError("duplicate trajectory step references")
        if self.status == "complete":
            if self.score is None or self.score > self.max_score or self.error_code is not None:
                raise ValueError("complete score must be finite, within its maximum, and have no error")
            if self.score > 0 and self.kind != "answer_correctness" and not self.evidence:
                raise ValueError("positive evidence/checkpoint credit requires evidence references")
            if self.score > 0 and self.kind == "checkpoint" and not self.trajectory_steps:
                raise ValueError("checkpoint credit requires observable trajectory steps")
        elif self.score is not None or self.first_completion_step is not None:
            raise ValueError("error/incomplete result must not carry a score or completion step")
        if (self.status == "error") != (self.error_code is not None):
            raise ValueError("only error results require an error code")
        if self.first_completion_step is not None:
            if self.first_completion_step not in self.trajectory_steps:
                raise ValueError("first completion step must cite an observed trajectory step")
            if self.score != self.max_score:
                raise ValueError("completion step requires a completed objective")
        return self


def normalized_checkpoint_progress(checkpoints: tuple[ScoreComponent, ...]) -> float:
    if not checkpoints:
        raise ValueError("checkpoint progress requires a nonempty rubric")
    total, maximum = Rational(0), Rational(0)
    for checkpoint in checkpoints:
        if checkpoint.status != "complete" or checkpoint.score is None:
            raise ValueError("checkpoint progress requires complete component scores")
        weight = Rational(str(checkpoint.weight))
        total += Rational(str(checkpoint.score)) * weight
        maximum += Rational(str(checkpoint.max_score)) * weight
    return float(total / maximum)


class EvaluationRecord(Contract):
    schema_version: Literal["1"] = "1"
    run_id: Identifier
    task_id: Identifier
    task_fingerprint: Digest
    evaluation_profile: Identifier
    backend: Literal["secrl", "acesevals"]
    backend_adapter_version: Identifier = "component-record-v1"
    reward_policy: RewardPolicy
    trajectory_ref: Text
    status: Literal["complete", "incomplete", "error"]
    answer_correctness: ScoreComponent
    final_evidence: ScoreComponent
    checkpoints: Annotated[tuple[ScoreComponent, ...], Field(min_length=1)]
    grounded_final: bool | None
    checkpoint_progress: Fraction | None
    aggregate_reward: Fraction | None

    @model_validator(mode="after")
    def consistent_result(self) -> EvaluationRecord:
        components = (self.answer_correctness, self.final_evidence, *self.checkpoints)
        require_unique(tuple(c.component_id for c in components), "score component IDs")
        if self.answer_correctness.kind != "answer_correctness" or self.final_evidence.kind != "final_evidence":
            raise ValueError("final score components have the wrong kind")
        if any(c.kind != "checkpoint" for c in self.checkpoints):
            raise ValueError("checkpoint scores must have kind checkpoint")
        if self.status != "complete":
            if any(value is not None for value in (
                self.grounded_final, self.checkpoint_progress, self.aggregate_reward,
            )):
                raise ValueError("error/incomplete evaluation must not publish completed aggregate metrics")
            return self
        if any(c.status != "complete" for c in components):
            raise ValueError("complete evaluation requires all components to be complete")
        final = (
            self.answer_correctness.score == self.answer_correctness.max_score
            and self.final_evidence.score == self.final_evidence.max_score
        )
        progress = normalized_checkpoint_progress(self.checkpoints)
        reward = max(float(final), self.reward_policy.checkpoint_cap * progress)
        if self.grounded_final is not final:
            raise ValueError("grounded final success must agree with answer and evidence components")
        if self.checkpoint_progress is None or not math.isclose(self.checkpoint_progress, progress, rel_tol=0, abs_tol=1e-12):
            raise ValueError("checkpoint progress differs from the component scores")
        if self.aggregate_reward is None or not math.isclose(self.aggregate_reward, reward, rel_tol=0, abs_tol=1e-12):
            raise ValueError("aggregate reward differs from the declared policy")
        return self

    def task_mismatches(self, task: TaskRecord) -> tuple[str, ...]:
        mismatches = []
        if self.task_id != task.task_id or self.task_fingerprint != fingerprint(task):
            mismatches.append("evaluation does not match this task revision/content")
        if self.evaluation_profile != task.evaluation_profile:
            mismatches.append("evaluation profile differs from task profile")
        expected = {c.checkpoint_id for c in task.private_gold.checkpoints}
        if {c.component_id for c in self.checkpoints} != expected:
            mismatches.append("checkpoint score IDs do not match the task rubric")
        by_id = {c.component_id: c for c in self.checkpoints}
        for rubric in task.private_gold.checkpoints:
            component = by_id.get(rubric.checkpoint_id)
            if component is None:
                continue
            if component.max_score != rubric.max_score or component.weight != rubric.weight:
                mismatches.append(f"{rubric.checkpoint_id}: score maximum/weight differs from the task rubric")
            if component.status == "complete" and component.score == component.max_score and component.first_completion_step is None:
                mismatches.append(f"{rubric.checkpoint_id}: completed checkpoint lacks its first completion step")
            if self.status == "complete" and component.score is not None and component.score > 0:
                for dependency in rubric.depends_on:
                    prerequisite = by_id.get(dependency)
                    if prerequisite is None or prerequisite.score != prerequisite.max_score:
                        mismatches.append(f"{rubric.checkpoint_id}: semantic dependency {dependency} is not complete")
        return tuple(mismatches)


class SimilarityWeights(Contract):
    edges: Fraction
    observations: Fraction
    facts: Fraction
    containment: Fraction

    @model_validator(mode="after")
    def normalized(self) -> SimilarityWeights:
        if not math.isclose(
            self.edges + self.observations + self.facts + self.containment,
            1.0, rel_tol=0, abs_tol=1e-12,
        ):
            raise ValueError("similarity weights must sum to one")
        return self


class SimilarityComponents(Contract):
    edges: Fraction | None
    observations: Fraction | None
    facts: Fraction | None
    containment: Fraction | None


class SimilarityRecord(Contract):
    schema_version: Literal["1"] = "1"
    metric_version: Identifier
    feature_weight_version: Identifier
    left_task_fingerprint: Digest
    right_task_fingerprint: Digest
    status: Literal["complete", "incomplete", "error"]
    weights: SimilarityWeights
    components: SimilarityComponents | None
    score: Fraction | None
    reason: Text
    error_code: Identifier | None = None

    @model_validator(mode="after")
    def result_matches_components(self) -> SimilarityRecord:
        if self.status == "complete":
            if self.components is None or self.score is None:
                raise ValueError("complete similarity requires every component and the final score")
            expected = 0.0
            for weight, component in (
                (self.weights.edges, self.components.edges),
                (self.weights.observations, self.components.observations),
                (self.weights.facts, self.components.facts),
                (self.weights.containment, self.components.containment),
            ):
                if component is None:
                    raise ValueError("complete similarity cannot have an unknown component")
                expected += weight * component
            if not math.isclose(self.score, expected, rel_tol=0, abs_tol=1e-12):
                raise ValueError("similarity score differs from the weighted components")
        elif self.score is not None:
            raise ValueError("unscorable similarity must not contain an aggregate score")
        if (self.status == "error") != (self.error_code is not None):
            raise ValueError("only error results require an error code")
        return self
