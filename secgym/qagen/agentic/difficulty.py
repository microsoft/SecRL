# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Provisional, source-bound difficulty profiles; model outcomes are never score inputs."""

from __future__ import annotations

import csv
import hashlib
import json
import re
from collections import Counter
from fractions import Fraction
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator
from sqlglot import exp

from .contracts import (
    AnswerProgram, Contract, Digest, Identifier, NonnegativeInt, PublicCitation, Text, fingerprint, require_unique,
)
from .evidence import EvidenceVerifier
from .query import QueryFailure, QueryLimits, QueryResult, checked_select
from .question_splits import LoadedQuestions, QuestionBinding, SplitQuestion, binding_for


VERSION = "difficulty-heuristic-v0.1"
Operation = Literal[
    "ranking_ordering", "aggregation", "request_deduplication", "dynamic_json",
    "temporal_alignment", "comparison_presence",
]
Band = Literal["easy", "medium", "hard", "very_hard"]
AxisValue = Annotated[int, Field(ge=0, le=3)]
ALERT_TABLES = frozenset({"SecurityIncident", "SecurityAlert", "AlertEvidence"})
MAX_PARTITION_QUERIES = 4096
MAX_PARTITION_RESULT_BYTES = 64 * 1024 * 1024
RECORD_LOCATOR = re.compile(r"r:[0-9a-f]{64}")


class ProofChoice(Contract):
    claim_id: Identifier
    evidence_set_fingerprint: Digest
    terminal_step: Identifier


class ReasoningStep(Contract):
    step_id: Identifier
    depends_on: tuple[Identifier, ...] = ()
    evidence_ids: Annotated[tuple[Identifier, ...], Field(min_length=1)]
    discovered_binding: bool = False
    cross_domain_binding: bool = False
    operations: tuple[Operation, ...] = ()
    justification: Text

    @model_validator(mode="after")
    def unique_inputs(self) -> ReasoningStep:
        require_unique(self.depends_on, "reasoning dependencies")
        require_unique(self.evidence_ids, "reasoning evidence")
        require_unique(self.operations, "operation families")
        if self.cross_domain_binding and not self.discovered_binding:
            raise ValueError("cross-domain transitions must be actual discovered bindings")
        return self


class AmbiguityProbe(Contract):
    probe_id: Identifier
    decision_step: Identifier
    program: AnswerProgram
    table: Identifier
    record_id_column: Text = "_record_id"
    identity_kind: Literal["source_observation", "qualified_fields"]
    identity_columns: tuple[Text, ...] = ()
    scope_and_relaxation: Text

    @model_validator(mode="after")
    def candidate_identity(self) -> AmbiguityProbe:
        require_unique(self.identity_columns, "candidate identity columns")
        if (self.identity_kind == "qualified_fields") != bool(self.identity_columns):
            raise ValueError("qualified identities require explicit fields; observation identities use source locators")
        if any(name.casefold() == "_record_id" for name in self.identity_columns):
            raise ValueError("opaque locators are not qualified entity properties")
        return self


class PartitionedAmbiguityProbe(AmbiguityProbe):
    retrieval_policy: Literal["exhaustive-record-ranges-v1"]


class ProofRoute(Contract):
    route_id: Identifier
    claims: Annotated[tuple[ProofChoice, ...], Field(min_length=1)]
    steps: Annotated[tuple[ReasoningStep, ...], Field(min_length=1)]
    ambiguity_probes: tuple[PartitionedAmbiguityProbe | AmbiguityProbe, ...] | None = None
    ambiguity_coverage: Text

    @model_validator(mode="after")
    def dependency_graph(self) -> ProofRoute:
        require_unique(tuple(claim.claim_id for claim in self.claims), "route claims")
        require_unique(tuple(step.step_id for step in self.steps), "reasoning step IDs")
        steps = {step.step_id: step for step in self.steps}
        if any(set(step.depends_on) - steps.keys() for step in self.steps):
            raise ValueError("reasoning dependency is missing")
        if any(claim.terminal_step not in steps for claim in self.claims):
            raise ValueError("claim terminal is missing")
        remaining = set(steps)
        reached: set[str] = set()
        while remaining:
            ready = {key for key in remaining if set(steps[key].depends_on) <= reached}
            if not ready:
                raise ValueError("reasoning dependencies contain a cycle")
            reached.update(ready)
            remaining.difference_update(ready)
        used = set()
        pending = [claim.terminal_step for claim in self.claims]
        while pending:
            key = pending.pop()
            if key not in used:
                used.add(key)
                pending.extend(steps[key].depends_on)
        if used != steps.keys():
            raise ValueError("unused reasoning steps cannot inflate difficulty")
        if self.ambiguity_probes is not None:
            require_unique(tuple(probe.probe_id for probe in self.ambiguity_probes), "ambiguity probes")
            if any(probe.decision_step not in steps for probe in self.ambiguity_probes):
                raise ValueError("ambiguity probe refers to an unknown reasoning step")
        return self


class DifficultyPlan(Contract):
    definition_version: Literal["difficulty-heuristic-v0.1"] = VERSION
    binding: QuestionBinding
    routes: Annotated[tuple[ProofRoute, ...], Field(min_length=1)]
    limitations: tuple[Text, ...] = ()

    @model_validator(mode="after")
    def unique_routes(self) -> DifficultyPlan:
        require_unique(tuple(route.route_id for route in self.routes), "difficulty routes")
        return self


class DifficultyReview(Contract):
    plan_fingerprint: Digest
    reviewer: Text
    recommendation: Literal["pass", "revise", "reject"]
    proof_choices_complete_and_material: bool
    logical_bindings_and_domains_valid: bool
    operations_necessary: bool
    ambiguity_scopes_and_identities_valid: bool
    reasons: Annotated[tuple[Text, ...], Field(min_length=1)]


class DifficultyPlanFiles(Contract):
    task_id: Identifier
    plan: Text
    review: Text | None = None


class DifficultyInputs(Contract):
    entries: Annotated[tuple[DifficultyPlanFiles, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def unique_tasks(self) -> DifficultyInputs:
        require_unique(tuple(entry.task_id for entry in self.entries), "difficulty input tasks")
        return self


class ProbeMeasurement(Contract):
    probe_id: Identifier
    decision_step: Identifier
    program_fingerprint: Digest
    status: Literal["complete", "error"]
    candidate_count: NonnegativeInt | None
    retrieved_rows: NonnegativeInt | None
    result_sha256: Digest | None
    observed_citations: tuple[PublicCitation, ...]
    error_code: Identifier | None
    reason: Text

    @model_validator(mode="after")
    def measurement_state(self) -> ProbeMeasurement:
        if self.status == "complete":
            if (self.candidate_count is None or self.retrieved_rows is None or self.result_sha256 is None
                or self.error_code is not None or not 1 <= self.candidate_count <= len(self.observed_citations) <= self.retrieved_rows):
                raise ValueError("complete ambiguity measurements need positive, source-backed candidate counts")
        elif (self.candidate_count is not None or self.retrieved_rows is not None or self.result_sha256 is not None
              or self.observed_citations or self.error_code is None):
            raise ValueError("failed ambiguity measurements cannot carry success-shaped counts")
        return self


class CandidatePartition(Contract):
    lower_exclusive: Text | None
    upper_inclusive: Text | None
    retrieved_rows: NonnegativeInt
    query_sha256: Digest
    result_sha256: Digest


class ExhaustiveRetrieval(Contract):
    policy: Literal["exhaustive-record-ranges-v1"] = "exhaustive-record-ranges-v1"
    full_scope_rows: Annotated[int, Field(gt=0)]
    census_query_sha256: Digest
    census_result_sha256: Digest
    partitions: Annotated[tuple[CandidatePartition, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def complete_partition(self) -> ExhaustiveRetrieval:
        if self.partitions[0].lower_exclusive is not None or self.partitions[-1].upper_inclusive is not None:
            raise ValueError("exhaustive partitions must cover the whole locator range")
        previous = None
        for partition in self.partitions:
            if partition.lower_exclusive != previous:
                raise ValueError("exhaustive partitions must be contiguous and disjoint")
            for boundary in (partition.lower_exclusive, partition.upper_inclusive):
                if boundary is not None and not RECORD_LOCATOR.fullmatch(boundary):
                    raise ValueError("partition boundaries must be canonical record locators")
            if (partition.lower_exclusive is not None and partition.upper_inclusive is not None
                and partition.lower_exclusive >= partition.upper_inclusive):
                raise ValueError("partition boundaries must be strictly increasing")
            previous = partition.upper_inclusive
        if any(part.upper_inclusive is None for part in self.partitions[:-1]):
            raise ValueError("only the last partition may have an unbounded upper range")
        if sum(part.retrieved_rows for part in self.partitions) != self.full_scope_rows:
            raise ValueError("partition rows must exactly match the whole-scope census")
        return self


class PartitionedProbeMeasurement(ProbeMeasurement):
    retrieval: ExhaustiveRetrieval

    @model_validator(mode="after")
    def complete_retrieval(self) -> PartitionedProbeMeasurement:
        if self.status != "complete" or self.retrieved_rows != self.retrieval.full_scope_rows:
            raise ValueError("partitioned measurements require a complete, count-matched retrieval")
        return self


class AxisScores(Contract):
    breadth: AxisValue | None
    dependency: AxisValue | None
    reasoning: AxisValue | None
    ambiguity: AxisValue | None


class ObjectiveDifficulty(Contract):
    claim_id: Identifier
    status: Literal["provisional", "incomplete"]
    axes: AxisScores
    score: Annotated[float, Field(ge=0, le=100)] | None
    band: Band | None
    observations: NonnegativeInt
    raw_tables: tuple[Identifier, ...]
    cross_domain_bindings: NonnegativeInt
    logical_binding_depth: NonnegativeInt
    necessary_reconvergence: bool
    operation_families: tuple[Operation, ...]
    ambiguity_candidates: tuple[NonnegativeInt, ...] | None
    reasons: tuple[Text, ...]

    @model_validator(mode="after")
    def score_consistency(self) -> ObjectiveDifficulty:
        require_unique(self.raw_tables, "difficulty raw tables")
        require_unique(self.operation_families, "difficulty operation families")
        if self.ambiguity_candidates is not None and any(count < 1 for count in self.ambiguity_candidates):
            raise ValueError("zero candidates cannot establish an ambiguity score")
        expected = AxisScores(
            breadth=max(_count_band(self.observations, (2, 5, 11)), _count_band(len(self.raw_tables), (2, 3, 4)),
                        min(self.cross_domain_bindings, 3)),
            dependency=min(_count_band(self.logical_binding_depth, (1, 2, 4)) + int(self.necessary_reconvergence), 3),
            reasoning=min(len(self.operation_families), 3),
            ambiguity=None if self.ambiguity_candidates is None else _count_band(max(self.ambiguity_candidates, default=1), (2, 4, 11)),
        )
        score, band = score_axes(expected)
        if self.axes != expected or self.score != score or self.band != band:
            raise ValueError("difficulty axes, scalar and band must match the measured features and versioned formula")
        if (self.status == "provisional") != (score is not None):
            raise ValueError("unavailable difficulty axes cannot be labeled provisional")
        return self


class RouteDifficulty(Contract):
    route_id: Identifier
    objectives: tuple[ObjectiveDifficulty, ...]
    combined: ObjectiveDifficulty
    probes: tuple[PartitionedProbeMeasurement | ProbeMeasurement, ...]


class DifficultyDescriptors(Contract):
    evidence_observation_union: NonnegativeInt
    overlap_footprint_edges: NonnegativeInt | None
    evidence_tables: tuple[Identifier, ...]
    final_proof_alternative_sizes: tuple[NonnegativeInt, ...]
    checkpoint_proof_alternative_sizes: dict[str, tuple[NonnegativeInt, ...]]
    checkpoint_count: NonnegativeInt
    answer_kind: Text
    answer_cardinality: NonnegativeInt


class DifficultySidecar(Contract):
    schema_version: Literal["1"] = "1"
    definition_version: Literal["difficulty-heuristic-v0.1"] = VERSION
    binding: QuestionBinding
    snapshot_id: Identifier
    graph_version: Identifier
    serving_view_id: Identifier
    status: Literal["not_measured", "needs_review", "incomplete", "provisional"]
    plan_fingerprint: Digest | None
    review_fingerprint: Digest | None
    measurement_engine: Literal["duckdb", "mysql"] | None
    query_limits: QueryLimits | None
    descriptors: DifficultyDescriptors
    routes: tuple[RouteDifficulty, ...]
    selected_route: Identifier | None
    score: Annotated[float, Field(ge=0, le=100)] | None
    band: Band | None
    reasons: tuple[Text, ...]
    visibility: Literal["private_review"] = "private_review"
    empirical_calibration_performed: Literal[False] = False
    student_prompt_changed: Literal[False] = False
    grading_changed: Literal[False] = False
    admission_gate: Literal[False] = False
    implementation_sha256: Digest

    @model_validator(mode="after")
    def profile_state(self) -> DifficultySidecar:
        require_unique(tuple(route.route_id for route in self.routes), "measured difficulty routes")
        if self.status == "provisional":
            if (not self.routes or self.plan_fingerprint is None or self.review_fingerprint is None
                or any(route.combined.score is None for route in self.routes)):
                raise ValueError("provisional difficulty requires complete reviewed measurements")
            selected = min(self.routes, key=lambda route: (route.combined.score, route.route_id))
            if (self.selected_route, self.score, self.band) != (
                selected.route_id, selected.combined.score, selected.combined.band,
            ):
                raise ValueError("difficulty sidecar does not match its least demanding reviewed route")
        else:
            if self.score is not None or self.band is not None or self.selected_route is not None:
                raise ValueError("unmeasured, unreviewed or incomplete difficulty cannot publish a scalar or band")
            if self.status == "not_measured" and (self.plan_fingerprint is not None or self.review_fingerprint is not None or self.routes):
                raise ValueError("unmeasured descriptors cannot pretend to contain reviewed routes")
        return self


def score_axes(axes: AxisScores) -> tuple[float | None, Band | None]:
    axes = AxisScores.model_validate(axes)
    if any(value is None for value in (axes.breadth, axes.dependency, axes.reasoning, axes.ambiguity)):
        return None, None
    total = sum(weight * value for weight, value in zip(
        (20, 30, 30, 20), (axes.breadth, axes.dependency, axes.reasoning, axes.ambiguity),
    ) if value is not None)
    score = Fraction(total, 3)
    band: Band = "easy" if score < 25 else "medium" if score < 50 else "hard" if score < 75 else "very_hard"
    return float(score), band


def _count_band(count: int, thresholds: tuple[int, int, int]) -> int:
    return sum(count >= threshold for threshold in thresholds)


def _ancestors(route: ProofRoute, terminals: tuple[str, ...]) -> set[str]:
    steps = {step.step_id: step for step in route.steps}
    seen = set()
    pending = list(terminals)
    while pending:
        key = pending.pop()
        if key not in seen:
            seen.add(key)
            pending.extend(steps[key].depends_on)
    return seen


def _selected_proofs(question: SplitQuestion, route: ProofRoute) -> dict[str, set[str]]:
    claims = {"final": question.task.private_gold.final,
              **{checkpoint.checkpoint_id: checkpoint.claim for checkpoint in question.task.private_gold.checkpoints}}
    if {claim.claim_id for claim in route.claims} != claims.keys():
        raise ValueError("a difficulty route must cover the final and every checkpoint")
    selected = {}
    steps = {step.step_id: step for step in route.steps}
    for choice in route.claims:
        matching = [group for group in claims[choice.claim_id].evidence_sets
                    if fingerprint(group) == choice.evidence_set_fingerprint]
        if len(matching) != 1:
            raise ValueError("difficulty proof choice does not bind one complete validated alternative")
        selected[choice.claim_id] = set(matching[0].evidence_ids)
        used = _ancestors(route, (choice.terminal_step,))
        represented = {evidence_id for key in used for evidence_id in steps[key].evidence_ids}
        if represented != selected[choice.claim_id]:
            raise ValueError("logical reasoning steps must cover exactly their claim-bound selected proof")
    return selected


def _result_digest(result: QueryResult) -> str:
    encoded = json.dumps({"columns": result.columns, "rows": result.rows}, sort_keys=True,
                         separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _partitioned_results(
    probe: PartitionedAmbiguityProbe, verifier: EvidenceVerifier, tree: exp.Expression,
) -> tuple[tuple[tuple[str, QueryResult], ...], ExhaustiveRetrieval]:
    engine = verifier.engine
    # This zero-row query obtains the original header only, never candidate evidence.
    header = engine.execute(tree.limit(0).sql(dialect=engine.engine))
    if len(set(header.columns)) != len(header.columns) or probe.record_id_column not in header.columns:
        raise QueryFailure("candidate_columns", "Candidate output must have unique columns and its declared locator.")
    locator = exp.column(probe.record_id_column, quoted=True)
    scope = tree.subquery("_candidate_scope")
    census_tree = exp.select(
        exp.alias_(exp.Count(this=exp.Star()), "scope_rows"),
        exp.alias_(exp.Count(this=locator.copy()), "located_rows"),
        exp.alias_(exp.Min(this=locator.copy()), "first_locator"),
        exp.alias_(exp.Max(this=locator.copy()), "last_locator"),
    ).from_(scope.copy())
    census_query = census_tree.sql(dialect=engine.engine)
    census = engine.execute(census_query)
    if census.columns != ("scope_rows", "located_rows", "first_locator", "last_locator") or len(census.rows) != 1:
        raise QueryFailure("candidate_census", "The whole-scope candidate census has an unexpected shape.")
    count, located, first, last = census.rows[0]
    if type(count) is not int or type(located) is not int or count < 1:
        raise QueryFailure("empty_candidate_scope", "The whole candidate scope must contain source observations.")
    if count != located:
        raise QueryFailure("invalid_candidate_locator", "The whole candidate scope contains null source locators.")
    if (not isinstance(first, str) or not isinstance(last, str)
        or not RECORD_LOCATOR.fullmatch(first) or not RECORD_LOCATOR.fullmatch(last)):
        raise QueryFailure("invalid_candidate_locator", "The candidate census must bound canonical source locators.")
    pending: list[tuple[str | None, str | None, int, int]] = [(None, None, int(first[2:], 16), int(last[2:], 16))]
    results: list[tuple[str, QueryResult]] = []
    partitions = []
    attempts = 0
    result_bytes = 0
    while pending:
        lower, upper, low, high = pending.pop()
        attempts += 1
        if attempts > MAX_PARTITION_QUERIES:
            raise QueryFailure("candidate_partition_limit", "Exhaustive retrieval exceeded its partition-query budget.")
        query_tree = exp.select("*").from_(scope.copy())
        if lower is not None:
            query_tree = query_tree.where(exp.GT(this=locator.copy(), expression=exp.Literal.string(lower)))
        if upper is not None:
            query_tree = query_tree.where(exp.LTE(this=locator.copy(), expression=exp.Literal.string(upper)))
        query = query_tree.sql(dialect=engine.engine)
        try:
            result = engine.execute(query)
        except QueryFailure as error:
            if error.code not in ("row_limit", "byte_limit"):
                raise
            midpoint = (low + high) // 2
            boundary = f"r:{midpoint:064x}"
            if low == high or (lower is not None and boundary <= lower) or (upper is not None and boundary >= upper):
                raise QueryFailure("candidate_partition_unsplittable",
                                   "A single locator block exceeds the unchanged result limits; no partial proof accepted.") from error
            pending.extend(((boundary, upper, midpoint, high), (lower, boundary, low, midpoint)))
            continue
        if result.columns != header.columns:
            raise QueryFailure("candidate_columns", "Partition retrieval changed the original query's output columns.")
        result_bytes += len(json.dumps([result.columns, result.rows], ensure_ascii=False, allow_nan=False).encode("utf-8"))
        if result_bytes > MAX_PARTITION_RESULT_BYTES:
            raise QueryFailure("candidate_partition_byte_budget", "Exhaustive retrieval exceeded its retained-result byte budget.")
        results.append((query, result))
        partitions.append(CandidatePartition(
            lower_exclusive=lower, upper_inclusive=upper, retrieved_rows=len(result.rows),
            query_sha256=hashlib.sha256(query.encode("utf-8")).hexdigest(), result_sha256=_result_digest(result),
        ))
    if sum(len(result.rows) for _, result in results) != count:
        raise QueryFailure("candidate_census_mismatch", "Exhaustive retrieval did not reproduce the whole-scope row count.")
    retrieval = ExhaustiveRetrieval(
        full_scope_rows=count, census_query_sha256=hashlib.sha256(census_query.encode("utf-8")).hexdigest(),
        census_result_sha256=_result_digest(census), partitions=tuple(partitions),
    )
    return tuple(results), retrieval


def _probe(probe: AmbiguityProbe, verifier: EvidenceVerifier) -> PartitionedProbeMeasurement | ProbeMeasurement:
    program_fp = fingerprint(probe.program)

    def failed(code: str, reason: str) -> ProbeMeasurement:
        return ProbeMeasurement(
            probe_id=probe.probe_id, decision_step=probe.decision_step, program_fingerprint=program_fp,
            status="error", candidate_count=None, retrieved_rows=None, result_sha256=None,
            observed_citations=(), error_code=code, reason=reason,
        )

    if probe.program.engine != verifier.engine.engine:
        raise ValueError("ambiguity probe and measurement engine differ")
    try:
        tree = checked_select(probe.program.query, probe.program.engine, set(verifier.tables))
        if tree.find(exp.Limit) is not None or tree.find(exp.Offset) is not None or tree.find(exp.TableSample) is not None:
            return failed("truncated_candidate_scope", "Exact ambiguity measurements cannot truncate or sample candidates.")
        retrieval = None
        if isinstance(probe, PartitionedAmbiguityProbe):
            results, retrieval = _partitioned_results(probe, verifier, tree)
        else:
            results = ((probe.program.query, verifier.engine.execute(probe.program.query)),)
        keys = set()
        citations = set()
        rows = []
        for query, result in results:
            if probe.record_id_column not in result.columns:
                return failed("missing_candidate_locator", "The ambiguity query did not return its declared source locator.")
            if len(set(result.columns)) != len(result.columns):
                return failed("ambiguous_candidate_columns", "The ambiguity query has duplicate output column names.")
            observed = verifier.observed_citations(result, query)
            id_index = result.columns.index(probe.record_id_column)
            rows.extend(result.rows)
            for row in result.rows:
                record_id = row[id_index]
                if not isinstance(record_id, str):
                    return failed("invalid_candidate_locator", "Candidate source locators must be strings.")
                citation = PublicCitation(table=probe.table, record_id=record_id)
                if citation not in observed:
                    return failed("unattributed_candidate", "A candidate locator was not attributed to its actual source values.")
                citations.add(citation)
                if probe.identity_kind == "source_observation":
                    keys.add((probe.table, record_id))
                else:
                    _, source = verifier.record_values(citation)
                    if any(column not in source or source[column] is None for column in probe.identity_columns):
                        return failed("incomplete_candidate_identity", "A qualified candidate identity has a missing source field.")
                    keys.add(tuple((type(source[column]).__name__, source[column]) for column in probe.identity_columns))
        if not rows:
            return failed("empty_candidate_scope", "No candidates were observed; repair the probe rather than assign an easy score.")
        values = dict(
            probe_id=probe.probe_id, decision_step=probe.decision_step, program_fingerprint=program_fp,
            status="complete", candidate_count=len(keys), retrieved_rows=len(rows),
            result_sha256=_result_digest(QueryResult(results[0][1].columns, tuple(rows))),
            observed_citations=tuple(sorted(citations, key=lambda value: (value.table, value.record_id))),
            error_code=None, reason="Exact distinct source-observation or reviewed qualified-field identities; no row sampling.",
        )
        if retrieval is not None:
            return PartitionedProbeMeasurement(**values, retrieval=retrieval)
        return ProbeMeasurement(**values)
    except QueryFailure as error:
        return failed(error.code, str(error))


def measure_ambiguity_probes(route: ProofRoute, verifier: EvidenceVerifier) -> tuple[PartitionedProbeMeasurement | ProbeMeasurement, ...]:
    """Measure source candidates without a difficulty score or a fabricated feature review."""
    route = ProofRoute.model_validate(route)
    return tuple(_probe(probe, verifier) for probe in route.ambiguity_probes or ())


def _objective(
    question: SplitQuestion, route: ProofRoute, claim_id: str, terminals: tuple[str, ...],
    evidence_ids: set[str], probes: tuple[ProbeMeasurement, ...],
) -> ObjectiveDifficulty:
    steps = {step.step_id: step for step in route.steps}
    used = _ancestors(route, terminals)
    references = {reference.evidence_id: reference for reference in question.task.evidence}
    observations = {references[key].private_locator for key in evidence_ids}
    tables = sorted({references[key].table for key in evidence_ids} - ALERT_TABLES)
    domains = sum(steps[key].cross_domain_binding for key in used)
    depths: dict[str, int] = {}
    binding_ancestors: dict[str, set[str]] = {}
    pending = set(used)
    while pending:
        ready = {key for key in pending if set(steps[key].depends_on) <= depths.keys()}
        for key in ready:
            step = steps[key]
            depths[key] = max((depths[parent] for parent in step.depends_on), default=0) + int(step.discovered_binding)
            binding_ancestors[key] = {node for parent in step.depends_on for node in binding_ancestors[parent]}
            if step.discovered_binding:
                binding_ancestors[key].add(key)
        pending.difference_update(ready)
    reconvergence = any(
        binding_ancestors[a] - binding_ancestors[b] and binding_ancestors[b] - binding_ancestors[a]
        for key in used for a in steps[key].depends_on for b in steps[key].depends_on if a != b
    )
    depth = max((depths[key] for key in terminals), default=0)
    families = tuple(sorted({family for key in used for family in steps[key].operations}))
    relevant_probes = tuple(probe for probe in probes if probe.decision_step in used)
    ambiguity = None
    reasons = []
    counts = None
    if route.ambiguity_probes is None:
        reasons.append("Ambiguity has not been measured; it is not assumed to be zero.")
    elif any(probe.status != "complete" for probe in relevant_probes):
        reasons.extend(probe.reason for probe in relevant_probes if probe.status != "complete")
    else:
        counts = tuple(probe.candidate_count for probe in relevant_probes if probe.candidate_count is not None)
        ambiguity = _count_band(max(counts, default=1), (2, 4, 11))
    axes = AxisScores(
        breadth=max(_count_band(len(observations), (2, 5, 11)), _count_band(len(tables), (2, 3, 4)), min(domains, 3)),
        dependency=min(_count_band(depth, (1, 2, 4)) + int(reconvergence), 3),
        reasoning=min(len(families), 3), ambiguity=ambiguity,
    )
    score, band = score_axes(axes)
    return ObjectiveDifficulty(
        claim_id=claim_id, status="provisional" if score is not None else "incomplete",
        axes=axes, score=score, band=band, observations=len(observations), raw_tables=tuple(tables),
        cross_domain_bindings=domains, logical_binding_depth=depth, necessary_reconvergence=bool(reconvergence),
        operation_families=families, ambiguity_candidates=counts, reasons=tuple(reasons),
    )


def describe_question(question: SplitQuestion) -> DifficultyDescriptors:
    references = {reference.evidence_id: reference for reference in question.task.evidence}

    def sizes(claim) -> tuple[int, ...]:
        return tuple(len({references[key].private_locator for key in group.evidence_ids})
                     for group in claim.evidence_sets)

    value = question.task.private_gold.final.expected.value
    return DifficultyDescriptors(
        evidence_observation_union=len(question.baseline.observations or ()),
        overlap_footprint_edges=len(question.baseline.edges) if question.baseline.edges is not None else None,
        evidence_tables=tuple(sorted({reference.table for reference in question.task.evidence})),
        final_proof_alternative_sizes=sizes(question.task.private_gold.final),
        checkpoint_proof_alternative_sizes={c.checkpoint_id: sizes(c.claim) for c in question.task.private_gold.checkpoints},
        checkpoint_count=len(question.task.private_gold.checkpoints),
        answer_kind=question.task.private_gold.final.expected.format.kind,
        answer_cardinality=len(value) if isinstance(value, tuple) else 1,
    )


def measure_difficulty(
    question: SplitQuestion, *, plan: DifficultyPlan | None = None,
    review: DifficultyReview | None = None, verifier: EvidenceVerifier | None = None,
) -> DifficultySidecar:
    question = SplitQuestion.model_validate(question)
    binding = binding_for(question)
    routes = []
    reasons = []
    status: Literal["not_measured", "needs_review", "incomplete", "provisional"] = "not_measured"
    selected_route = None
    score = band = None
    if plan is None:
        if review is not None or verifier is not None:
            raise ValueError("a review or measurement engine requires a difficulty plan")
        reasons.append("Descriptive inventory only: no reviewed logical proof/ambiguity plan was supplied.")
    else:
        plan = DifficultyPlan.model_validate(plan)
        if plan.binding != binding:
            raise ValueError("difficulty plan does not match the exact task/native/canonical evidence bindings")
        for route in plan.routes:
            _selected_proofs(question, route)
        if review is None:
            status = "needs_review"
            reasons.append("Semantic necessity and ambiguity scopes require an explicit plan-bound review.")
        else:
            review = DifficultyReview.model_validate(review)
            if review.plan_fingerprint != fingerprint(plan):
                raise ValueError("difficulty review does not bind the exact measurement plan")
            passed = review.recommendation == "pass" and all((
                review.proof_choices_complete_and_material, review.logical_bindings_and_domains_valid,
                review.operations_necessary, review.ambiguity_scopes_and_identities_valid,
            ))
            if not passed:
                status = "needs_review"
                reasons.extend(review.reasons)
            else:
                if any(route.ambiguity_probes for route in plan.routes) and verifier is None:
                    raise ValueError("source ambiguity probes require the actual read-only serving verifier")
                if verifier is not None and (
                    verifier.report["snapshot_id"], verifier.report["graph_id"], verifier.report["serving_view_id"]
                ) != (question.task.snapshot_id, question.task.graph_version, question.task.serving_view_id):
                    raise ValueError("difficulty measurement uses a different source snapshot or serving context")
                for route in plan.routes:
                    chosen = _selected_proofs(question, route)
                    measurements = measure_ambiguity_probes(route, verifier) if verifier else ()
                    objectives = tuple(_objective(
                        question, route, choice.claim_id, (choice.terminal_step,), chosen[choice.claim_id], measurements,
                    ) for choice in route.claims)
                    combined = _objective(
                        question, route, "combined", tuple(choice.terminal_step for choice in route.claims),
                        set().union(*chosen.values()), measurements,
                    )
                    routes.append(RouteDifficulty(route_id=route.route_id, objectives=objectives,
                                                  combined=combined, probes=measurements))
                if all(route.combined.score is not None for route in routes):
                    selected = min(routes, key=lambda route: (route.combined.score, route.route_id))
                    score, band, selected_route = selected.combined.score, selected.combined.band, selected.route_id
                    status = "provisional"
                    reasons.append("Minimum among the supplied, reviewed routes only; not a proven global minimum.")
                else:
                    status = "incomplete"
                    reasons.append("At least one reviewed route has unavailable required measurements; no scalar or band assigned.")
    return DifficultySidecar(
        binding=binding, snapshot_id=question.task.snapshot_id, graph_version=question.task.graph_version,
        serving_view_id=question.task.serving_view_id, status=status,
        plan_fingerprint=fingerprint(plan) if plan is not None else None,
        review_fingerprint=fingerprint(review) if review is not None else None,
        measurement_engine=verifier.engine.engine if verifier is not None else None,
        query_limits=verifier.engine.limits if verifier is not None else None,
        descriptors=describe_question(question), routes=tuple(routes), selected_route=selected_route,
        score=score, band=band, reasons=tuple(reasons),
        implementation_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    )


def profile_questions(
    loaded: LoadedQuestions, output: Path, *, plans_path: Path | None = None,
    serving_bundle: Path | None = None, limits: QueryLimits | None = None,
) -> dict:
    if output.exists() or any(output.resolve().is_relative_to(path) for path in loaded.annotation_directories):
        raise ValueError("difficulty output must be new and outside canonical annotation bundles")
    if (serving_bundle is None) != (limits is None):
        raise ValueError("serving bundle and explicit query limits must be supplied together")
    if serving_bundle is not None and output.resolve().is_relative_to(serving_bundle.resolve()):
        raise ValueError("difficulty output cannot be inside the immutable serving bundle")
    questions = {question.task.task_id: question for question in loaded.questions}
    plans: dict[str, DifficultyPlan] = {}
    reviews: dict[str, DifficultyReview] = {}
    hashes = dict(loaded.source_hashes)
    if plans_path is not None:
        data = plans_path.read_bytes()
        hashes[str(plans_path.resolve())] = hashlib.sha256(data).hexdigest()
        entries = DifficultyInputs.model_validate_json(data)
        for entry in entries.entries:
            if entry.task_id not in questions:
                raise ValueError("difficulty inputs contain a task outside the admitted cohort")
            path = (plans_path.parent / entry.plan).resolve()
            data = path.read_bytes()
            hashes[str(path)] = hashlib.sha256(data).hexdigest()
            plan = DifficultyPlan.model_validate_json(data)
            if plan.binding != binding_for(questions[entry.task_id]):
                raise ValueError("difficulty input task or source-review binding changed")
            plans[entry.task_id] = plan
            if entry.review is not None:
                path = (plans_path.parent / entry.review).resolve()
                data = path.read_bytes()
                hashes[str(path)] = hashlib.sha256(data).hexdigest()
                review = DifficultyReview.model_validate_json(data)
                if review.plan_fingerprint != fingerprint(plan):
                    raise ValueError("difficulty review fingerprint differs from its plan")
                reviews[entry.task_id] = review
    engine = verifier = None
    results = []
    try:
        if serving_bundle is not None:
            from .mysql_serving import open_duckdb_engine

            if limits is None:
                raise ValueError("measurement limits are missing")
            engine = open_duckdb_engine(serving_bundle, limits)
            verifier = EvidenceVerifier(serving_bundle, engine, frozenset())
        for task_id, question in sorted(questions.items()):
            results.append(measure_difficulty(
                question, plan=plans.get(task_id), review=reviews.get(task_id),
                verifier=verifier if task_id in plans else None,
            ))
    finally:
        if verifier is not None:
            verifier.close()
        if engine is not None:
            engine.connection.close()
    output.mkdir(parents=True, mode=0o700)
    for result in results:
        (output / f"{result.binding.task_id}.json").write_text(result.model_dump_json(indent=2) + "\n")
    with (output / "difficulty.csv").open("x", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=(
            "task_id", "task_fingerprint", "status", "route", "breadth", "dependency", "reasoning", "ambiguity", "score", "band",
        ))
        writer.writeheader()
        for result in results:
            selected = next((route.combined for route in result.routes if route.route_id == result.selected_route), None)
            writer.writerow({
                "task_id": result.binding.task_id, "task_fingerprint": result.binding.task_fingerprint,
                "status": result.status, "route": result.selected_route,
                **{name: getattr(selected.axes, name) if selected else None
                   for name in ("breadth", "dependency", "reasoning", "ambiguity")},
                "score": result.score, "band": result.band,
            })
    summary = {
        "definition_version": VERSION, "cohort_label": loaded.inputs.cohort_label,
        "questions": len(results), "requested_measurements": len(plans),
        "statuses": dict(Counter(result.status for result in results)),
        "requested_measurements_complete": all(
            result.status == "provisional" for result in results if result.binding.task_id in plans
        ),
        "source_artifacts_sha256": hashes, "implementation_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "empirical_calibration_performed": False, "model_evaluations_run": False,
        "grading_changed": False, "release_approved": False,
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary
