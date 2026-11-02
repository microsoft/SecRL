# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Private question-level split proposals and overlap disclosure, not release approval."""

from __future__ import annotations

import csv
import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path
from statistics import mean
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .canonical_facts import CanonicalFactBundle, CanonicalFactReview, canonical_fact_footprint
from .contracts import (
    Contract, Digest, Fraction, Identifier, NonnegativeInt, PositiveInt, SimilarityComponents,
    SimilarityWeights, TaskRecord, Text, ValidationReport, fingerprint, require_unique,
)
from .fact_curation import CURATION_VERSION
from .similarity import EvidenceFootprint, WeightedFeature, decisive_features, evidence_similarity, weighted_overlap


POLICY_VERSION = "question-level-overlap-reporting-v1"
RUNTIME_FILES = (
    "canonical_facts.py", "fact_curation.py", "contracts.py", "evidence.py",
    "qualified_witnesses.py", "generation.py", "query.py",
)
Partition = Literal["train", "test"]


class QuestionFiles(Contract):
    task: Text
    validation: Text
    baseline: Text
    annotation: Text


class SplitInputs(Contract):
    schema_version: Literal["1"] = "1"
    cohort_label: Identifier
    questions: Annotated[tuple[QuestionFiles, ...], Field(min_length=1)]


class SplitQuestion(Contract):
    task: TaskRecord
    validation: ValidationReport
    baseline: EvidenceFootprint
    facts: CanonicalFactBundle
    review: CanonicalFactReview

    @model_validator(mode="after")
    def validated_revision(self) -> SplitQuestion:
        blockers = self.validation.pilot_blockers(self.task)
        if blockers:
            raise ValueError(f"{self.task.task_id} is not admitted for private planning: {blockers}")
        if (self.facts.serving_view_id != self.task.serving_view_id
            or self.facts.task_fingerprint != fingerprint(self.task)
            or self.facts.snapshot_id != self.task.snapshot_id
            or self.facts.graph_version != self.task.graph_version):
            raise ValueError("canonical facts do not match this task revision and serving context")
        if any(checkpoint.checkpoint_id == "final" for checkpoint in self.task.private_gold.checkpoints):
            raise ValueError("checkpoint ID conflicts with the final fact claim")
        claims = {"final": self.task.private_gold.final,
                  **{checkpoint.checkpoint_id: checkpoint.claim for checkpoint in self.task.private_gold.checkpoints}}
        if {claim.claim_id for claim in self.facts.claims} != claims.keys():
            raise ValueError("canonical facts must cover the final and every checkpoint")
        references = {reference.evidence_id: reference for reference in self.task.evidence}
        facts = {fact.fact_id: fact for fact in self.facts.facts}
        for selection in self.facts.claims:
            allowed = {
                (references[key].table, references[key].private_locator, references[key].lineage)
                for group in claims[selection.claim_id].evidence_sets for key in group.evidence_ids
            }
            if any((facts[key].table, facts[key].subject_observation_id, facts[key].lineage) not in allowed
                   for key in selection.fact_ids):
                raise ValueError("canonical facts must remain within their claim-bound source evidence")
        canonical_fact_footprint(self.baseline, self.facts, self.review)
        return self

    @property
    def bucket(self) -> str:
        return f"incident:{self.task.scope.incident_id}" if self.task.scope.mode == "incident" else "tenant"

    @property
    def footprint(self) -> EvidenceFootprint:
        return canonical_fact_footprint(self.baseline, self.facts, self.review)


class QuestionBinding(Contract):
    task_id: Identifier
    task_fingerprint: Digest
    validation_fingerprint: Digest
    baseline_fingerprint: Digest
    facts_fingerprint: Digest
    review_fingerprint: Digest


class CohortBinding(Contract):
    questions: tuple[QuestionBinding, ...]


class BucketCounts(Contract):
    bucket: Identifier
    train: PositiveInt
    test: PositiveInt


class SplitRequest(Contract):
    seed: NonnegativeInt
    counts: Annotated[tuple[BucketCounts, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def unique_buckets(self) -> SplitRequest:
        require_unique(tuple(item.bucket for item in self.counts), "split-count buckets")
        return self


class Assignment(Contract):
    task_id: Identifier
    task_fingerprint: Digest
    partition: Partition


class SplitPlan(Contract):
    schema_version: Literal["1"] = "1"
    policy_version: Literal["question-level-overlap-reporting-v1"] = POLICY_VERSION
    cohort_fingerprint: Digest
    method: Literal["explicit", "sha256-ranked-v1"] = "explicit"
    request: SplitRequest | None = None
    assignments: Annotated[tuple[Assignment, ...], Field(min_length=1)]
    release_approved: Literal[False] = False

    @model_validator(mode="after")
    def explicit_method(self) -> SplitPlan:
        require_unique(tuple(item.task_id for item in self.assignments), "assigned task IDs")
        if (self.method == "sha256-ranked-v1") != (self.request is not None):
            raise ValueError("only a hash-ranked proposal requires an explicit seed/count request")
        return self


class QuestionSummary(QuestionBinding):
    revision_id: Identifier
    bucket: Identifier
    task_family: Text
    lineage_group: Identifier
    partition: Partition | None


class PairOverlap(Contract):
    left_task_id: Identifier
    right_task_id: Identifier
    left_task_fingerprint: Digest
    right_task_fingerprint: Digest
    left_bucket: Identifier
    right_bucket: Identifier
    scope_relation: Literal["same_incident", "cross_incident", "tenant_incident", "tenant_tenant"]
    partition_relation: Literal["unassigned", "train_train", "test_test", "train_test"]
    same_lineage: bool
    components: SimilarityComponents
    components_complete: bool
    score: Fraction | None
    score_status: Literal["unweighted", "complete", "incomplete"]
    shared_observation_count: NonnegativeInt | None
    shared_fact_count: NonnegativeInt | None
    reason: Text


class MetricSummary(Contract):
    available_pairs: NonnegativeInt
    minimum: Fraction | None
    mean: Fraction | None
    maximum: Fraction | None


class OverlapSummary(Contract):
    pair_count: NonnegativeInt
    complete_component_pairs: NonnegativeInt
    metrics: dict[str, MetricSummary]


class SplitAudit(Contract):
    schema_version: Literal["1"] = "1"
    policy_version: Literal["question-level-overlap-reporting-v1"] = POLICY_VERSION
    metric_version: Literal["evidence-overlap-v2"] = "evidence-overlap-v2"
    feature_weight_version: Identifier
    cohort_label: Identifier
    cohort_fingerprint: Digest
    snapshot_id: Identifier
    graph_version: Identifier
    serving_view_id: Identifier
    weights: SimilarityWeights | None
    plan: SplitPlan | None
    questions: tuple[QuestionSummary, ...]
    counts: dict[str, dict[str, int]]
    pairs: tuple[PairOverlap, ...]
    summaries: dict[str, OverlapSummary]
    components_complete: bool
    source_artifacts_sha256: dict[str, Digest] = Field(default_factory=dict)
    visibility: Literal["private_review"] = "private_review"
    shared_evidence_grouping: Literal[False] = False
    semantic_duplicate_review: Literal["not_performed"] = "not_performed"
    split_review_approved: Literal[False] = False
    release_approved: Literal[False] = False


@dataclass(frozen=True)
class LoadedQuestions:
    inputs: SplitInputs
    questions: tuple[SplitQuestion, ...]
    source_hashes: dict[str, str]
    annotation_directories: tuple[Path, ...]


def load_questions(path: Path) -> LoadedQuestions:
    """Load exact native/baseline/review bindings; do not rerun or forge source reviews."""
    hashes: dict[str, str] = {}

    def read(source: Path) -> bytes:
        data = source.read_bytes()
        hashes[str(source.resolve())] = hashlib.sha256(data).hexdigest()
        return data

    def resolve(name: str) -> Path:
        return (path.parent / name).resolve()

    inputs = SplitInputs.model_validate_json(read(path))
    runtime = {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
               for name in RUNTIME_FILES}
    questions = []
    directories = []
    for entry in inputs.questions:
        directory = resolve(entry.annotation)
        directories.append(directory)
        question = SplitQuestion(
            task=TaskRecord.model_validate_json(read(resolve(entry.task))),
            validation=ValidationReport.model_validate_json(read(resolve(entry.validation))),
            baseline=EvidenceFootprint.model_validate_json(read(resolve(entry.baseline))),
            facts=CanonicalFactBundle.model_validate_json(read(directory / "canonical-facts.json")),
            review=CanonicalFactReview.model_validate_json(read(directory / "reviewer/result.json")),
        )
        binding = json.loads(read(directory / "binding.json"))
        expected = {
            "task_fingerprint": fingerprint(question.task),
            "validation_fingerprint": fingerprint(question.validation),
            "baseline_fingerprint": fingerprint(question.baseline),
            "curation_version": CURATION_VERSION, "implementation_sha256": runtime,
        }
        if not isinstance(binding, dict) or any(binding.get(key) != value for key, value in expected.items()):
            raise ValueError(f"annotation binding/runtime differs for {question.task.task_id}")
        report = json.loads(read(directory / "fact_report.json"))
        if (not isinstance(report, dict) or report.get("status") != "canonical_facts_reviewed"
            or report.get("task_id") != question.task.task_id
            or report.get("bundle_fingerprint") != fingerprint(question.facts)):
            raise ValueError(f"annotation report differs for {question.task.task_id}")
        saved = EvidenceFootprint.model_validate_json(read(directory / "canonical-footprint.json"))
        if question.footprint != saved:
            raise ValueError(f"saved canonical footprint differs for {question.task.task_id}")
        questions.append(question)
    return LoadedQuestions(inputs, checked_cohort(tuple(questions)), hashes, tuple(directories))


def checked_cohort(questions: tuple[SplitQuestion, ...]) -> tuple[SplitQuestion, ...]:
    if not questions:
        raise ValueError("split planning requires a nonempty cohort")
    questions = tuple(SplitQuestion.model_validate(question) for question in questions)
    require_unique(tuple(question.task.task_id for question in questions), "cohort task IDs/revisions")
    contexts = {(q.task.snapshot_id, q.task.graph_version, q.task.serving_view_id, q.footprint.feature_weight_version)
                for q in questions}
    if len(contexts) != 1:
        raise ValueError("a split cohort must share source, graph, serving and feature-weight versions")
    return tuple(sorted(questions, key=lambda question: question.task.task_id))


def binding_for(question: SplitQuestion) -> QuestionBinding:
    return QuestionBinding(
        task_id=question.task.task_id, task_fingerprint=fingerprint(question.task),
        validation_fingerprint=fingerprint(question.validation), baseline_fingerprint=fingerprint(question.baseline),
        facts_fingerprint=fingerprint(question.facts), review_fingerprint=fingerprint(question.review),
    )


def cohort_fingerprint(questions: tuple[SplitQuestion, ...]) -> str:
    return fingerprint(CohortBinding(questions=tuple(binding_for(q) for q in checked_cohort(questions))))


def propose_split(questions: tuple[SplitQuestion, ...], request: SplitRequest) -> SplitPlan:
    questions = checked_cohort(questions)
    request = SplitRequest.model_validate(request)
    buckets: dict[str, list[SplitQuestion]] = defaultdict(list)
    for question in questions:
        buckets[question.bucket].append(question)
    counts = {item.bucket: item for item in request.counts}
    if counts.keys() != buckets.keys():
        raise ValueError("explicit split counts must cover exactly the cohort's incident/tenant buckets")
    assignments = []
    for bucket, members in sorted(buckets.items()):
        count = counts[bucket]
        if count.train + count.test != len(members):
            raise ValueError(f"train/test counts do not cover all admitted questions in {bucket}")

        def rank(question: SplitQuestion) -> tuple[str, str]:
            payload = json.dumps([request.seed, bucket, question.task.task_id, fingerprint(question.task)],
                                 separators=(",", ":"), ensure_ascii=True).encode("utf-8")
            return hashlib.sha256(payload).hexdigest(), question.task.task_id

        for index, question in enumerate(sorted(members, key=rank)):
            assignments.append(Assignment(
                task_id=question.task.task_id, task_fingerprint=fingerprint(question.task),
                partition="train" if index < count.train else "test",
            ))
    return SplitPlan(
        cohort_fingerprint=cohort_fingerprint(questions), method="sha256-ranked-v1", request=request,
        assignments=tuple(sorted(assignments, key=lambda item: item.task_id)),
    )


def validate_plan(questions: tuple[SplitQuestion, ...], plan: SplitPlan) -> dict[str, Partition]:
    plan = SplitPlan.model_validate(plan)
    if plan.cohort_fingerprint != cohort_fingerprint(questions):
        raise ValueError("split plan does not match the current task/native/fact-review cohort")
    assigned = {item.task_id: item for item in plan.assignments}
    if assigned.keys() != {question.task.task_id for question in questions}:
        raise ValueError("split assignments must cover every admitted question exactly once")
    by_bucket: dict[str, set[str]] = defaultdict(set)
    for question in questions:
        item = assigned[question.task.task_id]
        if item.task_fingerprint != fingerprint(question.task):
            raise ValueError("split assignment belongs to a different task revision")
        by_bucket[question.bucket].add(item.partition)
    if any(partitions != {"train", "test"} for partitions in by_bucket.values()):
        raise ValueError("each incident/tenant bucket requires an explicit nonempty train and test partition")
    if plan.request is not None and plan != propose_split(questions, plan.request):
        raise ValueError("hash-ranked assignments do not reproduce their declared seed and counts")
    return {task_id: item.partition for task_id, item in assigned.items()}


def _shared_count(
    left: tuple[WeightedFeature, ...] | None, right: tuple[WeightedFeature, ...] | None,
) -> int | None:
    if not left or not right:
        return None
    return len({item.feature_id for item in left} & {item.feature_id for item in right})


def _summarize(pairs: list[PairOverlap]) -> OverlapSummary:
    metrics = {}
    for name in ("edges", "observations", "facts", "containment", "score"):
        values = [pair.score if name == "score" else getattr(pair.components, name) for pair in pairs]
        present = [value for value in values if value is not None]
        metrics[name] = MetricSummary(
            available_pairs=len(present), minimum=min(present) if present else None,
            mean=mean(present) if present else None, maximum=max(present) if present else None,
        )
    return OverlapSummary(pair_count=len(pairs), complete_component_pairs=sum(p.components_complete for p in pairs),
                          metrics=metrics)


def audit_splits(
    questions: tuple[SplitQuestion, ...], *, cohort_label: str,
    plan: SplitPlan | None = None, weights: SimilarityWeights | None = None,
) -> SplitAudit:
    questions = checked_cohort(questions)
    weights = SimilarityWeights.model_validate(weights) if weights is not None else None
    assigned = validate_plan(questions, plan) if plan is not None else {}
    counts: dict[str, dict[str, int]] = {}
    inventory = []
    footprints = {q.task.task_id: q.footprint for q in questions}
    for question in questions:
        partition = assigned.get(question.task.task_id)
        bucket = counts.setdefault(question.bucket, {"total": 0, "train": 0, "test": 0, "unassigned": 0})
        bucket["total"] += 1
        bucket[partition if partition is not None else "unassigned"] += 1
        inventory.append(QuestionSummary(
            **binding_for(question).model_dump(), revision_id=question.task.revision_id,
            bucket=question.bucket, task_family=question.task.task_family,
            lineage_group=question.task.lineage_group, partition=partition,
        ))
    pairs = []
    groups: dict[str, list[PairOverlap]] = defaultdict(list)
    for left, right in combinations(questions, 2):
        a, b = footprints[left.task.task_id], footprints[right.task.task_id]
        edge, _ = weighted_overlap(a.edges, b.edges)
        observation, _ = weighted_overlap(a.observations, b.observations)
        fact, _ = weighted_overlap(a.facts, b.facts)
        _, containment = weighted_overlap(decisive_features(a), decisive_features(b))
        components = SimilarityComponents(edges=edge, observations=observation, facts=fact, containment=containment)
        complete = all(value is not None for value in (edge, observation, fact, containment))
        score = None
        score_status: Literal["unweighted", "complete", "incomplete"] = "unweighted"
        reason = "Aggregate weights were not supplied; components are reported without an aggregate score."
        if not complete:
            score_status = "incomplete"
            reason = "Missing/empty required footprint components are unscorable, not zero overlap."
        if weights is not None:
            result = evidence_similarity(a, b, weights)
            if result.status == "error":
                raise ValueError(result.reason)
            score = result.score
            score_status = "complete" if result.status == "complete" else "incomplete"
            reason = result.reason
        if left.task.scope.mode != right.task.scope.mode:
            scope_relation = "tenant_incident"
        elif left.task.scope.mode == "tenant":
            scope_relation = "tenant_tenant"
        else:
            scope_relation = "same_incident" if left.bucket == right.bucket else "cross_incident"
        partition_relation = "unassigned"
        if plan is not None:
            pair_partitions = {assigned[left.task.task_id], assigned[right.task.task_id]}
            partition_relation = "train_test" if len(pair_partitions) == 2 else (
                "train_train" if pair_partitions == {"train"} else "test_test"
            )
        pair = PairOverlap(
            left_task_id=left.task.task_id, right_task_id=right.task.task_id,
            left_task_fingerprint=a.task_fingerprint, right_task_fingerprint=b.task_fingerprint,
            left_bucket=left.bucket, right_bucket=right.bucket,
            scope_relation=scope_relation, partition_relation=partition_relation,
            same_lineage=left.task.lineage_group == right.task.lineage_group,
            components=components, components_complete=complete, score=score, score_status=score_status,
            shared_observation_count=_shared_count(a.observations, b.observations),
            shared_fact_count=_shared_count(a.facts, b.facts), reason=reason,
        )
        pairs.append(pair)
        groups[f"{scope_relation}/{partition_relation}"].append(pair)
        left_bucket, right_bucket = sorted((left.bucket, right.bucket))
        groups[f"{left_bucket}/{right_bucket}/{partition_relation}"].append(pair)
    summaries = {"all": _summarize(pairs), **{key: _summarize(values) for key, values in sorted(groups.items())}}
    first = questions[0]
    return SplitAudit(
        feature_weight_version=first.footprint.feature_weight_version, cohort_label=cohort_label,
        cohort_fingerprint=cohort_fingerprint(questions), snapshot_id=first.task.snapshot_id,
        graph_version=first.task.graph_version, serving_view_id=first.task.serving_view_id,
        weights=weights, plan=plan, questions=tuple(inventory), counts=counts, pairs=tuple(pairs), summaries=summaries,
        components_complete=all(pair.components_complete for pair in pairs),
    )


def write_split_audit(audit: SplitAudit, output: Path, loaded: LoadedQuestions) -> None:
    if audit.cohort_fingerprint != cohort_fingerprint(loaded.questions) or audit.cohort_label != loaded.inputs.cohort_label:
        raise ValueError("audit does not match the loaded input cohort")
    if output.exists() or any(output.resolve().is_relative_to(path) for path in loaded.annotation_directories):
        raise ValueError("split audit output must be new and outside annotation bundles")
    data = audit.model_dump(mode="json")
    data["source_artifacts_sha256"] = loaded.source_hashes
    audit = SplitAudit.model_validate_json(json.dumps(data))
    output.mkdir(parents=True, mode=0o700)
    if audit.plan is not None:
        (output / "split-plan.json").write_text(audit.plan.model_dump_json(indent=2) + "\n")
    fields = ("left_task_id", "right_task_id", "left_task_fingerprint", "right_task_fingerprint",
              "left_bucket", "right_bucket", "scope_relation", "partition_relation", "same_lineage",
              "edges", "observations", "facts", "containment", "components_complete",
              "score", "score_status", "shared_observation_count", "shared_fact_count", "reason")
    with (output / "pair-overlap.csv").open("x", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for pair in audit.pairs:
            row = pair.model_dump(mode="json")
            row.update(row.pop("components"))
            writer.writerow(row)
    (output / "split-audit.json").write_text(audit.model_dump_json(indent=2) + "\n")
