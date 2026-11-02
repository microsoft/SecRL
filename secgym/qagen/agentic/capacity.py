# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Observed-pool overlap capacity bounds; never admission, grouping or source-exhaustion claims."""

from __future__ import annotations

import csv
import hashlib
import json
from collections import defaultdict
from itertools import combinations
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .contracts import Contract, Fraction, Identifier, NonnegativeInt, PositiveInt, SimilarityWeights, fingerprint, require_unique
from .question_splits import LoadedQuestions, binding_for, checked_cohort, cohort_fingerprint
from .similarity import evidence_similarity


VERSION = "observed-overlap-capacity-v1"
DIAGNOSTIC_WEIGHTS = SimilarityWeights(edges=0.25, observations=0.25, facts=0.25, containment=0.25)


class CapacityRequest(Contract):
    thresholds: Annotated[tuple[Fraction, ...], Field(min_length=1)] = (0.25, 0.50, 0.75, 0.90)
    search_budget_states: PositiveInt

    @model_validator(mode="after")
    def ordered_thresholds(self) -> CapacityRequest:
        if tuple(sorted(set(self.thresholds))) != self.thresholds:
            raise ValueError("capacity thresholds must be strictly increasing and duplicate-free")
        return self


class CapacityPoint(Contract):
    bucket: Identifier
    threshold: Fraction
    observed_questions: PositiveInt
    status: Literal["exact_observed_pool", "bounded_observed_pool", "unscorable"]
    lower_bound: NonnegativeInt | None
    upper_bound: NonnegativeInt | None
    example_task_ids: tuple[Identifier, ...]
    search_states: NonnegativeInt
    unscorable_pairs: NonnegativeInt
    pairwise_limit_verified: bool

    @model_validator(mode="after")
    def consistent_bounds(self) -> CapacityPoint:
        require_unique(self.example_task_ids, "capacity example task IDs")
        if self.status == "unscorable":
            if (self.lower_bound is not None or self.upper_bound is not None or self.example_task_ids
                or not self.unscorable_pairs or self.pairwise_limit_verified or self.search_states):
                raise ValueError("unknown pair measurements cannot produce success-shaped capacity bounds")
        else:
            if (self.lower_bound is None or self.upper_bound is None
                or not 1 <= self.lower_bound <= self.upper_bound <= self.observed_questions
                or len(self.example_task_ids) != self.lower_bound or self.unscorable_pairs
                or not self.pairwise_limit_verified):
                raise ValueError("capacity bounds require a complete measured pool and a verified example")
            if (self.status == "exact_observed_pool") != (self.lower_bound == self.upper_bound):
                raise ValueError("exact observed capacity requires matching lower and upper bounds")
        return self


def _vertices(mask: int):
    while mask:
        bit = mask & -mask
        yield bit.bit_length() - 1
        mask ^= bit


def _color_bound(candidates: int, compatible: tuple[int, ...]) -> int:
    colors = 0
    remaining = candidates
    while remaining:
        colors += 1
        available = remaining
        while available:
            vertex = (available & -available).bit_length() - 1
            remaining &= ~(1 << vertex)
            available &= ~((1 << vertex) | compatible[vertex])
    return colors


def _greedy_clique(candidates: int, compatible: tuple[int, ...]) -> tuple[int, ...]:
    chosen = []
    while candidates:
        vertex = max(_vertices(candidates), key=lambda index: ((compatible[index] & candidates).bit_count(), -index))
        chosen.append(vertex)
        candidates &= compatible[vertex]
    return tuple(chosen)


def compatible_subset_bounds(conflicts: tuple[int, ...], *, search_budget_states: int) -> tuple[tuple[int, ...], int, int]:
    """Return a certified compatible subset, a valid observed-pool upper bound, and explored states."""
    if type(search_budget_states) is not int or search_budget_states < 1:
        raise ValueError("capacity search requires a positive explicit state budget")
    n = len(conflicts)
    if not n:
        raise ValueError("capacity search requires a nonempty observed bucket")
    universe = (1 << n) - 1
    for index, neighbors in enumerate(conflicts):
        if type(neighbors) is not int or neighbors < 0 or neighbors & ~universe or neighbors & (1 << index):
            raise ValueError("conflict masks must be in-range and irreflexive")
        if any(not conflicts[other] & (1 << index) for other in _vertices(neighbors)):
            raise ValueError("conflict masks must be symmetric")
    compatible = tuple(universe & ~(neighbors | (1 << index)) for index, neighbors in enumerate(conflicts))
    best = _greedy_clique(universe, compatible)
    initial_upper = _color_bound(universe, compatible)
    frontier: list[tuple[tuple[int, ...], int, int]] = [((), universe, initial_upper)]
    states = 0
    while frontier and states < search_budget_states:
        chosen, candidates, upper = frontier.pop()
        states += 1
        if upper <= len(best):
            continue
        extended = chosen + _greedy_clique(candidates, compatible)
        if len(extended) > len(best):
            best = extended
        if upper <= len(best) or not candidates:
            continue
        vertex = max(_vertices(candidates), key=lambda index: ((compatible[index] & candidates).bit_count(), -index))
        for selected, remaining in (
            (chosen, candidates & ~(1 << vertex)),
            ((*chosen, vertex), candidates & compatible[vertex]),
        ):
            bound = len(selected) + _color_bound(remaining, compatible)
            if bound > len(best):
                frontier.append((selected, remaining, bound))
    upper = max((bound for _, _, bound in frontier), default=len(best))
    upper = max(upper, len(best))
    best = tuple(sorted(best))
    if any(conflicts[left] & (1 << right) for left, right in combinations(best, 2)):
        raise ValueError("internal capacity certificate contains a conflicting pair")
    return best, upper, states


def report_capacity(loaded: LoadedQuestions, output: Path, request: CapacityRequest) -> dict:
    questions = checked_cohort(loaded.questions)
    request = CapacityRequest.model_validate(request)
    if output.exists() or any(output.resolve().is_relative_to(path) for path in loaded.annotation_directories):
        raise ValueError("capacity output must be new and outside source annotation bundles")
    buckets = defaultdict(list)
    for question in questions:
        buckets[question.bucket].append(question)
    output.mkdir(mode=0o700, parents=True)
    points = []
    pair_count = 0
    with (output / "within-scope-pairs.csv").open("x", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=(
            "bucket", "left_task_id", "right_task_id", "left_task_fingerprint", "right_task_fingerprint",
            "edges", "observations", "facts", "containment", "score", "status",
        ))
        writer.writeheader()
        for bucket, members in sorted(buckets.items()):
            footprints = [question.footprint for question in members]
            conflicts = {threshold: [0] * len(members) for threshold in request.thresholds}
            unscorable = 0
            for left, right in combinations(range(len(members)), 2):
                result = evidence_similarity(footprints[left], footprints[right], DIAGNOSTIC_WEIGHTS)
                if result.status == "error" or result.components is None:
                    raise ValueError(result.reason)
                writer.writerow({
                    "bucket": bucket, "left_task_id": members[left].task.task_id,
                    "right_task_id": members[right].task.task_id,
                    "left_task_fingerprint": fingerprint(members[left].task),
                    "right_task_fingerprint": fingerprint(members[right].task),
                    **result.components.model_dump(mode="json"), "score": result.score, "status": result.status,
                })
                pair_count += 1
                if result.status != "complete" or result.score is None:
                    unscorable += 1
                    continue
                for threshold, graph in conflicts.items():
                    if result.score > threshold:
                        graph[left] |= 1 << right
                        graph[right] |= 1 << left
            for threshold, graph in conflicts.items():
                if unscorable:
                    point = CapacityPoint(
                        bucket=bucket, threshold=threshold, observed_questions=len(members), status="unscorable",
                        lower_bound=None, upper_bound=None, example_task_ids=(), search_states=0,
                        unscorable_pairs=unscorable, pairwise_limit_verified=False,
                    )
                else:
                    chosen, upper, states = compatible_subset_bounds(tuple(graph), search_budget_states=request.search_budget_states)
                    point = CapacityPoint(
                        bucket=bucket, threshold=threshold, observed_questions=len(members),
                        status="exact_observed_pool" if len(chosen) == upper else "bounded_observed_pool",
                        lower_bound=len(chosen), upper_bound=upper,
                        example_task_ids=tuple(members[index].task.task_id for index in chosen), search_states=states,
                        unscorable_pairs=0, pairwise_limit_verified=True,
                    )
                points.append(point)
    with (output / "capacity.csv").open("x", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=(
            "bucket", "threshold", "observed_questions", "status", "lower_bound", "upper_bound",
            "search_states", "unscorable_pairs", "pairwise_limit_verified",
        ))
        writer.writeheader()
        for point in points:
            writer.writerow(point.model_dump(mode="json", exclude={"example_task_ids"}))
    from .ledger import file_sha256

    report = {
        "schema_version": "1", "policy_version": VERSION, "cohort_label": loaded.inputs.cohort_label,
        "cohort_fingerprint": cohort_fingerprint(questions), "question_count": len(questions),
        "questions": [{"bucket": question.bucket, **binding_for(question).model_dump(mode="json")} for question in questions],
        "snapshot_id": questions[0].task.snapshot_id, "graph_version": questions[0].task.graph_version,
        "serving_view_id": questions[0].task.serving_view_id,
        "feature_weight_version": questions[0].footprint.feature_weight_version,
        "request": request.model_dump(mode="json"), "diagnostic_weights": DIAGNOSTIC_WEIGHTS.model_dump(mode="json"),
        "threshold_semantics": "Every selected pair has aggregate overlap <= threshold; equality is permitted.",
        "points": [point.model_dump(mode="json") for point in points], "within_scope_pairs": pair_count,
        "measurements_complete": all(point.status != "unscorable" for point in points),
        "all_observed_pool_optima_proven": all(point.status == "exact_observed_pool" for point in points),
        "method": "Deterministic maximum compatible-subset search with greedy feasible lower bounds and coloring upper bounds.",
        "source_artifacts_sha256": loaded.source_hashes,
        "pair_report_sha256": file_sha256(output / "within-scope-pairs.csv"),
        "implementation_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "capacity_scope": "Observed admitted questions in each represented incident/tenant bucket only.",
        "absolute_source_capacity_established": False, "source_saturation_established": False,
        "generation_yield_measured": False, "admission_changed": False, "questions_removed": False,
        "groups_forced": False, "split_changed": False, "grading_changed": False, "release_approved": False,
        "cross_scope_overlap": "Not constrained by these curves; retain the separately bound full overlap audit.",
    }
    (output / "capacity-report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report
