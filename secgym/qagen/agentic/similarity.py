# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Version-bound evidence overlap, without automatic split/removal decisions."""

from fractions import Fraction

from pydantic import model_validator

from .contracts import (
    Contract, Digest, Identifier, PositiveFloat, SimilarityComponents, SimilarityRecord,
    SimilarityWeights, require_unique,
)


class WeightedFeature(Contract):
    feature_id: Identifier
    weight: PositiveFloat


class EvidenceFootprint(Contract):
    task_fingerprint: Digest
    snapshot_id: Identifier
    graph_version: Identifier
    feature_weight_version: Identifier
    edges: tuple[WeightedFeature, ...] | None
    observations: tuple[WeightedFeature, ...] | None
    facts: tuple[WeightedFeature, ...] | None

    @model_validator(mode="after")
    def unique_features(self):
        for features in (self.edges, self.observations, self.facts):
            if features is not None:
                require_unique(tuple(f.feature_id for f in features), "footprint features")
        return self


def weighted_overlap(left, right) -> tuple[float | None, float | None]:
    if not left or not right:
        return None, None
    a = {f.feature_id: Fraction(str(f.weight)) for f in left}
    b = {f.feature_id: Fraction(str(f.weight)) for f in right}
    shared = a.keys() & b.keys()
    if any(a[key] != b[key] for key in shared):
        raise ValueError("the same feature has conflicting weights under one weight version")
    intersection = sum((a[key] for key in shared), Fraction(0))
    total_a, total_b = sum(a.values(), Fraction(0)), sum(b.values(), Fraction(0))
    return float(intersection / (total_a + total_b - intersection)), float(intersection / min(total_a, total_b))


def decisive_features(footprint: EvidenceFootprint) -> tuple[WeightedFeature, ...] | None:
    if not footprint.observations or not footprint.facts:
        return None
    return tuple(
        WeightedFeature(feature_id=f"{namespace}:{feature.feature_id}", weight=feature.weight)
        for namespace, features in (("observation", footprint.observations), ("fact", footprint.facts))
        for feature in features
    )


def evidence_similarity(left: EvidenceFootprint, right: EvidenceFootprint, weights: SimilarityWeights) -> SimilarityRecord:
    left, right = EvidenceFootprint.model_validate(left), EvidenceFootprint.model_validate(right)
    weights = SimilarityWeights.model_validate(weights)
    common = {
        "metric_version": "evidence-overlap-v2",
        "feature_weight_version": left.feature_weight_version,
        "left_task_fingerprint": left.task_fingerprint, "right_task_fingerprint": right.task_fingerprint,
        "weights": weights,
    }
    if (left.snapshot_id, left.graph_version, left.feature_weight_version) != (
        right.snapshot_id, right.graph_version, right.feature_weight_version,
    ):
        return SimilarityRecord(**common, status="incomplete", components=None, score=None,
                                reason="Footprints need the same source, graph and feature-weight versions.")
    try:
        edge, _ = weighted_overlap(left.edges, right.edges)
        observation, _ = weighted_overlap(left.observations, right.observations)
        fact, _ = weighted_overlap(left.facts, right.facts)
        _, containment = weighted_overlap(decisive_features(left), decisive_features(right))
    except ValueError as error:
        return SimilarityRecord(**common, status="error", components=None, score=None,
                                reason=str(error), error_code="feature_weight_conflict")
    components = SimilarityComponents(edges=edge, observations=observation, facts=fact, containment=containment)
    values = (edge, observation, fact, containment)
    if any(value is None for value in values):
        return SimilarityRecord(**common, status="incomplete", components=components, score=None,
                                reason="Missing or empty footprint components are unscorable, not zero overlap.")
    score = sum(weight * value for weight, value in zip(
        (weights.edges, weights.observations, weights.facts, weights.containment), values,
    ) if value is not None)
    return SimilarityRecord(**common, status="complete", components=components, score=score,
                            reason="Weighted Jaccard overlaps; containment uses the namespaced observation/fact union over the smaller decisive footprint.")
