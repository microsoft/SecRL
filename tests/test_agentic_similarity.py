# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import unittest

from secgym.qagen.agentic.contracts import SimilarityWeights
from secgym.qagen.agentic.similarity import EvidenceFootprint, WeightedFeature, evidence_similarity


class EvidenceSimilarityTests(unittest.TestCase):
    def footprint(self, ids, **changes):
        features = tuple(WeightedFeature(feature_id=value, weight=1.0) for value in ids)
        fields = dict(task_fingerprint="a" * 64, snapshot_id="snapshot", graph_version="graph",
                      feature_weight_version="fixture-weights", edges=features, observations=features, facts=features)
        fields.update(changes)
        return EvidenceFootprint(**fields)

    def weights(self):
        return SimilarityWeights(edges=0.25, observations=0.25, facts=0.25, containment=0.25)

    def test_identical_disjoint_and_contained_footprints(self):
        one = self.footprint(["one"])
        self.assertEqual(evidence_similarity(one, one, self.weights()).score, 1.0)
        self.assertEqual(evidence_similarity(one, self.footprint(["two"]), self.weights()).score, 0.0)
        contained = evidence_similarity(one, self.footprint(["one", "two"]), self.weights())
        self.assertEqual(contained.components.containment, 1.0)
        self.assertEqual(contained.score, 0.625)

    def test_missing_is_not_zero_even_for_a_zero_weight_component(self):
        result = evidence_similarity(self.footprint(["one"], edges=None), self.footprint(["one"]),
                                     SimilarityWeights(edges=0.0, observations=1.0, facts=0.0, containment=0.0))
        self.assertEqual(result.status, "incomplete")
        self.assertIsNone(result.score)
        self.assertIsNone(result.components.edges)
        self.assertEqual(result.components.observations, 1.0)

    def test_version_and_feature_weight_conflicts_fail_closed(self):
        self.assertEqual(evidence_similarity(self.footprint(["one"]), self.footprint(["one"], graph_version="other"),
                                             self.weights()).status, "incomplete")
        conflict = self.footprint(["one"], edges=(WeightedFeature(feature_id="one", weight=2.0),))
        result = evidence_similarity(self.footprint(["one"]), conflict, self.weights())
        self.assertEqual(result.status, "error")
        self.assertIsNone(result.score)

    def test_duplicate_features_do_not_inflate_overlap(self):
        with self.assertRaises(ValueError):
            self.footprint(["one", "one"])

    def test_containment_includes_facts_without_namespace_collisions(self):
        left = self.footprint(["shared"], facts=(WeightedFeature(feature_id="fact-left", weight=2.0),))
        right = self.footprint(["shared"], facts=(WeightedFeature(feature_id="shared", weight=2.0),))
        result = evidence_similarity(left, right, self.weights())
        self.assertEqual(result.metric_version, "evidence-overlap-v2")
        self.assertEqual(result.components.observations, 1.0)
        self.assertEqual(result.components.facts, 0.0)
        self.assertAlmostEqual(result.components.containment, 1 / 3)
        self.assertEqual(result.score, evidence_similarity(right, left, self.weights()).score)

    def test_shared_facts_count_even_with_disjoint_observation_sets(self):
        left = self.footprint(["left"], facts=(WeightedFeature(feature_id="same-fact", weight=3.0),))
        right = self.footprint(["right"], facts=left.facts)
        result = evidence_similarity(left, right, self.weights())
        self.assertEqual(result.components.observations, 0.0)
        self.assertEqual(result.components.facts, 1.0)
        self.assertEqual(result.components.containment, 0.75)
        missing = evidence_similarity(left, self.footprint(["left"], facts=None), self.weights())
        self.assertEqual(missing.status, "incomplete")
        self.assertIsNone(missing.components.containment)


if __name__ == "__main__":
    unittest.main()
