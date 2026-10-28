# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import unittest
from pathlib import Path

from secgym.qagen.agentic.contracts import (
    RewardPolicy, ScoreComponent, TaskRecord, TypedAnswer, normalized_checkpoint_progress,
)
from secgym.qagen.agentic.scoring import aggregate_evaluation, compare_checkpoint_finding, compare_typed_answers


def answer(kind, value, **options):
    return TypedAnswer.model_validate_json(json.dumps({
        "format": {"kind": kind, "semantic_kind": "fixture", **options}, "value": value,
    }))


class TypedComparisonTests(unittest.TestCase):
    def test_checkpoint_descriptions_are_not_private_rubric_tokens(self):
        expected = answer("entity", "CaseSensitivePath", semantic_kind="private_created_file_path")
        submitted = answer("entity", "CaseSensitivePath", semantic_kind="file_path")
        self.assertTrue(compare_checkpoint_finding(expected, submitted))
        self.assertFalse(compare_checkpoint_finding(expected, answer("entity", "casesensitivepath",
                                                                    semantic_kind="file_path", normalization="casefold")))
        self.assertFalse(compare_checkpoint_finding(answer("number", 42, units="pid"),
                                                    answer("number", 42, units="bytes")))

    def test_finding_invalid_under_the_rubric_is_not_a_scorer_error(self):
        expected = answer("set", ["Item"], normalization="casefold")
        submitted = answer("set", ["Item", "item"])
        self.assertFalse(compare_checkpoint_finding(expected, submitted))

    def test_entities_are_exact_without_substrings_domain_stripping_or_trimming(self):
        expected = answer("entity", "User@one.test")
        for value in ("User", "User@two.test", "user@one.test", " User@one.test", "User@one.test extra"):
            self.assertFalse(compare_typed_answers(expected, answer("entity", value)))
        self.assertTrue(compare_typed_answers(expected, expected))

    def test_casefold_requires_explicit_task_policy(self):
        expected = answer("entity", "User@one.test", normalization="casefold")
        self.assertTrue(compare_typed_answers(expected, answer("entity", "user@one.test", normalization="casefold")))
        with self.assertRaisesRegex(ValueError, "declared comparison policy"):
            compare_typed_answers(answer("entity", "A"), answer("entity", "a", normalization="casefold"))

    def test_set_equality_rejects_supersets_and_ordered_lists_preserve_duplicates(self):
        self.assertTrue(compare_typed_answers(answer("set", ["a", "b"]), answer("set", ["b", "a"])))
        self.assertFalse(compare_typed_answers(answer("set", ["a"]), answer("set", ["a", "b"])))
        self.assertFalse(compare_typed_answers(answer("ordered_list", ["a", "a"]), answer("ordered_list", ["a"])))
        self.assertFalse(compare_typed_answers(answer("ordered_list", ["a", "b"]), answer("ordered_list", ["b", "a"])))
        self.assertTrue(compare_typed_answers(answer("set", []), answer("set", [])))

    def test_numeric_tolerance_has_exact_inclusive_boundary(self):
        expected = answer("number", 0.1, units="seconds", tolerance=0.2)
        self.assertTrue(compare_typed_answers(expected, answer("number", 0.3, units="seconds", tolerance=0.2)))
        self.assertFalse(compare_typed_answers(expected, answer("number", 0.30000000000000004, units="seconds", tolerance=0.2)))

    def test_large_integers_do_not_lose_precision(self):
        expected = answer("number", 10**100, units="records")
        self.assertFalse(compare_typed_answers(expected, answer("number", 10**100 + 1, units="records")))
        self.assertFalse(compare_typed_answers(answer("number", 2**53 + 1, units="records"),
                                             answer("number", float(2**53 + 1), units="records")))

    def test_timestamp_offsets_and_microsecond_boundary(self):
        expected = answer("timestamp", "2024-01-01T10:00:00Z", units="seconds", tolerance=0.000001)
        self.assertTrue(compare_typed_answers(expected, answer("timestamp", "2024-01-01T11:00:00.000001+01:00",
                                                               units="seconds", tolerance=0.000001)))
        self.assertFalse(compare_typed_answers(expected, answer("timestamp", "2024-01-01T09:59:59.999998Z",
                                                                units="seconds", tolerance=0.000001)))

    def test_boolean_is_not_numeric_and_invalid_answers_raise(self):
        self.assertFalse(compare_typed_answers(answer("boolean", True), answer("boolean", False)))
        for kind, value, options in (("boolean", 1, {}), ("number", True, {"units": "records"}),
                                     ("timestamp", "2024-01-01T10:00:00", {"units": "seconds"}),
                                     ("set", ["a", "a"], {})):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                answer(kind, value, **options)

    def test_submicrosecond_timestamps_are_not_silently_rounded_equal(self):
        expected = answer("timestamp", "2024-01-01T10:00:00.1234567Z", units="seconds")
        self.assertFalse(compare_typed_answers(expected, answer("timestamp", "2024-01-01T10:00:00.1234568Z", units="seconds")))
        self.assertTrue(compare_typed_answers(expected, answer("timestamp", "2024-01-01T11:00:00.1234567+01:00", units="seconds")))


class AggregationTests(unittest.TestCase):
    def setUp(self):
        self.task_data = json.loads((Path(__file__).parent / "fixtures/agentic_task.json").read_text())
        self.task = TaskRecord.model_validate_json(json.dumps(self.task_data))

    def component(self, kind, score=1.0, *, component_id=None, **changes):
        data = {
            "component_id": component_id or ("private-checkpoint" if kind == "checkpoint" else kind),
            "kind": kind, "status": "complete", "score": score, "max_score": 1.0, "weight": 1.0,
            "evidence": [] if kind == "answer_correctness" else [{"table": "DeviceProcessEvents", "record_id": "public-row-17"}],
            "trajectory_steps": [2] if kind == "checkpoint" else [],
            "first_completion_step": 2 if kind == "checkpoint" and score == 1.0 else None,
            "explanation": "Synthetic trusted component verdict, not independently verified source evidence.",
            "evaluator_version": "fixture-evaluator",
        }
        data.update(changes)
        return ScoreComponent.model_validate_json(json.dumps(data))

    def aggregate(self, answer_score=1.0, evidence_score=1.0, **changes):
        values = {
            "run_id": "fixture-run", "backend": "secrl", "trajectory_ref": "fixture:trajectory",
            "answer_correctness": self.component("answer_correctness", answer_score),
            "final_evidence": self.component("final_evidence", evidence_score),
            "checkpoints": (self.component("checkpoint"),),
        }
        values.update(changes)
        return aggregate_evaluation(self.task, **values)

    def test_checkpoint_only_reward_is_capped_even_if_final_answer_is_correct(self):
        result = self.aggregate(evidence_score=0.0)
        self.assertEqual(result.answer_correctness.score, 1.0)
        self.assertFalse(result.grounded_final)
        self.assertEqual(result.checkpoint_progress, 1.0)
        self.assertEqual(result.aggregate_reward, 0.5)
        self.assertEqual(self.aggregate(answer_score=0.0).aggregate_reward, 0.5)
        self.assertEqual(self.aggregate().aggregate_reward, 1.0)

    def test_completed_final_does_not_require_checkpoint_credit(self):
        result = self.aggregate(checkpoints=(self.component("checkpoint", 0.0),))
        self.assertEqual(result.aggregate_reward, 1.0)
        self.assertEqual(result.checkpoint_progress, 0.0)

    def test_missing_checkpoint_components_cannot_produce_a_final_only_score(self):
        with self.assertRaisesRegex(ValueError, "nonempty rubric"):
            normalized_checkpoint_progress(())
        with self.assertRaisesRegex(ValueError, "nonempty rubric"):
            self.aggregate(checkpoints=())

    def test_error_or_incomplete_components_do_not_become_zero_or_completed_rewards(self):
        for status in ("error", "incomplete"):
            with self.subTest(status=status):
                checkpoint = self.component("checkpoint", None, status=status, first_completion_step=None,
                                            error_code="timeout" if status == "error" else None)
                result = self.aggregate(checkpoints=(checkpoint,))
                self.assertEqual(result.status, status)
                self.assertIsNone(result.aggregate_reward)
                self.assertIsNone(result.grounded_final)
                self.assertIsNone(result.checkpoint_progress)
                self.assertEqual(result.checkpoints[0], checkpoint)

    def test_rubric_ids_maxima_weights_and_completion_metadata_are_checked(self):
        for changes in ({"component_id": "unknown"}, {"max_score": 2.0, "first_completion_step": None},
                        {"weight": 2.0}, {"first_completion_step": None}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.aggregate(checkpoints=(self.component("checkpoint", **changes),))
        with self.assertRaises(ValueError):
            self.aggregate(checkpoints=(self.component("checkpoint"), self.component("checkpoint")))

    def test_semantic_dependencies_do_not_enforce_trajectory_order(self):
        second = json.loads(json.dumps(self.task_data["private_gold"]["checkpoints"][0]))
        second.update(checkpoint_id="second", depends_on=["private-checkpoint"])
        self.task_data["private_gold"]["checkpoints"].append(second)
        self.task = TaskRecord.model_validate_json(json.dumps(self.task_data))
        child = self.component("checkpoint", component_id="second", trajectory_steps=[1], first_completion_step=1)
        with self.assertRaisesRegex(ValueError, "semantic dependency"):
            self.aggregate(checkpoints=(self.component("checkpoint", 0.0), child))
        result = self.aggregate(checkpoints=(self.component("checkpoint"), child))
        self.assertEqual(result.aggregate_reward, 1.0)

    def test_large_and_small_finite_weights_do_not_overflow_or_underflow(self):
        for scale in (1e308, 1e-308):
            component = self.component("checkpoint", scale / 2, max_score=scale, weight=scale, first_completion_step=None)
            self.assertEqual(normalized_checkpoint_progress((component,)), 0.5)

    def test_explicit_reaggregation_retains_components_and_backend_shapes(self):
        policy = RewardPolicy(policy_version="another-fixture-policy", checkpoint_cap=0.7)
        left = self.aggregate(evidence_score=0.0, reward_policy=policy)
        right = self.aggregate(evidence_score=0.0, reward_policy=policy, backend="acesevals")
        self.assertEqual(left.aggregate_reward, 0.7)
        self.assertEqual(right.aggregate_reward, left.aggregate_reward)
        self.assertEqual(left.checkpoints, right.checkpoints)
        self.assertEqual(left.reward_policy, policy)
        self.assertEqual(left.task_fingerprint, right.task_fingerprint)


if __name__ == "__main__":
    unittest.main()
