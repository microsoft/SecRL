# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import hashlib
import math
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from secgym.qagen.agentic.panel_analysis import analyze_panel, load_panel, paired_comparison, spearman, wilson


class PanelStatisticsTests(unittest.TestCase):
    def test_correct_answers_and_grounded_success_are_distinct_validation_measures(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = {
                "models": ["fixture"], "cohort_fingerprint": "cohort",
                "episodes": [{"model": "fixture"}] * 2,
                "difficulty_inventory": {"a": {"band": "medium"}, "b": {"band": "hard"}},
            }
            (root / "manifest.json").write_text(json.dumps(manifest))
            rows = [
                {"model": "fixture", "task_fingerprint": "a", "task_id": "a", "bucket": "tenant", "band": "medium",
                 "score": 40.0, "grounded_final": True, "answer_correctness": 1.0, "checkpoint_progress": 1.0,
                 "status": "completed", "output_tokens": 10, "grader_timeout_ms": 30000},
                {"model": "fixture", "task_fingerprint": "b", "task_id": "b", "bucket": "tenant", "band": "hard",
                 "score": 70.0, "grounded_final": False, "answer_correctness": 1.0, "checkpoint_progress": 0.0,
                 "status": "completed", "output_tokens": 20, "grader_timeout_ms": 120000},
            ]
            with patch("secgym.qagen.agentic.panel_analysis.load_panel", return_value=(manifest, rows, [])):
                report = analyze_panel(root, root / "analysis", samples=10)
            result = report["models"]["fixture"]
            self.assertEqual(result["success_rate"], 0.5)
            self.assertEqual(result["answer_only_accuracy"], 1.0)
            self.assertEqual(result["answer_correct_but_not_grounded"], 1)
            self.assertEqual(result["questions_with_full_checkpoint_credit"], 1)
            self.assertEqual(result["score_success_spearman"], -1.0)
            self.assertIsNone(result["score_answer_correctness_spearman"])
            self.assertEqual(result["bands"]["hard"]["answer_only_accuracy"], 1.0)
            self.assertEqual(result["bands"]["hard"]["success_rate"], 0.0)

    def test_wilson_handles_empty_and_boundary_groups_without_fake_precision(self):
        self.assertIsNone(wilson(0, 0))
        low, high = wilson(0, 6)
        self.assertAlmostEqual(low, 0)
        self.assertGreater(high, 0.39)
        low, high = wilson(6, 6)
        self.assertLess(low, 0.61)
        self.assertAlmostEqual(high, 1)
        with self.assertRaises(ValueError):
            wilson(7, 6)

    def test_score_success_correlation_preserves_ties_and_unknown_constant_outcomes(self):
        self.assertAlmostEqual(spearman([1, 2, 3], [1, 1, 0]), -math.sqrt(3) / 2)
        self.assertAlmostEqual(spearman([1, 2, 2, 3], [1, 2, 2, 3]), 1)
        self.assertIsNone(spearman([1, 2, 3], [1, 1, 1]))
        self.assertIsNone(spearman([], []))
        with self.assertRaises(ValueError):
            spearman([float("nan")], [1])

    def test_pairs_use_the_same_questions_and_keep_operational_results_unknown(self):
        rows = []
        for task, scope, first, second in (
            ("one", "incident:1", False, True),
            ("two", "incident:1", True, True),
            ("three", "tenant", False, False),
            ("four", "tenant", None, True),
        ):
            for model, result in (("luna", first), ("astra", second)):
                rows.append({"task_fingerprint": task, "bucket": scope, "model": model, "grounded_final": result})
        result = paired_comparison(rows, "luna", "astra", samples=200, seed=42)
        self.assertEqual(result["paired_questions"], 3)
        self.assertEqual(result["first_only_success"], 0)
        self.assertEqual(result["second_only_success"], 1)
        self.assertEqual(result["ties"], 2)
        self.assertAlmostEqual(result["second_minus_first_success_rate"], 1 / 3)
        self.assertEqual(result["scope_cluster_bootstrap_95"], (0, 0.5))
        self.assertEqual(result["exact_mcnemar_p_exploratory"], 1)
        self.assertEqual(result, paired_comparison(rows, "luna", "astra", samples=200, seed=42))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            paired_comparison(rows + [rows[0]], "luna", "astra")

    def test_no_pairs_or_one_cluster_do_not_produce_an_invented_confidence_interval(self):
        empty = paired_comparison([], "luna", "astra")
        self.assertIsNone(empty["second_minus_first_success_rate"])
        self.assertIsNone(empty["exact_mcnemar_p_exploratory"])
        rows = [{"task_fingerprint": "one", "bucket": "tenant", "model": model, "grounded_final": True}
                for model in ("luna", "astra")]
        self.assertIsNone(paired_comparison(rows, "luna", "astra")["scope_cluster_bootstrap_95"])

    def test_pending_panel_is_explicit_not_a_zero_accuracy_dataset(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = {
                "episode_count": 2, "models": ["luna", "astra"], "cohort_fingerprint": "fixture",
                "difficulty_inventory": {"task": {"band": "hard", "score": "70", "bucket": "tenant"}},
                "episodes": [{"task_id": "one", "task_fingerprint": "task", "model": model,
                              "run_id": model, "relative_output": f"episodes/{model}"} for model in ("luna", "astra")],
            }
            (root / "manifest.json").write_text(json.dumps(manifest))
            report = analyze_panel(root, root / "analysis", samples=10)
            self.assertEqual(report["status"], "partial")
            for model in report["models"].values():
                self.assertIsNone(model["success_rate"])
                self.assertEqual(model["all_planned_success_bounds"], (0, 1))
                self.assertEqual(model["pending"], 1)
                self.assertIsNone(model["bands"]["easy"]["success_rate"])
                self.assertEqual(model["bands"]["easy"]["planned"], 0)
            self.assertFalse(report["heuristic_changed"])
            with self.assertRaisesRegex(ValueError, "new"):
                analyze_panel(root, root / "analysis")
            manifest["episodes"].append(manifest["episodes"][0])
            manifest["episode_count"] = 3
            (root / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "duplicate"):
                load_panel(root)

    def test_a_partial_manifest_cannot_claim_a_complete_comparison_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "manifest.json").write_text(json.dumps({
                "episode_count": 1, "models": ["luna", "astra"], "difficulty_inventory": {"task": {}},
                "episodes": [{"task_fingerprint": "task", "model": "luna"}],
            }))
            with self.assertRaisesRegex(ValueError, "complete unique"):
                load_panel(root)

    def test_explicit_amendment_retains_old_producers_without_changing_student_limits(self):
        def digest(value):
            return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()

        def file_hash(path):
            return hashlib.sha256(path.read_bytes()).hexdigest()

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent = {
                "episode_count": 2, "models": ["luna", "astra"], "cohort_fingerprint": "fixture",
                "profile": {"query_limits": {"max_rows": 500, "max_bytes": 65536, "timeout_ms": 30000}},
                "source_artifacts_sha256": {}, "implementation_sha256": {"fixture": "original"},
                "difficulty_inventory": {"task": {"band": "hard", "score": "70", "bucket": "tenant"}},
                "episodes": [{"task_id": "one", "task_fingerprint": "task", "model": model,
                              "run_id": model, "relative_output": f"episodes/{model}"} for model in ("luna", "astra")],
            }
            parent_path = root / "manifest.json"
            parent_path.write_text(json.dumps(parent))
            amended = {
                **parent, "implementation_sha256": {"fixture": "amended"},
                "parent_manifest": {"path": "manifest.json", "sha256": file_hash(parent_path)},
                "grading_policy_amendment": {"private_grader_timeout_ms": 120000},
                "episodes": [{**parent["episodes"][0], "producer": "parent"},
                             {**parent["episodes"][1], "producer": "amended", "relative_output": "amended/astra"}],
            }
            (root / "amendment.json").write_text(json.dumps(amended))
            for entry in amended["episodes"]:
                folder = root / entry["relative_output"]
                (folder / "student").mkdir(parents=True)
                producer = parent if entry["producer"] == "parent" else amended
                binding = {"profile": parent["profile"], "implementation_sha256": producer["implementation_sha256"],
                           "manifest_fingerprint": digest(producer)}
                if entry["producer"] == "amended":
                    binding["grading_query_limits"] = {**parent["profile"]["query_limits"], "timeout_ms": 120000}
                (folder / "binding.json").write_text(json.dumps(binding))
                (folder / "episode.json").write_text(json.dumps({
                    "model": entry["model"], "task_fingerprint": "task", "run_id": entry["run_id"],
                    "binding_sha256": file_hash(folder / "binding.json"), "role_artifacts_sha256": {},
                    "status": "operational_error", "evaluation_sha256": None, "grounded_final": None,
                    "answer_correctness": None, "final_evidence": None, "checkpoint_progress": None, "reward": None,
                    "usage": {"responses": 0, "input_tokens": 0, "output_tokens": 0, "reasoning_tokens": None},
                }))
            _, rows, pending = load_panel(root, manifest_name="amendment.json")
            self.assertFalse(pending)
            self.assertEqual([row["grader_timeout_ms"] for row in rows], [30000, 120000])
            self.assertTrue(all(row["grounded_final"] is None for row in rows))
            self.assertEqual(json.loads(parent_path.read_bytes()), parent)
            changed = json.loads(json.dumps(amended))
            changed["profile"]["query_limits"]["timeout_ms"] = 120000
            (root / "changed.json").write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, "student settings"):
                load_panel(root, manifest_name="changed.json")


if __name__ == "__main__":
    unittest.main()
