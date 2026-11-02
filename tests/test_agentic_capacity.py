# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import csv
import json
import subprocess
import sys
import tempfile
import unittest
from itertools import combinations
from pathlib import Path

from test_agentic_question_splits import question, write_inputs
from secgym.qagen.agentic.capacity import CapacityPoint, CapacityRequest, compatible_subset_bounds, report_capacity
from secgym.qagen.agentic.contracts import fingerprint
from secgym.qagen.agentic.question_splits import load_questions


ROOT = Path(__file__).resolve().parents[1]


def exact_independent_size(conflicts):
    return max(mask.bit_count() for mask in range(1 << len(conflicts))
               if all(not (mask & (1 << index)) or not (neighbors & mask) for index, neighbors in enumerate(conflicts)))


class CapacitySearchTests(unittest.TestCase):
    def test_exact_bounds_for_every_five_vertex_graph(self):
        edges = tuple(combinations(range(5), 2))
        for mask in range(1 << len(edges)):
            graph = [0] * 5
            for index, (left, right) in enumerate(edges):
                if mask & (1 << index):
                    graph[left] |= 1 << right
                    graph[right] |= 1 << left
            chosen, upper, states = compatible_subset_bounds(tuple(graph), search_budget_states=1000)
            expected = exact_independent_size(graph)
            with self.subTest(mask=mask):
                self.assertEqual(len(chosen), expected)
                self.assertEqual(upper, expected)
                self.assertLessEqual(states, 1000)
                self.assertTrue(all(not graph[left] & (1 << right) for left, right in combinations(chosen, 2)))

    def test_budget_exhaustion_preserves_verified_lower_and_upper_bounds(self):
        graph = (292, 204, 747, 182, 872, 29, 790, 782, 209, 212)
        chosen, upper, states = compatible_subset_bounds(graph, search_budget_states=1)
        expected = exact_independent_size(graph)
        self.assertEqual(states, 1)
        self.assertLess(len(chosen), upper)
        self.assertLessEqual(len(chosen), expected)
        self.assertGreaterEqual(upper, expected)
        complete, exact, _ = compatible_subset_bounds(graph, search_budget_states=1000)
        self.assertEqual((len(complete), exact), (expected, expected))

    def test_simple_large_graphs_are_exact_without_recursive_depth_or_search_explosion(self):
        for n in (1, 1000):
            universe = (1 << n) - 1
            for graph, expected in ((tuple(0 for _ in range(n)), n),
                                    (tuple(universe ^ (1 << index) for index in range(n)), 1)):
                chosen, upper, states = compatible_subset_bounds(graph, search_budget_states=1)
                self.assertEqual((len(chosen), upper), (expected, expected))
                self.assertLessEqual(states, 1)

    def test_invalid_graph_and_budget_fail_explicitly(self):
        for graph in ((), (1,), (2,), (-1,), (2, 0), (False,)):
            with self.subTest(graph=graph), self.assertRaises(ValueError):
                compatible_subset_bounds(graph, search_budget_states=10)
        for budget in (0, -1, True):
            with self.subTest(budget=budget), self.assertRaises(ValueError):
                compatible_subset_bounds((0,), search_budget_states=budget)

    def test_requests_and_points_reject_misleading_states(self):
        for thresholds in ((0.5, 0.25), (0.25, 0.25), (), (-0.1,), (1.1,)):
            with self.subTest(thresholds=thresholds), self.assertRaises(ValueError):
                CapacityRequest(thresholds=thresholds, search_budget_states=10)
        with self.assertRaises(ValueError):
            CapacityRequest()
        with self.assertRaises(ValueError):
            CapacityPoint(
                bucket="tenant", threshold=0.25, observed_questions=3, status="exact_observed_pool",
                lower_bound=1, upper_bound=2, example_task_ids=("first",), search_states=1,
                unscorable_pairs=0, pairwise_limit_verified=True,
            )
        with self.assertRaises(ValueError):
            CapacityPoint(
                bucket="tenant", threshold=0.25, observed_questions=3, status="unscorable",
                lower_bound=0, upper_bound=None, example_task_ids=(), search_states=0,
                unscorable_pairs=1, pairwise_limit_verified=False,
            )


class CapacityReportTests(unittest.TestCase):
    def report(self, root, cases, request=None):
        loaded = load_questions(write_inputs(root, cases))
        return report_capacity(loaded, root / "capacity", request or CapacityRequest(search_budget_states=1000))

    def test_threshold_equality_is_permitted_and_below_threshold_conflicts(self):
        cases = (question("first", subject="obs:a"), question("second", subject="obs:b"))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = self.report(root, cases, CapacityRequest(thresholds=(0.249999, 0.25, 0.5), search_budget_states=1000))
            self.assertEqual([point["lower_bound"] for point in report["points"]], [1, 2, 2])
            self.assertEqual([point["upper_bound"] for point in report["points"]], [1, 2, 2])
            with (root / "capacity/within-scope-pairs.csv").open() as stream:
                pairs = list(csv.DictReader(stream))
            self.assertEqual(len(pairs), 1)
            self.assertEqual(float(pairs[0]["score"]), 0.25)
            self.assertTrue(all(point["pairwise_limit_verified"] for point in report["points"]))

    def test_identical_evidence_is_diagnostic_not_question_rejection_or_forced_grouping(self):
        cases = (question("first"), question("second"))
        before = tuple(fingerprint(case.task) for case in cases)
        with tempfile.TemporaryDirectory() as temporary:
            report = self.report(Path(temporary), cases)
            self.assertEqual(report["question_count"], 2)
            self.assertTrue(all(point["lower_bound"] == point["upper_bound"] == 1 for point in report["points"]))
            for field in ("admission_changed", "questions_removed", "groups_forced", "split_changed",
                          "grading_changed", "release_approved", "absolute_source_capacity_established",
                          "source_saturation_established", "generation_yield_measured"):
                self.assertFalse(report[field])
            self.assertEqual(tuple(fingerprint(case.task) for case in cases), before)

    def test_missing_components_never_become_zero_overlap_or_zero_capacity(self):
        cases = (question("first", edges=False), question("second"))
        with tempfile.TemporaryDirectory() as temporary:
            report = self.report(Path(temporary), cases)
            self.assertFalse(report["measurements_complete"])
            self.assertFalse(report["all_observed_pool_optima_proven"])
            for point in report["points"]:
                self.assertEqual(point["status"], "unscorable")
                self.assertEqual(point["unscorable_pairs"], 1)
                self.assertIsNone(point["lower_bound"])
                self.assertIsNone(point["upper_bound"])
                self.assertEqual(point["example_task_ids"], [])

    def test_scope_buckets_are_independent_and_examples_deterministic(self):
        cases = (question("one", incident=34), question("two", incident=36), question("three", incident=None))
        reports = []
        for order in (cases, tuple(reversed(cases))):
            with tempfile.TemporaryDirectory() as temporary:
                reports.append(self.report(Path(temporary), order))
        self.assertEqual(reports[0]["points"], reports[1]["points"])
        self.assertEqual(reports[0]["cohort_fingerprint"], reports[1]["cohort_fingerprint"])
        self.assertEqual({point["bucket"] for point in reports[0]["points"]}, {"incident:34", "incident:36", "tenant"})
        self.assertEqual(reports[0]["within_scope_pairs"], 0)
        self.assertTrue(all(point["lower_bound"] == point["upper_bound"] == 1 for point in reports[0]["points"]))

    def test_existing_or_annotation_output_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            loaded = load_questions(write_inputs(root, (question("first"),)))
            for output in (root, loaded.annotation_directories[0] / "new-capacity"):
                with self.subTest(output=output), self.assertRaises(ValueError):
                    report_capacity(loaded, output, CapacityRequest(search_budget_states=1))

    def test_cli_writes_curves_and_fails_for_unscorable_inputs(self):
        for complete in (True, False):
            with self.subTest(complete=complete), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                manifest = write_inputs(root, (question("first", edges=complete), question("second")))
                request = root / "request.json"
                request.write_text(CapacityRequest(search_budget_states=1000).model_dump_json())
                result = subprocess.run(
                    [sys.executable, "-m", "secgym.qagen.agentic", "capacity-curves",
                     "--inputs", str(manifest), "--request", str(request), "--output", str(root / "capacity")],
                    cwd=ROOT, capture_output=True, text=True, timeout=30,
                )
                self.assertEqual(result.returncode, 0 if complete else 1, result.stderr)
                self.assertEqual(json.loads(result.stdout)["measurements_complete"], complete)
                self.assertTrue((root / "capacity/capacity.csv").exists())
                self.assertTrue((root / "capacity/within-scope-pairs.csv").exists())
                saved = json.loads((root / "capacity/capacity-report.json").read_text())
                self.assertEqual(len(saved["points"]), 4)
                self.assertEqual(saved["request"]["search_budget_states"], 1000)
                self.assertFalse(saved["absolute_source_capacity_established"])

    def test_capacity_schemas_are_exposed(self):
        for name in ("capacity-request", "capacity-point"):
            result = subprocess.run(
                [sys.executable, "-m", "secgym.qagen.agentic", "schema", name],
                cwd=ROOT, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("properties", json.loads(result.stdout))


if __name__ == "__main__":
    unittest.main()
