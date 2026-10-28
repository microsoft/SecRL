# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agentic_runtime_fixture import runtime_fixture, runtime_task
from test_agentic_adapters import reviewed_fixture
from secgym.qagen.agentic.contracts import TaskRecord, ValidationReport
from secgym.qagen.agentic.footprints import build_unit_footprint, build_unit_footprints
from secgym.qagen.agentic.ledger import file_sha256


class FootprintTests(unittest.TestCase):
    def test_sources_and_fact_targets_are_deduplicated_without_graph_count_inflation(self):
        with tempfile.TemporaryDirectory() as temporary:
            graph, _, serving, report = runtime_fixture(Path(temporary))
            task = runtime_task(serving, report)
            footprint = build_unit_footprint(task, reviewed_fixture(task), graph)
            self.assertEqual([f.feature_id for f in footprint.observations], ["obs:1"])
            self.assertEqual(len(footprint.edges), 1)
            self.assertEqual(len(footprint.facts), 2)
            self.assertTrue(all(f.weight == 1.0 for f in footprint.facts))
            self.assertEqual(footprint, build_unit_footprint(task, reviewed_fixture(task), graph))

    def test_unvalidated_task_does_not_gain_a_scoreable_footprint(self):
        with tempfile.TemporaryDirectory() as temporary:
            graph, _, serving, report = runtime_fixture(Path(temporary))
            task = runtime_task(serving, report)
            review = reviewed_fixture(task)
            incomplete = ValidationReport(task_id=task.task_id, task_fingerprint=review.task_fingerprint,
                                          evaluator_version="fixture", gates=())
            with self.assertRaisesRegex(ValueError, "validated private-pilot evidence"):
                build_unit_footprint(task, incomplete, graph)

    def test_batch_matches_single_task_results_and_verifies_graph_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            graph, _, serving, report = runtime_fixture(Path(temporary))
            first = runtime_task(serving, report)
            data = first.model_dump(mode="json")
            data["task_id"] = "second-task"
            second = TaskRecord.model_validate_json(json.dumps(data))
            cases = ((first, reviewed_fixture(first)), (second, reviewed_fixture(second)))
            expected = tuple(build_unit_footprint(task, validation, graph) for task, validation in cases)
            with patch("secgym.qagen.agentic.footprints.file_sha256", wraps=file_sha256) as verify:
                self.assertEqual(build_unit_footprints(iter(cases), graph), expected)
                verify.assert_called_once()

    def test_batch_rejects_empty_duplicate_and_unvalidated_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            graph, _, serving, report = runtime_fixture(Path(temporary))
            task = runtime_task(serving, report)
            review = reviewed_fixture(task)
            incomplete = ValidationReport(task_id=task.task_id, task_fingerprint=review.task_fingerprint,
                                          evaluator_version="fixture", gates=())
            for cases in ((), ((task, review), (task, review)), ((task, incomplete),)):
                with self.subTest(cases=len(cases)):
                    with patch("secgym.qagen.agentic.footprints.file_sha256") as verify:
                        with self.assertRaises(ValueError):
                            build_unit_footprints(cases, graph)
                        verify.assert_not_called()

    def test_batch_rejects_mixed_graph_versions_and_changed_graph_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            graph, _, serving, report = runtime_fixture(Path(temporary))
            first = runtime_task(serving, report)
            data = first.model_dump(mode="json")
            data.update(task_id="other-graph-task", graph_version="graph:other")
            second = TaskRecord.model_validate_json(json.dumps(data))
            with self.assertRaisesRegex(ValueError, "task and verified graph differ"):
                build_unit_footprints(((first, reviewed_fixture(first)), (second, reviewed_fixture(second))), graph)
            with patch("secgym.qagen.agentic.footprints.file_sha256", return_value="0" * 64):
                with self.assertRaisesRegex(ValueError, "task and verified graph differ"):
                    build_unit_footprints(((first, reviewed_fixture(first)),), graph)


if __name__ == "__main__":
    unittest.main()
