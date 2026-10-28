# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from agentic_runtime_fixture import runtime_fixture, runtime_task
from secgym.qagen.agentic.batch import DevelopmentBatch, development_attempts, run_development_batch
from secgym.qagen.agentic.contracts import SELECTED_INCIDENTS, TaskRecord, fingerprint
from secgym.qagen.agentic.generation import RoleAbstained
from secgym.qagen.agentic.query import QueryLimits


class DevelopmentBatchTests(unittest.TestCase):
    def test_approved_volume_is_sixty_unique_attempts_not_a_success_quota(self):
        attempts = development_attempts("dev-batch01", 5, 10)
        self.assertEqual(len(attempts), 60)
        self.assertEqual(len({a.task_id for a in attempts}), 60)
        self.assertEqual(Counter(a.incident_id for a in attempts if a.mode == "incident"),
                         Counter({incident: 5 for incident in SELECTED_INCIDENTS}))
        self.assertEqual(sum(a.mode == "tenant" for a in attempts), 10)
        for per_incident, tenant in ((0, 0), (-1, 1), (True, 1), (1, 1.5)):
            with self.assertRaises(ValueError):
                development_attempts("invalid", per_incident, tenant)

    def fixture(self, root):
        graph, _, serving, report = runtime_fixture(root / "fixture")
        seed = runtime_task(serving, report)
        spec = DevelopmentBatch(batch_id="batch", serving_view_id=report["serving_view_id"], graph_id=report["graph_id"],
                                attempts=development_attempts("batch", 0, 2),
                                limits=QueryLimits(max_rows=100, max_bytes=65536, timeout_ms=3000),
                                checkpoint_cap=0.5, seed_questions=(seed,))
        return graph, serving, seed, spec

    def test_diversity_context_and_resume_preserve_ids_and_completed_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            graph, serving, seed, spec = self.fixture(root)
            calls = []
            def run(**kwargs):
                calls.append(kwargs)
                data = seed.model_dump(mode="json")
                data.update(task_id=kwargs["task_id"], lineage_group=kwargs["task_id"],
                            question="Synthetic question " + kwargs["task_id"])
                task = TaskRecord.model_validate_json(json.dumps(data))
                kwargs["output"].mkdir()
                (kwargs["output"] / "task.json").write_text(task.model_dump_json())
                return {"status": "candidate_for_mysql_validation", "task_fingerprint": fingerprint(task)}
            output = root / "batch"
            result = run_development_batch(spec, None, serving, graph, output, runner=run)
            self.assertEqual(result["attempts_finished"], 2)
            self.assertFalse(result["mysql_validated"])
            self.assertFalse(result["release_approved"])
            self.assertEqual(calls[0]["prior_questions"], (seed.question,))
            self.assertEqual(calls[1]["prior_questions"], (seed.question, "Synthetic question batch-tenant-01"))
            resumed = run_development_batch(spec, None, serving, graph, output, resume=True,
                                             runner=lambda **_: self.fail("completed attempts must not be rerun"))
            self.assertEqual(resumed, result)
            task_path = output / spec.attempts[0].task_id / "task.json"
            changed = json.loads(task_path.read_text())
            changed["question"] = "Changed after validation"
            task_path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, "task changed"):
                run_development_batch(spec, None, serving, graph, output, resume=True, runner=run)

    def test_abstention_and_errors_are_counted_without_claiming_accepted_tasks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            graph, serving, _, spec = self.fixture(root)
            def run(**kwargs):
                if kwargs["task_id"].endswith("01"):
                    raise RoleAbstained("Required source missing.")
                raise RuntimeError("Endpoint unavailable.")
            result = run_development_batch(spec, None, serving, graph, root / "batch", runner=run)
            self.assertEqual([x["status"] for x in result["outcomes"]], ["no_supported_candidate", "error"])
            self.assertEqual(result["status"], "discovery_attempts_complete")
            self.assertFalse(result["release_approved"])
            with self.assertRaisesRegex(ValueError, "original batch manifest"):
                run_development_batch(spec, None, serving, graph, root / "unrelated", resume=True, runner=run)


if __name__ == "__main__":
    unittest.main()
