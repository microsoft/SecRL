# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from contextlib import contextmanager
import contextlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_agentic_checkpoint_batches as batch_tests
from secgym.qagen.agentic.contracts import TaskRecord, fingerprint
from secgym.qagen.agentic.preproduction_pipeline import StageResult
from secgym.qagen.agentic.shared_validation import finish_shared_checkpoint_candidate, review_registered_checkpoint
from secgym.qagen.agentic.snapshot_service import SnapshotServiceBinding
from secgym.qagen.agentic.ledger import file_sha256
from secgym.qagen.agentic.model_panel import immutable_json
from secgym.qagen.agentic import snapshot_service
from secgym.qagen.agentic.__main__ import main
from test_agentic_review_transport import nonstudent_policy


MODULE = "secgym.qagen.agentic.shared_validation"
PIPELINE = "secgym.qagen.agentic.preproduction_pipeline"


class SharedValidationTests(unittest.TestCase):
    setUp = batch_tests.NativeLeaseTests.setUp
    candidate = batch_tests.NativeLeaseTests.candidate

    def pool(self):
        binding = SnapshotServiceBinding(
            serving_view_id=self.plan.serving_view_id, serving_bundle=str(self.serving.resolve()),
            mysql_bundle=str(self.metadata.resolve()), serving_report_sha256=self.plan.serving_report_sha256,
            mysql_report_sha256=self.plan.native_snapshot_sha256, native_indexes_sha256=self.plan.native_indexes_sha256,
            implementation_sha256=file_sha256(Path(snapshot_service.__file__)), native_candidate_slots=2,
        )
        self.shared_leases = []

        @contextmanager
        def lease(source, output):
            self.shared_leases.append((source, output))
            output.mkdir(parents=True, exist_ok=True)
            immutable_json(output / "shared-service.json", {"snapshot": self.plan.native_snapshot_sha256})
            try:
                yield self.native, self.student
            finally:
                self.shared_leases.append("released")

        return SimpleNamespace(
            binding=binding, plan=self.plan, ready_instance=lambda: None, lease=lease, metadata={"mysqld_binary": "/unused"},
        )

    def finish(self, task_id, pool):
        policy = SimpleNamespace()
        from secgym.qagen.agentic.checkpoint_batches import create_batch
        policy = create_batch(self.output, "shared", checkpoint_size=2, workers=2)
        client = SimpleNamespace(config=self.client.config, close=lambda: None)
        transport = nonstudent_policy().model_copy(update={"plan_fingerprint": fingerprint(self.plan)})
        immutable_json(self.output / "review-transport-policy02.json", transport)

        def metadata(plan, task, native):
            return {
                "policy_version": "native-physical-text-semantics-v1",
                "task_fingerprint": fingerprint(task), "plan_fingerprint": fingerprint(plan),
                "serving_view_id": task.serving_view_id, "native_snapshot_sha256": plan.native_snapshot_sha256,
                "physical_text_columns": {"DeviceProcessEvents": {"utf8mb4_0900_bin / NO PAD": ["FileName"]}},
            }

        with patch(MODULE + ".azure_review_client", return_value=client), \
             patch(MODULE + ".EvidenceVerifier", return_value=self.source), \
             patch(MODULE + ".native_text_semantics", side_effect=metadata), \
             patch.object(self.source, "close", create=True), \
             patch(PIPELINE + ".validate_quality_gate"):
            return finish_shared_checkpoint_candidate(
                plan=self.plan, run=self.output, policy=policy, task_id=task_id, serving=self.serving,
                graph=self.graph, mysql_bundle=self.metadata, env_file=self.client.config.env_file,
                workdir=self.root, pool=pool,
            )

    def test_schema_metadata_and_native_use_distinct_leases_and_preserve_execution_binding(self):
        task_id = self.candidate()
        pool = self.pool()
        with patch(PIPELINE + ".review_contract", return_value=StageResult(status="pass", reason="Reviewed.")), \
             patch(PIPELINE + ".native_candidate", return_value=StageResult(status="held", reason="Native fixture hold.")):
            result = self.finish(task_id, pool)
        self.assertEqual(result["stage"], "native")
        self.assertEqual(len(self.shared_leases), 4)
        self.assertEqual(self.shared_leases[-1], "released")
        output = self.output / "attempts" / task_id / "pipeline" / self.seed.revision_id
        execution = json.loads((output / "shared-native-execution.json").read_bytes())
        self.assertEqual(execution["service_binding"]["serving_view_id"], self.plan.serving_view_id)
        self.assertFalse(execution["mutation_fixtures_shared"])
        self.assertFalse(execution["student_settings_changed"])
        metadata = json.loads((output / "native-review-context.json").read_bytes())
        self.assertIn("utf8mb4_0900_bin / NO PAD", metadata["physical_text_columns"]["DeviceProcessEvents"])
        self.assertNotEqual(self.shared_leases[0][1], self.shared_leases[2][1])
        before = list(self.shared_leases)
        from secgym.qagen.agentic.shared_validation import shared_native_review_context
        task = TaskRecord.model_validate_json((self.output / "attempts" / task_id / "source/task.json").read_bytes())
        self.assertEqual(shared_native_review_context(self.plan, task, self.source, pool, output), metadata)
        self.assertEqual(self.shared_leases, before)
        Path(metadata["lease_artifact"]).write_text("{}")
        with self.assertRaisesRegex(ValueError, "snapshot lease changed"):
            shared_native_review_context(self.plan, task, self.source, pool, output)
        self.assertEqual(self.shared_leases, before)

    def test_grading_hold_acquires_only_metadata_not_a_native_student_episode(self):
        task_id = self.candidate()
        pool = self.pool()
        with patch(PIPELINE + ".review_contract", return_value=StageResult(status="held", reason="Source contract hold.")):
            self.assertEqual(self.finish(task_id, pool)["stage"], "grading")
        self.assertEqual(len(self.shared_leases), 2)
        output = self.output / "attempts" / task_id / "pipeline" / self.seed.revision_id
        self.assertFalse((output / "native").exists())

    def test_existing_pipeline_is_not_replaced_or_resampled(self):
        task_id = self.candidate()
        path = self.output / "attempts" / task_id / "pipeline" / self.seed.revision_id
        path.mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, "existing pipeline"):
            self.finish(task_id, self.pool())
        self.assertEqual(list(path.iterdir()), [])

    def test_registered_service_changes_runner_not_source_review_or_models(self):
        arguments = dict(run=Path("run"), batch_id="batch", serving=Path("serving"), graph=Path("graph"),
                         mysql_bundle=Path("mysql"), env_file=Path("env"), workdir=Path("tmp"))
        with patch(MODULE + ".registered_snapshot_pool", return_value=SimpleNamespace()), \
             patch(MODULE + ".review_checkpoint", return_value={"status": "verified"}) as review:
            result = review_registered_checkpoint(**arguments)
        self.assertEqual(result, {"status": "verified"})
        self.assertTrue(callable(review.call_args.kwargs["pipeline_runner"]))
        for key, value in arguments.items():
            self.assertEqual(review.call_args.kwargs[key], value)
        with patch(MODULE + ".registered_snapshot_pool", return_value=None), \
             patch(MODULE + ".review_checkpoint", return_value={"status": "legacy"}) as review:
            self.assertEqual(review_registered_checkpoint(**arguments), {"status": "legacy"})
        self.assertNotIn("pipeline_runner", review.call_args.kwargs)

    def test_cli_review_and_registration_use_shared_service_interfaces(self):
        args = ["agentic", "review-checkpoint", "--batch-id", "next-checkpoint"]
        for name in ("run", "serving-bundle", "graph-bundle", "mysql-bundle", "env-file", "workdir"):
            args.extend(["--" + name, str(self.root / name)])
        with patch(MODULE + ".review_registered_checkpoint", return_value={"status": "shared"}) as review:
            with patch("sys.argv", args), contextlib.redirect_stdout(io.StringIO()) as output:
                main()
        self.assertEqual(json.loads(output.getvalue())["status"], "shared")
        self.assertEqual(review.call_args.kwargs["batch_id"], "next-checkpoint")
        args = ["agentic", "register-sql-service", "--run", str(self.output),
                "--service-directory", str(self.root / "service")]
        with patch(MODULE + ".register_snapshot_service", return_value={"status": "ready"}) as register:
            with patch("sys.argv", args), contextlib.redirect_stdout(io.StringIO()):
                main()
        register.assert_called_once_with(self.output, self.root / "service")

    def test_cli_finish_uses_shared_provider_when_registered(self):
        args = ["agentic", "finish-preproduction", "--task-id", self.seed.task_id]
        for name in ("run", "serving-bundle", "graph-bundle", "mysql-bundle", "env-file", "workdir", "output"):
            args.extend(["--" + name, str(self.root / name)])
        pool = SimpleNamespace()
        with patch(MODULE + ".registered_snapshot_pool", return_value=pool), \
             patch(MODULE + ".run_shared_pipeline", return_value={"status": "held"}) as shared, \
             patch(PIPELINE + ".run_owned_candidate_pipeline") as owned:
            with patch("sys.argv", args), contextlib.redirect_stdout(io.StringIO()):
                main()
        self.assertIs(shared.call_args.kwargs["pool"], pool)
        owned.assert_not_called()

    def test_cli_forwards_qualified_support_approval_for_both_execution_routes(self):
        approval = self.root / "qualified-support-approval.json"
        args = ["agentic", "finish-preproduction", "--task-id", self.seed.task_id,
                "--qualified-support-review-recovery", str(approval)]
        for name in ("run", "serving-bundle", "graph-bundle", "mysql-bundle", "env-file", "workdir", "output"):
            args.extend(["--" + name, str(self.root / name)])
        for pool in (None, SimpleNamespace()):
            with self.subTest(shared=pool is not None), \
                 patch(MODULE + ".registered_snapshot_pool", return_value=pool), \
                 patch(MODULE + ".run_shared_pipeline", return_value={"status": "held"}) as shared, \
                 patch(PIPELINE + ".run_owned_candidate_pipeline", return_value={"status": "held"}) as owned, \
                 patch("sys.argv", args), contextlib.redirect_stdout(io.StringIO()):
                main()
            selected = owned if pool is None else shared
            self.assertEqual(selected.call_args.kwargs["qualified_support_review_recovery"], approval)

    def test_cli_forwards_difficulty_continuation_for_both_execution_routes(self):
        feedback = self.root / "difficulty-feedback.txt"
        feedback.write_text("Apply the exact source-only feature review; preserve task and completed stages.")
        args = ["agentic", "finish-preproduction", "--task-id", self.seed.task_id,
                "--difficulty-feedback", str(feedback), "--parent-pipeline", str(self.root / "parent"),
                "--parent-runtime-archive", str(self.root / "producer.zip")]
        for name in ("run", "serving-bundle", "graph-bundle", "mysql-bundle", "env-file", "workdir", "output"):
            args.extend(["--" + name, str(self.root / name)])
        for pool in (None, SimpleNamespace()):
            with self.subTest(shared=pool is not None), \
                 patch(MODULE + ".registered_snapshot_pool", return_value=pool), \
                 patch(MODULE + ".run_shared_pipeline", return_value={"status": "held"}) as shared, \
                 patch(PIPELINE + ".run_owned_candidate_pipeline", return_value={"status": "held"}) as owned, \
                 patch("sys.argv", args), contextlib.redirect_stdout(io.StringIO()):
                main()
                called = owned if pool is None else shared
                self.assertEqual(called.call_args.kwargs["difficulty_feedback"], feedback.read_text())
                self.assertEqual(called.call_args.kwargs["parent_pipeline"], self.root / "parent")

    def test_next_generated_checkpoint_automatically_uses_registered_review_routing(self):
        args = ["agentic", "generate-checkpoint", "--batch-id", "next-100", "--review-at-checkpoint"]
        for name in ("run", "serving-bundle", "graph-bundle", "env-file", "mysql-bundle", "workdir"):
            args.extend(["--" + name, str(self.root / name)])
        batch_module = "secgym.qagen.agentic.checkpoint_batches"
        with patch(batch_module + ".create_batch"), \
             patch(batch_module + ".generate_checkpoint", return_value={"ready_for_checkpoint": True}), \
             patch(MODULE + ".review_registered_checkpoint", return_value={"status": "shared-review"}) as shared:
            with patch("sys.argv", args), contextlib.redirect_stdout(io.StringIO()) as output:
                main()
        self.assertEqual(json.loads(output.getvalue())["status"], "shared-review")
        self.assertEqual(shared.call_args.kwargs["batch_id"], "next-100")


if __name__ == "__main__":
    unittest.main()
