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
from secgym.qagen.agentic.contracts import GateResult, TaskRecord, fingerprint
from secgym.qagen.agentic.preproduction_pipeline import StageResult
from secgym.qagen.agentic.preproduction import SourceOutcome, _artifacts
from secgym.qagen.agentic.shared_validation import (
    finish_shared_checkpoint_candidate, review_registered_checkpoint, review_shared_source,
)
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

    def native_execution_fixture(self, task_id):
        source = self.output / "attempts" / task_id / "source"
        task = TaskRecord.model_validate_json((source / "task.json").read_bytes())
        artifact = source / "native-source-preflight.json"
        value = {
            "task_fingerprint": fingerprint(task), "plan_fingerprint": fingerprint(self.plan),
            "serving_view_id": task.serving_view_id, "native_snapshot_sha256": self.plan.native_snapshot_sha256,
            "baseline_source_native_parity": GateResult(
                gate="serving_parity", status="pass", reason="Recorded native reference execution.",
                artifact_refs=(task.serving_view_id,),
            ).model_dump(mode="json"),
        }
        artifact.write_text(json.dumps(value))
        outcome = source.parent / "source-outcome.json"
        recorded = SourceOutcome.model_validate_json(outcome.read_bytes())
        outcome.write_text(recorded.model_copy(update={"artifact_sha256": _artifacts(source)}).model_dump_json())
        return task, artifact, value

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

    def test_recorded_execution_reaches_review_context_without_a_student_or_repeat_query(self):
        task_id = self.candidate()
        task, artifact, value = self.native_execution_fixture(task_id)
        before = artifact.read_bytes()
        pool = self.pool()
        with patch(PIPELINE + ".review_contract",
                   return_value=StageResult(status="held", reason="Inspection only.")) as review:
            self.assertEqual(self.finish(task_id, pool)["stage"], "grading")
        context = review.call_args.kwargs["native_context"]
        recorded = context["recorded_native_contract_execution"]
        self.assertEqual(recorded["task_fingerprint"], fingerprint(task))
        self.assertEqual(recorded["source_preflight_sha256"], file_sha256(artifact))
        self.assertEqual(recorded["baseline_source_native_parity"], value["baseline_source_native_parity"])
        self.assertTrue(recorded["mutation_world_semantics_still_require_validation"])
        self.assertIn("observed baseline execution", recorded["scope"])
        self.assertEqual(artifact.read_bytes(), before)
        self.assertEqual(len(self.shared_leases), 2)
        output = self.output / "attempts" / task_id / "pipeline" / self.seed.revision_id
        self.assertFalse((output / "native").exists())
        self.assertEqual(json.loads((output / "native-review-context.json").read_bytes()), context)

    def test_absent_recorded_execution_is_not_presented_as_success(self):
        task_id = self.candidate()
        with patch(PIPELINE + ".review_contract",
                   return_value=StageResult(status="held", reason="Inspection only.")) as review:
            self.finish(task_id, self.pool())
        self.assertIsNone(review.call_args.kwargs["native_context"]["recorded_native_contract_execution"])

    def test_native_execution_evidence_rejects_all_mismatched_identity_bindings(self):
        from secgym.qagen.agentic.shared_validation import _recorded_native_execution
        task_id = self.candidate()
        task, artifact, value = self.native_execution_fixture(task_id)
        output = self.output / "attempts" / task_id / "pipeline/r1"
        for field in ("task_fingerprint", "plan_fingerprint", "serving_view_id", "native_snapshot_sha256"):
            artifact.write_text(json.dumps({**value, field: "another-binding"}))
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "another task, plan or snapshot"):
                _recorded_native_execution(self.plan, task, artifact, output)

    def test_native_execution_requires_a_passing_actual_parity_result(self):
        from secgym.qagen.agentic.shared_validation import _recorded_native_execution
        task_id = self.candidate()
        task, artifact, value = self.native_execution_fixture(task_id)
        output = self.output / "attempts" / task_id / "pipeline/r1"
        for gate, status in (("serving_parity", "fail"), ("serving_parity", "error"), ("mechanical", "pass")):
            invalid = {**value, "baseline_source_native_parity": GateResult(
                gate=gate, status=status, reason="Not a passing native execution result.",
                error_code="query_execution" if status == "error" else None,
            ).model_dump(mode="json")}
            artifact.write_text(json.dumps(invalid))
            with self.subTest(gate=gate, status=status), self.assertRaisesRegex(ValueError, "passing actual"):
                _recorded_native_execution(self.plan, task, artifact, output)
        artifact.write_text(json.dumps({key: data for key, data in value.items()
                                        if key != "baseline_source_native_parity"}))
        with self.assertRaises(ValueError):
            _recorded_native_execution(self.plan, task, artifact, output)

    def test_native_execution_artifact_must_exist_and_remain_owned(self):
        from secgym.qagen.agentic.shared_validation import _recorded_native_execution
        task_id = self.candidate()
        task, artifact, _ = self.native_execution_fixture(task_id)
        output = self.output / "attempts" / task_id / "pipeline/r1"
        outside = self.root / "native-source-preflight.json"
        outside.write_bytes(artifact.read_bytes())
        with self.assertRaisesRegex(ValueError, "owned source preflight"):
            _recorded_native_execution(self.plan, task, outside, output)
        artifact.unlink()
        with self.assertRaises(FileNotFoundError):
            _recorded_native_execution(self.plan, task, artifact, output)

    def test_cached_execution_rejects_mutation_and_path_rebinding(self):
        from secgym.qagen.agentic.shared_validation import shared_native_review_context
        task_id = self.candidate()
        task, artifact, value = self.native_execution_fixture(task_id)
        pool = self.pool()
        with patch(PIPELINE + ".review_contract",
                   return_value=StageResult(status="held", reason="Inspection only.")):
            self.finish(task_id, pool)
        output = self.output / "attempts" / task_id / "pipeline" / self.seed.revision_id
        before = list(self.shared_leases)
        self.assertIsNotNone(shared_native_review_context(self.plan, task, self.source, pool, output))
        other = self.output / "other-source/native-source-preflight.json"
        other.parent.mkdir()
        other.write_bytes(artifact.read_bytes())
        with self.assertRaisesRegex(ValueError, "rebound"):
            shared_native_review_context(self.plan, task, self.source, pool, output, source_preflight=other)
        value["baseline_source_native_parity"]["reason"] = "Changed historical evidence."
        artifact.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "execution evidence changed"):
            shared_native_review_context(self.plan, task, self.source, pool, output)
        self.assertEqual(self.shared_leases, before)

    def test_cached_legacy_context_is_not_retrofitted(self):
        from secgym.qagen.agentic.shared_validation import shared_native_review_context
        task_id = self.candidate()
        pool = self.pool()
        with patch(PIPELINE + ".review_contract",
                   return_value=StageResult(status="held", reason="Inspection only.")):
            self.finish(task_id, pool)
        output = self.output / "attempts" / task_id / "pipeline" / self.seed.revision_id
        path = output / "native-review-context.json"
        legacy = json.loads(path.read_bytes())
        legacy.pop("recorded_native_contract_execution")
        path.write_text(json.dumps(legacy))
        before = path.read_bytes()
        task, artifact, _ = self.native_execution_fixture(task_id)
        self.assertEqual(shared_native_review_context(
            self.plan, task, self.source, pool, output, source_preflight=artifact,
        ), legacy)
        self.assertEqual(path.read_bytes(), before)

    def test_existing_pipeline_is_not_replaced_or_resampled(self):
        task_id = self.candidate()
        path = self.output / "attempts" / task_id / "pipeline" / self.seed.revision_id
        path.mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, "existing pipeline"):
            self.finish(task_id, self.pool())
        self.assertEqual(list(path.iterdir()), [])

    def test_registered_service_routes_source_preflight_and_pipeline_without_changing_models(self):
        arguments = dict(run=Path("run"), batch_id="batch", serving=Path("serving"), graph=Path("graph"),
                         mysql_bundle=Path("mysql"), env_file=Path("env"), workdir=Path("tmp"))
        with patch(MODULE + ".registered_snapshot_pool", return_value=SimpleNamespace()), \
             patch(MODULE + ".review_checkpoint", return_value={"status": "verified"}) as review:
            result = review_registered_checkpoint(**arguments)
        self.assertEqual(result, {"status": "verified"})
        self.assertTrue(callable(review.call_args.kwargs["pipeline_runner"]))
        self.assertTrue(callable(review.call_args.kwargs["source_runner"]))
        for key, value in arguments.items():
            self.assertEqual(review.call_args.kwargs[key], value)
        with patch(MODULE + ".registered_snapshot_pool", return_value=None), \
             patch(MODULE + ".review_checkpoint", return_value={"status": "legacy"}) as review:
            self.assertEqual(review_registered_checkpoint(**arguments), {"status": "legacy"})
        self.assertNotIn("pipeline_runner", review.call_args.kwargs)
        self.assertNotIn("source_runner", review.call_args.kwargs)

    def test_parallel_checkpoint_shares_one_store_without_changing_the_native_pool(self):
        self.output.mkdir(exist_ok=True)
        immutable_json(self.output / "plan.json", self.plan)
        pool = self.pool()
        arguments = dict(run=self.output, batch_id="batch", serving=self.serving, graph=self.graph,
                         mysql_bundle=self.metadata, env_file=self.client.config.env_file, workdir=self.root)

        def review(**kwargs):
            kwargs["pipeline_runner"](task_id="first")
            kwargs["pipeline_runner"](task_id="second")
            return {"status": "routed"}

        with patch(MODULE + ".registered_snapshot_pool", return_value=pool), \
             patch(MODULE + ".review_checkpoint", side_effect=review), \
             patch(MODULE + ".finish_shared_checkpoint_candidate", return_value={}) as finish:
            self.assertEqual(review_registered_checkpoint(**arguments, parallel_finalization=True), {"status": "routed"})
        first, second = finish.call_args_list
        self.assertIs(first.kwargs["finalization_store"], second.kwargs["finalization_store"])
        self.assertIs(first.kwargs["pool"], pool)
        self.assertEqual(pool.binding.native_candidate_slots, 2)
        with patch(MODULE + ".registered_snapshot_pool", return_value=None):
            with self.assertRaisesRegex(ValueError, "registered read-only snapshot service"):
                review_registered_checkpoint(**arguments, parallel_finalization=True)

    def test_run_authority_enables_parallel_routing_for_existing_campaign_workers(self):
        from secgym.qagen.agentic.transport_amendments import PARALLEL_RUNTIME

        self.output.mkdir(exist_ok=True)
        immutable_json(self.output / "plan.json", self.plan)
        path = self.output / PARALLEL_RUNTIME
        path.parent.mkdir()
        immutable_json(path, {"controlled_authority_routing_fixture": True})

        def review(**kwargs):
            kwargs["pipeline_runner"](task_id="candidate")
            return {}

        with patch(MODULE + ".registered_snapshot_pool", return_value=self.pool()), \
             patch(MODULE + ".review_checkpoint", side_effect=review), \
             patch(MODULE + ".finish_shared_checkpoint_candidate", return_value={}) as finish, \
             patch("secgym.qagen.agentic.transport_amendments.load_parallel_finalization_runtime",
                   return_value=object()) as authority:
            review_registered_checkpoint(
                run=self.output, batch_id="batch", serving=self.serving, graph=self.graph,
                mysql_bundle=self.metadata, env_file=self.client.config.env_file, workdir=self.root,
            )
        authority.assert_called_once_with(self.plan, self.output)
        self.assertIsNotNone(finish.call_args.kwargs["finalization_store"])

    def test_shared_source_preflight_restores_limits_and_releases_its_lease(self):
        pool = self.pool()
        native_context = {
            "task_fingerprint": fingerprint(self.seed), "plan_fingerprint": fingerprint(self.plan),
            "native_snapshot_sha256": self.plan.native_snapshot_sha256,
        }
        parity = GateResult(gate="serving_parity", status="pass", reason="Actual fixture parity.")
        limits = self.source.engine.limits

        def source_review(**kwargs):
            return kwargs["native_context_provider"](self.seed, self.source)

        def measure(task, source, native):
            self.assertEqual(source.engine.limits.timeout_ms, self.plan.grader_timeout_ms or self.plan.query_limits.timeout_ms)
            self.assertIs(native, self.native)
            return parity

        with patch(MODULE + ".review_source", side_effect=source_review), \
             patch(MODULE + ".native_text_semantics", return_value=native_context), \
             patch(MODULE + ".serving_parity", side_effect=measure):
            result = review_shared_source(plan=self.plan, source=self.root / "preflight", serving=self.serving,
                                          client=self.client, pool=pool)
        self.assertEqual(result["baseline_source_native_parity"], parity.model_dump(mode="json"))
        self.assertTrue(result["mutation_world_semantics_still_require_validation"])
        self.assertEqual(self.source.engine.limits, limits)
        self.assertEqual(self.shared_leases[-1], "released")

    def test_native_context_errors_are_not_hidden_or_used_to_start_a_student(self):
        pool = self.pool()
        limits = self.source.engine.limits
        with patch(MODULE + ".review_source", side_effect=lambda **kwargs: kwargs["native_context_provider"](
            self.seed, self.source)), patch(MODULE + ".native_text_semantics", side_effect=RuntimeError("schema unavailable")):
            with self.assertRaisesRegex(RuntimeError, "schema unavailable"):
                review_shared_source(plan=self.plan, source=self.root / "preflight", serving=self.serving,
                                     client=self.client, pool=pool)
        self.assertEqual(self.source.engine.limits, limits)
        self.assertEqual(self.shared_leases[-1], "released")

    def test_cli_quota_allocation_is_explicit_and_preserves_checkpoint_review(self):
        args = ["agentic", "generate-checkpoint", "--batch-id", "tail", "--quota-aware",
                "--review-at-checkpoint", "--parallel-finalization"]
        for name in ("run", "serving-bundle", "graph-bundle", "env-file", "mysql-bundle", "workdir"):
            args += ["--" + name, str(self.root / name)]
        with patch("sys.argv", args), contextlib.redirect_stdout(io.StringIO()), \
             patch("secgym.qagen.agentic.checkpoint_batches.create_batch") as create, \
             patch("secgym.qagen.agentic.checkpoint_batches.generate_checkpoint",
                   return_value={"ready_for_checkpoint": True}), \
             patch(MODULE + ".review_registered_checkpoint", return_value={"status": "reviewed"}) as review:
            main()
        self.assertTrue(create.call_args.kwargs["quota_aware"])
        self.assertEqual(create.call_args.kwargs["checkpoint_size"], 100)
        self.assertEqual(create.call_args.kwargs["workers"], 4)
        review.assert_called_once()
        self.assertTrue(review.call_args.kwargs["parallel_finalization"])

    def test_cli_parallel_generation_requires_checkpoint_review_before_allocating(self):
        args = ["agentic", "generate-checkpoint", "--batch-id", "tail", "--parallel-finalization"]
        for name in ("run", "serving-bundle", "graph-bundle", "env-file"):
            args += ["--" + name, str(self.root / name)]
        with patch("sys.argv", args), contextlib.redirect_stderr(io.StringIO()) as errors, \
             patch("secgym.qagen.agentic.checkpoint_batches.create_batch") as create, \
             self.assertRaises(SystemExit) as failure:
            main()
        self.assertEqual(failure.exception.code, 2)
        self.assertIn("requires --review-at-checkpoint", errors.getvalue())
        create.assert_not_called()

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

    def test_cli_parallel_finalization_is_explicit(self):
        args = ["agentic", "review-checkpoint", "--batch-id", "next-checkpoint", "--parallel-finalization"]
        for name in ("run", "serving-bundle", "graph-bundle", "mysql-bundle", "env-file", "workdir"):
            args.extend(["--" + name, str(self.root / name)])
        with patch(MODULE + ".review_registered_checkpoint", return_value={"status": "shared"}) as review:
            with patch("sys.argv", args), contextlib.redirect_stdout(io.StringIO()):
                main()
        self.assertTrue(review.call_args.kwargs["parallel_finalization"])

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

    def test_cli_forwards_canonical_scope_recovery_for_both_execution_routes(self):
        approval = self.root / "canonical-scope-approval.json"
        feedback = self.root / "canonical-feedback.txt"
        feedback.write_text("Reconcile the exact source-reviewed proof scope; retain the original curator.")
        args = ["agentic", "finish-preproduction", "--task-id", self.seed.task_id,
                "--canonical-scope-review-recovery", str(approval), "--canonical-feedback", str(feedback),
                "--parent-pipeline", str(self.root / "parent"),
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
            self.assertEqual(called.call_args.kwargs["canonical_scope_review_recovery"], approval)
            self.assertEqual(called.call_args.kwargs["canonical_feedback"], feedback.read_text())

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
