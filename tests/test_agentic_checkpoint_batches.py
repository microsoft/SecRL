# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
from pathlib import Path
from threading import Barrier, Lock
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agentic_runtime_fixture import qualified_runtime_draft
import test_agentic_preproduction as preproduction_tests
from test_agentic_review_transport import nonstudent_policy
from secgym.qagen.agentic import checkpoint_batches as batches
from secgym.qagen.agentic.contracts import TaskRecord, fingerprint
from secgym.qagen.agentic.quality import QualityAudit, SelectorIssue
from secgym.qagen.agentic.generation import BlindSolution, TaskDraft
from secgym.qagen.agentic.ledger import file_sha256
from secgym.qagen.agentic.model_panel import immutable_json
from secgym.qagen.agentic.preproduction import SourceOutcome, _artifacts, run_source_wave, source_progress
from secgym.qagen.agentic.preproduction_pipeline import StageResult, run_candidate_pipeline


MODULE = "secgym.qagen.agentic.checkpoint_batches"
PIPELINE = "secgym.qagen.agentic.preproduction_pipeline"


class CheckpointBatchTests(unittest.TestCase):
    def setUp(self):
        preproduction_tests.PreproductionTests.setUp(self)
        self.output.mkdir()
        immutable_json(self.output / "plan.json", self.plan)
        self.policy = batches.create_batch(self.output, "batch01", checkpoint_size=4, workers=2)
        self.closed = []

    def fake_client(self, *unused):
        return SimpleNamespace(close=lambda: self.closed.append(True))

    def draft(self, **kwargs):
        attempt = kwargs["item"]["attempt"]
        data = self.seed.model_dump(mode="json")
        data.update(task_id=attempt["task_id"], lineage_group=attempt["task_id"],
                    question="Distinct candidate " + attempt["task_id"])
        data["scope"].update(mode=attempt["mode"], incident_id=attempt["incident_id"])
        task = TaskRecord.model_validate_json(json.dumps(data))
        source = self.output / "attempts" / task.task_id / "source"
        source.mkdir(parents=True)
        immutable_json(source / "task.json", task)
        self.calls.append(task.task_id)
        return task

    def generate(self, runner=None, **kwargs):
        with patch(MODULE + "._client", side_effect=self.fake_client):
            return batches.generate_checkpoint(run=self.output, batch_id=self.policy.batch_id, serving=self.serving,
                                               graph=self.graph, env_file=self.client.config.env_file,
                                               runner=runner or self.draft, **kwargs)

    def review(self, source_runner, pipeline_runner=None):
        with patch(MODULE + "._client", side_effect=self.fake_client):
            return batches.review_checkpoint(
                run=self.output, batch_id=self.policy.batch_id, serving=self.serving, graph=self.graph,
                mysql_bundle=self.root / "unused-mysql", env_file=self.client.config.env_file, workdir=self.root,
                source_runner=source_runner, pipeline_runner=pipeline_runner,
            )

    def source_review(self, status="needs_revision"):
        def runner(**kwargs):
            source = kwargs["source"]
            task = TaskRecord.model_validate_json((source / "task.json").read_bytes())
            report = {"task_fingerprint": fingerprint(task), "status": status}
            immutable_json(source / "pilot_report.json", report)
            return report
        return runner

    def test_exact_hundred_drafts_balanced_scopes_and_no_review_or_student_calls(self):
        self.policy = batches.create_batch(self.output, "hundred", checkpoint_size=100, workers=4)
        first = self.generate(max_new_attempts=2)
        self.assertEqual(first["drafts"], {"draft_ready": 2})
        self.assertFalse(first["ready_for_checkpoint"])
        with self.assertRaisesRegex(ValueError, "checkpoint is filled"):
            self.review(lambda **kwargs: self.fail("review ran before100drafts"))
        result = self.generate()
        self.assertEqual(result["drafts"], {"draft_ready": 100})
        self.assertTrue(result["ready_for_checkpoint"])
        items = batches._items(batches.batch_directory(self.output, "hundred"))
        buckets = Counter(item["bucket"] for item in items)
        self.assertEqual(buckets["tenant"], 50)
        self.assertEqual(sorted(value for key, value in buckets.items() if key != "tenant"), [5] * 10)
        progress = source_progress(self.plan, self.output)
        self.assertEqual(progress["logical_attempts_started"], 100)
        self.assertEqual(progress["source_ready"], 0)
        self.assertFalse(list(self.output.glob("attempts/*/source/quality")))
        self.assertFalse(list(self.output.glob("attempts/*/source/blind")))
        count = len(self.calls)
        self.generate(runner=lambda **kwargs: self.fail("completed draft resampled"))
        self.assertEqual(len(self.calls), count)

    def test_one_failed_candidate_is_retained_without_blocking_others_or_resetting_budget(self):
        failed = []

        def runner(**kwargs):
            if kwargs["item"]["bucket"] == "incident:5" and not failed:
                failed.append(kwargs["item"]["attempt"]["task_id"])
                raise RuntimeError("one candidate failed")
            return self.draft(**kwargs)

        result = self.generate(runner=runner)
        self.assertTrue(result["ready_for_checkpoint"])
        self.assertEqual(result["logical_attempts_in_batch"], 5)
        self.assertEqual(result["drafts"], {"draft_ready": 4, "operational_error": 1})
        self.assertEqual(source_progress(self.plan, self.output)["logical_attempts_started"], 5)
        self.assertEqual(result["repair_queue"][0]["task_id"], failed[0])
        self.assertTrue((self.output / "attempts" / failed[0] / "source-outcome.json").exists())

    def test_pending_revalidation_blocks_new_generation_before_any_attempt_or_model_call(self):
        immutable_json(self.output / "checkpoint-revalidation-required.json", {"batch_id": "first100"})
        with self.assertRaisesRegex(ValueError, "revalidation is pending"):
            self.generate()
        self.assertEqual(self.calls, [])
        self.assertFalse((self.output / "attempts").exists())
        with self.assertRaisesRegex(ValueError, "legacy source-wave generation is blocked"):
            run_source_wave(plan=self.plan, client=self.client, serving_bundle=self.serving,
                            graph_bundle=self.graph, output=self.output, wave_size=1)
        self.assertEqual(self.calls, [])

    def test_all_operational_failures_pause_instead_of_consuming_the_campaign(self):
        def fail(**kwargs):
            raise RuntimeError("shared provider failure")

        result = self.generate(runner=fail)
        self.assertFalse(result["ready_for_checkpoint"])
        self.assertEqual(result["logical_attempts_in_batch"], 2)
        self.assertEqual(result["drafts"], {"operational_error": 2})

    def test_generation_workers_are_concurrent_and_do_not_hold_the_run_lock(self):
        barrier = Barrier(2)

        def runner(**kwargs):
            barrier.wait(timeout=10)
            return self.draft(**kwargs)

        self.assertTrue(self.generate(runner=runner)["ready_for_checkpoint"])

    def test_review_failure_is_per_item_and_completed_reviews_are_not_resampled(self):
        self.generate()
        failed = []
        underlying = self.source_review()
        mutex = Lock()

        def review(**kwargs):
            with mutex:
                first = not failed
                if first:
                    failed.append(str(kwargs["source"]))
            if first:
                raise RuntimeError("one reviewer failed")
            return underlying(**kwargs)

        result = self.review(review, lambda **kwargs: self.fail("held source reached native"))
        self.assertEqual(result["source_reviews"], {"needs_revision": 3, "operational_error": 1})
        self.assertEqual(source_progress(self.plan, self.output)["source_outcomes_recorded"], 4)
        self.review(lambda **kwargs: self.fail("completed source review resampled"))

    def test_pipeline_failures_do_not_stop_other_checkpoint_items(self):
        self.generate()
        seen = []
        mutex = Lock()

        def pipeline(**kwargs):
            with mutex:
                seen.append(kwargs["task_id"])
                first = len(seen) == 1
            if first:
                raise RuntimeError("one native pipeline failed")
            return {"task_id": kwargs["task_id"], "status": "held", "stage": "robustness"}

        with patch(MODULE + ".validate_quality_gate"):
            result = self.review(self.source_review("candidate_for_mysql_validation"), pipeline)
        self.assertEqual(len(seen), 4)
        self.assertEqual(result["source_reviews"], {"source_ready": 4})
        self.assertEqual(result["admission_pipelines"], {"held": 3, "operational_error": 1})

    def test_draft_tampering_blocks_review_before_any_client_is_started(self):
        self.generate()
        item = batches._items(batches.batch_directory(self.output, "batch01"))[0]
        task = self.output / "attempts" / item["attempt"]["task_id"] / "source/task.json"
        task.write_text("{}")
        with patch(MODULE + "._client") as client:
            with self.assertRaisesRegex(ValueError, "original trace changed"):
                self.review(self.source_review())
        client.assert_not_called()

    def test_legacy_wave_cannot_adopt_an_astra_batch_context(self):
        self.generate(max_new_attempts=1)
        with self.assertRaisesRegex(ValueError, "checkpoint-owned"):
            run_source_wave(plan=self.plan, client=self.client, serving_bundle=self.serving, graph_bundle=self.graph,
                            output=self.output, wave_size=1, resume=True, runner=lambda **kwargs: self.fail("legacy model used"))

    def test_failed_review_can_be_queued_but_completed_student_cannot_be_regenerated(self):
        self.generate()
        self.review(self.source_review())
        item = batches._items(batches.batch_directory(self.output, "batch01"))[0]
        task_id = item["attempt"]["task_id"]
        role = self.output / "attempts" / task_id / "source/blind"
        role.mkdir()
        (role / "0000-request.json").write_text("{}")
        outcome_path = role.parent.parent / "source-outcome.json"
        outcome = SourceOutcome.model_validate_json(outcome_path.read_bytes())
        outcome_path.write_text(outcome.model_copy(update={"artifact_sha256": _artifacts(role.parent)}).model_dump_json())
        with patch(MODULE + "._client") as client:
            with self.assertRaisesRegex(ValueError, "pre-blind only"):
                batches.repair_checkpoint(
                    run=self.output, batch_id="batch01", task_ids=(task_id,), serving=self.serving, graph=self.graph,
                    mysql_bundle=self.root / "unused", env_file=self.client.config.env_file, workdir=self.root,
                )
        client.assert_not_called()


class CheckpointRoutingTests(unittest.TestCase):
    def setUp(self):
        preproduction_tests.PreproductionTests.setUp(self)
        self.output.mkdir()
        immutable_json(self.output / "plan.json", self.plan)
        self.policy = batches.create_batch(self.output, "routing", checkpoint_size=2, workers=2)
        self.transport = nonstudent_policy().model_copy(update={"plan_fingerprint": fingerprint(self.plan)})
        self.root_role = self.root / "roles"
        self.root_role.mkdir()
        self.base_calls, self.astra_calls = [], []

        def author(config):
            return SimpleNamespace(config=config, close=lambda: None,
                                   complete=lambda messages, tools: self.astra_calls.append(messages) or {"source": "astra"})

        with patch(MODULE + ".azure_review_client", return_value=SimpleNamespace(
            config=self.client.config, close=lambda: None,
            complete=lambda messages, tools: self.base_calls.append(messages) or {"source": "sol"},
        )), patch(MODULE + ".AzureGenerationClient", side_effect=author):
            self.routed = batches.CheckpointClient(self.plan, self.policy, self.transport, self.client.config.env_file, self.root_role)
        self.addCleanup(self.routed.close)

    def request(self, role, index=0):
        directory = self.root_role / role
        directory.mkdir(exist_ok=True)
        schema = TaskDraft if role in ("author", "repair") else BlindSolution
        messages = [{"role": "user", "content": role}]
        tools = [{"type": "function", "function": {"name": "finish", "parameters": schema.model_json_schema()}}]
        path = directory / f"{index:04d}-request.json"
        immutable_json(path, {"role": role, "messages": messages, "tools": tools})
        return path, messages, tools

    def test_only_author_and_repair_use_astra_with_explicit_model_receipts(self):
        for role in ("author", "repair", "blind", "native-blind", "quality-refuter", "difficulty-curator"):
            path, messages, tools = self.request(role)
            result = self.routed.complete(messages, tools)
            immutable_json(path.with_name("0000-response.json"), result)
            if role in ("author", "repair"):
                self.assertEqual(result["generation_model"]["deployment"], "gpt-6-astra")
                receipt = json.loads(path.with_name("0000-generation-model.json").read_bytes())
                self.assertEqual(receipt["actual_config"]["timeout_seconds"], 900)
                self.assertEqual(receipt["review_student_default"]["deployment"], "gpt-6-sol")
                self.assertEqual(receipt["review_student_default"]["timeout_seconds"], 300)
            else:
                self.assertNotIn("generation_model", result)
        self.assertEqual(len(self.astra_calls), 2)
        self.assertEqual(len(self.base_calls), 4)

    def test_started_sol_or_unanswered_author_cannot_be_replayed_as_astra(self):
        path, _, _ = self.request("author")
        immutable_json(path.with_name("0000-response.json"), {"old": "sol"})
        _, messages, tools = self.request("author", 1)
        with self.assertRaisesRegex(ValueError, "cannot switch models"):
            self.routed.complete(messages, tools)
        self.assertEqual(self.astra_calls, [])

    def test_completed_author_and_changed_actual_model_receipt_are_rejected(self):
        path, messages, tools = self.request("author")
        result = self.routed.complete(messages, tools)
        immutable_json(path.with_name("0000-response.json"), result)
        _, messages, tools = self.request("author", 1)
        receipt_path = path.with_name("0000-generation-model.json")
        receipt = json.loads(receipt_path.read_bytes())
        receipt["actual_config"]["deployment"] = "gpt-6-sol"
        receipt_path.write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, "cannot switch models"):
            self.routed.complete(messages, tools)
        (path.parent / "complete.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "completed draft"):
            self.routed.complete(messages, tools)
        self.assertEqual(len(self.astra_calls), 1)


class NativeDraftContractTests(unittest.TestCase):
    def test_json_input_typing_is_idempotent_and_preserves_every_nested_json_table(self):
        query = ("WITH rows AS (SELECT * FROM JSON_TABLE(doc,'$[*]' COLUMNS(value TEXT PATH '$')) a) "
                 "SELECT * FROM rows, JSON_TABLE(value,'$[*]' COLUMNS(name TEXT PATH '$.name')) b")
        repaired = batches.cast_mysql_json_inputs(query)
        self.assertEqual(repaired.count("AS JSON"), 2)
        self.assertEqual(batches.cast_mysql_json_inputs(repaired), repaired)
        self.assertEqual(batches.cast_mysql_json_inputs("SELECT 1"), "SELECT 1")

    def test_selector_issue_ids_are_not_query_digests_even_when_two_issues_share_sql(self):
        first = SelectorIssue(claim_id="final", program_id="answer", engine="duckdb", surface="answer",
                              query_sha256="a" * 64, kind="computed_json_path", expression="path")
        second = first.model_copy(update={"kind": "raw_json_text", "expression": "text"})
        audit = QualityAudit.model_construct(issues=(first, second))
        identifiers = batches.selector_issue_identifiers(audit)
        self.assertEqual([entry["issue_fingerprint"] for entry in identifiers],
                         [fingerprint(first), fingerprint(second)])
        self.assertNotEqual(identifiers[0]["issue_fingerprint"], first.query_sha256)
        self.assertNotEqual(identifiers[0]["issue_fingerprint"], identifiers[1]["issue_fingerprint"])


class NativeLeaseTests(unittest.TestCase):
    def setUp(self):
        preproduction_tests.PreproductionTests.setUp(self)
        self.output.mkdir()
        metadata = self.root / "mysql"
        metadata.mkdir()
        (metadata / "mysql_report.json").write_text("{}")
        (metadata / "index_report.json").write_text("{}")
        index = {"index_report.json": file_sha256(metadata / "index_report.json")}
        import hashlib
        self.plan = self.plan.model_copy(update={
            "native_snapshot_sha256": file_sha256(metadata / "mysql_report.json"),
            "native_indexes_sha256": hashlib.sha256(json.dumps(index, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        })
        immutable_json(self.output / "plan.json", self.plan)
        self.metadata = metadata
        _, self.source_report = self.graph, json.loads((self.serving / "serving_report.json").read_bytes())
        self.draft = qualified_runtime_draft(self.serving, self.source_report)
        self.limits = self.plan.query_limits
        self.source = SimpleNamespace(engine=SimpleNamespace(engine="duckdb", limits=self.limits),
                                      allowed_literals=frozenset(value.value for value in self.draft.allowed_literals),
                                      report={"serving_view_id": self.plan.serving_view_id})
        self.native = SimpleNamespace(engine=SimpleNamespace(engine="mysql", limits=self.limits),
                                      allowed_literals=self.source.allowed_literals, report=self.source.report)
        self.student = SimpleNamespace(engine="mysql", limits=self.limits, serving_view_id=self.plan.serving_view_id)
        self.leases = []

    def candidate(self, index=0):
        attempt = self.plan.attempts()[index]
        data = self.seed.model_dump(mode="json")
        data.update(task_id=attempt.task_id, lineage_group=attempt.task_id)
        data["scope"].update(mode=attempt.mode, incident_id=attempt.incident_id)
        task = TaskRecord.model_validate_json(json.dumps(data))
        directory = self.output / "attempts" / task.task_id
        source = directory / "source"
        source.mkdir(parents=True)
        immutable_json(source / "task.json", task)
        immutable_json(source / "draft.json", self.draft)
        immutable_json(directory / "attempt.json", {"plan_fingerprint": fingerprint(self.plan), "attempt": attempt.model_dump(mode="json")})
        immutable_json(directory / "source-outcome.json", SourceOutcome(
            plan_fingerprint=fingerprint(self.plan), attempt_binding_sha256=file_sha256(directory / "attempt.json"),
            attempt=attempt, status="source_ready", task_fingerprint=fingerprint(task), reason="Synthetic lease test.",
            artifact_sha256={p.name: file_sha256(p) for p in source.iterdir()},
        ))
        return task.task_id

    @contextmanager
    def lease(self):
        self.leases.append("enter")
        try:
            yield self.native, self.student
        finally:
            self.leases.append("exit")

    def run_candidate(self, task_id):
        return run_candidate_pipeline(
            plan=self.plan, run=self.output, task_id=task_id, client=self.client, source=self.source,
            mysql=None, student=None, serving_bundle=self.serving, mysql_bundle=self.metadata,
            graph_bundle=self.graph, mysqld=self.root / "unused", workdir=self.root,
            output=self.output / "attempts" / task_id / "pipeline/r1", native_engines=self.lease,
        )

    def test_grading_hold_never_acquires_native_and_native_hold_releases_lease(self):
        first, second = self.candidate(), self.candidate(1)
        with patch(PIPELINE + ".validate_quality_gate"), patch(PIPELINE + ".review_contract", return_value=StageResult(status="held", reason="Source review hold.")):
            self.assertEqual(self.run_candidate(first)["stage"], "grading")
        self.assertEqual(self.leases, [])
        with patch(PIPELINE + ".validate_quality_gate"), \
             patch(PIPELINE + ".review_contract", return_value=StageResult(status="pass", reason="Source reviewed.")), \
             patch(PIPELINE + ".native_candidate", return_value=StageResult(status="held", reason="Native hold.")):
            self.assertEqual(self.run_candidate(second)["stage"], "native")
        self.assertEqual(self.leases, ["enter", "exit"])

    def test_independent_source_reviews_run_concurrently_in_leased_pipelines(self):
        ids = (self.candidate(), self.candidate(1))
        barrier = Barrier(2)

        def review(*args, native_context=None):
            self.assertIsNone(native_context)
            barrier.wait(timeout=10)
            return StageResult(status="held", reason="Concurrent source review finished.")

        with patch(PIPELINE + ".validate_quality_gate"), patch(PIPELINE + ".review_contract", side_effect=review):
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(self.run_candidate, ids))
        self.assertEqual([result["stage"] for result in results], ["grading", "grading"])
        self.assertEqual(self.leases, [])


if __name__ == "__main__":
    unittest.main()
