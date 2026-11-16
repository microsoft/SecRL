# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
import hashlib
from pathlib import Path
from threading import Barrier, Lock
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agentic_runtime_fixture import qualified_runtime_draft
import test_agentic_preproduction as preproduction_tests
from test_agentic_review_transport import nonstudent_policy
from test_agentic_generation import FakeClient, call
from secgym.qagen.agentic import checkpoint_batches as batches
from secgym.qagen.agentic.contracts import Contract, GateResult, TaskRecord, fingerprint
from secgym.qagen.agentic.quality import QualityAudit, SelectorIssue
from secgym.qagen.agentic.generation import BlindSolution, TaskDraft, run_role
from secgym.qagen.agentic.ledger import file_sha256
from secgym.qagen.agentic.json_result_recovery import JsonResultRecoveryPolicy
from secgym.qagen.agentic.model_panel import immutable_json
from secgym.qagen.agentic.preproduction import SourceOutcome, _artifacts, run_source_wave, source_progress
from secgym.qagen.agentic.preproduction_pipeline import StageResult, run_candidate_pipeline
from secgym.qagen.agentic.preproduction_admission import ArtifactVerification, admission_progress


MODULE = "secgym.qagen.agentic.checkpoint_batches"
PIPELINE = "secgym.qagen.agentic.preproduction_pipeline"


class CheckpointBatchTests(unittest.TestCase):
    def setUp(self):
        preproduction_tests.PreproductionTests.setUp(self)
        self.output.mkdir()
        immutable_json(self.output / "plan.json", self.plan)
        self.policy = batches.create_batch(self.output, "batch01", checkpoint_size=4, workers=2)
        self.closed = []

    def test_future_author_guidance_preserves_exact_indexed_lookups_and_grouped_output(self):
        for text in ("BINARY on a JSON-derived right-hand operand", "verified physical-column metadata",
                     "trailing-space distinctions", "CAST(... AS CHAR) in an outer SELECT",
                     "ONLY_FULL_GROUP_BY"):
            self.assertIn(text, batches.DRAFT_INSTRUCTIONS)
            self.assertNotIn(text, batches.AUTHOR_INSTRUCTIONS)

    def test_checkpoint_and_campaign_progress_share_one_verified_calculation(self):
        verification = ArtifactVerification()
        with patch(MODULE + ".admission_progress", wraps=admission_progress) as progress:
            checkpoint, campaign = batches.checkpoint_progress_with_campaign(
                self.output, self.policy.batch_id, verification=verification)
            progress.assert_called_once_with(self.plan, self.output, verification=verification)
        self.assertEqual(checkpoint, batches.checkpoint_progress(self.output, self.policy.batch_id))
        self.assertEqual(campaign, admission_progress(self.plan, self.output))
        self.assertEqual(checkpoint["campaign"], {key: campaign[key] for key in (
            "logical_attempts_started", "source_ready", "validated_new_questions")})

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

    def test_exact_checkpoint_producer_amendment_preserves_policy_and_completed_drafts(self):
        self.generate(max_new_attempts=2)
        directory = batches.batch_directory(self.output, self.policy.batch_id)
        policy_bytes = (directory / "policy.json").read_bytes()
        completed = {path: path.read_bytes() for path in (self.output / "attempts").glob("*/draft-result.json")}
        old, new = directory / "producer-before.py", directory / "producer-after.py"
        original = Path(batches.__file__).read_bytes()
        old.write_bytes(original)
        new.write_bytes(original + b"\n# Controlled producer metadata fixture.\n")
        updated = hashlib.sha256(new.read_bytes()).hexdigest()
        def hashes(path):
            return updated if Path(path).resolve() == Path(batches.__file__).resolve() else file_sha256(path)
        with patch(MODULE + ".file_sha256", side_effect=hashes):
            with self.assertRaisesRegex(ValueError, "run and producer"):
                batches._check_policy(self.plan, self.output, self.policy)
            amendment = batches.record_checkpoint_producer_amendment(
                self.output, self.policy.batch_id, previous_source=old, current_source=new,
                reason="Controlled author validation-error recovery; source runtime and completed drafts unchanged.",
            )
            self.assertEqual(amendment.previous_sha256, self.policy.implementation_sha256)
            self.assertEqual(batches.checkpoint_producer(self.output, self.policy), updated)
            batches._check_policy(self.plan, self.output, self.policy)
            result = self.generate()
            self.assertEqual(result["drafts"], {"draft_ready": 4})
        self.assertEqual((directory / "policy.json").read_bytes(), policy_bytes)
        self.assertTrue(all(path.read_bytes() == value for path, value in completed.items()))
        path = directory / "producer-amendments/0000.json"
        original_amendment = path.read_bytes()
        changed = json.loads(original_amendment)
        changed["source_runtime_sha256"]["quality.py"] = "0" * 64
        path.write_text(json.dumps(changed))
        with self.assertRaisesRegex(ValueError, "policy, source runtime"):
            batches.checkpoint_producer(self.output, self.policy)
        path.write_bytes(original_amendment)
        new.write_bytes(new.read_bytes() + b"changed")
        with self.assertRaisesRegex(ValueError, "producer archive"):
            batches.checkpoint_producer(self.output, self.policy)

    def test_producer_amendment_rejects_unowned_files_noop_and_changed_policy(self):
        directory = batches.batch_directory(self.output, self.policy.batch_id)
        original = directory / "producer-before.py"
        original.write_bytes(Path(batches.__file__).read_bytes())
        with self.assertRaisesRegex(ValueError, "no-op"):
            batches.record_checkpoint_producer_amendment(
                self.output, self.policy.batch_id, previous_source=original, current_source=original, reason="No change.",
            )
        outside = self.root / "outside-producer.py"
        outside.write_bytes(original.read_bytes() + b"\n# Unowned fixture.\n")
        updated = file_sha256(outside)
        def hashes(path):
            return updated if Path(path).resolve() == Path(batches.__file__).resolve() else file_sha256(path)
        with patch(MODULE + ".file_sha256", side_effect=hashes), self.assertRaisesRegex(ValueError, "exact owned"):
            batches.record_checkpoint_producer_amendment(
                self.output, self.policy.batch_id, previous_source=original, current_source=outside,
                reason="An archive outside the batch is not eligible.",
            )
        altered = self.policy.model_copy(update={"checkpoint_size": 5})
        with self.assertRaisesRegex(ValueError, "unchanged original"):
            batches.checkpoint_producer(self.output, altered)
        folder = directory / "producer-amendments"
        folder.mkdir()
        immutable_json(folder / "0001.json", {"invalid": True})
        with self.assertRaisesRegex(ValueError, "contiguous"):
            batches.checkpoint_producer(self.output, self.policy)

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
            complete_with_credentials=lambda client, messages, tools: client.complete(messages, tools),
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

    def test_astra_credential_failure_uses_the_same_bounded_transport(self):
        from azure.core.exceptions import ClientAuthenticationError
        from secgym.qagen.agentic.review_transport import ReviewTransportClient

        base = SimpleNamespace(config=self.client.config, close=lambda: None)
        review = SimpleNamespace(config=self.client.config.model_copy(update={"timeout_seconds": 900}), close=lambda: None)
        self.routed.base = ReviewTransportClient(base, review, self.transport, (self.root_role,))
        path, messages, tools = self.request("author")
        with patch.object(self.routed.author, "complete", side_effect=[
            ClientAuthenticationError("fixture"), {"source": "astra"},
        ]) as complete, patch("time.sleep"):
            response = self.routed.complete(messages, tools)
        self.assertEqual(complete.call_count, 2)
        self.assertEqual(complete.call_args_list[0], complete.call_args_list[1])
        self.assertEqual(response["generation_model"]["deployment"], "gpt-6-astra")
        event = json.loads(path.with_name("0000-credential-0000.json").read_bytes())
        self.assertEqual(event["role"], "author")
        self.assertEqual(event["effective_config"]["deployment"], "gpt-6-astra")
        self.assertEqual(event["effective_config"]["timeout_seconds"], 900)
        self.assertIs(event["model_request_sent"], False)

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

    def test_mysql_parser_failures_are_actionable_validation_errors(self):
        invalid = (
            "SELECT * FROM JSON_TABLE(CAST(doc AS JSON),'$' COLUMNS(n DOUBLE PATH '$.n' NULL ON EMPTY NULL ON ERROR)) j",
            "SELECT 'unterminated",
        )
        for query in invalid:
            with self.subTest(query=query), self.assertRaisesRegex(ValueError, "pinned SQL parser"):
                batches.cast_mysql_json_inputs(query)

    def test_author_can_correct_a_parser_failure_without_aborting_the_role(self):
        import tempfile
        class Proposal(Contract):
            query: str
        invalid = "SELECT * FROM JSON_TABLE(CAST(doc AS JSON),'$' COLUMNS(n DOUBLE PATH '$.n' NULL ON EMPTY)) j"
        client = FakeClient([call("finish", {"query": invalid}), call("finish", {"query": "SELECT 1"})])
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "author"
            result = run_role(
                client, SimpleNamespace(schemas=lambda: []), "author", "Controlled parser feedback fixture.", {},
                Proposal, output, validate_result=lambda value: batches.cast_mysql_json_inputs(value.query),
            )
            self.assertEqual(result.query, "SELECT 1")
            self.assertEqual(len(client.contexts), 2)
            self.assertIn("pinned SQL parser", (output / "0000-tool-results.json").read_text())
            self.assertIn(invalid, json.dumps(json.loads((output / "0000-response.json").read_bytes())))

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

    def test_json_recovery_selects_the_current_bound_policy_not_a_fixed_filename(self):
        import tempfile
        from secgym.qagen.agentic import json_result_recovery

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            current = JsonResultRecoveryPolicy(
                plan_fingerprint="a" * 64, user_authorization="approve_nonstudent_json_recovery",
                implementation_sha256=file_sha256(Path(json_result_recovery.__file__)),
            )
            old = current.model_copy(update={"implementation_sha256": "b" * 64})
            immutable_json(root / "json-result-recovery-policy01.json", old)
            immutable_json(root / "json-result-recovery-policy02.json", current)
            self.assertEqual(batches.current_json_recovery_policy(root, "a" * 64), current)
            self.assertEqual(json.loads((root / "json-result-recovery-policy01.json").read_bytes()),
                             old.model_dump(mode="json"))

    def test_json_recovery_cannot_use_stale_or_foreign_authorization(self):
        import tempfile

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertIsNone(batches.current_json_recovery_policy(root, "a" * 64))
            policy = JsonResultRecoveryPolicy(
                plan_fingerprint="b" * 64, user_authorization="approve_nonstudent_json_recovery",
                implementation_sha256="c" * 64,
            )
            immutable_json(root / "json-result-recovery-policy01.json", policy)
            with self.assertRaisesRegex(ValueError, "this plan and current producer"):
                batches.current_json_recovery_policy(root, "a" * 64)


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


class QuotaCheckpointTests(unittest.TestCase):
    setUp = CheckpointBatchTests.setUp
    fake_client = CheckpointBatchTests.fake_client
    draft = CheckpointBatchTests.draft
    generate = CheckpointBatchTests.generate

    def progress(self, *, tail=False):
        buckets = {
            name: {"validated_shortfall": 0 if tail else 50, "remaining_logical_attempts": 100}
            for name in batches._targets(100)
        }
        buckets["tenant"] = {"validated_shortfall": 0 if tail else 500, "remaining_logical_attempts": 1000}
        return {"buckets": buckets, "logical_attempts_started": 0, "source_ready": 0, "validated_new_questions": 0}

    def test_regular_quota_allocation_preserves_balanced_hundred(self):
        self.assertEqual(batches.quota_targets(self.progress()), batches._targets(100))

    def test_filled_incidents_are_skipped_without_overfilling_or_losing_tenant_balance(self):
        progress = self.progress()
        for name in ("incident:5", "incident:34"):
            progress["buckets"][name]["validated_shortfall"] = 0
        targets = batches.quota_targets(progress)
        self.assertEqual(targets["incident:5"], 0)
        self.assertEqual(targets["incident:34"], 0)
        self.assertEqual(targets["tenant"], 50)
        self.assertEqual(sum(targets.values()), 100)
        self.assertLessEqual(max(v for k, v in targets.items() if k != "tenant"), 7)

    def test_tenant_only_and_incident_only_tails_are_supported(self):
        for bucket in ("tenant", "incident:322"):
            progress = self.progress(tail=True)
            progress["buckets"][bucket]["validated_shortfall"] = 3
            targets = batches.quota_targets(progress)
            self.assertEqual(targets[bucket], 3)
            self.assertEqual(sum(targets.values()), 3)

    def test_each_scope_attempt_ceiling_bounds_its_draft_allocation(self):
        progress = self.progress(tail=True)
        progress["buckets"]["incident:36"].update(validated_shortfall=5, remaining_logical_attempts=2)
        progress["buckets"]["tenant"].update(validated_shortfall=4, remaining_logical_attempts=1)
        targets = batches.quota_targets(progress)
        self.assertEqual(targets["incident:36"], 2)
        self.assertEqual(targets["tenant"], 1)
        self.assertEqual(sum(targets.values()), 3)
        with self.assertRaisesRegex(ValueError, "no remaining admission quota"):
            batches.quota_targets(self.progress(tail=True))

    def test_quota_inputs_cannot_hide_invalid_capacity_or_exceed_checkpoint_limit(self):
        for maximum in (0, 101, True):
            with self.assertRaisesRegex(ValueError, "between one and one hundred"):
                batches.quota_targets(self.progress(), maximum)
        for invalid in (-1, 1000.0, True):
            progress = self.progress()
            progress["buckets"]["tenant"]["remaining_logical_attempts"] = invalid
            with self.assertRaisesRegex(ValueError, "nonnegative integers"):
                batches.quota_targets(progress)

    def test_quota_policy_is_immutable_and_legacy_fingerprints_are_unchanged(self):
        legacy = batches.load_batch_policy(batches.batch_directory(self.output, "batch01") / "policy.json")
        self.assertEqual(fingerprint(legacy), fingerprint(self.policy))
        self.assertNotIn("allocation_policy", legacy.model_dump())
        progress = self.progress(tail=True)
        progress["buckets"]["tenant"]["validated_shortfall"] = 3
        with patch(MODULE + ".admission_progress", return_value=progress):
            policy = batches.create_batch(self.output, "tail", quota_aware=True)
        self.assertIsInstance(policy, batches.QuotaCheckpointBatchPolicy)
        self.assertEqual(policy.checkpoint_size, 3)
        self.assertEqual(policy.requested_checkpoint_size, 100)
        with patch(MODULE + ".admission_progress", side_effect=AssertionError("reallocated an existing batch")):
            self.assertEqual(batches.create_batch(self.output, "tail", quota_aware=True), policy)
        with self.assertRaisesRegex(ValueError, "configuration cannot change"):
            batches.create_batch(self.output, "tail")
        with self.assertRaisesRegex(ValueError, "configuration cannot change"):
            batches.create_batch(self.output, "tail", checkpoint_size=3, quota_aware=True)

    def test_actual_reservations_follow_the_sealed_remaining_scope_targets(self):
        progress = self.progress(tail=True)
        progress["buckets"]["incident:322"]["validated_shortfall"] = 1
        progress["buckets"]["tenant"]["validated_shortfall"] = 2
        with patch(MODULE + ".admission_progress", return_value=progress):
            self.policy = batches.create_batch(self.output, "tail", quota_aware=True, workers=2)
            result = self.generate()
        self.assertEqual(result["drafts"], {"draft_ready": 3})
        self.assertTrue(result["ready_for_checkpoint"])
        self.assertEqual(result["checkpoint_size"], 3)
        reserved = batches._items(batches.batch_directory(self.output, "tail"))
        self.assertEqual(Counter(item["bucket"] for item in reserved), {"incident:322": 1, "tenant": 2})
        self.assertEqual(source_progress(self.plan, self.output)["logical_attempts_started"], 3)

    def test_changed_quota_blocks_pending_model_dispatch_without_reallocating(self):
        progress = self.progress(tail=True)
        progress["buckets"]["tenant"]["validated_shortfall"] = 1
        with patch(MODULE + ".admission_progress", return_value=progress):
            policy = batches.create_batch(self.output, "tail", quota_aware=True)
            pending = batches.reserve_drafts(self.plan, self.output, policy, 1, {})
            self.assertEqual(len(pending), 1)
            progress["buckets"]["tenant"]["validated_shortfall"] = 0
            with self.assertRaisesRegex(ValueError, "quotas changed"):
                batches.reserve_drafts(self.plan, self.output, policy, 1, {})
        self.assertEqual(self.calls, [])
        self.assertEqual(len(batches._items(batches.batch_directory(self.output, "tail"))), 1)

    def test_quota_is_rechecked_after_acquiring_the_admission_metadata_lock(self):
        progress = self.progress(tail=True)
        progress["buckets"]["tenant"]["validated_shortfall"] = 1
        with patch(MODULE + ".admission_progress", return_value=progress):
            policy = batches.create_batch(self.output, "tail", quota_aware=True)
        inside = []

        @contextmanager
        def locked(*args, **kwargs):
            inside.append(True)
            progress["buckets"]["tenant"]["validated_shortfall"] = 0
            yield

        def current(*args):
            self.assertEqual(inside, [True])
            return progress

        with patch(MODULE + ".locked_run", side_effect=locked), \
             patch(MODULE + ".admission_progress", side_effect=current):
            with self.assertRaisesRegex(ValueError, "quotas changed"):
                batches.reserve_drafts(self.plan, self.output, policy, 1, {})
        self.assertFalse((self.output / "attempts").exists())

    def test_unknown_allocation_and_inconsistent_target_totals_are_rejected(self):
        data = self.policy.model_dump(mode="json")
        data.update(allocation_policy="remaining-admission-quotas-v1", requested_checkpoint_size=4,
                    scope_targets=batches._targets(3))
        with self.assertRaisesRegex(ValueError, "actual checkpoint size"):
            batches.QuotaCheckpointBatchPolicy.model_validate_json(json.dumps(data))
        path = self.root / "unknown-policy.json"
        path.write_text(json.dumps({**data, "allocation_policy": "unknown"}))
        with self.assertRaisesRegex(ValueError, "unknown checkpoint allocation"):
            batches.load_batch_policy(path)


class SourceNativePreflightTests(unittest.TestCase):
    setUp = NativeLeaseTests.setUp

    def source_input(self):
        source = self.root / "source-review"
        source.mkdir()
        immutable_json(source / "task.json", self.seed)
        immutable_json(source / "draft.json", self.draft)
        immutable_json(source / "draft-quality-audit.json", {})
        return source

    def native_context(self, *, failed=False):
        parity = GateResult(
            gate="serving_parity", status="error" if failed else "pass",
            reason="Explicitly cast unsupported result type: bytes" if failed else "Actual source/native parity.",
            error_code="unsupported_result_type" if failed else None,
        )
        return {
            "task_fingerprint": fingerprint(self.seed), "plan_fingerprint": fingerprint(self.plan),
            "native_snapshot_sha256": self.plan.native_snapshot_sha256,
            "physical_text_columns": {"DeviceProcessEvents": {"utf8mb4_0900_bin / NO PAD": ["FileName"]}},
            "baseline_source_native_parity": parity.model_dump(mode="json"),
        }

    def invoke(self, source, provider):
        audit = QualityAudit.model_construct(
            task_fingerprint=fingerprint(self.seed), implementation_sha256=batches.quality_hashes(), issues=())
        with patch(MODULE + ".EvidenceVerifier", return_value=self.source), \
             patch.object(self.source, "close", create=True), \
             patch(MODULE + ".QualityAudit.model_validate_json", return_value=audit):
            return batches.review_source(plan=self.plan, source=source, serving=self.serving, client=self.client,
                                         native_context_provider=provider)

    def test_native_failure_is_reported_before_any_review_or_student(self):
        source = self.source_input()
        with patch(MODULE + ".run_quality_gate", side_effect=AssertionError("review called")), \
             patch(MODULE + ".run_role", side_effect=AssertionError("student called")):
            result = self.invoke(source, lambda task, verifier: self.native_context(failed=True))
        self.assertEqual(result["status"], "needs_revision")
        self.assertFalse(result["blind_started"])
        self.assertEqual(result["native_preflight"]["error_code"], "unsupported_result_type")
        self.assertEqual(result["source_quality"]["status"], "not_run")
        self.assertFalse((source / "quality").exists())
        self.assertFalse((source / "blind").exists())
        feedback = batches.source_repair_feedback(source)
        self.assertEqual(feedback["recorded_native_preflight"], self.native_context(failed=True))

    def test_review_receives_actual_native_metadata_and_grouped_proof_diagnostics(self):
        source = self.source_input()
        diagnostics = {"final": {"witness_group_sizes": [4]}}
        with patch(MODULE + ".run_quality_gate", return_value=({"status": "needs_revision"}, None)) as review, \
             patch(MODULE + ".contract_proof_diagnostics", return_value=diagnostics):
            result = self.invoke(source, lambda task, verifier: self.native_context())
        context = review.call_args.kwargs["review_context"]
        self.assertEqual(context["verified_native_semantics"], self.native_context())
        self.assertEqual(context["actual_verifier_diagnostics"], diagnostics)
        self.assertFalse(context["student_outcomes_supplied"])
        self.assertFalse(result["blind_started"])

    def test_wrong_native_task_binding_cannot_reach_review(self):
        source = self.source_input()
        context = {**self.native_context(), "task_fingerprint": "f" * 64}
        with patch(MODULE + ".run_quality_gate", side_effect=AssertionError("review called")):
            with self.assertRaisesRegex(ValueError, "different task or snapshot"):
                self.invoke(source, lambda task, verifier: context)
        self.assertFalse((source / "native-source-preflight.json").exists())

    def test_source_repair_does_not_invent_a_failure_from_passing_preflight(self):
        source = self.source_input()
        immutable_json(source / "native-source-preflight.json", self.native_context())
        with self.assertRaisesRegex(ValueError, "matching failed native preflight"):
            batches.source_repair_feedback(source)

    def test_legacy_source_review_does_not_claim_native_validation(self):
        source = self.source_input()
        with patch(MODULE + ".run_quality_gate", return_value=({"status": "needs_revision"}, None)) as review, \
             patch(MODULE + ".contract_proof_diagnostics", side_effect=AssertionError("native diagnostics requested")):
            self.invoke(source, None)
        self.assertNotIn("verified_native_semantics", review.call_args.kwargs["review_context"])
        self.assertFalse((source / "native-source-preflight.json").exists())


if __name__ == "__main__":
    unittest.main()
