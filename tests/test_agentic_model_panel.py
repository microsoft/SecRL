# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from importlib.util import find_spec
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agentic_runtime_fixture import runtime_fixture, runtime_task
from test_agentic_adapters import reviewed_fixture
from test_agentic_generation import FakeClient, call
from secgym.qagen.agentic.azure_generation import AzureGenerationClient, AzureGenerationConfig
from secgym.qagen.agentic.contracts import TaskRecord, fingerprint
from secgym.qagen.agentic.evidence import EvidenceVerifier
from secgym.qagen.agentic.model_panel import PanelProfile, captured_actions, response_usage, run_episode
from secgym.qagen.agentic.mysql_serving import open_duckdb_engine
from secgym.qagen.agentic.query import QueryFailure, QueryLimits
from secgym.qagen.agentic.secrl_adapter import SecRLV1Env, Submission


class ConfiguredFake(FakeClient):
    def __init__(self, responses):
        super().__init__(responses)
        self.config = AzureGenerationConfig(env_file=Path("unused"), deployment="fixture-model",
                                            timeout_seconds=300, max_completion_tokens=16000)
        self.budgets = []

    def complete(self, messages, tools):
        self.budgets.append(self.config.max_completion_tokens)
        return super().complete(messages, tools)


class AzureReasoningTests(unittest.TestCase):
    def test_explicit_reasoning_is_opt_in_without_storing_server_conversations(self):
        native = {"status": "completed", "output": [], "usage": {"input_tokens": 1, "output_tokens": 1}}
        for effort in (None, "medium"):
            client = object.__new__(AzureGenerationClient)
            client.config = AzureGenerationConfig(env_file=Path("unused"), deployment="fixture-model",
                                                   timeout_seconds=300, max_completion_tokens=16000, reasoning_effort=effort)
            captured = []

            def create(**kwargs):
                captured.append(kwargs)
                return SimpleNamespace(model_dump=lambda **unused: native)

            client.client = SimpleNamespace(responses=SimpleNamespace(create=create))
            client.complete([{"role": "user", "content": "Fixture only."}], [])
            self.assertEqual(captured[0]["extra_body"], {} if effort is None else {"reasoning": {"effort": effort}})
            self.assertFalse(captured[0]["store"])
            self.assertEqual(captured[0]["include"], ["reasoning.encrypted_content"])


class CapturedAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        _, _, self.serving, report = runtime_fixture(self.root / "source")
        original = runtime_task(self.serving, report).model_dump(mode="json")
        original["dataset_release"] = "v1-private-pilot"
        self.task = TaskRecord.model_validate_json(json.dumps(original))
        self.validation = reviewed_fixture(self.task)
        self.profile = PanelProfile(engine="duckdb", query_limits=QueryLimits(max_rows=100, max_bytes=65536, timeout_ms=3000))
        self.engine = open_duckdb_engine(self.serving, self.profile.query_limits)
        self.addCleanup(self.engine.connection.close)
        self.verifier = EvidenceVerifier(self.serving, self.engine, frozenset({"host.test"}))
        self.addCleanup(self.verifier.close)
        self.query = "SELECT * FROM DeviceProcessEvents WHERE DeviceName='host.test'"
        self.citations = [{"table": ref.table, "record_id": ref.public_record_id} for ref in self.task.evidence]

    def environment(self, captured=True):
        return SecRLV1Env(self.task, self.verifier, self.validation, run_id="captured-test", trajectory_ref="fixture",
                         max_steps=10, captured_results=captured, admission="private_pilot")

    def submission(self):
        return Submission.model_validate_json(json.dumps({
            "answer": self.task.private_gold.final.expected.model_dump(mode="json"), "citations": self.citations,
        })).model_dump_json()

    def test_failed_original_query_is_never_reexecuted_or_credited(self):
        env = self.environment()
        with patch.object(self.engine, "execute", side_effect=AssertionError("student query was rerun")):
            env.replay_query(self.query, QueryFailure("query_execution", "original query timed out"))
        result = env.finish_for_scorer(self.submission())
        self.assertFalse(result.grounded_final)
        self.assertEqual(result.aggregate_reward, 0.0)
        self.assertEqual(env.adapter_version, "secrl-captured-v1")

    def test_validated_captured_values_support_the_same_final_and_checkpoint(self):
        result = self.engine.execute(self.query)
        env = self.environment()
        env.replay_query(self.query, result)
        finding = {"answer": self.task.private_gold.checkpoints[0].claim.expected.model_dump(mode="json"),
                   "citations": self.citations}
        env.record_finding(json.dumps(finding))
        score = env.finish_for_scorer(self.submission())
        self.assertTrue(score.grounded_final)
        self.assertEqual(score.checkpoint_progress, 1.0)

    def test_replay_is_explicit_and_never_switches_back_to_live_student_sql(self):
        with self.assertRaisesRegex(ValueError, "captured-results"):
            self.environment(False).replay_query(self.query, self.engine.execute(self.query))
        with self.assertRaisesRegex(ValueError, "reexecute"):
            self.environment().step(self.query)


@unittest.skipUnless(find_spec("saber") and find_spec("inspect_ai"), "native panel replay requires SABER/Inspect")
class ModelPanelTests(CapturedAdapterTests):
    def run_model(self, client, *, profile=None, resume=False):
        return run_episode(
            task=self.task, validation=self.validation, verifier=self.verifier, client=client,
            profile=profile or self.profile, output=self.root / "episode", run_id="panel-test",
            manifest_fingerprint="a" * 64, resume=resume,
        )

    def finish_call(self, *, correct=True):
        answer = self.task.private_gold.final.expected.model_dump(mode="json")
        if not correct:
            answer["value"] = "wrong.exe"
        return call("finish", {"answer": answer, "citations": self.citations,
                               "confidence": "supported", "explanation": "Synthetic panel response."})

    def test_paired_native_replay_and_resume_preserve_a_completed_failure_without_model_calls(self):
        client = ConfiguredFake([call("sql", {"query": self.query}), self.finish_call(correct=False)])
        result = self.run_model(client)
        self.assertEqual(result["status"], "completed")
        self.assertFalse(result["grounded_final"])
        self.assertEqual(result["usage"]["responses"], 2)
        self.assertTrue(all(budget == 16000 for budget in client.budgets))
        public = json.loads(client.contexts[0][1]["content"])
        self.assertEqual(public, self.task.public_task().model_dump(mode="json"))
        self.assertNotIn("Tool.EXE", json.dumps(public))
        self.assertNotIn("difficulty", json.dumps(client.contexts))
        replay = self.run_model(ConfiguredFake([]), resume=True)
        self.assertEqual(replay, result)
        changed = self.profile.model_copy(update={"max_responses": 65})
        with self.assertRaisesRegex(ValueError, "immutable"):
            self.run_model(ConfiguredFake([]), resume=True, profile=changed)

    def test_response_exhaustion_preserves_checkpoint_credit_without_a_fabricated_answer(self):
        profile = self.profile.model_copy(update={"max_responses": 2})
        finding = {"answer": self.task.private_gold.checkpoints[0].claim.expected.model_dump(mode="json"),
                   "citations": self.citations}
        client = ConfiguredFake([call("sql", {"query": self.query}), call("record_finding", finding)])
        result = self.run_model(client, profile=profile)
        self.assertEqual(result["status"], "budget_exhausted")
        self.assertEqual(result["usage"]["responses"], 2)
        self.assertEqual(len(client.contexts), 2)
        self.assertFalse(result["grounded_final"])
        self.assertEqual(result["checkpoint_progress"], 1.0)
        self.assertEqual(result["reward"], 0.5)
        self.assertEqual(self.run_model(ConfiguredFake([]), profile=profile, resume=True), result)

    def test_total_output_budget_clamps_the_last_request(self):
        profile = self.profile.model_copy(update={"max_output_tokens": 2, "response_output_tokens": 2})
        client = ConfiguredFake([call("sql", {"query": self.query}), self.finish_call()])
        result = self.run_model(client, profile=profile)
        self.assertEqual(client.budgets, [2, 1])
        self.assertEqual(result["usage"]["output_tokens"], 2)
        self.assertTrue(result["grounded_final"])

    def test_abstention_is_retained_and_not_treated_as_an_operational_error(self):
        result = self.run_model(ConfiguredFake([call("abstain", {"reason": "Cannot establish the requested fact."})]))
        self.assertEqual(result["status"], "abstained")
        self.assertFalse(result["grounded_final"])
        self.assertEqual(result["reward"], 0.0)

    def test_truncated_response_cannot_contribute_unexecuted_sql_observations(self):
        class Truncated(ConfiguredFake):
            def complete(self, messages, tools):
                return {
                    "choices": [{"finish_reason": "incomplete", "message": {
                        "role": "assistant", "tool_calls": [call("sql", {"query": "SELECT * FROM DeviceProcessEvents"})],
                    }}], "usage": {"input_tokens": 1, "output_tokens": 2},
                    "azure_responses": {"status": "incomplete", "incomplete_details": {"reason": "max_output_tokens"}},
                }

        result = self.run_model(Truncated([]))
        self.assertEqual(result["status"], "budget_exhausted")
        self.assertEqual(captured_actions(self.root / "episode/student"), ())
        self.assertEqual(result["checkpoint_progress"], 0.0)
        self.assertFalse(result["grounded_final"])

    def test_operational_error_remains_unknown_and_is_not_resampled(self):
        class Broken(ConfiguredFake):
            def complete(self, messages, tools):
                raise RuntimeError("Synthetic endpoint unavailable.")

        result = self.run_model(Broken([]))
        self.assertEqual(result["status"], "operational_error")
        self.assertIsNone(result["grounded_final"])
        self.assertIsNone(result["reward"])
        self.assertEqual(self.run_model(ConfiguredFake([]), resume=True), result)

    def test_interrupted_grading_recovers_without_restarting_the_student(self):
        client = ConfiguredFake([call("sql", {"query": self.query}), self.finish_call()])
        with patch("secgym.qagen.agentic.model_panel._native_replay", side_effect=RuntimeError("Synthetic scoring interruption.")):
            with self.assertRaisesRegex(RuntimeError, "scoring interruption"):
                self.run_model(client)
        self.assertTrue((self.root / "episode/termination.json").exists())
        self.assertTrue((self.root / "episode/grading/attempt-0000/error.json").exists())
        result = self.run_model(ConfiguredFake([]), resume=True)
        self.assertTrue(result["grounded_final"])
        self.assertTrue((self.root / "episode/grading/attempt-0001/evaluation.json").exists())
        self.assertEqual(result["usage"]["responses"], 2)

    def test_changed_capture_is_not_a_valid_completed_episode(self):
        self.run_model(ConfiguredFake([call("sql", {"query": self.query}), self.finish_call()]))
        path = self.root / "episode/student/0000-tool-results.json"
        path.write_text(path.read_text() + " ")
        with self.assertRaisesRegex(ValueError, "captured trace changed"):
            self.run_model(ConfiguredFake([]), resume=True)

    def test_missing_usage_is_explicit_not_a_zero_cost_completion(self):
        role = self.root / "usage"
        role.mkdir()
        (role / "0000-response.json").write_text(json.dumps({"choices": []}))
        with self.assertRaisesRegex(ValueError, "usage accounting"):
            response_usage(role)

    def grader(self, **changes):
        limits = self.profile.query_limits.model_copy(update={"timeout_ms": 120000, **changes})
        engine = open_duckdb_engine(self.serving, limits)
        self.addCleanup(engine.connection.close)
        verifier = EvidenceVerifier(self.serving, engine, self.verifier.allowed_literals)
        self.addCleanup(verifier.close)
        return verifier

    def test_longer_private_grading_does_not_change_student_sql_limits(self):
        grader = self.grader()
        client = ConfiguredFake([call("sql", {"query": self.query}), self.finish_call()])
        student_limits = []
        execute = self.engine.execute

        def checked_execute(*args, **kwargs):
            student_limits.append(self.engine.limits.timeout_ms)
            return execute(*args, **kwargs)

        with patch.object(self.engine, "execute", checked_execute):
            result = run_episode(
                task=self.task, validation=self.validation, verifier=self.verifier, grading_verifier=grader,
                client=client, profile=self.profile, output=self.root / "episode", run_id="panel-test",
                manifest_fingerprint="a" * 64,
            )
        self.assertTrue(result["grounded_final"])
        self.assertTrue(student_limits)
        self.assertEqual(set(student_limits), {3000})
        binding = json.loads((self.root / "episode/binding.json").read_bytes())
        self.assertEqual(binding["profile"]["query_limits"]["timeout_ms"], 3000)
        self.assertEqual(binding["grading_query_limits"]["timeout_ms"], 120000)

    def test_private_grader_cannot_change_source_result_or_literal_policy(self):
        grader = self.grader(max_rows=101)
        with self.assertRaisesRegex(ValueError, "only the query timeout"):
            run_episode(
                task=self.task, validation=self.validation, verifier=self.verifier, grading_verifier=grader,
                client=ConfiguredFake([]), profile=self.profile, output=self.root / "invalid", run_id="panel-test",
                manifest_fingerprint="a" * 64,
            )

    def test_recorded_student_can_receive_a_versioned_grade_without_model_resampling(self):
        original = self.run_model(ConfiguredFake([call("sql", {"query": self.query}), self.finish_call(correct=False)]))
        original_bytes = (self.root / "episode/episode.json").read_bytes()
        client = ConfiguredFake([])
        result = run_episode(
            task=self.task, validation=self.validation, verifier=self.verifier, grading_verifier=self.grader(),
            client=client, profile=self.profile, output=self.root / "amended", run_id="panel-test",
            manifest_fingerprint="b" * 64, recorded_from=self.root / "episode",
        )
        self.assertFalse(result["grounded_final"])
        self.assertEqual(result["usage"], original["usage"])
        self.assertEqual(client.contexts, [])
        self.assertFalse((self.root / "amended/student").exists())
        self.assertEqual((self.root / "episode/episode.json").read_bytes(), original_bytes)
        source = json.loads((self.root / "amended/recording-source.json").read_bytes())
        self.assertEqual(source["model_calls"], 0)
        with self.assertRaisesRegex(ValueError, "different task, model or student profile"):
            run_episode(
                task=self.task, validation=self.validation, verifier=self.verifier, grading_verifier=self.grader(),
                client=ConfiguredFake([]), profile=self.profile.model_copy(update={"max_responses": 65}),
                output=self.root / "invalid-import", run_id="panel-test", manifest_fingerprint="b" * 64,
                recorded_from=self.root / "episode",
            )

    def test_accepted_finish_without_completion_files_cannot_request_another_model_answer(self):
        self.run_model(ConfiguredFake([call("sql", {"query": self.query}), self.finish_call()]))
        for name in ("episode.json", "termination.json", "student/result.json", "student/complete.json"):
            (self.root / "episode" / name).unlink()
        client = ConfiguredFake([])
        with self.assertRaisesRegex(ValueError, "accepted finish"):
            self.run_model(client, resume=True)
        self.assertEqual(client.contexts, [])


if __name__ == "__main__":
    unittest.main()
