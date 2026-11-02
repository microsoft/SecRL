# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
from pathlib import Path
import unittest
from unittest.mock import patch

import test_agentic_robustness as robustness_tests
from test_agentic_generation import FakeClient, call
from test_agentic_review_transport import nonstudent_policy
from secgym.qagen.agentic import json_result_recovery as recovery
from secgym.qagen.agentic.canonical_facts import SourceFactResolver
from secgym.qagen.agentic.contracts import fingerprint
from secgym.qagen.agentic.fact_curation import FactInspectionTools
from secgym.qagen.agentic.generation import RetryableCompletionError
from secgym.qagen.agentic.ledger import file_sha256
from secgym.qagen.agentic.preproduction import safe_unfinished_roles
from secgym.qagen.agentic.preproduction_pipeline import inspected_role
from secgym.qagen.agentic.review_execution import _robustness_author_validator
from secgym.qagen.agentic.robustness import RobustnessPlan


def response(text):
    output = [{"type": "message", "role": "assistant", "status": "completed",
               "content": [{"type": "output_text", "text": text}]}]
    return {
        "choices": [{"finish_reason": "stop", "message": {"role": "assistant", "tool_calls": [], "responses_output": output}}],
        "azure_responses": {"status": "completed", "error": None, "incomplete_details": None, "output": output},
    }


class ReceivedClient(FakeClient):
    def __init__(self, text, query, *, rate_limited=False):
        super().__init__([call("sql", {"query": query})])
        self.text = text
        self.rate_limited, self.attempts = rate_limited, 0

    def complete(self, messages, tools):
        index = self.attempts
        self.attempts += 1
        if self.rate_limited and index in (0, 2):
            raise RetryableCompletionError("Controlled token-rate wait.", delay_seconds=0)
        if not self.contexts:
            return super().complete(messages, tools)
        self.contexts.append(json.loads(json.dumps(messages)))
        return response(self.text)


class JsonRecoveryTests(unittest.TestCase):
    setUp = robustness_tests.RobustnessFixtureTests.setUp
    unchanged = robustness_tests.RobustnessFixtureTests.unchanged
    representation_case = robustness_tests.RobustnessFixtureTests.representation_case

    def policy(self):
        return recovery.JsonResultRecoveryPolicy(
            plan_fingerprint=nonstudent_policy().plan_fingerprint,
            user_authorization="approve_nonstudent_json_recovery",
            implementation_sha256=file_sha256(Path(recovery.__file__)),
        )

    def stopped(self, *, role="robustness-author", text=None, query="SELECT * FROM DeviceProcessEvents", name="author",
                rate_limited=False):
        self.plan = RobustnessPlan(task_fingerprint=fingerprint(self.task), cases=(self.representation_case(),))
        text = text if text is not None else "Inspected source; proposed plan follows.\n```json\n" + self.plan.model_dump_json() + "\n```"
        self.client = ReceivedClient(text, query, rate_limited=rate_limited)
        directory = self.root / name
        self.context = {"task_fingerprint": fingerprint(self.task)}
        with self.assertRaisesRegex(ValueError, "without an explicit structured finish"):
            inspected_role(self.client, self.verifier, directory, role, "Inspect original source facts.",
                           self.context, RobustnessPlan, _robustness_author_validator(self.task, self.verifier, self.context))
        return directory

    def recover(self, directory, **kwargs):
        return recovery.recover_json_result(
            directory=directory, root=kwargs.pop("root", self.root), policy=kwargs.pop("policy", self.policy()),
            transport_policy=kwargs.pop("transport_policy", nonstudent_policy()), response_type=RobustnessPlan,
            tools=kwargs.pop("tools", FactInspectionTools(SourceFactResolver(self.verifier))),
            validate_result=kwargs.pop("validate_result", _robustness_author_validator(self.task, self.verifier, self.context)),
            **kwargs,
        )

    def rewrite_response(self, directory, value):
        (directory / "0001-response.json").write_text(json.dumps(value))

    def assert_unpublished(self, directory):
        for name in (recovery.CERTIFICATE, "complete.json", "result.json", "0001-tool-results.json"):
            self.assertFalse((directory / name).exists(), name)

    def test_exact_fenced_result_preserves_history_and_resumes_without_inference(self):
        directory = self.stopped()
        original = recovery._files(directory)
        with self.assertRaises(ValueError):
            safe_unfinished_roles(directory.parent)
        result = self.recover(directory)
        self.assertEqual(result, self.plan)
        self.assertEqual({name: file_sha256(directory / name) for name in original}, original)
        certificate = json.loads((directory / recovery.CERTIFICATE).read_bytes())
        self.assertEqual(certificate["original_artifacts_sha256"], original)
        self.assertEqual(certificate["encoding"], "fenced_json")
        self.assertFalse(certificate["tool_calls_fabricated"])
        self.assertEqual(json.loads((directory / "0001-tool-results.json").read_bytes()), [])
        self.assertEqual(json.loads((directory / "0001-response.json").read_bytes())["choices"][0]["message"]["tool_calls"], [])
        safe_unfinished_roles(directory.parent)
        no_inference = FakeClient([])
        cached = inspected_role(no_inference, self.verifier, directory, "robustness-author", "Inspect original source facts.",
                                self.context, RobustnessPlan, _robustness_author_validator(self.task, self.verifier, self.context))
        self.assertEqual(cached, self.plan)
        self.assertEqual(no_inference.contexts, [])
        self.assertEqual(len(self.client.contexts), 2)
        self.assertEqual(json.loads((directory / "complete.json").read_bytes())["calls"], 2)

    def test_plain_json_and_idempotent_recovery_keep_exact_published_files(self):
        directory = self.stopped()
        self.rewrite_response(directory, response(self.plan.model_dump_json()))
        self.recover(directory)
        before = recovery._files(directory)
        self.assertEqual(self.recover(directory), self.plan)
        self.assertEqual(recovery._files(directory), before)

    def test_exact_token_waits_preserve_inspections_and_received_verdict_without_inference(self):
        directory = self.stopped(rate_limited=True)
        original = recovery._files(directory)
        self.assertEqual(self.recover(directory), self.plan)
        self.assertEqual({name: file_sha256(directory / name) for name in original}, original)
        self.assertEqual(len(list(directory.glob("*-request.json"))), 4)
        self.assertEqual(len(list(directory.glob("*-response.json"))), 2)
        self.assertEqual(json.loads((directory / "complete.json").read_bytes())["calls"], 4)
        self.assertEqual(self.recover(directory), self.plan)

    def test_token_wait_does_not_authorize_changed_context_or_unknown_send_state(self):
        directory = self.stopped(rate_limited=True)
        error = directory / "0000-error.json"
        original = error.read_bytes()
        data = json.loads(original)
        error.write_text(json.dumps({**data, "status": "error"}))
        with self.assertRaisesRegex(ValueError, "separate recovery"):
            self.recover(directory)
        error.write_bytes(original)
        request = directory / "0001-request.json"
        data = json.loads(request.read_bytes())
        data["messages"][1]["content"] = "changed context"
        request.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "exact next request"):
            self.recover(directory)
        self.assertFalse((directory / recovery.CERTIFICATE).exists())
        self.assertFalse((directory / "result.json").exists())

    def test_prose_multiple_blocks_duplicate_keys_and_nonfinite_json_fail_closed(self):
        directory = self.stopped()
        body = self.plan.model_dump_json()
        texts = (
            "The proposal is supported, please accept it.",
            "```json\n" + body + "\n```\n```json\n" + body + "\n```",
            '{"x":1,"x":2}',
            '{"x":NaN}',
            "```json\n[]\n```",
            body + "\nAnother object: {}",
        )
        for text in texts:
            with self.subTest(text=text[:40]):
                self.rewrite_response(directory, response(text))
                with self.assertRaises(ValueError):
                    self.recover(directory)
                self.assert_unpublished(directory)

    def test_incomplete_refused_tool_call_and_native_output_mismatch_are_not_recovered(self):
        directory = self.stopped()
        variants = []
        value = response(self.plan.model_dump_json())
        value["azure_responses"]["status"] = "incomplete"
        value["azure_responses"]["incomplete_details"] = {"reason": "max_output_tokens"}
        variants.append(value)
        value = response(self.plan.model_dump_json())
        value["choices"][0]["message"]["tool_calls"] = [call("finish", self.plan.model_dump(mode="json"))]
        variants.append(value)
        value = response(self.plan.model_dump_json())
        value["azure_responses"]["output"] = []
        variants.append(value)
        value = response(self.plan.model_dump_json())
        value["azure_responses"]["output"][0]["content"] = [{"type": "refusal", "refusal": "Cannot complete."}]
        variants.append(value)
        for value in variants:
            with self.subTest(value=value["azure_responses"].get("status")):
                self.rewrite_response(directory, value)
                with self.assertRaises(ValueError):
                    self.recover(directory)
                self.assert_unpublished(directory)

    def test_students_and_forged_finish_schema_cannot_recover(self):
        for role in ("blind", "native-blind", "unrecognized-role"):
            with self.subTest(role=role):
                directory = self.stopped(role=role, name=role)
                with self.assertRaisesRegex(ValueError, "non-student"):
                    self.recover(directory)
                self.assert_unpublished(directory)
        directory = self.stopped(name="bad-schema")
        path = directory / "0000-request.json"
        request = json.loads(path.read_bytes())
        next(tool for tool in request["tools"] if tool["function"]["name"] == "finish")["function"]["parameters"] = {}
        path.write_text(json.dumps(request))
        with self.assertRaisesRegex(ValueError, "trusted result schema"):
            self.recover(directory)
        self.assert_unpublished(directory)

    def test_completed_abstained_and_completed_stage_boundaries_remain_closed(self):
        for name in ("complete.json", "result.json", "abstention.json", "stage-receipt.json"):
            with self.subTest(name=name):
                directory = self.stopped(name=name.replace(".", "-"))
                (directory / name).write_text("{}")
                with self.assertRaisesRegex(ValueError, "completed|terminal"):
                    self.recover(directory)
                self.assertFalse((directory / recovery.CERTIFICATE).exists())

    def test_source_validator_and_original_inspection_coverage_are_mandatory(self):
        directory = self.stopped(query="SELECT * FROM DeviceProcessEvents WHERE 1=0")
        with self.assertRaisesRegex(ValueError, "independently inspect"):
            self.recover(directory)
        self.assert_unpublished(directory)
        directory = self.stopped(name="wrong-task")
        changed = self.plan.model_copy(update={"task_fingerprint": "b" * 64})
        self.rewrite_response(directory, response(changed.model_dump_json()))
        with self.assertRaisesRegex(ValueError, "another task"):
            self.recover(directory)
        self.assert_unpublished(directory)

    def test_unrecorded_inspections_and_changed_tool_interfaces_are_rejected(self):
        directory = self.stopped()
        tools = FactInspectionTools(SourceFactResolver(self.verifier))
        tools.observed.add(self.citation)
        with self.assertRaisesRegex(ValueError, "fresh tools"):
            self.recover(directory, tools=tools)
        self.assert_unpublished(directory)
        tools = FactInspectionTools(SourceFactResolver(self.verifier))
        with patch.object(tools, "schemas", return_value=[]):
            with self.assertRaisesRegex(ValueError, "source-tool interface"):
                self.recover(directory, tools=tools)
        self.assert_unpublished(directory)

    def test_context_missing_history_and_accepted_finish_cannot_be_bypassed(self):
        directory = self.stopped()
        request_path = directory / "0001-request.json"
        original = request_path.read_bytes()
        request = json.loads(original)
        request["messages"][1]["content"] = "{}"
        request_path.write_text(json.dumps(request))
        with self.assertRaisesRegex(ValueError, "exact next request"):
            self.recover(directory)
        request_path.write_bytes(original)
        results_path = directory / "0000-tool-results.json"
        original_results = results_path.read_bytes()
        results_path.unlink()
        with self.assertRaisesRegex(ValueError, "unresolved"):
            self.recover(directory)
        results_path.write_bytes(original_results)
        response_path = directory / "0000-response.json"
        saved = json.loads(response_path.read_bytes())
        saved["choices"][0]["message"]["tool_calls"][0]["function"]["name"] = "finish"
        response_path.write_text(json.dumps(saved))
        results = json.loads(original_results)
        results[0]["content"] = '{"accepted":true}'
        results_path.write_text(json.dumps(results))
        with self.assertRaisesRegex(ValueError, "accepted finish"):
            self.recover(directory)
        self.assert_unpublished(directory)

    def test_policy_root_and_recorded_error_are_fail_closed(self):
        directory = self.stopped()
        for policy in (
            self.policy().model_copy(update={"plan_fingerprint": "b" * 64}),
            self.policy().model_copy(update={"implementation_sha256": "0" * 64}),
        ):
            with self.assertRaisesRegex(ValueError, "policy"):
                self.recover(directory, policy=policy)
        with self.assertRaises(ValueError):
            self.recover(directory, policy=self.policy().model_copy(update={"student_roles_allowed": True}))
        with self.assertRaisesRegex(ValueError, "registry changed"):
            self.recover(directory, transport_policy=nonstudent_policy().model_copy(update={"implementation_sha256": "0" * 64}))
        with self.assertRaisesRegex(ValueError, "owned root"):
            self.recover(directory, root=self.root / "other")
        (directory / "0001-error.json").write_text('{"status":"error"}')
        with self.assertRaisesRegex(ValueError, "errored"):
            self.recover(directory)
        self.assert_unpublished(directory)

    def test_validator_cannot_modify_original_files_before_publication(self):
        directory = self.stopped()

        def changed(value, tools):
            (directory / "0000-request.json").write_text("{}")

        with self.assertRaisesRegex(ValueError, "changed during source validation"):
            self.recover(directory, validate_result=changed)
        self.assert_unpublished(directory)

    def test_partial_publication_resumes_without_reinterpreting_or_resampling(self):
        directory = self.stopped()
        original = recovery._files(directory)
        real = recovery.immutable_json

        def interrupted(path, value):
            if path.name == "complete.json":
                raise OSError("simulated publication interruption")
            return real(path, value)

        with patch.object(recovery, "immutable_json", side_effect=interrupted):
            with self.assertRaisesRegex(OSError, "publication interruption"):
                self.recover(directory)
        self.assertTrue((directory / recovery.CERTIFICATE).exists())
        self.assertFalse((directory / "complete.json").exists())
        self.assertEqual(self.recover(directory), self.plan)
        self.assertEqual({name: file_sha256(directory / name) for name in original}, original)
        self.assertEqual(len(self.client.contexts), 2)

    def test_completed_recovery_tampering_is_not_silently_repaired(self):
        directory = self.stopped()
        self.recover(directory)
        (directory / "result.json").write_text("{}")
        with self.assertRaises(ValueError):
            self.recover(directory)
        self.assertEqual((directory / "result.json").read_text(), "{}")

    def test_orphaned_producer_and_malformed_tool_results_do_not_publish(self):
        directory = self.stopped()
        (directory / recovery.PRODUCER).write_text("{}")
        with self.assertRaisesRegex(ValueError, "unresolved publication"):
            self.recover(directory)
        (directory / recovery.PRODUCER).unlink()
        path = directory / "0000-tool-results.json"
        results = json.loads(path.read_bytes())
        results[0]["content"] = "[]"
        path.write_text(json.dumps(results))
        with self.assertRaisesRegex(ValueError, "structured objects"):
            self.recover(directory)
        self.assert_unpublished(directory)


if __name__ == "__main__":
    unittest.main()
