# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from azure.core.exceptions import ClientAuthenticationError

import test_agentic_robustness as robustness_tests
import test_agentic_quality as quality_tests
from test_agentic_generation import FakeClient, call
from test_agentic_model_panel import ConfiguredFake
from secgym.qagen.agentic.azure_generation import AzureGenerationConfig
from secgym.qagen.agentic.canonical_facts import CanonicalFactBundle, CanonicalFactReview, CanonicalSourceFact
from secgym.qagen.agentic.contracts import fingerprint
from secgym.qagen.agentic.generation import BlindSolution
from secgym.qagen.agentic.generation import RetryableCompletionError
from secgym.qagen.agentic.ledger import file_sha256
from secgym.qagen.agentic.preproduction import safe_unfinished_roles
from secgym.qagen.agentic.preproduction_admission import FinalReview, ObjectiveReview
from secgym.qagen.agentic.preproduction_pipeline import _citations, _json_hashes, _review_validator, inspected_role
from secgym.qagen.agentic import review_transport
from secgym.qagen.agentic.review_transport import ReviewTransportClient, ReviewTransportPolicy, interrupted_review, recover_review
from secgym.qagen.agentic.review_transport import AUTHOR_ROLES, NonStudentTransportPolicy
from secgym.qagen.agentic.review_transport import (
    PreRequestRecoveryApproval, authorize_pre_request_recovery, load_run_transport_policy,
)
from secgym.qagen.agentic.review_execution import _robustness_author_validator, bind_transport_execution
from secgym.qagen.agentic.robustness import RobustnessPlan


class FakeTransport(FakeClient):
    def __init__(self, responses, config):
        super().__init__(responses)
        self.config = config
        self.closed = False

    def close(self):
        self.closed = True


def policy():
    return ReviewTransportPolicy(
        plan_fingerprint="a" * 64, user_authorization="approve_review_timeout_and_recovery",
        implementation_sha256=file_sha256(Path(review_transport.__file__)),
    )


def nonstudent_policy(previous=None):
    return NonStudentTransportPolicy(
        plan_fingerprint="a" * 64, previous_policy_fingerprint=fingerprint(previous or policy()),
        user_authorization="all_nonstudent_900_and_recovery",
        implementation_sha256=file_sha256(Path(review_transport.__file__)),
    )


def objective_comparison_context(count=32, *, special=False):
    rows = []
    for index in range(count):
        number = "-0.00e+05" if special else "0.5"
        huge = "9" * 5000 if special else "123"
        escaped = r'"\u0041 \"quoted\" \\ path \t"' if special else '"text"'
        rows.append(
            '{"task_id":"q' + str(index) + '","task_fingerprint":"' + str(index).zfill(64) + '",'
            '"task_family":"controlled-comparison","public_task":{"schema_version":1,'
            '"task_id":"q' + str(index) + '","revision_id":"r1","serving_view_id":"' + "v" * 64 + '",'
            '"scope":' + json.dumps({"scope": "exact source " * 8 + str(index % 2)}, separators=(",", ":")) + ","
            '"context":' + escaped + ',"question":"Every original question remains present ' + str(index) + '",'
            '"answer_format":{"kind":"number","tolerance":' + number + ',"big":' + huge + '}},'
            '"answer_window":{"start":"2024-01-01T00:00:00Z","end":"2024-01-02T00:00:00Z"},'
            r'"\u0065xtra":[true,false,null,"unchanged"]}'
        )
    return '{"task_fingerprint":"candidate","subject_fingerprint":"inventory","candidate":{"kept":true},"comparisons":[' + ",".join(rows) + "]}"


class ObjectiveComparisonWireTests(unittest.TestCase):
    def test_exact_inventory_order_nested_fields_and_aliases_round_trip(self):
        original = objective_comparison_context()
        encoded = review_transport.compact_objective_context(original)
        self.assertLess(len(encoded), len(original))
        self.assertEqual(review_transport.expand_objective_context(encoded), original)
        table = json.loads(encoded)["comparisons"]
        self.assertEqual(len(table["rows"]), 32)
        self.assertTrue(any("copy_column" in column for column in table["columns"]))
        self.assertTrue(any("constant" in column for column in table["columns"]))
        self.assertTrue(any("dictionary" in column for column in table["columns"]))

    def test_original_number_spellings_large_integers_escapes_and_key_order_survive(self):
        original = objective_comparison_context(special=True)
        encoded = review_transport.compact_objective_context(original)
        self.assertNotEqual(encoded, original)
        self.assertEqual(review_transport.expand_objective_context(encoded), original)
        for token in ("-0.00e+05", "9" * 5000, r'"\u0065xtra"', r'"\u0041 \"quoted\" \\ path \t"'):
            self.assertIn(token, encoded)

    def test_huge_exponents_are_not_converted_to_nonfinite_values(self):
        original = objective_comparison_context().replace('"tolerance":0.5', '"tolerance":1e1000')
        self.assertEqual(review_transport.expand_objective_context(
            review_transport.compact_objective_context(original)), original)

    def test_duplicate_keys_or_different_layouts_keep_the_original_representation(self):
        duplicate = objective_comparison_context().replace('"task_family":', '"task_id":"duplicate","task_family":', 1)
        heterogeneous = objective_comparison_context().replace('"task_id":"q1",', '"additional":true,"task_id":"q1",', 1)
        for original in (duplicate, heterogeneous):
            with self.subTest(context=original[:60]):
                self.assertEqual(review_transport.compact_objective_context(original), original)

    def test_nonbeneficial_or_empty_comparisons_are_not_expanded(self):
        for original in (
            '{"candidate":{},"comparisons":[]}',
            '{"candidate":{},"comparisons":[{"task_id":"one"}]}',
            '{"candidate":{},"comparisons":[{"public_task":{}}]}',
        ):
            self.assertEqual(review_transport.compact_objective_context(original), original)

    def test_all_constant_rows_are_preserved_not_deduplicated(self):
        record = '{"task_id":"same","public_task":{"question":"' + "keep this exact question " * 15 + '"}}'
        original = '{"candidate":{},"comparisons":[' + ",".join([record] * 24) + "]}"
        encoded = review_transport.compact_objective_context(original)
        self.assertEqual(review_transport.expand_objective_context(encoded), original)
        self.assertEqual(json.loads(encoded)["comparisons"]["rows"], [[]] * 24)

    def test_bad_inventory_counts_indices_cell_shapes_and_guidance_are_rejected(self):
        encoded = review_transport.compact_objective_context(objective_comparison_context())
        for kind in ("count", "alias", "dictionary", "cells", "guidance"):
            altered = json.loads(encoded)
            table = altered["comparisons"]
            if kind == "count":
                table["comparison_count"] -= 1
            elif kind == "alias":
                next(c for c in table["columns"] if "copy_column" in c)["copy_column"] = len(table["columns"])
            elif kind == "dictionary":
                column = next(c for c in table["columns"] if "dictionary" in c)
                table["rows"][0][column["cell"]] = len(column["dictionary"])
            elif kind == "cells":
                table["rows"][0].append("unbound cell")
            else:
                table["guidance"] = "Discard some comparisons."
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                review_transport.expand_objective_context(json.dumps(altered, separators=(",", ":")))

    def test_invalid_json_never_becomes_a_valid_table(self):
        for text in ('{"candidate":{},"comparisons":[],}', '{"candidate":NaN,"comparisons":[]}'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                review_transport.compact_objective_context(text)


class RouterTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = AzureGenerationConfig(env_file=self.root / "not-read.env", deployment="gpt-6-sol",
                                            timeout_seconds=300, max_completion_tokens=16000, reasoning_effort="medium")
        self.base = FakeTransport([{"base": True}], self.config)
        self.review = FakeTransport([{"choices": [], "usage": {}}], self.config.model_copy(update={"timeout_seconds": 900}))
        self.client = ReviewTransportClient(self.base, self.review, policy(), (self.root,))

    def request(self, role="contract-reviewer", schema=None, folder="role", index=0):
        tools = [{"type": "function", "function": {"name": "finish", "parameters": schema or FinalReview.model_json_schema()}}]
        messages = [{"role": "user", "content": "Controlled review context."}]
        directory = self.root / folder
        directory.mkdir(exist_ok=True)
        path = directory / f"{index:04d}-request.json"
        path.write_text(json.dumps({"role": role, "messages": messages, "tools": tools}))
        return path, messages, tools

    def test_exact_recorded_review_uses_only_900_second_client_and_records_actual_config(self):
        path, messages, tools = self.request()
        response = self.client.complete(messages, tools)
        self.assertEqual(len(self.review.contexts), 1)
        self.assertEqual(self.base.contexts, [])
        self.assertEqual(self.client.config.timeout_seconds, 300)
        receipt = json.loads(path.with_name("0000-transport.json").read_bytes())
        self.assertEqual(receipt["original_config"]["timeout_seconds"], 300)
        self.assertEqual(receipt["effective_config"]["timeout_seconds"], 900)
        self.assertEqual(receipt["request_sha256"], file_sha256(path))
        self.assertEqual(response["review_transport"]["timeout_seconds"], 900)
        self.assertNotIn("env_file", receipt["original_config"])

    def test_student_schema_uses_unchanged_original_client_without_review_metadata(self):
        _, messages, tools = self.request(role="native-blind", schema=BlindSolution.model_json_schema())
        response = self.client.complete(messages, tools)
        self.assertEqual(response["choices"][0]["message"]["tool_calls"], [{"base": True}])
        self.assertNotIn("review_transport", response)
        self.assertEqual(len(self.base.contexts), 1)
        self.assertEqual(self.review.contexts, [])
        self.assertFalse(list(self.root.rglob("*-transport.json")))

    def objective_request(self, messages):
        path, _, tools = self.request(role="objective-reviewer", schema=ObjectiveReview.model_json_schema())
        path.write_text(json.dumps({"role": "objective-reviewer", "messages": messages, "tools": tools}))
        return path, messages, tools

    def test_objective_column_wire_records_full_population_and_preserves_every_original_message(self):
        original_context = objective_comparison_context()
        messages = [
            {"role": "system", "content": "Compare the complete inventory without changing the instructions."},
            {"role": "user", "content": original_context},
            {"role": "assistant", "responses_output": [{"type": "reasoning", "encrypted_content": "opaque"}]},
            {"role": "tool", "tool_call_id": "sql", "content": '{"rows":[[1," unchanged "]]}'},
        ]
        before = deepcopy(messages)
        path, messages, tools = self.objective_request(messages)
        request_sha = file_sha256(path)
        response = self.client.complete(messages, tools)
        wire = json.loads((path.parent / "0000-wire.json").read_bytes())
        self.assertEqual(wire["encoding"], review_transport.OBJECTIVE_COMPARISON_WIRE_VERSION)
        self.assertEqual(wire["comparison_count"], 32)
        self.assertTrue(wire["comparison_json_tokens_reconstruct_exactly"])
        self.assertNotIn("json_token_bytes_preserved", wire)
        self.assertEqual(review_transport.expand_objective_context(wire["messages"][1]["content"]), original_context)
        self.assertEqual(wire["messages"][0], before[0])
        self.assertEqual(wire["messages"][2:], before[2:])
        self.assertEqual(messages, before)
        self.assertEqual(file_sha256(path), request_sha)
        self.assertEqual(wire["logical_request_sha256"], request_sha)
        self.assertEqual(wire["messages"], self.review.contexts[0])
        self.assertEqual(wire["tools"], tools)
        self.assertEqual(response["review_transport"]["wire_payload_sha256"], file_sha256(path.parent / "0000-wire.json"))
        self.assertEqual(self.base.contexts, [])

    def test_objective_column_encoding_never_rewrites_tool_data_or_other_roles(self):
        context = objective_comparison_context()
        messages = [{"role": "system", "content": "unchanged"}, {"role": "user", "content": context},
                    {"role": "tool", "tool_call_id": "sql", "content": context}]
        projected = review_transport.compact_objective_messages(messages)
        self.assertNotEqual(projected[1]["content"], context)
        self.assertEqual(projected[2]["content"], context)
        path, _, tools = self.request()
        path.write_text(json.dumps({"role": "contract-reviewer", "messages": messages, "tools": tools}))
        self.client.complete(messages, tools)
        self.assertEqual(self.review.contexts, [messages])
        self.assertFalse((path.parent / "0000-wire.json").exists())

    def test_objective_column_credential_retry_preserves_identical_wire_and_rate_wait_artifacts(self):
        messages = [{"role": "system", "content": "unchanged"}, {"role": "user", "content": objective_comparison_context()}]
        path, messages, tools = self.objective_request(messages)
        original = file_sha256(path)
        with patch.object(self.review, "complete", side_effect=[
            ClientAuthenticationError("private"), RetryableCompletionError("recorded rate wait", 0),
        ]) as complete, patch("time.sleep"):
            with self.assertRaises(RetryableCompletionError):
                self.client.complete(messages, tools)
        self.assertEqual(complete.call_args_list[0], complete.call_args_list[1])
        wire = json.loads((path.parent / "0000-wire.json").read_bytes())
        self.assertEqual(wire["encoding"], review_transport.OBJECTIVE_COMPARISON_WIRE_VERSION)
        self.assertEqual(file_sha256(path), original)
        self.assertFalse((path.parent / "0000-response.json").exists())

    def test_objective_compaction_preserves_string_escapes_numeric_tokens_and_key_order(self):
        text = r'''{ "text": " keep \"quoted\" \\ slash \t \u0041 ", "n": -0.00e+05, "big": 123456789012345678901234567890 }'''
        expected = r'''{"text":" keep \"quoted\" \\ slash \t \u0041 ","n":-0.00e+05,"big":123456789012345678901234567890}'''
        messages = [{"role": "user", "content": text}]
        before = deepcopy(messages)
        result = review_transport.compact_objective_messages(messages)
        self.assertEqual(result[0]["content"], expected)
        self.assertEqual(messages, before)

    def test_objective_compaction_preserves_duplicate_keys_and_large_exponents_lexically(self):
        messages = [{"role": "tool", "tool_call_id": "sql", "content": '{ "a": 1, "a": 2, "large": 1e1000 }'}]
        result = review_transport.compact_objective_messages(messages)
        self.assertEqual(result[0]["content"], '{"a":1,"a":2,"large":1e1000}')
        self.assertEqual(result[0]["tool_call_id"], "sql")

    def test_objective_compaction_keeps_system_assistant_and_plain_text_unchanged(self):
        messages = [
            {"role": "system", "content": " Keep all instructions and spacing. "},
            {"role": "assistant", "responses_output": [{"type": "reasoning", "encrypted_content": "opaque state"}]},
            {"role": "user", "content": "A plain textual context is not rewritten."},
            {"role": "tool", "tool_call_id": "sql", "content": ' { "rows": [ [ "a b" ] ], "truncated": false } '},
        ]
        result = review_transport.compact_objective_messages(messages)
        self.assertEqual(result[:3], messages[:3])
        self.assertEqual(result[3]["content"], '{"rows":[["a b"]],"truncated":false}')
        unchanged = messages[:3]
        self.assertIs(review_transport.compact_objective_messages(unchanged), unchanged)

    def test_objective_wire_is_bound_to_the_unchanged_logical_request_and_full_inventory(self):
        messages = [
            {"role": "system", "content": "Compare the complete inventory."},
            {"role": "user", "content": json.dumps({"inventory": [{"task_id": "one"}, {"task_id": "two"}]})},
            {"role": "tool", "tool_call_id": "sql", "content": json.dumps({"rows": [[1, " value "]]})},
        ]
        path, messages, tools = self.objective_request(messages)
        original = file_sha256(path)
        response = self.client.complete(messages, tools)
        wire = json.loads((path.parent / "0000-wire.json").read_bytes())
        self.assertEqual(wire["encoding"], review_transport.OBJECTIVE_WIRE_VERSION)
        self.assertTrue(wire["json_token_bytes_preserved"])
        self.assertEqual(wire["logical_request_sha256"], original)
        self.assertEqual(wire["messages"], self.review.contexts[0])
        self.assertEqual(wire["tools"], tools)
        self.assertEqual(json.loads(wire["messages"][1]["content"]), json.loads(messages[1]["content"]))
        self.assertEqual(file_sha256(path), original)
        self.assertEqual(response["review_transport"]["wire_payload_sha256"], file_sha256(path.parent / "0000-wire.json"))
        self.assertEqual(self.base.contexts, [])

    def test_objective_malformed_structured_json_fails_before_dispatch(self):
        for content in ('{"inventory": [}', '{"score": NaN}'):
            with self.subTest(content=content):
                path, messages, tools = self.objective_request([{"role": "user", "content": content}])
                with self.assertRaises(ValueError):
                    self.client.complete(messages, tools)
                self.assertEqual(self.review.contexts, [])
                for artifact in path.parent.glob("*.json"):
                    artifact.unlink()

    def test_other_reviewers_do_not_receive_objective_json_reformatting(self):
        path, _, tools = self.request()
        messages = [{"role": "user", "content": '{ "source": [ 1, 2 ] }'}]
        path.write_text(json.dumps({"role": "contract-reviewer", "messages": messages, "tools": tools}))
        self.client.complete(messages, tools)
        self.assertEqual(self.review.contexts, [messages])
        self.assertFalse((path.parent / "0000-wire.json").exists())

    def test_objective_credential_retry_preserves_identical_wire_and_original_context(self):
        path, messages, tools = self.objective_request([{"role": "user", "content": '{ "inventory": [ "one" ] }'}])
        with patch.object(self.review, "complete", side_effect=[ClientAuthenticationError("private"), {"ok": True}]) as complete, \
             patch("time.sleep"):
            result = self.client.complete(messages, tools)
        self.assertTrue(result["ok"])
        self.assertEqual(complete.call_args_list[0], complete.call_args_list[1])
        credential = json.loads((path.parent / "0000-credential-0000.json").read_bytes())
        self.assertEqual(credential["request_context_fingerprint"],
                         review_transport._digest({"messages": messages, "tools": tools}))

    def test_objective_rate_wait_preserves_actual_wire_and_logical_request(self):
        path, messages, tools = self.objective_request([{"role": "user", "content": '{ "inventory": [ "one" ] }'}])
        original = file_sha256(path)
        with patch.object(self.review, "complete", side_effect=RetryableCompletionError("rate", 5)):
            with self.assertRaises(RetryableCompletionError):
                self.client.complete(messages, tools)
        self.assertTrue((path.parent / "0000-wire.json").is_file())
        self.assertEqual(file_sha256(path), original)

    def test_unknown_role_duplicate_outstanding_context_and_terminal_role_fail_closed(self):
        path, messages, tools = self.request(role="native-blind")
        with self.assertRaisesRegex(ValueError, "nonreview"):
            self.client.complete(messages, tools)
        path.unlink()
        path, messages, tools = self.request()
        self.request(folder="duplicate")
        with self.assertRaisesRegex(ValueError, "exactly one"):
            self.client.complete(messages, tools)
        (self.root / "duplicate/0000-request.json").unlink()
        (path.parent / "result.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "terminal"):
            self.client.complete(messages, tools)
        self.assertEqual(self.review.contexts, [])

    def test_only_latest_request_is_dispatched_during_explicit_append_only_recovery(self):
        first, messages, tools = self.request()
        newest, _, _ = self.request(index=1)
        with self.assertRaisesRegex(ValueError, "explicit audited recovery"):
            self.client.complete(messages, tools)
        (first.parent / "approved-timeout-recovery.json").write_text(json.dumps({
            "policy": policy().model_dump(mode="json"), "unanswered_request": first.name,
            "original_artifacts_sha256": {first.name: file_sha256(first)},
            "request_context_fingerprint": review_transport._digest({"messages": messages, "tools": tools}),
        }))
        self.client.complete(messages, tools)
        self.assertFalse(first.with_name("0000-transport.json").exists())
        self.assertTrue(newest.with_name("0001-transport.json").exists())

    def test_model_budget_effort_or_base_timeout_cannot_change(self):
        for update in ({"deployment": "other-model"}, {"max_completion_tokens": 32000},
                       {"reasoning_effort": "high"}, {"timeout_seconds": 1200}):
            with self.assertRaises(ValueError):
                ReviewTransportClient(self.base, FakeTransport([], self.review.config.model_copy(update=update)),
                                      policy(), (self.root,))
        with self.assertRaises(ValueError):
            ReviewTransportClient(self.base, self.review, policy().model_copy(update={"implementation_sha256": "0" * 64}), (self.root,))


class CredentialBoundaryTests(unittest.TestCase):
    setUp = RouterTests.setUp
    request = RouterTests.request

    def test_native_credential_retry_preserves_exact_request_and_original_settings(self):
        path, messages, tools = self.request(role="native-blind", schema=BlindSolution.model_json_schema())
        before = file_sha256(path)
        with patch.object(self.base, "complete", side_effect=[
            ClientAuthenticationError("private credential detail"), {"ok": True},
        ]) as complete, patch("time.sleep"):
            self.assertEqual(self.client.complete(messages, tools), {"ok": True})
        self.assertEqual(complete.call_count, 2)
        self.assertEqual(complete.call_args_list[0], complete.call_args_list[1])
        event_path = path.with_name("0000-credential-0000.json")
        event = json.loads(event_path.read_bytes())
        self.assertEqual(event["role"], "native-blind")
        self.assertEqual(event["request_sha256"], before)
        self.assertIs(event["model_request_sent"], False)
        self.assertIs(event["same_context_retry"], True)
        self.assertEqual(event["effective_config"]["timeout_seconds"], 300)
        self.assertNotIn("private credential detail", event_path.read_text())
        self.assertEqual(file_sha256(path), before)
        self.assertFalse(path.with_name("0000-error.json").exists())
        self.assertFalse(path.with_name("0000-transport.json").exists())

    def test_repeated_credential_failure_is_explicitly_bound_and_bounded(self):
        path, messages, tools = self.request()
        with patch.object(self.review, "complete", side_effect=ClientAuthenticationError("private detail")) as complete, (
            patch("time.sleep")
        ):
            with self.assertRaisesRegex(RuntimeError, "credential acquisition failed before model dispatch"):
                self.client.complete(messages, tools)
        self.assertEqual(complete.call_count, 2)
        error = json.loads(path.with_name("0000-error.json").read_bytes())
        self.assertEqual((error["role"], error["call_index"], error["error_type"]),
                         ("contract-reviewer", 0, "ClientAuthenticationError"))
        self.assertIs(error["model_request_sent"], False)
        self.assertEqual(error["request_sha256"], file_sha256(path))
        self.assertEqual(len(list(path.parent.glob("*-credential-*.json"))), 2)
        self.assertEqual(json.loads(path.with_name("0000-credential-0001.json").read_bytes())["effective_config"]["timeout_seconds"], 900)
        self.assertNotIn("private detail", path.with_name("0000-error.json").read_text())

    def test_unknown_or_post_dispatch_error_never_gets_credential_retry(self):
        path, messages, tools = self.request(role="native-blind", schema=BlindSolution.model_json_schema())
        with patch.object(self.base, "complete", side_effect=TimeoutError("unknown dispatch")) as complete:
            with self.assertRaises(TimeoutError):
                self.client.complete(messages, tools)
        self.assertEqual(complete.call_count, 1)
        self.assertFalse(list(path.parent.glob("*-credential-*.json")))
        self.assertFalse(path.with_name("0000-error.json").exists())

    def test_ambiguous_or_terminal_native_request_cannot_authorize_credential_retry(self):
        path, messages, tools = self.request(role="native-blind", schema=BlindSolution.model_json_schema())
        duplicate, _, _ = self.request(role="native-blind", schema=BlindSolution.model_json_schema(), folder="duplicate")
        with patch.object(self.base, "complete", side_effect=ClientAuthenticationError("fixture")) as complete:
            with self.assertRaisesRegex(ValueError, "exactly one"):
                self.client.complete(messages, tools)
        self.assertEqual(complete.call_count, 1)
        duplicate.unlink()
        (path.parent / "complete.json").write_text("{}")
        with patch.object(self.base, "complete", side_effect=ClientAuthenticationError("fixture")) as complete:
            with self.assertRaisesRegex(ValueError, "terminal"):
                self.client.complete(messages, tools)
        self.assertEqual(complete.call_count, 1)


class PreRequestRecoveryTests(unittest.TestCase):
    setUp = RouterTests.setUp
    request = RouterTests.request

    def prepared(self):
        messages = [{"role": "system", "content": "Controlled initial role."}, {"role": "user", "content": "{}"}]
        for index in range(2):
            path, _, tools = self.request(index=index)
            value = json.loads(path.read_bytes())
            value["messages"] = messages
            path.write_text(json.dumps(value))
            error = {
                "status": "error", "role": value["role"], "call_index": index, "model_request_sent": False,
                "error_type": "ClientAuthenticationError" if index == 0 else "ValueError",
                "failure_stage": "credential_preflight" if index == 0 else "review_transport_guard",
                "detail": "Controlled preflight failure." if index == 0
                else "an unanswered prior review requires explicit audited recovery",
            }
            path.with_name(f"{index:04d}-error.json").write_text(json.dumps(error))
        directory = path.parent
        evidence = self.root / "failure-evidence.json"
        evidence.write_text('{"controlled_fixture":true,"network_calls":0}')
        self.approval = self.root / "approval.json"
        self.approval.write_text(PreRequestRecoveryApproval(
            plan_fingerprint=self.client.policy.plan_fingerprint, role_directory=str(directory),
            requests_sha256={p.name: file_sha256(p) for p in directory.glob("*-request.json")},
            evidence_sha256={evidence.name: file_sha256(evidence)}, reason="Audited synthetic pre-send boundaries.",
            approved=True,
        ).model_dump_json())
        return directory, messages, tools

    def authorize(self, directory):
        return authorize_pre_request_recovery(run=self.root, directory=directory, policy=self.client.policy,
                                              approval_path=self.approval)

    def test_two_known_unsent_calls_continue_once_without_fabricated_responses(self):
        directory, messages, tools = self.prepared()
        original = {p: p.read_bytes() for p in directory.glob("*.json")}
        self.authorize(directory)
        path, _, _ = self.request(index=2)
        value = json.loads(path.read_bytes())
        value["messages"] = messages
        path.write_text(json.dumps(value))
        self.client.complete(messages, tools)
        self.assertEqual(len(self.review.contexts), 1)
        self.assertEqual({p: p.read_bytes() for p in original}, original)
        self.assertFalse((directory / "0000-response.json").exists())
        self.assertFalse((directory / "0001-response.json").exists())
        self.assertTrue((directory / "0002-transport.json").exists())
        with self.assertRaisesRegex(ValueError, "already used"):
            self.authorize(directory)
        path, _, _ = self.request(index=3)
        value = json.loads(path.read_bytes())
        value["messages"] = messages
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "outstanding request boundary"):
            self.client.complete(messages, tools)
        self.assertEqual(len(self.review.contexts), 1)

    def test_unknown_send_state_and_changed_context_fail_closed(self):
        directory, _, _ = self.prepared()
        path = directory / "0000-error.json"
        error = json.loads(path.read_bytes())
        for sent in (None, True, 0):
            path.write_text(json.dumps({**error, "model_request_sent": sent}))
            with self.assertRaisesRegex(ValueError, "unknown or post-send"):
                self.authorize(directory)
        path.write_text(json.dumps(error))
        request = directory / "0001-request.json"
        value = json.loads(request.read_bytes())
        value["messages"][1]["content"] = "changed"
        request.write_text(json.dumps(value))
        approval = json.loads(self.approval.read_bytes())
        approval["requests_sha256"][request.name] = file_sha256(request)
        self.approval.write_text(json.dumps(approval))
        with self.assertRaisesRegex(ValueError, "context or tools changed"):
            self.authorize(directory)
        self.assertEqual(self.review.contexts, [])

    def test_received_completion_or_altered_failure_evidence_cannot_be_retried(self):
        directory, _, _ = self.prepared()
        (directory / "0000-response.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "received or completed"):
            self.authorize(directory)
        (directory / "0000-response.json").unlink()
        (self.root / "failure-evidence.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "failure evidence changed"):
            self.authorize(directory)

    def test_current_policy_loader_preserves_original_policy_and_verifies_amendments(self):
        original = nonstudent_policy().model_copy(update={"implementation_sha256": "f" * 64})
        path = self.root / "review-transport-policy02.json"
        path.write_text(original.model_dump_json())
        before = path.read_bytes()
        with self.assertRaisesRegex(ValueError, "not bound"):
            load_run_transport_policy(self.root, original.plan_fingerprint)
        current = original.model_copy(update={
            "previous_policy_fingerprint": fingerprint(original),
            "implementation_sha256": file_sha256(Path(review_transport.__file__)),
        })
        amendments = self.root / "review-transport-amendments"
        amendments.mkdir()
        (amendments / "0000.json").write_text(current.model_dump_json())
        self.assertEqual(load_run_transport_policy(self.root, original.plan_fingerprint), current)
        self.assertEqual(path.read_bytes(), before)
        (amendments / "0000.json").write_text(current.model_copy(update={"plan_fingerprint": "b" * 64}).model_dump_json())
        with self.assertRaisesRegex(ValueError, "policy chain"):
            load_run_transport_policy(self.root, original.plan_fingerprint)


class RecoveryTests(unittest.TestCase):
    setUp = robustness_tests.RobustnessFixtureTests.setUp

    def timed_out(self):
        role = self.root / "reviewer"
        subject = fingerprint(self.task.private_gold)
        context = {"task_fingerprint": fingerprint(self.task), "subject_fingerprint": subject}
        validator = _review_validator(self.task, subject, _citations(self.task))

        class TimeoutAfterQuery(ConfiguredFake):
            def complete(inner, messages, tools):
                if inner.contexts:
                    raise RuntimeError("Azure completion failed: APITimeoutError; status=None")
                return super().complete(messages, tools)

        with self.assertRaisesRegex(RuntimeError, "APITimeoutError"):
            inspected_role(TimeoutAfterQuery([call("sql", {"query": "SELECT * FROM DeviceProcessEvents"})]),
                           self.verifier, role, "contract-reviewer", "Inspect all actual source facts.",
                           context, FinalReview, validator)
        return role, validator

    def client(self, responses):
        config = AzureGenerationConfig(env_file=self.root / "unused.env", deployment="gpt-6-sol",
                                       timeout_seconds=300, max_completion_tokens=16000, reasoning_effort="medium")
        base = FakeTransport([], config)
        reviewer = FakeTransport(responses, config.model_copy(update={"timeout_seconds": 900}))
        return ReviewTransportClient(base, reviewer, policy(), (self.root,))

    def timed_out_after_waits(self):
        role = self.root / "wait-reviewer"
        subject = fingerprint(self.task.private_gold)
        context = {"task_fingerprint": fingerprint(self.task), "subject_fingerprint": subject}
        validator = _review_validator(self.task, subject, _citations(self.task))

        class WaitAndTimeout(ConfiguredFake):
            calls = 0

            def complete(inner, messages, tools):
                index = inner.calls
                inner.calls += 1
                if index in (0, 2):
                    raise RetryableCompletionError("Recorded token-rate wait.", 0)
                if index == 3:
                    raise RuntimeError("Azure completion failed: APITimeoutError; status=None")
                return super().complete(messages, tools)

        with self.assertRaisesRegex(RuntimeError, "APITimeoutError"):
            inspected_role(
                WaitAndTimeout([call("sql", {"query": "SELECT * FROM DeviceProcessEvents"})]),
                self.verifier, role, "contract-reviewer", "Inspect all actual source facts.",
                context, FinalReview, validator,
            )
        return role, validator

    def finish(self):
        review = FinalReview(task_fingerprint=fingerprint(self.task), subject_fingerprint=fingerprint(self.task.private_gold),
                             recommendation="pass", reviewer="fixture", reasons=("Source records independently inspected.",))
        return review, call("finish", review.model_dump(mode="json"))

    def test_explicit_recovery_restores_exact_context_and_source_inspections_without_replacing_failed_call(self):
        role, validator = self.timed_out()
        before = _json_hashes(role)
        last = json.loads((role / "0001-request.json").read_bytes())
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            safe_unfinished_roles(role)
        expected, response = self.finish()
        client = self.client([response])
        actual = recover_review(client=client, verifier=self.verifier, directory=role, task=self.task, validate=validator)
        self.assertEqual(actual, expected)
        self.assertFalse((role / "0001-response.json").exists())
        self.assertTrue((role / "0002-response.json").exists())
        self.assertEqual(json.loads((role / "0002-request.json").read_bytes())["messages"], last["messages"])
        self.assertEqual(client.base.contexts, [])
        self.assertEqual(len(client.reviewer.contexts), 1)
        for name, digest in before.items():
            self.assertEqual(file_sha256(role / name), digest)
        safe_unfinished_roles(role)
        with self.assertRaisesRegex(ValueError, "completed or terminal"):
            recover_review(client=client, verifier=self.verifier, directory=role, task=self.task, validate=validator)

    def test_timeout_recovery_preserves_initial_and_mid_role_rate_waits(self):
        role, validator = self.timed_out_after_waits()
        before = _json_hashes(role)
        last = json.loads((role / "0003-request.json").read_bytes())
        state = interrupted_review(role, policy())
        self.assertEqual(state["last_request"].name, "0003-request.json")
        expected, response = self.finish()
        client = self.client([response])
        self.assertEqual(
            recover_review(client=client, verifier=self.verifier, directory=role, task=self.task, validate=validator),
            expected,
        )
        self.assertEqual(json.loads((role / "0004-request.json").read_bytes())["messages"], last["messages"])
        self.assertEqual(len(client.reviewer.contexts), 1)
        self.assertEqual(client.base.contexts, [])
        for index in (0, 2, 3):
            self.assertFalse((role / f"{index:04d}-response.json").exists())
        for name, digest in before.items():
            self.assertEqual(file_sha256(role / name), digest)

    def test_timeout_recovery_rejects_malformed_or_ambiguous_retry_waits(self):
        role, _ = self.timed_out_after_waits()
        path = role / "0000-error.json"
        original = json.loads(path.read_bytes())
        for change in (
            {"status": "error"}, {"role": "native-blind"}, {"call_index": True}, {"call_index": 1},
            {"delay_seconds": True}, {"delay_seconds": -1}, {"delay_seconds": float("inf")},
            {"delay_seconds": float("nan")},
        ):
            path.write_text(json.dumps({**original, **change}))
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "unresolved"):
                interrupted_review(role, policy())
        path.write_text(json.dumps(original))
        following = role / "0001-request.json"
        data = json.loads(following.read_bytes())
        changed = json.loads(following.read_bytes())
        changed["messages"][1]["content"] = "{}"
        following.write_text(json.dumps(changed))
        with self.assertRaises(ValueError):
            interrupted_review(role, policy())
        following.write_text(json.dumps(data))
        for suffix, value in (("response", {"choices": []}), ("tool-results", [])):
            artifact = role / f"0000-{suffix}.json"
            artifact.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "unresolved"):
                interrupted_review(role, policy())
            artifact.unlink()

    def test_recovery_rejects_non_timeout_or_changed_tool_contract(self):
        role, _ = self.timed_out()
        error = role / "0001-error.json"
        original = error.read_bytes()
        error.write_text(json.dumps({"status": "error", "detail": "unknown network failure"}))
        with self.assertRaisesRegex(ValueError, "HTTP timeout"):
            interrupted_review(role, policy())
        error.write_bytes(original)
        request = role / "0001-request.json"
        data = json.loads(request.read_bytes())
        data["role"] = "native-blind"
        request.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "only an approved reviewer"):
            interrupted_review(role, policy())

    def test_accepted_finish_and_modified_history_cannot_be_retried_as_timeouts(self):
        role, _ = self.timed_out()
        request = role / "0001-request.json"
        original = request.read_bytes()
        data = json.loads(original)
        data["messages"][-1]["content"] = "{}"
        request.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "exact next request"):
            interrupted_review(role, policy())
        request.write_bytes(original)
        response = role / "0000-response.json"
        data = json.loads(response.read_bytes())
        call_id = data["choices"][0]["message"]["tool_calls"][0]["id"]
        data["choices"][0]["message"]["tool_calls"][0]["function"]["name"] = "finish"
        response.write_text(json.dumps(data))
        (role / "0000-tool-results.json").write_text(json.dumps([
            {"role": "tool", "tool_call_id": call_id, "content": json.dumps({"accepted": True})},
        ]))
        with self.assertRaisesRegex(ValueError, "accepted finish"):
            interrupted_review(role, policy())

    def test_source_validation_cannot_be_waived_by_transport_recovery(self):
        role, validator = self.timed_out()
        expected, _ = self.finish()
        invalid = expected.model_copy(update={"task_fingerprint": "f" * 64})
        client = self.client([call("finish", invalid.model_dump(mode="json")),
                              call("abstain", {"reason": "Cannot bind this result."})])
        from secgym.qagen.agentic.generation import RoleAbstained

        with self.assertRaises(RoleAbstained):
            recover_review(client=client, verifier=self.verifier, directory=role, task=self.task, validate=validator)
        self.assertFalse((role / "complete.json").exists())
        self.assertFalse((role / "result.json").exists())
        self.assertTrue((role / "abstention.json").exists())

    def test_a_second_timeout_preserves_both_unanswered_calls_and_does_not_retry_itself(self):
        role, validator = self.timed_out()
        client = self.client([])

        def fail(messages, tools):
            raise RuntimeError("Azure completion failed: APITimeoutError; status=None")

        client.reviewer.complete = fail
        with self.assertRaisesRegex(RuntimeError, "APITimeoutError"):
            recover_review(client=client, verifier=self.verifier, directory=role, task=self.task, validate=validator)
        self.assertTrue((role / "0002-transport.json").exists())
        self.assertFalse((role / "0001-response.json").exists())
        self.assertFalse((role / "0002-response.json").exists())
        with self.assertRaises(ValueError):
            recover_review(client=client, verifier=self.verifier, directory=role, task=self.task, validate=validator)
        self.assertFalse((role / "0003-request.json").exists())


class ServerErrorRecoveryTests(unittest.TestCase):
    setUp = RecoveryTests.setUp
    client = RecoveryTests.client
    finish = RecoveryTests.finish

    def interrupted(self):
        role = self.root / "reviewer"
        subject = fingerprint(self.task.private_gold)
        context = {"task_fingerprint": fingerprint(self.task), "subject_fingerprint": subject}
        validator = _review_validator(self.task, subject, _citations(self.task))
        client = self.client([call("sql", {"query": "SELECT * FROM DeviceProcessEvents"})])
        original_complete = client.reviewer.complete

        def fail_after_query(messages, tools):
            if client.reviewer.contexts:
                raise RuntimeError("Azure completion failed: InternalServerError; status=500")
            return original_complete(messages, tools)

        client.reviewer.complete = fail_after_query
        with self.assertRaisesRegex(RuntimeError, "InternalServerError"):
            inspected_role(client, self.verifier, role, "contract-reviewer", "Inspect all actual source facts.",
                           context, FinalReview, validator)
        approval = self.root / "http500-approval.json"
        approval.write_text(json.dumps({
            "policy_version": "review-http500-recovery-v1", "plan_fingerprint": policy().plan_fingerprint,
            "role_directory": str(role.resolve()), "request_sha256": file_sha256(role / "0001-request.json"),
            "error_sha256": file_sha256(role / "0001-error.json"),
            "reason": "One explicit recovery of the captured provider HTTP500; not an unsent call or timeout.",
            "approved": True,
        }))
        return role, validator, approval

    def test_explicit_server_error_recovery_preserves_exact_context_and_original_failure(self):
        role, validator, approval = self.interrupted()
        before = _json_hashes(role)
        context = json.loads((role / "0001-request.json").read_bytes())["messages"]
        with self.assertRaisesRegex(ValueError, "HTTP timeout"):
            interrupted_review(role, policy())
        expected, response = self.finish()
        client = self.client([response])
        actual = recover_review(client=client, verifier=self.verifier, directory=role, task=self.task,
                                validate=validator, server_error_approval=approval)
        self.assertEqual(actual, expected)
        self.assertEqual(json.loads((role / "0002-request.json").read_bytes())["messages"], context)
        self.assertFalse((role / "0001-response.json").exists())
        self.assertTrue((role / "approved-server-error-recovery.json").exists())
        self.assertFalse((role / "approved-timeout-recovery.json").exists())
        self.assertFalse((role / "approved-pre-request-recovery.json").exists())
        self.assertEqual(client.base.contexts, [])
        self.assertEqual(len(client.reviewer.contexts), 1)
        self.assertEqual({name: file_sha256(role / name) for name in before}, before)
        safe_unfinished_roles(role)

    def test_server_error_requires_bound_approval_and_exact_dispatched_failure(self):
        role, _, approval = self.interrupted()
        original = json.loads(approval.read_bytes())
        approval.write_text(json.dumps({**original, "plan_fingerprint": "f" * 64}))
        with self.assertRaisesRegex(ValueError, "HTTP500 approval"):
            interrupted_review(role, policy(), server_error_approval=approval)
        approval.write_text(json.dumps(original))
        error_path = role / "0001-error.json"
        error = json.loads(error_path.read_bytes())
        for update in ({"detail": "unknown network failure"}, {"model_request_sent": False},
                       {"detail": "Azure completion failed: RateLimitError; status=429"}):
            error_path.write_text(json.dumps({**error, **update}))
            approval.write_text(json.dumps({**original, "error_sha256": file_sha256(error_path)}))
            with self.assertRaisesRegex(ValueError, "recorded dispatched HTTP500"):
                interrupted_review(role, policy(), server_error_approval=approval)
        self.assertFalse((role / "0002-request.json").exists())

    def test_server_error_cannot_change_model_or_retry_a_second_failed_recovery(self):
        role, validator, approval = self.interrupted()
        client = self.client([])
        client.base.config = client.base.config.model_copy(update={"deployment": "other-model"})
        client.reviewer.config = client.reviewer.config.model_copy(update={"deployment": "other-model"})
        with self.assertRaisesRegex(ValueError, "captured model settings"):
            recover_review(client=client, verifier=self.verifier, directory=role, task=self.task,
                           validate=validator, server_error_approval=approval)
        client = self.client([])

        def fail(messages, tools):
            raise RuntimeError("Azure completion failed: InternalServerError; status=500")

        client.reviewer.complete = fail
        with self.assertRaisesRegex(RuntimeError, "InternalServerError"):
            recover_review(client=client, verifier=self.verifier, directory=role, task=self.task,
                           validate=validator, server_error_approval=approval)
        with self.assertRaises(ValueError):
            recover_review(client=client, verifier=self.verifier, directory=role, task=self.task,
                           validate=validator, server_error_approval=approval)
        self.assertTrue((role / "0002-error.json").exists())
        self.assertFalse((role / "0001-response.json").exists())
        self.assertFalse((role / "0002-response.json").exists())
        self.assertFalse((role / "0003-request.json").exists())


class ConnectionErrorRecoveryTests(unittest.TestCase):
    setUp = RecoveryTests.setUp
    client = RecoveryTests.client
    finish = RecoveryTests.finish

    def interrupted(self):
        role = self.root / "reviewer"
        subject = fingerprint(self.task.private_gold)
        context = {"task_fingerprint": fingerprint(self.task), "subject_fingerprint": subject}
        validator = _review_validator(self.task, subject, _citations(self.task))
        client = self.client([call("sql", {"query": "SELECT * FROM DeviceProcessEvents"})])
        complete = client.reviewer.complete

        def fail_after_query(messages, tools):
            if client.reviewer.contexts:
                raise RuntimeError("Azure completion failed: APIConnectionError; status=None")
            return complete(messages, tools)

        client.reviewer.complete = fail_after_query
        with self.assertRaisesRegex(RuntimeError, "APIConnectionError"):
            inspected_role(client, self.verifier, role, "contract-reviewer", "Inspect all actual source facts.",
                           context, FinalReview, validator)
        approval = self.root / "connection-approval.json"
        approval.write_text(review_transport.ConnectionErrorRecoveryApproval(
            plan_fingerprint=policy().plan_fingerprint, role_directory=str(role.resolve()),
            request_sha256=file_sha256(role / "0001-request.json"),
            error_sha256=file_sha256(role / "0001-error.json"),
            reason="Explicit nonstudent connection-error continuation; original send state remains unknown.",
            approved=True,
        ).model_dump_json())
        return role, validator, approval

    def test_connection_recovery_retains_unknown_send_state_and_exact_history(self):
        role, validator, approval = self.interrupted()
        before = _json_hashes(role)
        with self.assertRaisesRegex(ValueError, "HTTP timeout"):
            interrupted_review(role, policy())
        expected, response = self.finish()
        client = self.client([response])
        actual = recover_review(client=client, verifier=self.verifier, directory=role, task=self.task,
                                validate=validator, connection_error_approval=approval)
        self.assertEqual(actual, expected)
        certificate = json.loads((role / "approved-connection-error-recovery.json").read_bytes())
        self.assertEqual(certificate["original_request_send_state"], "unknown")
        self.assertFalse(certificate["unknown_student_recovery_authorized"])
        self.assertEqual(json.loads((role / "0002-request.json").read_bytes())["messages"],
                         json.loads((role / "0001-request.json").read_bytes())["messages"])
        self.assertFalse((role / "0001-response.json").exists())
        self.assertFalse((role / "approved-timeout-recovery.json").exists())
        self.assertFalse((role / "approved-server-error-recovery.json").exists())
        self.assertEqual({name: file_sha256(role / name) for name in before}, before)
        self.assertEqual(client.base.contexts, [])
        self.assertEqual(len(client.reviewer.contexts), 1)
        safe_unfinished_roles(role)

    def test_connection_recovery_rejects_wrong_approval_and_failure_kind(self):
        role, _, approval = self.interrupted()
        original = json.loads(approval.read_bytes())
        approval.write_text(json.dumps({**original, "plan_fingerprint": "f" * 64}))
        with self.assertRaisesRegex(ValueError, "approval does not bind"):
            interrupted_review(role, policy(), connection_error_approval=approval)
        error_path = role / "0001-error.json"
        error = json.loads(error_path.read_bytes())
        for update in (
            {"detail": "unknown network failure"}, {"model_request_sent": False},
            {"detail": "Azure completion failed: InternalServerError; status=500"},
            {"detail": "Azure completion failed: APITimeoutError; status=None"},
        ):
            error_path.write_text(json.dumps({**error, **update}))
            approval.write_text(json.dumps({**original, "error_sha256": file_sha256(error_path)}))
            with self.assertRaisesRegex(ValueError, "exact recorded transport error"):
                interrupted_review(role, policy(), connection_error_approval=approval)
        self.assertFalse((role / "0002-request.json").exists())

    def test_connection_recovery_rejects_students_completed_roles_and_two_approvals(self):
        role, _, approval = self.interrupted()
        with self.assertRaisesRegex(ValueError, "two transport-error"):
            interrupted_review(role, policy(), server_error_approval=approval, connection_error_approval=approval)
        request = role / "0001-request.json"
        value = json.loads(request.read_bytes())
        request.write_text(json.dumps({**value, "role": "native-blind"}))
        with self.assertRaisesRegex(ValueError, "only an approved reviewer"):
            interrupted_review(role, policy(), connection_error_approval=approval)
        (role / "complete.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "completed or terminal"):
            interrupted_review(role, policy(), connection_error_approval=approval)

    def test_connection_recovery_cannot_change_models_or_retry_its_own_failure(self):
        role, validator, approval = self.interrupted()
        client = self.client([])
        client.reviewer.config = client.reviewer.config.model_copy(update={"deployment": "another-model"})
        with self.assertRaisesRegex(ValueError, "captured model settings"):
            recover_review(client=client, verifier=self.verifier, directory=role, task=self.task,
                           validate=validator, connection_error_approval=approval)
        client = self.client([])

        def fail(messages, tools):
            raise RuntimeError("Azure completion failed: APIConnectionError; status=None")

        client.reviewer.complete = fail
        with self.assertRaisesRegex(RuntimeError, "APIConnectionError"):
            recover_review(client=client, verifier=self.verifier, directory=role, task=self.task,
                           validate=validator, connection_error_approval=approval)
        with self.assertRaises(ValueError):
            recover_review(client=client, verifier=self.verifier, directory=role, task=self.task,
                           validate=validator, connection_error_approval=approval)
        self.assertTrue((role / "0002-error.json").exists())
        self.assertFalse((role / "0001-response.json").exists())
        self.assertFalse((role / "0002-response.json").exists())
        self.assertFalse((role / "0003-request.json").exists())


class RateWaitRecoveryTests(unittest.TestCase):
    setUp = RecoveryTests.setUp
    client = RecoveryTests.client
    finish = RecoveryTests.finish

    def interrupted(self):
        role = self.root / "reviewer"
        subject = fingerprint(self.task.private_gold)
        context = {"task_fingerprint": fingerprint(self.task), "subject_fingerprint": subject}
        validator = _review_validator(self.task, subject, _citations(self.task))
        client = self.client([call("sql", {"query": "SELECT * FROM DeviceProcessEvents"})])
        complete = client.reviewer.complete

        def wait_after_query(messages, tools):
            if client.reviewer.contexts:
                raise RetryableCompletionError("Recorded token-rate wait.", 0)
            return complete(messages, tools)

        client.reviewer.complete = wait_after_query
        with patch("secgym.qagen.agentic.generation.time.sleep", side_effect=InterruptedError("drained")):
            with self.assertRaisesRegex(InterruptedError, "drained"):
                inspected_role(client, self.verifier, role, "contract-reviewer", "Inspect all actual source facts.",
                               context, FinalReview, validator)
        approval = self.root / "rate-wait-approval.json"
        approval.write_text(review_transport.RateWaitRecoveryApproval(
            plan_fingerprint=policy().plan_fingerprint, role_directory=str(role.resolve()),
            request_sha256=file_sha256(role / "0001-request.json"),
            error_sha256=file_sha256(role / "0001-error.json"),
            reason="Resume the exact recorded nonstudent rate-wait boundary after draining ownership.",
            approved=True,
        ).model_dump_json())
        return role, validator, approval

    def test_explicit_rate_wait_recovery_preserves_history_inspections_and_logical_context(self):
        role, validator, approval = self.interrupted()
        before = _json_hashes(role)
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            safe_unfinished_roles(role)
        with self.assertRaisesRegex(ValueError, "HTTP timeout"):
            interrupted_review(role, policy())
        expected, response = self.finish()
        client = self.client([response])
        self.assertEqual(recover_review(
            client=client, verifier=self.verifier, directory=role, task=self.task,
            validate=validator, rate_wait_approval=approval,
        ), expected)
        self.assertEqual({name: file_sha256(role / name) for name in before}, before)
        self.assertEqual(json.loads((role / "0002-request.json").read_bytes()),
                         json.loads((role / "0001-request.json").read_bytes()))
        certificate = json.loads((role / "approved-rate-wait-recovery.json").read_bytes())
        self.assertEqual(certificate["failure_kind"], "recorded_retry_wait_without_completion")
        self.assertFalse((role / "0001-response.json").exists())
        self.assertEqual(client.base.contexts, [])
        self.assertEqual(len(client.reviewer.contexts), 1)
        safe_unfinished_roles(role)

    def test_rate_wait_recovery_rejects_bad_approval_and_ambiguous_boundaries(self):
        role, _, approval = self.interrupted()
        original = json.loads(approval.read_bytes())
        approval.write_text(json.dumps({**original, "request_sha256": "f" * 64}))
        with self.assertRaisesRegex(ValueError, "approval does not bind"):
            interrupted_review(role, policy(), rate_wait_approval=approval)
        error_path = role / "0001-error.json"
        error = json.loads(error_path.read_bytes())
        for update in ({"status": "error"}, {"role": "native-blind"}, {"call_index": True},
                       {"delay_seconds": -1}, {"delay_seconds": float("inf")}, {"delay_seconds": True}):
            error_path.write_text(json.dumps({**error, **update}))
            approval.write_text(json.dumps({**original, "error_sha256": file_sha256(error_path)}))
            with self.assertRaisesRegex(ValueError, "exact recorded finite retry_wait"):
                interrupted_review(role, policy(), rate_wait_approval=approval)
        self.assertFalse((role / "0002-request.json").exists())

    def test_rate_wait_recovery_rejects_changed_settings_dispatch_and_competing_approval(self):
        role, validator, approval = self.interrupted()
        client = self.client([])
        client.reviewer.config = client.reviewer.config.model_copy(update={"deployment": "another-model"})
        with self.assertRaisesRegex(ValueError, "captured model settings"):
            recover_review(client=client, verifier=self.verifier, directory=role, task=self.task,
                           validate=validator, rate_wait_approval=approval)
        with self.assertRaisesRegex(ValueError, "two transport-error"):
            interrupted_review(role, policy(), rate_wait_approval=approval, connection_error_approval=approval)
        path = role / "0001-transport.json"
        data = json.loads(path.read_bytes())
        path.write_text(json.dumps({**data, "request_sha256": "f" * 64}))
        with self.assertRaisesRegex(ValueError, "exact recorded transport dispatch"):
            interrupted_review(role, policy(), rate_wait_approval=approval)
        self.assertFalse((role / "approved-rate-wait-recovery.json").exists())

    def test_rate_wait_recovery_rejects_students_received_completions_and_completed_roles(self):
        role, _, approval = self.interrupted()
        path = role / "0001-request.json"
        original = path.read_bytes()
        path.write_text(json.dumps({**json.loads(original), "role": "native-blind"}))
        with self.assertRaisesRegex(ValueError, "only an approved reviewer"):
            interrupted_review(role, policy(), rate_wait_approval=approval)
        path.write_bytes(original)
        (role / "0001-response.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "not a received completion"):
            interrupted_review(role, policy(), rate_wait_approval=approval)
        (role / "complete.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "completed or terminal"):
            interrupted_review(role, policy(), rate_wait_approval=approval)


class QualityRecoveryTests(unittest.TestCase):
    setUp = quality_tests.QualityTests.setUp
    compile = quality_tests.QualityTests.compile

    def test_source_quality_keeps_its_original_audit_and_validators_during_http_recovery(self):
        from secgym.qagen.agentic.quality import audit_source_quality, assessment_passes, run_quality_gate

        task = self.compile()
        output = self.root / "quality"

        class TimeoutAfterQuery(ConfiguredFake):
            def complete(inner, messages, tools):
                if inner.contexts:
                    raise RuntimeError("Azure completion failed: APITimeoutError; status=None")
                return super().complete(messages, tools)

        with self.assertRaisesRegex(RuntimeError, "APITimeoutError"):
            run_quality_gate(client=TimeoutAfterQuery([call("sql", {"query": "SELECT * FROM DeviceProcessEvents"})]),
                             task=task, verifier=self.verifier, serving_bundle=self.serving, output=output,
                             instructions="Inspect all source facts.", review_context={})
        audit = audit_source_quality(task, self.verifier, self.serving)
        expected = quality_tests.assessment(audit)
        config = AzureGenerationConfig(env_file=self.root / "unused.env", deployment="gpt-6-sol",
                                       timeout_seconds=300, max_completion_tokens=16000, reasoning_effort="medium")
        client = ReviewTransportClient(FakeTransport([], config),
                                       FakeTransport([call("finish", expected.model_dump(mode="json"))],
                                                     config.model_copy(update={"timeout_seconds": 900})),
                                       policy(), (output,))

        def validate(value, tools):
            if not assessment_passes(task, audit, value) or set(audit.required_review_citations) - tools.observed:
                raise ValueError("the actual source-quality audit and required inspections remain mandatory")

        before = file_sha256(output / "audit.json")
        recover_review(client=client, verifier=self.verifier, directory=output / "reviewer", task=task, validate=validate)
        gate, review = run_quality_gate(client=client, task=task, verifier=self.verifier, serving_bundle=self.serving,
                                       output=output, instructions="Inspect all source facts.", review_context={}, resume=True)
        self.assertEqual(gate["status"], "pass")
        self.assertEqual(review, expected.review)
        self.assertEqual(file_sha256(output / "audit.json"), before)
        self.assertEqual(len(client.reviewer.contexts), 1)
        self.assertEqual(client.base.contexts, [])
        self.assertIn("0002-transport.json", gate["review_artifacts_sha256"])


class NonStudentRoutingTests(unittest.TestCase):
    setUp = RouterTests.setUp
    request = RouterTests.request

    def test_v2_extends_every_declared_author_role_without_changing_student_routes(self):
        for role, schema in AUTHOR_ROLES.items():
            override = FakeTransport([{"author": role}], self.config.model_copy(update={"timeout_seconds": 900}))
            client = ReviewTransportClient(FakeTransport([], self.config), override, nonstudent_policy(), (self.root,))
            path, messages, tools = self.request(role=role, schema=schema.model_json_schema(), folder=role)
            result = client.complete(messages, tools)
            path.with_name("0000-response.json").write_text(json.dumps(result))
            self.assertEqual(result["qa_transport"]["timeout_seconds"], 900)
            self.assertEqual(len(override.contexts), 1)
            self.assertEqual(client.base.contexts, [])
            receipt = json.loads(path.with_name("0000-transport.json").read_bytes())
            self.assertEqual(receipt["policy"]["policy_version"], "nonstudent-http-override-v2")
            self.assertEqual(receipt["original_config"]["max_completion_tokens"], receipt["effective_config"]["max_completion_tokens"])
        for role in ("blind", "native-blind"):
            base = FakeTransport([{"student": role}], self.config)
            client = ReviewTransportClient(base, FakeTransport([], self.review.config), nonstudent_policy(), (self.root,))
            _, messages, tools = self.request(role=role, schema=BlindSolution.model_json_schema(), folder=role)
            result = client.complete(messages, tools)
            self.assertNotIn("qa_transport", result)
            self.assertEqual(len(base.contexts), 1)
            self.assertEqual(client.reviewer.contexts, [])

    def test_v1_does_not_silently_adopt_the_new_author_scope(self):
        role, schema = next(iter(AUTHOR_ROLES.items()))
        path, messages, tools = self.request(role=role, schema=schema.model_json_schema())
        self.client.complete(messages, tools)
        self.assertEqual(len(self.base.contexts), 1)
        self.assertEqual(self.review.contexts, [])
        self.assertFalse(path.with_name("0000-transport.json").exists())

    def test_execution_policy_transition_preserves_exact_original_policy_and_binding(self):
        old = policy()
        execution = {"plan_fingerprint": old.plan_fingerprint, "task_fingerprint": "b" * 64,
                     "policy_fingerprint": fingerprint(old), "implementation_sha256": "c" * 64, "recover_role": None}
        bind_transport_execution(self.root, old, execution)
        before = {name: (self.root / name).read_bytes() for name in ("review-transport-policy.json", "review-execution-binding.json")}
        new = nonstudent_policy(old)
        upgraded = {**execution, "policy_fingerprint": fingerprint(new), "recover_role": "robustness/author"}
        bind_transport_execution(self.root, new, upgraded)
        bind_transport_execution(self.root, new, upgraded)
        self.assertEqual(len(list((self.root / "transport-executions").glob("*.json"))), 1)
        for name, value in before.items():
            self.assertEqual((self.root / name).read_bytes(), value)
        wrong = new.model_copy(update={"previous_policy_fingerprint": "f" * 64})
        with self.assertRaisesRegex(ValueError, "exact approved predecessor"):
            bind_transport_execution(self.root, wrong, upgraded)


class AuthorRecoveryTests(unittest.TestCase):
    setUp = robustness_tests.RobustnessFixtureTests.setUp
    unchanged = robustness_tests.RobustnessFixtureTests.unchanged
    representation_case = robustness_tests.RobustnessFixtureTests.representation_case

    def test_connection_recovery_requires_nonstudent_author_policy_and_retains_validation(self):
        output = self.root / "author"
        context = {"task_fingerprint": fingerprint(self.task)}
        validator = _robustness_author_validator(self.task, self.verifier, context)
        config = AzureGenerationConfig(env_file=self.root / "unused.env", deployment="gpt-6-sol",
                                       timeout_seconds=300, max_completion_tokens=16000, reasoning_effort="medium")
        original = FakeTransport([call("sql", {"query": "SELECT * FROM DeviceProcessEvents"})],
                                 config.model_copy(update={"timeout_seconds": 900}))
        complete = original.complete

        def fail_after_query(messages, tools):
            if original.contexts:
                raise RuntimeError("Azure completion failed: APIConnectionError; status=None")
            return complete(messages, tools)

        original.complete = fail_after_query
        client = ReviewTransportClient(FakeTransport([], config), original, nonstudent_policy(), (self.root,))
        with self.assertRaisesRegex(RuntimeError, "APIConnectionError"):
            inspected_role(client, self.verifier, output, "robustness-author", "Author source-backed controls.",
                           context, RobustnessPlan, validator)
        before = _json_hashes(output)
        approval = self.root / "author-connection-approval.json"
        approval.write_text(review_transport.ConnectionErrorRecoveryApproval(
            plan_fingerprint=nonstudent_policy().plan_fingerprint, role_directory=str(output.resolve()),
            request_sha256=file_sha256(output / "0001-request.json"),
            error_sha256=file_sha256(output / "0001-error.json"),
            reason="Explicit incomplete-author connection recovery, never a student retry.", approved=True,
        ).model_dump_json())
        with self.assertRaisesRegex(ValueError, "only an approved reviewer"):
            interrupted_review(output, policy(), connection_error_approval=approval)
        expected = RobustnessPlan(task_fingerprint=fingerprint(self.task), cases=(self.representation_case(),))
        recovered_client = ReviewTransportClient(
            FakeTransport([], config),
            FakeTransport([call("finish", expected.model_dump(mode="json"))],
                          config.model_copy(update={"timeout_seconds": 900})),
            nonstudent_policy(), (self.root,))
        observed = recover_review(
            client=recovered_client, verifier=self.verifier, directory=output, task=self.task,
            validate=validator, connection_error_approval=approval)
        self.assertEqual(observed, expected)
        self.assertEqual({name: file_sha256(output / name) for name in before}, before)
        self.assertFalse((output / "0001-response.json").exists())
        self.assertEqual(recovered_client.base.contexts, [])

    def test_robustness_author_recovery_keeps_original_context_and_material_plan_guards(self):
        output = self.root / "author"
        context = {"task_fingerprint": fingerprint(self.task)}
        validator = _robustness_author_validator(self.task, self.verifier, context)

        class TimeoutAfterQuery(ConfiguredFake):
            def complete(inner, messages, tools):
                if inner.contexts:
                    raise RuntimeError("Azure completion failed: APITimeoutError; status=None")
                return super().complete(messages, tools)

        with self.assertRaisesRegex(RuntimeError, "APITimeoutError"):
            inspected_role(TimeoutAfterQuery([call("sql", {"query": "SELECT * FROM DeviceProcessEvents"})]),
                           self.verifier, output, "robustness-author", "Author every source-backed control.",
                           context, RobustnessPlan, validator)
        before = _json_hashes(output)
        with self.assertRaisesRegex(ValueError, "only an approved reviewer"):
            interrupted_review(output, policy())
        plan = RobustnessPlan(task_fingerprint=fingerprint(self.task), cases=(self.representation_case(),))
        config = AzureGenerationConfig(env_file=self.root / "unused.env", deployment="gpt-6-sol",
                                       timeout_seconds=300, max_completion_tokens=16000, reasoning_effort="medium")
        client = ReviewTransportClient(FakeTransport([], config),
                                       FakeTransport([call("finish", plan.model_dump(mode="json"))],
                                                     config.model_copy(update={"timeout_seconds": 900})),
                                       nonstudent_policy(), (self.root,))
        actual = recover_review(client=client, verifier=self.verifier, directory=output, task=self.task, validate=validator)
        self.assertEqual(actual, plan)
        self.assertEqual(client.base.contexts, [])
        for name, digest in before.items():
            self.assertEqual(file_sha256(output / name), digest)
        self.assertFalse((output / "0001-response.json").exists())
        self.assertTrue((output / "0002-response.json").exists())
        with self.assertRaisesRegex(ValueError, "completed or terminal"):
            recover_review(client=client, verifier=self.verifier, directory=output, task=self.task, validate=validator)


class CanonicalWireTests(unittest.TestCase):
    setUp = RouterTests.setUp

    def bundle(self):
        values = ("true", '"true"', "1", "1.0", "null", '"hello"', '"2024-06-20T09:00:00Z"')
        facts = tuple(CanonicalSourceFact(
            snapshot_id="snapshot-one", subject_observation_id=f"observation-{subject}", table="DeviceEvents",
            column=f"Field{index}", json_path=(("items", index) if index % 2 else None),
            value_json=value, lineage="behavior" if subject else "context",
            source_times=({"column": "Timestamp", "value_json": '"2024-06-20T09:00:00Z"'},),
        ) for index, value in enumerate(values) for subject in range(3))
        return CanonicalFactBundle(
            task_fingerprint="a" * 64, snapshot_id="snapshot-one", serving_view_id="serving-one",
            graph_version="graph-one", proposal_fingerprint="b" * 64, facts=facts,
            claims=({"claim_id": "final", "fact_ids": tuple(f.fact_id for f in reversed(facts))},
                    {"claim_id": "checkpoint", "fact_ids": (facts[3].fact_id, facts[1].fact_id)}),
            limitations=("Source coverage is not acquisition completeness.",),
        )

    def context(self):
        bundle = self.bundle()
        return {"facts": bundle.model_dump(mode="json"), "bundle_fingerprint": fingerprint(bundle),
                "public_task": {"question": "Original question"}, "evidence": ["original"],
                "claims": ["unchanged"], "proposal": {"unchanged": True}}

    def messages(self):
        return [{"role": "system", "content": "Original reviewer instructions."},
                {"role": "user", "content": json.dumps(self.context())},
                {"role": "tool", "content": '{"source":"unmodified"}', "tool_call_id": "original-call"}]

    def request(self, messages=None):
        messages = messages or self.messages()
        tools = [{"type": "function", "function": {"name": "finish", "parameters": CanonicalFactReview.model_json_schema()}}]
        path = self.root / "0000-request.json"
        path.write_text(json.dumps({"role": "fact-reviewer", "messages": messages, "tools": tools}))
        return path, messages, tools

    def test_round_trip_preserves_values_identities_times_claim_order_and_limitations(self):
        original = self.bundle()
        encoded = review_transport.compact_fact_bundle(original)
        wire = json.loads(json.dumps(encoded))
        restored = review_transport.expand_fact_bundle(wire)
        self.assertEqual(restored.model_dump_json(), original.model_dump_json())
        self.assertEqual(fingerprint(restored), fingerprint(original))
        self.assertEqual([fact.fact_id for fact in restored.facts], [fact.fact_id for fact in original.facts])
        self.assertLess(len(json.dumps(encoded)), len(original.model_dump_json()))
        self.assertEqual(len(encoded["groups"]), 3)

    def test_missing_duplicate_boolean_and_out_of_range_indices_fail_closed(self):
        original = review_transport.compact_fact_bundle(self.bundle())
        for index in (True, -1, original["fact_count"], original["groups"][0]["rows"][1][0]):
            changed = deepcopy(original)
            changed["groups"][0]["rows"][0][0] = index
            with self.subTest(index=index), self.assertRaisesRegex(ValueError, "index"):
                review_transport.expand_fact_bundle(changed)
        changed = deepcopy(original)
        changed["groups"][0]["rows"].pop()
        with self.assertRaisesRegex(ValueError, "omitted"):
            review_transport.expand_fact_bundle(changed)

    def test_claim_membership_cannot_be_missing_duplicated_or_invalid(self):
        original = review_transport.compact_fact_bundle(self.bundle())
        for indices in ([True], [-1], [original["fact_count"]], [0, 0], []):
            changed = deepcopy(original)
            changed["claims"][0]["fact_indices"] = indices
            with self.subTest(indices=indices), self.assertRaises(ValueError):
                review_transport.expand_fact_bundle(changed)

    def test_changed_defaults_columns_groups_and_extra_header_are_rejected(self):
        original = review_transport.compact_fact_bundle(self.bundle())
        mutations = [
            {"encoding": "unknown"}, {"fact_count": True}, {"fact_columns": ["value_json"]},
            {"fact_defaults": {}}, {"extra": True},
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, "header"):
                review_transport.expand_fact_bundle({**original, **mutation})
        changed = deepcopy(original)
        changed["groups"][0]["shared"]["invented"] = True
        with self.assertRaisesRegex(ValueError, "group"):
            review_transport.expand_fact_bundle(changed)

    def test_projection_preserves_every_other_context_field_and_all_later_messages(self):
        messages = self.messages()
        before = deepcopy(messages)
        projected = review_transport.compact_fact_review_messages(messages)
        original = json.loads(messages[1]["content"])
        physical = json.loads(projected[1]["content"])
        self.assertEqual(messages, before)
        self.assertEqual(projected[2:], messages[2:])
        self.assertTrue(projected[0]["content"].startswith(messages[0]["content"]))
        self.assertIn("Independently inspect all selected", projected[0]["content"])
        self.assertEqual({k: v for k, v in physical.items() if k != "facts"},
                         {k: v for k, v in original.items() if k != "facts"})
        self.assertEqual(review_transport.expand_fact_bundle(physical["facts"]).model_dump(mode="json"), original["facts"])

    def test_bundle_mismatch_and_lossy_encoder_are_rejected_before_dispatch(self):
        messages = self.messages()
        context = json.loads(messages[1]["content"])
        context["bundle_fingerprint"] = "0" * 64
        messages[1]["content"] = json.dumps(context)
        _, messages, tools = self.request(messages)
        with self.assertRaisesRegex(ValueError, "original bundle"):
            self.client.complete(messages, tools)
        self.assertEqual(self.review.contexts, [])
        encoded = review_transport.compact_fact_bundle(self.bundle())
        encoded["metadata"]["limitations"] = ["Changed limitation"]
        with patch.object(review_transport, "compact_fact_bundle", return_value=encoded):
            with self.assertRaisesRegex(ValueError, "not lossless"):
                review_transport.compact_fact_review_messages(self.messages())

    def test_actual_wire_payload_is_immutable_recorded_and_bound_to_logical_request(self):
        path, messages, tools = self.request()
        original = file_sha256(path)
        response = self.client.complete(messages, tools)
        wire = json.loads((self.root / "0000-wire.json").read_bytes())
        self.assertEqual(wire["logical_request_sha256"], original)
        self.assertEqual(wire["messages"], self.review.contexts[0])
        self.assertEqual(wire["tools"], tools)
        self.assertEqual(wire["original_bundle_fingerprint"], self.context()["bundle_fingerprint"])
        self.assertEqual(response["review_transport"]["wire_payload_sha256"], file_sha256(self.root / "0000-wire.json"))
        self.assertEqual(file_sha256(path), original)
        self.assertEqual(self.base.contexts, [])

    def test_credential_retry_uses_identical_wire_and_journals_original_logical_boundary(self):
        path, messages, tools = self.request()
        with patch.object(self.review, "complete", side_effect=[ClientAuthenticationError("private"), {"ok": True}]) as complete, \
             patch("time.sleep"):
            result = self.client.complete(messages, tools)
        self.assertTrue(result["ok"])
        first, second = complete.call_args_list
        self.assertEqual(first, second)
        self.assertEqual(first.args[0], json.loads((self.root / "0000-wire.json").read_bytes())["messages"])
        credential = json.loads((self.root / "0000-credential-0000.json").read_bytes())
        self.assertEqual(credential["request_sha256"], file_sha256(path))
        self.assertEqual(credential["request_context_fingerprint"],
                         review_transport._digest({"messages": messages, "tools": tools}))

    def test_throttled_dispatch_still_preserves_actual_wire(self):
        _, messages, tools = self.request()
        with patch.object(self.review, "complete", side_effect=RetryableCompletionError("rate", 5)):
            with self.assertRaises(RetryableCompletionError):
                self.client.complete(messages, tools)
        self.assertTrue((self.root / "0000-wire.json").exists())
        self.assertTrue((self.root / "0000-transport.json").exists())

    def test_connection_recovery_keeps_logical_context_wire_and_original_validation(self):
        from secgym.qagen.agentic.generation import run_role
        from secgym.qagen.agentic.review_transport import ConnectionErrorRecoveryApproval

        class NoSourceCalls:
            def schemas(self):
                return []

            def dispatch(self, name, arguments):
                raise AssertionError("This nonpassing test review cannot execute source tools")

        source_tools = NoSourceCalls()
        role = self.root / "canonical"
        with patch.object(self.review, "complete", side_effect=RuntimeError(
            "Azure completion failed: APIConnectionError; status=None",
        )):
            with self.assertRaisesRegex(RuntimeError, "APIConnectionError"):
                run_role(self.client, source_tools, "fact-reviewer", "Inspect independently.",
                         self.context(), CanonicalFactReview, role)
        original = _json_hashes(role)
        approval = self.root / "approval.json"
        approval.write_text(ConnectionErrorRecoveryApproval(
            plan_fingerprint=self.client.policy.plan_fingerprint, role_directory=str(role),
            request_sha256=file_sha256(role / "0000-request.json"),
            error_sha256=file_sha256(role / "0000-error.json"), approved=True,
            reason="One explicit nonstudent recovery; original send remains unknown.",
        ).model_dump_json())
        expected = CanonicalFactReview(
            bundle_fingerprint=fingerprint(self.bundle()), recommendation="revise",
            source_properties_relevant=False, subjects_roles_times_preserved=False,
            claim_coverage_complete=False, no_value_only_merging=False, reasons=("Requires independent source inspection.",),
        )
        self.review.responses = iter([call("finish", expected.model_dump(mode="json"))])
        validated = []
        result = recover_review(
            client=self.client, verifier=None, directory=role, task=self.bundle(), tools=source_tools,
            validate=lambda value, tools: validated.append((value, tools)), connection_error_approval=approval,
        )
        self.assertEqual(result, expected)
        self.assertEqual(validated, [(expected, source_tools)])
        self.assertTrue(all(file_sha256(role / name) == digest for name, digest in original.items()))
        before = json.loads((role / "0000-wire.json").read_bytes())
        after = json.loads((role / "0001-wire.json").read_bytes())
        self.assertEqual(before["messages"], after["messages"])
        self.assertEqual(before["tools"], after["tools"])
        certificate = json.loads((role / "approved-connection-error-recovery.json").read_bytes())
        self.assertEqual(certificate["original_request_send_state"], "unknown")
        self.assertFalse((role / "0000-response.json").exists())
        with self.assertRaises(ValueError):
            recover_review(client=self.client, verifier=None, directory=role, task=self.bundle(),
                           tools=source_tools, validate=lambda value, tools: None, connection_error_approval=approval)


if __name__ == "__main__":
    unittest.main()
