# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
from pathlib import Path
import tempfile
import unittest

import test_agentic_robustness as robustness_tests
import test_agentic_quality as quality_tests
from test_agentic_generation import FakeClient, call
from test_agentic_model_panel import ConfiguredFake
from secgym.qagen.agentic.azure_generation import AzureGenerationConfig
from secgym.qagen.agentic.contracts import fingerprint
from secgym.qagen.agentic.generation import BlindSolution
from secgym.qagen.agentic.ledger import file_sha256
from secgym.qagen.agentic.preproduction import safe_unfinished_roles
from secgym.qagen.agentic.preproduction_admission import FinalReview
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


if __name__ == "__main__":
    unittest.main()
