# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import httpx
from openai import AuthenticationError, InternalServerError, RateLimitError

import test_agentic_preproduction as preproduction_tests
import test_agentic_preproduction_admission as admission_tests
from test_agentic_review_transport import nonstudent_policy
from secgym.qagen.agentic.azure_generation import AzureGenerationClient, AzureGenerationConfig
from secgym.qagen.agentic.checkpoint_batches import (
    CheckpointClient, batch_directory, create_batch, load_batch_policy, reserve_drafts,
)
from secgym.qagen.agentic.contracts import fingerprint
from secgym.qagen.agentic.gateway import GatewayConfig, check_gateway_models
from secgym.qagen.agentic.generation import RetryableCompletionError, TaskDraft
from secgym.qagen.agentic.model_panel import BoundedClient, PanelProfile, immutable_json
from secgym.qagen.agentic.preproduction import configured_model_binding, task_generation_config, task_model_binding
from secgym.qagen.agentic.preproduction_admission import admitted_receipts, record_admission


def gateway():
    return GatewayConfig(base_url="http://127.0.0.1:41417/v1", version="2.9.3", image_sha256="a" * 64)


class GatewayClientTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.env = Path(self.temporary.name) / "gateway.env"
        self.env.write_text("SECRL_GATEWAY_API_KEY=synthetic-local-test-key\n")
        self.config = AzureGenerationConfig(
            env_file=self.env, deployment="gpt-6-sol", timeout_seconds=300,
            max_completion_tokens=16000, reasoning_effort="medium", gateway=gateway(),
        )

    def test_gateway_opt_in_never_uses_azure_credentials_or_ambient_endpoint(self):
        with patch("openai.OpenAI") as sdk, patch("azure.identity.AzureCliCredential") as credential, \
             patch.dict("os.environ", {"OPENAI_BASE_URL": "https://must-not-use.invalid",
                                      "AZURE_OPENAI_API_KEY": "unrelated-fixture-key"}):
            client = AzureGenerationClient(self.config)
            sdk.assert_called_once_with(base_url=gateway().base_url, api_key="synthetic-local-test-key",
                                        timeout=300, max_retries=0)
            credential.assert_not_called()
            client.close()
            sdk.return_value.close.assert_called_once()
        self.assertNotIn("synthetic-local-test-key", self.config.model_dump_json())

    def test_missing_gateway_key_fails_without_azure_fallback(self):
        self.env.write_text("AZUREAI_OPENAI_BASE_URL=https://fixture.invalid\n")
        with patch("openai.OpenAI") as sdk, patch("azure.identity.AzureCliCredential") as credential:
            with self.assertRaisesRegex(ValueError, "SECRL_GATEWAY_API_KEY"):
                AzureGenerationClient(self.config)
            sdk.assert_not_called()
            credential.assert_not_called()

    def test_legacy_config_serialization_has_no_new_fields(self):
        config = self.config.model_copy(update={"gateway": None})
        expected = {
            "env_file": str(self.env), "deployment": "gpt-6-sol", "timeout_seconds": 300,
            "max_completion_tokens": 16000, "reasoning_effort": "medium",
        }
        self.assertEqual(config.model_dump(mode="json"), expected)
        self.assertEqual(AzureGenerationConfig.model_validate_json(json.dumps(expected)), config)

    def test_invalid_remote_or_credential_bearing_endpoint_is_rejected(self):
        for url in ("http://example.test:4141/v1", "http://localhost:4141/v1", "http://127.0.0.1/v1",
                    "http://127.0.0.1:0/v1", "https://127.0.0.1:4141/v1", "http://user@127.0.0.1:4141/v1",
                    "http://127.0.0.1:4141/v1?key=x", "http://127.0.0.1:4141/v1#fragment"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                GatewayConfig.model_validate({**gateway().model_dump(), "base_url": url})

    def test_responses_options_reasoning_replay_and_transport_metadata(self):
        native = {
            "status": "completed", "model": "reported-sol", "usage": {"input_tokens": 10, "output_tokens": 2},
            "output": [{"type": "function_call", "call_id": "call-2", "id": "fc-2",
                        "name": "finish", "arguments": "{}"}],
        }
        with patch("openai.OpenAI") as sdk:
            sdk.return_value.responses.create.return_value.model_dump.return_value = native
            client = AzureGenerationClient(self.config)
            result = client.complete([
                {"role": "user", "content": "Synthetic only."},
                {"role": "assistant", "responses_output": [
                    {"type": "reasoning", "id": "rs-1", "summary": [], "encrypted_content": "opaque"},
                    {"type": "function_call", "id": "fc-1", "call_id": "call-1", "name": "sql", "arguments": "{}"},
                ]},
                {"role": "tool", "tool_call_id": "call-1", "content": "synthetic result"},
            ], [{"type": "function", "function": {"name": "finish", "parameters": {"type": "object"}}}])
            request = sdk.return_value.responses.create.call_args.kwargs
            self.assertFalse(request["store"])
            self.assertFalse(request["parallel_tool_calls"])
            self.assertEqual(request["include"], ["reasoning.encrypted_content"])
            self.assertEqual(request["extra_body"], {"reasoning": {"effort": "medium"}})
            self.assertEqual(request["input"][1]["encrypted_content"], "opaque")
            self.assertEqual(request["input"][-1]["call_id"], "call-1")
            self.assertEqual(result["gateway_transport"]["requested_model"], "gpt-6-sol")
            self.assertEqual(result["gateway_transport"]["reported_model"], "reported-sol")
            self.assertEqual(result["choices"][0]["finish_reason"], "tool_calls")
            native["status"] = "incomplete"
            self.assertEqual(client.complete([], [])["choices"][0]["finish_reason"], "incomplete")
            client.close()

    def test_rate_limit_retains_existing_retry_contract_and_auth_errors_surface(self):
        request = httpx.Request("POST", gateway().base_url + "/responses")
        with patch("openai.OpenAI") as sdk:
            client = AzureGenerationClient(self.config)
            response = httpx.Response(429, request=request, headers={"retry-after": "19"})
            sdk.return_value.responses.create.side_effect = RateLimitError("fixture", response=response, body={})
            with self.assertRaises(RetryableCompletionError) as raised:
                client.complete([], [])
            self.assertEqual(raised.exception.delay_seconds, 19)
            for kind, status in ((AuthenticationError, 401), (InternalServerError, 500)):
                sdk.return_value.responses.create.side_effect = kind(
                    "fixture", response=httpx.Response(status, request=request), body={},
                )
                with self.assertRaisesRegex(RuntimeError, f"Copilot gateway completion failed: {kind.__name__}; status={status}"):
                    client.complete([], [])
            self.assertEqual(sdk.return_value.responses.create.call_count, 3)
            client.close()

    def test_episode_budget_does_not_drop_gateway(self):
        client = SimpleNamespace(config=self.config)
        BoundedClient(client, PanelProfile(), Path(self.temporary.name))
        self.assertEqual(client.config.gateway, gateway())

    def test_readiness_rejects_missing_exact_model_without_requesting_alias(self):
        with patch("openai.OpenAI") as sdk, patch(
            "secgym.qagen.agentic.azure_generation.AzureGenerationClient",
        ) as generation:
            sdk.return_value.__enter__.return_value.models.list.return_value = [
                SimpleNamespace(id="gpt-6.1-sol-fast", model_dump=lambda **unused: {}),
            ]
            with self.assertRaisesRegex(ValueError, "gpt-6-sol; no model substitution"):
                check_gateway_models(gateway(), self.env, ("gpt-6-sol",))
            generation.assert_not_called()


class GatewayBatchTests(unittest.TestCase):
    setUp = preproduction_tests.PreproductionTests.setUp

    def prepare(self):
        self.output.mkdir()
        immutable_json(self.output / "plan.json", self.plan)
        policy = create_batch(self.output, "gateway01", checkpoint_size=2, workers=1, gateway=gateway())
        items = reserve_drafts(self.plan, self.output, policy, 1, {})
        return policy, items[0]["attempt"]["task_id"]

    def test_gateway_is_bound_to_new_batch_without_rewriting_plan_or_azure_defaults(self):
        original = self.plan.model_dump_json()
        policy, task_id = self.prepare()
        self.assertEqual(self.plan.model_dump_json(), original)
        self.assertEqual(load_batch_policy(batch_directory(self.output, "gateway01") / "policy.json"), policy)
        expected = task_model_binding(self.plan, self.output, task_id)
        self.assertEqual(expected.gateway, gateway())
        self.assertEqual(expected.deployment, "gpt-6-sol")
        self.assertEqual(expected.endpoint_sha256, hashlib.sha256(gateway().base_url.encode()).hexdigest())
        config = task_generation_config(self.plan, self.output, task_id, self.client.config.env_file)
        self.assertEqual(configured_model_binding(SimpleNamespace(config=config)), expected)
        self.assertEqual(task_model_binding(self.plan, self.output, "unallocated"), self.plan.model)
        with self.assertRaisesRegex(ValueError, "cannot change"):
            create_batch(self.output, "gateway01", checkpoint_size=2, workers=1)

    def test_changed_batch_or_reservation_cannot_switch_task_transport(self):
        _, task_id = self.prepare()
        path = self.output / "attempts" / task_id / "generation-batch.json"
        value = json.loads(path.read_bytes())
        value["reservation_fingerprint"] = "0" * 64
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "exact allocated"):
            task_model_binding(self.plan, self.output, task_id)

    def test_checkpoint_author_review_and_student_share_gateway_but_keep_model_settings(self):
        policy, task_id = self.prepare()
        root = self.output / "attempts" / task_id / "source"
        root.mkdir()
        transport = nonstudent_policy().model_copy(update={"plan_fingerprint": fingerprint(self.plan)})
        review = MagicMock()
        review.complete_with_credentials.side_effect = lambda client, messages, tools: {"source": "astra"}
        with patch("secgym.qagen.agentic.checkpoint_batches.azure_review_client", return_value=review) as factory, \
             patch("secgym.qagen.agentic.checkpoint_batches.AzureGenerationClient") as author:
            routed = CheckpointClient(self.plan, policy, transport, self.client.config.env_file, root)
            base_config = factory.call_args.args[0]
            author_config = author.call_args.args[0]
            self.assertEqual(base_config.gateway, gateway())
            self.assertEqual(author_config.gateway, gateway())
            self.assertEqual((base_config.deployment, base_config.timeout_seconds), ("gpt-6-sol", 300))
            self.assertEqual((author_config.deployment, author_config.timeout_seconds), ("gpt-6-astra", 900))
            author.return_value.config = author_config
            messages = [{"role": "user", "content": "Synthetic draft"}]
            tools = [{"type": "function", "function": {"name": "finish", "parameters": TaskDraft.model_json_schema()}}]
            (root / "author").mkdir()
            immutable_json(root / "author/0000-request.json", {"role": "author", "messages": messages, "tools": tools})
            self.assertEqual(routed.complete(messages, tools)["source"], "astra")
            receipt = json.loads((root / "author/0000-generation-model.json").read_bytes())
            self.assertEqual(receipt["actual_config"]["gateway"], gateway().model_dump(mode="json"))
            routed.close()


class GatewayAdmissionTests(unittest.TestCase):
    setUp = admission_tests.AdmissionTests.setUp
    review = admission_tests.AdmissionTests.review

    def prepare(self):
        task_id = self.case.task.task_id
        policy = create_batch(self.run, "gateway-admission", checkpoint_size=20, workers=1, gateway=gateway())
        batch = batch_directory(self.run, policy.batch_id)
        attempt = next(value for value in self.plan.attempts() if value.task_id == task_id)
        item = {"policy_fingerprint": fingerprint(policy), "attempt": attempt.model_dump(mode="json"),
                "bucket": "incident:34", "previous_questions": []}
        (batch / "items").mkdir()
        item_path = batch / "items" / (task_id + ".json")
        immutable_json(item_path, item)
        reservation = self.run / "attempts" / task_id / "generation-batch.json"
        immutable_json(reservation, {
            "batch_id": policy.batch_id, "policy_fingerprint": fingerprint(policy),
            "reservation_fingerprint": hashlib.sha256(
                json.dumps(item, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(),
            ).hexdigest(),
        })
        return reservation, batch / "policy.json", item_path

    def test_gateway_admission_pins_every_transport_allocation_dependency(self):
        paths = self.prepare()
        model = task_model_binding(self.plan, self.run, self.case.task.task_id)
        admission_tests.save(self.native / "binding.json", self.native_binding.model_copy(update={"model": model}))
        receipt = record_admission(self.plan, self.run, self.files)
        for path in paths:
            with self.subTest(path=path.name):
                original = path.read_bytes()
                self.assertEqual(receipt.source_artifacts_sha256[str(path.resolve())],
                                 hashlib.sha256(original).hexdigest())
                path.write_bytes(original + b" ")
                with self.assertRaisesRegex(ValueError, "source artifacts changed"):
                    admitted_receipts(self.plan, self.run)
                path.write_bytes(original)

    def test_gateway_batch_cannot_admit_an_azure_native_binding(self):
        self.prepare()
        with self.assertRaisesRegex(ValueError, "native source, indexes, student model"):
            record_admission(self.plan, self.run, self.files)


if __name__ == "__main__":
    unittest.main()
