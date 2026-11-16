# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

import httpx
from openai import InternalServerError

import test_agentic_preproduction as preproduction_tests
from test_agentic_gateway import gateway
from test_agentic_review_transport import nonstudent_policy
from secgym.qagen.agentic.azure_generation import AzureGenerationClient
from secgym.qagen.agentic.checkpoint_batches import (
    CheckpointBatchPolicy, CheckpointClient, _check_policy, create_batch, reserve_drafts,
)
from secgym.qagen.agentic.contracts import fingerprint
from secgym.qagen.agentic.ledger import file_sha256
from secgym.qagen.agentic.model_panel import immutable_json
from secgym.qagen.agentic.preproduction import (
    configured_model_binding, recorded_task_model_binding, runtime_hashes,
    run_source_wave, task_generation_config, task_model_binding, validate_task_client,
)
from secgym.qagen.agentic.provider_defaults import (
    AUTHORITY, load_provider_default, recorded_native_model,
)
from secgym.qagen.agentic import transport_amendments as amendments
from secgym.qagen.agentic.preproduction_revisions import effective_runtime, validate_source_audit_runtime
from secgym.qagen.agentic.review_transport import load_run_transport_policy
from secgym.qagen.agentic.review_transport import (
    ServerErrorRecoveryApproval, azure_review_client, recover_review,
)
from secgym.qagen.agentic.preproduction_admission import FinalReview
from secgym.qagen.agentic.generation import run_role


def authority_value(plan, env_file):
    return {
        "policy": "qa-future-live-model-provider-default-v1", "approved": True,
        "user_instruction": "use copilot cli gateway as the default endpoint for all work going foward",
        "approved_at": "2026-11-11T08:24:05.385+00:00",
        "scope": "All new live model work for this SecRL QA campaign, including remaining batch-seven validations and subsequent batches.",
        "plan_fingerprint": fingerprint(plan), "provider": "copilot-api", "gateway": gateway().model_dump(mode="json"),
        "credential_env_file": str(env_file.resolve()), "author_and_repair_model": "gpt-6-astra",
        "reviewer_and_student_model": "gpt-6-sol", "max_output_tokens": 16000, "reasoning_effort": "medium",
        "student_http_seconds": 300, "nonstudent_http_seconds": 900, "azure_fallback_authorized": False,
        "azure_future_live_calls_require_separate_explicit_authorization": True,
        "historical_provider_records_must_remain_exact": True, "unfinished_roles_require_explicit_task_bound_migration": True,
        "completed_student_or_semantic_review_resampling_authorized": False,
        "scoring_query_limits_or_admission_gates_changed": False, "release_approved": False,
    }


class ProviderDefaultTests(unittest.TestCase):
    def setUp(self):
        preproduction_tests.PreproductionTests.setUp(self)
        self.plan = self.plan.model_copy(update={
            "model": self.plan.model.model_copy(update={"reasoning_effort": "medium"}),
        })
        self.output.mkdir()
        immutable_json(self.output / "plan.json", self.plan)
        self.policy = create_batch(self.output, "old-batch", checkpoint_size=2, workers=1)
        self.item, = reserve_drafts(self.plan, self.output, self.policy, 1, {})
        self.task_id = self.item["attempt"]["task_id"]
        self.role_root = self.output / "attempts" / self.task_id / "pipeline/r1"
        self.env = self.root / "gateway.env"
        self.env.write_text("SECRL_GATEWAY_API_KEY=synthetic-local-test-key\n")

    def approve(self, **updates):
        path = self.output / AUTHORITY
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({**authority_value(self.plan, self.env), **updates}))
        return path

    def config(self):
        return task_generation_config(self.plan, self.output, self.task_id, self.client.config.env_file)

    def request(self, role="native-blind", index=0, directory=None):
        directory = directory or self.role_root / role
        directory.mkdir(parents=True, exist_ok=True)
        messages = [{"role": "user", "content": "Synthetic " + role}]
        tools = [{"type": "function", "function": {"name": "finish", "parameters": {"type": "object"}}}]
        path = directory / f"{index:04d}-request.json"
        immutable_json(path, {"role": role, "messages": messages, "tools": tools})
        return path, messages, tools

    def mock_sdk(self):
        sdk = self.enterContext(patch("openai.OpenAI"))
        sdk.return_value.responses.create.return_value.model_dump.return_value = {
            "status": "completed", "model": "reported-model", "output": [],
            "usage": {"input_tokens": 1, "output_tokens": 1},
        }
        return sdk

    def test_existing_batch_fresh_execution_uses_default_without_rewriting_history(self):
        plan_bytes = (self.output / "plan.json").read_bytes()
        policy_path = self.output / "generation-batches/old-batch/policy.json"
        policy_bytes = policy_path.read_bytes()
        self.approve()
        config = self.config()
        self.assertEqual(config.gateway, gateway())
        self.assertEqual(config.env_file, self.env)
        self.assertEqual(configured_model_binding(SimpleNamespace(config=config)), task_model_binding(
            self.plan, self.output, self.task_id,
        ))
        self.assertEqual(recorded_task_model_binding(self.plan, self.output, self.task_id), self.plan.model)
        self.assertEqual((self.output / "plan.json").read_bytes(), plan_bytes)
        self.assertEqual(policy_path.read_bytes(), policy_bytes)

    def test_legacy_and_explicit_gateway_bindings_are_not_ambient_defaults(self):
        with patch.dict("os.environ", {"OPENAI_BASE_URL": gateway().base_url, "SECRL_PROVIDER": "copilot-api"}):
            self.assertIsNone(self.config().gateway)
            self.assertNotIn("forward_default", self.config().model_dump())
        policy = create_batch(self.output, "explicit", checkpoint_size=2, workers=1, gateway=gateway())
        item, = reserve_drafts(self.plan, self.output, policy, 1, {})
        task_id = item["attempt"]["task_id"]
        self.assertEqual(task_model_binding(self.plan, self.output, task_id).gateway, gateway())
        self.approve(gateway=gateway().model_copy(update={"base_url": "http://127.0.0.1:41418/v1"}).model_dump())
        with self.assertRaisesRegex(ValueError, "explicitly bound gateway"):
            task_model_binding(self.plan, self.output, task_id)

    def test_bad_authority_and_model_profile_changes_fail_closed(self):
        for update in (
            {"approved": False}, {"plan_fingerprint": "0" * 64}, {"azure_fallback_authorized": True},
            {"reviewer_and_student_model": "gpt-6.1-sol-fast"}, {"author_and_repair_model": "gpt-6-sol"},
            {"reasoning_effort": "high"}, {"max_output_tokens": 32000}, {"student_http_seconds": 900},
        ):
            with self.subTest(update=update):
                self.approve(**update)
                with self.assertRaises(ValueError):
                    self.config()
        altered = self.plan.model_copy(update={"model": self.plan.model.model_copy(update={"reasoning_effort": "high"})})
        self.approve(plan_fingerprint=fingerprint(altered))
        with self.assertRaisesRegex(ValueError, "model/profile"):
            load_provider_default(altered, self.output)

    def test_missing_stale_authority_and_azure_fallback_never_construct_sdk(self):
        authority = self.approve()
        config = self.config()
        authority.unlink()
        with patch("openai.OpenAI") as sdk, patch("azure.identity.AzureCliCredential") as azure:
            with self.assertRaisesRegex(ValueError, "immutable"):
                AzureGenerationClient(config)
            self.approve(approved_at="2026-11-11T09:00:00+00:00")
            with self.assertRaisesRegex(ValueError, "exact retained"):
                AzureGenerationClient(config)
            self.approve()
            with self.assertRaisesRegex(ValueError, "Azure fallback"):
                AzureGenerationClient(config.model_copy(update={"gateway": None}))
            sdk.assert_not_called()
            azure.assert_not_called()

    def test_forward_client_requires_task_authority_even_if_gateway_matches(self):
        self.approve()
        client = SimpleNamespace(config=self.config().model_copy(update={"forward_default": None}))
        with self.assertRaisesRegex(ValueError, "task-bound"):
            validate_task_client(self.plan, self.output, self.task_id, client)

    def test_removed_authority_directory_cannot_restore_legacy_azure_default(self):
        authority = self.approve()
        self.config()
        authority.unlink()
        authority.parent.rmdir()
        with self.assertRaisesRegex(ValueError, "Azure fallback is forbidden"):
            self.config()

    def test_real_transport_selects_exact_models_and_timeouts_for_fresh_roles(self):
        self.approve()
        sdk = self.mock_sdk()
        client = AzureGenerationClient(self.config())
        self.addCleanup(client.close)
        for role, model, timeout in (
            ("author", "gpt-6-astra", 900), ("repair", "gpt-6-astra", 900),
            ("quality-refuter", "gpt-6-sol", 900), ("native-blind", "gpt-6-sol", 300),
        ):
            with self.subTest(role=role):
                path, messages, tools = self.request(role)
                response = client.complete(messages, tools)
                request = sdk.return_value.responses.create.call_args.kwargs
                self.assertEqual((request["model"], request["timeout"], request["max_output_tokens"]), (model, timeout, 16000))
                self.assertEqual(request["extra_body"], {"reasoning": {"effort": "medium"}})
                self.assertEqual(response["gateway_transport"]["requested_model"], model)
                binding = json.loads((path.parent / "provider-binding.json").read_bytes())
                self.assertEqual(binding["actual_config"]["deployment"], model)
                self.assertEqual(binding["authority_sha256"], file_sha256(self.output / AUTHORITY))
                immutable_json(path.with_name("0000-response.json"), response)
        self.assertEqual(sdk.return_value.responses.create.call_count, 4)

    def test_checkpoint_author_constructor_uses_default_on_original_azure_policy(self):
        from secgym.qagen.agentic.generation import TaskDraft

        self.approve()
        sdk = self.mock_sdk()
        policy = nonstudent_policy().model_copy(update={"plan_fingerprint": fingerprint(self.plan)})
        client = CheckpointClient(self.plan, self.policy, policy, self.client.config.env_file, self.role_root, run=self.output)
        self.addCleanup(client.close)
        self.assertEqual(client.config.gateway, gateway())
        self.assertEqual(client.author.config.deployment, "gpt-6-astra")
        self.assertEqual(client.author.config.timeout_seconds, 900)
        self.assertIsNotNone(client.author.config.forward_default)
        path, messages, _ = self.request("author")
        tools = [{"type": "function", "function": {"name": "finish", "parameters": TaskDraft.model_json_schema()}}]
        path.write_text(json.dumps({"role": "author", "messages": messages, "tools": tools}))
        client.complete(messages, tools)
        self.assertEqual(sdk.return_value.responses.create.call_args.kwargs["model"], "gpt-6-astra")
        self.assertEqual(json.loads((path.parent / "provider-binding.json").read_bytes())["actual_config"]["timeout_seconds"], 900)

    def test_source_wave_constructs_per_task_default_instead_of_using_supplied_azure_client(self):
        self.output = self.root / "source-wave"
        self.output.mkdir()
        immutable_json(self.output / "plan.json", self.plan)
        self.approve()
        with patch("secgym.qagen.agentic.azure_generation.AzureGenerationClient") as factory:
            run_source_wave(
                plan=self.plan, client=self.client, serving_bundle=self.serving, graph_bundle=self.graph,
                output=self.output, wave_size=1, resume=True,
                runner=lambda **kwargs: preproduction_tests.PreproductionTests.runner(self, **kwargs),
            )
        config, = factory.call_args.args
        self.assertEqual(config.gateway, gateway())
        self.assertEqual(config.forward_default.task_id, self.plan.attempts()[0].task_id)
        self.assertIs(self.calls[0]["client"], factory.return_value)
        factory.return_value.close.assert_called_once()

    def test_unknown_preexisting_or_terminal_roles_cannot_silently_switch(self):
        self.approve()
        sdk = self.mock_sdk()
        old, old_messages, old_tools = self.request("quality-refuter")
        client = AzureGenerationClient(self.config())
        self.addCleanup(client.close)
        before = old.read_bytes()
        with self.assertRaisesRegex(ValueError, "task-bound migration"):
            client.complete(old_messages, old_tools)
        self.assertFalse((old.parent / "provider-binding.json").exists())
        self.assertEqual(old.read_bytes(), before)
        path, messages, tools = self.request("unknown-role")
        with self.assertRaisesRegex(ValueError, "unknown role"):
            client.complete(messages, tools)
        path, messages, tools = self.request("native-blind")
        immutable_json(path.parent / "complete.json", {"completed": True})
        with self.assertRaisesRegex(ValueError, "terminal"):
            client.complete(messages, tools)
        sdk.return_value.responses.create.assert_not_called()

    def test_resumption_requires_exact_prior_dispatch_and_no_ambiguous_retry(self):
        self.approve()
        sdk = self.mock_sdk()
        client = AzureGenerationClient(self.config())
        self.addCleanup(client.close)
        path, messages, tools = self.request()
        response = client.complete(messages, tools)
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            client.complete(messages, tools)
        immutable_json(path.with_name("0000-response.json"), response)
        path, messages, tools = self.request(index=1)
        receipt = path.with_name("0000-provider.json")
        receipt.write_text("{}")
        with self.assertRaisesRegex(ValueError, "relabeling"):
            client.complete(messages, tools)
        self.assertEqual(sdk.return_value.responses.create.call_count, 1)

    def server_error_recovery_fixture(self):
        self.approve()
        sdk = self.mock_sdk()
        policy = nonstudent_policy().model_copy(update={"plan_fingerprint": fingerprint(self.plan)})
        client = azure_review_client(self.config(), policy, (self.role_root,))
        self.addCleanup(client.close)
        task = self.seed.model_copy(update={"task_id": self.task_id})
        subject = fingerprint(task.private_gold)
        role = self.role_root / "contract-reviewer"

        class InspectionTools:
            def schemas(inner):
                return [{"type": "function", "function": {
                    "name": "inspect", "description": "Read the synthetic fixture.",
                    "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
                }}]

            def dispatch(inner, name, arguments):
                self.assertEqual((name, arguments), ("inspect", {}))
                return {"fixture_inspected": True}

        tools = InspectionTools()
        error = InternalServerError("synthetic recorded500", response=httpx.Response(
            500, request=httpx.Request("POST", "http://127.0.0.1:41417/v1/responses")), body=None)
        sdk.return_value.responses.create.side_effect = error
        with self.assertRaisesRegex(RuntimeError, "Copilot gateway.*status=500"):
            run_role(client, tools, "contract-reviewer", "Inspect the synthetic fixture.",
                     {"task_fingerprint": fingerprint(task), "subject_fingerprint": subject},
                     FinalReview, role)
        original = {path.name: path.read_bytes() for path in role.glob("*.json")}
        approval = self.root / "server-error-approval.json"
        immutable_json(approval, ServerErrorRecoveryApproval(
            plan_fingerprint=fingerprint(self.plan), role_directory=str(role),
            request_sha256=file_sha256(role / "0000-request.json"),
            error_sha256=file_sha256(role / "0000-error.json"),
            reason="Exact synthetic nonstudent HTTP500 recovery.", approved=True,
        ))

        def validate(review, inspected):
            self.assertEqual(review.task_fingerprint, fingerprint(task))
            self.assertEqual(review.subject_fingerprint, subject)
            self.assertIs(inspected, tools)

        return sdk, client, task, subject, role, tools, approval, original, validate

    def test_explicit_server_error_recovery_composes_with_the_real_forward_provider(self):
        sdk, client, task, subject, role, tools, approval, original, validate = self.server_error_recovery_fixture()
        review = FinalReview(task_fingerprint=fingerprint(task), subject_fingerprint=subject,
                             recommendation="pass", reviewer="fixture", reasons=("Synthetic source verified.",))

        def response(name, arguments, call_id):
            payload = {
                "status": "completed", "model": "reported-model",
                "output": [{"type": "function_call", "call_id": call_id, "name": name, "arguments": json.dumps(arguments)}],
                "usage": {"input_tokens": 1, "output_tokens": 1},
            }
            return SimpleNamespace(model_dump=lambda **kwargs: payload)

        sdk.return_value.responses.create.side_effect = [
            response("inspect", {}, "inspect-recovered"),
            response("finish", review.model_dump(mode="json"), "finish-recovered"),
        ]
        result = recover_review(client=client, verifier=None, directory=role, task=task,
                                validate=validate, tools=tools, server_error_approval=approval)
        self.assertEqual(result, review)
        self.assertEqual(sdk.return_value.responses.create.call_count, 3)
        self.assertEqual({name: (role / name).read_bytes() for name in original}, original)
        self.assertTrue((role / "0001-provider.json").is_file())
        self.assertTrue((role / "0002-provider.json").is_file())
        self.assertFalse((role / "0000-response.json").exists())
        self.assertEqual(json.loads((role / "complete.json").read_bytes())["calls"], 3)

    def test_server_error_provider_recovery_rejects_changed_approval_or_first_context(self):
        sdk, client, task, _, role, tools, approval, _, validate = self.server_error_recovery_fixture()
        with patch.object(client.reviewer, "complete", side_effect=ValueError("test stops before provider binding")):
            with self.assertRaisesRegex(ValueError, "test stops before"):
                recover_review(client=client, verifier=None, directory=role, task=task,
                               validate=validate, tools=tools, server_error_approval=approval)
        request = role / "0001-request.json"
        recorded = json.loads(request.read_bytes())
        original_approval = approval.read_bytes()
        approval.write_text("{}")
        with self.assertRaisesRegex(ValueError, "approval changed"):
            client.reviewer.complete(recorded["messages"], recorded["tools"])
        approval.write_bytes(original_approval)
        original_request = request.read_bytes()
        changed = json.loads(original_request)
        changed["messages"][1]["content"] = "changed recovered context"
        request.write_text(json.dumps(changed))
        with self.assertRaisesRegex(ValueError, "exact unanswered request"):
            client.reviewer.complete(changed["messages"], changed["tools"])
        self.assertFalse((role / "0001-provider.json").exists())
        self.assertEqual(sdk.return_value.responses.create.call_count, 1)

    def test_server_error_certificate_never_authorizes_student_history(self):
        from secgym.qagen.agentic.provider_defaults import _approved_server_error_history

        self.approve()
        for role in ("blind", "native-blind"):
            with self.subTest(role=role):
                previous, _, _ = self.request(role, index=0)
                current, _, _ = self.request(role, index=1)
                immutable_json(current.parent / "approved-server-error-recovery.json", {})
                with self.assertRaisesRegex(ValueError, "another student request"):
                    _approved_server_error_history(self.config(), fingerprint(self.plan), current, previous)

    def test_existing_stranded_recovered_request_is_not_implicitly_dispatched(self):
        sdk, client, task, _, role, tools, approval, _, validate = self.server_error_recovery_fixture()
        with patch.object(client.reviewer, "complete", side_effect=ValueError("test before provider binding")):
            with self.assertRaisesRegex(ValueError, "test before provider"):
                recover_review(client=client, verifier=None, directory=role, task=task,
                               validate=validate, tools=tools, server_error_approval=approval)
        restarted = AzureGenerationClient(self.config().model_copy(update={"timeout_seconds": 900}))
        self.addCleanup(restarted.close)
        recorded = json.loads((role / "0001-request.json").read_bytes())
        with self.assertRaisesRegex(ValueError, "separate audited pre-dispatch recovery"):
            restarted.complete(recorded["messages"], recorded["tools"])
        self.assertFalse((role / "0001-provider.json").exists())
        self.assertEqual(sdk.return_value.responses.create.call_count, 1)

    def test_new_native_directory_cannot_resample_the_old_student(self):
        self.approve()
        sdk = self.mock_sdk()
        old, _, _ = self.request(directory=self.role_root / "old-native/student")
        immutable_json(old.with_name("0000-response.json"), {"old": "azure"})
        immutable_json(old.parent / "complete.json", {"completed": True})
        before = {path.name: path.read_bytes() for path in old.parent.iterdir()}
        client = AzureGenerationClient(self.config())
        self.addCleanup(client.close)
        _, messages, tools = self.request(directory=self.role_root / "new-native/student")
        with self.assertRaisesRegex(ValueError, "instead of resampling"):
            client.complete(messages, tools)
        sdk.return_value.responses.create.assert_not_called()
        self.assertEqual({path.name: path.read_bytes() for path in old.parent.iterdir()}, before)

    def test_retained_native_model_is_historical_not_the_new_live_default(self):
        self.approve()
        native = self.role_root / "native"
        native.mkdir(parents=True)
        self.assertEqual(recorded_native_model(self.plan, self.output, self.task_id, native), self.plan.model)
        self.assertNotEqual(recorded_native_model(self.plan, self.output, self.task_id, native),
                            task_model_binding(self.plan, self.output, self.task_id))
        self.mock_sdk()
        client = AzureGenerationClient(self.config())
        self.addCleanup(client.close)
        path, messages, tools = self.request(directory=native / "student")
        client.complete(messages, tools)
        self.assertEqual(recorded_native_model(self.plan, self.output, self.task_id, native),
                         task_model_binding(self.plan, self.output, self.task_id))
        binding_path = path.parent / "provider-binding.json"
        binding = json.loads(binding_path.read_bytes())
        binding["actual_config"].pop("gateway")
        binding_path.write_text(json.dumps(binding))
        with self.assertRaisesRegex(ValueError, "cannot be relabeled"):
            recorded_native_model(self.plan, self.output, self.task_id, native)


class TransportAmendmentTests(unittest.TestCase):
    def setUp(self):
        preproduction_tests.PreproductionTests.setUp(self)
        self.output.mkdir()
        self.sources = {path.name: path.read_bytes() for path in Path(amendments.__file__).parent.glob("*.py")}
        self.old = {name: data for name, data in self.sources.items() if name not in amendments.ADDED_MODULES}
        self.old["azure_generation.py"] = b"# exact synthetic old transport\n"
        self.old["review_transport.py"] = b"# exact synthetic old reviewer transport\n"
        self.old["checkpoint_batches.py"] = b"# exact synthetic old checkpoint transport\n"
        self.old_hashes = {name: hashlib.sha256(data).hexdigest() for name, data in self.old.items()}
        self.plan = self.plan.model_copy(update={
            "model": self.plan.model.model_copy(update={"reasoning_effort": "medium"}),
            "implementation_sha256": {name: self.old_hashes[name] for name in runtime_hashes() if name in self.old},
        })
        immutable_json(self.output / "plan.json", self.plan)
        authority = self.output / AUTHORITY
        authority.parent.mkdir(parents=True)
        immutable_json(authority, authority_value(self.plan, self.root / "unused.env"))
        self.archive, self.current_archive = self.output / "before.zip", self.output / "after.zip"
        self.save_archive(self.archive, self.old)
        self.save_archive(self.current_archive, self.sources)
        self.enterContext(patch.object(amendments, "BEFORE_MANIFEST_SHA256", amendments._manifest_digest(self.old_hashes)))
        self.enterContext(patch.object(amendments, "UPDATED_MODULES", {
            name: hashlib.sha256(self.sources[name]).hexdigest() for name in amendments.UPDATED_MODULES
        }))
        self.enterContext(patch.object(amendments, "TRANSPORT_MODULE_SHA256",
                                      hashlib.sha256(self.sources["transport_amendments.py"]).hexdigest()))

    @staticmethod
    def save_archive(path, sources):
        with zipfile.ZipFile(path, "w") as archive:
            for name, data in sources.items():
                archive.writestr(name, data)

    def record(self):
        return amendments.record_transport_amendment(
            self.plan, self.output, archive=self.archive, current_archive=self.current_archive,
            reason="Synthetic exact archived transport cutover.",
        )

    def test_archived_cutover_preserves_plan_and_updates_only_reviewer_implementation(self):
        policy = nonstudent_policy().model_copy(update={
            "plan_fingerprint": fingerprint(self.plan), "implementation_sha256": self.old_hashes["review_transport.py"],
        })
        immutable_json(self.output / "review-transport-policy02.json", policy)
        before = (self.output / "plan.json").read_bytes()
        amendment = self.record()
        self.assertEqual(effective_runtime(self.plan, self.output), runtime_hashes())
        self.assertEqual((self.output / "plan.json").read_bytes(), before)
        current = load_run_transport_policy(self.output, fingerprint(self.plan))
        self.assertEqual(current.model_dump(exclude={"previous_policy_fingerprint", "implementation_sha256"}),
                         policy.model_dump(exclude={"previous_policy_fingerprint", "implementation_sha256"}))
        self.assertFalse(amendment.retained_native_runtime_compatibility_authorized)
        with self.assertRaisesRegex(ValueError, "already exists"):
            self.record()

    def test_modified_protected_kernel_and_arbitrary_old_archive_are_rejected(self):
        for name in ("generation.py", "query.py", "scoring.py", "evidence.py", "model_panel.py", "azure_generation.py"):
            with self.subTest(name=name):
                self.save_archive(self.current_archive, {**self.sources, name: self.sources[name] + b"\n# modified\n"})
                with self.assertRaisesRegex(ValueError, "protected kernels"):
                    self.record()
        self.save_archive(self.current_archive, self.sources)
        self.save_archive(self.archive, {**self.old, "generation.py": b"# arbitrary older generation\n"})
        with self.assertRaisesRegex(ValueError, "exact audited"):
            self.record()

    def test_existing_batch_and_source_audit_use_only_exact_archived_transition(self):
        from secgym.qagen.agentic.quality import runtime_hashes as quality_hashes

        policy = CheckpointBatchPolicy(
            plan_fingerprint=fingerprint(self.plan), batch_id="old",
            source_generation_runtime_sha256=self.plan.implementation_sha256,
            implementation_sha256=self.old_hashes["checkpoint_batches.py"],
            user_authorization="astra_generation_checkpoint_reviews",
        )
        folder = self.output / "generation-batches/old"
        folder.mkdir(parents=True)
        immutable_json(folder / "policy.json", policy)
        original = (folder / "policy.json").read_bytes()
        with self.assertRaisesRegex(ValueError, "producer"):
            _check_policy(self.plan, self.output, policy)
        self.record()
        _check_policy(self.plan, self.output, policy)
        self.assertEqual((folder / "policy.json").read_bytes(), original)
        task = self.seed.model_copy(update={"task_id": self.plan.attempts()[0].task_id})
        candidate = self.output / "attempts" / task.task_id / "source"
        candidate.mkdir(parents=True)
        old_quality = {name: self.old_hashes[name] for name in quality_hashes() if name in self.old}
        validate_source_audit_runtime(candidate, task, old_quality)
        with self.assertRaisesRegex(ValueError, "runtime changed"):
            validate_source_audit_runtime(candidate, task, {**old_quality, "evidence.py": "0" * 64})

    def test_authority_deletion_or_mutation_and_archive_tamper_invalidate_cutover(self):
        self.record()
        path = self.output / AUTHORITY
        data = path.read_bytes()
        path.write_bytes(data + b"\n")
        with self.assertRaisesRegex(ValueError, "authority"):
            effective_runtime(self.plan, self.output)
        path.unlink()
        with self.assertRaisesRegex(ValueError, "immutable"):
            effective_runtime(self.plan, self.output)
        path.write_bytes(data)
        self.current_archive.write_bytes(self.current_archive.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "archive bytes"):
            effective_runtime(self.plan, self.output)


if __name__ == "__main__":
    unittest.main()
