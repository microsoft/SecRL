# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Explicit forward-only campaign transport authority; never a historical model binding."""

from datetime import datetime
import hashlib
import json
from pathlib import Path
from typing import Literal

from .contracts import Contract, Digest, Identifier, Text, fingerprint
from .gateway import GatewayConfig
from .ledger import file_sha256


AUTHORITY = Path("campaign-control/model-provider-defaults/0001.json")
AUTHORITY_BINDING = Path("campaign-control/model-provider-default-binding.json")


class ProviderDefault(Contract):
    policy: Literal["qa-future-live-model-provider-default-v1"]
    approved: Literal[True]
    user_instruction: Literal["use copilot cli gateway as the default endpoint for all work going foward"]
    approved_at: datetime
    scope: Literal[
        "All new live model work for this SecRL QA campaign, including remaining batch-seven validations and subsequent batches."
    ]
    plan_fingerprint: Digest
    provider: Literal["copilot-api"]
    gateway: GatewayConfig
    credential_env_file: Text
    author_and_repair_model: Literal["gpt-6-astra"]
    reviewer_and_student_model: Literal["gpt-6-sol"]
    max_output_tokens: Literal[16000]
    reasoning_effort: Literal["medium"]
    student_http_seconds: Literal[300]
    nonstudent_http_seconds: Literal[900]
    azure_fallback_authorized: Literal[False]
    azure_future_live_calls_require_separate_explicit_authorization: Literal[True]
    historical_provider_records_must_remain_exact: Literal[True]
    unfinished_roles_require_explicit_task_bound_migration: Literal[True]
    completed_student_or_semantic_review_resampling_authorized: Literal[False]
    scoring_query_limits_or_admission_gates_changed: Literal[False]
    release_approved: Literal[False]


class ForwardDefault(Contract):
    run: Path
    task_id: Identifier
    authority_sha256: Digest


def load_provider_default(plan, run: Path) -> ProviderDefault | None:
    directory = run / AUTHORITY.parent
    if not directory.exists():
        if (run / AUTHORITY_BINDING).exists():
            raise ValueError("the activated provider-default authority is missing; Azure fallback is forbidden")
        return None
    if sorted(path.name for path in directory.iterdir()) != ["0001.json"]:
        raise ValueError("provider default requires its sole immutable 0001.json authority")
    authority = ProviderDefault.model_validate_json((run / AUTHORITY).read_bytes())
    if authority.plan_fingerprint != fingerprint(plan):
        raise ValueError("provider default authority belongs to a different or stale model plan")
    if (plan.model.deployment, plan.model.reasoning_effort, plan.model.max_completion_tokens,
        plan.model.request_timeout_seconds) != ("gpt-6-sol", "medium", 16000, 300):
        raise ValueError("provider default cannot change the approved model/profile")
    if not Path(authority.credential_env_file).is_absolute() or authority.approved_at.utcoffset() is None:
        raise ValueError("provider default requires an explicit credential file and dated authorization")
    from .model_panel import immutable_json
    binding = {"policy": authority.policy, "plan_fingerprint": fingerprint(plan),
               "authority_sha256": file_sha256(run / AUTHORITY)}
    marker = run / AUTHORITY_BINDING
    if marker.exists() and json.loads(marker.read_bytes()) != binding:
        raise ValueError("forward execution requires its exact retained provider-default authority")
    immutable_json(marker, binding)
    return authority


def forward_model_binding(plan, run: Path, recorded):
    authority = load_provider_default(plan, run)
    if authority is None:
        return recorded
    if recorded.gateway is not None and recorded.gateway != authority.gateway:
        raise ValueError("an explicitly bound gateway cannot switch to another provider default")
    return recorded.model_copy(update={
        "gateway": authority.gateway,
        "endpoint_sha256": hashlib.sha256(authority.gateway.base_url.encode()).hexdigest(),
        "api_version": "openai-responses",
    })


def validate_forward_config(config):
    from .preproduction import PreproductionPlan, task_model_binding

    reference = config.forward_default
    run = reference.run
    if not run.is_absolute() or run != run.resolve():
        raise ValueError("forward execution requires the canonical owning run")
    plan = PreproductionPlan.model_validate_json((run / "plan.json").read_bytes())
    authority = load_provider_default(plan, run)
    if authority is None or file_sha256(run / AUTHORITY) != reference.authority_sha256:
        raise ValueError("forward execution requires its exact retained provider-default authority")
    if reference.task_id not in {attempt.task_id for attempt in plan.attempts()}:
        raise ValueError("forward execution requires an allocated logical task")
    model = task_model_binding(plan, run, reference.task_id)
    if (config.gateway, config.env_file, config.reasoning_effort, config.max_completion_tokens) != (
        model.gateway, Path(authority.credential_env_file), "medium", 16000,
    ) or config.deployment not in ("gpt-6-sol", "gpt-6-astra") or config.timeout_seconds not in (300, 900):
        raise ValueError("forward execution cannot change its provider, model/profile or use Azure fallback")
    return authority


def _approved_server_error_history(config, plan_fingerprint: str, current: Path, previous: Path, *,
                                   preexisting_request: bool = False) -> bool:
    from pydantic import TypeAdapter
    from . import review_transport

    directory = current.parent
    certificate = directory / "approved-server-error-recovery.json"
    if not certificate.exists():
        return False
    request = json.loads(current.read_bytes())
    if request["role"] in ("blind", "native-blind"):
        raise ValueError("provider-default recovery cannot authorize another student request")
    certificates = [directory / name for name in review_transport.RECOVERY_CERTIFICATES if (directory / name).exists()]
    if certificates != [certificate]:
        raise ValueError("provider-default recovery requires one exact nonstudent server-error certificate")
    recovery = json.loads(certificate.read_bytes())
    if recovery.get("unanswered_request") != previous.name:
        return False
    policy = TypeAdapter(review_transport.TransportPolicy).validate_json(json.dumps(recovery["policy"]))
    if policy.plan_fingerprint != plan_fingerprint or policy.implementation_sha256 != file_sha256(
        Path(review_transport.__file__)
    ) or review_transport._request_role(request, policy) is None:
        raise ValueError("provider-default recovery requires the exact approved nonstudent transport policy")
    approval_path = Path(recovery["approval"])
    if file_sha256(approval_path) != recovery["approval_sha256"]:
        raise ValueError("provider-default recovery approval changed")
    approval = review_transport._server_error_approval(approval_path, directory, previous, policy)
    if recovery.get("policy_version") != approval.policy_version or (
        recovery.get("original_request_replaced") is not False
        or recovery.get("original_responses_replaced") is not False
        or type(recovery.get("student_calls")) is not int or recovery["student_calls"] != 0
    ):
        raise ValueError("provider-default recovery cannot replace history or authorize student calls")
    original = json.loads(previous.read_bytes())
    first = directory / f"{int(previous.name.split('-')[0]) + 1:04d}-request.json"
    if not first.is_file() or first > current or json.loads(first.read_bytes()) != original or (
        recovery["request_context_fingerprint"] != review_transport._digest({
            "messages": original["messages"], "tools": original["tools"],
        })
    ):
        raise ValueError("the first provider-default recovery must retain the exact unanswered request")
    originals = recovery["original_artifacts_sha256"]
    required = {previous.name, previous.name.replace("-request.json", "-error.json"),
                previous.name.replace("-request.json", "-provider.json"), "provider-binding.json"}
    if not isinstance(originals, dict) or not required <= originals.keys():
        raise ValueError("provider-default recovery lacks its original provider-bound failure history")
    for name, checksum in originals.items():
        if Path(name).name != name or not name.endswith(".json") or file_sha256(directory / name) != checksum:
            raise ValueError("provider-default recovery changed or escaped an original role artifact")
    receipt = json.loads(current.with_name(current.name.replace("-request.json", "-transport.json")).read_bytes())
    if receipt["policy"] != policy.model_dump(mode="json") or (
        receipt["role"] != request["role"] or receipt["request_sha256"] != file_sha256(current)
        or receipt["request_context_fingerprint"] != review_transport._digest({
            "messages": request["messages"], "tools": request["tools"],
        })
    ):
        raise ValueError("provider-default recovery lacks the exact current transport dispatch binding")
    base = config.model_copy(update={"timeout_seconds": policy.original_timeout_seconds})
    review_transport._server_error_model_settings(previous, base, config)
    if (receipt["original_config"], receipt["effective_config"]) != (
        base.model_dump(mode="json", exclude={"env_file"}), config.model_dump(mode="json", exclude={"env_file"}),
    ):
        raise ValueError("provider-default recovery cannot change its original model settings")
    if preexisting_request:
        raise ValueError("a stranded provider-default recovery requires separate audited pre-dispatch recovery")
    return True


def bind_forward_request(config, messages, tools, preexisting_requests):
    """Bind before dispatch; old, terminal and ambiguous roles are never migrated implicitly."""
    from .model_panel import immutable_json
    from .review_transport import AUTHOR_ROLES, REVIEW_ROLES, compact_fact_review_messages, compact_objective_messages

    authority = validate_forward_config(config)
    reference = config.forward_default
    root = reference.run / "attempts" / reference.task_id
    matches = []
    native_roles = set()
    for role in {path.parent for path in root.rglob("*-request.json")}:
        request = sorted(role.glob("*-request.json"))[-1]
        if not request.resolve().is_relative_to(root.resolve()):
            raise ValueError("forward request escaped its owning logical task")
        value = json.loads(request.read_bytes())
        if value.get("role") == "native-blind":
            native_roles.add(role)
        if request.with_name(request.name.replace("-request.json", "-response.json")).exists():
            continue
        logical = value.get("messages")
        if value.get("tools") != tools or not isinstance(logical, list):
            continue
        projected = logical
        if value.get("role") == "fact-reviewer":
            projected = compact_fact_review_messages(logical)
        elif value.get("role") == "objective-reviewer":
            projected = compact_objective_messages(logical)
        if messages == logical or messages == projected:
            matches.append((request, value))
    if len(matches) != 1:
        raise ValueError("forward execution requires exactly one owned outstanding request")
    path, request = matches[0]
    role = request["role"]
    if role == "native-blind" and native_roles != {path.parent}:
        raise ValueError("another native student already started; retain its trace instead of resampling")
    student = role in ("native-blind", "blind")
    if role not in AUTHOR_ROLES and role not in REVIEW_ROLES and not student:
        raise ValueError("unknown role cannot use the forward provider default")
    if any((path.parent / name).exists() for name in ("complete.json", "result.json", "abstention.json")):
        raise ValueError("terminal roles cannot be resampled under a provider default")
    actual = config.model_copy(update={
        "deployment": authority.author_and_repair_model if role in ("author", "repair") else authority.reviewer_and_student_model,
        "timeout_seconds": authority.student_http_seconds if student else authority.nonstudent_http_seconds,
    })
    binding = {
        "policy": "qa-forward-role-binding-v1", "authority_sha256": reference.authority_sha256,
        "task_id": reference.task_id, "role_directory": str(path.parent.resolve()), "role": role,
        "actual_config": actual.model_dump(mode="json", exclude={"env_file", "forward_default"}),
    }
    marker = path.parent / "provider-binding.json"
    if not marker.exists() and (
        path.resolve() in preexisting_requests or path.name != "0000-request.json"
        or list(path.parent.glob("*-response.json")) or list(path.parent.glob("*-error.json"))
    ):
        raise ValueError("started or unknown old role requires explicit task-bound migration; refusing provider switch")
    immutable_json(marker, binding)
    for previous in sorted(path.parent.glob("*-request.json")):
        receipt = previous.with_name(previous.name.replace("-request.json", "-provider.json"))
        if previous == path:
            if receipt.exists():
                raise ValueError("previous dispatch is ambiguous; no automatic provider-default retry")
            continue
        value = json.loads(receipt.read_bytes()) if receipt.exists() else {}
        if value != {"binding_sha256": file_sha256(marker), "request_sha256": file_sha256(previous)}:
            raise ValueError("old-role provider relabeling or unbound request history is forbidden")
        response = previous.with_name(previous.name.replace("-request.json", "-response.json"))
        error = previous.with_name(previous.name.replace("-request.json", "-error.json"))
        if not response.exists() and (
            not error.exists() or json.loads(error.read_bytes()).get("status") != "retry_wait"
        ):
            if not _approved_server_error_history(
                config, authority.plan_fingerprint, path, previous,
                preexisting_request=path.resolve() in preexisting_requests,
            ):
                raise ValueError("unknown previous dispatch requires explicit recovery, not another live request")
    immutable_json(path.with_name(path.name.replace("-request.json", "-provider.json")), {
        "binding_sha256": file_sha256(marker), "request_sha256": file_sha256(path),
    })
    return actual


def recorded_native_model(plan, run: Path, task_id: str, native: Path):
    from .preproduction import recorded_task_model_binding, task_model_binding

    marker = native / "student/provider-binding.json"
    if not marker.exists():
        return recorded_task_model_binding(plan, run, task_id)
    authority = load_provider_default(plan, run)
    binding = json.loads(marker.read_bytes())
    model = task_model_binding(plan, run, task_id)
    expected = {
        "deployment": model.deployment, "timeout_seconds": model.request_timeout_seconds,
        "max_completion_tokens": model.max_completion_tokens, "reasoning_effort": model.reasoning_effort,
        "gateway": model.gateway.model_dump(mode="json") if model.gateway is not None else None,
    }
    if authority is None or binding != {
        "policy": "qa-forward-role-binding-v1", "authority_sha256": file_sha256(run / AUTHORITY),
        "task_id": task_id, "role_directory": str((native / "student").resolve()), "role": "native-blind",
        "actual_config": expected,
    }:
        raise ValueError("recorded student provider cannot be relabeled by the live default")
    requests = sorted((native / "student").glob("*-request.json"))
    if not requests:
        raise ValueError("recorded default student lacks its dispatched request")
    for path in requests:
        receipt = path.with_name(path.name.replace("-request.json", "-provider.json"))
        if not receipt.exists() or json.loads(receipt.read_bytes()) != {
            "binding_sha256": file_sha256(marker), "request_sha256": file_sha256(path),
        }:
            raise ValueError("recorded student request lacks its exact provider dispatch")
    return model
