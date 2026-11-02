# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Explicit, validation-only publication of received non-student JSON results."""

from __future__ import annotations

from collections.abc import Callable
import fcntl
import hashlib
import json
from pathlib import Path
import re
import shutil
import tempfile
from typing import Literal, TypeVar

from .contracts import Contract, Digest, fingerprint
from .difficulty_curation import _restore_inspections
from .fact_curation import FactInspectionTools
from .generation import DiscoveryTools, GENERATOR_VERSION
from .ledger import file_sha256
from .model_panel import immutable_json
from .review_transport import AUTHOR_ROLES, REVIEW_ROLES, NonStudentTransportPolicy, _request_role


T = TypeVar("T", bound=Contract)
CERTIFICATE = "received-json-recovery.json"
PRODUCER = "received-json-recovery-producer.json"
LOCK = ".received-json-recovery.lock"


class JsonResultRecoveryPolicy(Contract):
    policy_version: Literal["nonstudent-received-json-recovery-v1"] = "nonstudent-received-json-recovery-v1"
    plan_fingerprint: Digest
    user_authorization: Literal["approve_nonstudent_json_recovery"]
    new_model_calls: Literal[0] = 0
    student_roles_allowed: Literal[False] = False
    original_artifacts_rewritten: Literal[False] = False
    tool_calls_fabricated: Literal[False] = False
    automatic_retry: Literal[False] = False
    implementation_sha256: Digest


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _files(directory: Path) -> dict[str, str]:
    result = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise ValueError("JSON recovery cannot follow symlinked role artifacts")
        if path.is_file() and path.name != LOCK:
            result[str(path.relative_to(directory))] = file_sha256(path)
    return result


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("received JSON contains duplicate object keys")
        result[key] = value
    return result


def _nonfinite(value: str) -> None:
    raise ValueError("received JSON contains a nonfinite numeric constant: " + value)


def _json_text(text: str) -> tuple[str, str]:
    if text.strip().startswith("{"):
        body, encoding = text.strip(), "plain_json"
    else:
        blocks = re.findall(r"(?ms)^```json[ \t]*\r?\n(.*?)\r?\n```[ \t]*(?=\r?\n|$)", text)
        if len(blocks) != 1 or text.count("```") != 2:
            raise ValueError("recovery requires one complete JSON object or one unambiguous json code block")
        body, encoding = blocks[0], "fenced_json"
    value = json.loads(body, object_pairs_hook=_unique_object, parse_constant=_nonfinite)
    if not isinstance(value, dict):
        raise ValueError("received result must be a JSON object")
    return body, encoding


def _message(response: dict) -> dict:
    choices = response.get("choices", [])
    if len(choices) != 1 or choices[0].get("finish_reason") not in ("stop", "tool_calls"):
        raise ValueError("recorded role history has an incomplete or ambiguous completion")
    message = choices[0].get("message")
    if not isinstance(message, dict) or message.get("role") != "assistant":
        raise ValueError("recorded response lacks its assistant message")
    return message


def _received_text(response: dict) -> str:
    message = _message(response)
    native = response.get("azure_responses") or {}
    if response["choices"][0]["finish_reason"] != "stop" or message.get("tool_calls") or (
        native.get("status") != "completed" or native.get("error") is not None
        or native.get("incomplete_details") is not None
    ):
        raise ValueError("JSON recovery requires a fully received, untruncated response without tool calls")
    output = message.get("responses_output")
    if not isinstance(output, list) or output != native.get("output") or any(
        item.get("type") not in ("message", "reasoning") for item in output
    ):
        raise ValueError("native and replay response outputs disagree")
    messages = [item for item in output if item["type"] == "message"]
    if len(messages) != 1 or messages[0].get("role") != "assistant" or messages[0].get("status") != "completed":
        raise ValueError("recovery requires one completed assistant text message")
    content = messages[0].get("content", [])
    if not content or any(part.get("type") != "output_text" or not isinstance(part.get("text"), str) for part in content):
        raise ValueError("refused, missing or non-text output cannot become a recovered result")
    text = "".join(part["text"] for part in content)
    if message.get("content") not in (None, text):
        raise ValueError("normalized text disagrees with the received assistant message")
    return text


def _history(directory: Path, transport: NonStudentTransportPolicy, response_type: type[T],
             original: dict[str, str]) -> tuple[list[Path], dict, T, dict]:
    if any(name in original for name in ("complete.json", "result.json", "abstention.json")):
        raise ValueError("completed or terminal roles cannot receive JSON recovery")
    requests = sorted(directory.glob("*-request.json"))
    if not requests or [path.name for path in requests] != [f"{i:04d}-request.json" for i in range(len(requests))]:
        raise ValueError("JSON recovery requires a contiguous recorded request history")
    first = json.loads(requests[0].read_bytes())
    if first.get("role") not in REVIEW_ROLES.keys() | AUTHOR_ROLES.keys() or _request_role(first, transport) is not response_type:
        raise ValueError("only a declared non-student role with its exact trusted result schema can recover")
    messages = first.get("messages")
    if not isinstance(messages, list) or len(messages) != 2 or (
        messages[0].get("role") != "system" or messages[1].get("role") != "user"
    ):
        raise ValueError("the original role envelope is missing")
    for index, path in enumerate(requests):
        request = json.loads(path.read_bytes())
        if request.get("role") != first["role"] or request.get("tools") != first["tools"] or request.get("messages") != messages:
            raise ValueError("recorded history does not reconstruct the exact next request")
        response_path = path.with_name(path.name.replace("-request.json", "-response.json"))
        results_path = path.with_name(path.name.replace("-request.json", "-tool-results.json"))
        error_path = path.with_name(path.name.replace("-request.json", "-error.json"))
        if response_path.name not in original and error_path.name in original:
            error = json.loads(error_path.read_bytes())
            delay = error.get("delay_seconds")
            if (
                error.get("status") != "retry_wait" or error.get("role") != first["role"]
                or type(error.get("call_index")) is not int or error["call_index"] != index
                or type(delay) not in (int, float) or not 0 <= delay < float("inf")
                or results_path.name in original or index == len(requests) - 1
            ):
                raise ValueError("unanswered or errored boundaries require a separate recovery")
            continue
        if response_path.name not in original or error_path.name in original:
            raise ValueError("unanswered or errored boundaries require a separate recovery")
        response = json.loads(response_path.read_bytes())
        message = _message(response)
        if index == len(requests) - 1:
            if results_path.name in original:
                raise ValueError("the received JSON boundary has already published tool results")
            text = _received_text(response)
            body, encoding = _json_text(text)
            result = response_type.model_validate_json(body)
            return requests, first, result, {
                "response_file": response_path.name, "source_text_sha256": _digest(text),
                "json_text_sha256": _digest(body), "encoding": encoding,
            }
        if results_path.name not in original:
            raise ValueError("an earlier response/tool boundary is unresolved")
        calls = message.get("tool_calls") or []
        results = json.loads(results_path.read_bytes())
        if not calls or any(call["function"]["name"] == "abstain" for call in calls) or (
            not isinstance(results, list) or len(results) != len(calls)
            or [value.get("tool_call_id") for value in results] != [call["id"] for call in calls]
            or any(value.get("role") != "tool" for value in results)
        ):
            raise ValueError("prior tool history is missing, terminal or inconsistent")
        for call, value in zip(calls, results):
            payload = json.loads(value["content"])
            if not isinstance(payload, dict):
                raise ValueError("recorded tool results must be structured objects")
            if call["function"]["name"] == "finish" and payload.get("accepted") is True:
                raise ValueError("an accepted finish cannot be resampled or reinterpreted")
        messages = [
            *messages,
            {key: message[key] for key in ("role", "content", "tool_calls", "responses_output")
             if key in message and message[key] is not None},
            *results,
        ]
    raise ValueError("received JSON boundary was not found")


def recover_json_result(
    *, directory: Path, root: Path, policy: JsonResultRecoveryPolicy,
    transport_policy: NonStudentTransportPolicy, response_type: type[T],
    tools: DiscoveryTools, validate_result: Callable[[T, DiscoveryTools], None],
) -> T:
    """Publish only the received value after its original validator; no model client is accepted."""
    policy = JsonResultRecoveryPolicy.model_validate_json(policy.model_dump_json())
    transport_policy = NonStudentTransportPolicy.model_validate_json(transport_policy.model_dump_json())
    directory, root = directory.resolve(), root.resolve()
    if directory == root or not directory.is_relative_to(root) or not directory.is_dir():
        raise ValueError("JSON recovery requires an existing role below its explicit owned root")
    if policy.plan_fingerprint != transport_policy.plan_fingerprint or policy.implementation_sha256 != file_sha256(Path(__file__)):
        raise ValueError("JSON recovery policy does not bind this run and implementation")
    if transport_policy.implementation_sha256 != file_sha256(Path(__file__).with_name("review_transport.py")):
        raise ValueError("the trusted non-student role registry changed")
    for parent in (directory, *directory.parents):
        if not parent.is_relative_to(root):
            break
        if (parent / "stage-receipt.json").exists():
            raise ValueError("a completed stage cannot be reopened by JSON recovery")
    with (directory / LOCK).open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        current = _files(directory)
        saved = json.loads((directory / CERTIFICATE).read_bytes()) if CERTIFICATE in current else None
        if saved is None and PRODUCER in current:
            raise ValueError("a recovery producer without its approval certificate is an unresolved publication")
        original = saved["original_artifacts_sha256"] if saved is not None else current
        if any(current.get(name) != digest for name, digest in original.items()):
            raise ValueError("original role artifacts changed after recovery validation")
        requests, request, result, received = _history(directory, transport_policy, response_type, original)
        results_name = requests[-1].name.replace("-request.json", "-tool-results.json")
        publications = {CERTIFICATE, PRODUCER, "result.json", "complete.json", results_name}
        if saved is not None and (
            saved["policy"] != policy.model_dump(mode="json")
            or set(current) - original.keys() - publications
        ):
            raise ValueError("recovery policy or appended role artifacts changed")
        declared_tools = [tool for tool in request["tools"] if tool["function"]["name"] not in ("finish", "abstain")]
        if tools.schemas() != declared_tools:
            raise ValueError("recovery requires the exact original source-tool interface")
        if isinstance(tools, FactInspectionTools):
            if tools.observed:
                raise ValueError("inspection recovery requires fresh tools, not unrecorded additional observations")
            with tempfile.TemporaryDirectory(prefix="secrl-json-inspections-") as temporary:
                prefix = Path(temporary)
                for path in requests[:-1]:
                    if path.name.replace("-request.json", "-response.json") not in original:
                        continue
                    for suffix in ("response", "tool-results"):
                        name = path.name.replace("-request.json", f"-{suffix}.json")
                        shutil.copyfile(directory / name, prefix / name)
                _restore_inspections(tools, prefix)
        validate_result(result, tools)
        if _files(directory) != current:
            raise ValueError("role artifacts changed during source validation")
        if policy.implementation_sha256 != file_sha256(Path(__file__)):
            raise ValueError("JSON recovery implementation changed during source validation")
        certificate = {
            "policy": policy.model_dump(mode="json"), "role": request["role"],
            "transport_policy_fingerprint": fingerprint(transport_policy),
            "original_artifacts_sha256": original, "last_request": requests[-1].name,
            **received, "result_fingerprint": fingerprint(result),
            "empty_tool_results_file": results_name, "original_validator_passed": True,
            "new_model_calls": 0, "tool_calls_fabricated": False,
        }
        producer = {
            "module": Path(__file__).name, "sha256": policy.implementation_sha256,
            "source": Path(__file__).read_text(),
        }
        immutable_json(directory / CERTIFICATE, certificate)
        immutable_json(directory / PRODUCER, producer)
        immutable_json(directory / "result.json", result)
        immutable_json(directory / results_name, [])
        immutable_json(directory / "complete.json", {
            "role": request["role"], "calls": len(requests), "generator_version": GENERATOR_VERSION,
            "result_fingerprint": fingerprint(result),
            "received_json_recovery": {"certificate": CERTIFICATE, "certificate_sha256": file_sha256(directory / CERTIFICATE)},
        })
        if any(file_sha256(directory / name) != digest for name, digest in original.items()):
            raise ValueError("received JSON publication changed an original role artifact")
        return result
