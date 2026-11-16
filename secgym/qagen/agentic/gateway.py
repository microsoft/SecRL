# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Explicit, nonsecret bindings for an opt-in Copilot Responses gateway."""

from ipaddress import ip_address
import json
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import SerializerFunctionWrapHandler, model_serializer, model_validator

from .contracts import Contract, Digest, Identifier, Text


QA_GATEWAY_MODELS = ("gpt-6-astra", "gpt-6-sol", "gpt-6-luna")


class GatewayConfig(Contract):
    provider: Literal["copilot-api"] = "copilot-api"
    protocol: Literal["responses"] = "responses"
    base_url: Text
    version: Text
    image_sha256: Digest
    api_key_variable: Identifier = "SECRL_GATEWAY_API_KEY"

    @model_validator(mode="after")
    def local_authenticated_endpoint(self):
        url = urlsplit(self.base_url)
        if (url.scheme != "http" or url.hostname is None or url.username is not None
            or url.password is not None or url.query or url.fragment or url.path != "/v1"):
            raise ValueError("the Copilot gateway requires an explicit loopback HTTP /v1 endpoint without credentials")
        try:
            loopback = ip_address(url.hostname).is_loopback
            port = url.port
        except ValueError as error:
            raise ValueError("the Copilot gateway requires a literal loopback IP and valid port") from error
        if not loopback or port is None or port == 0:
            raise ValueError("the Copilot gateway requires a literal loopback IP and explicit port")
        return self


class GatewayOptIn(Contract):
    gateway: GatewayConfig | None = None

    @model_serializer(mode="wrap")
    def omit_legacy_gateway(self, handler: SerializerFunctionWrapHandler) -> dict:
        data = handler(self)
        if self.gateway is None:
            data.pop("gateway", None)
        return data


def gateway_key(config: GatewayConfig, env_file: Path) -> str:
    from dotenv import dotenv_values

    key = dotenv_values(env_file).get(config.api_key_variable)
    if not key or not key.strip():
        raise ValueError(f"the explicit endpoint env file requires {config.api_key_variable}")
    return key


def check_gateway_models(config: GatewayConfig, env_file: Path,
                         models: tuple[str, ...] = QA_GATEWAY_MODELS) -> dict:
    """Verify exact IDs and the production Responses tool/replay contract using synthetic data."""
    from openai import OpenAI

    from .azure_generation import AzureGenerationClient, AzureGenerationConfig

    if not models or len(set(models)) != len(models):
        raise ValueError("gateway readiness requires distinct explicit model IDs")
    results = []
    with OpenAI(base_url=config.base_url, api_key=gateway_key(config, env_file),
                timeout=60, max_retries=0) as discovery:
        catalog = {model.id: model.model_dump(mode="json") for model in discovery.models.list()}
    for model in models:
        advertised = catalog.get(model)
        if advertised is None:
            raise ValueError(f"required gateway model is unavailable: {model}; no model substitution is permitted")
        supports = advertised.get("capabilities", {}).get("supports", {})
        endpoints = advertised.get("supported_endpoints") or []
        limits = advertised.get("capabilities", {}).get("limits", {})
        if (not {"/responses", "/v1/responses"}.intersection(endpoints)
            or supports.get("tool_calls") is not True or "medium" not in supports.get("reasoning_effort", [])
            or limits.get("max_output_tokens", 0) < 16000):
            raise ValueError(f"required gateway model lacks the QA Responses/tool/reasoning/output contract: {model}")
        client = AzureGenerationClient(AzureGenerationConfig(
            env_file=env_file, deployment=model, timeout_seconds=300, max_completion_tokens=16000,
            reasoning_effort="medium", gateway=config,
        ))
        try:
            tools = [{"type": "function", "function": {
                "name": "probe", "description": "First request the marker; then return the marker supplied by the tool.",
                "parameters": {"type": "object", "properties": {"marker": {"type": "string"}},
                               "required": ["marker"], "additionalProperties": False},
            }}]
            messages = [
                {"role": "system", "content": "Synthetic compatibility test. Call probe with marker=request. "
                 "After its tool result, call probe again with the exact returned marker. No plain text."},
                {"role": "user", "content": "Run the synthetic tool test."},
            ]
            usages, reasoning, reported = [], False, []
            for expected, marker in (("request", "secrl-gateway-probe-8642"), ("secrl-gateway-probe-8642", None)):
                response = client.complete(messages, tools)
                choice, = response["choices"]
                calls = choice["message"]["tool_calls"]
                if (choice["finish_reason"] != "tool_calls" or len(calls) != 1
                    or calls[0]["function"]["name"] != "probe"
                    or json.loads(calls[0]["function"]["arguments"]) != {"marker": expected}):
                    raise ValueError(f"gateway model failed the synthetic tool/replay boundary: {model}")
                usage = response["usage"]
                if not isinstance(usage, dict) or any(
                    type(usage.get(key)) is not int or usage[key] < 0 for key in ("input_tokens", "output_tokens")
                ) or usage["output_tokens"] > 16000:
                    raise ValueError(f"gateway model lacks valid bounded token accounting: {model}")
                usages.append(usage)
                reported.append(response["azure_responses"].get("model"))
                reasoning |= any(bool(item.get("encrypted_content")) for item in choice["message"]["responses_output"]
                                 if item["type"] == "reasoning")
                if marker is not None:
                    messages.extend([choice["message"], {
                        "role": "tool", "tool_call_id": calls[0]["id"], "content": json.dumps({"marker": marker}),
                    }])
            results.append({"requested_model": model, "reported_models": reported, "tool_replay_passed": True,
                            "encrypted_reasoning_returned": reasoning, "usage": usages})
        finally:
            client.close()
    return {"gateway": config.model_dump(mode="json"), "status": "ready", "models": results,
            "synthetic_data_only": True, "production_batch_started": False}
