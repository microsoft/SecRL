# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Responses client with Azure/Entra defaults and an explicitly bound local gateway."""

from pathlib import Path
import os
from urllib.parse import urlsplit
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
from typing import Literal

from pydantic import model_serializer

from .contracts import Identifier, PositiveInt
from .gateway import GatewayOptIn, gateway_key
from .provider_defaults import ForwardDefault, bind_forward_request, validate_forward_config


class AzureGenerationConfig(GatewayOptIn):
    env_file: Path
    deployment: Identifier
    timeout_seconds: PositiveInt
    max_completion_tokens: PositiveInt
    reasoning_effort: Literal["low", "medium", "high"] | None = None
    forward_default: ForwardDefault | None = None

    @model_serializer(mode="wrap")
    def omit_legacy_transport(self, handler):
        data = handler(self)
        for name in ("gateway", "forward_default"):
            if getattr(self, name) is None:
                data.pop(name, None)
        return data


def replay_output(items: list[dict]) -> list[dict]:
    fields = {
        "reasoning": ("id", "type", "summary", "encrypted_content"),
        "function_call": ("id", "type", "call_id", "name", "arguments"),
        "message": ("id", "type", "role", "content"),
    }
    replay = []
    for item in items:
        if item["type"] not in fields:
            raise ValueError("unexpected response item type for the configured function-tool workflow")
        replay.append({key: item[key] for key in fields[item["type"]] if item.get(key) is not None})
    return replay


class AzureGenerationClient:
    def __init__(self, config: AzureGenerationConfig):
        from dotenv import dotenv_values

        config = AzureGenerationConfig.model_validate(config)
        self.config = config
        self.credential = None
        self.preexisting_requests = set()
        if config.forward_default is not None:
            validate_forward_config(config)
            root = config.forward_default.run / "attempts" / config.forward_default.task_id
            self.preexisting_requests = {path.resolve() for path in root.rglob("*-request.json")}
        if config.gateway is not None:
            from openai import OpenAI

            self.client = OpenAI(base_url=config.gateway.base_url, api_key=gateway_key(config.gateway, config.env_file),
                                 timeout=config.timeout_seconds, max_retries=0)
            return
        from azure.identity import AzureCliCredential, get_bearer_token_provider
        from openai import AzureOpenAI

        values = dotenv_values(config.env_file)
        endpoint = values.get("AZUREAI_OPENAI_BASE_URL")
        version = values.get("AZUREAI_OPENAI_API_VERSION")
        if not endpoint or not version or urlsplit(endpoint).scheme != "https":
            raise ValueError("explicit HTTPS Azure endpoint and API version are required")
        self.credential = AzureCliCredential(process_timeout=30)
        provider = get_bearer_token_provider(self.credential, "https://cognitiveservices.azure.com/.default")
        if os.environ.get("AZURE_OPENAI_API_KEY") or os.environ.get("AZURE_OPENAI_AD_TOKEN"):
            self.credential.close()
            raise ValueError("remove conflicting Azure key/static-token environment values before using Entra token-provider authentication")
        self.client = AzureOpenAI(azure_endpoint=endpoint, api_version=version,
                                  azure_ad_token_provider=provider, timeout=config.timeout_seconds, max_retries=0)

    def complete(self, messages: list[dict], tools: list[dict]) -> dict:
        from openai import APIError, RateLimitError
        from .generation import RetryableCompletionError

        config = self.config
        if config.forward_default is not None:
            config = bind_forward_request(config, messages, tools, self.preexisting_requests)
        inputs = []
        for message in messages:
            if "responses_output" in message:
                inputs.extend(replay_output(message["responses_output"]))
            elif message["role"] == "tool":
                inputs.append({"type": "function_call_output", "call_id": message["tool_call_id"], "output": message["content"]})
            else:
                inputs.append({"role": message["role"], "content": message["content"]})
        declarations = [{"type": "function", **tool["function"], "strict": False} for tool in tools]
        try:
            response = self.client.responses.create(
                model=config.deployment, input=inputs, tools=declarations,
                max_output_tokens=config.max_completion_tokens, store=False,
                include=["reasoning.encrypted_content"], parallel_tool_calls=False,
                extra_body=({"reasoning": {"effort": config.reasoning_effort}}
                            if config.reasoning_effort is not None else {}),
                **({"timeout": config.timeout_seconds} if config.forward_default is not None else {}),
            ).model_dump(mode="json")
        except RateLimitError as error:
            raw = error.response.headers.get("retry-after")
            delay = 60.0
            if raw:
                try:
                    delay = float(raw)
                except ValueError:
                    delay = (parsedate_to_datetime(raw) - datetime.now(timezone.utc)).total_seconds()
            provider = "Copilot gateway" if self.config.gateway is not None else "Azure"
            raise RetryableCompletionError(f"{provider} token-rate limit; retrying the same retained role context.",
                                           max(5.0, delay)) from error
        except APIError as error:
            provider = "Copilot gateway" if self.config.gateway is not None else "Azure"
            raise RuntimeError(f"{provider} completion failed: {type(error).__name__}; status={getattr(error, 'status_code', None)}") from error
        calls = [{"id": item["call_id"], "type": "function", "function": {"name": item["name"], "arguments": item["arguments"]}}
                 for item in response["output"] if item["type"] == "function_call"]
        reason = "tool_calls" if calls else "stop"
        if response["status"] != "completed":
            reason = "incomplete"
        result = {
            "choices": [{"finish_reason": reason, "message": {
                "role": "assistant", "tool_calls": calls, "responses_output": response["output"],
            }}],
            "usage": response.get("usage"), "azure_responses": response,
        }
        if self.config.gateway is not None:
            result["gateway_transport"] = {
                **self.config.gateway.model_dump(mode="json"), "requested_model": config.deployment,
                "reported_model": response.get("model"),
            }
        return result

    def close(self):
        self.client.close()
        if self.credential is not None:
            self.credential.close()
