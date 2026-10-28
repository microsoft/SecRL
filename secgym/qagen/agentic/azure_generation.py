# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Explicit Azure/Entra client; no API-key or global dotenv configuration mutation."""

from pathlib import Path
import os
from urllib.parse import urlsplit
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone

from .contracts import Contract, Identifier, PositiveInt


class AzureGenerationConfig(Contract):
    env_file: Path
    deployment: Identifier
    timeout_seconds: PositiveInt
    max_completion_tokens: PositiveInt


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
        from azure.identity import AzureCliCredential, get_bearer_token_provider
        from dotenv import dotenv_values
        from openai import AzureOpenAI

        config = AzureGenerationConfig.model_validate(config)
        values = dotenv_values(config.env_file)
        endpoint = values.get("AZUREAI_OPENAI_BASE_URL")
        version = values.get("AZUREAI_OPENAI_API_VERSION")
        if not endpoint or not version or urlsplit(endpoint).scheme != "https":
            raise ValueError("explicit HTTPS Azure endpoint and API version are required")
        self.config = config
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
                model=self.config.deployment, input=inputs, tools=declarations,
                max_output_tokens=self.config.max_completion_tokens, store=False,
                include=["reasoning.encrypted_content"], parallel_tool_calls=False,
            ).model_dump(mode="json")
        except RateLimitError as error:
            raw = error.response.headers.get("retry-after")
            delay = 60.0
            if raw:
                try:
                    delay = float(raw)
                except ValueError:
                    delay = (parsedate_to_datetime(raw) - datetime.now(timezone.utc)).total_seconds()
            raise RetryableCompletionError("Azure token-rate limit; retrying the same retained role context.",
                                           max(5.0, delay)) from error
        except APIError as error:
            raise RuntimeError(f"Azure completion failed: {type(error).__name__}; status={getattr(error, 'status_code', None)}") from error
        calls = [{"id": item["call_id"], "type": "function", "function": {"name": item["name"], "arguments": item["arguments"]}}
                 for item in response["output"] if item["type"] == "function_call"]
        reason = "tool_calls" if calls else "stop"
        if response["status"] != "completed":
            reason = "incomplete"
        return {
            "choices": [{"finish_reason": reason, "message": {
                "role": "assistant", "tool_calls": calls, "responses_output": response["output"],
            }}],
            "usage": response.get("usage"), "azure_responses": response,
        }

    def close(self):
        self.client.close()
        self.credential.close()
