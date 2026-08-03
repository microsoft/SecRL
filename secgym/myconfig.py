# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import os

try:
    from azure.identity import get_bearer_token_provider, AzureCliCredential
    from azure.ai.inference import ChatCompletionsClient
    from azure.core.credentials import AzureKeyCredential
except Exception:  # azure deps are optional (only needed for Azure model configs)
    get_bearer_token_provider = AzureCliCredential = None
    ChatCompletionsClient = AzureKeyCredential = None


def _load_anthropic_key():
    """Resolve the Anthropic API key.

    Order: ANTHROPIC_API_KEY env var -> $SABER_ENV_FILE -> oss_saber/.env.
    """
    key = os.environ.get("ANTHROPIC_API_KEY")
    if key:
        return key
    candidates = [os.environ.get("SABER_ENV_FILE"),
                  os.path.expanduser("~/repos/oss_saber/.env")]
    for path in candidates:
        if path and os.path.exists(path):
            for line in open(path):
                line = line.strip()
                if line.startswith("ANTHROPIC_API_KEY="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    return None


# token_provider = get_bearer_token_provider(
#     AzureCliCredential(), "https://cognitiveservices.azure.com/.default"
# )

# BE SURE TO include a "tags": [<model_name>] for each dictionary in the config_list to include the model name
# We will filter out the config list passed in to only include the model that model_name in the tags is equal to qa_gen_model
# config_list = [
#     {
#         "model": "some name",
#         "tags": ["gpt-4o"]
#     },
#     {
#         "model": "some name",
#         "tags": ["gpt-3.5"]
#     }
# ]
# If qa_gen_model = "gpt-4o", the config_list for qa_gen will be only the first dictionary in the config_list
# Similarly in run_exp.py, if you set --model gpt-4o, the config_list for the agent will be only the first dictionary in the config_list


CONFIG_LIST = [
    # exmaple using openai
    #   {
    #     "model": "gpt-4.1",
    #     "api_key": open("/Users/kevin/Downloads/SecRL/keys/openaikey").read().strip(),
    #     "tags": ["gpt-4.1"],
    # }
  
  # example of using azure openai
  # {
  #   "model": "gpt-4.1-nano",
  #   "base_url": "https://secphibench-aoai-eastus.openai.azure.com",
  #   "api_type": "azure",
  #   "api_version": "2025-01-01-preview",
  #   "tags": ["gpt-4.1-nano"],
  #   "azure_ad_token_provider": token_provider
  # },

  # Anthropic Claude / Opus (used for the entity-parsing-bug QA regeneration).
  # Key is resolved from ANTHROPIC_API_KEY / $SABER_ENV_FILE / oss_saber/.env.
  *([{
      "model": "claude-opus-5",
      "api_key": _load_anthropic_key(),
      "api_type": "anthropic",
      "tags": ["opus5"],
      "max_tokens": 8192,
  }] if _load_anthropic_key() else []),
]

if len(CONFIG_LIST) == 0:
    print("Potential Error: No config set in CONFIG_LIST, please add your config list to the CONFIG_LIST variable in secgym/myconfig.py")