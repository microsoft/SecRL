from azure.identity import get_bearer_token_provider, AzureCliCredential
from azure.ai.inference import ChatCompletionsClient
from azure.core.credentials import AzureKeyCredential

# aoai_endpoint = "https://medeina-openai-dev-011.openai.azure.com/"
# aoai_emb_endpoint = "https://medeinaapi-dev-openai-san.openai.azure.com/"

token_provider = get_bearer_token_provider(
    AzureCliCredential(), "https://cognitiveservices.azure.com/.default"
)

CONFIG_LIST = [
  # {
  #   "model": "gpt-4o-0513-spot",
  #   "base_url": "https://devpythiaaoaiauseast.openai.azure.com",
  #   "api_type": "azure",
  #   "api_version": "2024-08-01-preview",
  #   "tags": ["gpt-4o"],
  #   "azure_ad_token_provider": token_provider
  # },
  # {
  #   "model": "gpt-4o-0513-spot",
  #   "base_url": "https://devpythiaaoaiswedencentral.openai.azure.com",
  #   "api_type": "azure",
  #   "api_version": "2025-01-01-preview",
  #   "tags": ["gpt-4o"],
  #   "azure_ad_token_provider": token_provider
  # },
  # {
  #   "model": "gpt-4-0125-spot",
  #   "base_url": "https://devpythiaaoaicanadacentral.openai.azure.com",
  #   "api_type": "azure",
  #   "api_version": "2024-08-01-preview",
  #   "tags": ["gpt-4o"],
  #   "azure_ad_token_provider": token_provider
  # },
    #   {
    #     "model": "gemini-2.5-flash-preview-04-17",
    #     "api_key": open("googlekey").read().strip(),
    #     "api_type": "google",
    #     "tags": ["gemini-2.5-flash"],
    #     # "price": [0.03/1000, 0.05/1000],
    # },
    # {
    #     "model": "deepseek-ai/DeepSeek-R1",
    #     "base_url": "https://api.deepinfra.com/v1/openai",
    #     "api_key": open("deepinfrakey").read().strip(),
    #     "api_type": "openai",
    #     "tags": ["deepseek-r1"],
    #     "price": [0.5/1000, 2.18/1000],
    # },
    # {
    #     "model": "Qwen/Qwen3-32B",
    #     "base_url": "https://api.deepinfra.com/v1/openai",
    #     "api_key": open("deepinfrakey").read().strip(),
    #     "api_type": "openai",
    #     "tags": ["qwen3-32b"],
    #     "price": [0.1/1000, 0.3/1000],
    # },
    # {
    #     "model": "Qwen/Qwen3-14B",
    #     "base_url": "https://api.deepinfra.com/v1/openai",
    #     "api_key": open("deepinfrakey").read().strip(),
    #     "api_type": "openai",
    #     "tags": ["qwen3-14b"],
    #     "price": [0.08/1000, 0.24/1000],
    # },
    # {
    #     "model": "meta-llama/Llama-4-Scout-17B-16E-Instruct",
    #     "base_url": "https://api.deepinfra.com/v1/openai",
    #     "api_key": open("deepinfrakey").read().strip(),
    #     "api_type": "openai",
    #     "tags": ["llama4-Scout-17b"],
    #     "price": [0.08/1000, 0.3/1000],
    # },
    # {
    #     "model": "meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8",
    #     "base_url": "https://api.deepinfra.com/v1/openai",
    #     "api_key": open("deepinfrakey").read().strip(),
    #     "api_type": "openai",
    #     "tags": ["llama4-Mav-17b"],
    #     "price": [0.17/1000, 0.60/1000],
    # },
    # {
    #     "model": "meta-llama/Meta-Llama-3.1-405B-Instruct",
    #     "base_url": "https://api.deepinfra.com/v1/openai",
    #     "api_key": open("deepinfrakey").read().strip(),
    #     "api_type": "openai",
    #     "tags": ["llama3-405b"],
    #     "price": [0.8/1000, 0.8/1000],
    # },
  {
    "model": "phi4",
    "endpoint": "https://Phi-4-secrl.eastus.models.ai.azure.com",
    "api_type": "ai_foundry",
    "tags": ["phi4"],
  },
  {
    "model": "r1",
    "endpoint" : "https://DeepSeek-R1-secrl.eastus.models.ai.azure.com",
    "api_type": "ai_foundry",
    "tags": ["r1"], 
  },
  {
    "model": "gpt-4o",
    "base_url": "https://devpythiaaoaieus2.openai.azure.com",
    "api_type": "azure",
    "api_version": "2025-01-01-preview",
    "tags": ["gpt-4o"],
    "price": [2.5/1000, 10.0/1000],
    "azure_ad_token_provider": token_provider
  },
  {
     "model": "gpt-4o-0806",
      "base_url": "https://devpythiaaoainwus3.openai.azure.com",
      "api_type": "azure",
      "api_version": "2025-01-01-preview",
      "tags": ["gpt-4o"],
      "price": [2.5/1000, 10.0/1000],
      "azure_ad_token_provider": token_provider
  },
  # {
  #   "model": "gpt-4.1",
  #   "endpoint" : "https://metabase-aoi-eus2.openai.azure.com/openai/deployments/gpt-4.1",
  #   "api_type": "ai_foundry",
  #   "tags": ["gpt-4.1"], 
  # },
  { 
    "model": "o3",
    "base_url": "https://devpythiaaoaieus2.openai.azure.com/",
    "api_type": "azure",
    "api_version": "2024-12-01-preview",
    "tags": ["o3"],
    "price": [10.0/1000, 40.0/1000],
    "azure_ad_token_provider": token_provider
  },
  { 
    "model": "o4-mini",
    "base_url": "https://devpythiaaoaieus2.openai.azure.com/",
    "api_type": "azure",
    "api_version": "2024-12-01-preview",
    "tags": ["o4-mini"],
    "price": [1.1/1000, 4.4/1000],
    "azure_ad_token_provider": token_provider
  },
  {
    "model": "o4-mini",
    "base_url": "https://metabase-aoi-eus2.openai.azure.com/",
    "api_type": "azure",
    "api_version": "2024-12-01-preview",
    "tags": ["o4-mini"],
    "price": [1.1/1000, 4.4/1000],
    "azure_ad_token_provider": token_provider
  },
  {
    "model": "gpt-41",
    "base_url": "https://metabase-aoi-eus2.openai.azure.com/",
    "api_type": "azure",
    "api_version": "2024-12-01-preview",
    "tags": ["gpt-4.1"],
    "price": [2.0/1000, 8.0/1000],
    "azure_ad_token_provider": token_provider
  },
  {
    "model": "gpt-41-mini",
    "base_url": "https://metabase-aoi-eus2.openai.azure.com/",
    "api_type": "azure",
    "api_version": "2024-12-01-preview",
    "tags": ["gpt-4.1-mini"],
    "price": [0.4/1000, 1.6/1000],
    "azure_ad_token_provider": token_provider
  },
  {
    "model": "gpt-41-nano",
    "base_url": "https://metabase-aoi-eus2.openai.azure.com/",
    "api_type": "azure",
    "api_version": "2024-12-01-preview",
    "tags": ["gpt-4.1-nano"],
    "price": [0.1/1000, 0.4/1000],
    "azure_ad_token_provider": token_provider
  },
  # { #https://metabase-aoi-eus2.openai.azure.com/openai/deployments/gpt-4.1/chat/completions?api-version=2025-01-01-preview
  #    #https://metabase-aoi-eus2.openai.azure.com/openai/deployments/gpt-4o/chat/completions?api-version=2025-01-01-preview
  #   "model": "o1",
  #   #"deployment": "gpt-4.1",
  #   #"model_name": "gpt-4.1",
  #   "base_url": "https://metabase-aoi-eus2.openai.azure.com/",
  #   "api_type": "azure",
  #   "api_version": "2024-12-01-preview",
  #   "tags": ["gpt-4.1"],
  #   "price": [2.0/1000, 8.0/1000],
  #   "azure_ad_token_provider": token_provider
  # },
  {
    "model": "gpt-4o",
    "base_url": "https://metabase-aoi-eus2.openai.azure.com",
    "api_type": "azure",
    "api_version": "2025-01-01-preview",
    "tags": ["gpt-4o"],
    "price": [2.5/1000, 10.0/1000],
    "azure_ad_token_provider": token_provider
  },
  {
    "model": "gpt-4o",
    "base_url": "https://secphibench-aoai-eastus.openai.azure.com",
    "api_type": "azure",
    "api_version": "2024-08-01-preview",
    "tags": ["gpt-4o"],
    "azure_ad_token_provider": token_provider
  },
  {
    "model": "gpt-4o-2",
    "base_url": "https://secphibench-aoai-eastus.openai.azure.com",
    "api_type": "azure",
    "api_version": "2024-08-01-preview",
    "tags": ["gpt-4o"],
    "azure_ad_token_provider": token_provider
  },
  {
      "model": "o1-preview-2024-09-12-global",
      "base_url": "https://devpythiaaoaieus2.openai.azure.com",
      "api_type": "azure",
      "api_version": "2024-08-01-preview",
      "tags": ["o1"],
      "azure_ad_token_provider": token_provider
  },
  {
      "model": "o1-preview",
      "base_url": "https://ai-nguyenthanhai426837561304.cognitiveservices.azure.com",
      "api_type": "azure",
      "api_version": "2024-08-01-preview",
      "tags": ["o1"],
      "azure_ad_token_provider": token_provider
  },
    {
      "model": "o1-preview",
      "base_url": "https://secphibench-aoai-eastus.openai.azure.com",
      "api_type": "azure",
      "api_version": "2024-08-01-preview",
      "tags": ["o1"],
      "azure_ad_token_provider": token_provider
  },
  {
      "model": "o1-ga-2024-12-17",
      "base_url": "https://devpythiaaoaieus2.openai.azure.com",
      "api_type": "azure",
      "api_version": "2024-12-01-preview",
      "tags": ["o1-ga"],
      "price": [15.0/1000, 60.0/1000],
      "azure_ad_token_provider": token_provider
  },
  {
    "model": "gpt-4o-mini",
    "base_url": "https://secphibench-aoai-eastus.openai.azure.com",
    "api_type": "azure",
    "api_version": "2025-01-01-preview",
    "tags": ["4o-mini"],
    "azure_ad_token_provider": token_provider
  },
  {
    "model": "gpt-4o-mini-2",
    "base_url": "https://secphibench-aoai-eastus.openai.azure.com",
    "api_type": "azure",
    "api_version": "2025-01-01-preview",
    "tags": ["4o-mini"],
    "azure_ad_token_provider": token_provider
  },
  {
    "model": "gpt-4o-mini-3",
    "base_url": "https://secphibench-aoai-eastus.openai.azure.com",
    "api_type": "azure",
    "api_version": "2025-01-01-preview",
    "tags": ["4o-mini"],
    "azure_ad_token_provider": token_provider
  },
  {
    "model": "gpt-4o-mini-4",
    "base_url": "https://secphibench-aoai-eastus.openai.azure.com",
    "api_type": "azure",
    "api_version": "2025-01-01-preview",
    "tags": ["4o-mini"],
    "azure_ad_token_provider": token_provider
  },
    {
    "model": "gpt-4o-mini-5",
    "base_url": "https://secphibench-aoai-eastus.openai.azure.com",
    "api_type": "azure",
    "api_version": "2025-01-01-preview",
    "tags": ["4o-mini"],
    "azure_ad_token_provider": token_provider
  },
  {
    "model": "gpt-4o-mini-6",
    "base_url": "https://secphibench-aoai-eastus.openai.azure.com",
    "api_type": "azure",
    "api_version": "2025-01-01-preview",
    "tags": ["4o-mini"],
    "azure_ad_token_provider": token_provider
  },
  {
    "model": "gpt-4o-mini-7",
    "base_url": "https://secphibench-aoai-eastus.openai.azure.com",
    "api_type": "azure",
    "api_version": "2025-01-01-preview",
    "tags": ["4o-mini"],
    "azure_ad_token_provider": token_provider
  },
  {
    "model": "gpt-4o-mini-8",
    "base_url": "https://secphibench-aoai-eastus.openai.azure.com",
    "api_type": "azure",
    "api_version": "2025-01-01-preview",
    "tags": ["4o-mini"],
    "azure_ad_token_provider": token_provider
  },
    {
    "model": "gpt-4o-mini-9",
    "base_url": "https://secphibench-aoai-eastus.openai.azure.com",
    "api_type": "azure",
    "api_version": "2025-01-01-preview",
    "tags": ["4o-mini"],
    "azure_ad_token_provider": token_provider
  },
  {
    "model": "gpt-4o-mini-10",
    "base_url": "https://secphibench-aoai-eastus.openai.azure.com",
    "api_type": "azure",
    "api_version": "2025-01-01-preview",
    "tags": ["4o-mini"],
    "azure_ad_token_provider": token_provider
  },
  {
    "model": "o3-mini",
    "base_url": "https://metabase-aoi-eus2.openai.azure.com",
    "api_type": "azure",
    "api_version": "2024-12-01-preview",
    "tags": ["o3-mini"],
    "price": [1.1/1000, 4.4/1000],
    "azure_ad_token_provider": token_provider
  },
  {
    "model": "o3-mini",
    "base_url": "https://devpythiaaoaieus2.openai.azure.com",
    "api_type": "azure",
    "api_version": "2024-12-01-preview",
    "price": [1.1/1000, 4.4/1000],
    "tags": ["o3-mini"],
    "azure_ad_token_provider": token_provider
  },
  {
    "model": "o1-mini-2024-09-12-global",
    "base_url": "https://devpythiaaoaieus2.openai.azure.com",
    "api_type": "azure",
    "api_version": "2024-08-01-preview",
    "tags": ["o1-mini"],
    "price" : [1.1/1000, 4.4/1000], #TODO: This is wrong price, it should be [3.0/1000, 12.0/1000]
    "azure_ad_token_provider": token_provider
  },
  {
    "model": "o1-mini-2024-09-12-standard",
    "base_url": "https://devpythiaaoaieus2.openai.azure.com",
    "api_type": "azure",
    "api_version": "2024-08-01-preview",
    "tags": ["o1-mini"],
    "price" : [1.1/1000, 4.4/1000], #TODO: This is wrong price, it should be [3.0/1000, 12.0/1000]
    "azure_ad_token_provider": token_provider
  },
  #fine-tuned models
  {
    "model": "gpt-4o-2024-08-06-secrl_cv1",
    "base_url": "https://devpythiaaoaieus2.openai.azure.com",
    "api_type": "azure",
    "api_version": "2025-01-01-preview",
    "tags": ["gpt-4o-ft-cv1"],
    "azure_ad_token_provider": token_provider
  }
]