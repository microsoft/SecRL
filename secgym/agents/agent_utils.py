# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import re
from autogen import OpenAIWrapper
import time
from typing import List
from openai.types.chat import ChatCompletion
from openai import RateLimitError as OpenAIRateLimitError
from azure.ai.inference import ChatCompletionsClient
from azure.ai.inference.models import ChatCompletions
from anthropic import APIStatusError as AnthropicAPIStatusError


def msging(msg: str, role: str="user"):
    return {"role": role, "content": msg}

def sql_parser(action: str, code_block=False):
    # remove ` in the str
    action = action.replace("`", "")
    if "submit[" in action:
        pattern = r'submit\[(.*)\]'
        submit = True
    else:
        if code_block:
            pattern = r'```sql(.*?)```'
        pattern = r'execute\[(.*)\]'
        submit = False

    matches = re.findall(pattern, action, re.DOTALL)
    if len(matches) > 0:
        action = matches[0]
        if ";" in action:
            return action[:action.index(";")], True, submit
        return action, True, submit
    return action, False, submit

def call_llm_foundry(
        client:ChatCompletionsClient, 
        model:str,
        messages:List[str], 
        retry_num=10, 
        retry_wait_time=5,
        temperature=None,
        stop=None,
    ) -> ChatCompletions:

    for _ in range(retry_num):
        try: 
            response = client.complete(messages=messages, temperature=temperature, stop=stop)
            break
        except TimeoutError as e:
            time.sleep(retry_wait_time)
    return response

def update_total_usage(total_usage, new_usage):
    """
    Recursively update the total_usage dictionary with values from new_usage.
    
    Parameters:
    - total_usage (dict): The running total usage dictionary.
    - new_usage (dict): The new usage data to be added.
    """
    for key, value in new_usage.items():
        if isinstance(value, dict):
            # Initialize a nested dictionary if it doesn't exist.
            if key not in total_usage:
                total_usage[key] = {}
            update_total_usage(total_usage[key], value)
        elif isinstance(value, int):
            # Initialize the key to 0 if it doesn't exist.
            if key not in total_usage:
                total_usage[key] = 0
            total_usage[key] += value

def update_model_usage(total_usage_by_model:dict, model_name:str, usage_dict:dict):
    """
    Update the total usage for a given model with the new response data.
    
    Parameters:
    - total_usage_by_model (dict): Dictionary mapping model names to their cumulative usage.
    - model_name (str): The name of the model.
    - usage_dict (dict): The new usage data to be added.
    """
    assert isinstance(total_usage_by_model, dict), "total_usage_by_model should be a dictionary"
    assert isinstance(model_name, str), "model_name should be a string"
    assert isinstance(usage_dict, dict), "usage_dict should be a dictionary"
    # If the model is not in the total_usage_by_model, initialize its usage dictionary.
    if model_name not in total_usage_by_model:
        total_usage_by_model[model_name] = {}
    
    update_total_usage(total_usage_by_model[model_name], usage_dict)


def call_llm(
        client:OpenAIWrapper, 
        model:str,
        messages:List[str], 
        retry_num=10, 
        retry_wait_time=5,
        temperature=None,
        stop=None
    ) -> ChatCompletion:

    for attempt in range(retry_num):
        try: 
            if "o1" in model:
                messages[0]['role'] = 'user'
                response = client.create(messages=messages, model=model)
            elif "o3" in model:
                response = client.create(messages=messages, model=model)
            elif "gpt-5" in model:
                #by default running at reasoning level high
                response = client.create(messages=messages, model=model, temperature=temperature, stop=stop, reasoning_effort="medium")
            elif "claude" in model:
                try:
                    response = client.create(messages=messages, model=model, temperature=temperature, stop=stop, thinking={"type": "enabled","budget_tokens": 10000})
                except AnthropicAPIStatusError as e:
                    if attempt < retry_num - 1:  # Don't sleep on the last retry
                        wait_time = retry_wait_time * (2 ** attempt)  # Exponential backoff
                        time.sleep(wait_time)
                        continue
                    else:
                        raise  # Re-raise on the last attempt
            else:
                response = client.create(messages=messages, model=model, temperature=temperature, stop=stop)
            break
        except OpenAIRateLimitError as e:
            if attempt < retry_num - 1:  # Don't sleep on the last retry
                wait_time = retry_wait_time * (2 ** attempt)  # Exponential backoff
                print(f"Rate limit error encountered. Retrying in {wait_time} seconds... (Attempt {attempt + 1}/{retry_num})")
                time.sleep(wait_time)
                continue
            else:
                raise  # Re-raise on the last attempt
        except TimeoutError as e:
            if attempt < retry_num - 1:
                time.sleep(retry_wait_time)
            else:
                raise
    return response
