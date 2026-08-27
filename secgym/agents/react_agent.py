# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from autogen import OpenAIWrapper
from secgym.agents.agent_utils import sql_parser, msging, call_llm, call_llm_foundry, update_model_usage
import os
from azure.ai.inference import ChatCompletionsClient
from azure.core.credentials import AzureKeyCredential
curr_path = os.path.dirname(os.path.abspath(__file__))

BASE_PROMPT = """You are a security analyst. 
You need to answer a given security question by querying the database.
The logs are stored in a MySQL database, you can use SQL queries to retrieve entries as needed.
Note there are more than 20 tables in the database, so you may need to explore the schema or check example entries to understand the database structure.

Your response should always be a thought-action pair:
Thought: <your reasoning>
Action: <your SQL query>

In Thought, you can analyse and reason about the current situation, 
Action can be one of the following: 
(1) execute[<your query>], which executes the SQL query
(2) submit[<your answer>], which is the final answer to the question

Below are some demonstrations. Note that `Observation` denotes the returned logs from the database.
Many of the returned logs are reduced for brevity (replaced with `...`).
"""
O1_PROMPT = """You are a security analyst. 
You need to answer a given security question by querying the database.
The logs are stored in a MySQL database, you can use SQL queries to retrieve entries as needed.
Note there are more than 20 tables in the database, so you may need to explore the schema or check example entries to understand the database structure.

Your response should always be a thought-action pair:
Thought: <your reasoning>
Action: <your action>

In Thought, you can analyse and reason about the current situation, 
Action can be one of the following: 
(1) execute[<your sql query>], which executes the SQL query. For example, execute[DESCRIBE table_name].
(2) submit[<your answer>], which is the final answer to the question

You should only give one thought-action per response. The action from your response will be executed and the result will be shown to you.
Follow the format "Thought: ....\nAction: ...." exactly.
Do not include any other information in your response. Wait for the response from one action before giving the next thought-action pair. DO NOT make assumptions about the data that are not observed in the logs.

Below are some demonstrations. Note that `Observation` denotes the returned logs from the database.
Many of the returned logs are reduced for brevity (replaced with `...`).
"""

for i, file in enumerate(os.listdir(os.path.join(curr_path, "react_examples"))):
    with open(os.path.join(curr_path, "react_examples", file), "r") as f:
        BASE_PROMPT +=  f"\nExample {i+1}: \n" + f.read() + "\n" + "-"*50
        O1_PROMPT +=  f"\nExample {i+1}: \n" + f.read() + "\n" + "-"*50

BASE_PROMPT = BASE_PROMPT[:-50].strip()
O1_PROMPT = O1_PROMPT[:-50].strip()

class ReActAgent:
    def __init__(self,
                 config_list,
                 cache_seed=41,
                 max_steps=15,
                 submit_summary=False,
                 temperature=0,
                 retry_num=10,
                 retry_wait_time=5,
                 ):
        self.config_list = config_list
        self.temperature = temperature
        self.cache_seed = cache_seed

        if "ai_foundry" in config_list[0]['api_type']:
            from secgym.config_key import api_key
            self.client = ChatCompletionsClient(
            endpoint= config_list[0]['endpoint'],
            credential=AzureKeyCredential(api_key),
            seed =self.cache_seed
            )
        else:
            self.client = OpenAIWrapper(config_list=config_list, cache_seed=cache_seed)
        
        sys_prompt = BASE_PROMPT
        if "o1" in config_list[0]['model'] or "o3" in config_list[0]['model'] or "r1" in config_list[0]['model']:
            sys_prompt = O1_PROMPT
            #raise ValueError("O1 and O3 models prompt is not set for ReactAgent")
        self.messages = [{"role": "system", "content": sys_prompt}]

        self.max_steps = max_steps
        self.submit_summary = submit_summary
        self.step_count = 0
        self.retry_num = retry_num
        self.retry_wait_time = retry_wait_time
        self.totoal_usage = {}
        
    @property
    def name(self):
        return "ReactAgent"

    def _call_llm(self, messages):
        
        if "ai_foundry" not in self.config_list[0]['api_type']:
            response = call_llm(
                client=self.client, 
                model=self.config_list[0]['model'],
                messages=messages,
                retry_num=self.retry_num,
                retry_wait_time=self.retry_wait_time,
                temperature=self.temperature,
                stop=["Observation:", "observation:"]
            )
            update_model_usage(self.totoal_usage, model_name=response.model, usage_dict=response.usage.model_dump())
        elif "ai_foundry" in self.config_list[0]['api_type']:
            response = call_llm_foundry(
                client=self.client, 
                model=self.config_list[0]['model'],
                messages=messages,
                retry_num=self.retry_num,
                retry_wait_time=self.retry_wait_time,
                temperature=self.temperature,
                stop=["Observation:", "observation:"]
            )
            update_model_usage(self.totoal_usage, model_name=response.model, usage_dict=response.usage.as_dict())
        
        return response.choices[0].message.content
        
    def act(self, observation: str):
        self._add_message(observation, role="user")
        response = self._call_llm(messages=self.messages)
        print(response)

        if self.step_count >= self.max_steps-1 and self.submit_summary:
            summary_prompt = "You have reached maximum number of steps. Please summarize your findings of key information, and sumbit them."
            self._add_message(summary_prompt, role="system")

        split_str = "\nAction:"
        if "**Action:**" in response:
            split_str = "\n**Action:**"
        try:
            thought, action = response.strip().split(split_str)
            self._add_message(response.strip(), role="assistant")
        except:
            print("\nRetry Split Action:")
            thought = response.strip()
            action = self._call_llm(self.messages + [msging(f"{thought}\nAction:")])
            print(action)
            action = action.strip()
            if not "Thought" in thought:
                thought = f"Thought: {thought}"
            self._add_message(f"{thought}\nAction:{action}", role="assistant")
        
        print("*"*50)

        self.step_count += 1
        # parse the action
        parsed_action, is_code, submit = sql_parser(action)
        
        # submit = True if "submit" in thought.lower() else False
        return parsed_action, submit
    
    def get_logging(self):
        return {
            "messages": self.messages,
            "usage_summary": self.totoal_usage,
        }
    
    def _add_message(self, msg: str, role: str="user"):
        self.messages.append(msging(msg, role))

    def reset(self, change_seed=True):
        if change_seed:
            self.cache_seed += 1
        
        if "ai_foundry" in self.config_list[0]['api_type']:
            from secgym.config_key import api_key
            self.client = ChatCompletionsClient(
            endpoint= self.config_list[0]['endpoint'],
            credential=AzureKeyCredential(api_key),
            seed =self.cache_seed
            )
        else:
            self.client = OpenAIWrapper(config_list=self.config_list, cache_seed=self.cache_seed)

        self.step_count = 0
        sys_prompt = BASE_PROMPT
        if "o1" in self.config_list[0]['model'] or "o3" in self.config_list[0]['model'] or "r1" in self.config_list[0]['model']:
            sys_prompt = O1_PROMPT
            #raise ValueError("O1 and O3 models prompt is not set for ReactAgent")
        self.messages = [{"role": "system", "content": sys_prompt}]
        self.totoal_usage = {}
