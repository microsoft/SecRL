# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
from datetime import datetime
from typing import Union
import os
from secgym.excytin_env import ATTACKS
from secgym.evaluator import Evaluator, LLMEvaluator
from secgym.myconfig import CONFIG_LIST
from autogen import LLMConfig
from secgym.agents.agent_utils import sql_parser



def run_evaluation(
    evaluator: Evaluator,
    save_agent_file: str,
    save_env_file: str,
    # base_file: str,
    is_update_file: bool = False,
):
    """
    Run evaluation on the agent logs"
    """
    with open(save_agent_file, "r") as f:
        agent_log = json.load(f)
    
    with open(save_env_file, "r") as f:
        env_log = json.load(f)

    reevaluated_count = 0
    changed_reward = 0

    env_log_dict = {f"{env['question']['start_alert']}-{env['question']['end_alert']}": env for env in env_log} 
    new_env_log = []

    for i, agent_log_entry in enumerate(agent_log):
        if "info" in agent_log_entry:
            info = agent_log_entry["info"]
            last_message = agent_log_entry["messages"][-1]['content']
        else:
            info = agent_log_entry['trials']["0"]["info"] # assume only one trial
            last_message = agent_log_entry['trials']["0"]["messages"][-1]['content']
        
        env_entry = None
        if agent_log_entry['nodes'] in env_log_dict:
            env_entry = env_log_dict[agent_log_entry['nodes']]
        if env_entry:
            assert env_entry['question']['question'] == agent_log_entry['question_dict']['question']

        if not info.get("submit", False):
            print(f"question {agent_log_entry['nodes']} | Not submitted", info)
            continue # skip if not submitted
        
        # get env log entry
        # if submit, last action is the submitted answer
        if env_entry:
            submitted_answer = env_entry['trajectory'][-1]['action']
        else:
            submitted_answer, _, _ = sql_parser(last_message)

        old_reward = agent_log_entry["reward"]

        # re-evaluate
        eval_dict = evaluator.checking(question=agent_log_entry["question_dict"], submitted_answer=submitted_answer)
        reevaluated_count += 1

        # ------------------------------------
        info.update(eval_dict) # update info with eval results

        # update agent log entry
        agent_log_entry['reward'] = eval_dict["reward"]
        if "info" in agent_log_entry:
            agent_log_entry["info"] = info
        else:
            agent_log_entry['trials']["0"]["info"] = info
        
        # update env log entry
        if env_entry:
            env_entry['reward'] = eval_dict["reward"]
            env_entry['trajectory'][-1]['reward'] = eval_dict["reward"]
            env_entry['trajectory'][-1]['info'] = info
            new_env_log.append(env_entry)
        
        if eval_dict['reward'] != old_reward:
            changed_reward += 1
            #with open('test.txt', 'a') as sys.stdout:
            print(f"question {agent_log_entry['nodes']} | reward: {old_reward} -> {eval_dict['reward']}")
            print("Submitted Answer", submitted_answer)
            print("Correct Answer", agent_log_entry["question_dict"]['answer'])
            print("Evaluation", eval_dict['check_ans_response'])
            print("Reflection on Explanation", eval_dict['check_ans_reflection'])
            print("---"*50)
        else:
            print(f"question {agent_log_entry['nodes']} | reward: {old_reward} | No change")


    print(f"Re-evaluated {reevaluated_count} questions | Changed reward: {changed_reward}")

    if is_update_file:
        with open(save_agent_file, "w") as f:
            json.dump(agent_log, f, indent=4)
        with open(save_env_file, "w") as f:
            json.dump(new_env_log, f, indent=4)


def filter_config_list(config_list, model_name):
    config_list = LLMConfig(*config_list).where(tags=[model_name]).config_list
    if len(config_list) == 0:
        raise ValueError(f"model {model_name} not found in the config list, please put 'tags': ['{model_name}'] in the config list to inicate this model")
    return config_list

if __name__ == "__main__":
    eval_model = "gpt-4o"
    cache_seed = 133
    temperature = 0
    eval_config_list = filter_config_list(CONFIG_LIST, eval_model)
    evaluator = LLMEvaluator(
        config_list=eval_config_list, 
        ans_check_reflection=True, 
        sol_check_reflection=True,
        step_checking=True,
        strict_check=False,
        verbose=False,
        cache_seed=cache_seed,
    )

    base_files = [
        "BaselineAgent_4o-mini_c71_alert_level_t0_s25_trial1",
        "BaselineAgent_gpt-4o_c70_alert_level_t0_s25_trial1",
        "BaselineAgent_gpt-4o_c102_alert_level_t0_s25_trial1_train",
        "BaselineAgent_gpt-4o-ft-cv1_c102_alert_level_t0_s25_trial1",
        "BaselineAgent_o1-mini_c92_alert_level_t0_s25_trial1",
        "BaselineAgent_o3-mini_c99_alert_level_t0_s25_trial1",

        # new ones: info only in trias['i']['info']
        "MultiModelBaselineAgent_master_o1_mini_slave_gpt-4o_c96_alert_level_t0_s25_trial1",
        "MultiModelBaselineAgent_master_o1_slave_gpt-4o_c98_alert_level_t0_s25_trial1",
        "MultiModelBaselineAgent_master_o3_mini_slave_gpt-4o_c100_alert_level_t0_s25_trial1",
    ]


    for base_file in base_files:
        print(f"Running evaluation for {base_file}")
        for attack in ATTACKS:
            print(f"Running evaluation for {attack}")
            # avg_success, tested_num, avg_reward = 
            run_evaluation(
                evaluator=evaluator,
                save_agent_file=f"./final_results/{base_file}/agent_{attack}.json",
                save_env_file=f"./final_results/{base_file}/env_{attack}.json",
                #base_file=base_file,
                is_update_file=True,
            )