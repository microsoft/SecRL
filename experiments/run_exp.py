# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
from datetime import datetime
import time
from typing import Union
import os
from secgym.excytin_env import ExcytinEnv, ATTACKS
from secgym.evaluator import LLMEvaluator, Evaluator
from secgym.myconfig import CONFIG_LIST
from secgym.qagen.alert_graph import AlertGraph
import argparse
from secgym.agents import BaselineAgent, PromptSauceAgent, MultiModelBaselineAgent, ReActAgent, PromptSauceReflexionAgent, ReActReflexionAgent, ExpelAgent

#config_list_4_turbo, config_list_35

def run_experiment(
        agent,
        thug_env: ExcytinEnv,
        save_agent_file: str,
        num_test: Union[int, None] = None,
        num_trials: int = 1,
        overwrite: bool = False,
        trial_run: bool = False,
    ):
    if num_test is None:
        num_test = thug_env.num_questions
    if trial_run:
        overwrite = True

    accum_reward = 0
    accum_success = 0
    accum_logs = []
    tested_num = 0
    tested_question_keys = set()

    # load logs if not overwrite
    if not overwrite and os.path.exists(save_agent_file):
        with open(save_agent_file, "r") as f:
            accum_logs = json.load(f)
            accum_reward = sum([log["reward"] for log in accum_logs])
            accum_success = sum([log["reward"]==1 for log in accum_logs])
            tested_num = len(accum_logs)
            tested_question_keys = set([log["nodes"] for log in accum_logs])
            print(f"Loaded logs from {save_agent_file}")
        
    for i in range(thug_env.num_questions):
        #emptying the replay buffer for each question
        if agent.name == "ReActReflexionAgent" or agent.name == "PromptSauceReflexionAgent":
            agent.replay_buffer = []
        tested_num += 1 # increment tested number of questions

        is_solved = False
        trials_dict = {}
        for tid in range(num_trials):
            if i == num_test:
                print(f"Tested {num_test} questions. Stopping...")
                break
            
            # reset environment and agent
            observation, _ = thug_env.reset(i) # first observation is question dict
            if agent.name == "ExpelAgent":
                agent.reset(question_dict=thug_env.curr_question)
            else:
                agent.reset()

            # check if question has been tested before
            current_question_key = f"{thug_env.curr_question['start_alert']}-{thug_env.curr_question['end_alert']}"
            if current_question_key in tested_question_keys:
                # get the log for the question
                for log in accum_logs:
                    if log.get("nodes") == current_question_key:
                        trials_dict = log["trials"]
                        break
                # make sure the trials_dict reaches the number of trials
                if len(trials_dict) >= num_trials:
                    is_solved = True
                    print(f"Skipping question with key {current_question_key}")
                    break

            # run one episode
            for s in range(thug_env.max_steps):
                print(f"Observation: {observation}")
                print("*"*50)
                try:
                    action, submit = agent.act(observation)
                except Exception as e:
                     # Check if it's an Anthropic rate limit error
                    if "anthropic.RateLimitError" in str(type(e).__module__ + "." + type(e).__name__) or \
                       (hasattr(e, 'status_code') and e.status_code == 429) or \
                       "rate_limit_error" in str(e).lower():
                        print(f"Rate limit error encountered. Waiting 120 seconds before retry...")
                        time.sleep(120)
                        action, submit = agent.act(observation)
                    else:
                        raise e # comment this to continue on error
                        print(f"Error: {e}")
                        info = {}
                        reward = 0
                        break
                observation, reward, _, info = thug_env.step(action=action, submit=submit)

                if submit:
                    break
            
            # for Reflexion Agent
            if agent.name == "ReActReflexionAgent" or agent.name == "PromptSauceReflexionAgent":
                # saving replay in agent memory
                replay = {
                    "messages": agent.messages,
                    "incident": agent.incident,
                    "question": thug_env.curr_question,
                    "reward": reward,
                    "trial": tid,
                }
                agent.replay_buffer.append(replay)
            

            trials_dict[tid] = {
                "reward": reward,
                "info": info,
            }
            trials_dict[tid].update(agent.get_logging())

            # correct answer found -> stop trials
            if reward == 1:
                print(f"Skipping question {i+1} as it has been solved")
                break
        
        if is_solved:
            continue

        #saving logs
        result_dict = {
            "nodes": current_question_key,
            "reward": reward,
            "question_dict": thug_env.curr_question,
            "trials": trials_dict,
        }
        accum_logs.append(result_dict)
        accum_reward += reward
        accum_success += reward == 1

        with open(save_agent_file, "w") as f:
            json.dump(accum_logs, f, indent=4)
        print(f"Question {i+1} | Reward: {reward} || Accumlated Success: {accum_success}/{tested_num}={accum_success/(tested_num):.3f} | Avg Reward so far: {accum_reward/(tested_num):.3f}")  
        print("*"*50, "\n", "*"*50)

        if trial_run and tested_num >= 2:
            print("Trial run completed, stopping after 2 questions.")
            break
    
    return accum_success, tested_num, accum_reward

#TODO: fix eval step default value
def get_args():
    parser = argparse.ArgumentParser(description="Run Experienments")
    parser.add_argument("--model", "-m", type=str, default="gpt-4.1-nano", help="Model to use for experiment")
    parser.add_argument("--eval_model", "-e", type=str, default="gpt-4.1", help="Model to use for evaluation")
    parser.add_argument("--cache_seed", type=int, default=131, help="Seed for the cache")
    parser.add_argument("--temperature", type=int, default=0, help="Temperature for the model")
    parser.add_argument("--max_steps", type=int, default=15, help="Maximum number of steps for the agent")
    parser.add_argument("--layer", type=str, default="alert", help="Layer to use for the agent")
    #parser.add_argument("--step_checking", action="store_true", help="Evaluate each step")
    parser.add_argument("--agent", type=str, default="baseline", help="Agent to use for the experiment")
    parser.add_argument("--num_trials", type=int, default=1, help="Number of trials to run for each question if not solved")
    parser.add_argument("--split", type=str, default="test", help="Split to use for the experiment")
    parser.add_argument("--full_db", action="store_true", help="Use full database for the experiment. Need to setup 'AlphineSkiHouse' database first.")
    parser.add_argument("--trial_run", action="store_true", help="Run the experiment in trial mode, will only run 2 questions from the first attack")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite the saved agent file if it exists")
    args = parser.parse_args()
    return args

from autogen import LLMConfig
def filter_config_list(config_list, model_name):
    config_list = LLMConfig(*config_list).where(tags=[model_name]).config_list
    if len(config_list) == 0:
        raise ValueError(f"model {model_name} not found in the config list, please put 'tags': ['{model_name}'] in the config list to inicate this model")
    return config_list

if __name__ == "__main__":
    # curr_time = datetime.now().strftime("%Y%m%d-%H%M%S")
    args = get_args()

    model = args.model
    eval_model = args.eval_model
    cache_seed = args.cache_seed
    temperature = args.temperature
    max_steps = args.max_steps
    assert args.layer in ["log", "alert", "alert_only"], "Layer must be either 'log' or 'alert'"
    layer = args.layer
    num_trials = args.num_trials
    use_full_db = args.full_db

    agent_config_list = filter_config_list(CONFIG_LIST, model)
    eval_config_list = filter_config_list(CONFIG_LIST, eval_model)

    llmevaluator = LLMEvaluator(
        config_list=eval_config_list, 
        cache_seed=cache_seed,
        ans_check_reflection=True, 
        sol_check_reflection=True,
        step_checking=True,
        strict_check=False,
    )

    agent_map = {
        "baseline": BaselineAgent,
        "react": ReActAgent,
        "prompt_sauce": PromptSauceAgent,
        "ps_reflexion": PromptSauceReflexionAgent,
        "react_reflexion": ReActReflexionAgent,
    }

    if args.agent in agent_map:
        test_agent = agent_map[args.agent](
            config_list=agent_config_list,
            cache_seed=cache_seed, 
            temperature=temperature,
            max_steps=max_steps,
        )
    elif args.agent == "multi_model_baseline":
        agent_config_list_master = filter_config_list(CONFIG_LIST, "o3-mini")
        test_agent = MultiModelBaselineAgent(
            config_list_master=agent_config_list_master,
            config_list_slave=agent_config_list,
            cache_seed=cache_seed, 
            temperature=temperature,
            max_steps=max_steps,
        )
    elif args.agent == "expel":
        test_agent = ExpelAgent(
            config_list=agent_config_list,
            insight_path="agents/expel_train/insights.json", # TODO:
            experience_path="agents/expel_train/corrects.jsonl",
            cache_seed=cache_seed,
            temperature=temperature,
            max_steps=max_steps,
        )
    else:
        raise ValueError(f"Invalid agent name: {args.agent}, please modify run_exp.py to include the agent")

    base_dir = "final_results"
    os.makedirs(base_dir, exist_ok=True)
    agent_name = test_agent.name

    if use_full_db:
        sub_dir = f"{agent_name}_{model}_c{cache_seed}_full_db_{layer}_level_t{temperature}_s{max_steps}_trial{num_trials}"
    else:
        sub_dir = f"{agent_name}_{model}_c{cache_seed}_{layer}_level_t{temperature}_s{max_steps}_trial{num_trials}"
    if args.split != "test":
        sub_dir += f"_{args.split}"
    os.makedirs(f"{base_dir}/{sub_dir}", exist_ok=True)

    for attack in ATTACKS:
        print(f"Running attack: {attack}")
        save_agent_file = f"{base_dir}/{sub_dir}/agent_{attack}.json" 
        save_env_file = f"{base_dir}/{sub_dir}/env_{attack}.json"

        thug_env = ExcytinEnv(
            attack=attack,
            evaluator=llmevaluator,
            save_file=save_env_file,
            max_steps=max_steps,
            split=args.split,
            use_full_db=use_full_db,
            layer=layer,
        )
        
        avg_success, tested_num, avg_reward = run_experiment(
            agent=test_agent,
            thug_env=thug_env,
            save_agent_file=save_agent_file,
            num_test=-1, # set to -1 to run all questions
            num_trials=num_trials,
            overwrite=args.overwrite,
            trial_run=args.trial_run,
        )

        if args.trial_run:
            break

        with open(f'{base_dir}/{sub_dir}/results.txt', 'a') as f:
            f.write(f"Model: {model}, Attack: {attack}, Agent: {agent_name}, Cache Seed: {cache_seed}, Temperature: {temperature}, Layer: {layer}, Max Steps: {max_steps}, Eval Model: {eval_model}, Num Trials: {num_trials}\n")
            f.write(f"Success: {avg_success}/{tested_num}={avg_success/tested_num:.3f}, Avg Reward: {avg_reward/tested_num:.3f}\n")
    