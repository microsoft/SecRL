# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.


import gymnasium as gym
import numpy as np
import datetime, json, logging, os, re
from typing import Dict, List, Tuple, Union
import docker
import mysql.connector
from datetime import datetime
from time import sleep

from secgym.utils.utils import get_full_question
from secgym.evaluator import LLMEvaluator

ATTACKS = {
    "incident_5": {
        "qafile": "o1/test/incident_5_qa_incident_o1-ga_c42.json",
        "port": "3306",
        "container_name": "incident_5"
    },
    "incident_38": {
        "qafile": "o1/test/incident_38_qa_incident_o1-ga_c42.json",
        "port": "3307",
        "container_name": "incident_38"
    },
    "incident_34": {
        "qafile": "o1/test/incident_34_qa_incident_o1-ga_c42.json",
        "port": "3308",
        "container_name": "incident_34"
    },
    "incident_39": {
        "qafile": "o1/test/incident_39_qa_incident_o1-ga_c42.json",
        "port": "3309",
        "container_name": "incident_39"
    },
    "incident_55": {
        "qafile": "o1/test/incident_55_qa_incident_o1-ga_c42.json",
        "port": "3310",
        "container_name": "incident_55"
    },
    "incident_134": {
        "qafile": "o1/test/incident_134_qa_incident_o1-ga_c42.json",
        "port": "3311",
        "container_name": "incident_134"
    },
    "incident_166": {
        "qafile": "o1/test/incident_166_qa_incident_o1-ga_c42.json",
        "port": "3312",
        "container_name": "incident_166"
    },
    "incident_322": {
        "qafile": "o1/test/incident_322_qa_incident_o1-ga_c42.json",
        "port": "3313",
        "container_name": "incident_322"
    },
}

AlphineSkiHouseInfo = {
    "port": "3314",
    "container_name": "alpineskihouse"
}

def start_container(container_name):
    client = docker.from_env()
    container = client.containers.get(container_name)
    if container.status == "running":
        print(f"Container {container_name} is already running.")
        return container
    else:
        container.start()
        print(f"Restarting stopped container with ID: {container.id}...")
        sleep(3)
        return container


class ExcytinEnv(gym.Env):
    def __init__(
            self,
            attack: Union[str, int],
            evaluator: LLMEvaluator,
            noise_level: int = 0,
            save_file: Union[str, bool] = True,
            max_steps: int = 15,
            max_entry_return: int = 15, # database entry return limit
            max_str_len: int = 100000, # maximum string length to return 100000
            # container_name: str = "mysql-container",
            database_name: str = "env_monitor_db", # sql database name
            # port: str = "3306",
            split: str = "test",
            use_full_db: bool = False,
            layer: str = "alert",
    ):
        self.noise_level = noise_level
        self.max_steps = max_steps
        self.max_entry_return = max_entry_return
        self.max_str_len = max_str_len
        self.layer = layer
        # evaluator
        self.evaluator = evaluator

        if save_file is False:
            print("Warning: No save file provided. Logging will not be saved.")
        else:
            if isinstance(save_file, bool):            
                os.makedirs("results", exist_ok=True)
                # + datetime.now().strftime("%Y%m%d%H%M%S")
                curr_time = datetime.now().strftime("%Y%m%d-%H%M%S")
                self.save_file = f"results/{attack}_noise_{noise_level}_{curr_time}.json"
            else:
                self.save_file = save_file
        print(self.save_file)

        # get questions
        if isinstance(attack, int):
            self.attack = list(ATTACKS.keys())[attack]
        elif isinstance(attack, str):
            if attack not in ATTACKS:
                raise ValueError(f"Attack {attack} not found, please choose from {list(ATTACKS.keys())} or add a new one in the ATTACKS dictionary.")
            self.attack = attack

        attack_info = ATTACKS[self.attack]
        if use_full_db:
            print("Warning: Replace dataset with full dataset.")
            attack_info["port"] = AlphineSkiHouseInfo["port"]
            attack_info["container_name"] = AlphineSkiHouseInfo["container_name"]
        if self.layer == "alert_only":
            attack_info['container_name'] += "_alert_only"
            print(f"Warning: Change container name to {attack_info['container_name']} for alert only, using the same port as {ATTACKS[self.attack]['container_name']}.")

        curr_path = os.path.dirname(os.path.abspath(__file__))
        if split == "test":
            qafile = attack_info["qafile"]
        else:
            qafile = attack_info["qafile"].replace("test", split)
        with open(os.path.join(curr_path, f'questions/{qafile}'), "r") as f:
            self._all_questions = json.load(f)
            self.num_questions = len(self._all_questions)

        # set up container
        self.container_name = attack_info["container_name"]
        self.container = start_container(self.container_name)
        self.connection = mysql.connector.connect(
            host='localhost',
            port=attack_info["port"],
            user='root',
            password='admin'
        )
        if self.connection.is_connected():
            self.cursor = self.connection.cursor()
            self.cursor.execute("SET SESSION MAX_EXECUTION_TIME=30000")
            self.cursor.execute(f"USE {database_name};")
        else:
            raise ValueError("Could not connect to the database.")

        # saved logs
        self.step_count = 0
        self.curr_question: Union[dict, None] = None
        self.curr_trajectory = []
        self.all_logs = []
        if os.path.exists(self.save_file):
            print(f"Warning: Save file {self.save_file} already exists, by default will append to the file.")
            with open(self.save_file, "r") as f:
                self.all_logs = json.load(f)

        self.check_layer(layer)

    def get_attack_list(self):
        """Get the list of attacks.
        """
        return list(ATTACKS.keys())
    
    def get_table_names(self):
        """Get the table names.
        """
        self.cursor.execute("SHOW TABLES;")
        return self.cursor.fetchall()   
    
    def get_schema(self, table_name: str) -> List[Dict]:
        """Get the schema of a table.
        """
        return None

    def getAllQuestions(self) -> List[dict]:
        return self._all_questions

    def get_logging(self):
        success_query_count = 0
        total_query_count = 0
        for step in self.curr_trajectory:
            if not step['info']['submit']:
                total_query_count += 1
                if step['info']['query_success']:
                    success_query_count += 1
        
        return {
            "success": self.curr_trajectory[-1]['reward'] == 1,
            "steps": self.step_count,
            "reward": self.curr_trajectory[-1]['reward'],
            "success_query_count": success_query_count,
            "total_query_count": total_query_count,
            "question": self.curr_question,
            "trajectory": self.curr_trajectory,
        }
    
    def save_logging(self):
        if self.save_file:
            with open(self.save_file, "w") as f:
                json.dump(self.all_logs, f, indent=4)


    def execute_query(self, query: str) -> Tuple[np.ndarray, bool]:
        """Execute a query and return the result.
        """
        try:
            self.cursor.execute(query)
            # print(self.cursor.column_names)
            return self.cursor.fetchall(), True
        except Exception as e:
            return f"{e.__class__.__name__}: {e.__context__}", False

    def step(self, action: str, submit=False, stringify=True) -> Tuple[np.ndarray, float, bool, Dict]:
        """Take a step in the environment.

        Args:
            action (str): The action to take. It should be a SQL query or a string that is the final answer.
            submit (bool, optional): Whether to submit the action. Defaults to False. If set, the final answer should be passed as the action.
            stringify (bool, optional): Whether to stringify the result. Defaults to True.
        
        Returns:
            Tuple[np.ndarray, float, bool, Dict]: The observation, reward, done, and info.

            In info:
                - query_success (bool): Whether the query was run successfully.
                - submit (bool): Whether the action was submitted.
        """
        if self.curr_question is None:
            raise ValueError("Cannot step in the environment without resetting first.")
        
        query_success = True
        if submit:
            observation, reward, done, info = self._submit(action)
        elif self.step_count < self.max_steps:
            try: 
                self.cursor.execute(action)
                observation = self.cursor.fetchall()

                limit_entry = False
                retrieved_len = len(observation)
                if len(str(observation)) > self.max_str_len:
                    if len(observation) > self.max_entry_return:
                        observation = observation[:self.max_entry_return]
                        limit_entry = True
                if stringify:
                    observation = str(observation)
                    if limit_entry:
                        observation = f"Retrieved {retrieved_len} entries. Displaying first {self.max_entry_return} entries.\n{observation}"
            except Exception as e:
                observation = f"{e.__class__.__name__}: {e.__context__}"
                query_success = False

            reward = 0
            done = False
            info = {}
        else:
            print("Warning: Maximum steps reached. Ending the episode.")
            observation = ""
            reward = 0
            done = True
            info = {}
        
        self.step_count += 1
        
        info.update({
            "query_success": query_success,
            "submit": submit
        })

        self.curr_trajectory.append(
            {
                "action": action,
                "observation": observation,
                "reward": reward,
                "done": done,
                "info": info,
            }
        )
        return observation, reward, done, info


    def reset(self, idx=None, save_log=True) -> Tuple[str, Dict]:
        """Reset the environment and return the initial observation.

        Args:
            idx (int, optional): The index of the question to reset to. Defaults to 0
        
        Returns:
            Tuple[str, Dict]: The initial observation and info.
                - observation (str): The initial observation is the question text.
                - info (Dict): The info dictionary with fields "attack" and "noise_level".
        """
        if len(self.curr_trajectory) != 0:
            self.all_logs.append(self.get_logging())
            if save_log:
                self.save_logging()

        if idx is None:
            print(f"Warning: No idx provided for reset. Defaulting to 0.")
            observation =  self._all_questions[0]
        else:
            observation =  self._all_questions[idx]

        self.curr_question = observation
        self.step_count = 0
        self.curr_trajectory = []

        info = {
            "attack": self.attack,
            "noise_level": self.noise_level,
            "qid": idx
        }
    
        return get_full_question(observation), info
    
    def render(self):
        """Render the environment.
        """
        print("Cannot render the environment.")
        pass

    def close(self):
        """Close the environment.
        """
        self.connection.close()
        self.container.stop()

    def _submit(self, answer: str) -> Tuple[np.ndarray, float, bool, Dict]:
        """Submit the answer and return the result.

        Args:
            answer (str): The answer to the question.
        
        Returns:
            Tuple[np.ndarray, float, bool, Dict]: The observation, reward, done, and info.
        """
        eval_dict = self._eval(answer)
        eval_dict['submitted_answer'] = answer
        reward = eval_dict["reward"]
        return "", reward, True, eval_dict

    def _eval(self, answer: str) -> dict:
        """Evaluate the answer and return the score.
        """
        eval_dict = self.evaluator.checking(self.curr_question, answer)
        return eval_dict
    
    def check_layer(self, layer: str) -> None:
        assert layer in ["alert", 'log', 'alert_only'], "Layer should be 'alert', 'log' or 'alert_only'."

        tables, _ = self.execute_query(f"SHOW TABLES;")
        # print(tables)
        # print(type(tables))
        tables = str(tables)

        if layer == "log":
            assert "AlertEvidence" not in tables, "With 'log' level, the table 'AlertEvidence' should not be present."
            assert "AlertInfo" not in tables, "With 'log' level, the table 'AlertInfo' should not be present."
            assert "SecurityAlert" not in tables, "With 'log' level, the table 'SecurityAlert' should not be present."
        elif layer == "alert":
            assert "AlertEvidence" in tables, "With 'alert' level, the table 'AlertEvidence' should be present."
            assert "AlertInfo" in tables, "With 'alert' level, the table 'AlertInfo' should be present."
            assert "SecurityAlert" in tables, "With 'alert' level, the table 'SecurityAlert' should be present."
        elif layer == "alert_only":
            assert "AlertEvidence" in tables, "With 'alert_only' level, the table 'AlertEvidence' should be present."
            assert "AlertInfo" in tables, "With 'alert_only' level, the table 'AlertInfo' should be present."
            assert "SecurityAlert" in tables, "With 'alert_only' level, the table 'SecurityAlert' should be present."
            assert "AADServicePrincipalSignInLogs" not in tables, "With 'alert_only' level, the table 'AADServicePrincipalSignInLogs' should not be present."
            assert "OfficeActivity" not in tables, "With 'alert_only' level, the table 'OfficeActivity' should not be present."
            


if __name__ == "__main__":
    env = ExcytinEnv(attack=1, noise_level=0)
    # print(env.get_table_names())

    query = """SELECT *
FROM OfficeActivity
WHERE Operation = 'MailItemsAccessed'
  AND AppId = '00000003-0000-0000-c000-000000000000';
"""
#     query = """SELECT *
# FROM AADServicePrincipalSignInLogs
# WHERE AppId = 'bb77fe0b-52af-4f26-9bc7-19aa48854ebf';
# """
    result, success = env.execute_query(query)
    
    print(result, len(result))