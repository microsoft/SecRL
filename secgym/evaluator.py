from autogen import OpenAIWrapper
import json
import re
from secgym.myconfig import config_list_4o
from secgym.utils.utils import msging, get_full_question
from textwrap import dedent

EVAL_ANSWER_TEMPLATE = dedent("""Question: {question}
                              
Golden Answer: {golden_answer}
                              
Submitted Answer: {submitted_answer}""")

FUZZY_ANSWER_CHECK_PROMPT = dedent("""Given a golden answer to a security question and a submitted answer, please evaluate whether the submitted answer matches the golden answer.
You are given:
- The question
- The golden answer
- The submitted answer
                                   
Note:
The submitted answer does not need to match the golden answer exactly. But the key content should be present.
If the submitted answer presents the golden answer along with additional context, it should be considered correct.
If the submitted answer is an overly large enumeration (>15 is the strict limit) that includes the golden answer and lacks relevance, it should be considered false. All enumerations less than 10 and containing the golden answer should be considered correct. Between 10 and 15, use your discretion to determine if the answer is relevant enough to be considered correct.
If the format of the submitted answer is different from the golden answer but the meaning is the same, it should be considered as true. Ignore the case of the text.
For time-based questions, the submitted answer should be within a reasonable time frame of the golden answer and the format of the timestamps is not required to match exactly.
For domain-specific questions, the submitted answer should contain the key information mentioned in the golden answer. Ignore differences in http/https, www, and trailing slashes in URLs. 
In case you find discrepancies between the question and the golden answer, please consider the golden answer as the ground truth as you do not have full context of the question.

Examples:
Example 1
Golden Answer: notepad.exe
Submitted Answer: notepad is running
Analysis: Although the submitted answer is lacking the ".exe" extension, it is correct because the file name is correct, which is the key information.
Is_Answer_Correct: True

Example 2
Golden Answer: vnevado-win11u
Submitted Answer: The hostnames of the target devices involved in the 'CommandAndControl' malware attempts are: 'vnevado-win10s', 'vnevado-win10r', 'vnevado-win11t', and 'vnevado-win11u'. 
Analysis: The submitted answer is correct because it contains the golden answer along with additional context that is useful for the investigation since it provides the hostnames of all the target devices in the network that were targetted by the command and control malware.
Is_Answer_Correct: True

Example 3
Golden Answer: 72.153.24.3
Submitted Answer: These are the IP addresses are related to this incident: [72.153.24.3, 43.22.123.45, 293.56.765.54, 99.24.34.28, ....]
Analysis: The submitted answer is incorrect because it contains too many IP addresses, potentially all that are in the database. It will be hard to conduct further investigation with this information.
Is_Answer_Correct: False                                   
                                   
First give a brief analysis using 1-2 short sentences, then give your decision.
Follow this format:
Analysis: <your analysis>
Is_Answer_Correct: <"True" or "False">       
""" )

FUZZY_ANSWER_CHECK_REFLECTION_PROMPT = """Given a golden answer and a submitted answer, please evaluate whether the submitted answer matches the golden answer.
You are given:
- The question
- The golden answer
- The submitted answer
You are also given a previous evaluation of this submitted answer. Reflect on it and serve as a second reviewer to double-check whether the answer is correct.

Note:
The submitted answer does not need to match the golden answer exactly. But the key content should be present.
If the submitted answer presents the golden answer along with additional context, it should be considered correct.
If the submitted answer is an overly large enumeration (>15 is the strict limit) that includes the golden answer and lacks relevance, it should be considered false. All enumerations less than 10 and containing the golden answer should be considered correct. Between 10 and 15, use your discretion to determine if the answer is relevant enough to be considered correct.
If the format of the submitted answer is different from the golden answer but the meaning is the same, it should be considered as true. Ignore the case of the text.
For time-based questions, the submitted answer should be within a reasonable time frame of the golden answer and the format of the timestamps is not required to match exactly.
For domain-specific questions, the submitted answer should contain the key information mentioned in the golden answer. Ignore differences in http/https, www, and trailing slashes in URLs.
In case you find discrepancies between the question and the golden answer, please consider the golden answer as the ground truth as you do not have full context of the question.

Examples:
Example 1
Golden Answer: notepad.exe
Submitted Answer: notepad is running
Analysis: Although the submitted answer is lacking the ".exe" extension, it is correct because the file name is correct, which is the key information.
Is_Answer_Correct: True

Example 2
Golden Answer: vnevado-win11u
Submitted Answer: The hostnames of the target devices involved in the 'CommandAndControl' malware attempts are: 'vnevado-win10s', 'vnevado-win10r', 'vnevado-win11t', and 'vnevado-win11u'. 
Analysis: The submitted answer is correct because it contains the golden answer along with additional context that is useful for the investigation since it provides the hostnames of all the target devices in the network that were targetted by the command and control malware.
Is_Answer_Correct: True

Example 3
Golden Answer: 72.153.24.3
Submitted Answer: These are the IP addresses are related to this incident: [72.153.24.3, 43.22.123.45, 293.56.765.54, 99.24.34.28, ....]
Analysis: The submitted answer is incorrect because it contains too many IP addresses, potentially all that are in the database. It will be hard to conduct further investigation with this information.
Is_Answer_Correct: False  

Follow this format:
Reflection: <your reflection on previous evaluation>
Analysis: <your analysis>
Is_Answer_Correct: <"True" or "False", whether the submitted answer is correct>       
"""

STRICT_ANSWER_CHECK_PROMPT = dedent("""Given a golden answer to a security question and a submitted answer, please evaluate whether the submitted answer matches the golden answer without ambiguity.
- if the submitted answer gives several possible answers, you should mark it as False no matter if the golden answer is one of the answers.
                                    
You are given:
- The question
- The golden answer
- The submitted answer

First give a brief analysis using 1-2 short sentences, then give your decision.
Follow this format:
Analysis: <your analysis>
Is_Answer_Correct: <"True" or "False">       
""" )

STRICT_ANSWER_CHECK_REFLECTION_PROMPT = """Given a golden answer to a security question and a submitted answer, please evaluate whether the submitted answer matches the golden answer without ambiguity.
- if the submitted answer gives several possible answers, you should mark it as False even if the golden answer is one of the answers.

You are given:
- The question
- The golden answer
- The submitted answer
You are also given a previous evaluation of this submitted answer. Reflect on it and serve as a second reviewer to double-check whether the answer is correct.

Follow this format:
Reflection: <your reflection on previous evaluation>
Analysis: <your analysis>
Is_Answer_Correct: <"True" or "False", whether the submitted answer is correct>       
"""


# -----------------------------------
# ---- Solution Evaluation ----

EVAL_SOLUTION_TEMPLATE = dedent("""Question: {question}
                                
Golden Solution: 
{golden_solution}
                                
Submitted Answer: 
{submitted_answer}""")

STEP_CHECK_PROMPT = """Given a security question, a submitted answer, and a ground truth solution, please evaluate the correctness of the submitted answer.
The ground truth solution may contain several steps. Please go through each step of the ground truth solution and evaluate whether the given answer correctly contains key info (the Indicator of Comprise) of that step, which is usually enclosed in `< >`.
Note:
- If the format of the submitted answer is different from the golden answer but the meaning is the same, it should be considered as true.
- The key information should not be the ones that is already present in the question.
         
Your response should be in JSON format:
{
    "<step_i>" : {
            "analysis": "<your analysis>",
            "is_step_correct": "<"True" or "False">,
        },
    ...
}
step_i is the step number from the ground truth solution, starting from 0. 
For each step, you must have two fields:
- `analysis`: a quick analysis of whether this step is correct.
- `is_step_correct`: whether the answer matches the key info from this step.
"""

STEP_CHECK_REFLECTION_PROMPT = """Given a security question, a submitted answer, and a ground truth solution, please evaluate the correctness of the submitted answer.
The ground truth solution may contain several steps. Please go through each step of the ground truth solution and evaluate whether the given answer correctly contains key info (the Indicator of Comprise) of that step, which is usually enclosed in `< >`.
Note:
- If the format of the submitted answer is different from the golden answer but the meaning is the same, it should be considered as true.
- The key information should not be the ones that is already present in the question.

You are also given a previous evaluation of this submitted answer. Reflect on it and serve as a second reviewer to double-check whether the answer is correct.

Your response should be in JSON format:
{
    "<step_i>" : {
            "analysis": "<your analysis>",
            "is_step_correct": "<"True" or "False">,
        },
    ...
}
step_i is the step number from the ground truth solution, starting from 0. 
For each step, you must have three fields:
- `analysis`: your reflection on the previous evaluation, and a quick analysis of whether this step is correct.
- `is_step_correct`: whether the answer matches the key info from this step.
"""

class Evaluator:
    def __init__(self):
        pass

    def checking(self, question: dict, submitted_answer: str) -> dict:
        """Check the correctness of the submitted answer.
        Args:
            question (dict): The question dictionary containing the question, answer, and solution.
            submitted_answer (str): The submitted answer to be evaluated.

        Returns:
            dict: A dictionary containing the evaluation results. Must have "reward" key.
        """
        raise NotImplementedError("Please implement the checking method in your evaluator class.")


class StaticEvaluator(Evaluator):
    def __init__(self):
        pass
    
    def checking(self, question: dict, submitted_answer: str) -> dict:
        # string matching
        if question["answer"].strip() == submitted_answer.strip():
            return {"reward": 1}
        return {"reward": 0}



class LLMEvaluator(Evaluator):
    def __init__(self,
                 config_list,
                 cache_seed: int = 41,
                 ans_check_reflection: bool = False,
                 sol_check_reflection: bool = False,
                 step_checking: bool = False,
                 strict_check: bool = False,
                 verbose: bool = False
                 ) -> None:
        #print(config_list)
        self.llm_config = {
            "config_list": config_list,
            "cache_seed": cache_seed,
        }
        self.cache_seed = cache_seed
        self.use_llm = True
        self.ans_check_reflection = ans_check_reflection
        self.sol_check_reflection = sol_check_reflection
        self.step_checking = step_checking
        self.strict_check = strict_check
        self.verbose = verbose

        if strict_check:
            self.ans_check_prompt = STRICT_ANSWER_CHECK_PROMPT
            self.ans_check_reflection_prompt = STRICT_ANSWER_CHECK_REFLECTION_PROMPT
        else:
            self.ans_check_prompt = FUZZY_ANSWER_CHECK_PROMPT
            self.ans_check_reflection_prompt = FUZZY_ANSWER_CHECK_REFLECTION_PROMPT
    
    def _retry_create(self, messages, match_pattern=None, **kwargs):
        """Retry at None response, or no match pattern found"""
        tmp_config = self.llm_config.copy()
        tmp_config.update(kwargs)
        for i in range(10):
            tmp_config["cache_seed"] = self.cache_seed+i
            client = OpenAIWrapper(**tmp_config)
            response = client.create(messages=messages)
            if response.choices[0].message.content is not None:
                if match_pattern is not None:
                    results = re.search(match_pattern, response.choices[0].message.content)
                    if results is not None:
                        break
                else:
                    break
        return response
    
    def _get_json_response(
        self,
        system_prompt,
        task,
    ):
        messages=[
            msging(system_prompt, role="system"), 
            msging(task, role="user")
        ]
        for i in range(10):
            try:
                tmp_config = self.llm_config.copy()
                tmp_config["cache_seed"] = self.cache_seed+10+i
                client = OpenAIWrapper(**tmp_config)
                response = client.create(
                    messages=messages,
                    response_format= { "type": "json_object" }
                ).choices[0].message.content
                if "```json" in response:
                    print("Spearating ```json placeholder")
                    response = response.split("```json")[1].split("```")[0]
                response = json.loads(response)
                for _, v in response.items():
                    v["is_step_correct"]
                break
            except Exception as e:
                print(f"Error: {e}: {response}, retry {i+1} time.")
        
        self.llm_config["cache_seed"] = self.cache_seed
        if not isinstance(response, dict):
            print("Failed to get response")
            return response, False
        return response, True
    
    def checking(self, 
                 question: dict, 
                 submitted_answer: str, 
                 step_checking: bool = None
                 ) -> dict:
        step_checking = step_checking if step_checking is not None else self.step_checking
        # 1. Check if the answer is correct
        eval_dict = self.check_single_response(question, submitted_answer)
        if eval_dict["reward"] == 1:
            return eval_dict
        if "solution" not in question or not step_checking:
            if "solution" not in question:
                print("Warning: No solution in the question. Skipping solution checking...")
            return eval_dict
        
        # 2. Check if the solution is correct
        eval_dict.update(self.check_solution(question, submitted_answer))
        return eval_dict

    def check_solution(self,
                       question: dict,
                       submitted_answer: str
                       ) -> dict:
            
            eval_dict = {}
            # 2. Check if the solution is correct
            if isinstance(question["solution"], list):
                golden_solution = ""
                for i, s in enumerate(question["solution"]):
                    golden_solution += f"Step {i}: {s}\n"
            else:
                golden_solution = question["solution"]

            solution_str = EVAL_SOLUTION_TEMPLATE.format(question=get_full_question(question), golden_solution=golden_solution, submitted_answer=submitted_answer) 
            response, is_json_success = self._get_json_response(STEP_CHECK_PROMPT, solution_str)
            eval_dict["is_json_success"] = is_json_success
            eval_dict["check_sol_response"] = response

            # if failed,return
            if not is_json_success:
                return eval_dict
            
            if self.verbose:
                print("Ground Truth Solution:")
                for k in question["solution"]:
                    print(k)
                print(f"-----> Solution Evaluation Result:\n {str(response)}\n--------------------")

            if self.sol_check_reflection:
                reflection_str = solution_str + "\n" + json.dumps(response)
                reflect_reponse, is_reflect_success = self._get_json_response(STEP_CHECK_REFLECTION_PROMPT, reflection_str)
                if self.verbose:
                    print(f"-----> Solution Evaluation Reflection: \n{str(response)}\n--------------------")
                eval_dict["is_reflect_success"] = is_reflect_success
                eval_dict["check_sol_reflection"] = reflect_reponse
                if not is_reflect_success:
                    return eval_dict
                else:
                    response = reflect_reponse
            
            # calculate the reward based on the response
            discount_factor = 0.4
            # reverse the response

            total_reward = 0
            step_eval = []
            for _, v in response.items():
                step_eval.append(v["is_step_correct"])
            # step_eval = list(response.values())
            step_eval.reverse()

            # starting from the last second step
            current_reward = discount_factor
            for b in step_eval[1:]:  # skip the last step as it is the final answer
                if b == "True":
                    total_reward += current_reward
                if total_reward >= 1: # cap the reward to 1 if discount_factor is too large
                    total_reward = 1
                    break
                current_reward *= discount_factor

            eval_dict["reward"] = total_reward
            # 1 2 3 4
            # False  False False True -> 1
            # False False True  False -> 0.3
            # True True True False -> 0.3     # 0.3 + 0.09 + 0.027 = 0.417
            # all false
            return eval_dict

    def check_single_response(self, question: dict, submitted_answer: str) -> dict:
        # Call LLM to evaluate the answer
        input_str = EVAL_ANSWER_TEMPLATE.format(question=get_full_question(question), golden_answer=question["answer"], submitted_answer=submitted_answer)
        match_pattern = r"Is_Answer_Correct: (True|False)"
        response = self._retry_create(messages=[
                msging(self.ans_check_prompt, role="system"), 
                msging(input_str, role="user")
            ],
            match_pattern=match_pattern
        )

        # Parse the response
        response = response.choices[0].message.content
        decision = re.search(match_pattern, response)
        decision = decision.group(1)
        if self.verbose:
            print("Ground Truth Answer:", question["answer"])
            print(f"-----> Answer Evaluation Result: {response}")
        return_dict = {"check_ans_response": response, "reward": int(decision == "True")}

        # Reflection
        if self.ans_check_reflection:
            messages=[
                msging(self.ans_check_reflection_prompt, role="system"), 
                msging(input_str+"\n"+response, role="user")
            ]
            reflect_response = self._retry_create(messages=messages, match_pattern=match_pattern).choices[0].message.content

            decision = re.search(match_pattern, reflect_response)
            decision = decision.group(1)
            return_dict["check_ans_reflection"] = reflect_response
            return_dict['reward'] = int(decision == "True")
            if self.verbose:
                print(f"-----> Answer Evaluation Reflection: {reflect_response}")
        return return_dict
 