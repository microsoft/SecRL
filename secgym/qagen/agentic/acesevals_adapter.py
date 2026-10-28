# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""ACE task export and optional native strategy/tools; keep gold in evaluator bindings."""

from importlib import import_module
import json

from .contracts import TaskRecord, fingerprint
from .secrl_adapter import SecRLV1Env


STRATEGY = "secrl_v1"


def aces_task_id(task: TaskRecord) -> str:
    return "secrl_" + fingerprint(task)


def export_aces_task(task: TaskRecord, *, instruction_template: str, max_steps: int) -> dict:
    if not instruction_template.strip():
        raise ValueError("an explicit ACE instruction template is required")
    if max_steps <= 0:
        raise ValueError("max_steps must be positive")
    names = ("reward", "answer_correctness", "final_evidence", "grounded_final",
             *(f"checkpoint_{index + 1}" for index, _ in enumerate(task.private_gold.checkpoints)))
    return {
        "tasks": [{
            "task_id": aces_task_id(task), "title": task.task_id, "description": task.question,
            "prompts": {"instruction": instruction_template},
            "max_steps": max_steps,
            "initial_context": {
                "incident_context": task.context, "question": task.question,
                "answer_format": task.private_gold.final.expected.format.model_dump(mode="json"),
                "submission_protocol": "Submit JSON with answer={format,value} and citations=[{table,record_id}]. Record discoveries with secrl_finding; query only the public SQL tool.",
            },
            "tools": {"secrl_sql": {}, "secrl_finding": {}, "secrl_schema": {}},
            "scoring": {STRATEGY: {name: {"target": "trajectory", "max_score": 1.0, "weight": 1.0} for name in names}},
            # Only the already capped canonical reward participates by default.
            "scoring_aggregation": {"max": {"scores": ["reward"]}},
        }],
    }


class ACESEvalsStrategy:
    def __init__(self, episodes: dict[str, SecRLV1Env]):
        self.episodes = episodes

    async def score(self, ctx, renderer):
        run_id = ctx.metadata.get("secrl_run_id")
        if not isinstance(run_id, str) or run_id not in self.episodes:
            raise ValueError("ACE scorer requires a trusted, per-episode SecRL binding")
        env = self.episodes[run_id]
        if ctx.task_id != aces_task_id(env._task) or env.backend != "acesevals" or env.run_id != run_id:
            raise ValueError("ACE task/episode binding mismatch")
        result = env.finish_for_scorer(ctx.submission)
        if result.status != "complete":
            raise ValueError(f"SecRL evaluation {result.status}; inspect the retained per-component error record")
        name = ctx.scorer.scorer_name
        if name == "reward":
            value = result.aggregate_reward
        elif name == "grounded_final":
            value = float(result.grounded_final)
        else:
            components = {
                "answer_correctness": result.answer_correctness, "final_evidence": result.final_evidence,
                **{f"checkpoint_{i + 1}": c for i, c in enumerate(result.checkpoints)},
            }
            if name not in components:
                raise ValueError("unknown SecRL scorer component")
            component = components[name]
            if component.score is None:
                raise ValueError("component score is incomplete")
            value = component.score / component.max_score
        score_type = import_module("inspect_ai.scorer").Score
        return score_type(value=value * ctx.scorer.max_score, explanation="Source-bound SecRL v1 evaluation.",
                          metadata={"secrl_evaluation": result.model_dump(mode="json")})


def register_aces_strategy(registry, episodes: dict[str, SecRLV1Env]):
    registry.register(STRATEGY, ACESEvalsStrategy(episodes))


def make_aces_tools(env: SecRLV1Env):
    tool = import_module("inspect_ai.tool").tool

    @tool
    def secrl_sql():
        async def execute(query: str):
            """Query the public read-only telemetry database.

            Args:
                query: One SELECT statement.
            """
            observation, _, _, _ = env.step(query, stringify=False)
            return json.dumps(observation)
        return execute

    @tool
    def secrl_finding():
        async def execute(finding: str):
            """Record a factual discovery without revealing private checkpoint feedback.

            Args:
                finding: JSON with a typed answer and public record citations.
            """
            observation, _, _, _ = env.record_finding(finding)
            return json.dumps(observation)
        return execute

    @tool
    def secrl_schema():
        async def execute():
            """List only the public table/column schema."""
            return json.dumps({name: env.get_schema(name) for name, in env.get_table_names()})
        return execute

    return [secrl_sql(), secrl_finding(), secrl_schema()]
