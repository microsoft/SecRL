# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Bounded, version-bound model episodes over an already admitted private cohort."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import fcntl
import json
import os
from pathlib import Path
import tempfile
from typing import Literal, Protocol

from pydantic import model_validator

from .acesevals_adapter import export_aces_task, register_aces_strategy
from .azure_generation import AzureGenerationConfig
from .contracts import Contract, EvaluationRecord, Identifier, PositiveInt, TaskRecord, ValidationReport, fingerprint
from .evidence import EvidenceVerifier
from .generation import BlindSolution, CompletionClient, DiscoveryTools, RoleAbstained, run_role
from .ledger import file_sha256
from .pilot import BLIND_INSTRUCTIONS
from .query import Engine, QueryFailure, QueryLimits, QueryResult
from .secrl_adapter import SecRLV1Env, Submission


PANEL_VERSION = "matched-model-panel-v1"
RUNTIME_FILES = (
    "model_panel.py", "azure_generation.py", "generation.py", "pilot.py", "contracts.py",
    "query.py", "evidence.py", "qualified_witnesses.py", "scoring.py", "mysql_serving.py",
    "secrl_adapter.py", "acesevals_adapter.py",
)


class PanelProfile(Contract):
    profile_version: Literal["matched-model-panel-v1"] = PANEL_VERSION
    engine: Engine = "mysql"
    reasoning_effort: Literal["low", "medium", "high"] = "medium"
    max_responses: PositiveInt = 64
    max_output_tokens: PositiveInt = 64000
    response_output_tokens: PositiveInt = 16000
    request_timeout_seconds: PositiveInt = 300
    query_limits: QueryLimits = QueryLimits(max_rows=500, max_bytes=65536, timeout_ms=30000)

    @model_validator(mode="after")
    def bounded_response(self):
        if self.response_output_tokens > self.max_output_tokens:
            raise ValueError("per-response output limit cannot exceed the episode limit")
        return self


class ConfiguredClient(CompletionClient, Protocol):
    config: AzureGenerationConfig


class EpisodeBudgetExhausted(RuntimeError):
    pass


def runtime_hashes():
    return {name: file_sha256(Path(__file__).with_name(name)) for name in RUNTIME_FILES}


def immutable_json(path: Path, value: Contract | dict) -> None:
    data = value.model_dump(mode="json") if isinstance(value, Contract) else json.loads(json.dumps(value, allow_nan=False))
    if path.exists():
        if json.loads(path.read_text()) != data:
            raise ValueError(f"immutable panel artifact changed: {path.name}")
        return
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", prefix=".panel-", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(data, stream, indent=2, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def response_usage(directory: Path) -> dict:
    responses = []
    for path in sorted(directory.glob("*-response.json")):
        value = json.loads(path.read_bytes())
        usage = value.get("usage")
        if not isinstance(usage, dict):
            raise ValueError("model response is missing explicit usage accounting")
        output = usage.get("output_tokens", usage.get("completion_tokens"))
        inputs = usage.get("input_tokens", usage.get("prompt_tokens"))
        if any(type(number) is not int or number < 0 for number in (output, inputs)):
            raise ValueError("model response usage counts must be nonnegative integers")
        reasoning = (usage.get("output_tokens_details") or usage.get("completion_tokens_details") or {}).get("reasoning_tokens")
        if reasoning is not None and (type(reasoning) is not int or reasoning < 0 or reasoning > output):
            raise ValueError("invalid reported reasoning-token count")
        responses.append({"response": path.name, "input_tokens": inputs, "output_tokens": output,
                          "reasoning_tokens": reasoning, "reported_model": (value.get("azure_responses") or {}).get("model")})
    return {
        "responses": len(responses), "input_tokens": sum(row["input_tokens"] for row in responses),
        "output_tokens": sum(row["output_tokens"] for row in responses),
        "reasoning_tokens": sum(row["reasoning_tokens"] for row in responses) if all(
            row["reasoning_tokens"] is not None for row in responses
        ) else None,
        "calls": responses,
    }


class BoundedClient:
    def __init__(self, client: ConfiguredClient, profile: PanelProfile, directory: Path):
        self.client, self.profile, self.directory = client, profile, directory
        client.config = AzureGenerationConfig(
            env_file=client.config.env_file, deployment=client.config.deployment,
            timeout_seconds=profile.request_timeout_seconds, max_completion_tokens=profile.response_output_tokens,
            reasoning_effort=profile.reasoning_effort,
        )

    def complete(self, messages: list[dict], tools: list[dict]) -> dict:
        usage = response_usage(self.directory)
        remaining = self.profile.max_output_tokens - usage["output_tokens"]
        if usage["responses"] >= self.profile.max_responses or remaining <= 0:
            raise EpisodeBudgetExhausted("the pinned episode response/output-token budget is exhausted")
        self.client.config = self.client.config.model_copy(update={
            "max_completion_tokens": min(self.profile.response_output_tokens, remaining),
        })
        return self.client.complete(messages, tools)


@dataclass(frozen=True)
class CapturedAction:
    kind: Literal["sql", "finding"]
    argument: str
    result: QueryResult | QueryFailure | None


def captured_actions(directory: Path) -> tuple[CapturedAction, ...]:
    actions = []
    for path in sorted(directory.glob("*-response.json")):
        response = json.loads(path.read_bytes())
        choices = response.get("choices", [])
        if len(choices) != 1:
            raise ValueError("captured response lacks one unambiguous choice")
        results_path = path.with_name(path.name.replace("-response.json", "-tool-results.json"))
        if choices[0].get("finish_reason") not in ("stop", "tool_calls"):
            if results_path.exists():
                raise ValueError("incomplete model output must not have executed tool results")
            continue
        calls = choices[0]["message"].get("tool_calls") or []
        if not results_path.exists():
            if not calls or (len(calls) == 1 and calls[0]["function"]["name"] == "abstain"):
                continue
            raise ValueError("captured tool boundary is incomplete; explicit recovery is required")
        results = json.loads(results_path.read_bytes())
        if len({call["id"] for call in calls}) != len(calls) or len(results) != len(calls):
            raise ValueError("captured tool/result cardinality mismatch")
        by_id = {result["tool_call_id"]: result for result in results}
        if len(by_id) != len(results) or by_id.keys() != {call["id"] for call in calls}:
            raise ValueError("captured tool results do not match their response")
        for call in calls:
            function = call["function"]
            result = json.loads(by_id[call["id"]]["content"])
            try:
                arguments = json.loads(function["arguments"])
            except json.JSONDecodeError:
                if "error" not in result:
                    raise ValueError("invalid tool arguments were incorrectly marked successful")
                continue
            if function["name"] == "sql":
                if not isinstance(arguments, dict) or set(arguments) != {"query"} or not isinstance(arguments["query"], str):
                    if "error" not in result:
                        raise ValueError("malformed SQL call was marked successful")
                    continue
                if "error" in result:
                    captured = QueryFailure(result["error"], result["detail"])
                else:
                    if set(result) != {"columns", "rows", "truncated"} or result["truncated"] is not False:
                        raise ValueError("captured SQL result is incomplete or has an unknown shape")
                    captured = QueryResult(tuple(result["columns"]), tuple(tuple(row) for row in result["rows"]))
                    if any(len(row) != len(captured.columns) for row in captured.rows):
                        raise ValueError("captured SQL row/column counts differ")
                actions.append(CapturedAction("sql", arguments["query"], captured))
            elif function["name"] == "record_finding" and "error" not in result:
                if result != {"finding_recorded": True}:
                    raise ValueError("unexpected finding acknowledgment")
                submission = Submission.model_validate_json(function["arguments"])
                actions.append(CapturedAction("finding", submission.model_dump_json(), None))
    return tuple(actions)


def _native_replay(task, validation, verifier, actions, submission, output, run_id):
    from saber.config.models import TaskConfig
    from saber.scoring.aggregation import aggregate_scorer_results
    from saber.scoring.context import ScoringContext
    from saber.scoring.registry import ScoringStrategyRegistry

    environments = {}
    for backend in ("secrl", "acesevals"):
        env = SecRLV1Env(
            task, verifier, validation, run_id=f"{run_id}-{backend}", trajectory_ref=str(output / f"{backend}.json"),
            max_steps=len(actions) + 1, backend=backend, log_path=output / f"{backend}.json",
            admission="private_pilot", captured_results=True,
        )
        for action in actions:
            if action.kind == "sql":
                if not isinstance(action.result, (QueryResult, QueryFailure)):
                    raise ValueError("captured SQL action lacks its original result")
                env.replay_query(action.argument, action.result)
            else:
                env.record_finding(action.argument)
        environments[backend] = env
    payload = submission.model_dump_json() if submission is not None else ""
    result = environments["secrl"].finish_for_scorer(payload)
    ace = environments["acesevals"]
    exported = export_aces_task(task, instruction_template="secrl-v1-instructions.j2", max_steps=len(actions) + 1)
    config = TaskConfig.model_validate(exported["tasks"][0])
    registry = ScoringStrategyRegistry()
    register_aces_strategy(registry, {ace.run_id: ace})
    scores = {}
    for scorer in config.scorers:
        context = ScoringContext(
            submission=payload, tool_steps=(), messages=(), target="", task_id=config.task_id,
            domain="excytin", metadata={"secrl_run_id": ace.run_id}, scorer=scorer,
        )
        scores[scorer.scorer_name] = asyncio.run(registry.get(scorer.strategy).score(context, None)).value
    aggregate, _ = aggregate_scorer_results(scorer_configs=config.scorers, raw_scores=scores, agg_config=config.scoring_aggregation)
    if ace.evaluation is None:
        raise ValueError("native ACE did not produce an evaluation")
    for name in ("status", "answer_correctness", "final_evidence", "checkpoints", "grounded_final",
                 "checkpoint_progress", "aggregate_reward"):
        if getattr(result, name) != getattr(ace.evaluation, name):
            raise ValueError("captured SecRL/native ACE evaluation components differ")
    if aggregate != result.aggregate_reward or result.status != "complete":
        raise ValueError("captured evaluation did not complete with matching native aggregate")
    immutable_json(output / "evaluation.json", result)
    return result


def _role_hashes(directory: Path) -> dict[str, str]:
    return {path.name: file_sha256(path) for path in sorted(directory.glob("*.json"))}


def _read_grade(output: Path, role: Path, task: TaskRecord, run_id: str) -> EvaluationRecord:
    grade = json.loads((output / "grade.json").read_bytes())
    if grade["role_artifacts_sha256"] != _role_hashes(role):
        raise ValueError("graded episode trace changed")
    for name, digest in grade["artifacts_sha256"].items():
        path = (output / name).resolve()
        if not path.is_relative_to(output.resolve()) or file_sha256(path) != digest:
            raise ValueError("graded episode artifact changed")
    evaluation = EvaluationRecord.model_validate_json(json.dumps(grade["evaluation"]))
    if evaluation.task_fingerprint != fingerprint(task) or evaluation.run_id != f"{run_id}-secrl":
        raise ValueError("grade belongs to another episode")
    return evaluation


def run_episode(
    *, task: TaskRecord, validation: ValidationReport, verifier: EvidenceVerifier,
    client: ConfiguredClient, profile: PanelProfile, output: Path, run_id: Identifier,
    manifest_fingerprint: str, resume: bool = False, grading_verifier: EvidenceVerifier | None = None,
    recorded_from: Path | None = None,
) -> dict:
    if output.exists() and not resume:
        raise ValueError("model episode output must be new unless explicitly resumed")
    output.mkdir(parents=True, mode=0o700, exist_ok=resume)
    with (output / "episode.lock").open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("this model episode is already owned by another runner") from error
        return _run_episode(task=task, validation=validation, verifier=verifier, client=client, profile=profile,
                            output=output, run_id=run_id, manifest_fingerprint=manifest_fingerprint, resume=resume,
                            grading_verifier=grading_verifier, recorded_from=recorded_from)


def _run_episode(
    *, task: TaskRecord, validation: ValidationReport, verifier: EvidenceVerifier,
    client: ConfiguredClient, profile: PanelProfile, output: Path, run_id: Identifier,
    manifest_fingerprint: str, resume: bool, grading_verifier: EvidenceVerifier | None,
    recorded_from: Path | None,
) -> dict:
    profile = PanelProfile.model_validate(profile)
    if validation.pilot_blockers(task) or task.dataset_release != "v1-private-pilot":
        raise ValueError("model panel requires the exact admitted private task revision")
    if verifier.engine.engine != profile.engine or verifier.engine.limits != profile.query_limits:
        raise ValueError("episode backend/query limits differ from the pinned model profile")
    if client.config.timeout_seconds != profile.request_timeout_seconds:
        raise ValueError("the configured HTTP timeout differs from the profile")
    grader = grading_verifier or verifier
    if (grader.report != verifier.report or grader.allowed_literals != verifier.allowed_literals
        or grader.engine.engine != profile.engine
        or grader.engine.limits.max_rows != profile.query_limits.max_rows
        or grader.engine.limits.max_bytes != profile.query_limits.max_bytes):
        raise ValueError("separate grading may change only the query timeout, not the source or result policy")
    binding = {
        "panel_version": PANEL_VERSION, "run_id": run_id, "manifest_fingerprint": manifest_fingerprint,
        "task_fingerprint": fingerprint(task), "validation_fingerprint": fingerprint(validation),
        "model": client.config.deployment, "profile": profile.model_dump(mode="json"),
        "serving_view_id": task.serving_view_id, "implementation_sha256": runtime_hashes(),
        "allowed_literals": sorted(verifier.allowed_literals),
        "release_approved": False,
    }
    if grading_verifier is not None:
        binding["grading_query_limits"] = grader.engine.limits.model_dump(mode="json")
    if recorded_from is not None:
        if recorded_from.resolve() == output.resolve():
            raise ValueError("a retained recording must remain separate from its new grading output")
        binding["student_trace_from"] = str((recorded_from / "student").resolve())
        binding["source_episode_binding_sha256"] = file_sha256(recorded_from / "binding.json")
    immutable_json(output / "binding.json", binding)
    role = recorded_from / "student" if recorded_from is not None else output / "student"
    if (output / "episode.json").exists():
        result = json.loads((output / "episode.json").read_bytes())
        if result["binding_sha256"] != file_sha256(output / "binding.json") or result["role_artifacts_sha256"] != _role_hashes(role):
            raise ValueError("completed episode binding or captured trace changed")
        if result.get("evaluation_sha256") is not None and result["evaluation_sha256"] != file_sha256(output / "grade.json"):
            raise ValueError("completed episode evaluation changed")
        if result.get("evaluation_sha256") is not None:
            _read_grade(output, role, task, run_id)
        return result
    terminal_path = output / "termination.json"
    if terminal_path.exists():
        terminal = json.loads(terminal_path.read_bytes())
        if terminal["role_artifacts_sha256"] != _role_hashes(role):
            raise ValueError("terminated episode trace changed")
        status, detail = terminal["status"], terminal["detail"]
        solved = BlindSolution.model_validate_json((role / "result.json").read_bytes()) if terminal["solution_fingerprint"] is not None else None
        if solved is not None and fingerprint(solved) != terminal["solution_fingerprint"]:
            raise ValueError("terminated episode solution changed")
        usage = response_usage(role)
        return _finish_episode(task, validation, grader, output, run_id, binding, role, status, detail, solved, usage)
    if recorded_from is not None:
        prior = json.loads((recorded_from / "binding.json").read_bytes())
        for key in ("run_id", "task_fingerprint", "validation_fingerprint", "model", "profile",
                    "serving_view_id", "allowed_literals"):
            if prior[key] != binding[key]:
                raise ValueError("retained student belongs to a different task, model or student profile")
        original_terminal = json.loads((recorded_from / "termination.json").read_bytes())
        complete = json.loads((role / "complete.json").read_bytes())
        solved = BlindSolution.model_validate_json((role / "result.json").read_bytes())
        first = json.loads((role / "0000-request.json").read_bytes())
        if (original_terminal["status"] != "completed"
            or original_terminal["role_artifacts_sha256"] != _role_hashes(role)
            or complete["result_fingerprint"] != fingerprint(solved)
            or original_terminal["solution_fingerprint"] != fingerprint(solved)
            or json.loads(first["messages"][1]["content"]) != task.public_task().model_dump(mode="json")):
            raise ValueError("retained completed student has an invalid completion or context binding")
        immutable_json(output / "recording-source.json", {
            "directory": str(recorded_from.resolve()), "binding_sha256": file_sha256(recorded_from / "binding.json"),
            "termination_sha256": file_sha256(recorded_from / "termination.json"),
            "role_artifacts_sha256": _role_hashes(role), "model_calls": 0,
        })
        immutable_json(terminal_path, original_terminal)
        return _finish_episode(task, validation, grader, output, run_id, binding, role,
                               original_terminal["status"], original_terminal["detail"], solved, response_usage(role))
    requests = sorted(role.glob("*-request.json"))
    if requests and not (role / "complete.json").exists():
        last = requests[-1]
        response = last.with_name(last.name.replace("-request.json", "-response.json"))
        tools = last.with_name(last.name.replace("-request.json", "-tool-results.json"))
        if not response.exists() or not tools.exists() or (role / "result.json").exists() or (role / "abstention.json").exists():
            raise ValueError("interrupted episode has an ambiguous completion boundary; no automatic model retry")
        saved = json.loads(response.read_bytes())
        results = json.loads(tools.read_bytes())
        finishes = {call["id"] for call in saved["choices"][0]["message"].get("tool_calls") or []
                    if call["function"]["name"] == "finish"}
        if any(result["tool_call_id"] in finishes and json.loads(result["content"]).get("accepted") is True
               for result in results):
            raise ValueError("accepted finish needs explicit completion recovery; never request another model answer")
    bounded = BoundedClient(client, profile, role)
    instructions = BLIND_INSTRUCTIONS + (
        f"\nThis evaluation permits at most {profile.max_responses} model responses and "
        f"{profile.max_output_tokens} total output tokens, including reasoning. "
        "Use finish or abstain before exhausting the budget. No private scoring feedback is available."
    )
    solved = None
    detail = None
    try:
        solved = run_role(
            bounded, DiscoveryTools(verifier.engine, verifier.tables, record_findings=True),
            "panel-student", instructions, task.public_task().model_dump(mode="json"),
            BlindSolution, role, resume=resume,
        )
        status = "completed"
    except EpisodeBudgetExhausted as error:
        status, detail = "budget_exhausted", str(error)
    except RoleAbstained as error:
        status, detail = "abstained", str(error)
    except (RuntimeError, ValueError) as error:
        responses = sorted(role.glob("*-response.json"))
        last = json.loads(responses[-1].read_bytes()) if responses else {}
        native = last.get("azure_responses") or {}
        if native.get("status") == "incomplete" and (native.get("incomplete_details") or {}).get("reason") == "max_output_tokens":
            status = "budget_exhausted"
        elif last.get("choices") and last["choices"][0].get("finish_reason") == "stop" and not last["choices"][0]["message"].get("tool_calls"):
            status = "invalid_completion"
        else:
            status = "operational_error"
        detail = f"{type(error).__name__}: {error}"
    usage = response_usage(role)
    if usage["responses"] > profile.max_responses or usage["output_tokens"] > profile.max_output_tokens or any(
        call["output_tokens"] > profile.response_output_tokens for call in usage["calls"]
    ):
        status, detail = "operational_error", "provider output exceeded the requested matched budget"
    immutable_json(terminal_path, {
        "status": status, "detail": detail, "role_artifacts_sha256": _role_hashes(role),
        "solution_fingerprint": fingerprint(solved) if solved is not None else None,
    })
    return _finish_episode(task, validation, grader, output, run_id, binding, role, status, detail, solved, usage)


def _finish_episode(task, validation, verifier, output, run_id, binding, role, status, detail, solved, usage):
    evaluation = None
    if status != "operational_error":
        grade_path = output / "grade.json"
        if grade_path.exists():
            evaluation = _read_grade(output, role, task, run_id)
        else:
            actions = captured_actions(role)
            submission = Submission(answer=solved.answer, citations=solved.citations) if solved is not None else None
            grading = output / "grading"
            grading.mkdir(exist_ok=True)
            index = 0
            while (grading / f"attempt-{index:04d}").exists():
                index += 1
            attempt = grading / f"attempt-{index:04d}"
            attempt.mkdir(mode=0o700)
            try:
                evaluation = _native_replay(task, validation, verifier, actions, submission, attempt, run_id)
            except (ValueError, RuntimeError, QueryFailure) as error:
                immutable_json(attempt / "error.json", {"error_type": type(error).__name__, "detail": str(error)})
                raise
            immutable_json(grade_path, {
                "evaluation": evaluation.model_dump(mode="json"), "role_artifacts_sha256": _role_hashes(role),
                "artifacts_sha256": {str(path.relative_to(output)): file_sha256(path) for path in sorted(attempt.glob("*.json"))},
            })
    if runtime_hashes() != binding["implementation_sha256"]:
        raise ValueError("model panel runtime changed during an episode")
    result = {
        "panel_version": PANEL_VERSION, "status": status, "detail": detail, "model": binding["model"],
        "task_id": task.task_id, "task_fingerprint": fingerprint(task), "run_id": run_id,
        "binding_sha256": file_sha256(output / "binding.json"), "role_artifacts_sha256": _role_hashes(role),
        "usage": usage, "evaluation_sha256": file_sha256(output / "grade.json") if evaluation is not None else None,
        "grounded_final": evaluation.grounded_final if evaluation is not None else None,
        "answer_correctness": evaluation.answer_correctness.score if evaluation is not None else None,
        "final_evidence": evaluation.final_evidence.score if evaluation is not None else None,
        "checkpoint_progress": evaluation.checkpoint_progress if evaluation is not None else None,
        "reward": evaluation.aggregate_reward if evaluation is not None else None,
        "existing_student_outcomes_changed": False, "release_approved": False,
    }
    if "student_trace_from" in binding:
        result["student_trace_from"] = binding["student_trace_from"]
    immutable_json(output / "episode.json", result)
    return result
