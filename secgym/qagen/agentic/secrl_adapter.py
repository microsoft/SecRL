# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Opt-in SecRL reset/step adapter; never loads legacy agents, datasets or connections."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Literal

import duckdb
from pydantic import ValidationError

from .contracts import Contract, EvaluationRecord, PublicCitation, ScoreComponent, TaskRecord, TypedAnswer, ValidationReport
from .evidence import EvidenceFailure, EvidenceVerifier, Finding, VERIFIER_VERSION
from .query import QueryFailure, QueryResult, checked_select
from .mysql_serving import mysql_column_name
from .scoring import aggregate_evaluation


class Submission(Contract):
    answer: TypedAnswer
    citations: tuple[PublicCitation, ...]


class SecRLV1Env:
    def __init__(self, task: TaskRecord, verifier: EvidenceVerifier, validation: ValidationReport, *,
                 run_id: str, trajectory_ref: str, max_steps: int, backend: Literal["secrl", "acesevals"] = "secrl",
                 log_path: Path | None = None, admission: Literal["release", "private_pilot"] = "release",
                 captured_results: bool = False):
        if admission not in ("release", "private_pilot"):
            raise ValueError("unknown evaluation admission mode")
        if admission == "private_pilot" and task.dataset_release != "v1-private-pilot":
            raise ValueError("private-pilot admission requires an explicitly unreleased pilot task")
        blockers = validation.pilot_blockers(task) if admission == "private_pilot" else validation.release_blockers(task)
        if blockers:
            raise ValueError("task is not admitted: " + "; ".join(blockers))
        if type(max_steps) is not int or max_steps <= 0:
            raise ValueError("max_steps must be positive")
        if backend not in ("secrl", "acesevals"):
            raise ValueError("unsupported evaluation backend")
        verifier.preflight(task)
        self._task, self._verifier = task, verifier
        self.run_id, self.trajectory_ref, self.max_steps = run_id, trajectory_ref, max_steps
        self.backend: Literal["secrl", "acesevals"] = backend
        self.adapter_version = "secrl-env-v1" if backend == "secrl" else "aces-native-v1"
        if type(captured_results) is not bool:
            raise ValueError("captured-results mode must be explicit")
        self.captured_results = captured_results
        if captured_results:
            self.adapter_version = "secrl-captured-v1" if backend == "secrl" else "aces-captured-v1"
        self.admission = admission
        self._base_run_id, self._episode_number = run_id, 0
        self.log_path = log_path
        if log_path is not None and log_path.exists():
            raise ValueError("episode log output must be a new file")
        self.all_logs: list[dict] = []
        self.curr_question = task.public_task().model_dump(mode="json")
        self.reset()

    def reset(self, idx=0, save_log=True):
        if idx != 0:
            raise ValueError("this version-bound episode has exactly one task")
        if getattr(self, "curr_trajectory", None):
            self.all_logs.append(self.get_logging())
            self._episode_number += 1
            self.run_id = f"{self._base_run_id}:{self._episode_number}"
        self.step_count, self.done = 0, False
        self.curr_trajectory: list[dict] = []
        self._findings: list[Finding] = []
        self._observed: dict[PublicCitation, int] = {}
        self.evaluation: EvaluationRecord | None = None
        self._submission: str | None = None
        if save_log:
            self.save_logging()
        return json.dumps(self.curr_question), {"task_id": self._task.task_id, "revision_id": self._task.revision_id}

    def getAllQuestions(self):
        return [self._task.public_task().model_dump(mode="json")]

    def get_table_names(self):
        return [(name,) for name in sorted(self._verifier.engine.tables)]

    def get_schema(self, table_name: str):
        if table_name not in self._verifier.tables:
            raise ValueError("table is not in the public schema")
        columns = self._verifier.tables[table_name]["columns"]
        if self._verifier.engine.engine == "mysql":
            return [{**column, "name": mysql_column_name(column["name"]), "source_column": column["name"]} for column in columns]
        return columns

    def _record(self, action, observation, reward, done, info):
        self.curr_trajectory.append({"action": action, "observation": observation, "reward": reward, "done": done, "info": info})
        self.step_count += 1
        self.done = done
        if done:
            self.save_logging()
        return observation, reward, done, info

    def record_finding(self, payload: str):
        if self.done or self.step_count >= self.max_steps:
            raise ValueError("episode has no remaining finding steps")
        try:
            value = Submission.model_validate_json(payload)
            self._findings.append(Finding(answer=value.answer, citations=value.citations, step=self.step_count))
        except ValidationError as error:
            return self._record(payload, {"error": "invalid_finding", "detail": str(error)}, 0.0, False,
                                {"submit": False, "query_success": False, "error_code": "invalid_finding"})
        return self._record(payload, {"finding_recorded": True}, 0.0, False, {"submit": False, "query_success": True})

    def _error_result(self, error: Exception) -> EvaluationRecord:
        code = error.code if isinstance(error, QueryFailure) else "evidence_validation"

        def failed(cid: str, kind: Literal["answer_correctness", "final_evidence", "checkpoint"],
                   maximum: float = 1.0, weight: float = 1.0) -> ScoreComponent:
            return ScoreComponent(
                component_id=cid, kind=kind, status="error", score=None, max_score=maximum, weight=weight,
                evidence=(), trajectory_steps=(), first_completion_step=None, explanation=str(error),
                evaluator_version=VERIFIER_VERSION, error_code=code,
            )
        return aggregate_evaluation(
            self._task, run_id=self.run_id, backend=self.backend, trajectory_ref=self.trajectory_ref,
            backend_adapter_version=self.adapter_version,
            answer_correctness=failed("final-answer", "answer_correctness"), final_evidence=failed("final-evidence", "final_evidence"),
            checkpoints=tuple(failed(c.checkpoint_id, "checkpoint", c.max_score, c.weight) for c in self._task.private_gold.checkpoints),
        )

    def finish_for_scorer(self, payload: str) -> EvaluationRecord:
        if self.evaluation is not None:
            if payload != self._submission:
                raise ValueError("a completed episode cannot be rescored with a different submission")
            return self.evaluation
        self._submission = payload
        finding = None
        try:
            value = Submission.model_validate_json(payload)
            finding = Finding(answer=value.answer, citations=value.citations, step=self.step_count)
        except ValidationError as error:
            self.curr_trajectory.append({
                "action": payload, "observation": {"error": "invalid_submission", "detail": str(error)},
                "reward": None, "done": True, "info": {"submit": True, "query_success": False, "error_code": "invalid_submission"},
            })
        try:
            grounded_findings = []
            for recorded in self._findings:
                if recorded.citations and all(c in self._observed for c in recorded.citations):
                    steps = tuple(sorted({recorded.step, *(self._observed[c] for c in recorded.citations)}))
                    grounded_findings.append(Finding(answer=recorded.answer, citations=recorded.citations,
                                                     step=max(steps), support_steps=steps))
            if finding and not all(c in self._observed for c in finding.citations):
                finding = Finding(answer=finding.answer, citations=(), step=finding.step)
            self.evaluation = self._verifier.evaluate(
                self._task, finding, tuple(grounded_findings), run_id=self.run_id,
                backend=self.backend, trajectory_ref=self.trajectory_ref,
                backend_adapter_version=self.adapter_version,
            )
        except (QueryFailure, EvidenceFailure, duckdb.Error) as error:
            self.evaluation = self._error_result(error)
        self.done = True
        self.save_logging()
        return self.evaluation

    def step(self, action: str, submit=False, stringify=True):
        if self.done:
            raise ValueError("reset before using a completed episode")
        if self.captured_results and not submit:
            raise ValueError("captured-results episodes must use replay_query, not reexecute student SQL")
        if submit or self.step_count >= self.max_steps:
            result = self.finish_for_scorer(action if submit else "")
            info = {"submit": True, "query_success": result.status == "complete", "evaluation_status": result.status}
            if result.status != "complete":
                info["error_code"] = "evaluation_unavailable"
            return self._record(action, "Submission evaluated." if result.status == "complete" else "Evaluation unavailable.",
                                result.aggregate_reward, True, info)
        try:
            result = self._verifier.engine.execute(action)
            for citation in self._verifier.observed_citations(result, action):
                self._observed.setdefault(citation, self.step_count)
            observation = {"columns": result.columns, "rows": result.rows}
            return self._record(action, json.dumps(observation) if stringify else observation, 0.0, False,
                                {"submit": False, "query_success": True})
        except QueryFailure as error:
            return self._record(action, {"error": error.code, "detail": str(error)}, 0.0, False,
                                {"submit": False, "query_success": False, "error_code": error.code})

    def replay_query(self, query: str, result: QueryResult | QueryFailure):
        """Credit only validated fields the student actually received, never a later rerun."""
        if not self.captured_results or self.done or self.step_count >= self.max_steps:
            raise ValueError("captured query replay requires an active captured-results episode")
        if isinstance(result, QueryFailure):
            return self._record(query, {"error": result.code, "detail": str(result)}, 0.0, False,
                                {"submit": False, "query_success": False, "error_code": result.code, "captured": True})
        engine = self._verifier.engine
        if len(query.encode()) > engine.limits.max_bytes or len(result.rows) > engine.limits.max_rows or len(
            json.dumps([result.columns, result.rows], ensure_ascii=False, allow_nan=False).encode()
        ) > engine.limits.max_bytes:
            raise ValueError("captured query/result exceeds the bound original SQL limits")
        checked_select(query, engine.engine, set(engine.tables))
        for citation in self._verifier.observed_citations(result, query):
            self._observed.setdefault(citation, self.step_count)
        return self._record(query, {"columns": result.columns, "rows": result.rows}, 0.0, False,
                            {"submit": False, "query_success": True, "captured": True})

    def get_logging(self):
        return {
            "question": self._task.public_task().model_dump(mode="json"), "trajectory": self.curr_trajectory,
            "evaluation": self.evaluation.model_dump(mode="json") if self.evaluation else None,
            "run_id": self.run_id, "task_fingerprint": self.evaluation.task_fingerprint if self.evaluation else None,
            "admission": self.admission, "release_approved": self.admission == "release",
        }

    def save_logging(self):
        if self.log_path is None:
            return
        self.log_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", prefix=".secrl-", dir=self.log_path.parent, delete=False) as stream:
                temporary = Path(stream.name)
                json.dump({"completed_episodes": self.all_logs, "current_episode": self.get_logging()}, stream)
            temporary.replace(self.log_path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
