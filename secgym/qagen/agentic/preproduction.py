# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Pinned source waves and logical-attempt accounting; source readiness is not admission."""

from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
import fcntl
import hashlib
import json
from pathlib import Path
from typing import Literal

import duckdb
from pydantic import Field, model_validator

from .batch import DevelopmentAttempt, development_attempts
from .contracts import Contract, Digest, Identifier, SELECTED_INCIDENTS, TaskRecord, Text, fingerprint, require_unique
from .generation import RoleAbstained
from .ledger import file_sha256
from .model_panel import immutable_json
from .pilot import run_discovery_pilot
from .quality import runtime_hashes as quality_runtime_hashes
from .query import QueryLimits


VERSION = "preproduction-source-waves-v1"


class ModelBinding(Contract):
    deployment: Literal["gpt-6-sol"]
    endpoint_sha256: Digest
    api_version: Text
    request_timeout_seconds: int = Field(gt=0)
    max_completion_tokens: int = Field(gt=0)
    reasoning_effort: Literal["low", "medium", "high"] | None


class PreproductionPlan(Contract):
    policy_version: Literal["preproduction-source-waves-v1"] = VERSION
    batch_id: Identifier
    serving_view_id: Identifier
    graph_id: Identifier
    serving_report_sha256: Digest
    graph_report_sha256: Digest
    native_snapshot_sha256: Digest | None = None
    native_indexes_sha256: Digest | None = None
    model: ModelBinding
    query_limits: QueryLimits
    grader_timeout_ms: int | None = Field(default=None, gt=0)
    checkpoint_cap: float = Field(gt=0, lt=1)
    seed_questions: tuple[TaskRecord, ...] = Field(min_length=1)
    implementation_sha256: dict[str, Digest]
    incident_target: Literal[50] = 50
    tenant_target: Literal[500] = 500
    incident_attempt_ceiling: Literal[100] = 100
    tenant_attempt_ceiling: Literal[1000] = 1000
    overlap_admission_cap: None = None
    difficulty_admission_quota: None = None
    release_approved: Literal[False] = False

    @model_validator(mode="after")
    def fixed_scope(self):
        if (self.native_snapshot_sha256 is None) != (self.native_indexes_sha256 is None):
            raise ValueError("native snapshot and index bindings must be supplied together")
        require_unique(tuple(task.task_id for task in self.seed_questions), "frozen/seed question IDs")
        if any(task.serving_view_id != self.serving_view_id or task.graph_version != self.graph_id
               for task in self.seed_questions):
            raise ValueError("preproduction novelty context must use the pinned source snapshot")
        if any(task.task_id.startswith(self.batch_id + "-") for task in self.seed_questions):
            raise ValueError("new logical attempt namespace collides with existing questions")
        return self

    def attempts(self) -> tuple[DevelopmentAttempt, ...]:
        return development_attempts(self.batch_id, self.incident_attempt_ceiling, self.tenant_attempt_ceiling)


class SourceOutcome(Contract):
    plan_fingerprint: Digest
    attempt_binding_sha256: Digest
    attempt: DevelopmentAttempt
    status: Literal["source_ready", "needs_revision", "no_supported_candidate", "operational_error"]
    task_fingerprint: Digest | None
    reason: Text
    artifact_sha256: dict[str, Digest]
    accepted_question: Literal[False] = False
    release_approved: Literal[False] = False


def runtime_hashes() -> dict[str, str]:
    return {**quality_runtime_hashes(),
            "preproduction.py": file_sha256(Path(__file__)),
            "batch.py": file_sha256(Path(__file__).with_name("batch.py")),
            "model_panel.py": file_sha256(Path(__file__).with_name("model_panel.py")),
            "preproduction_admission.py": file_sha256(Path(__file__).with_name("preproduction_admission.py")),
            "preproduction_revisions.py": file_sha256(Path(__file__).with_name("preproduction_revisions.py"))}


def configured_model_binding(client) -> ModelBinding:
    from dotenv import dotenv_values

    values = dotenv_values(client.config.env_file)
    endpoint, api_version = values.get("AZUREAI_OPENAI_BASE_URL"), values.get("AZUREAI_OPENAI_API_VERSION")
    if not endpoint or not endpoint.startswith("https://") or not api_version:
        raise ValueError("preproduction requires the explicit approved HTTPS Azure endpoint and API version")
    return ModelBinding(
        deployment=client.config.deployment, endpoint_sha256=hashlib.sha256(endpoint.encode()).hexdigest(),
        api_version=api_version, request_timeout_seconds=client.config.timeout_seconds,
        max_completion_tokens=client.config.max_completion_tokens, reasoning_effort=client.config.reasoning_effort,
    )


def _bucket(attempt: DevelopmentAttempt) -> str:
    return f"incident:{attempt.incident_id}" if attempt.mode == "incident" else "tenant"


def _artifacts(directory: Path) -> dict[str, str]:
    return {str(path.relative_to(directory)): file_sha256(path) for path in sorted(directory.rglob("*.json"))}


def _check_artifacts(directory: Path, expected: dict[str, str]) -> None:
    if _artifacts(directory) != expected:
        raise ValueError("retained source attempt artifacts changed")


def safe_unfinished_roles(directory: Path) -> None:
    """Only recorded, nonterminal boundaries may return to model inference."""
    for role in sorted({path.parent for path in directory.rglob("*-request.json")}):
        requests = sorted(role.glob("*-request.json"))
        if (role / "complete.json").exists():
            if not (role / "result.json").exists():
                raise ValueError("completed role is missing its result; explicit recovery required")
            continue
        if (role / "result.json").exists() or (role / "abstention.json").exists():
            raise ValueError("terminal role requires explicit completion recovery, not another model call")
        last = requests[-1]
        response_path = last.with_name(last.name.replace("-request.json", "-response.json"))
        results_path = last.with_name(last.name.replace("-request.json", "-tool-results.json"))
        if not response_path.exists():
            raise ValueError("model completion outcome is ambiguous; no automatic retry")
        if not results_path.exists():
            raise ValueError("incomplete response/tool boundary requires explicit recovery")
        response = json.loads(response_path.read_bytes())
        results = json.loads(results_path.read_bytes())
        choices = response.get("choices", [])
        if len(choices) != 1:
            raise ValueError("resumed response lacks a unique completion")
        finishes = {call["id"] for call in choices[0]["message"].get("tool_calls") or []
                    if call["function"]["name"] == "finish"}
        if any(result["tool_call_id"] in finishes and json.loads(result["content"]).get("accepted") is True
               for result in results):
            raise ValueError("an accepted finish must be recovered without resampling")


@contextmanager
def locked_run(output: Path, *, wait: bool = False):
    """Wait only for short metadata transactions; whole-run ownership remains fail-fast."""
    with (output / "run.lock").open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX if wait else fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("this preproduction run already has an owning worker") from error
        yield


def source_progress(plan: PreproductionPlan, output: Path) -> dict:
    from .preproduction_revisions import current_source

    buckets = {f"incident:{incident}": {
        "target_validated_new": plan.incident_target, "logical_attempt_ceiling": plan.incident_attempt_ceiling,
    } for incident in SELECTED_INCIDENTS}
    buckets["tenant"] = {"target_validated_new": plan.tenant_target, "logical_attempt_ceiling": plan.tenant_attempt_ceiling}
    outcomes = []
    historical = []
    revision_counts = Counter()
    started = Counter()
    expected_ids = {attempt.task_id for attempt in plan.attempts()}
    if any(path.name not in expected_ids for path in (output / "attempts").glob("*") if path.is_dir()):
        raise ValueError("unallocated logical attempts exist outside the approved envelope")
    for attempt in plan.attempts():
        path = output / "attempts" / attempt.task_id
        if not (path / "attempt.json").exists():
            continue
        binding = json.loads((path / "attempt.json").read_bytes())
        if binding["plan_fingerprint"] != fingerprint(plan) or binding["attempt"] != attempt.model_dump(mode="json"):
            raise ValueError("logical attempt binding changed")
        started[_bucket(attempt)] += 1
        if (path / "source-outcome.json").exists():
            _, outcome, revisions = current_source(plan, output, attempt.task_id)
            if outcome is None:
                raise ValueError("recorded source outcome is unavailable")
            outcomes.append(outcome)
            revision_counts[_bucket(attempt)] += revisions
            historical.append(SourceOutcome.model_validate_json((path / "source-outcome.json").read_bytes()))
            for receipt in sorted((path / "revisions").glob("*/revision.json")):
                historical.append(SourceOutcome.model_validate_json((receipt.parent / "source-outcome.json").read_bytes()))
    for bucket, counts in buckets.items():
        selected = [outcome for outcome in outcomes if _bucket(outcome.attempt) == bucket]
        history = [outcome for outcome in historical if _bucket(outcome.attempt) == bucket]
        states = Counter(outcome.status for outcome in selected)
        counts.update({
            "logical_attempts_started": started[bucket], "source_outcomes_recorded": len(selected),
            "source_ready": states["source_ready"], "quality_holds": states["needs_revision"],
            "source_insufficiency": states["no_supported_candidate"], "operational_errors": states["operational_error"],
            "unfinished_attempts": started[bucket] - len(selected),
            "remaining_logical_attempts": counts["logical_attempt_ceiling"] - started[bucket],
            "attempt_budget_exhausted": started[bucket] == counts["logical_attempt_ceiling"],
            "validated_new_questions": 0, "source_ready_is_not_admission": True,
            "validated_shortfall": counts["target_validated_new"],
            "source_candidate_yield": states["source_ready"] / len(selected) if selected else None,
            "source_revisions": revision_counts[bucket],
            "historical_quality_holds": sum(value.status == "needs_revision" for value in history),
            "model_requests": sum(sum(name.endswith("-request.json") for name in value.artifact_sha256) for value in history),
            "model_responses": sum(sum(name.endswith("-response.json") for name in value.artifact_sha256) for value in history),
            "compile_repair_events": sum(sum(name.startswith("compile-failure-") for name in value.artifact_sha256) for value in history),
        })
    return {
        "policy_version": VERSION, "plan_fingerprint": fingerprint(plan),
        "buckets": buckets, "logical_attempts_started": sum(started.values()),
        "source_outcomes_recorded": len(outcomes), "source_ready": sum(o.status == "source_ready" for o in outcomes),
        "validated_new_questions": 0,
        "remaining_required_stages": ["native", "backend_robustness", "objective_duplicate_review", "canonical_facts", "difficulty"],
        "source_capacity_exhausted": False, "admission_performed": False, "release_approved": False,
    }


def run_source_wave(
    *, plan: PreproductionPlan, client, serving_bundle: Path, graph_bundle: Path,
    output: Path, wave_size: int, resume: bool = False, runner=run_discovery_pilot,
) -> dict:
    plan = PreproductionPlan.model_validate(plan)
    from .preproduction_revisions import current_source, effective_runtime
    if (output / "checkpoint-revalidation-required.json").exists():
        raise ValueError("checkpoint revalidation is pending; legacy source-wave generation is blocked")
    if type(wave_size) is not int or wave_size <= 0:
        raise ValueError("wave size must be a positive number of logical attempts")
    if effective_runtime(plan, output) != runtime_hashes() or configured_model_binding(client) != plan.model:
        raise ValueError("preproduction model or source-quality runtime differs from its pinned plan")
    serving_report = serving_bundle / "serving_report.json"
    graph_report = graph_bundle / "graph_report.json"
    if (file_sha256(serving_report), file_sha256(graph_report)) != (
        plan.serving_report_sha256, plan.graph_report_sha256,
    ):
        raise ValueError("preproduction source/graph metadata changed")
    source, graph = json.loads(serving_report.read_bytes()), json.loads(graph_report.read_bytes())
    if (source.get("status"), graph.get("status"), source["serving_view_id"], source["graph_id"], graph["graph_id"]) != (
        "complete", "complete", plan.serving_view_id, plan.graph_id, plan.graph_id,
    ):
        raise ValueError("preproduction source/graph identity is inconsistent")
    if output.exists() and not resume:
        raise ValueError("preproduction output must be new unless explicitly resumed")
    if resume and not (output / "plan.json").is_file():
        raise ValueError("resume requires the original preproduction plan")
    output.mkdir(parents=True, mode=0o700, exist_ok=resume)
    with locked_run(output):
        immutable_json(output / "plan.json", plan)
        # Validate all recorded attempts before making another inference call.
        source_progress(plan, output)
        from .preproduction_admission import admitted_receipts
        admitted = admitted_receipts(plan, output)
        admitted_counts = Counter(receipt.bucket for receipt in admitted)
        questions = [(task.scope.mode, task.scope.incident_id, task.question) for task in plan.seed_questions]
        executed = 0
        for attempt in plan.attempts():
            directory = output / "attempts" / attempt.task_id
            source_directory = directory / "source"
            outcome_path = directory / "source-outcome.json"
            if outcome_path.exists():
                latest, _, _ = current_source(plan, output, attempt.task_id)
                if (latest / "task.json").exists():
                    task = TaskRecord.model_validate_json((latest / "task.json").read_bytes())
                    questions.append((task.scope.mode, task.scope.incident_id, task.question))
                continue
            if (directory / "generation-batch.json").exists():
                raise ValueError("checkpoint-owned attempt must resume through its generation batch, not a legacy source wave")
            target = plan.tenant_target if attempt.mode == "tenant" else plan.incident_target
            if admitted_counts[_bucket(attempt)] >= target:
                continue
            prior = tuple(dict.fromkeys(question for mode, incident, question in questions
                                        if (mode, incident) == (attempt.mode, attempt.incident_id)))
            directory.mkdir(parents=True, mode=0o700, exist_ok=True)
            immutable_json(directory / "attempt.json", {
                "plan_fingerprint": fingerprint(plan), "attempt": attempt.model_dump(mode="json"),
                "previous_questions": list(prior), "logical_attempt_count": 1,
            })
            if source_directory.exists():
                safe_unfinished_roles(source_directory)
            try:
                result = runner(
                    client=client, serving_bundle=serving_bundle, graph_bundle=graph_bundle,
                    mode=attempt.mode, incident_id=attempt.incident_id, task_id=attempt.task_id,
                    output=source_directory, limits=plan.query_limits, checkpoint_cap=plan.checkpoint_cap,
                    prior_questions=prior, resume=source_directory.exists(), quality_gate=True,
                )
                if result["status"] not in ("candidate_for_mysql_validation", "needs_revision"):
                    raise ValueError("source pilot returned an unknown admission state")
                if json.loads((source_directory / "pilot_report.json").read_bytes()) != json.loads(json.dumps(result, allow_nan=False)):
                    raise ValueError("source pilot result does not match its saved report")
                task = TaskRecord.model_validate_json((source_directory / "task.json").read_bytes())
                if (task.task_id, task.scope.mode, task.scope.incident_id, task.serving_view_id, task.graph_version,
                    fingerprint(task)) != (
                    attempt.task_id, attempt.mode, attempt.incident_id, plan.serving_view_id, plan.graph_id,
                    result["task_fingerprint"],
                ):
                    raise ValueError("source task differs from its allocated logical attempt")
                if result["status"] == "candidate_for_mysql_validation":
                    from .quality import validate_quality_gate
                    validate_quality_gate(source_directory, task)
                status = "source_ready" if result["status"] == "candidate_for_mysql_validation" else "needs_revision"
                reason = "Source checks completed; native, robustness, uniqueness, canonical and difficulty stages remain required."
                task_fp = fingerprint(task)
            except RoleAbstained as error:
                reason, task_fp = str(error), None
                if (source_directory / "task.json").exists():
                    task_fp = fingerprint(TaskRecord.model_validate_json((source_directory / "task.json").read_bytes()))
                    status = "needs_revision"
                else:
                    status = "no_supported_candidate"
            except (ValueError, RuntimeError, OSError, duckdb.Error) as error:
                status, reason, task_fp = "operational_error", f"{type(error).__name__}: {error}", None
            outcome = SourceOutcome(plan_fingerprint=fingerprint(plan), attempt_binding_sha256=file_sha256(directory / "attempt.json"),
                                    attempt=attempt, status=status,
                                    task_fingerprint=task_fp, reason=reason, artifact_sha256=_artifacts(source_directory))
            immutable_json(outcome_path, outcome)
            executed += 1
            if status == "operational_error":
                raise RuntimeError(f"source attempt {attempt.task_id} has a retained operational error: {reason}")
            if (source_directory / "task.json").exists():
                task = TaskRecord.model_validate_json((source_directory / "task.json").read_bytes())
                questions.append((task.scope.mode, task.scope.incident_id, task.question))
            if executed >= wave_size:
                break
        if runtime_hashes() != effective_runtime(plan, output):
            raise ValueError("preproduction runtime changed during this wave")
        waves = output / "waves"
        waves.mkdir(exist_ok=True)
        sequence = 0
        while (waves / f"{sequence:04d}.json").exists():
            sequence += 1
        from .preproduction_admission import admission_progress
        progress = admission_progress(plan, output)
        immutable_json(waves / f"{sequence:04d}.json", {**progress, "attempts_executed_this_wave": executed})
        return progress
