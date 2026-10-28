# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Versioned development attempts; discovery outcomes are never release approvals."""

import json
from pathlib import Path
from typing import Literal

import duckdb
from pydantic import Field, model_validator
from typing_extensions import Annotated

from .contracts import Contract, Identifier, SELECTED_INCIDENTS, TaskRecord, fingerprint, require_unique
from .generation import RoleAbstained
from .pilot import run_discovery_pilot
from .query import QueryLimits


class DevelopmentAttempt(Contract):
    task_id: Identifier
    mode: Literal["tenant", "incident"]
    incident_id: int | None

    @model_validator(mode="after")
    def valid_scope(self):
        if self.mode == "tenant" and self.incident_id is not None:
            raise ValueError("tenant attempts do not use incident seeds")
        if self.mode == "incident" and self.incident_id not in SELECTED_INCIDENTS:
            raise ValueError("incident attempt is outside the selected benchmark scopes")
        return self


class DevelopmentBatch(Contract):
    batch_id: Identifier
    serving_view_id: Identifier
    graph_id: Identifier
    attempts: Annotated[tuple[DevelopmentAttempt, ...], Field(min_length=1)]
    limits: QueryLimits
    checkpoint_cap: Annotated[float, Field(gt=0, lt=1)]
    seed_questions: tuple[TaskRecord, ...] = ()

    @model_validator(mode="after")
    def unique_attempts(self):
        require_unique(tuple(a.task_id for a in self.attempts), "batch task IDs")
        seed_ids = tuple(t.task_id for t in self.seed_questions)
        require_unique(seed_ids, "seed task IDs")
        if set(seed_ids) & {a.task_id for a in self.attempts}:
            raise ValueError("new attempts cannot reuse a seed task ID")
        if any(t.serving_view_id != self.serving_view_id or t.graph_version != self.graph_id for t in self.seed_questions):
            raise ValueError("seed tasks belong to a different source view or graph")
        return self


def development_attempts(batch_id: str, per_incident: int, tenant: int) -> tuple[DevelopmentAttempt, ...]:
    if type(per_incident) is not int or type(tenant) is not int or per_incident < 0 or tenant < 0 or not per_incident + tenant:
        raise ValueError("development attempt counts must be nonnegative integers with a positive total")
    attempts = []
    for ordinal in range(max(per_incident, tenant)):
        if ordinal < per_incident:
            attempts.extend(DevelopmentAttempt(task_id=f"{batch_id}-incident-{incident}-{ordinal + 1:02}",
                                               mode="incident", incident_id=incident) for incident in SELECTED_INCIDENTS)
        if ordinal < tenant:
            attempts.append(DevelopmentAttempt(task_id=f"{batch_id}-tenant-{ordinal + 1:02}", mode="tenant", incident_id=None))
    return tuple(attempts)


def run_development_batch(spec: DevelopmentBatch, client, serving_bundle: Path, graph_bundle: Path,
                          output: Path, *, resume: bool = False, runner=run_discovery_pilot) -> dict:
    """Run discovery sequentially; preserve failures/revisions for later adjudication."""
    spec = DevelopmentBatch.model_validate(spec)
    serving_report = json.loads((serving_bundle / "serving_report.json").read_text())
    graph_report = json.loads((graph_bundle / "graph_report.json").read_text())
    if (serving_report.get("status"), graph_report.get("status")) != ("complete", "complete"):
        raise ValueError("batch requires completed serving and graph bundles")
    if serving_report["serving_view_id"] != spec.serving_view_id or graph_report["graph_id"] != spec.graph_id:
        raise ValueError("batch source identities differ")
    if serving_report["graph_id"] != spec.graph_id:
        raise ValueError("serving and graph snapshots differ")
    if resume and not (output / "batch.json").is_file():
        raise ValueError("resume requires the original batch manifest")
    if output.exists() and not resume:
        raise ValueError("batch output must be new unless explicitly resumed")
    output.mkdir(parents=True, mode=0o700, exist_ok=resume)
    manifest = output / "batch.json"
    if manifest.exists():
        if DevelopmentBatch.model_validate_json(manifest.read_text()) != spec:
            raise ValueError("resumed batch specification changed")
    else:
        manifest.write_text(spec.model_dump_json(indent=2) + "\n")
    outcomes = []
    questions = [(task.scope.mode, task.scope.incident_id, task.question) for task in spec.seed_questions]
    for attempt in spec.attempts:
        result_file = output / f"{attempt.task_id}.json"
        directory = output / attempt.task_id
        if result_file.exists():
            outcome = json.loads(result_file.read_text())
            if outcome["batch_fingerprint"] != fingerprint(spec) or outcome["attempt"] != attempt.model_dump(mode="json"):
                raise ValueError("persisted attempt result does not match the batch")
            if (directory / "task.json").exists() and outcome.get("task_fingerprint"):
                saved = TaskRecord.model_validate_json((directory / "task.json").read_text())
                if fingerprint(saved) != outcome["task_fingerprint"]:
                    raise ValueError("persisted attempt task changed")
        else:
            prior = tuple(dict.fromkeys(question for mode, incident, question in questions
                                        if mode == attempt.mode and incident == attempt.incident_id))
            print(f"[batch] {len(outcomes) + 1}/{len(spec.attempts)} {attempt.task_id}", flush=True)
            try:
                result = runner(
                    client=client, serving_bundle=serving_bundle, graph_bundle=graph_bundle,
                    mode=attempt.mode, incident_id=attempt.incident_id, task_id=attempt.task_id,
                    output=directory, limits=spec.limits, checkpoint_cap=spec.checkpoint_cap,
                    prior_questions=prior, resume=resume and directory.exists(),
                )
                outcome = {"status": result["status"], "task_fingerprint": result.get("task_fingerprint")}
            except RoleAbstained as error:
                outcome = {"status": "no_supported_candidate", "reason": str(error)}
            except (ValueError, RuntimeError, OSError, duckdb.Error) as error:
                outcome = {"status": "error", "error_type": type(error).__name__, "reason": str(error)}
            outcome.update(batch_fingerprint=fingerprint(spec), attempt=attempt.model_dump(mode="json"),
                           release_approved=False)
            result_file.write_text(json.dumps(outcome, indent=2) + "\n")
        outcomes.append(outcome)
        if (directory / "task.json").exists():
            task = TaskRecord.model_validate_json((directory / "task.json").read_text())
            questions.append((task.scope.mode, task.scope.incident_id, task.question))
        progress = {
            "status": "discovery_attempts_complete" if len(outcomes) == len(spec.attempts) else "running",
            "batch_fingerprint": fingerprint(spec), "attempts_finished": len(outcomes), "attempts_requested": len(spec.attempts),
            "outcomes": outcomes, "mysql_validated": False, "release_approved": False,
        }
        with (output / "progress.tmp").open("w") as stream:
            json.dump(progress, stream, indent=2)
        (output / "progress.tmp").replace(output / "progress.json")
    (output / "discovery-report.json").write_text(json.dumps(progress, indent=2) + "\n")
    return progress
