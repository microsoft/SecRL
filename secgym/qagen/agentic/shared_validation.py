# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Checkpoint validation backed by a registered persistent snapshot service."""

from __future__ import annotations

import fcntl
import json
from pathlib import Path

from .azure_generation import AzureGenerationConfig
from .checkpoint_batches import (
    CheckpointBatchPolicy, ITEM_ERRORS, _check_policy, _client, _items, _workflow_lock, batch_directory,
    draft_candidate, repair_checkpoint, review_checkpoint, review_source,
)
from .contracts import TaskRecord, fingerprint
from .evidence import EvidenceVerifier
from .generation import TaskDraft
from .ledger import file_sha256
from .model_panel import immutable_json
from .mysql_serving import open_duckdb_engine
from .preproduction import PreproductionPlan, configured_model_binding
from .preproduction_pipeline import native_text_semantics, run_candidate_pipeline
from .preproduction_revisions import current_source, effective_native_plan, native_index_history, run_source_revision
from .review_transport import azure_review_client, load_run_transport_policy
from .snapshot_service import SnapshotServicePool


REGISTRATION = "shared-sql-service.json"


def register_snapshot_service(run: Path, service_directory: Path) -> dict:
    plan = PreproductionPlan.model_validate_json((run / "plan.json").read_bytes())
    pool = SnapshotServicePool(service_directory, effective_native_plan(plan, run))
    status = pool.status()
    value = {
        "policy_version": "shared-native-service-routing-v1", "plan_fingerprint": fingerprint(plan),
        "service_directory": str(service_directory.resolve()), "service_binding_fingerprint": fingerprint(pool.binding),
        "service_binding_sha256": file_sha256(service_directory / "binding.json"),
        "source_and_grading_rules_changed": False, "mutation_fixtures_shared": False,
    }
    previous_path = _registration_path(run)
    if previous_path is None:
        immutable_json(run / REGISTRATION, value)
    elif json.loads(previous_path.read_bytes()).get("service_binding_fingerprint") == fingerprint(pool.binding):
        registered_snapshot_pool(run)
    else:
        previous = json.loads(previous_path.read_bytes())
        old_directory = Path(previous["service_directory"])
        if file_sha256(old_directory / "binding.json") != previous["service_binding_sha256"]:
            raise ValueError("previous shared service binding changed")
        old = json.loads((old_directory / "binding.json").read_bytes())
        if old["native_indexes_sha256"] == pool.binding.native_indexes_sha256 or (
            old["native_indexes_sha256"] not in native_index_history(plan, run)[:-1]
            or old["serving_view_id"] != pool.binding.serving_view_id
            or old["serving_report_sha256"] != pool.binding.serving_report_sha256
            or old["mysql_report_sha256"] != pool.binding.mysql_report_sha256
        ):
            raise ValueError("service replacement requires an explicit native-index amendment")
        old_pointer = json.loads((old_directory / "current.json").read_bytes())
        old_instance = (old_directory / "instances" / old_pointer["instance_id"]).resolve()
        if old_instance.parent != (old_directory / "instances").resolve() or not (old_instance / "stopped.json").is_file():
            raise ValueError("previous shared service must be stopped before replacement")
        value["previous_registration_sha256"] = file_sha256(previous_path)
        folder = run / "shared-sql-service-revisions"
        folder.mkdir(mode=0o700, exist_ok=True)
        immutable_json(folder / f"{len(list(folder.glob('*.json'))):04d}.json", value)
    return {**status, "registered_for_run": str(run.resolve()), "validation_default": "shared_snapshot_service"}


def _registration_path(run: Path) -> Path | None:
    path = run / REGISTRATION
    revisions = sorted((run / "shared-sql-service-revisions").glob("*.json"))
    if not path.exists():
        if revisions:
            raise ValueError("service routing revisions lost the original registration")
        return None
    original_plan = fingerprint(PreproductionPlan.model_validate_json((run / "plan.json").read_bytes()))
    for sequence, revision in enumerate(revisions):
        value = json.loads(revision.read_bytes())
        if revision.name != f"{sequence:04d}.json" or (
            value.get("previous_registration_sha256") != file_sha256(path)
            or value.get("plan_fingerprint") != original_plan
        ):
            raise ValueError("service routing revisions must preserve their original plan and registration chain")
        path = revision
    return path


def registered_snapshot_pool(run: Path) -> SnapshotServicePool | None:
    path = _registration_path(run)
    if path is None:
        return None
    plan = PreproductionPlan.model_validate_json((run / "plan.json").read_bytes())
    registration = json.loads(path.read_bytes())
    directory = Path(registration["service_directory"])
    pool = SnapshotServicePool(directory, effective_native_plan(plan, run))
    if (registration["policy_version"], registration["plan_fingerprint"], registration["service_binding_fingerprint"],
        registration["service_binding_sha256"]) != (
        "shared-native-service-routing-v1", fingerprint(plan), fingerprint(pool.binding), file_sha256(directory / "binding.json"),
    ):
        raise ValueError("the registered native service changed")
    pool.status()
    return pool


def finish_shared_checkpoint_candidate(
    *, plan: PreproductionPlan, run: Path, policy: CheckpointBatchPolicy, task_id: str, serving: Path,
    graph: Path, mysql_bundle: Path, env_file: Path, workdir: Path, pool: SnapshotServicePool,
) -> dict:
    _check_policy(plan, run, policy)
    source, _, _ = current_source(plan, run, task_id)
    task = TaskRecord.model_validate_json((source / "task.json").read_bytes())
    return run_shared_pipeline(
        run=run, task_id=task_id, serving_bundle=serving, graph_bundle=graph, mysql_bundle=mysql_bundle,
        env_file=env_file, workdir=workdir, output=run / "attempts" / task_id / "pipeline" / task.revision_id,
        pool=pool,
    )


def shared_native_review_context(plan: PreproductionPlan, task: TaskRecord, source: EvidenceVerifier,
                                 pool: SnapshotServicePool, output: Path) -> dict | None:
    destination = output / "native-review-context.json"
    if not destination.exists() and (output / "binding.json").exists():
        return None
    output.mkdir(parents=True, mode=0o700, exist_ok=True)
    with (output / "native-review-context.lock").open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if destination.exists():
            context = json.loads(destination.read_bytes())
            lease_path = Path(context["lease_artifact"]).resolve()
            if (context.get("plan_fingerprint"), context.get("task_fingerprint"),
                context.get("native_snapshot_sha256")) != (
                fingerprint(plan), fingerprint(task), plan.native_snapshot_sha256,
            ) or not lease_path.is_relative_to(output.resolve()) or file_sha256(lease_path) != context["lease_artifact_sha256"]:
                raise ValueError("recorded native review context or its exact snapshot lease changed")
            return context
        measurements = output / "native-context-measurements"
        measurements.mkdir(mode=0o700, exist_ok=True)
        directory = measurements / f"{len(list(measurements.iterdir())):04d}"
        with pool.lease(source, directory) as (native, _):
            context = native_text_semantics(plan, task, native)
        lease_path = (directory / "shared-service.json").resolve()
        context.update(lease_artifact=str(lease_path), lease_artifact_sha256=file_sha256(lease_path))
        immutable_json(destination, context)
        return context


def run_shared_pipeline(
    *, run: Path, task_id: str, serving_bundle: Path, graph_bundle: Path, mysql_bundle: Path,
    env_file: Path, workdir: Path, output: Path, pool: SnapshotServicePool, resume: bool = False,
    grading_policy_directory: Path | None = None,
    parent_pipeline: Path | None = None, parent_runtime_archive: Path | None = None,
    prepared_robustness_plan: Path | None = None, robustness_feedback: str | None = None,
    canonical_feedback: str | None = None, difficulty_feedback: str | None = None,
    retained_native_pipeline: Path | None = None, retained_native_task: Path | None = None,
    retained_native_runtime_archive: Path | None = None,
    fresh_validation: bool = False,
    robustness_control_repairs: dict[str, str] | None = None,
    robustness_review_recovery: bool = False,
    qualified_support_review_recovery: Path | None = None,
    admitted_contract_revision: Path | None = None,
) -> dict:
    plan = PreproductionPlan.model_validate_json((run / "plan.json").read_bytes())
    if pool.plan != effective_native_plan(plan, run):
        raise ValueError("the shared pool carries a different candidate model or query-limit plan")
    source, outcome, _ = current_source(plan, run, task_id)
    if outcome is None or outcome.status != "source_ready":
        raise ValueError("shared validation requires the current source-ready candidate")
    task = TaskRecord.model_validate_json((source / "task.json").read_bytes())
    draft = TaskDraft.model_validate_json((source / "draft.json").read_bytes())
    if output.resolve().parent != (run / "attempts" / task_id / "pipeline").resolve():
        raise ValueError("shared pipeline output must be an owned direct child")
    if output.exists() and (not resume or not (output / "shared-native-execution.json").exists()):
        raise ValueError("shared validation cannot replace an existing pipeline or rerun a started student")
    if (Path(pool.binding.serving_bundle).resolve(), Path(pool.binding.mysql_bundle).resolve()) != (
        serving_bundle.resolve(), mysql_bundle.resolve(),
    ):
        raise ValueError("shared validation bundles differ from the requested candidate")
    pool.ready_instance()
    literals = frozenset(value.value for value in draft.allowed_literals)
    limits = plan.query_limits.model_copy(update={"timeout_ms": plan.grader_timeout_ms or plan.query_limits.timeout_ms})
    engine = open_duckdb_engine(serving_bundle, limits)
    verifier = client = None
    try:
        verifier = EvidenceVerifier(serving_bundle, engine, literals)
        transport = load_run_transport_policy(run, fingerprint(plan))
        if transport.plan_fingerprint != fingerprint(plan):
            raise ValueError("the review transport policy belongs to another run")
        client = azure_review_client(AzureGenerationConfig(
            env_file=env_file, deployment=plan.model.deployment, timeout_seconds=plan.model.request_timeout_seconds,
            max_completion_tokens=plan.model.max_completion_tokens, reasoning_effort=plan.model.reasoning_effort,
        ), transport, (output,))
        if configured_model_binding(client) != plan.model:
            raise ValueError("shared service changed the review or student model")
        output.mkdir(parents=True, mode=0o700, exist_ok=resume)
        immutable_json(output / "shared-native-execution.json", {
            "task_fingerprint": fingerprint(task), "plan_fingerprint": fingerprint(plan),
            "service_binding": pool.binding.model_dump(mode="json"),
            "review_transport_policy_fingerprint": fingerprint(transport),
            "adapter_implementation_sha256": file_sha256(Path(__file__)),
            "student_settings_changed": False, "mutation_fixtures_shared": False,
        })
        immutable_json(output / "shared-native-producer.json", {
            "adapter_sha256": file_sha256(Path(__file__)), "adapter_source": Path(__file__).read_text(),
            "service_sha256": pool.binding.implementation_sha256,
            "service_source": Path(__file__).with_name("snapshot_service.py").read_text(),
        })
        native_context = (shared_native_review_context(plan, task, verifier, pool, output)
                          if parent_pipeline is None or robustness_feedback is not None else None)
        return run_candidate_pipeline(
            plan=plan, run=run, task_id=task_id, client=client, source=verifier, mysql=None, student=None,
            serving_bundle=serving_bundle, mysql_bundle=mysql_bundle, graph_bundle=graph_bundle,
            mysqld=Path(pool.metadata["mysqld_binary"]), workdir=workdir, output=output, resume=True,
            native_engines=lambda: pool.lease(verifier, output / "native"),
            native_review_context=native_context,
            grading_policy_directory=grading_policy_directory, parent_pipeline=parent_pipeline,
            parent_runtime_archive=parent_runtime_archive, prepared_robustness_plan=prepared_robustness_plan,
            robustness_feedback=robustness_feedback, canonical_feedback=canonical_feedback,
            difficulty_feedback=difficulty_feedback,
            retained_native_pipeline=retained_native_pipeline, retained_native_task=retained_native_task,
            retained_native_runtime_archive=retained_native_runtime_archive,
            fresh_validation=fresh_validation,
            robustness_control_repairs=robustness_control_repairs,
            robustness_review_recovery=robustness_review_recovery,
            qualified_support_review_recovery=qualified_support_review_recovery,
            admitted_contract_revision=admitted_contract_revision,
        )
    finally:
        if client is not None:
            client.close()
        if verifier is not None:
            verifier.close()
        engine.connection.close()


def review_registered_checkpoint(
    *, run: Path, batch_id: str, serving: Path, graph: Path, mysql_bundle: Path, env_file: Path, workdir: Path,
) -> dict:
    pool = registered_snapshot_pool(run)
    if pool is None:
        return review_checkpoint(run=run, batch_id=batch_id, serving=serving, graph=graph,
                                 mysql_bundle=mysql_bundle, env_file=env_file, workdir=workdir)

    def finish(**kwargs):
        return finish_shared_checkpoint_candidate(**kwargs, pool=pool)

    return review_checkpoint(run=run, batch_id=batch_id, serving=serving, graph=graph,
                             mysql_bundle=mysql_bundle, env_file=env_file, workdir=workdir, pipeline_runner=finish)


def repair_registered_checkpoint(
    *, run: Path, batch_id: str, task_ids: tuple[str, ...], serving: Path, graph: Path,
    mysql_bundle: Path, env_file: Path, workdir: Path,
) -> dict:
    pool = registered_snapshot_pool(run)
    if pool is None:
        return repair_checkpoint(run=run, batch_id=batch_id, task_ids=task_ids, serving=serving, graph=graph,
                                 mysql_bundle=mysql_bundle, env_file=env_file, workdir=workdir)
    plan = PreproductionPlan.model_validate_json((run / "plan.json").read_bytes())
    directory = batch_directory(run, batch_id)
    policy = CheckpointBatchPolicy.model_validate_json((directory / "policy.json").read_bytes())
    _check_policy(plan, run, policy)
    if not (directory / "checkpoint-report.json").exists():
        raise ValueError("repairs require a completed checkpoint review")
    items = {item["attempt"]["task_id"]: item for item in _items(directory)}
    if not task_ids or len(set(task_ids)) != len(task_ids) or not set(task_ids) <= items.keys():
        raise ValueError("choose distinct failed items from this checkpoint")
    with _workflow_lock(run):
        for task_id in task_ids:
            source, outcome, _ = current_source(plan, run, task_id)
            if outcome is None or outcome.status != "needs_revision" or (
                any((source / "blind").glob("*-request.json")) or (source / "retained-source-student.json").exists()
            ):
                raise ValueError("automatic regeneration is pre-blind only; completed students require retained-trace repair")
        results = []
        for task_id in task_ids:
            source, _, _ = current_source(plan, run, task_id)
            feedback = json.dumps({
                "recorded_checkpoint_review": json.loads((source / "quality/reviewer/result.json").read_bytes()),
                "instruction": "Repair the actual defect; preserve original typed goals, meaningful checkpoints and source scope.",
            })
            client = _client(plan, policy, run, env_file, run / "attempts" / task_id)
            try:
                def runner(**kwargs):
                    draft_candidate(plan=plan, run=run, policy=policy, item=items[task_id], serving=serving,
                                    graph_bundle=graph, client=kwargs["client"], source=kwargs["output"],
                                    previous=kwargs["revision_from"], feedback=kwargs["revision_feedback"])
                    return review_source(plan=plan, source=kwargs["output"], serving=serving, client=kwargs["client"])

                outcome = run_source_revision(plan=plan, client=client, serving_bundle=serving, graph_bundle=graph,
                                              output=run, task_id=task_id, feedback=feedback, runner=runner)
                result = {"task_id": task_id, "source_status": outcome.status, "pipeline": None}
                if outcome.status == "source_ready":
                    result["pipeline"] = finish_shared_checkpoint_candidate(
                        plan=plan, run=run, policy=policy, task_id=task_id, serving=serving, graph=graph,
                        mysql_bundle=mysql_bundle, env_file=env_file, workdir=workdir, pool=pool,
                    )
            except ITEM_ERRORS as error:
                _, current, _ = current_source(plan, run, task_id)
                result = {"task_id": task_id, "source_status": current.status if current else "operational_error",
                          "pipeline": {"status": "operational_error", "reason": f"{type(error).__name__}: {error}"}}
            finally:
                client.close()
            history = run / "attempts" / task_id / "checkpoint-repairs"
            history.mkdir(mode=0o700, exist_ok=True)
            immutable_json(history / f"{len(list(history.glob('*.json'))):04d}.json", result)
            results.append(result)
        return {"batch_id": batch_id, "repairs": results, "native_backend": "shared_snapshot_service", "release_approved": False}
