# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Opt-in review transport runner without changing frozen source or pipeline producers."""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time

import mysql.connector

from .azure_generation import AzureGenerationConfig
from .contracts import TaskRecord, fingerprint
from .evidence import EvidenceVerifier
from .generation import TaskDraft
from .ledger import file_sha256
from .model_panel import immutable_json
from .mysql_serving import open_duckdb_engine, open_mysql_engine
from .preproduction import PreproductionPlan, configured_model_binding
from .preproduction_admission import admission_progress
from .preproduction_pipeline import _citations, _continuation, _review_validator, _validate_plan_revision, run_candidate_pipeline
from .preproduction_revisions import current_source
from .quality import validate_quality_gate
from .review_transport import NonStudentTransportPolicy, TransportPolicy, azure_review_client, interrupted_review, load_transport_policy, recover_review
from .robustness import RobustnessPlan, _expected_answers


def bind_transport_execution(output: Path, policy: TransportPolicy, execution: dict) -> None:
    policy_path = output / "review-transport-policy.json"
    execution_path = output / "review-execution-binding.json"
    if not policy_path.exists():
        immutable_json(policy_path, policy)
    original = load_transport_policy(policy_path)
    if original == policy:
        if execution_path.exists() and execution["recover_role"] is None:
            execution["recover_role"] = json.loads(execution_path.read_bytes()).get("recover_role")
        immutable_json(execution_path, execution)
        return
    if not isinstance(policy, NonStudentTransportPolicy) or original.policy_version != "review-http-override-v1" or (
        policy.previous_policy_fingerprint != fingerprint(original)
        or policy.plan_fingerprint != original.plan_fingerprint
    ):
        raise ValueError("transport scope change requires the exact approved predecessor policy")
    key = hashlib.sha256(json.dumps({
        "policy_fingerprint": fingerprint(policy), "recover_role": execution["recover_role"],
    }, sort_keys=True).encode()).hexdigest()
    directory = output / "transport-executions"
    directory.mkdir(mode=0o700, exist_ok=True)
    immutable_json(directory / (key + ".json"), {
        **execution, "approved_policy": policy.model_dump(mode="json"),
        "previous_policy_sha256": file_sha256(policy_path),
        "previous_execution_sha256": file_sha256(execution_path) if execution_path.exists() else None,
        "original_policy_or_execution_rewritten": False,
    })


def _robustness_author_validator(task: TaskRecord, source: EvidenceVerifier, context: dict):
    proofs = source.preflight(task)
    references = _citations(task) | frozenset(c for groups in proofs.values() for group in groups for c in group)
    prior = context.get("previous_plan")
    previous_plan = RobustnessPlan.model_validate_json(json.dumps(prior)) if prior is not None else None
    if previous_plan is not None and previous_plan.task_fingerprint != fingerprint(task):
        raise ValueError("cross-task author recovery requires a separate explicit equivalence workflow")

    def validate(value: RobustnessPlan, tools):
        if value.task_fingerprint != fingerprint(task):
            raise ValueError("recovered robustness proposal belongs to another task")
        if previous_plan is not None:
            _validate_plan_revision(previous_plan, value)
        fixture = references | frozenset(value.extra_source_records)
        claims = {"final": task.private_gold.final,
                  **{checkpoint.checkpoint_id: checkpoint.claim for checkpoint in task.private_gold.checkpoints}}
        for case in value.cases:
            if {entry.claim_id for entry in case.expected} != claims.keys():
                raise ValueError("recovered counterfactual must cover every original claim")
            if set(case.removed_records) - fixture or any(edit.citation not in fixture for edit in case.edits):
                raise ValueError("recovered counterfactual refers to an unbound fixture record")
            for entry in case.expected:
                for backend in ("duckdb", "mysql"):
                    _expected_answers(claims[entry.claim_id], entry.answer, backend)
                if isinstance(entry.support, tuple) and len(entry.support) != len(fixture) + 2:
                    raise ValueError("recovered support must cover every original citation probe")
        if fixture - tools.observed:
            raise ValueError("recovered author must independently inspect every fixture record")

    return validate


@contextmanager
def owned_review_engines(plan: PreproductionPlan, serving_bundle: Path, mysql_bundle: Path, workdir: Path,
                         literals: frozenset[str]):
    report_path = mysql_bundle / "mysql_report.json"
    if file_sha256(report_path) != plan.native_snapshot_sha256:
        raise ValueError("review runner native snapshot differs from the original plan")
    metadata = json.loads(report_path.read_bytes())
    serving = json.loads((serving_bundle / "serving_report.json").read_bytes())
    if (metadata["status"], metadata["serving_view_id"], metadata["verified_rows"]) != (
        "complete", plan.serving_view_id, sum(table.get("rows", 0) for table in serving["tables"]),
    ):
        raise ValueError("review runner requires the complete verified public snapshot")
    limits = plan.query_limits.model_copy(update={"timeout_ms": plan.grader_timeout_ms or plan.query_limits.timeout_ms})
    source = native = source_engine = native_engine = student_engine = None
    with (mysql_bundle / "pipeline-mysql.lock").open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("the verified native snapshot already has an owning pipeline") from error
        with tempfile.TemporaryDirectory(prefix=".secrl-review-", dir=workdir.resolve()) as temporary:
            folder = Path(temporary)
            socket = folder / "mysql.sock"
            if len(str(socket).encode()) > 100:
                raise ValueError("review runner socket path is too long")
            credentials = json.loads((mysql_bundle / metadata["reader_credentials_file"]).read_bytes())
            server = subprocess.Popen([
                metadata["mysqld_binary"], "--no-defaults", f"--datadir={metadata['data_directory']}",
                f"--socket={socket}", "--skip-networking", "--mysqlx=OFF",
                f"--innodb-page-size={metadata['innodb_page_size']}", "--innodb-buffer-pool-size=512M",
                f"--pid-file={folder / 'mysql.pid'}", f"--log-error={folder / 'mysql.log'}",
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                for _ in range(240):
                    if server.poll() is not None:
                        log = folder / "mysql.log"
                        raise RuntimeError("owned review server failed; " + (log.read_text() if log.exists() else "no server log"))
                    try:
                        connection = mysql.connector.connect(unix_socket=str(socket), **credentials)
                        connection.close()
                        break
                    except mysql.connector.Error:
                        time.sleep(0.25)
                else:
                    raise RuntimeError("owned review server readiness timeout")
                source_engine = open_duckdb_engine(serving_bundle, limits)
                native_engine = open_mysql_engine(serving_bundle, limits=limits, unix_socket=str(socket), **credentials)
                student_engine = open_mysql_engine(serving_bundle, limits=plan.query_limits, unix_socket=str(socket), **credentials)
                source = EvidenceVerifier(serving_bundle, source_engine, literals)
                native = EvidenceVerifier(serving_bundle, native_engine, literals)
                yield source, native, student_engine, Path(metadata["mysqld_binary"])
            finally:
                try:
                    for verifier in (source, native):
                        if verifier is not None:
                            verifier.close()
                    for engine in (source_engine, native_engine, student_engine):
                        if engine is not None:
                            engine.connection.close()
                finally:
                    server.terminate()
                    try:
                        server.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait(timeout=30)


def run_review_pipeline(
    *, run: Path, task_id: str, serving_bundle: Path, graph_bundle: Path, mysql_bundle: Path,
    env_file: Path, workdir: Path, output: Path, policy: TransportPolicy,
    resume: bool = False, recover_role: Path | None = None,
    parent_pipeline: Path | None = None, parent_runtime_archive: Path | None = None,
    prepared_robustness_plan: Path | None = None, robustness_feedback: str | None = None,
) -> dict:
    plan = PreproductionPlan.model_validate_json((run / "plan.json").read_bytes())
    if policy.plan_fingerprint != fingerprint(plan):
        raise ValueError("review transport approval belongs to another immutable run")
    candidate, outcome, _ = current_source(plan, run, task_id)
    if outcome is None or outcome.status != "source_ready":
        raise ValueError("review pipeline requires the current source-ready task")
    task = TaskRecord.model_validate_json((candidate / "task.json").read_bytes())
    draft = TaskDraft.model_validate_json((candidate / "draft.json").read_bytes())
    validate_quality_gate(candidate, task)
    indexes = {path.name: file_sha256(path) for path in sorted(mysql_bundle.glob("index_report*.json"))}
    if not indexes or (file_sha256(serving_bundle / "serving_report.json"),
                       file_sha256(graph_bundle / "graph_report.json"),
                       hashlib.sha256(json.dumps(indexes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()) != (
        plan.serving_report_sha256, plan.graph_report_sha256, plan.native_indexes_sha256,
    ):
        raise ValueError("review recovery serving, graph or native index bindings changed")
    if output.resolve().parent != (run / "attempts" / task_id / "pipeline").resolve():
        raise ValueError("review pipeline output must be an owned direct child")
    if output.exists() and not resume:
        raise ValueError("review pipeline output already exists; explicitly resume only an unfinished boundary")
    if (output / "pipeline-report.json").exists():
        raise ValueError("a completed pipeline is not eligible for reviewer transport recovery")
    if recover_role is not None:
        recover_role = recover_role.resolve()
        if recover_role not in ((output / "grading/reviewer").resolve(), (output / "grading/reflection").resolve(),
                                (output / "robustness/reviewer").resolve(), (output / "robustness/author").resolve()):
            raise ValueError("only a bound interrupted contract or robustness role can recover here")
        if (recover_role.parent / "stage-receipt.json").exists():
            raise ValueError("a completed stage cannot recover a reviewer")
        state = interrupted_review(recover_role, policy)
        if state["context"].get("task_fingerprint") != fingerprint(task):
            raise ValueError("the interrupted review belongs to another task")
        binding = json.loads((output / "binding.json").read_bytes())
        if (binding["task_fingerprint"], binding["plan_fingerprint"], binding["source_outcome_fingerprint"]) != (
            fingerprint(task), fingerprint(plan), fingerprint(outcome),
        ) or any(file_sha256(Path(__file__).with_name(name)) != digest for name, digest in binding["implementation_sha256"].items()):
            raise ValueError("review recovery cannot change the original pipeline/source/runtime binding")
        previous = binding.get("continuation")
        if previous is not None:
            if parent_pipeline is None or parent_runtime_archive is None or (
                str(parent_pipeline.resolve()), str(parent_runtime_archive.resolve())
            ) != (previous["parent_pipeline"], previous["runtime_archive"]) or _continuation(
                parent_pipeline, parent_runtime_archive, binding, run, output.parent,
            ) != previous:
                raise ValueError("review recovery changed the existing annotation continuation")
            revision = binding.get("robustness_revision")
            if revision is None or robustness_feedback != revision["feedback"] or (
                file_sha256(prepared_robustness_plan) if prepared_robustness_plan is not None else None
            ) != revision["prepared_plan_sha256"]:
                raise ValueError("review recovery changed the prepared robustness correction")
        elif parent_pipeline is not None or parent_runtime_archive is not None:
            raise ValueError("a direct interrupted pipeline cannot adopt an annotation parent")
    output.mkdir(parents=True, mode=0o700, exist_ok=resume)
    bind_transport_execution(output, policy, {
        "plan_fingerprint": fingerprint(plan), "task_fingerprint": fingerprint(task),
        "policy_fingerprint": fingerprint(policy), "implementation_sha256": file_sha256(Path(__file__)),
        "student_request_timeout_seconds": plan.model.request_timeout_seconds,
        "student_query_limits": plan.query_limits.model_dump(mode="json"),
        "recover_role": str(recover_role.relative_to(output.resolve())) if recover_role is not None else None,
    })
    config = AzureGenerationConfig(
        env_file=env_file, deployment=plan.model.deployment, timeout_seconds=plan.model.request_timeout_seconds,
        max_completion_tokens=plan.model.max_completion_tokens, reasoning_effort=plan.model.reasoning_effort,
    )
    client = azure_review_client(config, policy, (output,))
    try:
        if configured_model_binding(client) != plan.model:
            raise ValueError("review override changed the original default/student model binding")
        with owned_review_engines(plan, serving_bundle, mysql_bundle, workdir,
                                  frozenset(item.value for item in draft.allowed_literals)) as (source, native, student, mysqld):
            if recover_role is not None:
                subject = fingerprint(task.private_gold)
                required = _citations(task)
                if recover_role.parent.name == "robustness" and recover_role.name == "author":
                    if not isinstance(policy, NonStudentTransportPolicy):
                        raise ValueError("author recovery requires the approved non-student transport policy")
                    recover_review(client=client, verifier=source, directory=recover_role, task=task,
                                   validate=_robustness_author_validator(task, source, state["context"]))
                elif recover_role.parent.name == "robustness":
                    matrix = RobustnessPlan.model_validate_json((recover_role.parent / "proposed-plan.json").read_bytes())
                    if matrix.task_fingerprint != fingerprint(task):
                        raise ValueError("interrupted robustness plan belongs to another task")
                    subject = fingerprint(matrix)
                    proofs = source.preflight(task)
                    required |= frozenset(c for groups in proofs.values() for group in groups for c in group) | frozenset(matrix.extra_source_records)
                if recover_role.name != "author":
                    if state["context"]["subject_fingerprint"] != subject:
                        raise ValueError("interrupted review subject changed")
                    recover_review(client=client, verifier=source, directory=recover_role, task=task,
                                   validate=_review_validator(task, subject, required))
            result = run_candidate_pipeline(
                plan=plan, run=run, task_id=task_id, client=client, source=source, mysql=native, student=student,
                serving_bundle=serving_bundle, mysql_bundle=mysql_bundle, graph_bundle=graph_bundle,
                mysqld=mysqld, workdir=workdir, output=output, resume=True,
                parent_pipeline=parent_pipeline, parent_runtime_archive=parent_runtime_archive,
                prepared_robustness_plan=prepared_robustness_plan, robustness_feedback=robustness_feedback,
            )
        admission_progress(plan, run)
        return result
    finally:
        client.close()
