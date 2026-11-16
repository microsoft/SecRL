# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Concurrent drafting, checkpoint reviews, and durable per-item repair queues."""

from __future__ import annotations

from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
import fcntl
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time
from typing import Callable, Literal

import duckdb
from dotenv import dotenv_values
from pydantic import Field, model_validator
import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError, TokenError

from .azure_generation import AzureGenerationClient, AzureGenerationConfig
from .batch import DevelopmentAttempt
from .contracts import Contract, Digest, GateResult, Identifier, QualifiedWitnessProgram, SELECTED_INCIDENTS, TaskRecord, Text, fingerprint
from .discovery_context import GraphDiscovery, scope_context
from .evidence import EvidenceVerifier, Finding
from .generation import BlindSolution, DiscoveryTools, RoleAbstained, TaskDraft, compile_draft, observed_role_citations, run_role
from .gateway import GatewayConfig, GatewayOptIn
from .json_result_recovery import JsonResultRecoveryPolicy, recover_json_result
from .ledger import file_sha256
from .model_panel import immutable_json
from .mysql_serving import open_duckdb_engine
from .pilot import AUTHOR_INSTRUCTIONS, BLIND_INSTRUCTIONS, REFUTER_INSTRUCTIONS
from .preproduction import PreproductionPlan, SourceOutcome, _artifacts, _bucket, configured_model_binding, locked_run, source_progress
from .preproduction_admission import ArtifactVerification, admission_progress
from .preproduction_pipeline import contract_proof_diagnostics, run_candidate_pipeline
from .preproduction_revisions import current_source, effective_runtime, run_source_revision
from .quality import (
    AUTHOR_QUALITY_INSTRUCTIONS, QUALITY_VERSION, QualityAudit, audit_source_quality, run_quality_gate,
    runtime_hashes as quality_hashes, validate_quality_gate,
)
from .review_execution import owned_review_engines
from .review_transport import NonStudentTransportPolicy, _digest, azure_review_client, load_run_transport_policy
from .scoring import compare_typed_answers


class CheckpointBatchPolicy(GatewayOptIn):
    policy_version: Literal["checkpoint-generation-v1"] = "checkpoint-generation-v1"
    plan_fingerprint: Digest
    batch_id: Identifier
    generation_deployment: Literal["gpt-6-astra"] = "gpt-6-astra"
    generation_timeout_seconds: Literal[900] = 900
    checkpoint_size: int = Field(default=100, ge=1, le=100)
    workers: int = Field(default=4, ge=1, le=4)
    review_and_student_models_changed: Literal[False] = False
    source_generation_runtime_sha256: dict[str, Digest]
    implementation_sha256: Digest
    user_authorization: Literal["astra_generation_checkpoint_reviews"]
    release_approved: Literal[False] = False


class QuotaCheckpointBatchPolicy(CheckpointBatchPolicy):
    allocation_policy: Literal["remaining-admission-quotas-v1"] = "remaining-admission-quotas-v1"
    requested_checkpoint_size: int = Field(ge=1, le=100)
    scope_targets: dict[str, int]

    @model_validator(mode="after")
    def bounded_scope_allocation(self):
        scopes = {f"incident:{incident}" for incident in SELECTED_INCIDENTS} | {"tenant"}
        if set(self.scope_targets) != scopes or any(value < 0 for value in self.scope_targets.values()):
            raise ValueError("quota allocation requires every supported scope and nonnegative targets")
        if sum(self.scope_targets.values()) != self.checkpoint_size or self.checkpoint_size > self.requested_checkpoint_size:
            raise ValueError("quota allocation must match its bounded actual checkpoint size")
        return self


class CheckpointProducerAmendment(Contract):
    policy_version: Literal["checkpoint-producer-amendment-v1"] = "checkpoint-producer-amendment-v1"
    batch_policy_fingerprint: Digest
    previous_sha256: Digest
    current_sha256: Digest
    previous_source: Text
    current_source: Text
    source_runtime_sha256: dict[str, Digest]
    reason: Text
    completed_drafts_or_students_changed: Literal[False] = False


def load_batch_policy(path: Path) -> CheckpointBatchPolicy:
    data = path.read_bytes()
    allocation = json.loads(data).get("allocation_policy")
    if allocation is None:
        return CheckpointBatchPolicy.model_validate_json(data)
    if allocation != "remaining-admission-quotas-v1":
        raise ValueError("unknown checkpoint allocation policy")
    return QuotaCheckpointBatchPolicy.model_validate_json(data)


DRAFT_INSTRUCTIONS = AUTHOR_INSTRUCTIONS.replace(
    "Investigate a scouted lead and draft", "Explore the supplied source scope, choose a novel factual investigation, and draft",
) + AUTHOR_QUALITY_INSTRUCTIONS + """
This is drafting for a later review checkpoint, not admission. You perform discovery and authorship
in this one role; do not wait for a separate scout. Seek an objective different from previous_questions.
Use width-free TEXT in MySQL JSON_TABLE, not arbitrary VARCHAR capacities.
Explicitly CAST every MySQL JSON_TABLE input AS JSON, including inputs coming from CTEs.
MySQL JSON_TABLE text columns do not inherit public-table binary collation. Use explicit binary
comparisons for exact named roles/values; preserve intentionally case-insensitive public semantics.
The verified public MySQL text columns already use binary, NO PAD collation. Preserve indexed
physical-column access; do not add index-defeating BINARY casts there merely to repeat those semantics.
Check the lookup value too: BINARY on a JSON-derived right-hand operand can defeat indexed access even
when the physical column is untouched. Where verified physical-column metadata establishes the exact
binary, NO PAD semantics, decode that lookup value with CAST(... AS CHAR) and compare to the uncast
indexed column. Keep explicit binary comparisons between JSON-derived values where needed; never
trade case sensitivity, trailing-space distinctions or complete matches for an index shortcut.
For exact binary grouping, group/select the same binary expression inside a CTE or subquery, then
decode the grouped result with CAST(... AS CHAR) in an outer SELECT. Do not select a differently
decoded expression beside GROUP BY BINARY and assume ONLY_FULL_GROUP_BY will accept it.
Binary comparisons are not binary answer values. Return native strings as CHAR, including after
binary DISTINCT, and native numeric results as supported integer/DOUBLE scalars, not raw bytes or Decimal.
Preserve exact comparisons and full timestamp dates/microseconds when correcting result transport.
For exact string collections of UTC timestamps, semantic_kind does not normalize collection members.
State the required lexical output format in the public question, matching the actual answer-program
results: date/time separator, timezone suffix (+00:00 versus Z), and presence and exact fractional
precision. Preserve all source precision. UTC-equivalent spellings are not equal under the frozen
exact-set comparator. Specify the format without disclosing any actual answer or intermediate value.
This guidance applies to new authorship only; never rewrite completed questions or student answers,
change the frozen comparator, or manufacture a different expected spelling to fit a retained student.
Public-anchor literals must actually appear in the public question/context or its supplied incident ID.
State exact title/action/command-pattern/time-window selectors when the query requires them.
Do not disclose private answers or intermediate IOCs to justify a selector; derive those from sources.
Witness group constants must be public anchors or actual source/table namespaces, not private labels.
An intermediate checkpoint must not require completion of its downstream final investigation.
Treat complete alternative observation paths as alternatives, not jointly mandatory evidence.
Use source-qualified whole-answer obligations where valid alternative proofs exist. Preserve
source-wide eligibility, ties, count/absence and ranking completeness; do not make irrelevant
preliminary-cohort rows mandatory merely because they were useful while authoring the question.
Qualified candidate rows describe COMPLETE source-required bundles, not merely the cited fragment.
The frozen solver checks whole-bundle availability and coherent bindings. Use actual supplied/source
joins to activate eligible candidate IDs, then return their full required rows. Do not truncate
required bundles to the supplied citations, and do not make a valid smaller proof plus legitimate
source-qualified comparison context fail just because the larger cohort bundle is incomplete.
Expose materially different accepted routes, including smaller qualified routes, as complete
representative witness groups: canonical selection and difficulty proof choices bind those groups.
Use source-derived representative selection, preserve ties and every required obligation, and
retain full comparison routes. Do not enumerate every interchangeable combination or add a new
containment requirement to qualified support merely to produce these representative groups.
Test complete alternatives, bounded related-context supersets, missing essential members and
unrelated extras. Neither incomplete positive proof nor arbitrary same-host/time context is sufficient.
End with the finish function. Source-semantic reviews and all students run only at the checkpoint.
"""
ITEM_ERRORS = (ValueError, RuntimeError, OSError, duckdb.Error, subprocess.SubprocessError)


def batch_directory(run: Path, batch_id: str) -> Path:
    path = (run / "generation-batches" / batch_id).resolve()
    if path.parent != (run / "generation-batches").resolve():
        raise ValueError("generation batch must be an owned direct child")
    return path


def checkpoint_producer(run: Path, policy: CheckpointBatchPolicy) -> str:
    directory = batch_directory(run, policy.batch_id)
    if load_batch_policy(directory / "policy.json") != policy:
        raise ValueError("checkpoint producer amendments require the unchanged original batch policy")
    expected = policy.implementation_sha256
    for sequence, path in enumerate(sorted((directory / "producer-amendments").glob("*.json"))):
        if path.name != f"{sequence:04d}.json":
            raise ValueError("checkpoint producer amendments must form a contiguous chain")
        amendment = CheckpointProducerAmendment.model_validate_json(path.read_bytes())
        if amendment.batch_policy_fingerprint != fingerprint(policy) or amendment.previous_sha256 != expected or (
            amendment.current_sha256 == expected
            or amendment.source_runtime_sha256 != policy.source_generation_runtime_sha256
        ):
            raise ValueError("checkpoint producer amendment changed its policy, source runtime or previous producer")
        for name, digest in ((amendment.previous_source, expected), (amendment.current_source, amendment.current_sha256)):
            source = (directory / name).resolve()
            if not source.is_relative_to(directory.resolve()) or file_sha256(source) != digest:
                raise ValueError("checkpoint producer archive changed or escaped its batch")
        expected = amendment.current_sha256
    from .transport_amendments import transport_checkpoint_producer
    plan = PreproductionPlan.model_validate_json((run / "plan.json").read_bytes())
    return transport_checkpoint_producer(plan, run, expected)


def record_checkpoint_producer_amendment(run: Path, batch_id: str, *, previous_source: Path,
                                        current_source: Path, reason: str) -> CheckpointProducerAmendment:
    from .preproduction import runtime_hashes

    directory = batch_directory(run, batch_id)
    policy = load_batch_policy(directory / "policy.json")
    plan = PreproductionPlan.model_validate_json((run / "plan.json").read_bytes())
    with locked_run(run, wait=True):
        previous = checkpoint_producer(run, policy)
        current = file_sha256(Path(__file__))
        if policy.plan_fingerprint != fingerprint(plan) or policy.source_generation_runtime_sha256 != runtime_hashes() or (
            effective_runtime(plan, run) != runtime_hashes() or current == previous
        ):
            raise ValueError("checkpoint producer amendment cannot change the approved source runtime or be a no-op")
        sources = []
        for source, digest in ((previous_source, previous), (current_source, current)):
            source = source.resolve()
            if not source.is_relative_to(directory.resolve()) or file_sha256(source) != digest:
                raise ValueError("checkpoint producer amendment requires both exact owned producer sources")
            sources.append(str(source.relative_to(directory.resolve())))
        amendment = CheckpointProducerAmendment(
            batch_policy_fingerprint=fingerprint(policy), previous_sha256=previous, current_sha256=current,
            previous_source=sources[0], current_source=sources[1],
            source_runtime_sha256=runtime_hashes(), reason=reason,
        )
        folder = directory / "producer-amendments"
        folder.mkdir(mode=0o700, exist_ok=True)
        immutable_json(folder / f"{len(list(folder.glob('*.json'))):04d}.json", amendment)
        return amendment


def _check_policy(plan: PreproductionPlan, run: Path, policy: CheckpointBatchPolicy) -> None:
    from .preproduction import runtime_hashes

    if policy.plan_fingerprint != fingerprint(plan) or checkpoint_producer(run, policy) != file_sha256(Path(__file__)):
        raise ValueError("generation policy does not bind this run and producer")
    from .transport_amendments import transport_runtime_matches
    if effective_runtime(plan, run) != runtime_hashes() or (
        policy.source_generation_runtime_sha256 != runtime_hashes()
        and not transport_runtime_matches(plan, run, policy.source_generation_runtime_sha256, runtime_hashes())
    ):
        raise ValueError("checkpoint generation requires the explicitly pinned source runtime")


def create_batch(run: Path, batch_id: str, *, checkpoint_size: int = 100, workers: int = 4,
                 quota_aware: bool = False, gateway: GatewayConfig | None = None) -> CheckpointBatchPolicy:
    from .preproduction import runtime_hashes

    plan = PreproductionPlan.model_validate_json((run / "plan.json").read_bytes())
    directory = batch_directory(run, batch_id)
    if (directory / "policy.json").exists():
        policy = load_batch_policy(directory / "policy.json")
        requested = policy.requested_checkpoint_size if isinstance(policy, QuotaCheckpointBatchPolicy) else policy.checkpoint_size
        if (requested, policy.workers, isinstance(policy, QuotaCheckpointBatchPolicy), policy.gateway) != (
            checkpoint_size, workers, quota_aware, gateway,
        ):
            raise ValueError("an existing checkpoint allocation or worker configuration cannot change")
        _check_policy(plan, run, policy)
        return policy
    if effective_runtime(plan, run) != runtime_hashes():
        raise ValueError("checkpoint generation requires the explicitly pinned source runtime")
    if quota_aware:
        targets = quota_targets(admission_progress(plan, run), checkpoint_size)
        policy = QuotaCheckpointBatchPolicy(
            plan_fingerprint=fingerprint(plan), batch_id=batch_id, workers=workers,
            source_generation_runtime_sha256=runtime_hashes(), implementation_sha256=file_sha256(Path(__file__)),
            user_authorization="astra_generation_checkpoint_reviews",
            checkpoint_size=sum(targets.values()), requested_checkpoint_size=checkpoint_size,
            scope_targets=targets,
            gateway=gateway,
        )
    else:
        policy = CheckpointBatchPolicy(
            plan_fingerprint=fingerprint(plan), batch_id=batch_id, workers=workers,
            source_generation_runtime_sha256=runtime_hashes(), implementation_sha256=file_sha256(Path(__file__)),
            user_authorization="astra_generation_checkpoint_reviews", checkpoint_size=checkpoint_size,
            gateway=gateway,
        )
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    immutable_json(directory / "policy.json", policy)
    immutable_json(directory / "producer.json", {
        "module": Path(__file__).name, "sha256": policy.implementation_sha256, "source": Path(__file__).read_text(),
    })
    _check_policy(plan, run, policy)
    return policy


@contextmanager
def _workflow_lock(run: Path):
    with (run / "checkpoint-workflow.lock").open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("another checkpoint workflow owns this run") from error
        yield


class CheckpointClient:
    """Route only fresh draft/repair roles to Astra; retain the original Sol validation client."""

    def __init__(self, plan: PreproductionPlan, policy: CheckpointBatchPolicy,
                 transport: NonStudentTransportPolicy, env_file: Path, root: Path, *,
                 execution_producer_sha256: str | None = None, run: Path | None = None):
        from .preproduction import task_generation_config

        config = None
        if run is not None:
            relative = root.resolve().relative_to((run / "attempts").resolve())
            config = task_generation_config(plan, run, relative.parts[0], env_file)
        if (config.gateway if config is not None else policy.gateway) is None:
            values = dotenv_values(env_file)
            endpoint = values.get("AZUREAI_OPENAI_BASE_URL")
            if not endpoint or hashlib.sha256(endpoint.encode()).hexdigest() != plan.model.endpoint_sha256 or (
                values.get("AZUREAI_OPENAI_API_VERSION") != plan.model.api_version
            ):
                raise ValueError("Astra must use the original approved endpoint and API version")
        self.policy, self.root = policy, root.resolve()
        self.execution_producer_sha256 = (
            policy.implementation_sha256 if execution_producer_sha256 is None else execution_producer_sha256
        )
        self.config = config if config is not None else AzureGenerationConfig(
            env_file=env_file, deployment=plan.model.deployment, timeout_seconds=plan.model.request_timeout_seconds,
            max_completion_tokens=plan.model.max_completion_tokens, reasoning_effort=plan.model.reasoning_effort,
            gateway=policy.gateway,
        )
        self.base = azure_review_client(self.config, transport, (self.root,))
        try:
            self.author = AzureGenerationClient(self.config.model_copy(update={
                "deployment": policy.generation_deployment, "timeout_seconds": policy.generation_timeout_seconds,
            }))
        except (ValueError, RuntimeError, OSError):
            self.base.close()
            raise

    def complete(self, messages: list[dict], tools: list[dict]) -> dict:
        matches = []
        for directory in {path.parent for path in self.root.rglob("*-request.json")}:
            path = sorted(directory.glob("*-request.json"))[-1]
            if path.with_name(path.name.replace("-request.json", "-response.json")).exists():
                continue
            request = json.loads(path.read_bytes())
            if request.get("messages") == messages and request.get("tools") == tools:
                matches.append((path, request))
        if len(matches) != 1:
            raise ValueError("checkpoint routing requires exactly one recorded outstanding request")
        path, request = matches[0]
        if request["role"] not in ("author", "repair"):
            return self.base.complete(messages, tools)
        if self.execution_producer_sha256 != file_sha256(Path(__file__)):
            raise ValueError("the generation implementation changed during inference")
        finish = [tool["function"] for tool in tools if tool.get("function", {}).get("name") == "finish"]
        if len(finish) != 1 or finish[0]["parameters"] != TaskDraft.model_json_schema():
            raise ValueError("Astra author must use the exact TaskDraft schema")
        if any((path.parent / name).exists() for name in ("complete.json", "result.json", "abstention.json")):
            raise ValueError("a completed draft role cannot be resampled")
        for previous in sorted(path.parent.glob("*-request.json")):
            if previous == path:
                continue
            receipt = previous.with_name(previous.name.replace("-request.json", "-generation-model.json"))
            recorded = json.loads(receipt.read_bytes()) if receipt.exists() else None
            if recorded is None or recorded["policy_fingerprint"] != fingerprint(self.policy) or (
                recorded["actual_config"] != self.author.config.model_dump(mode="json", exclude={"env_file"})
                or recorded["request_sha256"] != file_sha256(previous)
            ):
                raise ValueError("a started role cannot switch models or replay another model's encrypted context")
            if not previous.with_name(previous.name.replace("-request.json", "-response.json")).exists():
                error_path = previous.with_name(previous.name.replace("-request.json", "-error.json"))
                if not error_path.exists() or json.loads(error_path.read_bytes()).get("status") != "retry_wait":
                    raise ValueError("an uncertain earlier generation call requires explicit recovery")
        receipt = path.with_name(path.name.replace("-request.json", "-generation-model.json"))
        immutable_json(receipt, {
            "policy_fingerprint": fingerprint(self.policy), "request_sha256": file_sha256(path),
            "execution_producer_sha256": self.execution_producer_sha256,
            "actual_config": self.author.config.model_dump(mode="json", exclude={"env_file"}),
            "review_student_default": self.config.model_dump(mode="json", exclude={"env_file"}),
        })
        response = self.base.complete_with_credentials(self.author, messages, tools)
        return {**response, "generation_model": {
            "policy_fingerprint": fingerprint(self.policy), "receipt_sha256": file_sha256(receipt),
            "execution_producer_sha256": self.execution_producer_sha256,
            "deployment": self.policy.generation_deployment,
        }}

    def close(self):
        try:
            self.author.close()
        finally:
            self.base.close()


def _targets(size: int) -> dict[str, int]:
    incident_count = (size + 1) // 2
    result = {f"incident:{incident}": incident_count // len(SELECTED_INCIDENTS) for incident in SELECTED_INCIDENTS}
    for incident in SELECTED_INCIDENTS[:incident_count % len(SELECTED_INCIDENTS)]:
        result[f"incident:{incident}"] += 1
    return {**result, "tenant": size - incident_count}


def quota_targets(progress: dict, maximum: int = 100) -> dict[str, int]:
    if type(maximum) is not int or not 1 <= maximum <= 100:
        raise ValueError("quota-aware checkpoint size must be between one and one hundred")
    scopes = _targets(maximum)
    capacity = {}
    for name in scopes:
        remaining = progress["buckets"][name]["validated_shortfall"]
        attempts = progress["buckets"][name]["remaining_logical_attempts"]
        if any(type(value) is not int or value < 0 for value in (remaining, attempts)):
            raise ValueError("remaining scope quotas and attempt capacity must be nonnegative integers")
        capacity[name] = min(remaining, attempts)
    size = min(maximum, sum(capacity.values()))
    if not size:
        raise ValueError("no remaining admission quota with available logical attempts")
    incident_capacity = sum(value for name, value in capacity.items() if name != "tenant")
    incident_count = min((size + 1) // 2, incident_capacity)
    tenant_count = min(size - incident_count, capacity["tenant"])
    incident_count += size - incident_count - tenant_count
    targets = {name: 0 for name in scopes}
    targets["tenant"] = tenant_count
    incidents = [name for name in scopes if name != "tenant"]
    for _ in range(incident_count):
        available = [name for name in incidents if targets[name] < capacity[name]]
        selected = min(available, key=lambda name: targets[name])
        targets[selected] += 1
    return targets


def batch_targets(policy: CheckpointBatchPolicy) -> dict[str, int]:
    return dict(policy.scope_targets) if isinstance(policy, QuotaCheckpointBatchPolicy) else _targets(policy.checkpoint_size)


def _items(directory: Path) -> list[dict]:
    return [json.loads(path.read_bytes()) for path in sorted((directory / "items").glob("*.json"))]


def _item_state(run: Path, item: dict, filename: str) -> dict | None:
    path = run / "attempts" / item["attempt"]["task_id"] / filename
    return json.loads(path.read_bytes()) if path.exists() else None


def _question_inventory(plan: PreproductionPlan, run: Path) -> dict[str, list[str]]:
    questions: dict[str, list[str]] = {}
    for task in plan.seed_questions:
        bucket = f"incident:{task.scope.incident_id}" if task.scope.mode == "incident" else "tenant"
        questions.setdefault(bucket, []).append(task.question)
    for other in plan.attempts():
        folder = run / "attempts" / other.task_id
        if (folder / "source-outcome.json").exists():
            source, _, _ = current_source(plan, run, other.task_id)
        else:
            source = folder / "source"
        if (source / "task.json").exists():
            questions.setdefault(_bucket(other), []).append(TaskRecord.model_validate_json((source / "task.json").read_bytes()).question)
    return {key: list(dict.fromkeys(values)) for key, values in questions.items()}


def _materialize_reservation(plan: PreproductionPlan, run: Path, policy: CheckpointBatchPolicy, item: dict) -> Path:
    attempt = DevelopmentAttempt.model_validate_json(json.dumps(item["attempt"]))
    if item["policy_fingerprint"] != fingerprint(policy) or attempt not in plan.attempts():
        raise ValueError("batch reservation is not bound to an allocated campaign slot")
    folder = run / "attempts" / attempt.task_id
    folder.mkdir(parents=True, mode=0o700, exist_ok=True)
    immutable_json(folder / "attempt.json", {
        "plan_fingerprint": fingerprint(plan), "attempt": attempt.model_dump(mode="json"),
        "previous_questions": item["previous_questions"], "logical_attempt_count": 1,
    })
    immutable_json(folder / "generation-batch.json", {
        "batch_id": policy.batch_id, "policy_fingerprint": fingerprint(policy),
        "reservation_fingerprint": _digest(item),
    })
    return folder


def reserve_drafts(plan: PreproductionPlan, run: Path, policy: CheckpointBatchPolicy, count: int,
                   questions: dict[str, list[str]]) -> list[dict]:
    directory = batch_directory(run, policy.batch_id)
    with locked_run(run, wait=True):
        progress = admission_progress(plan, run) if isinstance(policy, QuotaCheckpointBatchPolicy) else None
        existing = _items(directory)
        for item in existing:
            _materialize_reservation(plan, run, policy, item)
        targets = batch_targets(policy)
        if progress is not None and any(
            target > progress["buckets"][name]["validated_shortfall"] for name, target in targets.items()
        ):
            raise ValueError("admission quotas changed after this checkpoint allocation; do not generate surplus scope drafts")
        pending = [item for item in existing if _item_state(run, item, "draft-result.json") is None]
        if pending:
            return pending[:count]
        done = Counter()
        for item in existing:
            result = _item_state(run, item, "draft-result.json")
            if result is not None and result["status"] == "draft_ready":
                done[item["bucket"]] += 1
        selected = []
        available = [attempt for attempt in plan.attempts() if not (run / "attempts" / attempt.task_id).exists()]
        while len(selected) < count:
            remaining = [key for key, target in targets.items() if done[key] < target]
            if not remaining:
                break
            bucket = max(remaining, key=lambda key: (targets[key] - done[key]) / targets[key])
            attempt = next((value for value in available if _bucket(value) == bucket), None)
            if attempt is None:
                targets[bucket] = done[bucket]
                continue
            available.remove(attempt)
            item = {"policy_fingerprint": fingerprint(policy), "attempt": attempt.model_dump(mode="json"),
                    "bucket": bucket, "previous_questions": list(questions.get(bucket, ()))}
            (directory / "items").mkdir(mode=0o700, exist_ok=True)
            immutable_json(directory / "items" / (attempt.task_id + ".json"), item)
            _materialize_reservation(plan, run, policy, item)
            selected.append(item)
            done[bucket] += 1
        return selected


def _verify_generation_files(folder: Path, result: dict) -> None:
    if any(file_sha256(folder / "source" / name) != digest for name, digest in result["generation_artifacts_sha256"].items()):
        raise ValueError("an accepted generated draft or its original trace changed")


def cast_mysql_json_inputs(query: str) -> str:
    try:
        tree = sqlglot.parse_one(query, read="mysql")
    except (ParseError, TokenError) as error:
        raise ValueError(
            "MySQL program is unsupported by the pinned SQL parser. Use supported syntax; "
            "JSON_TABLE may omit explicit NULL ON EMPTY/NULL ON ERROR defaults. " + str(error)
        ) from error
    changed = False
    for node in tree.find_all(exp.JSONTable):
        target = node.this.args.get("to") if isinstance(node.this, exp.Cast) else None
        if not isinstance(target, exp.DataType) or target.this != exp.DataType.Type.JSON:
            node.set("this", exp.Cast(this=node.this.copy(), to=exp.DataType.build("JSON")))
            changed = True
    return tree.sql(dialect="mysql") if changed else query


def selector_issue_identifiers(audit: QualityAudit) -> list[dict]:
    return [{"issue_fingerprint": fingerprint(issue), "issue": issue.model_dump(mode="json")} for issue in audit.issues]


def current_json_recovery_policy(run: Path, plan_fingerprint: str) -> JsonResultRecoveryPolicy | None:
    policies = sorted(run.glob("json-result-recovery-policy*.json"))
    if not policies:
        return None
    implementation = file_sha256(Path(__file__).with_name("json_result_recovery.py"))
    matches = {}
    for path in policies:
        policy = JsonResultRecoveryPolicy.model_validate_json(path.read_bytes())
        if policy.plan_fingerprint == plan_fingerprint and policy.implementation_sha256 == implementation:
            matches[fingerprint(policy)] = policy
    if len(matches) != 1:
        raise ValueError("JSON result recovery requires one approved policy for this plan and current producer")
    return next(iter(matches.values()))


def _compile(draft: TaskDraft, verifier: EvidenceVerifier, attempt: DevelopmentAttempt, revision: str,
             checkpoint_cap: float) -> TaskRecord:
    public = draft.context + "\n" + draft.question + "\n" + str(attempt.incident_id or "")
    undisclosed = [literal.value for literal in draft.allowed_literals
                   if literal.basis == "public_anchor" and literal.value not in public]
    if undisclosed:
        raise ValueError("Public-anchor literals are not explicit. Derive private answers rather than exposing them: " + repr(undisclosed))
    for claim in (draft.final, *(checkpoint.claim for checkpoint in draft.checkpoints)):
        for program in (*claim.programs, *claim.witness_programs):
            if program.engine != "mysql":
                continue
            queries = [program.query]
            if isinstance(program, QualifiedWitnessProgram):
                queries.extend((program.obligations_query, program.candidates_query))
            for query in queries:
                if re.search(r"\bVARCHAR\s*\(\s*\d+\s*\)", query, re.I):
                    raise ValueError("Use width-free TEXT in MySQL gold declarations, not arbitrary VARCHAR capacities")
                if cast_mysql_json_inputs(query) != query:
                    raise ValueError(f"{program.program_id}: explicitly CAST every JSON_TABLE input AS JSON to preserve native CTE typing")
    task = compile_draft(draft, verifier, mode=attempt.mode, incident_id=attempt.incident_id,
                         task_id=attempt.task_id, revision_id=revision, lineage_group=attempt.task_id,
                         checkpoint_cap=checkpoint_cap)
    return task


def draft_candidate(*, plan: PreproductionPlan, run: Path, policy: CheckpointBatchPolicy, item: dict,
                    serving: Path, graph_bundle: Path, client, source: Path | None = None,
                    previous: Path | None = None, feedback: str | None = None) -> TaskRecord:
    attempt = DevelopmentAttempt.model_validate_json(json.dumps(item["attempt"]))
    folder = run / "attempts" / attempt.task_id
    source = source or folder / "source"
    source.mkdir(mode=0o700, parents=True, exist_ok=True)
    engine = open_duckdb_engine(serving, plan.query_limits)
    initial = graph = None
    try:
        initial = EvidenceVerifier(serving, engine, frozenset())
        graph = GraphDiscovery(graph_bundle, initial)
        tools = DiscoveryTools(engine, initial.tables, graph.neighbors)
        scope = scope_context(engine, attempt.mode, attempt.incident_id)
        context = {"scope": scope, "previous_questions": item["previous_questions"],
                   "task_id": attempt.task_id, "batch_policy_fingerprint": fingerprint(policy), "checkpoint_reviews_deferred": True}
        revision, role = "r1", "author"
        old = None
        if previous is not None:
            old = TaskRecord.model_validate_json((previous / "task.json").read_bytes())
            revision = f"r{int(old.revision_id.removeprefix('r')) + 1}"
            context.update(previous_draft=json.loads((previous / "draft.json").read_bytes()), repair_feedback=feedback)
            role = "repair"
        cached = (source / role / "complete.json").exists()
        if any((source / role).glob("*-request.json")) and not cached:
            raise ValueError("a started draft requires its recorded result or explicit recovery, not another model sample")
        immutable_json(source / "scope.json", scope)
        immutable_json(source / "execution-policy.json", {
            "scope": attempt.mode, "incident_id": attempt.incident_id, "serving_view_id": plan.serving_view_id,
            "query_limits": plan.query_limits.model_dump(mode="json"), "checkpoint_cap": plan.checkpoint_cap,
            "source_quality_policy": QUALITY_VERSION, "source_quality_runtime_sha256": quality_hashes(),
            "generation_policy": policy.model_dump(mode="json"), "release_approved": False,
        })
        compiled = {}

        def validate(draft: TaskDraft):
            verifier = EvidenceVerifier(serving, engine, frozenset(value.value for value in draft.allowed_literals))
            try:
                task = _compile(draft, verifier, attempt, revision, plan.checkpoint_cap)
                if old is not None:
                    from .preproduction_revisions import _validate_repair
                    _validate_repair(old, task, True)
                audit = audit_source_quality(task, verifier, serving)
                if audit.collection_failures():
                    raise ValueError("each complete proof alternative must reproduce the entire requested collection")
                compiled.update(task=task, audit=audit, mechanical=verifier.mechanical_report(task))
            finally:
                verifier.close()

        try:
            draft = run_role(client, tools, role, DRAFT_INSTRUCTIONS, context, TaskDraft, source / role,
                             resume=cached, validate_result=validate)
        except ValueError as error:
            if str(error) != "role stopped without an explicit structured finish result":
                raise
            recovery_policy = current_json_recovery_policy(run, fingerprint(plan))
            if recovery_policy is None:
                raise
            draft = recover_json_result(
                directory=source / role, root=source,
                policy=recovery_policy,
                transport_policy=load_run_transport_policy(run, fingerprint(plan)),
                response_type=TaskDraft, tools=DiscoveryTools(engine, initial.tables, graph.neighbors),
                validate_result=lambda value, _tools: validate(value),
            )
        task = compiled["task"]
        immutable_json(source / "draft.json", draft)
        immutable_json(source / "task.json", task)
        immutable_json(source / "mechanical-validation.json", compiled["mechanical"])
        immutable_json(source / "draft-quality-audit.json", compiled["audit"])
        return task
    finally:
        if graph is not None:
            graph.close()
        if initial is not None:
            initial.close()
        engine.connection.close()


def review_source(
    *, plan: PreproductionPlan, source: Path, serving: Path, client,
    native_context_provider: Callable[[TaskRecord, EvidenceVerifier], dict] | None = None,
) -> dict:
    task = TaskRecord.model_validate_json((source / "task.json").read_bytes())
    draft = TaskDraft.model_validate_json((source / "draft.json").read_bytes())
    engine = open_duckdb_engine(serving, plan.query_limits)
    verifier = None
    try:
        verifier = EvidenceVerifier(serving, engine, frozenset(value.value for value in draft.allowed_literals))
        audit = QualityAudit.model_validate_json((source / "draft-quality-audit.json").read_bytes())
        if audit.task_fingerprint != fingerprint(task) or audit.implementation_sha256 != quality_hashes():
            raise ValueError("draft quality audit differs from the current task or source-quality runtime")
        native_context = None
        if native_context_provider is not None:
            native_context = native_context_provider(task, verifier)
            if (native_context.get("task_fingerprint"), native_context.get("plan_fingerprint"),
                native_context.get("native_snapshot_sha256")) != (
                fingerprint(task), fingerprint(plan), plan.native_snapshot_sha256,
            ):
                raise ValueError("source review native context belongs to different task or snapshot inputs")
            parity = GateResult.model_validate_json(json.dumps(native_context["baseline_source_native_parity"]))
            if parity.gate != "serving_parity":
                raise ValueError("source review requires actual source/native parity, not a substitute gate")
            immutable_json(source / "native-source-preflight.json", native_context)
            if parity.status != "pass":
                report = {
                    "status": "needs_revision", "task_fingerprint": fingerprint(task),
                    "source_quality": {"status": "not_run", "reason": "native_preflight_failed"},
                    "native_preflight": parity.model_dump(mode="json"), "blind_started": False,
                    "mysql_validated": False, "release_approved": False,
                    "reason": "Native contract preflight failed before source review or student sampling: " + parity.reason,
                }
                immutable_json(source / "pilot_report.json", report)
                return report
        review_context = {
            "draft": draft.model_dump(mode="json"), "selector_issue_identifiers": selector_issue_identifiers(audit),
            "selector_identifier_instruction": "Copy each supplied issue_fingerprint exactly; query_sha256 is not the issue identifier.",
        }
        if native_context is not None:
            review_context.update(
                verified_native_semantics=native_context,
                actual_verifier_diagnostics=contract_proof_diagnostics(task, verifier),
                behavior_flag_semantics="A required behavior witness may contain behavior OR security_control lineage.",
                student_outcomes_supplied=False,
            )
        gate, review = run_quality_gate(
            client=client, task=task, verifier=verifier, serving_bundle=serving, output=source / "quality",
            instructions=REFUTER_INSTRUCTIONS,
            review_context=review_context,
        )
        report = {"status": "needs_revision", "task_fingerprint": fingerprint(task), "source_quality": gate,
                  "blind_started": False, "mysql_validated": False, "release_approved": False}
        if gate["status"] == "pass" and review is not None:
            (source / "refuter").mkdir(mode=0o700)
            immutable_json(source / "refuter/result.json", review)

            def validate_blind(value):
                for citation in value.citations:
                    verifier.citation_lineage(citation)

            blind = run_role(client, DiscoveryTools(engine, verifier.tables, record_findings=True),
                             "blind", BLIND_INSTRUCTIONS, task.public_task().model_dump(mode="json"),
                             BlindSolution, source / "blind", validate_result=validate_blind)
            proofs = verifier.preflight(task)
            observed = frozenset(observed_role_citations(verifier, source / "blind", task))
            correct = compare_typed_answers(task.private_gold.final.expected, blind.answer)
            grounded = verifier.evidence_matches(Finding(answer=blind.answer, citations=blind.citations, step=0),
                                                 proofs["final"], claim=task.private_gold.final)
            complete = verifier.complete_witness_observed(task.private_gold.final, proofs["final"], observed)
            report.update(blind_started=True, blind_answer_correct=correct, blind_evidence_grounded=grounded,
                          complete_witness_observed=complete, independent_review=review.model_dump(mode="json"))
            if correct and complete and blind.confidence == "supported":
                report["status"] = "candidate_for_mysql_validation"
        immutable_json(source / "pilot_report.json", report)
        return report
    finally:
        if verifier is not None:
            verifier.close()
        engine.connection.close()


def source_repair_feedback(source: Path) -> dict:
    review = source / "quality/reviewer/result.json"
    if review.exists():
        return {"recorded_checkpoint_review": json.loads(review.read_bytes())}
    preflight = source / "native-source-preflight.json"
    if preflight.exists():
        context = json.loads(preflight.read_bytes())
        parity = GateResult.model_validate_json(json.dumps(context["baseline_source_native_parity"]))
        task = TaskRecord.model_validate_json((source / "task.json").read_bytes())
        if context["task_fingerprint"] != fingerprint(task) or parity.gate != "serving_parity" or parity.status == "pass":
            raise ValueError("source repair lacks a matching failed native preflight")
        return {"recorded_native_preflight": context}
    raise ValueError("source repair requires a recorded semantic review or native contract failure")


def _outcome(plan, run, item, status, task_fp, reason):
    folder = run / "attempts" / item["attempt"]["task_id"]
    immutable_json(folder / "source-outcome.json", SourceOutcome(
        plan_fingerprint=fingerprint(plan), attempt_binding_sha256=file_sha256(folder / "attempt.json"),
        attempt=DevelopmentAttempt.model_validate_json(json.dumps(item["attempt"])), status=status,
        task_fingerprint=task_fp, reason=reason, artifact_sha256=_artifacts(folder / "source"),
    ))


def checkpoint_progress(run: Path, batch_id: str, *, verification: ArtifactVerification | None = None) -> dict:
    return checkpoint_progress_with_campaign(run, batch_id, verification=verification)[0]


def checkpoint_progress_with_campaign(
    run: Path, batch_id: str, *, verification: ArtifactVerification | None = None,
) -> tuple[dict, dict]:
    """Return the existing checkpoint summary and its single current campaign calculation."""
    directory = batch_directory(run, batch_id)
    policy = load_batch_policy(directory / "policy.json")
    plan = PreproductionPlan.model_validate_json((run / "plan.json").read_bytes())
    campaign = (admission_progress(plan, run) if verification is None
                else admission_progress(plan, run, verification=verification))
    items = _items(directory)
    drafts, reviews, gates = Counter(), Counter(), Counter()
    repairs = []
    for item in items:
        folder = run / "attempts" / item["attempt"]["task_id"]
        draft = _item_state(run, item, "draft-result.json")
        review = _item_state(run, item, "checkpoint-review-result.json")
        pipeline = _item_state(run, item, "checkpoint-pipeline-result.json")
        drafts[draft["status"] if draft else "pending"] += 1
        if draft and draft["status"] == "draft_ready":
            _verify_generation_files(folder, draft)
        history = sorted((folder / "checkpoint-repairs").glob("*.json"))
        if history:
            latest = json.loads(history[-1].read_bytes())
            review = {"status": latest["source_status"]}
            pipeline = latest.get("pipeline")
        reviews[review["status"] if review else "pending"] += 1
        gates[pipeline["status"] if pipeline else "pending"] += 1
        for stage, value in (("generation", draft), ("source_review", review), ("admission_pipeline", pipeline)):
            if value and value["status"] not in ("draft_ready", "source_ready", "admitted", "already_admitted"):
                repairs.append({"task_id": item["attempt"]["task_id"], "stage": stage, **value})
    return {
        "batch_id": batch_id, "policy_fingerprint": fingerprint(policy), "checkpoint_size": policy.checkpoint_size,
        "scope_targets": batch_targets(policy),
        "logical_attempts_in_batch": len(items), "drafts": dict(drafts), "source_reviews": dict(reviews),
        "admission_pipelines": dict(gates), "ready_for_checkpoint": drafts["draft_ready"] >= policy.checkpoint_size,
        "repair_queue": repairs, "source_ready_is_not_admission": True, "release_approved": False,
        "campaign": {key: campaign[key] for key in ("logical_attempts_started", "source_ready", "validated_new_questions")},
    }, campaign


def _parallel(items, workers, operation):
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(operation, item): item for item in items}
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            print(json.dumps({key: value for key, value in result.items()
                              if key in ("task_id", "status", "stage", "elapsed_seconds", "reason")}), flush=True)
    return results


def _client(plan, policy, run, env_file, source):
    transport = load_run_transport_policy(run, fingerprint(plan))
    if transport.plan_fingerprint != fingerprint(plan):
        raise ValueError("the validation model policy belongs to another run")
    return CheckpointClient(plan, policy, transport, env_file, source,
                            execution_producer_sha256=checkpoint_producer(run, policy), run=run)


def generate_checkpoint(*, run: Path, batch_id: str, serving: Path, graph: Path, env_file: Path,
                        max_new_attempts: int | None = None, runner=draft_candidate) -> dict:
    if (run / "checkpoint-revalidation-required.json").exists():
        raise ValueError("checkpoint revalidation is pending; further question generation is blocked")
    plan = PreproductionPlan.model_validate_json((run / "plan.json").read_bytes())
    policy = load_batch_policy(batch_directory(run, batch_id) / "policy.json")
    _check_policy(plan, run, policy)
    if max_new_attempts is not None and max_new_attempts <= 0:
        raise ValueError("the explicit smoke-run attempt limit must be positive")
    if (file_sha256(serving / "serving_report.json"), file_sha256(graph / "graph_report.json")) != (
        plan.serving_report_sha256, plan.graph_report_sha256,
    ):
        raise ValueError("generation source snapshot changed")
    with _workflow_lock(run):
        source_progress(plan, run)
        checkpoint_progress(run, batch_id)
        questions = _question_inventory(plan, run)
        started = 0

        def generate(item):
            folder = run / "attempts" / item["attempt"]["task_id"]
            source = folder / "source"
            start = time.monotonic()
            client = None
            task_fp = None
            try:
                client = _client(plan, policy, run, env_file, source)
                task = runner(plan=plan, run=run, policy=policy, item=item, serving=serving, graph_bundle=graph, client=client)
                task_fp = fingerprint(task)
                result = {"status": "draft_ready", "task_fingerprint": task_fp,
                          "generation_artifacts_sha256": _artifacts(source), "semantic_review_deferred": True,
                          "execution_producer_sha256": file_sha256(Path(__file__))}
            except RoleAbstained as error:
                result = {"status": "no_supported_candidate", "reason": str(error)}
                _outcome(plan, run, item, result["status"], task_fp, result["reason"])
            except ITEM_ERRORS as error:
                result = {"status": "operational_error", "reason": f"{type(error).__name__}: {error}"}
                if (source / "task.json").exists():
                    try:
                        task_fp = fingerprint(TaskRecord.model_validate_json((source / "task.json").read_bytes()))
                    except (ValueError, OSError) as artifact_error:
                        result["reason"] += f"; unbound task artifact: {artifact_error}"
                _outcome(plan, run, item, result["status"], task_fp, result["reason"])
            finally:
                if client is not None:
                    client.close()
            result.update(elapsed_seconds=time.monotonic() - start, task_id=item["attempt"]["task_id"])
            immutable_json(folder / "draft-result.json", result)
            return result

        while sum((_item_state(run, item, "draft-result.json") or {}).get("status") == "draft_ready"
                  for item in _items(batch_directory(run, batch_id))) < policy.checkpoint_size:
            count = policy.workers if max_new_attempts is None else min(policy.workers, max_new_attempts - started)
            if count <= 0:
                break
            items = reserve_drafts(plan, run, policy, count, questions)
            if not items:
                break
            results = _parallel(items, policy.workers, generate)
            started += len(items)
            for item in items:
                result = _item_state(run, item, "draft-result.json")
                if result is not None and result["status"] == "draft_ready":
                    task = TaskRecord.model_validate_json((run / "attempts" / result["task_id"] / "source/task.json").read_bytes())
                    questions.setdefault(item["bucket"], []).append(task.question)
            if results and all(result["status"] == "operational_error" for result in results):
                break
        report = checkpoint_progress(run, batch_id)
        history = batch_directory(run, batch_id) / "generation-runs"
        history.mkdir(mode=0o700, exist_ok=True)
        immutable_json(history / f"{len(list(history.glob('*.json'))):04d}.json", report)
        return report


def review_checkpoint(*, run: Path, batch_id: str, serving: Path, graph: Path, mysql_bundle: Path,
                      env_file: Path, workdir: Path, source_runner=review_source, pipeline_runner=None) -> dict:
    plan = PreproductionPlan.model_validate_json((run / "plan.json").read_bytes())
    directory = batch_directory(run, batch_id)
    policy = load_batch_policy(directory / "policy.json")
    _check_policy(plan, run, policy)
    with _workflow_lock(run):
        progress = checkpoint_progress(run, batch_id)
        if not progress["ready_for_checkpoint"]:
            raise ValueError("semantic review cannot start before the candidate checkpoint is filled")
        items = [item for item in _items(directory) if (_item_state(run, item, "draft-result.json") or {}).get("status") == "draft_ready"]

        def review(item):
            existing = _item_state(run, item, "checkpoint-review-result.json")
            if existing is not None:
                return existing
            folder = run / "attempts" / item["attempt"]["task_id"]
            source = folder / "source"
            task = TaskRecord.model_validate_json((source / "task.json").read_bytes())
            if (folder / "source-outcome.json").exists():
                _, outcome, _ = current_source(plan, run, task.task_id)
                if outcome is None or outcome.task_fingerprint != fingerprint(task):
                    raise ValueError("saved source outcome does not bind the generated task")
                result = {"task_id": task.task_id, "status": outcome.status, "reason": outcome.reason,
                          "recovered_outcome_publication": True}
                immutable_json(folder / "checkpoint-review-result.json", result)
                return result
            client = None
            start = time.monotonic()
            try:
                if (source / "quality").exists():
                    raise ValueError("a started source review requires explicit boundary recovery, not a new sample")
                client = _client(plan, policy, run, env_file, source)
                report = source_runner(plan=plan, source=source, serving=serving, client=client)
                if report.get("task_fingerprint") != fingerprint(task) or report["status"] not in (
                    "candidate_for_mysql_validation", "needs_revision",
                ) or json.loads((source / "pilot_report.json").read_bytes()) != json.loads(json.dumps(report, allow_nan=False)):
                    raise ValueError("checkpoint source report does not bind the actual task and outcome")
                if report["status"] == "candidate_for_mysql_validation":
                    validate_quality_gate(source, task)
                status = "source_ready" if report["status"] == "candidate_for_mysql_validation" else "needs_revision"
                reason = report.get("reason") or (
                    "Checkpoint source review and original student completed; final admission remains separate."
                    if report.get("blind_started") else
                    "Checkpoint source review needs revision; no source student was sampled."
                )
            except RoleAbstained as error:
                status, reason = "needs_revision", str(error)
            except ITEM_ERRORS as error:
                status, reason = "operational_error", f"{type(error).__name__}: {error}"
            finally:
                if client is not None:
                    client.close()
            _outcome(plan, run, item, status, fingerprint(task), reason)
            result = {"task_id": task.task_id, "status": status, "reason": reason, "elapsed_seconds": time.monotonic() - start}
            immutable_json(folder / "checkpoint-review-result.json", result)
            return result

        _parallel(items, policy.workers, review)
        ready = [item for item in items if (_item_state(run, item, "checkpoint-review-result.json") or {})["status"] == "source_ready"]

        def finish(item):
            existing = _item_state(run, item, "checkpoint-pipeline-result.json")
            if existing is not None:
                return existing
            start = time.monotonic()
            task_id = item["attempt"]["task_id"]
            try:
                result = (pipeline_runner or finish_checkpoint_candidate)(
                    plan=plan, run=run, policy=policy, task_id=task_id, serving=serving, graph=graph,
                    mysql_bundle=mysql_bundle, env_file=env_file, workdir=workdir,
                )
                result = {key: value for key, value in result.items() if key != "artifacts_sha256"}
            except ITEM_ERRORS as error:
                result = {"task_id": task_id, "status": "operational_error", "reason": f"{type(error).__name__}: {error}"}
            result["elapsed_seconds"] = time.monotonic() - start
            immutable_json(run / "attempts" / task_id / "checkpoint-pipeline-result.json", result)
            return result

        _parallel(ready, policy.workers, finish)
        report = checkpoint_progress(run, batch_id)
        immutable_json(directory / "checkpoint-report.json", report)
        return report


def finish_checkpoint_candidate(*, plan, run, policy, task_id, serving, graph, mysql_bundle, env_file, workdir):
    source, outcome, _ = current_source(plan, run, task_id)
    if outcome is None or outcome.status != "source_ready":
        raise ValueError("checkpoint validation requires the bound current source-ready candidate")
    task = TaskRecord.model_validate_json((source / "task.json").read_bytes())
    draft = TaskDraft.model_validate_json((source / "draft.json").read_bytes())
    output = run / "attempts" / task_id / "pipeline" / task.revision_id
    if output.exists() and not (output / "pipeline-report.json").exists():
        raise ValueError("an existing candidate pipeline requires explicit recovery, not a new student")
    literals = frozenset(value.value for value in draft.allowed_literals)
    limits = plan.query_limits.model_copy(update={"timeout_ms": plan.grader_timeout_ms or plan.query_limits.timeout_ms})
    engine = open_duckdb_engine(serving, limits)
    verifier = client = None
    try:
        verifier = EvidenceVerifier(serving, engine, literals)
        client = _client(plan, policy, run, env_file, output)
        from .preproduction import task_model_binding, validate_task_client
        validate_task_client(plan, run, task_id, client)
        if configured_model_binding(client) != task_model_binding(plan, run, task_id):
            raise ValueError("the review/student model settings changed")
        metadata = json.loads((mysql_bundle / "mysql_report.json").read_bytes())

        @contextmanager
        def native_lease():
            with (run / "native-stage-queue.lock").open("a+") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                with owned_review_engines(plan, serving, mysql_bundle, workdir, literals) as (_, native, student, _):
                    yield native, student

        return run_candidate_pipeline(
            plan=plan, run=run, task_id=task_id, client=client, source=verifier, mysql=None, student=None,
            serving_bundle=serving, mysql_bundle=mysql_bundle, graph_bundle=graph,
            mysqld=Path(metadata["mysqld_binary"]), workdir=workdir, output=output, native_engines=native_lease,
            resume=output.exists(),
        )
    finally:
        if client is not None:
            client.close()
        if verifier is not None:
            verifier.close()
        engine.connection.close()


def repair_checkpoint(*, run: Path, batch_id: str, task_ids: tuple[str, ...], serving: Path, graph: Path,
                      mysql_bundle: Path, env_file: Path, workdir: Path) -> dict:
    plan = PreproductionPlan.model_validate_json((run / "plan.json").read_bytes())
    directory = batch_directory(run, batch_id)
    policy = load_batch_policy(directory / "policy.json")
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
                raise ValueError("automatic regeneration is pre-blind only; completed students require supervised retained-trace repair")
        results = []
        for task_id in task_ids:
            source, _, _ = current_source(plan, run, task_id)
            feedback = json.dumps({**source_repair_feedback(source),
                                   "instruction": "Repair the actual defect; preserve original typed goals, meaningful checkpoints and source scope."})
            client = _client(plan, policy, run, env_file, run / "attempts" / task_id)
            try:
                def runner(**kwargs):
                    draft_candidate(
                        plan=plan, run=run, policy=policy, item=items[task_id], serving=serving,
                        graph_bundle=graph, client=kwargs["client"], source=kwargs["output"],
                        previous=kwargs["revision_from"], feedback=kwargs["revision_feedback"],
                    )
                    return review_source(plan=plan, source=kwargs["output"], serving=serving, client=kwargs["client"])

                outcome = run_source_revision(plan=plan, client=client, serving_bundle=serving, graph_bundle=graph,
                                              output=run, task_id=task_id, feedback=feedback, runner=runner)
                result = {"task_id": task_id, "source_status": outcome.status, "pipeline": None}
                if outcome.status == "source_ready":
                    result["pipeline"] = finish_checkpoint_candidate(
                        plan=plan, run=run, policy=policy, task_id=task_id, serving=serving, graph=graph,
                        mysql_bundle=mysql_bundle, env_file=env_file, workdir=workdir,
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
        return {"batch_id": batch_id, "repairs": results, "release_approved": False}
