# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Final private admission receipts, separate from source attempts and student success."""

from __future__ import annotations

import hashlib
import fcntl
import json
from contextlib import nullcontext
from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
from typing import Callable, Literal
import zipfile

from pydantic import Field, model_validator

from .contracts import Contract, Digest, EvaluationRecord, Identifier, TaskRecord, Text, ValidationReport, fingerprint, require_unique
from .difficulty import DifficultyPlan, DifficultyReview, DifficultySidecar
from .difficulty_curation import DifficultyAssessment, DifficultyProposal, _runtime_hashes as difficulty_runtime_hashes
from .grading_review import POLICY_VERSION as GRADING_POLICY_VERSION, ReviewedGradingAmendment, load_reviewed_grading
from .ledger import file_sha256
from .model_panel import immutable_json
from .preproduction import ModelBinding, PreproductionPlan, locked_run, source_progress, task_model_binding
from .quality import validate_quality_gate
from .query import QueryLimits
from .question_splits import QuestionBinding, SplitInputs, binding_for, load_questions
from .robustness import (
    RobustnessPlan, RobustnessReport, RUNTIME_FILES as ROBUSTNESS_RUNTIME_FILES,
    _answer_vectors_equal, _expected_answers, _groups,
)


VERSION = "preproduction-private-admission-v1"
NATIVE_RUNTIME_FILES = (
    "contracts.py", "evidence.py", "qualified_witnesses.py", "query.py", "scoring.py",
    "generation.py", "azure_generation.py", "gateway.py", "pilot_evaluation.py", "mysql_serving.py",
    "secrl_adapter.py", "acesevals_adapter.py",
)


class NativeBinding(Contract):
    task_fingerprint: Digest
    plan_fingerprint: Digest
    serving_view_id: Identifier
    native_snapshot_sha256: Digest
    native_indexes_sha256: Digest
    model: ModelBinding
    student_query_limits: QueryLimits
    grader_query_limits: QueryLimits
    implementation_sha256: dict[str, Digest]


class NativeStudentImport(Contract):
    policy_version: Literal["preproduction-retained-native-v1"] = "preproduction-retained-native-v1"
    task_fingerprint: Digest
    recorded_task_fingerprint: Digest
    plan_fingerprint: Digest
    parent_pipeline: Text
    recorded_task: Text
    runtime_archive: Text
    source_artifacts_sha256: dict[str, Digest]
    new_student_calls: Literal[0] = 0


class NativePrefixImportAuthorization(Contract):
    policy_version: Literal[
        "interrupted-robustness-native-prefix-v1", "interrupted-canonical-native-prefix-v2",
    ] = "interrupted-robustness-native-prefix-v1"
    interrupted_stage: Literal["robustness", "canonical"] = "robustness"
    plan_fingerprint: Digest
    task_fingerprint: Digest
    parent_binding_sha256: Digest
    native_stage_receipt_sha256: Digest
    original_artifacts_sha256: dict[str, Digest] = Field(min_length=1)
    runtime_archive: Text
    runtime_archive_sha256: Digest
    reason: Text
    question_admitted: Literal[False] = False
    student_calls: Literal[0] = 0

    @model_validator(mode="after")
    def explicit_boundary(self):
        if (self.policy_version, self.interrupted_stage) not in {
            ("interrupted-robustness-native-prefix-v1", "robustness"),
            ("interrupted-canonical-native-prefix-v2", "canonical"),
        }:
            raise ValueError("native-prefix policy does not authorize this interrupted stage")
        return self


NATIVE_PREFIX_AUTHORIZATION = "native-prefix-import-authorization.json"


def _interrupted_prefix_hashes(parent: Path) -> dict[str, str]:
    return {str(p.relative_to(parent)): file_sha256(p) for p in parent.rglob("*.json")
            if p != parent / NATIVE_PREFIX_AUTHORIZATION}


def _canonical_prefix_complete(parent: Path) -> bool:
    path = parent / "canonical/stage-binding.json"
    if not path.is_file():
        return False
    recorded = json.loads(path.read_bytes())
    if recorded.get("pipeline") != json.loads((parent / "binding.json").read_bytes()):
        return False
    prior = recorded.get("prior_stage_receipts", {})
    required = {"grading", "native", "baseline", "robustness"}
    if set(prior) != required:
        return False
    for name in required:
        directory = parent / name
        receipt_path = directory / "stage-receipt.json"
        if not receipt_path.is_file() or file_sha256(receipt_path) != prior[name]:
            return False
        receipt = json.loads(receipt_path.read_bytes())
        if receipt["result"]["status"] != "pass" or receipt["artifacts_sha256"] != {
            str(p.relative_to(directory)): file_sha256(p) for p in directory.rglob("*.json")
            if p != receipt_path
        }:
            return False
    return True


def record_native_prefix_import_authorization(plan: PreproductionPlan, run: Path, parent: Path, *,
                                              archive: Path, reason: str,
                                              interrupted_stage: Literal["robustness", "canonical"] = "robustness",
                                              ) -> NativePrefixImportAuthorization:
    from .preproduction_revisions import _within

    parent, archive = (_within(run, str(path)) for path in (parent, archive))
    if parent.parent.name != "pipeline" or parent.parent.parent.parent != (run / "attempts").resolve():
        raise ValueError("native-prefix recovery must use an owned candidate pipeline")
    if PreproductionPlan.model_validate_json((run / "plan.json").read_bytes()) != plan:
        raise ValueError("native-prefix recovery requires the original run plan")
    with (parent.parent.parent / "candidate-pipeline.lock").open("a+") as owner:
        try:
            fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("an active candidate cannot authorize an interrupted-prefix import") from error
        if interrupted_stage not in ("robustness", "canonical"):
            raise ValueError("native-prefix recovery requires an explicitly supported nonstudent stage")
        if (parent / "pipeline-report.json").exists() or (parent / interrupted_stage / "stage-receipt.json").exists():
            raise ValueError(f"native-prefix recovery cannot replace a completed pipeline or {interrupted_stage} result")
        errors = sorted((parent / interrupted_stage / "errors").glob("*.json"))
        if not errors or any(json.loads(path.read_bytes()).get("status") != "operational_error" for path in errors):
            raise ValueError("native-prefix recovery needs its recorded downstream operational interruption")
        if interrupted_stage == "canonical" and not _canonical_prefix_complete(parent):
            raise ValueError("canonical-prefix recovery requires its exact completed pre-canonical stages")
        binding = json.loads((parent / "binding.json").read_bytes())
        native = parent / "native"
        stage = json.loads((native / "stage-receipt.json").read_bytes())
        if binding["plan_fingerprint"] != fingerprint(plan) or stage["result"]["status"] != "pass" or (
            stage["artifacts_sha256"] != {str(p.relative_to(native)): file_sha256(p) for p in native.rglob("*.json")
                                         if p != native / "stage-receipt.json"}
        ):
            raise ValueError("native-prefix recovery requires the exact completed native stage")
        authorization = NativePrefixImportAuthorization(
            policy_version=("interrupted-canonical-native-prefix-v2" if interrupted_stage == "canonical"
                            else "interrupted-robustness-native-prefix-v1"),
            interrupted_stage=interrupted_stage,
            plan_fingerprint=fingerprint(plan), task_fingerprint=binding["task_fingerprint"],
            parent_binding_sha256=file_sha256(parent / "binding.json"),
            native_stage_receipt_sha256=file_sha256(native / "stage-receipt.json"),
            original_artifacts_sha256=_interrupted_prefix_hashes(parent),
            runtime_archive=str(archive), runtime_archive_sha256=file_sha256(archive), reason=reason,
        )
        with locked_run(run, wait=True):
            immutable_json(parent / NATIVE_PREFIX_AUTHORIZATION, authorization)
        return authorization


def native_import_artifacts(run: Path, task_id: str, parent: Path, recorded_task: Path, archive: Path) -> dict[str, str]:
    from .preproduction_revisions import _within

    parent, recorded_task, archive = (_within(run, str(path)) for path in (parent, recorded_task, archive))
    attempt = (run / "attempts" / task_id).resolve()
    if parent.parent != attempt / "pipeline" or not recorded_task.is_relative_to(attempt) or recorded_task.name != "task.json":
        raise ValueError("retained native inputs must belong to the same logical attempt")
    if (parent / "native").resolve() != parent / "native":
        raise ValueError("retained native stage must be a direct, owned parent directory")
    paths = {recorded_task, archive, *parent.rglob("*.json")}
    return {str(_within(run, str(path))): file_sha256(_within(run, str(path))) for path in sorted(paths)}


def _validate_completed_native_journal(role: Path, complete: dict) -> None:
    calls = complete["calls"]
    requests = sorted(role.glob("*-request.json"))
    if type(calls) is not int or calls < 1 or [p.name for p in requests] != [
        f"{index:04d}-request.json" for index in range(calls)
    ]:
        raise ValueError("retained native student request history is incomplete")
    prefixes = {f"{index:04d}" for index in range(calls)}
    if any(p.name.split("-")[0] not in prefixes for pattern in (
        "*-response.json", "*-error.json", "*-tool-results.json",
    ) for p in role.glob(pattern)):
        raise ValueError("retained native student journal has unbound artifacts")
    for index, request_path in enumerate(requests):
        request = json.loads(request_path.read_bytes())
        if request["role"] != complete["role"]:
            raise ValueError("retained native student journal role changed")
        if (role / f"{index:04d}-response.json").exists():
            continue
        error_path = role / f"{index:04d}-error.json"
        if not error_path.exists() or index + 1 == calls:
            raise ValueError("retained native student response history is incomplete")
        error = json.loads(error_path.read_bytes())
        delay = error.get("delay_seconds")
        if (
            error.get("status") != "retry_wait" or error.get("role") != complete["role"]
            or type(error.get("call_index")) is not int or error["call_index"] != index
            or type(delay) not in (int, float) or not 0 <= delay < float("inf")
            or (role / f"{index:04d}-tool-results.json").exists()
            or request != json.loads(requests[index + 1].read_bytes())
        ):
            raise ValueError("retained native token wait lacks its exact unchanged next request")


def validate_native_import(retained: NativeStudentImport, plan: PreproductionPlan, task: TaskRecord, run: Path) -> None:
    from .generation import BlindSolution
    from .model_panel import captured_actions
    from .preproduction_revisions import _validate_repair, native_index_history
    from .provider_defaults import recorded_native_model

    parent, recorded_task, archive = Path(retained.parent_pipeline), Path(retained.recorded_task), Path(retained.runtime_archive)
    if any(not path.is_absolute() or path != path.resolve() for path in (parent, recorded_task, archive)):
        raise ValueError("retained native provenance requires canonical absolute paths")
    actual = native_import_artifacts(run, task.task_id, parent, recorded_task, archive)
    if (retained.task_fingerprint, retained.plan_fingerprint, retained.source_artifacts_sha256) != (
        fingerprint(task), fingerprint(plan), actual,
    ):
        raise ValueError("retained native task, plan or source artifacts changed")
    old = TaskRecord.model_validate_json(recorded_task.read_bytes())
    binding = json.loads((parent / "binding.json").read_bytes())
    if (fingerprint(old), binding["task_fingerprint"], binding["plan_fingerprint"]) != (
        retained.recorded_task_fingerprint, retained.recorded_task_fingerprint, fingerprint(plan),
    ):
        raise ValueError("retained native parent is not the exact completed held pipeline")
    report_path = parent / "pipeline-report.json"
    prefix_path = parent / NATIVE_PREFIX_AUTHORIZATION
    if report_path.exists():
        report = json.loads(report_path.read_bytes())
        parent_hashes = {str(path.relative_to(parent)): file_sha256(path) for path in parent.rglob("*.json")
                         if path != report_path}
        if prefix_path.exists() or report["task_fingerprint"] != retained.recorded_task_fingerprint or (
            report["status"] not in ("held", "admitted") or report["artifacts_sha256"] != parent_hashes
        ):
            raise ValueError("retained native parent is not the exact completed held pipeline")
        native_receipt_sha256 = report["stage_receipts"].get("native")
    else:
        authorization = NativePrefixImportAuthorization.model_validate_json(prefix_path.read_bytes())
        interrupted = parent / authorization.interrupted_stage
        errors = sorted((interrupted / "errors").glob("*.json"))
        if (authorization.plan_fingerprint, authorization.task_fingerprint, authorization.parent_binding_sha256,
            authorization.runtime_archive, authorization.runtime_archive_sha256, authorization.original_artifacts_sha256) != (
            fingerprint(plan), retained.recorded_task_fingerprint, file_sha256(parent / "binding.json"),
            str(archive), file_sha256(archive), _interrupted_prefix_hashes(parent),
        ) or (interrupted / "stage-receipt.json").exists() or not errors or any(
            json.loads(path.read_bytes()).get("status") != "operational_error" for path in errors
        ) or (authorization.interrupted_stage == "canonical" and not _canonical_prefix_complete(parent)):
            raise ValueError("the explicitly authorized interrupted native prefix changed")
        native_receipt_sha256 = authorization.native_stage_receipt_sha256
    if binding.get("continuation") is not None or binding.get("native_import") is not None or binding["grading_policy_fingerprint"] is not None:
        raise ValueError("retained native import requires a direct parent with the unchanged default grader")
    _validate_repair(old, task, True)
    if old.public_task().model_dump(exclude={"revision_id"}) != task.public_task().model_dump(exclude={"revision_id"}):
        raise ValueError("retained native public task changed beyond its revision identifier")
    native = parent / "native"
    prior = NativeBinding.model_validate_json((native / "binding.json").read_bytes())
    if any(name in binding["implementation_sha256"] and binding["implementation_sha256"][name] != digest
           for name, digest in prior.implementation_sha256.items()):
        raise ValueError("retained native stage and parent producer bindings disagree")
    producer = {**binding["implementation_sha256"], **prior.implementation_sha256}
    with zipfile.ZipFile(archive) as saved:
        if set(producer) - set(saved.namelist()):
            raise ValueError("retained native archive lacks part of its stage-bound producer")
        for name, digest in producer.items():
            if hashlib.sha256(saved.read(name)).hexdigest() != digest:
                raise ValueError("retained native archive does not preserve its exact producer")
    for name in (*NATIVE_RUNTIME_FILES, "pilot.py", "model_panel.py"):
        if producer.get(name) != file_sha256(Path(__file__).with_name(name)):
            raise ValueError("retained native generation, capture or grading protocol changed")
    stage = json.loads((native / "stage-receipt.json").read_bytes())
    stage_hashes = {str(path.relative_to(native)): file_sha256(path) for path in native.rglob("*.json")
                    if path != native / "stage-receipt.json"}
    if (stage["result"]["status"] != "pass" or stage["artifacts_sha256"] != stage_hashes
        or native_receipt_sha256 != file_sha256(native / "stage-receipt.json")):
        raise ValueError("retained native stage is not complete and unchanged")
    if (prior.task_fingerprint, prior.plan_fingerprint, prior.serving_view_id,
        prior.native_snapshot_sha256, prior.model, prior.student_query_limits,
        prior.grader_query_limits, prior.implementation_sha256) != (
        fingerprint(old), fingerprint(plan), plan.serving_view_id, plan.native_snapshot_sha256,
        recorded_native_model(plan, run, task.task_id, native), plan.query_limits,
        plan.query_limits.model_copy(update={"timeout_ms": plan.grader_timeout_ms or plan.query_limits.timeout_ms}),
        {name: file_sha256(Path(__file__).with_name(name)) for name in NATIVE_RUNTIME_FILES},
    ) or prior.native_indexes_sha256 not in native_index_history(plan, run):
        raise ValueError("retained native snapshot, indexes, model, limits or evaluator changed")
    role = native / "student"
    terminal = json.loads((native / "student-termination.json").read_bytes())
    if terminal["artifacts_sha256"] != {str(path.relative_to(role)): file_sha256(path) for path in role.rglob("*.json")}:
        raise ValueError("retained native student trace changed")
    if terminal["status"] == "completed":
        solution = BlindSolution.model_validate_json((role / "result.json").read_bytes())
        complete = json.loads((role / "complete.json").read_bytes())
        if (terminal["result_fingerprint"], complete["result_fingerprint"]) != (fingerprint(solution), fingerprint(solution)):
            raise ValueError("retained native solution changed")
        _validate_completed_native_journal(role, complete)
    elif terminal["status"] != "abstained" or terminal["result_fingerprint"] is not None:
        raise ValueError("retained native student lacks a completed or abstained termination")
    captured_actions(role)


class FinalReview(Contract):
    task_fingerprint: Digest
    subject_fingerprint: Digest
    recommendation: Literal["pass", "revise", "reject"]
    reviewer: Text
    reasons: tuple[Text, ...] = Field(min_length=1)


class ObjectiveReview(FinalReview):
    duplicate_task_ids: tuple[Identifier, ...] = ()

    @model_validator(mode="after")
    def no_duplicate_pass(self):
        require_unique(self.duplicate_task_ids, "duplicate task IDs")
        if self.recommendation == "pass" and self.duplicate_task_ids:
            raise ValueError("a genuine scoped-objective duplicate cannot be admitted as new")
        return self


class AdmissionFiles(Contract):
    question_inputs: Text
    native_directory: Text
    native_binding: Text
    robustness_directory: Text
    robustness_review: Text
    objective_review: Text
    difficulty_directory: Text
    grading_review: Text
    grading_policy_directory: Text | None = None


class AdmissionReceipt(Contract):
    policy_version: Literal["preproduction-private-admission-v1"] = VERSION
    plan_fingerprint: Digest
    task: QuestionBinding
    inputs_fingerprint: Digest
    bucket: Identifier
    objective_comparison_fingerprint: Digest
    difficulty_status: Text
    difficulty_score: float | None
    difficulty_band: Text | None
    student_grounded_success: bool
    source_artifacts_sha256: dict[str, Digest] = Field(min_length=1)
    implementation_sha256: Digest
    release_approved: Literal[False] = False


class AdmittedContractRevision(Contract):
    policy_version: Literal["admitted-contract-revision-v1"] = "admitted-contract-revision-v1"
    plan_fingerprint: Digest
    task_id: Identifier
    original_admission_sha256: Digest
    original_task_fingerprint: Digest
    revised_task_fingerprint: Digest
    source_revision: Text
    source_revision_sha256: Digest
    reason: Text
    logical_attempts_added: Literal[0] = 0
    completed_students_resampled: Literal[False] = False


class ObjectiveInventory(Contract):
    questions: tuple[tuple[Identifier, Digest], ...]

    @model_validator(mode="after")
    def unique_questions(self):
        require_unique(tuple(task_id for task_id, _ in self.questions), "objective inventory question IDs")
        return self


class ObjectiveReviewPart(Contract):
    inventory: ObjectiveInventory
    review: Text
    review_sha256: Digest

    @model_validator(mode="after")
    def actual_comparisons(self):
        if not self.inventory.questions:
            raise ValueError("each objective review part must bind actual new comparisons")
        return self


class ObjectiveReviewCoverage(Contract):
    policy_version: Literal["incremental-objective-review-v1"] = "incremental-objective-review-v1"
    task_fingerprint: Digest
    inventory: ObjectiveInventory
    parts: tuple[ObjectiveReviewPart, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def complete_disjoint_coverage(self):
        questions = tuple(question for part in self.parts for question in part.inventory.questions)
        require_unique(tuple(task_id for task_id, _ in questions), "objective review coverage question IDs")
        if set(questions) != set(self.inventory.questions):
            raise ValueError("objective review parts must cover exactly the complete comparison inventory")
        return self


class InventoryAdvanced(ValueError):
    """New immutable admissions require additional objective comparisons before commit."""


_VERIFIED_PREPARATION = object()


def _file_stamp(path: Path) -> tuple[int, ...]:
    link, target = path.lstat(), path.stat()
    return tuple(value for state in (link, target) for value in (
        state.st_dev, state.st_ino, state.st_mode, state.st_size, state.st_mtime_ns, state.st_ctime_ns,
    ))


class ArtifactVerification:
    """Content-verified, in-process reuse; changed file identities always trigger a new hash."""

    def __init__(self) -> None:
        self._files: dict[Path, tuple[tuple[int, ...], str]] = {}
        self._trees: dict[Path, frozenset[str]] = {}
        self._lock = RLock()

    def _record(self, path: Path, stamp: tuple[int, ...], digest: str) -> str:
        previous = self._files.get(path)
        if previous is not None and previous[1] != digest:
            raise ValueError(f"validated artifact changed: {path}")
        self._files[path] = (stamp, digest)
        return digest

    def digest(self, path: Path) -> str:
        path = path.absolute()
        with self._lock:
            before = _file_stamp(path)
            previous = self._files.get(path)
            if previous is not None and previous[0] == before:
                return previous[1]
            digest = file_sha256(path)
            if _file_stamp(path) != before:
                raise ValueError(f"artifact changed while hashing: {path}")
            return self._record(path, before, digest)

    def read(self, path: Path) -> bytes:
        path = path.absolute()
        with self._lock:
            before = _file_stamp(path)
            data = path.read_bytes()
            if _file_stamp(path) != before:
                raise ValueError(f"artifact changed while reading: {path}")
            self._record(path, before, hashlib.sha256(data).hexdigest())
            return data

    def require(self, path: Path, digest: str, reason: str) -> None:
        if self.digest(path) != digest:
            raise ValueError(reason)

    def watch_json_tree(self, path: Path) -> None:
        path = path.resolve()
        names = frozenset(str(item.relative_to(path)) for item in path.rglob("*.json"))
        with self._lock:
            if path in self._trees and self._trees[path] != names:
                raise ValueError(f"validated artifact inventory changed: {path}")
            self._trees[path] = names

    def verify_unchanged(self) -> None:
        with self._lock:
            for path in tuple(self._files):
                self.digest(path)
            for path in tuple(self._trees):
                self.watch_json_tree(path)


@dataclass(frozen=True)
class AdmissionSnapshot:
    plan_fingerprint: str
    output: Path
    receipts: tuple[AdmissionReceipt, ...]
    paths: frozenset[Path]
    verification: ArtifactVerification
    source_directories: frozenset[str]
    source_metadata: frozenset[Path]
    _authority: object = field(default=None, repr=False, compare=False)

    def inventory(self, plan: PreproductionPlan, *, excluding: str | None = None) -> ObjectiveInventory:
        self.require_binding(plan, self.output)
        items = {task.task_id: fingerprint(task) for task in plan.seed_questions}
        items.update((receipt.task.task_id, receipt.task.task_fingerprint)
                     for receipt in self.receipts if receipt.task.task_id != excluding)
        return ObjectiveInventory(questions=tuple(sorted(items.items())))

    def require_binding(self, plan: PreproductionPlan, output: Path) -> None:
        if self._authority is not _VERIFIED_PREPARATION or (
            self.plan_fingerprint, self.output
        ) != (fingerprint(plan), output.resolve()):
            raise ValueError("verified admission snapshot belongs to another plan or run")

    def require_current(self) -> None:
        if self._authority is not _VERIFIED_PREPARATION:
            raise ValueError("admission snapshot was not verified in this process")
        self.verification.verify_unchanged()
        if _source_metadata_paths(self.output) != (self.source_directories, self.source_metadata):
            raise ValueError("sealed source-wave metadata changed during parallel finalization")
        current = frozenset((self.output / "admissions").glob("*.json"))
        if not self.paths <= current:
            raise ValueError("an immutable admission disappeared from the validated inventory")
        if current != self.paths:
            raise InventoryAdvanced("new admissions require additional objective comparisons")


def _source_metadata_paths(output: Path) -> tuple[frozenset[str], frozenset[Path]]:
    directories = tuple(path for path in (output / "attempts").glob("*") if path.is_dir())
    paths = {output / "plan.json"}
    for directory in directories:
        paths.update(path for path in (directory / "attempt.json", directory / "source-outcome.json") if path.exists())
        paths.update((directory / "revisions").glob("*/*.json"))
    for name in ("runtime-amendments", "native-index-amendments", "transport-amendments", "parallel-finalization-runtime"):
        paths.update((output / name).glob("*.json"))
    return frozenset(path.name for path in directories), frozenset(paths)


class AdmissionSnapshotStore:
    """Share verified immutable history, never a cached admission or objective decision."""

    def __init__(self, plan: PreproductionPlan, output: Path):
        self.plan, self.output = plan, output.resolve()
        self.verification = ArtifactVerification()
        self._snapshot: AdmissionSnapshot | None = None
        self._source_state: tuple[frozenset[str], frozenset[Path]] | None = None
        self._lock = RLock()

    def snapshot(self) -> AdmissionSnapshot:
        with self._lock:
            self.verification.verify_unchanged()
            source_state = _source_metadata_paths(self.output)
            if self._source_state is None:
                for path in source_state[1]:
                    self.verification.digest(path)
                    if path.name == "source-outcome.json":
                        self.verification.watch_json_tree(path.parent / "source")
                source_progress(self.plan, self.output, hash_file=self.verification.digest)
                self.verification.verify_unchanged()
                if _source_metadata_paths(self.output) != source_state:
                    raise ValueError("source wave changed while validating its snapshot")
                self._source_state = source_state
            elif source_state != self._source_state:
                raise ValueError("sealed source-wave metadata changed during parallel finalization")
            paths = frozenset((self.output / "admissions").glob("*.json"))
            previous = self._snapshot
            if previous is not None:
                if not previous.paths <= paths:
                    raise ValueError("an immutable admission disappeared from the validated inventory")
                if previous.paths == paths:
                    return previous
            receipts = list(previous.receipts) if previous is not None else []
            known = previous.paths if previous is not None else frozenset()
            receipts.extend(_load_admission_receipts(self.plan, self.output, paths - known, self.verification))
            receipts.sort(key=lambda receipt: receipt.task.task_id)
            require_unique(tuple(receipt.task.task_id for receipt in receipts), "admitted logical questions")
            self.verification.verify_unchanged()
            self._snapshot = AdmissionSnapshot(
                fingerprint(self.plan), self.output, tuple(receipts), paths, self.verification,
                *self._source_state, _VERIFIED_PREPARATION,
            )
            return self._snapshot


@dataclass(frozen=True)
class PreparedAdmission:
    plan_fingerprint: str
    output: Path
    task: TaskRecord
    binding: QuestionBinding
    files: AdmissionFiles
    bucket: str
    difficulty: DifficultySidecar
    student_grounded_success: bool
    hashes: dict[str, str]
    verification: ArtifactVerification
    source: Path
    runtime_sha256: dict[str, str]
    _authority: object = field(default=None, repr=False, compare=False)
    _validated_fingerprint: str = field(default="", repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self._validated_fingerprint:
            object.__setattr__(self, "_validated_fingerprint", self._facts_fingerprint())

    def _facts_fingerprint(self) -> str:
        values = {
            "plan": self.plan_fingerprint, "output": str(self.output), "task": fingerprint(self.task),
            "binding": fingerprint(self.binding), "files": fingerprint(self.files), "bucket": self.bucket,
            "difficulty": fingerprint(self.difficulty), "student_grounded_success": self.student_grounded_success,
            "hashes": self.hashes, "source": str(self.source), "runtime": self.runtime_sha256,
        }
        return hashlib.sha256(json.dumps(values, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def require_unchanged(self) -> None:
        if self._validated_fingerprint != self._facts_fingerprint():
            raise ValueError("validated admission preparation changed in memory")


def _load_admission_receipts(plan: PreproductionPlan, output: Path, paths: frozenset[Path],
                            verification: ArtifactVerification) -> tuple[AdmissionReceipt, ...]:
    from .transport_amendments import archived_admission_producers

    receipts = []
    archived, dependencies = archived_admission_producers(plan, output.resolve())
    for path, expected in dependencies.items():
        verification.require(path, expected, "archived producer authority or carrier changed")
    allocated = {attempt.task_id: attempt for attempt in plan.attempts()}
    plan_fp = fingerprint(plan)
    for path in sorted(paths):
        receipt = AdmissionReceipt.model_validate_json(verification.read(path))
        attempt = allocated.get(receipt.task.task_id)
        if attempt is None or path.name != receipt.task.task_id + ".json" or receipt.plan_fingerprint != plan_fp:
            raise ValueError("admission does not belong to an allocated logical attempt")
        bucket = f"incident:{attempt.incident_id}" if attempt.mode == "incident" else "tenant"
        if receipt.bucket != bucket:
            raise ValueError("admitted question scope differs from its logical allocation")
        for name, digest in receipt.source_artifacts_sha256.items():
            carrier = archived.get((path.resolve(), Path(name), digest))
            if carrier is None:
                verification.require(Path(name), digest, "an admitted question's source artifacts changed")
            else:
                archive, archive_digest, member = carrier
                verification.require(archive, archive_digest, "an archived producer carrier changed")
                with zipfile.ZipFile(archive) as source:
                    if hashlib.sha256(source.read(member)).hexdigest() != digest:
                        raise ValueError("an archived producer differs from the original admitted reference")
        receipts.append(receipt)
    return tuple(receipts)


def admitted_receipts(plan: PreproductionPlan, output: Path, *,
                      verification: ArtifactVerification | None = None) -> tuple[AdmissionReceipt, ...]:
    if verification is None:
        verification = ArtifactVerification()
    receipts = _load_admission_receipts(plan, output, frozenset((output / "admissions").glob("*.json")), verification)
    require_unique(tuple(receipt.task.task_id for receipt in receipts), "admitted logical questions")
    verification.verify_unchanged()
    return receipts


def admitted_task(output: Path, receipt: AdmissionReceipt) -> TaskRecord:
    attempt = (output / "attempts" / receipt.task.task_id).resolve()
    for name, digest in receipt.source_artifacts_sha256.items():
        path = Path(name)
        if path.name != "task.json" or not path.resolve().is_relative_to(attempt):
            continue
        if file_sha256(path) != digest:
            raise ValueError("the historical admitted task artifact changed")
        task = TaskRecord.model_validate_json(path.read_bytes())
        if task.task_id == receipt.task.task_id and fingerprint(task) == receipt.task.task_fingerprint:
            return task
    raise ValueError("historical admission lacks its exact pinned task descriptor")


def _admitted_contract_revision(plan: PreproductionPlan, output: Path, task: TaskRecord, reason: str) -> AdmittedContractRevision:
    from .preproduction_revisions import _validate_repair, current_source

    receipt = next((r for r in admitted_receipts(plan, output) if r.task.task_id == task.task_id), None)
    if receipt is None:
        raise ValueError("a private-contract revision requires a historical admission")
    old = admitted_task(output, receipt)
    _validate_repair(old, task, True)
    if old.public_task().model_dump(exclude={"revision_id"}) != task.public_task().model_dump(exclude={"revision_id"}) or (
        [(c.checkpoint_id, c.weight, c.max_score) for c in old.private_gold.checkpoints]
        != [(c.checkpoint_id, c.weight, c.max_score) for c in task.private_gold.checkpoints]
    ):
        raise ValueError("an admitted contract revision cannot change public goals or checkpoint weights")
    old_claims = (old.private_gold.final, *(c.claim for c in old.private_gold.checkpoints))
    new_claims = (task.private_gold.final, *(c.claim for c in task.private_gold.checkpoints))
    if any(a.requires_behavior_evidence != b.requires_behavior_evidence for a, b in zip(old_claims, new_claims)):
        raise ValueError("an admitted contract revision cannot relax required evidence lineage")
    if fingerprint(old) == fingerprint(task):
        raise ValueError("an unchanged admitted task requires ordinary fresh validation, not a contract revision")
    candidate, outcome, sequence = current_source(plan, output, task.task_id)
    if outcome is None or outcome.status != "source_ready" or sequence < 1 or outcome.task_fingerprint != fingerprint(task):
        raise ValueError("an admitted contract revision requires the exact sealed source-ready revision")
    if TaskRecord.model_validate_json((candidate / "task.json").read_bytes()) != task:
        raise ValueError("the admitted contract revision differs from the authoritative source")
    validate_quality_gate(candidate, task)
    revision = candidate.parent / "revision.json"
    return AdmittedContractRevision(
        plan_fingerprint=fingerprint(plan), task_id=task.task_id,
        original_admission_sha256=file_sha256(output / "admissions" / (task.task_id + ".json")),
        original_task_fingerprint=fingerprint(old), revised_task_fingerprint=fingerprint(task),
        source_revision=str(revision.resolve()), source_revision_sha256=file_sha256(revision), reason=reason,
    )


def record_admitted_contract_revision(plan: PreproductionPlan, output: Path, task: TaskRecord, *,
                                      destination: Path, reason: str) -> AdmittedContractRevision:
    directory = (output / "admission-contract-revisions" / task.task_id).resolve()
    if destination.resolve().parent != directory or destination.suffix != ".json":
        raise ValueError("admitted contract authorization must use its separate owned namespace")
    with locked_run(output, wait=True):
        revision = _admitted_contract_revision(plan, output, task, reason)
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        immutable_json(destination, revision)
        return revision


def validate_admitted_contract_revision(plan: PreproductionPlan, output: Path, task: TaskRecord,
                                        path: Path) -> AdmittedContractRevision:
    if path.resolve().parent != (output / "admission-contract-revisions" / task.task_id).resolve() or path.suffix != ".json":
        raise ValueError("admitted contract authorization escaped its owned namespace")
    stored = AdmittedContractRevision.model_validate_json(path.read_bytes())
    if stored != _admitted_contract_revision(plan, output, task, stored.reason):
        raise ValueError("admitted contract authorization or its original/source bindings changed")
    return stored


def objective_inventory(plan: PreproductionPlan, output: Path, *, excluding: str | None = None) -> ObjectiveInventory:
    items = {task.task_id: fingerprint(task) for task in plan.seed_questions}
    for receipt in admitted_receipts(plan, output):
        if receipt.task.task_id != excluding:
            items[receipt.task.task_id] = receipt.task.task_fingerprint
    return ObjectiveInventory(questions=tuple(sorted(items.items())))


def _read_review(path: Path, task_fp: str, subject_fp: str, hashes: dict, *, objective=False):
    review_type = ObjectiveReview if objective else FinalReview
    data = path.read_bytes()
    review = review_type.model_validate_json(data)
    hashes[str(path.resolve())] = hashlib.sha256(data).hexdigest()
    if (review.task_fingerprint, review.subject_fingerprint, review.recommendation) != (task_fp, subject_fp, "pass"):
        raise ValueError("a required final review is unbound or requests revision/rejection")
    return review


def _read_objective_coverage(path: Path, task_fp: str, inventory: ObjectiveInventory,
                             hashes: dict[str, str]) -> None:
    data = path.read_bytes()
    value = json.loads(data)
    if value.get("policy_version") != "incremental-objective-review-v1":
        review = _read_review(path, task_fp, fingerprint(inventory), hashes, objective=True)
        if review.duplicate_task_ids:
            raise ValueError("a genuine duplicate cannot be counted as a new accepted objective")
        return
    coverage = ObjectiveReviewCoverage.model_validate_json(json.dumps(value))
    if coverage.task_fingerprint != task_fp or coverage.inventory != inventory:
        raise ValueError("objective review coverage is not bound to the current complete inventory")
    hashes[str(path.resolve())] = hashlib.sha256(data).hexdigest()
    for part in coverage.parts:
        review_path = (path.parent / part.review).resolve()
        if not review_path.is_relative_to(path.parent.resolve()):
            raise ValueError("objective review part escapes its immutable coverage binding")
        review = _read_review(review_path, task_fp, fingerprint(part.inventory), hashes, objective=True)
        if hashes[str(review_path)] != part.review_sha256:
            raise ValueError("objective review part differs from its immutable coverage binding")
        if review.duplicate_task_ids:
            raise ValueError("a genuine duplicate cannot be counted as a new accepted objective")


def prepare_admission(plan: PreproductionPlan, output: Path, files: AdmissionFiles,
                      snapshot: AdmissionSnapshot) -> PreparedAdmission:
    snapshot.require_binding(plan, output)
    snapshot.verification.verify_unchanged()
    result = _validate_admission(plan, output, files, snapshot=snapshot)
    if not isinstance(result, PreparedAdmission):
        raise ValueError("parallel preparation requires a not-yet-admitted logical question")
    return result


def commit_prepared_admission(plan: PreproductionPlan, output: Path, prepared: PreparedAdmission,
                              snapshot: AdmissionSnapshot, objective_review: Path, *,
                              admission_inputs_directory: Path | None = None) -> AdmissionReceipt:
    from .preproduction import runtime_hashes
    from .preproduction_revisions import current_source

    snapshot.require_binding(plan, output)
    if prepared._authority is not _VERIFIED_PREPARATION or (
        prepared.plan_fingerprint, prepared.output
    ) != (fingerprint(plan), output.resolve()):
        raise ValueError("prepared admission belongs to another plan or run")
    with (output / "admission-finalization.lock").open("a+") as finalization:
        fcntl.flock(finalization, fcntl.LOCK_EX)
        with locked_run(output, wait=True):
            prepared.require_unchanged()
            snapshot.require_current()
            prepared.verification.verify_unchanged()
            if runtime_hashes() != prepared.runtime_sha256:
                raise ValueError("prepared admission runtime changed")
            source, outcome, _ = current_source(plan, output, prepared.task.task_id,
                                                hash_file=prepared.verification.digest)
            if source != prepared.source or outcome is None or (
                outcome.status != "source_ready" or outcome.task_fingerprint != fingerprint(prepared.task)
            ):
                raise ValueError("prepared admission no longer binds the current source-ready task")
            inventory = snapshot.inventory(plan, excluding=prepared.task.task_id)
            hashes = dict(prepared.hashes)
            _read_objective_coverage(objective_review, fingerprint(prepared.task), inventory, hashes)
            for name, digest in hashes.items():
                prepared.verification.require(Path(name), digest, "prepared admission artifact changed")
            files = prepared.files.model_copy(update={"objective_review": str(objective_review)})
            prior = next((receipt for receipt in snapshot.receipts
                          if receipt.task.task_id == prepared.task.task_id), None)
            if prior is not None:
                if prior.task != prepared.binding or prior.inputs_fingerprint != fingerprint(files):
                    raise ValueError("accepted logical question cannot be replaced silently by another revision")
                return prior
            target = plan.tenant_target if prepared.bucket == "tenant" else plan.incident_target
            if sum(receipt.bucket == prepared.bucket for receipt in snapshot.receipts) >= target:
                raise ValueError("this scope already reached its validated-new target; retain surplus candidates without automatic admission")
            if admission_inputs_directory is not None:
                if admission_inputs_directory.resolve() != Path(files.question_inputs).resolve().parent:
                    raise ValueError("versioned admission inputs must belong to the candidate pipeline")
                inputs = admission_inputs_directory / ("admission-inputs-" + fingerprint(files) + ".json")
                immutable_json(inputs, files)
                hashes[str(inputs.resolve())] = file_sha256(inputs)
            receipt = AdmissionReceipt(
                plan_fingerprint=fingerprint(plan), task=prepared.binding, bucket=prepared.bucket,
                inputs_fingerprint=fingerprint(files), objective_comparison_fingerprint=fingerprint(inventory),
                difficulty_status=prepared.difficulty.status, difficulty_score=prepared.difficulty.score,
                difficulty_band=prepared.difficulty.band, student_grounded_success=prepared.student_grounded_success,
                source_artifacts_sha256=hashes, implementation_sha256=file_sha256(Path(__file__)),
            )
            destination = output / "admissions" / (prepared.task.task_id + ".json")
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            immutable_json(destination, receipt)
            return receipt


def _retained_annotation_only_grading(
    plan: PreproductionPlan, output: Path, directory: Path, prior: AdmissionReceipt,
    reviewed: ReviewedGradingAmendment, read: Callable[[Path], bytes],
) -> ReviewedGradingAmendment:
    from .grading_review import runtime_hashes as grading_runtime_hashes
    from .preproduction import runtime_hashes
    from .preproduction_revisions import RuntimeAmendment, effective_runtime

    current = grading_runtime_hashes()
    recorded = reviewed.implementation_sha256
    annotations = {"canonical_facts.py", "fact_curation.py", "difficulty_curation.py"}
    if recorded.keys() != current.keys() or (
        {name for name in current if recorded[name] != current[name]} - annotations
    ):
        raise ValueError("feature-only revalidation cannot change grading, source-capture or scoring kernels")
    approved = effective_runtime(plan, output)
    if approved != runtime_hashes() or any(current[name] != approved.get(name) for name in annotations):
        raise ValueError("feature-only grading retention requires the approved current annotation producer")
    states = [plan.implementation_sha256]
    for path in sorted((output / "runtime-amendments").glob("*.json")):
        amendment = RuntimeAmendment.model_validate_json(read(path))
        states.append(amendment.current_runtime_sha256)
        read(output / amendment.archive)
        if amendment.current_archive is not None:
            read(output / amendment.current_archive)
    if not any(all(recorded[name] == state.get(name) for name in annotations) for state in states):
        raise ValueError("retained grading annotations do not match an exact approved historical producer")
    directory = directory.resolve()
    original = {Path(name).resolve(): digest for name, digest in prior.source_artifacts_sha256.items()
                if Path(name).resolve().is_relative_to(directory)}
    actual = {path.resolve() for path in directory.rglob("*.json")}
    if not original or actual != original.keys():
        raise ValueError("feature-only grading retention requires exactly the original admitted policy artifacts")
    for path, digest in original.items():
        if hashlib.sha256(read(path)).hexdigest() != digest:
            raise ValueError("an originally admitted grading policy artifact changed")
    # The original receipt pins the complete strict review validation; retain its evaluator identity.
    if reviewed.policy.task_fingerprint != prior.task.task_fingerprint:
        raise ValueError("retained grading belongs to another originally admitted question")
    return reviewed


def record_admission(plan: PreproductionPlan, output: Path, files: AdmissionFiles, *,
                     revalidation_receipt: Path | None = None,
                     admitted_contract_revision: Path | None = None,
                     original_admission_files: AdmissionFiles | None = None) -> AdmissionReceipt:
    result = _validate_admission(
        plan, output, files, revalidation_receipt=revalidation_receipt,
        admitted_contract_revision=admitted_contract_revision, original_admission_files=original_admission_files,
    )
    if not isinstance(result, AdmissionReceipt):
        raise TypeError("ordinary admission did not produce its verified receipt")
    return result


def _validate_admission(plan: PreproductionPlan, output: Path, files: AdmissionFiles, *,
                        revalidation_receipt: Path | None = None,
                        admitted_contract_revision: Path | None = None,
                        original_admission_files: AdmissionFiles | None = None,
                        snapshot: AdmissionSnapshot | None = None) -> AdmissionReceipt | PreparedAdmission:
    """Validate every gate before an immutable receipt can count toward the new-question target."""
    plan = PreproductionPlan.model_validate(plan)
    from .preproduction import runtime_hashes
    from .preproduction_revisions import RuntimeAmendment, _within, current_source, effective_runtime

    if effective_runtime(plan, output) != runtime_hashes():
        raise ValueError("admission orchestration runtime is not explicitly bound to this run")
    files = AdmissionFiles.model_validate(files)
    if PreproductionPlan.model_validate_json((output / "plan.json").read_bytes()) != plan:
        raise ValueError("admission requires the original immutable source-wave plan")
    if admitted_contract_revision is not None and revalidation_receipt is None:
        raise ValueError("an admitted contract revision must produce a separate fresh certificate")
    if original_admission_files is not None:
        original_admission_files = AdmissionFiles.model_validate(original_admission_files)
        if revalidation_receipt is None or admitted_contract_revision is not None:
            raise ValueError("feature-only retention requires separate revalidation without a task/contract revision")
    verification = ArtifactVerification() if snapshot is not None else None
    with nullcontext() if snapshot is not None else locked_run(output, wait=True):
        if snapshot is None:
            source_progress(plan, output)
        else:
            snapshot.require_binding(plan, output)
        hashes = {}

        def read(path: Path):
            data = path.read_bytes() if verification is None else verification.read(path)
            hashes[str(path.resolve())] = hashlib.sha256(data).hexdigest()
            return data

        if verification is not None:
            inputs = SplitInputs.model_validate_json(read(Path(files.question_inputs)))
            for entry in inputs.questions:
                verification.watch_json_tree(Path(entry.annotation))
            for directory in (files.native_directory, files.robustness_directory, files.difficulty_directory):
                verification.watch_json_tree(Path(directory))
        loaded = load_questions(Path(files.question_inputs))
        hashes.update(loaded.source_hashes)
        if len(loaded.questions) != 1:
            raise ValueError("one logical question revision must be admitted at a time")
        question = loaded.questions[0]
        task, task_fp = question.task, fingerprint(question.task)
        if task.dataset_release != "v1-private-pilot":
            raise ValueError("preproduction admits only explicitly unreleased private-pilot tasks")
        destination = output / "admissions" / (task.task_id + ".json")
        prior_admission = None
        for current in admitted_receipts(plan, output) if snapshot is None else snapshot.receipts:
            if current.task.task_id == task.task_id:
                prior_admission = current
                if (current.task.task_fingerprint != task_fp and (
                    revalidation_receipt is None or admitted_contract_revision is None
                )) or (
                    revalidation_receipt is None and current.task != binding_for(question)
                ):
                    raise ValueError("accepted logical question cannot be replaced silently by another revision")
                if revalidation_receipt is None:
                    if current.inputs_fingerprint != fingerprint(files):
                        raise ValueError("accepted logical question cannot be replaced silently by another revision")
                    return current
        if admitted_contract_revision is not None:
            authorization = validate_admitted_contract_revision(plan, output, task, admitted_contract_revision)
            read(admitted_contract_revision)
            read(Path(authorization.source_revision))
            if not (Path(files.native_directory) / "retained-student.json").is_file():
                raise ValueError("an admitted contract revision requires the original retained native student")
        if revalidation_receipt is not None:
            if prior_admission is None:
                raise ValueError("a revalidation certificate requires an existing admission for the unchanged question")
            if original_admission_files is not None and (
                fingerprint(original_admission_files) != prior_admission.inputs_fingerprint
                or prior_admission.task != binding_for(question)
                or files.model_dump(exclude={"difficulty_directory", "objective_review"})
                != original_admission_files.model_dump(exclude={"difficulty_directory", "objective_review"})
            ):
                raise ValueError("feature-only revalidation changed original task, native, canonical, robustness or grading inputs")
            directory = (output / "revalidations" / task.task_id).resolve()
            if revalidation_receipt.resolve().parent != directory or revalidation_receipt.suffix != ".json":
                raise ValueError("revalidation must use this question's separate owned certificate directory")
            read(destination)
            destination = revalidation_receipt.resolve()
        attempt = next((value for value in plan.attempts() if value.task_id == task.task_id), None)
        if attempt is None or task.task_id in {seed.task_id for seed in plan.seed_questions}:
            raise ValueError("a development/seed/unallocated task cannot count as a new preproduction question")
        if (task.scope.mode, task.scope.incident_id, task.serving_view_id, task.graph_version) != (
            attempt.mode, attempt.incident_id, plan.serving_view_id, plan.graph_id,
        ):
            raise ValueError("candidate differs from its allocated scope/source")
        candidate, source_outcome, _ = current_source(plan, output, task.task_id)
        if source_outcome is None:
            raise ValueError("admission requires a completed source stage")
        if verification is not None:
            verification.watch_json_tree(candidate)
        read(candidate.parent / "source-outcome.json")
        attempt_root = output / "attempts" / task.task_id
        read(attempt_root / "attempt.json")
        read(attempt_root / "source-outcome.json")
        from .provider_defaults import AUTHORITY, AUTHORITY_BINDING, recorded_native_model

        native = Path(files.native_directory)
        import_path = native / "retained-student.json"
        recorded_native = native
        if import_path.exists():
            retained = NativeStudentImport.model_validate_json(read(import_path))
            recorded_native = Path(retained.parent_pipeline) / "native"
        expected_model = recorded_native_model(plan, output, task.task_id, recorded_native)
        if (recorded_native / "student/provider-binding.json").exists():
            read(output / AUTHORITY)
            read(output / AUTHORITY_BINDING)
            read(recorded_native / "student/provider-binding.json")
            for path in sorted((recorded_native / "student").glob("*-provider.json")):
                read(path)
        if expected_model.gateway is not None:
            from .checkpoint_batches import batch_directory

            reservation_path = attempt_root / "generation-batch.json"
            if reservation_path.exists():
                reservation = json.loads(read(reservation_path))
                batch = batch_directory(output, reservation["batch_id"])
                read(batch / "policy.json")
                read(batch / "items" / (task.task_id + ".json"))
        for path in sorted((attempt_root / "revisions").glob("*/*.json")):
            read(path)
        for path in sorted((output / "runtime-amendments").glob("*.json")):
            amendment = RuntimeAmendment.model_validate_json(read(path))
            archive = _within(output, amendment.archive)
            read(archive)
            if hashes[str(archive)] != amendment.archive_sha256:
                raise ValueError("archived runtime changed during admission")
            if amendment.current_archive is not None:
                updated_archive = _within(output, amendment.current_archive)
                read(updated_archive)
                if hashes[str(updated_archive)] != amendment.current_archive_sha256:
                    raise ValueError("updated annotation producer changed during admission")
        from .transport_amendments import (
            PARALLEL_RUNTIME, parse_finalization_approval, load_parallel_finalization_runtime, load_transport_amendment,
        )
        transport = load_transport_amendment(plan, output)
        if transport is not None:
            amendment, _, _ = transport
            read(output / "transport-amendments/0000.json")
            read(output / AUTHORITY)
            read(output / AUTHORITY_BINDING)
            read(_within(output, amendment.archive))
            read(_within(output, amendment.current_archive))
        parallel_runtime = load_parallel_finalization_runtime(plan, output)
        if parallel_runtime is not None:
            read(output / PARALLEL_RUNTIME)
            read(_within(output, parallel_runtime.archive))
            approved = parse_finalization_approval(read(_within(output, parallel_runtime.approval)))
            read(_within(output, approved.qualification))
        from .preproduction_revisions import NativeIndexAmendment, native_index_history
        approved_indexes = native_index_history(plan, output)
        for path in sorted((output / "native-index-amendments").glob("*.json")):
            amendment = NativeIndexAmendment.model_validate_json(read(path))
            read(_within(output, amendment.report))
            read(_within(output, amendment.approval))
        if source_outcome.status != "source_ready" or source_outcome.task_fingerprint != task_fp:
            raise ValueError("a source hold or unbound revision cannot be promoted to admission")
        if TaskRecord.model_validate_json(read(candidate / "task.json")) != task:
            raise ValueError("canonical/native inputs differ from the source-ready task")
        validate_quality_gate(candidate, task)
        hashes.update({str((candidate / name).resolve()): digest for name, digest in source_outcome.artifact_sha256.items()})

        native = Path(files.native_directory)
        native_binding = NativeBinding.model_validate_json(read(Path(files.native_binding)))
        if (native_binding.task_fingerprint, native_binding.plan_fingerprint, native_binding.serving_view_id,
            native_binding.native_snapshot_sha256) != (
            task_fp, fingerprint(plan), task.serving_view_id, plan.native_snapshot_sha256,
        ) or native_binding.native_indexes_sha256 not in approved_indexes or (
            native_binding.model != expected_model or native_binding.student_query_limits != plan.query_limits
        ):
            raise ValueError("native source, indexes, student model or query settings differ from the run plan")
        if native_binding.grader_query_limits.timeout_ms != (plan.grader_timeout_ms or plan.query_limits.timeout_ms) or (
            native_binding.grader_query_limits.max_rows != plan.query_limits.max_rows
        ) or (
            native_binding.grader_query_limits.max_bytes != plan.query_limits.max_bytes
        ) or native_binding.implementation_sha256 != {
            name: file_sha256(Path(__file__).with_name(name)) for name in NATIVE_RUNTIME_FILES
        }:
            raise ValueError("native grading result bounds or runtime changed")
        native_report = json.loads(read(native / "evaluation_report.json"))
        import_path = native / "retained-student.json"
        if import_path.exists() or native_report.get("retained_native_student") is True:
            if files.grading_policy_directory is not None or native_report.get("retained_native_student") is not True:
                raise ValueError("retained native replay requires its explicit default-grader provenance")
            retained_student = NativeStudentImport.model_validate_json(read(import_path))
            validate_native_import(retained_student, plan, task, output)
            for name, digest in retained_student.source_artifacts_sha256.items():
                read(Path(name))
                if hashes[str(Path(name).resolve())] != digest:
                    raise ValueError("retained native dependency changed during admission")
        if ValidationReport.model_validate_json(read(native / "private-pilot-validation.json")) != question.validation:
            raise ValueError("native and canonical inputs use different validation records")
        if (native_report.get("status"), native_report.get("task_fingerprint"), native_report.get("serving_view_id")) != (
            "private_pilot_completed", task_fp, task.serving_view_id,
        ) or native_report.get("candidate_checks_passed") is not True or native_report.get("adapter_components_equal") is not True:
            raise ValueError("actual native validation and matching adapter replay are required")
        evaluations = []
        for backend, filename in (("secrl", "secrl.json"), ("acesevals", "acesevals.json")):
            record = json.loads(read(native / filename))["current_episode"]
            value = EvaluationRecord.model_validate_json(json.dumps(record["evaluation"]))
            if value.status != "complete" or value.backend != backend or value.task_mismatches(task):
                raise ValueError("native student outcomes are not complete and bound to this task")
            evaluations.append(value)
        components = ("answer_correctness", "final_evidence", "checkpoints", "grounded_final", "checkpoint_progress", "aggregate_reward")
        if any(getattr(evaluations[0], field) != getattr(evaluations[1], field) for field in components):
            raise ValueError("native SecRL and ACE outcomes differ")
        if native_report.get("student_grounded_success") != evaluations[0].grounded_final:
            raise ValueError("native summary disagrees with its recorded student result")

        robust_dir = Path(files.robustness_directory)
        robust_plan = RobustnessPlan.model_validate_json(read(robust_dir / "plan.json"))
        robust = RobustnessReport.model_validate_json(read(robust_dir / "report.json"))
        runtime = {name: file_sha256(Path(__file__).with_name(name)) for name in ROBUSTNESS_RUNTIME_FILES}
        if (robust_plan.task_fingerprint, robust.task_fingerprint, robust.plan_fingerprint, robust.status) != (
            task_fp, task_fp, fingerprint(robust_plan), "pass",
        ) or robust.implementation_sha256 != runtime or robust.cases_not_run or set(robust.backend_versions) != {"duckdb", "mysql"} or (
            robust.serving_view_id != task.serving_view_id
            or robust.query_limits.max_rows != plan.query_limits.max_rows
            or robust.query_limits.max_bytes != plan.query_limits.max_bytes
            or robust.query_limits.timeout_ms > native_binding.grader_query_limits.timeout_ms
        ):
            raise ValueError("actual reviewed backend robustness is incomplete or has changed")
        expected_checks = {
            (case, claim, backend)
            for case in ("baseline", *(case.case_id for case in robust_plan.cases))
            for claim in ("final", *(checkpoint.checkpoint_id for checkpoint in task.private_gold.checkpoints))
            for backend in ("duckdb", "mysql")
        }
        if {(check.case_id, check.claim_id, check.engine) for check in robust.checks} != expected_checks or (
            len(robust.checks) != len(expected_checks)
        ) or any(check.status != "pass" or check.observed is None or check.error_code is not None or check.reasons for check in robust.checks):
            raise ValueError("robustness report lacks a complete passing backend/claim matrix")
        claims = {"final": task.private_gold.final, **{c.checkpoint_id: c.claim for c in task.private_gold.checkpoints}}
        references = {ref.evidence_id: (ref.table, ref.public_record_id) for ref in task.evidence}
        from .contracts import PublicCitation
        by_key = {(check.case_id, check.claim_id, check.engine): check.observed for check in robust.checks}
        for claim_id, claim in claims.items():
            groups = _groups({PublicCitation(table=references[eid][0], record_id=references[eid][1])
                              for eid in group.evidence_ids} for group in claim.evidence_sets)
            for backend in ("duckdb", "mysql"):
                baseline = by_key["baseline", claim_id, backend]
                if (baseline is None
                    or not _answer_vectors_equal(_expected_answers(claim, "baseline", backend), baseline.answers)
                    or baseline.witnesses != groups or len(baseline.support) != len(robust.probes)
                    or len(baseline.support) < 2 or baseline.support[:2] != (True, False)):
                    raise ValueError("robustness baseline does not reproduce the required complete proof")
                for case in robust_plan.cases:
                    expected = next((entry for entry in case.expected if entry.claim_id == claim_id), None)
                    observed = by_key[case.case_id, claim_id, backend]
                    if expected is None or observed is None:
                        raise ValueError("robustness case is missing its exact claim expectation")
                    answers = _expected_answers(claim, expected.answer, backend)
                    witnesses = baseline.witnesses if expected.witnesses == "baseline" else _groups(g.citations for g in expected.witnesses)
                    support = baseline.support if expected.support == "baseline" else (
                        (False,) * len(robust.probes) if expected.support is False else expected.support
                    )
                    if (not _answer_vectors_equal(answers, observed.answers)
                        or observed.witnesses != witnesses or observed.support != support):
                        raise ValueError("passing robustness summary contradicts its measured counterfactual")
        _read_review(Path(files.robustness_review), task_fp, fingerprint(robust_plan), hashes)

        grading_subject = fingerprint(task.private_gold)
        if files.grading_policy_directory is not None:
            policy_dir = Path(files.grading_policy_directory)
            if original_admission_files is not None and prior_admission is not None:
                reviewed = ReviewedGradingAmendment.model_validate_json(read(policy_dir / "reviewed-policy.json"))
                policy = _retained_annotation_only_grading(plan, output, policy_dir, prior_admission, reviewed, read)
            else:
                policy = load_reviewed_grading(policy_dir)
            if policy.policy.task_fingerprint != task_fp:
                raise ValueError("reviewed grading amendment belongs to another question")
            grading_subject = fingerprint(policy)
            for path in policy_dir.rglob("*.json"):
                read(path)
            if any(component.evaluator_version != GRADING_POLICY_VERSION + ":" + grading_subject
                   for evaluation in evaluations for component in (
                       evaluation.answer_correctness, evaluation.final_evidence, *evaluation.checkpoints,
                   )):
                raise ValueError("native evaluation did not use the reviewed grading amendment")
        else:
            from .evidence import VERIFIER_VERSION
            if any(component.evaluator_version != VERIFIER_VERSION
                   for evaluation in evaluations for component in (
                       evaluation.answer_correctness, evaluation.final_evidence, *evaluation.checkpoints,
                   )):
                raise ValueError("native grading policy is not the explicitly reviewed core policy")
        _read_review(Path(files.grading_review), task_fp, grading_subject, hashes)

        difficulty_dir = Path(files.difficulty_directory)
        sidecar = DifficultySidecar.model_validate_json(read(difficulty_dir / "difficulty-sidecar.json"))
        plan_record = DifficultyPlan.model_validate_json(read(difficulty_dir / "difficulty-plan.json"))
        review = DifficultyReview.model_validate_json(read(difficulty_dir / "difficulty-review.json"))
        assessment = DifficultyAssessment.model_validate_json(read(difficulty_dir / "reviewer/result.json"))
        proposal = DifficultyProposal.model_validate_json(read(difficulty_dir / "curator/result.json"))
        binding = json.loads(read(difficulty_dir / "binding.json"))
        report = json.loads(read(difficulty_dir / "difficulty-report.json"))
        if (sidecar.binding != binding_for(question) or plan_record.binding != sidecar.binding
            or sidecar.plan_fingerprint != fingerprint(plan_record) or sidecar.review_fingerprint != fingerprint(review)
            or review.plan_fingerprint != fingerprint(plan_record)
            or assessment.review != review or assessment.task_defect_reasons
            or binding["implementation_sha256"] != difficulty_runtime_hashes()
            or binding["question_binding"] != sidecar.binding.model_dump(mode="json")
            or report["sidecar_fingerprint"] != fingerprint(sidecar)
            or report["task_fingerprint"] != task_fp or report["task_defect_reasons"]
            or report["plan_fingerprint"] != fingerprint(plan_record)
            or report["review_fingerprint"] != fingerprint(review)
            or report["model_performance_used_as_feature"] is not False
            or proposal.routes != plan_record.routes or proposal.limitations != plan_record.limitations
            or sidecar.implementation_sha256 != file_sha256(Path(__file__).with_name("difficulty.py"))
            or (sidecar.snapshot_id, sidecar.graph_version, sidecar.serving_view_id) != (
                task.snapshot_id, task.graph_version, task.serving_view_id
            )):
            raise ValueError("difficulty/source-quality review is not bound to the exact admitted task")
        for role, result in (("curator", proposal), ("reviewer", assessment)):
            complete = json.loads(read(difficulty_dir / role / "complete.json"))
            if complete.get("result_fingerprint") != fingerprint(result):
                raise ValueError("difficulty role is not a matching completed curation")
        if review.recommendation != "pass" or not all((
            review.proof_choices_complete_and_material, review.logical_bindings_and_domains_valid,
            review.operations_necessary, review.ambiguity_scopes_and_identities_valid,
        )) or sidecar.status not in ("provisional", "incomplete"):
            raise ValueError("difficulty semantics need review; no difficulty-band threshold is applied")
        expected_status = "difficulty_reviewed" if sidecar.status == "provisional" else "measurement_incomplete"
        if report["status"] != expected_status:
            raise ValueError("difficulty report does not reflect its measured/unknown state")
        for path in difficulty_dir.rglob("*.json"):
            read(path)

        if verification is not None:
            for name, digest in hashes.items():
                verification.require(Path(name), digest, "prepared admission artifact changed")
            verification.verify_unchanged()
            return PreparedAdmission(
                fingerprint(plan), output.resolve(), task, binding_for(question), files, question.bucket,
                sidecar, bool(evaluations[0].grounded_final), hashes, verification, candidate, runtime_hashes(),
                _VERIFIED_PREPARATION,
            )
        inventory = objective_inventory(plan, output, excluding=task.task_id)
        _read_objective_coverage(Path(files.objective_review), task_fp, inventory, hashes)
        admitted = admitted_receipts(plan, output)
        target = plan.tenant_target if question.bucket == "tenant" else plan.incident_target
        if revalidation_receipt is None and sum(item.bucket == question.bucket for item in admitted) >= target:
            raise ValueError("this scope already reached its validated-new target; retain surplus candidates without automatic admission")
        receipt = AdmissionReceipt(
            plan_fingerprint=fingerprint(plan), task=binding_for(question), bucket=question.bucket,
            inputs_fingerprint=fingerprint(files),
            objective_comparison_fingerprint=fingerprint(inventory), difficulty_status=sidecar.status,
            difficulty_score=sidecar.score, difficulty_band=sidecar.band,
            student_grounded_success=bool(evaluations[0].grounded_final),
            source_artifacts_sha256=hashes, implementation_sha256=file_sha256(Path(__file__)),
        )
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        immutable_json(destination, receipt)
        return receipt


def admission_progress(plan: PreproductionPlan, output: Path, *,
                       verification: ArtifactVerification | None = None) -> dict:
    """Recompute current counts, optionally reusing only verified immutable-file hashes."""
    if verification is None:
        progress = source_progress(plan, output)
        admitted = admitted_receipts(plan, output)
    else:
        progress = source_progress(plan, output, hash_file=verification.digest)
        admitted = admitted_receipts(plan, output, verification=verification)
    for bucket, counts in progress["buckets"].items():
        selected = [receipt for receipt in admitted if receipt.bucket == bucket]
        counts["validated_new_questions"] = len(selected)
        counts["validated_shortfall"] = counts["target_validated_new"] - len(selected)
        counts["difficulty_unmeasured"] = sum(receipt.difficulty_score is None for receipt in selected)
    progress["validated_new_questions"] = len(admitted)
    progress["admission_performed"] = bool(admitted)
    progress["admission_note"] = "Every admitted receipt has passed all downstream gates; remaining source candidates have not."
    return progress
