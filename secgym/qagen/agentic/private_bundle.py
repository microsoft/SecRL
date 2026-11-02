# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Portable, private question packets with unchanged authorizations and source bindings."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import Field

from . import difficulty
from .contracts import Contract, Digest, Identifier, TaskRecord, Text, fingerprint, require_unique
from .difficulty import DifficultyPlan, DifficultyReview, DifficultySidecar
from .grading_review import load_reviewed_grading
from .ledger import file_sha256
from .model_panel import immutable_json
from .preproduction import PreproductionPlan
from .preproduction_admission import AdmissionReceipt, admitted_receipts
from .question_splits import (
    QuestionBinding, QuestionFiles, SplitInputs, SplitPlan, SplitQuestion,
    binding_for, cohort_fingerprint, load_questions,
)


class DifficultyFiles(Contract):
    task_id: Identifier
    plan: Text
    review: Text
    sidecar: Text
    plan_sha256: Digest
    review_sha256: Digest
    sidecar_sha256: Digest


class DifficultyIndex(Contract):
    entries: tuple[DifficultyFiles, ...] = Field(min_length=1)


class BundledQuestion(Contract):
    binding: QuestionBinding
    origin: Literal["development", "preproduction"]
    partition: Literal["train", "test", "unassigned"]
    difficulty_directory: Text
    grading_policy_directory: Text | None
    authorization: Text


class PrivateBundle(Contract):
    policy_version: Literal["portable-private-qa-v1"] = "portable-private-qa-v1"
    cohort_fingerprint: Digest
    development_cohort_fingerprint: Digest
    inputs: Text
    student_tasks: Text
    development_approval: Text
    development_split: Text
    preproduction_plan: Text | None
    questions: tuple[BundledQuestion, ...] = Field(min_length=1)
    artifacts_sha256: dict[str, Digest]
    original_paths: dict[str, Text]
    source_snapshot_embedded: Literal[False] = False
    training_approved: Literal[False] = False
    release_approved: Literal[False] = False


def _path(root: Path, name: str) -> Path:
    relative = PurePosixPath(name)
    if relative.is_absolute() or ".." in relative.parts or "\\" in name or ":" in name:
        raise ValueError("private bundle paths must be portable relative paths")
    path = (root / name).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError("private bundle path escapes its packet")
    return path


def _one_named(paths, name: str) -> Path:
    found = [Path(path) for path in paths if Path(path).name == name]
    if len(found) != 1:
        raise ValueError(f"expected one exact authorized {name} artifact")
    return found[0]


def _difficulty(question: SplitQuestion, directory: Path) -> DifficultySidecar:
    plan = DifficultyPlan.model_validate_json((directory / "difficulty-plan.json").read_bytes())
    review = DifficultyReview.model_validate_json((directory / "difficulty-review.json").read_bytes())
    sidecar = DifficultySidecar.model_validate_json((directory / "difficulty-sidecar.json").read_bytes())
    if (plan.binding != binding_for(question) or sidecar.binding != plan.binding
        or sidecar.plan_fingerprint != fingerprint(plan) or review.plan_fingerprint != fingerprint(plan)
        or sidecar.review_fingerprint != fingerprint(review) or review.recommendation != "pass"
        or sidecar.implementation_sha256 != file_sha256(Path(difficulty.__file__))
        or sidecar.status not in ("provisional", "incomplete")
        or not all((review.proof_choices_complete_and_material, review.logical_bindings_and_domains_valid,
                    review.operations_necessary, review.ambiguity_scopes_and_identities_valid))
        or (sidecar.snapshot_id, sidecar.graph_version, sidecar.serving_view_id)
        != (question.task.snapshot_id, question.task.graph_version, question.task.serving_view_id)):
        raise ValueError("private bundle difficulty lacks its exact reviewed question/runtime binding")
    return sidecar


def load_private_bundle(directory: Path) -> tuple[PrivateBundle, tuple[SplitQuestion, ...]]:
    directory = directory.resolve()
    manifest = PrivateBundle.model_validate_json((directory / "manifest.json").read_bytes())
    if manifest.inputs != "private-inputs.json" or manifest.student_tasks != "student/tasks.json" or any(
        name.startswith("student/") and name != manifest.student_tasks for name in manifest.artifacts_sha256
    ):
        raise ValueError("private bundle must keep the student directory public-only")
    require_unique(tuple(item.binding.task_id for item in manifest.questions), "private bundle question IDs")
    actual = {str(path.relative_to(directory)) for path in directory.rglob("*") if path.is_file()}
    if actual != set(manifest.artifacts_sha256) | {"manifest.json"}:
        raise ValueError("private bundle file inventory differs from its manifest")
    for name, digest in manifest.artifacts_sha256.items():
        if file_sha256(_path(directory, name)) != digest:
            raise ValueError("private bundle artifact changed: " + name)
    if not set(manifest.original_paths.values()) <= manifest.artifacts_sha256.keys():
        raise ValueError("private bundle provenance points to an unbound artifact")

    def original(name: str, digest: str) -> Path:
        relative = manifest.original_paths.get(name)
        if relative is None or manifest.artifacts_sha256[relative] != digest:
            raise ValueError("private bundle lacks an exact original authorization dependency")
        return _path(directory, relative)

    def authorized(relative: str, hashes: dict[str, str]) -> None:
        if not any(manifest.original_paths.get(name) == relative and manifest.artifacts_sha256.get(relative) == digest
                   for name, digest in hashes.items()):
            raise ValueError("question sidecar or policy is not covered by its original admission")

    loaded = load_questions(_path(directory, manifest.inputs))
    by_id = {question.task.task_id: question for question in loaded.questions}
    if set(by_id) != {item.binding.task_id for item in manifest.questions} or cohort_fingerprint(loaded.questions) != manifest.cohort_fingerprint:
        raise ValueError("private bundle question membership or fingerprint changed")
    public = json.loads(_path(directory, manifest.student_tasks).read_bytes())
    if public != [question.task.public_task().model_dump(mode="json") for question in loaded.questions]:
        raise ValueError("student projection differs from the public-only task contracts")
    approval = json.loads(_path(directory, manifest.development_approval).read_bytes())
    if (approval["status"], approval["user_selection"], approval["split_method"]) != (
        "user_approved", "approve_refreshed_snapshot", "explicit",
    ) or approval["training_approved"] or approval["release_approved"]:
        raise ValueError("private bundle requires the explicit unreleased development approval")
    for hashes in (approval["source_artifacts_sha256"], approval["reviewed_artifact_sha256"]):
        for name, digest in hashes.items():
            original(name, digest)
    split_path = _one_named(approval["reviewed_artifact_sha256"], "split-plan.json")
    if manifest.original_paths[str(split_path)] != manifest.development_split:
        raise ValueError("private bundle split is not the approved original plan")
    split = SplitPlan.model_validate_json(_path(directory, manifest.development_split).read_bytes())
    dev = tuple(by_id[item.binding.task_id] for item in manifest.questions if item.origin == "development")
    if (cohort_fingerprint(dev), split.cohort_fingerprint, manifest.development_cohort_fingerprint) != (
        approval["cohort_fingerprint"], approval["cohort_fingerprint"], approval["cohort_fingerprint"],
    ) or len(dev) != approval["questions"] or split.method != "explicit":
        raise ValueError("private bundle changed the approved development cohort")
    assignments = {item.task_id: item for item in split.assignments}
    if set(assignments) != {q.task.task_id for q in dev}:
        raise ValueError("private bundle development split membership is incomplete")
    for partition in ("train", "test"):
        if sum(item.partition == partition for item in split.assignments) != approval[partition]:
            raise ValueError("private bundle changed an approved partition count")
    csv_path = _one_named(approval["reviewed_artifact_sha256"], "difficulty.csv")
    with original(str(csv_path), approval["reviewed_artifact_sha256"][str(csv_path)]).open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    difficulty_rows = {row["task_id"]: row for row in rows}
    if len(difficulty_rows) != len(rows) or set(difficulty_rows) != set(assignments):
        raise ValueError("approved difficulty table has missing or duplicate questions")
    dev_policies = {item["task_id"]: item for item in approval["grading_amendments"]}
    plan = (PreproductionPlan.model_validate_json(_path(directory, manifest.preproduction_plan).read_bytes())
            if manifest.preproduction_plan is not None else None)
    if plan is not None and {task.task_id: fingerprint(task) for task in plan.seed_questions} != {
        question.task.task_id: fingerprint(question.task) for question in dev
    }:
        raise ValueError("preproduction plan uses a different approved development baseline")
    for entry in manifest.questions:
        question = by_id[entry.binding.task_id]
        if entry.binding != binding_for(question):
            raise ValueError("private bundle question binding changed")
        sidecar = _difficulty(question, _path(directory, entry.difficulty_directory))
        policy = load_reviewed_grading(_path(directory, entry.grading_policy_directory)) if entry.grading_policy_directory else None
        if policy is not None and policy.policy.task_fingerprint != fingerprint(question.task):
            raise ValueError("private grading policy belongs to another task")
        if entry.origin == "development":
            assignment = assignments[entry.binding.task_id]
            if (entry.partition, entry.binding.task_fingerprint, entry.authorization) != (
                assignment.partition, assignment.task_fingerprint, manifest.development_approval,
            ):
                raise ValueError("private bundle changed an explicit development assignment")
            row = difficulty_rows[entry.binding.task_id]
            route = next((route for route in sidecar.routes if route.route_id == sidecar.selected_route), None)
            if route is None:
                raise ValueError("approved development difficulty requires its measured route, not a fabricated default")
            axes = route.combined.axes
            if (row["task_fingerprint"], row["status"], row["band"], float(row["score"])) != (
                entry.binding.task_fingerprint, sidecar.status, sidecar.band, sidecar.score,
            ) or any(int(row[name]) != value for name, value in axes.model_dump().items()):
                raise ValueError("private difficulty differs from the approved axes, score or band")
            expected = dev_policies.get(entry.binding.task_id)
            if (policy is None) != (expected is None):
                raise ValueError("an approved development grading amendment was dropped or added")
            if expected is not None:
                if policy is None or entry.grading_policy_directory is None or fingerprint(policy) != expected["policy_fingerprint"]:
                    raise ValueError("development grading amendment changed")
                path = str(Path(expected["directory"]) / "reviewed-policy.json")
                if manifest.original_paths.get(path) != entry.grading_policy_directory + "/reviewed-policy.json":
                    raise ValueError("development policy provenance changed")
                original(path, expected["reviewed_policy_sha256"])
        else:
            if plan is None or entry.partition != "unassigned":
                raise ValueError("preproduction questions require their plan and no implicit train/test assignment")
            receipt = AdmissionReceipt.model_validate_json(_path(directory, entry.authorization).read_bytes())
            if receipt.task != entry.binding or receipt.plan_fingerprint != fingerprint(plan):
                raise ValueError("preproduction question lacks its exact admission")
            for name, digest in receipt.source_artifacts_sha256.items():
                original(name, digest)
            for name in ("difficulty-plan.json", "difficulty-review.json", "difficulty-sidecar.json"):
                authorized(entry.difficulty_directory + "/" + name, receipt.source_artifacts_sha256)
            policy_sources = [name for name in receipt.source_artifacts_sha256 if Path(name).name == "reviewed-policy.json"]
            if bool(policy_sources) != (policy is not None):
                raise ValueError("an admitted grading amendment was dropped or added")
            if policy is not None:
                if entry.grading_policy_directory is None:
                    raise ValueError("admitted grading policy directory is missing")
                authorized(entry.grading_policy_directory + "/reviewed-policy.json", receipt.source_artifacts_sha256)
            if (sidecar.status, sidecar.score, sidecar.band) != (
                receipt.difficulty_status, receipt.difficulty_score, receipt.difficulty_band,
            ):
                raise ValueError("private difficulty differs from the immutable admission")
    return manifest, loaded.questions


def export_private_bundle(*, development: Path, difficulty_index: Path, output: Path,
                          preproduction_run: Path | None = None) -> PrivateBundle:
    development, difficulty_index, output = development.resolve(), difficulty_index.resolve(), output.resolve()
    if output.exists():
        raise ValueError("private bundle output must be a new directory")
    approval_path = development / "development-snapshot-approval.json"
    approval = json.loads(approval_path.read_bytes())
    loaded = load_questions(development / "inputs.json")
    if approval["source_artifacts_sha256"] != loaded.source_hashes:
        raise ValueError("development approval does not bind the current source packet")
    index = DifficultyIndex.model_validate_json(difficulty_index.read_bytes())
    require_unique(tuple(entry.task_id for entry in index.entries), "private difficulty sources")
    difficulty_sources = {entry.task_id: entry for entry in index.entries}
    if set(difficulty_sources) != {q.task.task_id for q in loaded.questions}:
        raise ValueError("difficulty index must cover the exact approved development cohort")
    split_path = _one_named(approval["reviewed_artifact_sha256"], "split-plan.json")
    split = SplitPlan.model_validate_json(split_path.read_bytes())
    assignments = {entry.task_id: entry.partition for entry in split.assignments}
    policies = {item["task_id"]: Path(item["directory"]) for item in approval["grading_amendments"]}
    packets = []
    sources = dict(loaded.source_hashes)
    sources.update(approval["reviewed_artifact_sha256"])
    sources[str(approval_path)] = file_sha256(approval_path)
    sources[str(difficulty_index)] = file_sha256(difficulty_index)
    development_questions = {q.task.task_id: q for q in loaded.questions}
    for entry in loaded.inputs.questions:
        task_path = (development / entry.task).resolve()
        task = TaskRecord.model_validate_json(task_path.read_bytes())
        question = development_questions[task.task_id]
        if task != question.task:
            raise ValueError("development task changed during export preparation")
        spec = difficulty_sources[question.task.task_id]
        difficulty_paths = {}
        for field in ("plan", "review", "sidecar"):
            path = (difficulty_index.parent / getattr(spec, field)).resolve()
            digest = getattr(spec, field + "_sha256")
            if file_sha256(path) != digest:
                raise ValueError("exact source difficulty artifact changed")
            sources[str(path)] = digest
            difficulty_paths[field] = path
        packets.append((question, entry, development, difficulty_paths, policies.get(question.task.task_id),
                        "development", assignments[question.task.task_id], approval_path))
    production_plan_path = None
    if preproduction_run is not None:
        preproduction_run = preproduction_run.resolve()
        production_plan_path = preproduction_run / "plan.json"
        plan = PreproductionPlan.model_validate_json(production_plan_path.read_bytes())
        sources[str(production_plan_path)] = file_sha256(production_plan_path)
        for receipt in admitted_receipts(plan, preproduction_run):
            names = receipt.source_artifacts_sha256
            inputs_path = _one_named(names, "inputs.json")
            candidate = load_questions(inputs_path)
            if len(candidate.questions) != 1 or binding_for(candidate.questions[0]) != receipt.task:
                raise ValueError("admission does not identify one exact native/canonical packet")
            policy_paths = [Path(name).parent for name in names if Path(name).name == "reviewed-policy.json"]
            if len(policy_paths) > 1:
                raise ValueError("admission has ambiguous grading-policy provenance")
            receipt_path = preproduction_run / "admissions" / (receipt.task.task_id + ".json")
            sources.update(names)
            sources[str(receipt_path)] = file_sha256(receipt_path)
            packets.append((candidate.questions[0], candidate.inputs.questions[0], inputs_path.parent,
                            {field: _one_named(names, filename) for field, filename in (
                                ("plan", "difficulty-plan.json"), ("review", "difficulty-review.json"),
                                ("sidecar", "difficulty-sidecar.json"),
                            )}, policy_paths[0] if policy_paths else None, "preproduction", "unassigned", receipt_path))
    require_unique(tuple(packet[0].task.task_id for packet in packets), "private export tasks")
    for name, digest in sources.items():
        if file_sha256(Path(name)) != digest:
            raise ValueError("authorized source artifact changed before export")
    output.mkdir(parents=True, mode=0o700)
    origins: dict[str, str] = {}
    hashes: dict[str, str] = {}

    def copy(source: Path, relative: str) -> str:
        source = source.resolve()
        if str(source) in origins:
            return origins[str(source)]
        if source.suffix not in (".json", ".csv", ".zip"):
            raise ValueError("private bundle accepts only declared JSON/CSV/runtime-archive artifacts")
        data = source.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if str(source) in sources and sources[str(source)] != digest:
            raise ValueError("source artifact changed during export")
        destination = _path(output, relative)
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with destination.open("xb") as stream:
            stream.write(data)
        origins[str(source)], hashes[relative] = relative, digest
        return relative

    entries = []
    question_files = []
    for index, (question, entry, base, difficulty_paths, policy, origin, partition, authorization) in enumerate(
        sorted(packets, key=lambda packet: packet[0].task.task_id)
    ):
        prefix = f"private/questions/{index:04d}"
        fields = {name: copy(base / getattr(entry, name), prefix + "/" + name + ".json")
                  for name in ("task", "validation", "baseline")}
        annotation = (base / entry.annotation).resolve()
        if output.is_relative_to(annotation) or (policy is not None and output.is_relative_to(policy.resolve())):
            raise ValueError("private bundle output cannot be nested inside a source annotation or policy")
        annotation_paths = {annotation / name for name in (
            "canonical-facts.json", "reviewer/result.json", "binding.json", "fact_report.json", "canonical-footprint.json",
        )}
        for role in ("curator", "reviewer"):
            annotation_paths.update((annotation / role).rglob("*.json"))
        for path in sorted(annotation_paths):
            copy(path, prefix + "/canonical/" + str(path.relative_to(annotation)))
        fields["annotation"] = prefix + "/canonical"
        question_files.append(QuestionFiles(**fields))
        for name, path in difficulty_paths.items():
            copy(path, prefix + "/difficulty/difficulty-" + name + ".json")
        policy_directory = None
        if policy is not None:
            load_reviewed_grading(policy)
            policy_directory = prefix + "/grading-policy"
            for path in sorted(policy.rglob("*.json")):
                copy(path, policy_directory + "/" + str(path.relative_to(policy)))
        authorization_path = copy(authorization, f"private/provenance/{len(origins):06d}.json")
        entries.append(BundledQuestion(
            binding=binding_for(question), origin=origin, partition=partition,
            difficulty_directory=prefix + "/difficulty", grading_policy_directory=policy_directory,
            authorization=authorization_path,
        ))
    for name in sorted(sources):
        copy(Path(name), f"private/provenance/{len(origins):06d}" + Path(name).suffix)
    portable_inputs = SplitInputs(cohort_label="portable-private-qa", questions=tuple(question_files))
    immutable_json(output / "private-inputs.json", portable_inputs)
    hashes["private-inputs.json"] = file_sha256(output / "private-inputs.json")
    questions = load_questions(output / "private-inputs.json").questions
    student = output / "student"
    student.mkdir(mode=0o700)
    public = [question.task.public_task().model_dump(mode="json") for question in questions]
    (student / "tasks.json").write_text(json.dumps(public, indent=2, allow_nan=False) + "\n")
    hashes["student/tasks.json"] = file_sha256(student / "tasks.json")
    manifest = PrivateBundle(
        cohort_fingerprint=cohort_fingerprint(questions), development_cohort_fingerprint=approval["cohort_fingerprint"],
        inputs="private-inputs.json", student_tasks="student/tasks.json", questions=tuple(entries),
        development_approval=origins[str(approval_path)], development_split=origins[str(split_path)],
        preproduction_plan=origins[str(production_plan_path)] if production_plan_path is not None else None,
        artifacts_sha256=hashes, original_paths=origins,
    )
    immutable_json(output / "manifest.json", manifest)
    load_private_bundle(output)
    return manifest
