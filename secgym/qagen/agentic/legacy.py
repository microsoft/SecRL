# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Read-only version aliases and content checks for the legacy benchmark."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from .contracts import Contract, Digest, NonnegativeInt, PositiveInt, Text, fingerprint


LEGACY_INCIDENTS = (5, 34, 38, 39, 55, 134, 166, 322)
RELEASES = {
    "v0.1": ("secgym/questions/o1/v1", "incident_{incident}_qa_incident_o1-ga_c42.json"),
    "v0.2": ("secgym/questions/opus5", "incident_{incident}_qa_opus5_cleaned.json"),
}
LEGACY_CODE = (
    "secgym/qagen/alert_graph.py", "secgym/qagen/qa_gen.py", "secgym/qagen/qa_gen_prompts.py",
    "secgym/qagen/entity_email_fix/regenerate_opus5.py",
    "secgym/excytin_env.py", "secgym/evaluator.py", "secgym/utils/utils.py",
    "secgym/agents/agent_utils.py", "experiments/run_qa_gen.py",
    "experiments/run_exp.py", "experiments/run_reevaluation.py",
    "experiments/result_analysis/analysis.py", "notebooks/question_split.ipynb",
)


class LegacyFile(Contract):
    path: Text
    sha256: Digest
    size_bytes: NonnegativeInt


class LegacyQuestionFile(LegacyFile):
    dataset_release: Literal["v0.1", "v0.2"]
    incident_id: PositiveInt
    split: Literal["train", "test"]
    questions: NonnegativeInt


class LegacyBaseline(Contract):
    schema_version: Literal["1"] = "1"
    generator_version: Literal["v0"] = "v0"
    release_files: Annotated[tuple[LegacyQuestionFile, ...], Field(min_length=1)]
    preserved_files: Annotated[tuple[LegacyFile, ...], Field(min_length=1)]


def file_record(root: Path, relative: str) -> LegacyFile:
    path = root / relative
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"expected a regular legacy file within the repository: {relative}")
    content = path.read_bytes()
    return LegacyFile(
        path=relative, sha256=hashlib.sha256(content).hexdigest(), size_bytes=len(content),
    )


def build_legacy_baseline(root: Path) -> LegacyBaseline:
    release_files = []
    for version, (directory, pattern) in RELEASES.items():
        for split in ("train", "test"):
            for incident in LEGACY_INCIDENTS:
                relative = f"{directory}/{split}/{pattern.format(incident=incident)}"
                entry = file_record(root, relative)
                data = json.loads((root / relative).read_bytes())
                if not isinstance(data, list) or any(not isinstance(row, dict) for row in data):
                    raise ValueError(f"expected a JSON array of question objects: {relative}")
                release_files.append(LegacyQuestionFile.model_validate({
                    **entry.model_dump(), "dataset_release": version, "incident_id": incident,
                    "split": split, "questions": len(data),
                }))
    paths = set(LEGACY_CODE)
    for directory, extension in (
        ("secgym/questions/o1", "*.json"),
        ("secgym/questions/o3", "*.json"),
        ("secgym/questions/opus5", "*.json"),
        ("secgym/qagen/graph_files", "*.graphml"),
        ("secgym/qagen/graph_files_fixed", "*.graphml"),
    ):
        discovered = sorted((root / directory).rglob(extension))
        if not discovered:
            raise ValueError(f"missing legacy baseline directory or files: {directory}")
        paths.update(p.relative_to(root).as_posix() for p in discovered)
    return LegacyBaseline(
        release_files=tuple(release_files),
        preserved_files=tuple(file_record(root, p) for p in sorted(paths)),
    )


def load_pinned_baseline() -> LegacyBaseline:
    return LegacyBaseline.model_validate_json(Path(__file__).with_name("legacy_baseline.json").read_bytes())


def baseline_changes(expected: LegacyBaseline, actual: LegacyBaseline) -> tuple[str, ...]:
    before = {f.path: f for f in expected.preserved_files}
    after = {f.path: f for f in actual.preserved_files}
    changes = []
    for path in sorted(before.keys() | after.keys()):
        if path not in before:
            changes.append(f"added: {path}")
        elif path not in after:
            changes.append(f"missing: {path}")
        elif before[path] != after[path]:
            changes.append(f"changed: {path}")
    if expected.release_files != actual.release_files:
        changes.append("legacy release alias mapping, counts, or contents changed")
    return tuple(changes)


def baseline_summary(baseline: LegacyBaseline) -> dict[str, object]:
    counts = {
        release: {
            split: sum(f.questions for f in baseline.release_files
                       if f.dataset_release == release and f.split == split)
            for split in ("train", "test")
        }
        for release in RELEASES
    }
    return {
        "generator_version": baseline.generator_version, "releases": counts,
        "preserved_files": len(baseline.preserved_files), "fingerprint": fingerprint(baseline),
    }
