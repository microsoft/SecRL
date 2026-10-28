# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Deterministic scoring primitives, not an evidence verifier or live backend adapter."""

from fractions import Fraction
from typing import Literal

from pydantic import ValidationError

from .contracts import (
    EvaluationRecord, RewardPolicy, ScoreComponent, TaskRecord, TypedAnswer,
    exact_timestamp_seconds, fingerprint, normalized_checkpoint_progress,
)


def compare_typed_answers(expected: TypedAnswer, submitted: TypedAnswer) -> bool:
    expected = TypedAnswer.model_validate(expected)
    submitted = TypedAnswer.model_validate(submitted)
    if submitted.format != expected.format:
        raise ValueError("submitted answer format must match the task's declared comparison policy")
    kind, left, right = expected.format.kind, expected.value, submitted.value
    if kind == "number":
        return abs(Fraction(str(left)) - Fraction(str(right))) <= Fraction(str(expected.format.tolerance))
    if kind == "timestamp":
        if not isinstance(left, str) or not isinstance(right, str):
            raise ValueError("timestamp comparison requires strings")
        return abs(exact_timestamp_seconds(left) - exact_timestamp_seconds(right)) <= Fraction(str(expected.format.tolerance))
    if kind in ("entity", "boolean"):
        if expected.format.normalization == "casefold":
            if not isinstance(left, str) or not isinstance(right, str):
                raise ValueError("casefold comparison requires strings")
            return left.casefold() == right.casefold()
        return left == right
    if not isinstance(left, tuple) or not isinstance(right, tuple):
        raise ValueError("collection comparison requires tuple values")
    if expected.format.normalization == "casefold":
        left, right = tuple(v.casefold() for v in left), tuple(v.casefold() for v in right)
    return set(left) == set(right) if kind == "set" else left == right


def compare_checkpoint_finding(expected: TypedAnswer, submitted: TypedAnswer) -> bool:
    """Descriptive finding labels are not secret rubric IDs; the rubric owns comparison policy."""
    expected, submitted = TypedAnswer.model_validate(expected), TypedAnswer.model_validate(submitted)
    if submitted.format.kind != expected.format.kind or submitted.format.units != expected.format.units:
        return False
    try:
        under_rubric = TypedAnswer(format=expected.format, value=submitted.value)
    except ValidationError:
        return False
    return compare_typed_answers(expected, under_rubric)


def aggregate_evaluation(
    task: TaskRecord, *, run_id: str, backend: Literal["secrl", "acesevals"], trajectory_ref: str,
    answer_correctness: ScoreComponent, final_evidence: ScoreComponent,
    checkpoints: tuple[ScoreComponent, ...], reward_policy: RewardPolicy | None = None,
    backend_adapter_version: str = "component-record-v1",
) -> EvaluationRecord:
    """Aggregate trusted component verdicts; citations are not independently validated here."""
    task = TaskRecord.model_validate(task)
    answer_correctness = ScoreComponent.model_validate(answer_correctness)
    final_evidence = ScoreComponent.model_validate(final_evidence)
    checkpoints = tuple(ScoreComponent.model_validate(c) for c in checkpoints)
    policy = RewardPolicy.model_validate(reward_policy or task.reward_policy)
    components = (answer_correctness, final_evidence, *checkpoints)
    status: Literal["complete", "incomplete", "error"] = (
        "error" if any(c.status == "error" for c in components)
        else "incomplete" if any(c.status == "incomplete" for c in components)
        else "complete"
    )
    final, progress, reward = None, None, None
    if status == "complete":
        final = answer_correctness.score == answer_correctness.max_score and final_evidence.score == final_evidence.max_score
        progress = normalized_checkpoint_progress(checkpoints)
        reward = max(float(final), policy.checkpoint_cap * progress)
    result = EvaluationRecord(
        run_id=run_id, task_id=task.task_id, task_fingerprint=fingerprint(task),
        evaluation_profile=task.evaluation_profile, backend=backend, reward_policy=policy,
        backend_adapter_version=backend_adapter_version,
        trajectory_ref=trajectory_ref, status=status,
        answer_correctness=answer_correctness, final_evidence=final_evidence, checkpoints=checkpoints,
        grounded_final=final, checkpoint_progress=progress, aggregate_reward=reward,
    )
    mismatches = result.task_mismatches(task)
    if mismatches:
        raise ValueError("; ".join(mismatches))
    return result
