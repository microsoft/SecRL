# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Exploratory paired results; model outcomes never modify difficulty annotations."""

from collections import Counter, defaultdict
import csv
import hashlib
import itertools
import json
import math
from pathlib import Path
import random
import statistics

from .contracts import EvaluationRecord
from .ledger import file_sha256


def wilson(successes: int, total: int) -> tuple[float, float] | None:
    if not 0 <= successes <= total:
        raise ValueError("invalid binomial counts")
    if not total:
        return None
    z = 1.959963984540054
    rate = successes / total
    denominator = 1 + z * z / total
    center = (rate + z * z / (2 * total)) / denominator
    radius = z * math.sqrt(rate * (1 - rate) / total + z * z / (4 * total * total)) / denominator
    return max(0.0, center - radius), min(1.0, center + radius)


def _ranks(values):
    order = sorted(range(len(values)), key=lambda index: values[index])
    ranks = [0.0] * len(values)
    start = 0
    while start < len(order):
        end = start + 1
        while end < len(order) and values[order[end]] == values[order[start]]:
            end += 1
        for index in order[start:end]:
            ranks[index] = (start + 1 + end) / 2
        start = end
    return ranks


def spearman(scores, outcomes):
    if len(scores) != len(outcomes) or any(not math.isfinite(value) for value in (*scores, *outcomes)):
        raise ValueError("correlation requires equal finite measurements")
    if len(scores) < 2:
        return None
    x, y = _ranks(scores), _ranks(outcomes)
    xm, ym = statistics.mean(x), statistics.mean(y)
    denominator = math.sqrt(sum((value - xm) ** 2 for value in x) * sum((value - ym) ** 2 for value in y))
    return sum((a - xm) * (b - ym) for a, b in zip(x, y)) / denominator if denominator else None


def paired_comparison(rows, first, second, *, samples=2000, seed=42):
    if samples <= 0:
        raise ValueError("bootstrap samples must be positive")
    pairs = defaultdict(dict)
    for row in rows:
        if row["model"] in (first, second) and row["grounded_final"] is not None:
            if row["model"] in pairs[row["task_fingerprint"]]:
                raise ValueError("duplicate model outcome for a question")
            pairs[row["task_fingerprint"]][row["model"]] = row
    complete = [pair for pair in pairs.values() if first in pair and second in pair]
    wins_first = sum(pair[first]["grounded_final"] and not pair[second]["grounded_final"] for pair in complete)
    wins_second = sum(pair[second]["grounded_final"] and not pair[first]["grounded_final"] for pair in complete)
    discordant = wins_first + wins_second
    p_value = min(1.0, 2 * sum(math.comb(discordant, k) for k in range(min(wins_first, wins_second) + 1)) / 2 ** discordant) if discordant else 1.0
    clusters = defaultdict(list)
    for pair in complete:
        if pair[first]["bucket"] != pair[second]["bucket"]:
            raise ValueError("paired task scope differs")
        clusters[pair[first]["bucket"]].append(int(pair[second]["grounded_final"]) - int(pair[first]["grounded_final"]))
    interval = None
    if len(clusters) > 1:
        rng = random.Random(seed)
        keys = sorted(clusters)
        values = []
        for _ in range(samples):
            selected = [value for key in rng.choices(keys, k=len(keys)) for value in clusters[key]]
            values.append(statistics.mean(selected))
        values.sort()
        interval = (values[int(0.025 * (samples - 1))], values[int(0.975 * (samples - 1))])
    return {
        "first": first, "second": second, "paired_questions": len(complete),
        "first_only_success": wins_first, "second_only_success": wins_second,
        "ties": len(complete) - discordant,
        "second_minus_first_success_rate": (wins_second - wins_first) / len(complete) if complete else None,
        "exact_mcnemar_p_exploratory": p_value if complete else None,
        "scope_cluster_bootstrap_95": interval, "scope_clusters": len(clusters),
        "bootstrap_samples": samples, "bootstrap_seed": seed,
    }


def _within(root: Path, relative: str) -> Path:
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError("panel artifact escapes its owning directory")
    return path


def load_panel(panel: Path, *, manifest_name="manifest.json"):
    manifest_path = _within(panel, manifest_name)
    manifest = json.loads(manifest_path.read_bytes())
    manifest_fingerprint = hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    parent = None
    parent_fingerprint = None
    if "parent_manifest" in manifest:
        parent_path = _within(panel, manifest["parent_manifest"]["path"])
        if file_sha256(parent_path) != manifest["parent_manifest"]["sha256"]:
            raise ValueError("the protocol amendment's parent manifest changed")
        parent = json.loads(parent_path.read_bytes())
        parent_fingerprint = hashlib.sha256(json.dumps(parent, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
        for key in ("profile", "models", "cohort_fingerprint", "difficulty_inventory", "source_artifacts_sha256"):
            if manifest[key] != parent[key]:
                raise ValueError("a grader-only amendment cannot change student settings, source or difficulty")
        if {(r["task_fingerprint"], r["model"], r["run_id"]) for r in manifest["episodes"]} != {
            (r["task_fingerprint"], r["model"], r["run_id"]) for r in parent["episodes"]
        }:
            raise ValueError("protocol amendment changed the planned student episode matrix")
    if len(manifest["episodes"]) != manifest["episode_count"]:
        raise ValueError("panel episode inventory differs from its manifest")
    keys = [(row["task_fingerprint"], row["model"]) for row in manifest["episodes"]]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate planned question/model pair")
    if not manifest["models"] or len(set(manifest["models"])) != len(manifest["models"]) or set(keys) != {
        (task, model) for task in manifest["difficulty_inventory"] for model in manifest["models"]
    }:
        raise ValueError("panel manifest must cover the complete unique question/model matrix")
    rows = []
    pending = []
    for planned in manifest["episodes"]:
        directory = _within(panel, planned["relative_output"])
        if not (directory / "episode.json").exists():
            pending.append(planned)
            continue
        result = json.loads((directory / "episode.json").read_bytes())
        binding = json.loads((directory / "binding.json").read_bytes())
        if (result["model"], result["task_fingerprint"], result["run_id"]) != (
            planned["model"], planned["task_fingerprint"], planned["run_id"],
        ) or result["binding_sha256"] != file_sha256(directory / "binding.json"):
            raise ValueError("recorded episode does not match the panel plan")
        retained = planned.get("producer") == "parent"
        if planned.get("producer") not in (None, "parent", "amended") or (retained and parent is None):
            raise ValueError("unknown episode producer in amended panel")
        expected_manifest = parent_fingerprint if retained else manifest_fingerprint
        expected_runtime = parent["implementation_sha256"] if retained else manifest["implementation_sha256"]
        if (binding["manifest_fingerprint"] != expected_manifest or binding["profile"] != manifest["profile"]
            or binding["implementation_sha256"] != expected_runtime):
            raise ValueError("episode runtime/profile differs from its frozen panel")
        if parent is not None and not retained:
            expected_limits = {**manifest["profile"]["query_limits"],
                               "timeout_ms": manifest["grading_policy_amendment"]["private_grader_timeout_ms"]}
            if binding.get("grading_query_limits") != expected_limits:
                raise ValueError("private grading limits differ from the explicit protocol amendment")
        role = Path(result["student_trace_from"]) if "student_trace_from" in result else directory / "student"
        if not role.resolve().is_relative_to(panel.resolve()) or binding.get("student_trace_from") != result.get("student_trace_from"):
            raise ValueError("retained student trace has an invalid source binding")
        role_hashes = {path.name: file_sha256(path) for path in sorted(role.glob("*.json"))}
        if result["role_artifacts_sha256"] != role_hashes:
            raise ValueError("captured model episode changed")
        if result["evaluation_sha256"] is not None:
            grade_path = directory / "grade.json"
            if file_sha256(grade_path) != result["evaluation_sha256"]:
                raise ValueError("episode grade changed")
            grade = json.loads(grade_path.read_bytes())
            if grade["role_artifacts_sha256"] != role_hashes:
                raise ValueError("native grade is not bound to the captured episode")
            for name, digest in grade["artifacts_sha256"].items():
                if file_sha256(_within(directory, name)) != digest:
                    raise ValueError("native grading artifact changed")
            evaluation = EvaluationRecord.model_validate_json(json.dumps(grade["evaluation"]))
            if evaluation.task_fingerprint != planned["task_fingerprint"] or evaluation.run_id != f"{planned['run_id']}-secrl" or (
                result["grounded_final"], result["checkpoint_progress"], result["reward"],
                result["answer_correctness"], result["final_evidence"],
            ) != (evaluation.grounded_final, evaluation.checkpoint_progress, evaluation.aggregate_reward,
                  evaluation.answer_correctness.score, evaluation.final_evidence.score):
                raise ValueError("episode summary differs from its native evaluation")
        elif any(result[name] is not None for name in ("grounded_final", "checkpoint_progress", "reward", "answer_correctness", "final_evidence")):
            raise ValueError("an ungraded episode must not manufacture scores")
        difficulty = manifest["difficulty_inventory"][planned["task_fingerprint"]]
        rows.append({
            "task_id": planned["task_id"], "task_fingerprint": planned["task_fingerprint"],
            "bucket": difficulty["bucket"], "score": float(difficulty["score"]), "band": difficulty["band"],
            "model": planned["model"], "status": result["status"], "grounded_final": result["grounded_final"],
            "answer_correctness": result["answer_correctness"], "final_evidence": result["final_evidence"],
            "checkpoint_progress": result["checkpoint_progress"], "reward": result["reward"],
            "responses": result["usage"]["responses"], "input_tokens": result["usage"]["input_tokens"],
            "output_tokens": result["usage"]["output_tokens"], "reasoning_tokens": result["usage"]["reasoning_tokens"],
            "grader_timeout_ms": binding.get("grading_query_limits", manifest["profile"]["query_limits"])["timeout_ms"],
        })
    return manifest, rows, pending


def analyze_panel(panel: Path, output: Path, *, samples=2000, seed=42, manifest_name="manifest.json") -> dict:
    if output.exists():
        raise ValueError("panel analysis output must be new")
    if samples <= 0:
        raise ValueError("bootstrap samples must be positive")
    manifest, rows, pending = load_panel(panel, manifest_name=manifest_name)
    models = {}
    for model in manifest["models"]:
        measured = [row for row in rows if row["model"] == model]
        scored = [row for row in measured if row["grounded_final"] is not None]
        successes = sum(row["grounded_final"] for row in scored)
        planned = sum(item["model"] == model for item in manifest["episodes"])
        bands = {}
        for band in ("easy", "medium", "hard", "very_hard"):
            group = [row for row in scored if row["band"] == band]
            successful = sum(row["grounded_final"] for row in group)
            correct_answers = sum(row["answer_correctness"] == 1.0 for row in group)
            bands[band] = {
                "scored": len(group), "successes": successful,
                "success_rate": successful / len(group) if group else None,
                "answer_only_correct": correct_answers,
                "answer_only_accuracy": correct_answers / len(group) if group else None,
                "descriptive_wilson_95": wilson(successful, len(group)),
                "planned": sum(value["band"] == band for value in manifest["difficulty_inventory"].values()),
            }
        models[model] = {
            "planned": planned, "recorded": len(measured), "scored": len(scored),
            "pending": planned - len(measured), "ungraded": len(measured) - len(scored),
            "terminal_statuses": dict(Counter(row["status"] for row in measured)),
            "successes": successes, "success_rate": successes / len(scored) if scored else None,
            "descriptive_wilson_95": wilson(successes, len(scored)),
            "all_planned_success_bounds": (successes / planned, (successes + planned - len(scored)) / planned),
            "answer_only_correct": sum(row["answer_correctness"] == 1.0 for row in scored),
            "answer_only_accuracy": statistics.mean(row["answer_correctness"] for row in scored) if scored else None,
            "answer_correct_but_not_grounded": sum(row["answer_correctness"] == 1.0 and not row["grounded_final"] for row in scored),
            "questions_with_full_checkpoint_credit": sum(row["checkpoint_progress"] == 1.0 for row in scored),
            "mean_checkpoint_progress": statistics.mean(row["checkpoint_progress"] for row in scored) if scored else None,
            "score_success_spearman": spearman([row["score"] for row in scored], [int(row["grounded_final"]) for row in scored]),
            "score_answer_correctness_spearman": spearman([row["score"] for row in scored],
                                                          [row["answer_correctness"] for row in scored]),
            "output_tokens": sum(row["output_tokens"] for row in measured), "bands": bands,
        }
    report = {
        "status": "partial" if pending else "all_planned_outcomes_recorded",
        "manifest_sha256": file_sha256(_within(panel, manifest_name)), "cohort_fingerprint": manifest["cohort_fingerprint"],
        "grading_timeout_counts": dict(Counter(row["grader_timeout_ms"] for row in rows)),
        "models": models, "paired": [paired_comparison(rows, a, b, samples=samples, seed=seed)
                                     for a, b in itertools.combinations(manifest["models"], 2)],
        "pending_episodes": pending, "heuristic_changed": False, "thresholds_tuned": False,
        "interpretation": (
            "Exploratory deployed-model comparison, not a causal parameter-count study or production calibration. "
            "No easy items are present in this cohort. Six very-hard items provide weak precision. "
            "Wilson intervals are descriptive question-level intervals; shared evidence limits independence. "
            "Paired differences additionally use scope-cluster bootstrap intervals. P-values are exploratory, "
            "not multiplicity-adjusted confirmatory tests. Missing/operational outcomes remain unknown; "
            "budget exhaustion, abstention and invalid completions retain their observed unsuccessful final outcomes. "
            "Any future heuristic tuning needs independent preproduction confirmation."
        ),
    }
    output.mkdir(parents=True, mode=0o700)
    (output / "report.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    with (output / "episodes.csv").open("w") as stream:
        columns = list(rows[0]) if rows else ["task_id", "task_fingerprint", "model", "status"]
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
    return report
