# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Finish private candidate admission with actual MySQL and dual adapter replay."""

import asyncio
import json
from pathlib import Path

from .acesevals_adapter import export_aces_task, make_aces_tools, register_aces_strategy
from .contracts import GateResult, TaskRecord, ValidationReport, fingerprint
from .evidence import EvidenceVerifier, Finding, serving_parity
from .generation import BlindSolution, DiscoveryTools, ReviewResult, TaskDraft, run_role
from .pilot import BLIND_INSTRUCTIONS
from .scoring import compare_typed_answers
from .secrl_adapter import SecRLV1Env, Submission


def recorded_actions(role_directory: Path) -> list[tuple[str, str]]:
    actions = []
    for path in sorted(role_directory.glob("*-response.json")):
        response = json.loads(path.read_text())
        for call in response["choices"][0]["message"].get("tool_calls", []):
            if call["function"]["name"] == "sql":
                actions.append(("sql", json.loads(call["function"]["arguments"])["query"]))
            elif call["function"]["name"] == "record_finding":
                actions.append(("finding", call["function"]["arguments"]))
    return actions


def private_pilot_validation(candidate: Path, source: EvidenceVerifier, mysql: EvidenceVerifier,
                             *, discovery_report: Path | None = None,
                             require_source_quality: bool = False) -> ValidationReport:
    task = TaskRecord.model_validate_json((candidate / "task.json").read_text())
    summary = json.loads((discovery_report or candidate / "pilot_report.json").read_text())
    if summary["task_fingerprint"] != fingerprint(task) or summary["status"] != "candidate_for_mysql_validation":
        raise ValueError("candidate did not pass its version-bound discovery checks")
    policy_path = candidate / "execution-policy.json"
    policy = json.loads(policy_path.read_text()) if policy_path.exists() else {}
    if not isinstance(policy, dict):
        raise ValueError("candidate execution policy must be a JSON object")
    quality_required = (
        require_source_quality or "source_quality_policy" in policy
        or "source_quality" in summary or (candidate / "quality").exists()
    )
    if quality_required:
        from .quality import QUALITY_VERSION, validate_quality_gate

        gate = json.loads((candidate / "quality/gate.json").read_text())
        if policy.get("source_quality_policy") != QUALITY_VERSION or summary.get("source_quality") != gate:
            raise ValueError("native validation requires the bound source quality policy and report")
        validate_quality_gate(candidate, task)
    review = ReviewResult.model_validate_json((candidate / "refuter/result.json").read_text())
    if review.recommendation != "pass":
        raise ValueError("independent refutation did not pass")
    for citation in review.counterevidence:
        mysql.citation_lineage(citation)
    mechanical = mysql.mechanical_report(task)
    reasons = " ".join(review.reasons)
    outcomes = {
        "identity_evidence": review.scope_supported and review.causal_claims_supported,
        "evidence_independence": review.evidence_independent,
        "scope": review.scope_supported,
        "uniqueness": review.answer_unambiguous,
        "wording_leakage": review.wording_leakage_free,
        "refutation": all((review.scope_supported, review.evidence_independent, review.causal_claims_supported,
                           review.wording_leakage_free, review.literal_justifications_supported,
                           review.answer_unambiguous, review.checkpoints_distinct_and_supported)),
        "blind_verification": summary["blind_answer_correct"] and summary.get(
            "complete_witness_observed", summary["blind_evidence_grounded"]),
    }
    gates = list(mechanical.gates)
    if not review.literal_justifications_supported or not review.checkpoints_distinct_and_supported:
        raise ValueError("literal/checkpoint review failed")
    for name, passed in outcomes.items():
        gates.append(GateResult(gate=name, status="pass" if passed else "fail",
                                reason="Independent source-inspecting model review: " + reasons,
                                artifact_refs=(str(candidate / "refuter/result.json"),) + (
                                    (str(candidate / "quality/gate.json"),) if quality_required and name == "refutation" else ()
                                )))
    gates.append(serving_parity(task, source, mysql))
    result = ValidationReport(task_id=task.task_id, task_fingerprint=fingerprint(task),
                              evaluator_version="private-pilot-validation-v1", gates=tuple(gates))
    return result


def evaluate_candidate(candidate: Path, output: Path, source: EvidenceVerifier, mysql: EvidenceVerifier, client,
                       *, blind_from: Path | None = None, discovery_report: Path | None = None,
                       require_source_quality: bool = False) -> dict:
    if output.exists():
        raise ValueError("candidate evaluation output must be new")
    output.mkdir(parents=True, mode=0o700)
    task = TaskRecord.model_validate_json((candidate / "task.json").read_text())
    draft = TaskDraft.model_validate_json((candidate / "draft.json").read_text())
    if mysql.allowed_literals != frozenset(item.value for item in draft.allowed_literals):
        raise ValueError("MySQL verifier is not configured for the candidate literal policy")
    validation = private_pilot_validation(candidate, source, mysql, discovery_report=discovery_report,
                                          require_source_quality=require_source_quality)
    (output / "private-pilot-validation.json").write_text(validation.model_dump_json(indent=2) + "\n")
    if validation.pilot_blockers(task):
        raise ValueError("; ".join(validation.pilot_blockers(task)))
    blind_directory = blind_from or output / "mysql-blind"
    if blind_from is not None:
        context = json.loads((blind_from / "0000-request.json").read_text())
        if json.loads(context["messages"][1]["content"]) != task.public_task().model_dump(mode="json"):
            raise ValueError("recorded blind context does not match the current public task")
        blind = BlindSolution.model_validate_json((blind_from / "result.json").read_text())
        complete = json.loads((blind_from / "complete.json").read_text())
        if complete["role"] != "mysql-blind" or complete["result_fingerprint"] != fingerprint(blind):
            raise ValueError("recorded blind result fingerprint mismatch")
        (output / "blind-source.json").write_text(json.dumps({
            "role_directory": str(blind_from), "result_fingerprint": fingerprint(blind),
            "reason": "Reevaluate unchanged recorded student behavior; do not resample it to force success.",
        }, indent=2) + "\n")
    else:
        blind = run_role(client, DiscoveryTools(mysql.engine, mysql.tables, record_findings=True), "mysql-blind", BLIND_INSTRUCTIONS,
                         task.public_task().model_dump(mode="json"), BlindSolution, blind_directory)
    proofs = mysql.preflight(task)
    correct = blind.answer.format == task.private_gold.final.expected.format and compare_typed_answers(task.private_gold.final.expected, blind.answer)
    grounded = mysql.evidence_matches(Finding(answer=blind.answer, citations=blind.citations, step=0),
                                      proofs["final"], claim=task.private_gold.final)
    actions = recorded_actions(blind_directory)
    payload = Submission(answer=blind.answer, citations=blind.citations).model_dump_json()
    max_steps = len(actions) + 1
    secrl = SecRLV1Env(task, mysql, validation, run_id=f"{task.task_id}-secrl", trajectory_ref=str(output / "secrl.json"),
                      max_steps=max_steps, log_path=output / "secrl.json", admission="private_pilot")
    for action, payload_value in actions:
        if action == "sql":
            secrl.step(payload_value)
        else:
            secrl.record_finding(payload_value)
    secrl.step(payload, submit=True)

    from saber.config.models import TaskConfig
    from saber.scoring.context import ScoringContext
    from saber.scoring.registry import ScoringStrategyRegistry
    from saber.scoring.aggregation import aggregate_scorer_results

    ace = SecRLV1Env(task, mysql, validation, run_id=f"{task.task_id}-ace", trajectory_ref=str(output / "acesevals.json"),
                    max_steps=max_steps, log_path=output / "acesevals.json", backend="acesevals", admission="private_pilot")
    tools = make_aces_tools(ace)
    for action, payload_value in actions:
        if action == "sql":
            asyncio.run(tools[0](query=payload_value))
        else:
            asyncio.run(tools[1](finding=payload_value))
    exported = export_aces_task(task, instruction_template="secrl-v1-instructions.j2", max_steps=max_steps)
    (output / "aces-task.json").write_text(json.dumps(exported, indent=2) + "\n")
    config = TaskConfig.model_validate(exported["tasks"][0])
    registry = ScoringStrategyRegistry()
    register_aces_strategy(registry, {ace.run_id: ace})
    scores = {}
    for scorer in config.scorers:
        context = ScoringContext(submission=payload, tool_steps=(), messages=(), target="", task_id=config.task_id,
                                 domain="excytin", metadata={"secrl_run_id": ace.run_id}, scorer=scorer)
        scores[scorer.scorer_name] = asyncio.run(registry.get(scorer.strategy).score(context, None)).value
    aggregate, _ = aggregate_scorer_results(scorer_configs=config.scorers, raw_scores=scores, agg_config=config.scoring_aggregation)
    if secrl.evaluation is None or ace.evaluation is None:
        raise ValueError("adapter did not produce an evaluation")
    comparisons = ("status", "answer_correctness", "final_evidence", "checkpoints", "grounded_final",
                   "checkpoint_progress", "aggregate_reward")
    if any(getattr(secrl.evaluation, key) != getattr(ace.evaluation, key) for key in comparisons):
        raise ValueError("adapter components differ on the same recorded MySQL trajectory")
    if aggregate != secrl.evaluation.aggregate_reward:
        raise ValueError("adapter aggregate differs on the same recorded MySQL trajectory")
    observed_complete = mysql.complete_witness_observed(task.private_gold.final, proofs["final"], frozenset(secrl._observed))
    result = {
        "status": "private_pilot_completed", "candidate_checks_passed": True, "task_fingerprint": fingerprint(task),
        "serving_view_id": task.serving_view_id, "mysql_blind_answer_correct": correct,
        "mysql_blind_evidence_grounded": grounded, "adapter_components_equal": True,
        "mysql_blind_confidence": blind.confidence,
        "secrl_reward": secrl.evaluation.aggregate_reward, "aces_aggregate_reward": aggregate,
        "student_grounded_success": secrl.evaluation.grounded_final, "complete_witness_observed": observed_complete,
        "explicit_checkpoint_findings_in_blind_trace": any(action == "finding" for action, _ in actions),
        "checkpoint_progress": secrl.evaluation.checkpoint_progress,
        "checkpoint_count": len(task.private_gold.checkpoints),
        "checkpoint_credit_available": bool(task.private_gold.checkpoints),
        "release_approved": False, "remaining_release_blockers": validation.release_blockers(task),
    }
    (output / "evaluation_report.json").write_text(json.dumps(result, indent=2) + "\n")
    return result
