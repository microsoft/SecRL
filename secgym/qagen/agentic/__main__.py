# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""V1 preparation and mechanical validation; no external model calls."""

import argparse
import json
import sys
from pathlib import Path

from .contracts import (
    CaseManifest, EvaluationRecord, HistoricalMembership, PublicTask, ScoreComponent, SimilarityRecord,
    SnapshotManifest, TaskRecord, ValidationReport, fingerprint,
)
from .legacy import baseline_changes, baseline_summary, build_legacy_baseline, load_pinned_baseline


SCHEMAS = {
    "task": TaskRecord, "public-task": PublicTask, "snapshot": SnapshotManifest,
    "case": CaseManifest, "historical-membership": HistoricalMembership,
    "gate-report": ValidationReport, "score-component": ScoreComponent,
    "evaluation": EvaluationRecord, "similarity": SimilarityRecord,
}
SPLIT_SCHEMAS = ("split-inputs", "split-request", "split-plan")
DIFFICULTY_SCHEMAS = ("difficulty-plan", "difficulty-review", "difficulty-inputs", "difficulty-sidecar")
CAPACITY_SCHEMAS = ("capacity-request", "capacity-point")
QUALITY_SCHEMAS = ("source-quality-audit", "source-quality-assessment")
ROBUSTNESS_SCHEMAS = ("robustness-plan", "robustness-report")
GRADING_SCHEMAS = ("grading-amendment", "reviewed-grading-amendment")
PREPRODUCTION_SCHEMAS = ("preproduction-plan", "preproduction-source-outcome")
ADMISSION_SCHEMAS = ("preproduction-admission-files", "preproduction-admission", "preproduction-final-review", "preproduction-objective-review", "preproduction-native-binding")
PRIVATE_BUNDLE_SCHEMAS = ("private-bundle", "private-difficulty-index")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    schema = commands.add_parser("schema", help="Print the JSON Schema for an I0 contract")
    schema.add_argument("kind", choices=(*SCHEMAS, *SPLIT_SCHEMAS, *DIFFICULTY_SCHEMAS, *CAPACITY_SCHEMAS, *QUALITY_SCHEMAS, *ROBUSTNESS_SCHEMAS, *GRADING_SCHEMAS, *PREPRODUCTION_SCHEMAS, *ADMISSION_SCHEMAS, *PRIVATE_BUNDLE_SCHEMAS))
    validate = commands.add_parser("validate-contract", help="Check a private task's structure, not its truth")
    validate.add_argument("task", type=Path)
    public = commands.add_parser("public-task", help="Print an allowlisted public task preview")
    public.add_argument("task", type=Path)
    baseline = commands.add_parser("legacy-baseline", help="Print a newly measured, read-only legacy inventory")
    baseline.add_argument("--repo", type=Path, default=Path.cwd())
    check = commands.add_parser("check-legacy", help="Compare current legacy files with the pinned I0 baseline")
    check.add_argument("--repo", type=Path, default=Path.cwd())
    reconcile = commands.add_parser("reconcile-sources", help="Read-only I1 incident/alert reconciliation and source coverage")
    reconcile.add_argument("--tenant-db", type=Path, required=True)
    reconcile.add_argument("--incident-root", type=Path, required=True)
    reconcile.add_argument("--output", type=Path, required=True)
    telemetry = commands.add_parser("audit-telemetry", help="Inspect telemetry schemas and values before graph-source merging")
    telemetry.add_argument("--source-bundle", type=Path, required=True)
    telemetry.add_argument("--output", type=Path, required=True)
    columns = commands.add_parser("normalize-diagnostic-columns", help="Consolidate approved AzureDiagnostics aliases in new derived data")
    columns.add_argument("--source-bundle", type=Path, required=True)
    columns.add_argument("--output", type=Path, required=True)
    dynamic = commands.add_parser("normalize-dynamic-fields", help="Apply recorded, lossless dynamic-field repairs to derived data")
    dynamic.add_argument("--source-bundle", type=Path, required=True)
    dynamic.add_argument("--output", type=Path, required=True)
    ledger = commands.add_parser("build-observation-ledger", help="Reconcile exact typed telemetry observations with all source origins")
    ledger.add_argument("--source-bundle", type=Path, required=True)
    ledger.add_argument("--dynamic-bundle", type=Path, required=True)
    ledger.add_argument("--output", type=Path, required=True)
    graph = commands.add_parser("build-evidence-graph", help="Build a fresh observation-centered typed graph")
    graph.add_argument("--ledger-bundle", type=Path, required=True)
    graph.add_argument("--output", type=Path, required=True)
    compare = commands.add_parser("compare-evidence-graphs", help="Compare source and legacy identifier coverage, not semantic parity")
    compare.add_argument("--graph-bundle", type=Path, required=True)
    compare.add_argument("--old-graph", type=Path, required=True)
    compare.add_argument("--legacy-graphs", type=Path, required=True)
    compare.add_argument("--output", type=Path, required=True)
    semantics = commands.add_parser("check-graph-semantics", help="Check legacy identifier meaning against current source and graph evidence")
    semantics.add_argument("--graph-bundle", type=Path, required=True)
    semantics.add_argument("--legacy-graphs", type=Path, required=True)
    semantics.add_argument("--output", type=Path, required=True)
    serving = commands.add_parser("export-public-view", help="Apply a fully reviewed, exhaustive public projection policy")
    serving.add_argument("--graph-bundle", type=Path, required=True)
    serving.add_argument("--policy", type=Path, required=True)
    serving.add_argument("--output", type=Path, required=True)
    preflight = commands.add_parser("preflight-task", help="Run mechanical DuckDB answer/witness checks, not release approval")
    quality = commands.add_parser("audit-source-quality", help="Diagnose collection proofs and JSON selectors; no model calls or changed admissions")
    robustness = commands.add_parser("check-robustness", help="Run explicit counterfactuals in owned DuckDB/MySQL fixtures; not semantic approval")
    for command in (preflight, quality, robustness):
        command.add_argument("--task", type=Path, required=True)
        command.add_argument("--serving-bundle", type=Path, required=True)
        command.add_argument("--limits", type=Path, required=True)
        command.add_argument("--allowed-literals", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True)
    robustness.add_argument("--plan", type=Path, required=True)
    robustness.add_argument("--mysqld", type=Path, required=True)
    robustness.add_argument("--scratch", type=Path, required=True)
    split_audit = commands.add_parser("audit-question-splits", help="Audit a private question inventory or explicit split plan; shared evidence is allowed")
    split_proposal = commands.add_parser("propose-question-splits", help="Propose question-level assignments from explicit counts and seed, not release them")
    for command in (split_audit, split_proposal):
        command.add_argument("--inputs", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True)
        command.add_argument("--weights", type=Path)
    split_audit.add_argument("--plan", type=Path)
    split_proposal.add_argument("--request", type=Path, required=True)
    difficulty = commands.add_parser("difficulty-profile", help="Describe admitted questions or measure reviewed provisional difficulty; no model evaluations")
    difficulty.add_argument("--inputs", type=Path, required=True)
    difficulty.add_argument("--output", type=Path, required=True)
    difficulty.add_argument("--plans", type=Path)
    difficulty.add_argument("--serving-bundle", type=Path)
    difficulty.add_argument("--limits", type=Path)
    capacity = commands.add_parser("capacity-curves", help="Report observed-pool overlap capacity bounds, not admission caps or source exhaustion")
    capacity.add_argument("--inputs", type=Path, required=True)
    capacity.add_argument("--request", type=Path, required=True)
    capacity.add_argument("--output", type=Path, required=True)
    panel_analysis = commands.add_parser("analyze-model-panel", help="Analyze frozen paired model outcomes; never tune difficulty or rerun models")
    panel_analysis.add_argument("--panel", type=Path, required=True)
    panel_analysis.add_argument("--output", type=Path, required=True)
    panel_analysis.add_argument("--bootstrap-samples", type=int, default=2000)
    panel_analysis.add_argument("--seed", type=int, default=42)
    panel_analysis.add_argument("--manifest", default="manifest.json")
    preprod_progress = commands.add_parser("preproduction-progress", help="Verify private source-wave accounting; source readiness is not admission")
    preprod_progress.add_argument("--run", type=Path, required=True)
    checkpoint_progress = commands.add_parser("checkpoint-progress", help="Inspect generated drafts, checkpoint reviews and retained repair queues")
    checkpoint_progress.add_argument("--run", type=Path, required=True)
    checkpoint_progress.add_argument("--batch-id", required=True)
    service_register = commands.add_parser("register-sql-service", help="Use a verified persistent SQL service for this run's future validation")
    service_register.add_argument("--run", type=Path, required=True)
    service_register.add_argument("--service-directory", type=Path, required=True)
    service_status = commands.add_parser("sql-service-status", help="Check the run's registered readonly SQL service")
    service_status.add_argument("--run", type=Path, required=True)
    checkpoint_generate = commands.add_parser("generate-checkpoint", help="Generate Astra drafts concurrently; semantic reviews wait for the checkpoint")
    for name in ("run", "serving-bundle", "graph-bundle", "env-file"):
        checkpoint_generate.add_argument("--" + name, type=Path, required=True)
    checkpoint_generate.add_argument("--batch-id", required=True)
    checkpoint_generate.add_argument("--checkpoint-size", type=int, default=100)
    checkpoint_generate.add_argument("--workers", type=int, default=4)
    checkpoint_generate.add_argument("--max-new-attempts", type=int)
    checkpoint_generate.add_argument("--review-at-checkpoint", action="store_true")
    checkpoint_generate.add_argument("--mysql-bundle", type=Path)
    checkpoint_generate.add_argument("--workdir", type=Path)
    for name in ("review-checkpoint", "repair-checkpoint"):
        command = commands.add_parser(name, help="Review a completed candidate checkpoint or repair its selected pre-blind holds")
        for argument in ("run", "serving-bundle", "graph-bundle", "mysql-bundle", "env-file", "workdir"):
            command.add_argument("--" + argument, type=Path, required=True)
        command.add_argument("--batch-id", required=True)
        if name == "repair-checkpoint":
            command.add_argument("--task-ids", nargs="+", required=True)
    preprod_admit = commands.add_parser("admit-preproduction", help="Verify every private gate and record one new-question admission; no generation or release")
    preprod_admit.add_argument("--run", type=Path, required=True)
    preprod_admit.add_argument("--files", type=Path, required=True)
    preprod_finish = commands.add_parser(
        "finish-preproduction", help="Run guarded private candidate stages with model calls and owned MySQL; no release",
    )
    preprod_finish.add_argument("--task-id", required=True)
    for name in ("run", "serving-bundle", "graph-bundle", "mysql-bundle", "env-file", "workdir", "output"):
        preprod_finish.add_argument("--" + name, type=Path, required=True)
    preprod_finish.add_argument("--grading-policy-directory", type=Path)
    preprod_finish.add_argument("--parent-pipeline", type=Path)
    preprod_finish.add_argument("--parent-runtime-archive", type=Path)
    preprod_finish.add_argument("--prepared-robustness-plan", type=Path)
    preprod_finish.add_argument("--robustness-feedback", type=Path)
    preprod_finish.add_argument("--canonical-feedback", type=Path)
    preprod_finish.add_argument("--difficulty-feedback", type=Path,
                                help="Authorize a feature-only continuation using the held source-only difficulty review.")
    preprod_finish.add_argument("--recover-contaminated-robustness-review", action="store_true",
                                help="Recover one proven author-history-contaminated review; preserve its exact plan.")
    preprod_finish.add_argument("--qualified-support-review-recovery", type=Path,
                                help="Use an evidence-bound approval to re-review an unchanged qualified-support plan.")
    preprod_finish.add_argument("--admitted-contract-revision", type=Path,
                                help="Use an explicit goal-equivalent contract authorization and retain the original admission/student.")
    preprod_finish.add_argument("--retained-native-pipeline", type=Path)
    preprod_finish.add_argument("--retained-native-task", type=Path)
    preprod_finish.add_argument("--retained-native-runtime-archive", type=Path)
    preprod_finish.add_argument("--fresh-validation", action="store_true",
                                help="Revalidate an unchanged admitted question using its retained native student.")
    preprod_finish.add_argument("--robustness-control-repairs", type=Path,
                                help="JSON mapping of exact prior control IDs to source-backed repair reasons.")
    preprod_finish.add_argument("--resume", action="store_true")
    private_export = commands.add_parser("export-private-bundle", help="Copy approved/admitted private QA with portable paths; no training or release")
    for name in ("development", "difficulty-index", "output"):
        private_export.add_argument("--" + name, type=Path, required=True)
    private_export.add_argument("--preproduction-run", type=Path)
    private_check = commands.add_parser("check-private-bundle", help="Verify a relocated private packet without original host paths or model calls")
    private_check.add_argument("--bundle", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "register-sql-service":
            from .shared_validation import register_snapshot_service

            output = register_snapshot_service(args.run, args.service_directory)
        elif args.command == "sql-service-status":
            from .shared_validation import registered_snapshot_pool

            pool = registered_snapshot_pool(args.run)
            if pool is None:
                raise ValueError("this run has no registered SQL service")
            output = pool.status()
        elif args.command in ("checkpoint-progress", "generate-checkpoint", "review-checkpoint", "repair-checkpoint"):
            from .checkpoint_batches import checkpoint_progress, create_batch, generate_checkpoint
            from .shared_validation import repair_registered_checkpoint as repair_checkpoint
            from .shared_validation import review_registered_checkpoint as review_checkpoint

            if args.command == "checkpoint-progress":
                output = checkpoint_progress(args.run, args.batch_id)
            elif args.command == "generate-checkpoint":
                if args.review_at_checkpoint and (args.mysql_bundle is None or args.workdir is None):
                    raise ValueError("checkpoint review requires --mysql-bundle and --workdir")
                create_batch(args.run, args.batch_id, checkpoint_size=args.checkpoint_size, workers=args.workers)
                output = generate_checkpoint(
                    run=args.run, batch_id=args.batch_id, serving=args.serving_bundle, graph=args.graph_bundle,
                    env_file=args.env_file, max_new_attempts=args.max_new_attempts,
                )
                if args.review_at_checkpoint:
                    if not output["ready_for_checkpoint"]:
                        raise ValueError("generation stopped below the requested checkpoint; inspect checkpoint-progress and its repair queue")
                    output = review_checkpoint(
                        run=args.run, batch_id=args.batch_id, serving=args.serving_bundle, graph=args.graph_bundle,
                        mysql_bundle=args.mysql_bundle, env_file=args.env_file, workdir=args.workdir,
                    )
            else:
                kwargs = dict(run=args.run, batch_id=args.batch_id, serving=args.serving_bundle, graph=args.graph_bundle,
                              mysql_bundle=args.mysql_bundle, env_file=args.env_file, workdir=args.workdir)
                output = (repair_checkpoint(**kwargs, task_ids=tuple(args.task_ids)) if args.command == "repair-checkpoint"
                          else review_checkpoint(**kwargs))
        elif args.command == "export-private-bundle":
            from .private_bundle import export_private_bundle

            bundle = export_private_bundle(development=args.development, difficulty_index=args.difficulty_index,
                                           preproduction_run=args.preproduction_run, output=args.output)
            output = {"status": "private_bundle_verified", "questions": len(bundle.questions),
                      "cohort_fingerprint": bundle.cohort_fingerprint, "release_approved": False, "training_approved": False}
        elif args.command == "check-private-bundle":
            from .private_bundle import load_private_bundle

            bundle, questions = load_private_bundle(args.bundle)
            output = {"status": "private_bundle_verified", "questions": len(questions),
                      "cohort_fingerprint": bundle.cohort_fingerprint, "release_approved": False, "training_approved": False}
        elif args.command == "schema":
            if args.kind in PRIVATE_BUNDLE_SCHEMAS:
                from .private_bundle import DifficultyIndex, PrivateBundle

                output = {"private-bundle": PrivateBundle, "private-difficulty-index": DifficultyIndex}[args.kind].model_json_schema()
            elif args.kind in ADMISSION_SCHEMAS:
                from .preproduction_admission import AdmissionFiles, AdmissionReceipt, FinalReview, NativeBinding, ObjectiveReview

                output = {
                    "preproduction-admission-files": AdmissionFiles, "preproduction-admission": AdmissionReceipt,
                    "preproduction-final-review": FinalReview, "preproduction-objective-review": ObjectiveReview,
                    "preproduction-native-binding": NativeBinding,
                }[args.kind].model_json_schema()
            elif args.kind in PREPRODUCTION_SCHEMAS:
                from .preproduction import PreproductionPlan, SourceOutcome

                output = {"preproduction-plan": PreproductionPlan, "preproduction-source-outcome": SourceOutcome}[args.kind].model_json_schema()
            elif args.kind in GRADING_SCHEMAS:
                from .grading_review import GradingAmendment, ReviewedGradingAmendment

                output = {"grading-amendment": GradingAmendment, "reviewed-grading-amendment": ReviewedGradingAmendment}[args.kind].model_json_schema()
            elif args.kind in ROBUSTNESS_SCHEMAS:
                from .robustness import RobustnessPlan, RobustnessReport

                output = {"robustness-plan": RobustnessPlan, "robustness-report": RobustnessReport}[args.kind].model_json_schema()
            elif args.kind in QUALITY_SCHEMAS:
                from .quality import QualityAssessment, QualityAudit

                output = {"source-quality-audit": QualityAudit, "source-quality-assessment": QualityAssessment}[args.kind].model_json_schema()
            elif args.kind in CAPACITY_SCHEMAS:
                from .capacity import CapacityPoint, CapacityRequest

                output = {"capacity-request": CapacityRequest, "capacity-point": CapacityPoint}[args.kind].model_json_schema()
            elif args.kind in DIFFICULTY_SCHEMAS:
                from .difficulty import DifficultyInputs, DifficultyPlan, DifficultyReview, DifficultySidecar

                difficulty_schemas = {
                    "difficulty-plan": DifficultyPlan, "difficulty-review": DifficultyReview,
                    "difficulty-inputs": DifficultyInputs, "difficulty-sidecar": DifficultySidecar,
                }
                output = difficulty_schemas[args.kind].model_json_schema()
            elif args.kind in SPLIT_SCHEMAS:
                from .question_splits import SplitInputs, SplitPlan, SplitRequest

                split_schemas = {"split-inputs": SplitInputs, "split-request": SplitRequest, "split-plan": SplitPlan}
                output = split_schemas[args.kind].model_json_schema()
            else:
                output = SCHEMAS[args.kind].model_json_schema()
        elif args.command == "finish-preproduction":
            from functools import partial
            from .preproduction_pipeline import run_owned_candidate_pipeline
            from .shared_validation import registered_snapshot_pool, run_shared_pipeline

            pool = registered_snapshot_pool(args.run)
            runner = run_owned_candidate_pipeline if pool is None else partial(run_shared_pipeline, pool=pool)
            output = runner(
                run=args.run, task_id=args.task_id, serving_bundle=args.serving_bundle,
                graph_bundle=args.graph_bundle, mysql_bundle=args.mysql_bundle, env_file=args.env_file,
                workdir=args.workdir, output=args.output, resume=args.resume,
                grading_policy_directory=args.grading_policy_directory,
                parent_pipeline=args.parent_pipeline, parent_runtime_archive=args.parent_runtime_archive,
                prepared_robustness_plan=args.prepared_robustness_plan,
                robustness_feedback=args.robustness_feedback.read_text() if args.robustness_feedback is not None else None,
                canonical_feedback=args.canonical_feedback.read_text() if args.canonical_feedback is not None else None,
                difficulty_feedback=args.difficulty_feedback.read_text() if args.difficulty_feedback is not None else None,
                robustness_review_recovery=args.recover_contaminated_robustness_review,
                qualified_support_review_recovery=args.qualified_support_review_recovery,
                admitted_contract_revision=args.admitted_contract_revision,
                retained_native_pipeline=args.retained_native_pipeline, retained_native_task=args.retained_native_task,
                retained_native_runtime_archive=args.retained_native_runtime_archive,
                fresh_validation=args.fresh_validation,
                robustness_control_repairs=(json.loads(args.robustness_control_repairs.read_bytes())
                                            if args.robustness_control_repairs is not None else None),
            )
        elif args.command == "admit-preproduction":
            from .preproduction import PreproductionPlan
            from .preproduction_admission import AdmissionFiles, record_admission

            plan = PreproductionPlan.model_validate_json((args.run / "plan.json").read_bytes())
            files = AdmissionFiles.model_validate_json(args.files.read_bytes())
            resolved = {key: str((args.files.parent / value).resolve()) if value is not None else None
                        for key, value in files.model_dump(mode="json").items()}
            receipt = record_admission(plan, args.run, AdmissionFiles.model_validate_json(json.dumps(resolved)))
            output = {"task_id": receipt.task.task_id, "bucket": receipt.bucket,
                      "admitted": True, "release_approved": False}
        elif args.command == "preproduction-progress":
            from .preproduction import PreproductionPlan
            from .preproduction_admission import admission_progress

            plan = PreproductionPlan.model_validate_json((args.run / "plan.json").read_bytes())
            output = admission_progress(plan, args.run)
        elif args.command == "analyze-model-panel":
            from .panel_analysis import analyze_panel

            report = analyze_panel(args.panel, args.output, samples=args.bootstrap_samples, seed=args.seed,
                                   manifest_name=args.manifest)
            output = {"status": report["status"], "models": report["models"], "paired": report["paired"],
                      "output": str(args.output), "heuristic_changed": False}
        elif args.command == "capacity-curves":
            from .capacity import CapacityRequest, report_capacity
            from .question_splits import load_questions

            request = CapacityRequest.model_validate_json(args.request.read_bytes())
            report = report_capacity(load_questions(args.inputs), args.output, request)
            print(json.dumps({key: report[key] for key in (
                "policy_version", "question_count", "within_scope_pairs", "measurements_complete",
                "all_observed_pool_optima_proven", "absolute_source_capacity_established",
            )}, indent=2))
            if not report["measurements_complete"]:
                raise SystemExit(1)
            return
        elif args.command in ("validate-contract", "public-task"):
            task = TaskRecord.model_validate_json(args.task.read_bytes())
            output = task.public_task().model_dump(mode="json") if args.command == "public-task" else {
                "contract_valid": True, "task_id": task.task_id, "fingerprint": fingerprint(task),
                "evidence_validated": False, "release_approved": False,
            }
        elif args.command == "difficulty-profile":
            from .difficulty import profile_questions
            from .query import QueryLimits
            from .question_splits import load_questions

            loaded = load_questions(args.inputs)
            limits = QueryLimits.model_validate_json(args.limits.read_bytes()) if args.limits else None
            report = profile_questions(
                loaded, args.output, plans_path=args.plans,
                serving_bundle=args.serving_bundle, limits=limits,
            )
            print(json.dumps({key: value for key, value in report.items() if key != "source_artifacts_sha256"}, indent=2))
            if not report["requested_measurements_complete"]:
                raise SystemExit(1)
            return
        elif args.command in ("audit-question-splits", "propose-question-splits"):
            from .contracts import SimilarityWeights
            from .question_splits import (
                SplitPlan, SplitRequest, audit_splits, load_questions, propose_split, write_split_audit,
            )

            loaded = load_questions(args.inputs)
            weights = SimilarityWeights.model_validate_json(args.weights.read_bytes()) if args.weights else None
            if args.command == "propose-question-splits":
                plan = propose_split(loaded.questions, SplitRequest.model_validate_json(args.request.read_bytes()))
            else:
                plan = SplitPlan.model_validate_json(args.plan.read_bytes()) if args.plan else None
            report = audit_splits(loaded.questions, cohort_label=loaded.inputs.cohort_label, plan=plan, weights=weights)
            write_split_audit(report, args.output, loaded)
            print(json.dumps({
                "status": "proposal_audited" if plan is not None else "inventory_audited",
                "cohort_fingerprint": report.cohort_fingerprint, "questions": len(report.questions),
                "pairs": len(report.pairs), "counts": report.counts,
                "components_complete": report.components_complete, "aggregate_weights_supplied": weights is not None,
                "shared_evidence_grouping": False, "semantic_duplicate_review": "not_performed",
                "split_review_approved": False, "release_approved": False, "output": str(args.output),
            }, indent=2))
            if not report.components_complete:
                raise SystemExit(1)
            return
        elif args.command == "export-public-view":
            from .serving import ServingPolicy, export_public_view

            report = export_public_view(args.graph_bundle, ServingPolicy.model_validate_json(args.policy.read_bytes()), args.output)
            output = {"status": report["status"], "serving_view_id": report["serving_view_id"],
                      "release_approved": False, "output": str(args.output)}
        elif args.command in ("preflight-task", "audit-source-quality", "check-robustness"):
            from .evidence import EvidenceVerifier
            from .mysql_serving import open_duckdb_engine
            from .query import QueryLimits

            if args.output.exists() or args.output.resolve().is_relative_to(args.serving_bundle.resolve()):
                raise ValueError("preflight output must be new and outside the serving bundle")
            literals = json.loads(args.allowed_literals.read_text())
            if not isinstance(literals, list) or any(not isinstance(value, str) for value in literals):
                raise ValueError("allowed-literals must be an explicitly reviewed JSON array of strings")
            task = TaskRecord.model_validate_json(args.task.read_bytes())
            limits = QueryLimits.model_validate_json(args.limits.read_bytes())
            engine = open_duckdb_engine(args.serving_bundle, limits)
            try:
                verifier = EvidenceVerifier(args.serving_bundle, engine, frozenset(literals))
                try:
                    if args.command == "check-robustness":
                        from .robustness import RobustnessPlan, run_robustness

                        robustness_report = run_robustness(
                            task, verifier, RobustnessPlan.model_validate_json(args.plan.read_bytes()),
                            mysqld=args.mysqld, workdir=args.scratch, output=args.output,
                        )
                    elif args.command == "audit-source-quality":
                        from .quality import audit_source_quality

                        audit = audit_source_quality(task, verifier, args.serving_bundle)
                    else:
                        report = verifier.mechanical_report(task)
                finally:
                    verifier.close()
            finally:
                engine.connection.close()
            if args.command == "check-robustness":
                print(json.dumps({
                    "output": str(args.output), "status": robustness_report.status,
                    "checks": len(robustness_report.checks), "admission_changed": False,
                    "semantic_plan_review_performed": False,
                }, indent=2))
                if robustness_report.status != "pass":
                    raise SystemExit(1)
                return
            if args.command == "audit-source-quality":
                args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with args.output.open("x") as stream:
                    stream.write(audit.model_dump_json(indent=2) + "\n")
                print(json.dumps({
                    "output": str(args.output), "selector_issues": len(audit.issues),
                    "collection_checks": len(audit.collections), "collection_failures": len(audit.collection_failures()),
                    "independent_review_required": True, "release_approved": False,
                }, indent=2))
                if audit.collection_failures():
                    raise SystemExit(1)
                return
            output = {
                "validation_report": report.model_dump(mode="json"), "release_approved": False,
                "release_blockers": report.release_blockers(task),
                "query_policy": {"allowed_literals": literals, "limits": limits.model_dump(mode="json")},
            }
            args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            args.output.write_text(json.dumps(output, indent=2) + "\n")
            print(json.dumps({"output": str(args.output), "release_approved": False,
                              "gates": [g.model_dump(mode="json") for g in report.gates]}, indent=2))
            if any(g.status != "pass" for g in report.gates):
                raise SystemExit(1)
            return
        elif args.command == "check-graph-semantics":
            from .graph_semantics import check_graph_semantics

            report = check_graph_semantics(args.graph_bundle, args.legacy_graphs, args.output)
            output = {"status": report["status"], "summary": report["summary"], "output": str(args.output)}
            print(json.dumps(output, indent=2))
            if report["status"] == "needs_review":
                raise SystemExit(1)
            return
        elif args.command == "compare-evidence-graphs":
            from .graph_compare import compare_graphs

            report = compare_graphs(args.graph_bundle, args.old_graph, args.legacy_graphs, args.output)
            output = {"status": report["status"], "summary": report["summary"], "output": str(args.output)}
        elif args.command == "build-evidence-graph":
            from .graph import build_graph

            report = build_graph(args.ledger_bundle, args.output)
            output = {"status": report["status"], "graph_id": report["graph_id"],
                      "summary": report["summary"], "output": str(args.output)}
        elif args.command == "build-observation-ledger":
            from .ledger import build_ledger

            report = build_ledger(args.source_bundle, args.dynamic_bundle, args.output)
            output = {
                "status": report["status"], "ledger_id": report["ledger_id"],
                "summary": report["summary"], "output": str(args.output),
            }
            print(json.dumps(output, indent=2))
            if report["status"] != "complete":
                raise SystemExit(1)
            return
        elif args.command == "normalize-dynamic-fields":
            from .dynamic import normalize_dynamic_fields

            report = normalize_dynamic_fields(args.source_bundle, args.output)
            output = {
                "status": report["status"], "normalization_id": report["normalization_id"],
                "summary": report["summary"], "output": str(args.output),
            }
            print(json.dumps(output, indent=2))
            if report["status"] != "complete":
                raise SystemExit(1)
            return
        elif args.command == "normalize-diagnostic-columns":
            from .telemetry import normalize_diagnostics

            report = normalize_diagnostics(args.source_bundle, args.output)
            output = {
                key: report[key] for key in (
                    "status", "normalization_id", "column_policy_version", "source_stream_count",
                    "imported_rows", "csv_rows", "inputs_unchanged", "populated_value_mismatches",
                )
            }
            output["output"] = str(args.output)
        elif args.command == "audit-telemetry":
            from .telemetry import audit_telemetry

            report = audit_telemetry(args.source_bundle, args.output)
            output = {"status": report["status"], "summary": report["summary"], "output": str(args.output)}
            print(json.dumps(output, indent=2))
            if report["status"] != "scanned":
                raise SystemExit(1)
            return
        elif args.command == "reconcile-sources":
            from .sources import reconcile_sources

            report = reconcile_sources(args.tenant_db, args.incident_root, args.output)
            output = {"status": report["status"], "summary": report["summary"], "output": str(args.output)}
            if report["status"] == "complete_with_blocks":
                print(json.dumps(output, indent=2))
                raise SystemExit(1)
        else:
            actual = build_legacy_baseline(args.repo)
            if args.command == "legacy-baseline":
                output = actual.model_dump(mode="json")
            else:
                changes = baseline_changes(load_pinned_baseline(), actual)
                output = {**baseline_summary(actual), "unchanged": not changes, "changes": changes}
                if changes:
                    print(json.dumps(output, indent=2), file=sys.stderr)
                    raise SystemExit(1)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(output, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
