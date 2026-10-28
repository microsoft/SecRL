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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    schema = commands.add_parser("schema", help="Print the JSON Schema for an I0 contract")
    schema.add_argument("kind", choices=(*SCHEMAS, *SPLIT_SCHEMAS))
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
    preflight.add_argument("--task", type=Path, required=True)
    preflight.add_argument("--serving-bundle", type=Path, required=True)
    preflight.add_argument("--limits", type=Path, required=True)
    preflight.add_argument("--allowed-literals", type=Path, required=True)
    preflight.add_argument("--output", type=Path, required=True)
    split_audit = commands.add_parser("audit-question-splits", help="Audit a private question inventory or explicit split plan; shared evidence is allowed")
    split_proposal = commands.add_parser("propose-question-splits", help="Propose question-level assignments from explicit counts and seed, not release them")
    for command in (split_audit, split_proposal):
        command.add_argument("--inputs", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True)
        command.add_argument("--weights", type=Path)
    split_audit.add_argument("--plan", type=Path)
    split_proposal.add_argument("--request", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "schema":
            if args.kind in SPLIT_SCHEMAS:
                from .question_splits import SplitInputs, SplitPlan, SplitRequest

                split_schemas = {"split-inputs": SplitInputs, "split-request": SplitRequest, "split-plan": SplitPlan}
                output = split_schemas[args.kind].model_json_schema()
            else:
                output = SCHEMAS[args.kind].model_json_schema()
        elif args.command in ("validate-contract", "public-task"):
            task = TaskRecord.model_validate_json(args.task.read_bytes())
            output = task.public_task().model_dump(mode="json") if args.command == "public-task" else {
                "contract_valid": True, "task_id": task.task_id, "fingerprint": fingerprint(task),
                "evidence_validated": False, "release_approved": False,
            }
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
        elif args.command == "preflight-task":
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
                    report = verifier.mechanical_report(task)
                finally:
                    verifier.close()
            finally:
                engine.connection.close()
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
