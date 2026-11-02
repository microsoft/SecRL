# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agentic_runtime_fixture import qualified_runtime_draft, runtime_fixture, runtime_task
from test_agentic_generation import FakeClient, call
from secgym.qagen.agentic.__main__ import main
from secgym.qagen.agentic.contracts import TaskRecord, fingerprint
from secgym.qagen.agentic.evidence import EvidenceVerifier
from secgym.qagen.agentic.generation import ReviewResult, TaskDraft, compile_draft
from secgym.qagen.agentic.ledger import file_sha256
from secgym.qagen.agentic.mysql_serving import open_duckdb_engine
from secgym.qagen.agentic.pilot import run_discovery_pilot
from secgym.qagen.agentic.pilot_evaluation import private_pilot_validation
from secgym.qagen.agentic.quality import (
    QualityAssessment, QualityAudit, SelectorIssue, assessment_passes, audit_source_quality,
    run_quality_gate, scan_selectors, validate_quality_gate,
)
from secgym.qagen.agentic.query import PublicQueryEngine, QueryFailure, QueryLimits, QueryResult


def passing_review():
    return ReviewResult(
        recommendation="pass", scope_supported=True, evidence_independent=True, causal_claims_supported=True,
        wording_leakage_free=True, literal_justifications_supported=True, answer_unambiguous=True,
        checkpoints_distinct_and_supported=True, reasons=("Synthetic independent review.",), counterevidence=(),
    )


def assessment(audit, review=None, dispositions=()):
    return QualityAssessment(
        task_fingerprint=audit.task_fingerprint, audit_fingerprint=fingerprint(audit),
        review=review or passing_review(), whole_claim_proofs_supported=True,
        json_semantics_supported=True, dispositions=dispositions,
    )


class SelectorTests(unittest.TestCase):
    def test_numeric_paths_are_screened_in_both_backends_and_json_table_columns(self):
        cases = [
            ("duckdb", "SELECT json_extract_string(Entities,'$[0].Name') FROM t"),
            ("mysql", "SELECT JSON_UNQUOTE(JSON_EXTRACT(Parameters,'$[2].Value')) FROM t"),
            ("duckdb", "SELECT json_extract_string(raw,'$.a[-1]') FROM t"),
            ("mysql", "SELECT j.x FROM t JOIN JSON_TABLE(t.raw,'$[*]' COLUMNS(x VARCHAR(100) PATH '$[1].Name')) j"),
        ]
        for engine, query in cases:
            with self.subTest(engine=engine, query=query):
                self.assertIn("positional_json_path", {kind for kind, _ in scan_selectors(query, engine, frozenset())})

    def test_wildcards_named_keys_and_path_like_data_literals_are_not_numeric_selectors(self):
        for query in (
            "SELECT JSON_EXTRACT(raw,'$.Name') FROM t",
            """SELECT JSON_EXTRACT(raw,'$."member[0]"') FROM t""",
            "SELECT '$[0]' FROM t",
            """SELECT j.x FROM t JOIN JSON_TABLE(t.raw,'$[*]' COLUMNS(x VARCHAR(100) PATH '$."member[0]"')) j""",
        ):
            with self.subTest(query=query):
                self.assertFalse(scan_selectors(query, "mysql", frozenset()))

    def test_computed_paths_and_serialized_comparisons_are_not_silently_clear(self):
        cases = (
            ("computed_json_path", "SELECT JSON_EXTRACT(raw,CONCAT('$[',j.i,'].Value')) FROM t"),
            ("raw_json_comparison", "SELECT a._record_id FROM t a JOIN t b ON a.Parameters=b.Parameters"),
            ("raw_json_text", """SELECT SUBSTRING(ConditionalAccessPolicies,STR_POSITION(ConditionalAccessPolicies,'"result":"')) FROM t"""),
            ("raw_json_text", "SELECT _record_id FROM t WHERE Parameters LIKE '%ForwardTo%'"),
            ("raw_json_comparison", "WITH a AS (SELECT Parameters AS p FROM t),b AS (SELECT p AS q FROM a) SELECT q FROM b WHERE q='[]'"),
        )
        columns = frozenset({"Parameters", "ConditionalAccessPolicies"})
        for kind, query in cases:
            with self.subTest(kind=kind, query=query):
                self.assertIn(kind, {k for k, _ in scan_selectors(query, "mysql", columns)})
        self.assertFalse(scan_selectors("SELECT _record_id FROM t WHERE JSON_EXTRACT(Parameters,'$.Name')='x'",
                                        "mysql", columns))


class QualityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.graph, _, self.serving, self.report = runtime_fixture(self.root / "fixture", extra_rows=1)
        self.anchor = runtime_task(self.serving, self.report)
        self.draft = qualified_runtime_draft(self.serving, self.report)
        self.engine = open_duckdb_engine(self.serving, QueryLimits(max_rows=100, max_bytes=65536, timeout_ms=3000))
        self.addCleanup(self.engine.connection.close)
        self.verifier = EvidenceVerifier(self.serving, self.engine, frozenset({"43"}))
        self.addCleanup(self.verifier.close)

    def compile(self, draft=None, task_id="quality-task", lineage_group=None):
        return compile_draft(draft or self.draft, self.verifier, mode="tenant", incident_id=None,
                             task_id=task_id, revision_id="r1", checkpoint_cap=0.5, lineage_group=lineage_group)

    def broken_draft(self, *, checkpoint=False):
        data = self.draft.model_dump(mode="json")
        claim = data["final"]
        claim["witness_programs"] = [
            {"program_id": f"partial-{engine}", "engine": engine,
             "query": "SELECT DeviceName AS evidence_group,'DeviceProcessEvents' AS table_name,"
                      "MIN(_record_id) AS record_id FROM DeviceProcessEvents WHERE ProcessId=43 GROUP BY DeviceName"}
            for engine in ("duckdb", "mysql")
        ]
        if checkpoint:
            data["final"], data["checkpoints"][0]["claim"] = data["checkpoints"][0]["claim"], data["final"]
        return TaskDraft.model_validate_json(json.dumps(data))

    def test_complete_qualified_collection_is_reproduced_and_sources_remain_unchanged(self):
        task = self.compile()
        before = file_sha256(self.serving / self.report["public_database"]["path"])
        audit = audit_source_quality(task, self.verifier, self.serving)
        self.assertEqual(len(audit.collections), 2)
        self.assertFalse(audit.collection_failures())
        self.assertEqual(audit.programs_checked, 16)
        self.assertEqual({check.claim_id for check in audit.collections}, {"final"})
        self.assertIn("not a general proof", audit.limitations)
        self.assertFalse(audit.native_executed)
        self.assertEqual(file_sha256(self.serving / self.report["public_database"]["path"]), before)
        self.assertEqual(QualityAudit.model_validate_json(audit.model_dump_json()), audit)
        self.assertTrue(assessment_passes(task, audit, assessment(audit)))

    def test_partial_final_and_checkpoint_groups_cannot_borrow_private_anchors(self):
        for checkpoint in (False, True):
            with self.subTest(checkpoint=checkpoint):
                task = self.compile(self.broken_draft(checkpoint=checkpoint))
                data = task.model_dump(mode="json")
                data["scope"]["anchor_evidence_ids"] = [ref.evidence_id for ref in task.evidence]
                task = TaskRecord.model_validate_json(json.dumps(data))
                audit = audit_source_quality(task, self.verifier, self.serving)
                self.assertEqual(len(audit.collection_failures()), 2)
                self.assertTrue(next(c for c in audit.collections if c.fixture == "declared_evidence_union").reproduces_collection)
                self.assertTrue(all(c.fixture == "alternative_alone" for c in audit.collection_failures()))
                self.assertTrue(all(len(c.actual.value) == 1 for c in audit.collection_failures()))
                self.assertFalse(assessment_passes(task, audit, assessment(audit)))

    def test_ordered_collections_use_the_actual_ordered_answer_contract(self):
        data = self.draft.model_dump(mode="json")
        data["final"]["expected"]["format"]["kind"] = "ordered_list"
        for program in data["final"]["programs"]:
            program["query"] += " ORDER BY DeviceName"
        task = self.compile(TaskDraft.model_validate_json(json.dumps(data)))
        audit = audit_source_quality(task, self.verifier, self.serving)
        self.assertFalse(audit.collection_failures())
        self.assertEqual(audit.collections[0].actual.value, ("bulk.test", "other.test"))

    def test_set_row_order_does_not_change_the_audit_fingerprint(self):
        task = self.compile()
        original = audit_source_quality(task, self.verifier, self.serving)
        execute = PublicQueryEngine.execute

        def reverse_rows(engine, *args, **kwargs):
            result = execute(engine, *args, **kwargs)
            return QueryResult(result.columns, tuple(reversed(result.rows)))

        with patch.object(PublicQueryEngine, "execute", reverse_rows):
            reordered = audit_source_quality(task, self.verifier, self.serving)
        self.assertEqual(fingerprint(original), fingerprint(reordered))

    def test_every_query_surface_is_screened_including_qualified_catalog_and_candidates(self):
        data = self.compile().model_dump(mode="json")
        for claim in (data["private_gold"]["final"], data["private_gold"]["checkpoints"][0]["claim"]):
            for program in claim["programs"] + claim["witness_programs"]:
                for field in ("query", "obligations_query", "candidates_query"):
                    if field in program:
                        program[field] = "SELECT JSON_EXTRACT(AdditionalFields,'$[0]') FROM DeviceProcessEvents"
        task = TaskRecord.model_validate_json(json.dumps(data))
        with patch.object(self.verifier, "preflight", return_value={"final": (), "common-executable": ()}):
            with patch("secgym.qagen.agentic.quality.answer_from_rows", return_value=task.private_gold.final.expected):
                with patch("secgym.qagen.agentic.quality.PublicQueryEngine.execute", return_value=QueryResult(("answer",), ())):
                    audit = audit_source_quality(task, self.verifier, self.serving)
        self.assertEqual(len(audit.issues), 16)
        self.assertEqual({issue.surface for issue in audit.issues}, {"answer", "witness", "obligations", "candidates"})
        self.assertEqual({issue.engine for issue in audit.issues}, {"duckdb", "mysql"})
        self.assertEqual({issue.claim_id for issue in audit.issues}, {"final", "common-executable"})

    def test_query_errors_remain_errors_not_empty_or_successful_proofs(self):
        task = self.compile()
        proofs = self.verifier.preflight(task)
        with patch.object(self.verifier, "preflight", return_value=proofs):
            with patch("secgym.qagen.agentic.quality.PublicQueryEngine.execute",
                       side_effect=QueryFailure("sql_timeout", "fixture timeout")):
                with self.assertRaisesRegex(QueryFailure, "fixture timeout"):
                    audit_source_quality(task, self.verifier, self.serving)

    def test_fixture_bundle_must_match_the_source_verifier_before_queries(self):
        task = self.compile()
        _, _, other, _ = runtime_fixture(self.root / "other-source")
        with patch.object(self.verifier, "preflight", wraps=self.verifier.preflight) as preflight:
            with self.assertRaisesRegex(ValueError, "fixture bundle"):
                audit_source_quality(task, self.verifier, other)
            preflight.assert_not_called()

    def test_ordered_selector_disposition_requires_public_scope_and_exact_issue_coverage(self):
        from secgym.qagen.agentic.quality import SelectorDisposition

        task = self.compile()
        audit = audit_source_quality(task, self.verifier, self.serving)
        issue = SelectorIssue(claim_id="final", program_id="fixture", engine="duckdb", surface="answer",
                              query_sha256="a" * 64, kind="positional_json_path", expression="'$[0]'")
        audit = audit.model_copy(update={"issues": (issue,)})
        with self.assertRaisesRegex(ValueError, "every selector issue"):
            assessment_passes(task, audit, assessment(audit))
        disposition = SelectorDisposition(issue_fingerprint=fingerprint(issue), decision="public_order",
                                          public_quote="first ordered step", source_justification="Synthetic order contract.")
        with self.assertRaisesRegex(ValueError, "exact public quote"):
            assessment_passes(task, audit, assessment(audit, dispositions=(disposition,)))
        altered = task.model_dump(mode="json")
        altered["context"] += " Resolve the first ordered step."
        ordered = TaskRecord.model_validate_json(json.dumps(altered))
        ordered_audit = audit.model_copy(update={"task_fingerprint": fingerprint(ordered)})
        self.assertTrue(assessment_passes(ordered, ordered_audit, assessment(ordered_audit, dispositions=(disposition,))))
        with self.assertRaisesRegex(ValueError, "duplicate selector"):
            assessment_passes(ordered, ordered_audit, assessment(ordered_audit, dispositions=(disposition, disposition)))
        with self.assertRaisesRegex(ValueError, "different task/audit"):
            assessment_passes(task, ordered_audit, assessment(ordered_audit, dispositions=(disposition,)))
        wrong_kind = disposition.model_copy(update={"decision": "scalar_membership", "public_quote": None})
        with self.assertRaisesRegex(ValueError, "kind of risk"):
            assessment_passes(ordered, ordered_audit, assessment(ordered_audit, dispositions=(wrong_kind,)))

    def test_review_must_retrieve_actual_fields_and_completed_review_is_not_rerolled(self):
        task = self.compile()
        audit = audit_source_quality(task, self.verifier, self.serving)
        value = assessment(audit)
        client = FakeClient([
            call("finish", value.model_dump(mode="json")),
            call("sql", {"query": "SELECT _record_id FROM DeviceProcessEvents"}),
            call("finish", value.model_dump(mode="json")),
            call("sql", {"query": "SELECT * FROM DeviceProcessEvents"}),
            call("finish", value.model_dump(mode="json")),
        ])
        kwargs = dict(task=task, verifier=self.verifier, serving_bundle=self.serving,
                      output=self.root / "quality", instructions="Synthetic quality review.", review_context={})
        gate, review = run_quality_gate(client=client, **kwargs)
        self.assertEqual(gate["status"], "pass")
        self.assertEqual(review, value.review)
        self.assertEqual(len(client.contexts), 5)
        self.assertIn("must inspect", json.dumps(client.contexts[3]))
        saved = file_sha256(self.root / "quality/reviewer/result.json")
        replay, _ = run_quality_gate(client=FakeClient([]), resume=True, **kwargs)
        self.assertEqual(replay, gate)
        self.assertEqual(file_sha256(self.root / "quality/reviewer/result.json"), saved)

    def pilot_fixture(self, *, broken=False, literal_supported=True, blind_correct=True):
        seed = self.root / "seed"
        (seed / "scout").mkdir(parents=True)
        context = {"mode": "tenant", "fixture": True}
        draft = self.broken_draft() if broken else self.draft
        values = {
            "scope.json": context, "execution-policy.json": {"serving_view_id": self.anchor.serving_view_id},
            "task.json": self.anchor.model_dump(mode="json"), "draft.json": draft.model_dump(mode="json"),
            "pilot_report.json": {"task_fingerprint": fingerprint(self.anchor), "status": "candidate_for_mysql_validation"},
            "scout/result.json": {"leads": [{"title": "Fixture", "question_direction": "Inspect the cohort.",
                                           "evidence": draft.model_dump(mode="json")["anchors"], "uncertainty": "Synthetic."}],
                                  "coverage_limits": []},
        }
        for name, value in values.items():
            (seed / name).write_text(json.dumps(value))
        task = self.compile(draft, task_id="quality-pilot", lineage_group=self.anchor.lineage_group)
        audit = audit_source_quality(task, self.verifier, self.serving)
        responses = [call("finish", draft.model_dump(mode="json"))]
        if not broken:
            review = passing_review().model_copy(update={"literal_justifications_supported": literal_supported})
            responses += [
                call("sql", {"query": "SELECT * FROM DeviceProcessEvents"}),
                call("finish", assessment(audit, review).model_dump(mode="json")),
            ]
            if literal_supported:
                answer = task.private_gold.final.expected.model_dump(mode="json")
                if not blind_correct:
                    answer["value"] = ["bulk.test"]
                responses += [
                    call("sql", {"query": "SELECT * FROM DeviceProcessEvents WHERE ProcessId=43"}),
                    call("finish", {"answer": answer, "citations": [], "confidence": "supported", "explanation": "Synthetic."}),
                ]
        kwargs = dict(serving_bundle=self.serving, graph_bundle=self.graph, mode="tenant", incident_id=None,
                      output=self.root / "pilot", limits=self.engine.limits, checkpoint_cap=0.5,
                      related_from=seed, relation="shared_evidence", task_id="quality-pilot", quality_gate=True)
        client = FakeClient(responses)
        with patch("secgym.qagen.agentic.pilot.scope_context", return_value=context):
            report = run_discovery_pilot(client=client, **kwargs)
        return report, client, kwargs, context

    def test_bad_collection_never_starts_review_or_blind_student(self):
        report, client, _, _ = self.pilot_fixture(broken=True)
        self.assertEqual(report["status"], "needs_revision")
        self.assertEqual(report["source_quality"]["collection_failure_count"], 2)
        self.assertFalse(report["blind_started"])
        self.assertEqual(len(client.contexts), 1)
        self.assertFalse((self.root / "pilot/quality/reviewer").exists())
        self.assertFalse((self.root / "pilot/blind").exists())

    def test_literal_review_failure_stops_before_blind_and_is_not_a_student_failure(self):
        report, client, _, _ = self.pilot_fixture(literal_supported=False)
        self.assertEqual(report["status"], "needs_revision")
        self.assertNotIn("blind_answer_correct", report)
        self.assertEqual(len(client.contexts), 3)
        self.assertFalse((self.root / "pilot/blind").exists())

    def test_source_pilot_resume_preserves_failed_student_and_private_public_boundary(self):
        report, client, kwargs, context = self.pilot_fixture(blind_correct=False)
        self.assertEqual(report["source_quality"]["status"], "pass")
        self.assertFalse(report["blind_answer_correct"])
        self.assertEqual(report["status"], "needs_revision")
        blind_context = json.loads(client.contexts[3][1]["content"])
        self.assertNotIn("audit", blind_context)
        self.assertNotIn("Other.EXE", json.dumps(blind_context))
        self.assertNotIn("private_gold", blind_context)
        saved = file_sha256(self.root / "pilot/blind/result.json")
        with patch("secgym.qagen.agentic.pilot.scope_context", return_value=context):
            replay = run_discovery_pilot(client=FakeClient([]), resume=True, **kwargs)
            self.assertEqual(report, replay)
            with self.assertRaisesRegex(ValueError, "execution policy changed"):
                run_discovery_pilot(client=FakeClient([]), resume=True, **{**kwargs, "quality_gate": False})
        self.assertEqual(file_sha256(self.root / "pilot/blind/result.json"), saved)

    def test_bound_native_gate_rejects_tampered_review_and_policy_before_backend_work(self):
        report, _, _, _ = self.pilot_fixture()
        candidate = self.root / "pilot"
        task = TaskRecord.model_validate_json((candidate / "task.json").read_bytes())
        self.assertEqual(report["status"], "candidate_for_mysql_validation")
        validate_quality_gate(candidate, task)
        policy = json.loads((candidate / "execution-policy.json").read_text())
        policy["query_limits"]["max_rows"] += 1
        (candidate / "execution-policy.json").write_text(json.dumps(policy))
        with patch.object(self.verifier, "mechanical_report") as native_work:
            with self.assertRaisesRegex(ValueError, "execution policy"):
                private_pilot_validation(candidate, self.verifier, self.verifier, require_source_quality=True)
            native_work.assert_not_called()
        policy["query_limits"]["max_rows"] -= 1
        (candidate / "execution-policy.json").write_text(json.dumps(policy))
        trace = candidate / "quality/reviewer/0000-request.json"
        trace.write_text(trace.read_text() + " ")
        with self.assertRaisesRegex(ValueError, "review artifacts changed"):
            validate_quality_gate(candidate, task)

    def test_quality_policy_cannot_downgrade_to_legacy_when_artifacts_are_missing(self):
        self.pilot_fixture()
        candidate = self.root / "pilot"
        summary = json.loads((candidate / "pilot_report.json").read_text())
        summary.pop("source_quality")
        (candidate / "pilot_report.json").write_text(json.dumps(summary))
        (candidate / "quality").rename(candidate / "retained-quality")
        with patch.object(self.verifier, "mechanical_report", side_effect=AssertionError("legacy downgrade")) as native_work:
            with self.assertRaises(FileNotFoundError):
                private_pilot_validation(candidate, self.verifier, self.verifier)
            native_work.assert_not_called()

    def test_cli_writes_diagnostic_only_and_refuses_to_overwrite(self):
        task = self.compile()
        (self.root / "task.json").write_text(task.model_dump_json())
        (self.root / "limits.json").write_text(self.engine.limits.model_dump_json())
        (self.root / "literals.json").write_text('["43"]')
        output = self.root / "audit.json"
        argv = ["agentic", "audit-source-quality", "--task", str(self.root / "task.json"),
                "--serving-bundle", str(self.serving), "--limits", str(self.root / "limits.json"),
                "--allowed-literals", str(self.root / "literals.json"), "--output", str(output)]
        with patch("sys.argv", argv), contextlib.redirect_stdout(io.StringIO()) as stdout:
            main()
        self.assertTrue(json.loads(stdout.getvalue())["independent_review_required"])
        self.assertFalse(QualityAudit.model_validate_json(output.read_bytes()).release_approved)
        with patch("sys.argv", argv), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                main()
        self.assertEqual(error.exception.code, 2)
        for kind in ("source-quality-audit", "source-quality-assessment"):
            with patch("sys.argv", ["agentic", "schema", kind]), contextlib.redirect_stdout(io.StringIO()) as stdout:
                main()
            self.assertIn("properties", json.loads(stdout.getvalue()))


if __name__ == "__main__":
    unittest.main()
