# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import tempfile
import unittest
from pathlib import Path

from agentic_runtime_fixture import runtime_fixture, runtime_task
from test_agentic_adapters import reviewed_fixture
from test_agentic_difficulty import plan_for, review_for
from test_agentic_generation import FakeClient, call
from secgym.qagen.agentic.canonical_facts import CanonicalFactReview, SourceFactProposal, SourceFactResolver
from secgym.qagen.agentic.contracts import AnswerProgram, QualifiedWitnessProgram, fingerprint
from secgym.qagen.agentic.difficulty import PartitionedAmbiguityProbe
from secgym.qagen.agentic.difficulty_curation import DifficultyAssessment, DifficultyProposal, _context, curate_difficulty
from secgym.qagen.agentic.evidence import EvidenceVerifier
from secgym.qagen.agentic.footprints import build_unit_footprint
from secgym.qagen.agentic.ledger import file_sha256
from secgym.qagen.agentic.mysql_serving import open_duckdb_engine
from secgym.qagen.agentic.query import QueryLimits
from secgym.qagen.agentic.question_splits import SplitQuestion


class DifficultyCurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        graph, _, serving, report = runtime_fixture(self.root / "source")
        task = runtime_task(serving, report)
        validation = reviewed_fixture(task)
        self.engine = open_duckdb_engine(serving, QueryLimits(max_rows=100, max_bytes=65536, timeout_ms=3000))
        self.addCleanup(self.engine.connection.close)
        self.verifier = EvidenceVerifier(serving, self.engine, frozenset())
        self.addCleanup(self.verifier.close)
        citation = {"table": "DeviceProcessEvents", "record_id": task.evidence[0].public_record_id}
        facts = SourceFactResolver(self.verifier).resolve(task, validation, SourceFactProposal.model_validate_json(json.dumps({
            "claims": [
                {"claim_id": "final", "references": [{"citation": citation, "column": "FileName"}], "rationale": "Fixture."},
                {"claim_id": task.private_gold.checkpoints[0].checkpoint_id,
                 "references": [{"citation": citation, "column": "ProcessId"}], "rationale": "Fixture."},
            ],
        })))
        fact_review = CanonicalFactReview(
            bundle_fingerprint=fingerprint(facts), recommendation="pass", source_properties_relevant=True,
            subjects_roles_times_preserved=True, claim_coverage_complete=True, no_value_only_merging=True,
            reasons=("Controlled source fixture.",),
        )
        self.question = SplitQuestion(task=task, validation=validation, baseline=build_unit_footprint(task, validation, graph),
                                      facts=facts, review=fact_review)
        self.plan = plan_for(self.question)
        self.proposal = DifficultyProposal(routes=self.plan.routes)
        self.query = "SELECT _record_id,FileName,ProcessId FROM DeviceProcessEvents WHERE DeviceName='host.test'"

    def responses(self, assessment=None):
        assessment = assessment or DifficultyAssessment(review=review_for(self.plan))
        return [
            call("sql", {"query": self.query}), call("finish", self.proposal.model_dump(mode="json")),
            call("sql", {"query": self.query}), call("finish", assessment.model_dump(mode="json")),
        ]

    def run_case(self, client, output, **kwargs):
        return curate_difficulty(client=client, question=self.question, verifier=self.verifier, output=output, **kwargs)

    def test_independent_inspection_and_no_outcome_or_score_context(self):
        client = FakeClient(self.responses())
        result = self.run_case(client, self.root / "annotation")
        self.assertEqual(result["status"], "difficulty_reviewed")
        self.assertEqual(result["curator_observed_records"], 1)
        self.assertEqual(result["reviewer_observed_records"], 1)
        curator = json.loads(client.contexts[0][1]["content"])
        reviewer = json.loads(client.contexts[2][1]["content"])
        for context in (curator, reviewer):
            for key in ("score", "band", "axes", "evaluations", "model_results", "native_validation", "reward_policy"):
                self.assertNotIn(key, context)
            final = context["claims"][0]
            self.assertEqual(final["source_witness_programs"], [
                p.model_dump(mode="json") for p in self.question.task.private_gold.final.witness_programs
                if p.engine == "duckdb"
            ])
            self.assertEqual(final["requires_behavior_evidence"],
                             self.question.task.private_gold.final.requires_behavior_evidence)
        self.assertNotIn("plan", curator)
        self.assertIn("canonical_source_properties", curator)
        self.assertNotIn("canonical_facts", curator)
        self.assertNotIn("value_json", json.dumps(curator["canonical_source_properties"]))
        self.assertNotIn("content_sha256", json.dumps(curator["evidence"]))
        self.assertIn("plan", reviewer)
        self.assertEqual(reviewer["plan_fingerprint"], fingerprint(self.plan))
        self.assertFalse(result["model_performance_used_as_feature"])
        self.assertFalse(result["model_ability_evaluations_run"])

    def test_qualified_catalog_and_candidates_are_visible_without_student_outcomes(self):
        task = self.question.task
        claim = task.private_gold.final
        programs = tuple(QualifiedWitnessProgram.model_validate({
            **p.model_dump(mode="json"),
            "witness_policy": "source-qualified-obligations-v1",
            "obligations_query": "SELECT 'group' AS evidence_group, 'proof' AS obligation_id",
            "candidates_query": "SELECT * FROM proof_citations",
        }) for p in claim.witness_programs)
        qualified = task.model_copy(update={"private_gold": task.private_gold.model_copy(update={
            "final": claim.model_copy(update={"witness_programs": programs}),
        })})
        context = _context(self.question.model_copy(update={"task": qualified}))
        source_programs = context["claims"][0]["source_witness_programs"]
        self.assertEqual(source_programs, [p.model_dump(mode="json") for p in programs if p.engine == "duckdb"])
        self.assertTrue(all(p["obligations_query"] and p["candidates_query"] for p in source_programs))
        self.assertNotIn("evaluations", context)

    def test_both_roles_must_inspect_their_own_selected_sources(self):
        assessment = DifficultyAssessment(review=review_for(self.plan))
        client = FakeClient([
            call("finish", self.proposal.model_dump(mode="json")),
            call("sql", {"query": self.query}), call("finish", self.proposal.model_dump(mode="json")),
            call("finish", assessment.model_dump(mode="json")),
            call("sql", {"query": self.query}), call("finish", assessment.model_dump(mode="json")),
        ])
        result = self.run_case(client, self.root / "inspection")
        self.assertEqual(result["status"], "difficulty_reviewed")
        self.assertIn("must inspect every selected proof record", json.dumps(client.contexts[1]))
        self.assertIn("must independently inspect", json.dumps(client.contexts[4]))

    def test_paged_measurements_keep_full_private_inventory_and_compact_reviewer_context(self):
        self.engine.limits = QueryLimits(max_rows=1, max_bytes=65536, timeout_ms=3000)
        probe = PartitionedAmbiguityProbe(
            probe_id="population", decision_step="lookup", table="DeviceProcessEvents",
            program=AnswerProgram(program_id="population-query", engine="duckdb",
                                  query="SELECT _record_id,ProcessId FROM DeviceProcessEvents"),
            identity_kind="source_observation", retrieval_policy="exhaustive-record-ranges-v1",
            scope_and_relaxation="Controlled two-source population under a one-row query bound.",
        )
        plan = plan_for(self.question, probes=(probe,))
        proposal = DifficultyProposal(routes=plan.routes)
        assessment = DifficultyAssessment(review=review_for(plan))
        client = FakeClient([
            call("sql", {"query": self.query}), call("finish", proposal.model_dump(mode="json")),
            call("sql", {"query": self.query}), call("finish", assessment.model_dump(mode="json")),
        ])
        output = self.root / "paged"
        result = self.run_case(client, output)
        self.assertEqual(result["status"], "difficulty_reviewed")
        reviewer = json.loads(client.contexts[2][1]["content"])
        summary = reviewer["source_probe_measurements"]["reviewed-route"][0]
        self.assertNotIn("observed_citations", summary)
        self.assertEqual(summary["source_verified_citation_count"], 2)
        self.assertEqual(len(summary["source_verified_citations_sha256"]), 64)
        self.assertEqual(summary["retrieval"]["full_scope_rows"], 2)
        stored = json.loads((output / "pre-review-measurements.json").read_text())["reviewed-route"][0]
        self.assertEqual(len(stored["observed_citations"]), 2)
        self.assertEqual(stored["retrieval"], summary["retrieval"])
        for key in ("score", "band", "axes", "model_results"):
            self.assertNotIn(key, summary)

    def test_literal_id_and_id_only_inspection_are_not_credited(self):
        record_id = self.question.task.evidence[0].public_record_id
        for query in ("SELECT _record_id FROM DeviceProcessEvents WHERE DeviceName='host.test'",
                      f"SELECT '{record_id}' AS _record_id,FileName,ProcessId FROM DeviceProcessEvents WHERE DeviceName='host.test'"):
            with self.subTest(query=query):
                client = FakeClient([
                    call("sql", {"query": query}), call("finish", self.proposal.model_dump(mode="json")),
                    *self.responses(),
                ])
                output = self.root / ("id-only" if query.startswith("SELECT _record_id") else "literal-id")
                self.assertEqual(self.run_case(client, output)["status"], "difficulty_reviewed")
                self.assertIn("must inspect every selected proof record", json.dumps(client.contexts[2]))

    def test_completed_resume_makes_no_new_model_calls_and_preserves_artifacts(self):
        output = self.root / "resume"
        first = self.run_case(FakeClient(self.responses()), output)
        hashes = {path.relative_to(output): file_sha256(path) for path in output.rglob("*") if path.is_file()}
        client = FakeClient([])
        second = self.run_case(client, output, resume=True)
        self.assertEqual(first, second)
        self.assertEqual(client.contexts, [])
        self.assertTrue(all(file_sha256(output / path) == value for path, value in hashes.items()))
        with self.assertRaisesRegex(ValueError, "must be new"):
            self.run_case(FakeClient([]), output)

    def test_resume_rejects_changed_runtime_binding(self):
        output = self.root / "changed"
        self.run_case(FakeClient(self.responses()), output)
        binding = json.loads((output / "binding.json").read_text())
        binding["implementation_sha256"]["query.py"] = "0" * 64
        (output / "binding.json").write_text(json.dumps(binding))
        with self.assertRaisesRegex(ValueError, "runtime changed"):
            self.run_case(FakeClient([]), output, resume=True)

    def test_feature_revision_feedback_is_not_given_to_the_fresh_reviewer(self):
        first_output = self.root / "held"
        assessment = DifficultyAssessment(review=review_for(self.plan, recommendation="revise", operations_necessary=False))
        held = self.run_case(FakeClient(self.responses(assessment)), first_output)
        self.assertEqual(held["status"], "needs_feature_revision")
        hashes = {path.relative_to(first_output): file_sha256(path) for path in first_output.rglob("*") if path.is_file()}
        client = FakeClient(self.responses())
        result = self.run_case(client, self.root / "revision", revision_from=first_output)
        self.assertEqual(result["status"], "difficulty_reviewed")
        self.assertIn("feature_revision_feedback", json.loads(client.contexts[0][1]["content"]))
        self.assertNotIn("feature_revision_feedback", json.loads(client.contexts[2][1]["content"]))
        self.assertNotIn("previous_plan", json.loads(client.contexts[2][1]["content"]))
        self.assertTrue(all(file_sha256(first_output / path) == value for path, value in hashes.items()))

    def test_explicit_feature_audit_feedback_does_not_forge_or_leak_a_review(self):
        original = self.root / "audited"
        held = self.run_case(FakeClient(self.responses(
            DifficultyAssessment(review=review_for(self.plan, recommendation="revise", operations_necessary=False)),
        )), original)
        held["feature_audit_issues"] = ["Preserve resolved identity bindings in ambiguity probes."]
        (original / "difficulty-report.json").write_text(json.dumps(held))
        old_review = (original / "reviewer/result.json").read_bytes()
        client = FakeClient(self.responses())
        result = self.run_case(client, self.root / "audited-revision", revision_from=original)
        self.assertEqual(result["status"], "difficulty_reviewed")
        self.assertIn("feature_audit_feedback", json.loads(client.contexts[0][1]["content"]))
        self.assertNotIn("feature_audit_feedback", json.loads(client.contexts[2][1]["content"]))
        self.assertEqual((original / "reviewer/result.json").read_bytes(), old_review)

    def test_task_defect_is_not_waived_as_a_feature_revision(self):
        assessment = DifficultyAssessment(
            review=review_for(self.plan, recommendation="revise", proof_choices_complete_and_material=False),
            task_defect_reasons=("Controlled question/rubric defect.",),
        )
        output = self.root / "task-defect"
        report = self.run_case(FakeClient(self.responses(assessment)), output)
        self.assertEqual(report["status"], "task_revision_required")
        self.assertIsNone(report["score"])
        with self.assertRaisesRegex(ValueError, "held feature annotation"):
            self.run_case(FakeClient([]), self.root / "wrong-revision", revision_from=output)
        with self.assertRaises(ValueError):
            DifficultyAssessment(review=review_for(self.plan), task_defect_reasons=("Cannot pass.",))

    def test_oracle_witness_filter_is_rejected_in_an_ambiguity_probe(self):
        data = self.proposal.model_dump(mode="json")
        record_id = self.question.task.evidence[0].public_record_id
        data["routes"][0]["ambiguity_probes"] = [{
            "probe_id": "oracle", "decision_step": "lookup", "table": "DeviceProcessEvents",
            "program": {"program_id": "bad-probe", "engine": "duckdb",
                        "query": f"SELECT _record_id,ProcessId FROM DeviceProcessEvents WHERE _record_id='{record_id}'"},
            "identity_kind": "source_observation",
            "scope_and_relaxation": "This is not a legitimate public-scope relaxation.",
        }]
        assessment = DifficultyAssessment(review=review_for(self.plan))
        client = FakeClient([
            call("sql", {"query": self.query}), call("finish", data),
            call("finish", self.proposal.model_dump(mode="json")),
            call("sql", {"query": self.query}), call("finish", assessment.model_dump(mode="json")),
        ])
        result = self.run_case(client, self.root / "no-oracle")
        self.assertEqual(result["status"], "difficulty_reviewed")
        self.assertIn("not select private witness", json.dumps(client.contexts[2]))

    def test_unmeasured_ambiguity_stays_a_reported_gap(self):
        plan = plan_for(self.question, probes=None)
        proposal = DifficultyProposal(routes=plan.routes)
        assessment = DifficultyAssessment(review=review_for(plan))
        client = FakeClient([
            call("sql", {"query": self.query}), call("finish", proposal.model_dump(mode="json")),
            call("sql", {"query": self.query}), call("finish", assessment.model_dump(mode="json")),
        ])
        report = self.run_case(client, self.root / "unmeasured")
        self.assertEqual(report["status"], "measurement_incomplete")
        self.assertIsNone(report["score"])
        self.assertTrue(report["measurement_gaps"])

    def test_completed_curator_is_retained_when_only_reviewer_was_interrupted(self):
        class InterruptedClient(FakeClient):
            def complete(self, messages, tools):
                if len(self.contexts) == 2:
                    raise RuntimeError("controlled interruption")
                return super().complete(messages, tools)

        output = self.root / "interrupted"
        with self.assertRaisesRegex(RuntimeError, "controlled interruption"):
            self.run_case(InterruptedClient(self.responses()), output)
        self.assertTrue((output / "curator/complete.json").exists())
        self.assertFalse((output / "reviewer/complete.json").exists())
        hashes = {path.relative_to(output): file_sha256(path) for path in (output / "curator").rglob("*") if path.is_file()}
        client = FakeClient(self.responses()[2:])
        result = self.run_case(client, output, resume=True)
        self.assertEqual(result["status"], "difficulty_reviewed")
        self.assertEqual(len(client.contexts), 2)
        self.assertTrue(all(file_sha256(output / path) == value for path, value in hashes.items()))


if __name__ == "__main__":
    unittest.main()
