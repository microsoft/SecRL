# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
from pathlib import Path
import tempfile
import unittest

import test_agentic_robustness as robustness_tests
import test_agentic_preproduction_pipeline as pipeline_tests
from secgym.qagen.agentic.contracts import PublicCitation, fingerprint
from secgym.qagen.agentic.ledger import file_sha256
from secgym.qagen.agentic.preproduction_admission import FinalReview
from secgym.qagen.agentic.preproduction_pipeline import (
    QualifiedSupportRecoveryApproval, _recover_contaminated_robustness_review, _recover_qualified_support_review,
)
from secgym.qagen.agentic import robustness
from secgym.qagen.agentic.robustness import (
    CellEdit, ClaimExpectation, ObservedClaim, RobustnessCase, RobustnessCheck, RobustnessPlan, RobustnessReport, WitnessGroup,
)


class ContaminatedReviewRecoveryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.previous = self.root / "prior/robustness"
        (self.previous / "reviewer").mkdir(parents=True)
        self.output = self.root / "new/robustness"
        self.output.mkdir(parents=True)
        self.plan = RobustnessPlan(task_fingerprint="a" * 64, cases=(RobustnessCase(
            case_id="control", scope="serving_contract", rationale="Source-backed controlled intervention.",
            edits=(CellEdit(citation=PublicCitation(table="T", record_id="r:" + "1" * 64),
                            column="Value", value="changed"),),
            expected=(ClaimExpectation(claim_id="final", answer="baseline", witnesses="baseline", support="baseline"),),
        ),))
        (self.previous / "proposed-plan.json").write_text(self.plan.model_dump_json())
        self.review = FinalReview(
            task_fingerprint=self.plan.task_fingerprint, subject_fingerprint=fingerprint(self.plan),
            recommendation="revise", reviewer="fixture", reasons=("Controlled stale-history review.",),
        )
        (self.previous / "review.json").write_text(self.review.model_dump_json())
        self.context = {
            "task_fingerprint": self.plan.task_fingerprint, "subject_fingerprint": fingerprint(self.plan),
            "plan": self.plan.model_dump(mode="json"), "previous_plan": {"stale": True},
        }
        self.request()

    def request(self):
        (self.previous / "reviewer/0000-request.json").write_text(json.dumps({
            "role": "robustness-reviewer",
            "messages": [{"role": "system", "content": "Fixture."},
                         {"role": "user", "content": json.dumps(self.context)}],
        }))

    def recover(self, plan=None, output=None):
        _recover_contaminated_robustness_review(self.root, self.previous, output or self.output, plan or self.plan)

    def test_exact_contaminated_review_is_single_use_and_preserves_every_original(self):
        originals = {p: p.read_bytes() for p in self.previous.rglob("*.json")}
        self.recover()
        self.recover()
        self.assertEqual({p: p.read_bytes() for p in originals}, originals)
        receipt = json.loads((self.output / "review-only-recovery.json").read_bytes())
        self.assertEqual(receipt["student_calls"], 0)
        self.assertFalse(receipt["plan_changed"])
        self.assertTrue(receipt["fresh_review_and_backend_measurement_required"])
        another = self.root / "another"
        another.mkdir()
        with self.assertRaises(ValueError):
            self.recover(output=another)

    def test_clean_context_cannot_be_retried_until_it_passes(self):
        self.context.pop("previous_plan")
        self.request()
        with self.assertRaisesRegex(ValueError, "proven contaminated"):
            self.recover()
        self.assertFalse((self.root / "robustness-review-recoveries").exists())

    def test_plan_changes_or_passing_review_are_ineligible(self):
        revised = self.plan.model_copy(update={"cases": (
            self.plan.cases[0].model_copy(update={"rationale": "A different annotation."}),
        )})
        with self.assertRaisesRegex(ValueError, "unchanged"):
            self.recover(plan=revised)
        (self.previous / "review.json").write_text(self.review.model_copy(update={"recommendation": "pass"}).model_dump_json())
        with self.assertRaisesRegex(ValueError, "proven contaminated"):
            self.recover()

    def test_wrong_captured_plan_or_task_is_rejected(self):
        self.context["task_fingerprint"] = "b" * 64
        self.request()
        with self.assertRaisesRegex(ValueError, "proven contaminated"):
            self.recover()


class QualifiedSupportRecoveryTests(unittest.TestCase):
    unchanged = robustness_tests.RobustnessFixtureTests.unchanged
    representation_case = robustness_tests.RobustnessFixtureTests.representation_case
    plan = pipeline_tests.NativePipelineTests.plan

    def setUp(self):
        robustness_tests.RobustnessFixtureTests.setUp(self)
        self.run = self.root / "run"
        self.run.mkdir()
        self.run_plan = self.plan()
        (self.run / "plan.json").write_text(self.run_plan.model_dump_json())
        pipelines = self.run / "attempts" / self.task.task_id / "pipeline"
        self.previous = pipelines / "old/robustness"
        (self.previous / "reviewer").mkdir(parents=True)
        self.output = pipelines / "corrected/robustness"
        self.output.mkdir(parents=True)
        self.matrix = RobustnessPlan(task_fingerprint=fingerprint(self.task), cases=(self.representation_case(),))
        (self.previous / "proposed-plan.json").write_text(self.matrix.model_dump_json())
        self.review = FinalReview(
            task_fingerprint=fingerprint(self.task), subject_fingerprint=fingerprint(self.matrix),
            recommendation="revise", reviewer="fixture", reasons=("Controlled representative-containment mistake.",),
        )
        (self.previous / "review.json").write_text(self.review.model_dump_json())
        self.context = {
            "task_fingerprint": fingerprint(self.task), "subject_fingerprint": fingerprint(self.matrix),
            "plan": self.matrix.model_dump(mode="json"),
            "measurement_semantics": "Qualified support additionally executes its obligations/candidates.",
        }
        self.request()
        citations = tuple(PublicCitation(table=e.table, record_id=e.public_record_id) for e in self.task.evidence)
        self.probes = (citations, (), citations[:-1])
        claims = {"final": self.task.private_gold.final, **{c.checkpoint_id: c.claim for c in self.task.private_gold.checkpoints}}
        self.diagnostic = RobustnessReport(
            task_fingerprint=fingerprint(self.task), plan_fingerprint=fingerprint(self.matrix),
            serving_view_id=self.task.serving_view_id, status="pass", query_limits=self.engine.limits,
            implementation_sha256={name: file_sha256(Path(robustness.__file__).with_name(name))
                                   for name in robustness.RUNTIME_FILES},
            source_records_sha256="b" * 64, backend_versions={"duckdb": "fixture", "mysql": "fixture"},
            probes=self.probes, checks=tuple(
                RobustnessCheck(case_id=case, claim_id=name, engine=backend, status="pass", reasons=(),
                                observed=ObservedClaim(answers=(claim.expected,),
                                                       witnesses=(WitnessGroup(citations=citations),),
                                                       support=(True, False, True)))
                for case in ("baseline", self.matrix.cases[0].case_id)
                for name, claim in claims.items() for backend in ("duckdb", "mysql")
            ), cases_not_run=(),
        )
        self.report_path = self.run / "diagnostic.json"
        self.report_path.write_text(self.diagnostic.model_dump_json())
        self.approval_path = self.run / "approval.json"
        self.approve()

    def request(self):
        (self.previous / "reviewer/0000-request.json").write_text(json.dumps({
            "role": "robustness-reviewer",
            "messages": [{"role": "system", "content": "Fixture."},
                         {"role": "user", "content": json.dumps(self.context)}],
        }))

    def approve(self):
        approval = QualifiedSupportRecoveryApproval(
            plan_fingerprint=fingerprint(self.run_plan), task_fingerprint=fingerprint(self.task),
            previous_request_sha256=file_sha256(self.previous / "reviewer/0000-request.json"),
            previous_review_sha256=file_sha256(self.previous / "review.json"),
            previous_plan_sha256=file_sha256(self.previous / "proposed-plan.json"),
            diagnostic_report=str(self.report_path), diagnostic_report_sha256=file_sha256(self.report_path),
            reason="Controlled authorization-guard fixture; measurement semantics are covered by backend tests.",
            approved=True,
        )
        self.approval_path.write_text(approval.model_dump_json())

    def recover(self, output=None, matrix=None):
        _recover_qualified_support_review(self.run, self.previous, output or self.output, self.task,
                                           matrix or self.matrix, self.approval_path)

    def test_exact_context_plan_and_diagnostic_authorize_only_one_new_review(self):
        before = {p: p.read_bytes() for p in self.previous.rglob("*.json")}
        self.recover()
        self.recover()
        self.assertEqual({p: p.read_bytes() for p in before}, before)
        certificate = json.loads((self.output / "review-only-recovery.json").read_bytes())
        self.assertFalse(certificate["plan_changed"])
        self.assertFalse(certificate["diagnostic_outcomes_supplied_to_reviewer"])
        self.assertEqual(certificate["student_calls"], 0)
        other = self.output.parent.parent / "another/robustness"
        other.mkdir(parents=True)
        with self.assertRaises(ValueError):
            self.recover(output=other)

    def test_changed_plan_or_corrected_context_cannot_resample_a_review(self):
        changed = self.matrix.model_copy(update={"cases": (
            self.matrix.cases[0].model_copy(update={"rationale": "A changed plan."}),
        )})
        with self.assertRaisesRegex(ValueError, "unchanged plan"):
            self.recover(matrix=changed)
        self.context["measurement_semantics"] = "Already-correct qualified support semantics."
        self.request()
        self.approve()
        with self.assertRaisesRegex(ValueError, "ambiguous prior support context"):
            self.recover()

    def test_incomplete_or_non_discriminating_diagnostics_fail_closed(self):
        self.report_path.write_text(self.diagnostic.model_copy(update={
            "checks": self.diagnostic.checks[:-1],
        }).model_dump_json())
        self.approve()
        with self.assertRaisesRegex(ValueError, "every case, claim and backend"):
            self.recover()
        checks = []
        for check in self.diagnostic.checks:
            assert check.observed is not None
            checks.append(check.model_copy(update={"observed": check.observed.model_copy(update={
                "support": (True, False, False),
            })}))
        self.report_path.write_text(self.diagnostic.model_copy(update={"checks": tuple(checks)}).model_dump_json())
        self.approve()
        with self.assertRaisesRegex(ValueError, "counterexamples"):
            self.recover()

    def test_tampered_approval_or_backend_producer_is_rejected(self):
        self.report_path.write_text(self.diagnostic.model_copy(update={"source_records_sha256": "c" * 64}).model_dump_json())
        with self.assertRaisesRegex(ValueError, "diagnostic evidence changed"):
            self.recover()
        self.report_path.write_text(self.diagnostic.model_copy(update={"implementation_sha256": {"unknown.py": "a" * 64}}).model_dump_json())
        self.approve()
        with self.assertRaisesRegex(ValueError, "unchanged passing actual backend diagnostic"):
            self.recover()
