# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from test_agentic_adapters import reviewed_fixture
from test_agentic_difficulty import plan_for, review_for
from test_agentic_question_splits import question, write_inputs
from secgym.qagen.agentic.__main__ import main
from secgym.qagen.agentic.contracts import PublicCitation, ScoreComponent, TaskRecord, fingerprint
from secgym.qagen.agentic.difficulty import measure_difficulty
from secgym.qagen.agentic.difficulty_curation import DifficultyAssessment, DifficultyProposal, _runtime_hashes as difficulty_hashes
from secgym.qagen.agentic.evidence import VERIFIER_VERSION
from secgym.qagen.agentic.ledger import file_sha256
from secgym.qagen.agentic.preproduction import ModelBinding, PreproductionPlan, SourceOutcome, runtime_hashes
from secgym.qagen.agentic.preproduction_admission import (
    AdmissionFiles, FinalReview, NativeBinding, NativeStudentImport, NATIVE_RUNTIME_FILES, ObjectiveReview,
    admission_progress, admitted_receipts, objective_inventory, record_admission,
)
from secgym.qagen.agentic.preproduction_revisions import record_runtime_amendment
from secgym.qagen.agentic.query import QueryLimits
from secgym.qagen.agentic.question_splits import SplitQuestion
from secgym.qagen.agentic.robustness import (
    CellEdit, ClaimExpectation, ObservedClaim, ProgramAnswers, RobustnessCase, RobustnessCheck,
    RobustnessPlan, RobustnessReport, RUNTIME_FILES as ROBUSTNESS_FILES, _groups,
)
from secgym.qagen.agentic.scoring import aggregate_evaluation


MODULES = Path(__file__).resolve().parents[1] / "secgym/qagen/agentic"


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    path.write_text(json.dumps(value))


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        original = question("new-incident-34-01")
        data = original.task.model_dump(mode="json")
        data["dataset_release"] = "v1-private-pilot"
        for claim in (data["private_gold"]["final"], *(c["claim"] for c in data["private_gold"]["checkpoints"])):
            claim["programs"].extend(
                {**program, "program_id": program["program_id"] + "-mysql", "engine": "mysql"}
                for program in tuple(claim["programs"])
            )
        task = TaskRecord.model_validate_json(json.dumps(data))
        facts = original.facts.model_copy(update={"task_fingerprint": fingerprint(task)})
        self.case = SplitQuestion(
            task=task, validation=reviewed_fixture(task),
            baseline=original.baseline.model_copy(update={"task_fingerprint": fingerprint(task)}),
            facts=facts, review=original.review.model_copy(update={"bundle_fingerprint": fingerprint(facts)}),
        )
        self.plan = PreproductionPlan(
            batch_id="new", serving_view_id=task.serving_view_id, graph_id=task.graph_version,
            serving_report_sha256="a" * 64, graph_report_sha256="b" * 64,
            native_snapshot_sha256="c" * 64, native_indexes_sha256="d" * 64,
            model=ModelBinding(deployment="gpt-6-sol", endpoint_sha256="e" * 64, api_version="fixture",
                               request_timeout_seconds=300, max_completion_tokens=16000, reasoning_effort=None),
            query_limits=QueryLimits(max_rows=500, max_bytes=65536, timeout_ms=30000),
            grader_timeout_ms=120000, checkpoint_cap=0.5,
            seed_questions=(question("development-seed").task,), implementation_sha256=runtime_hashes(),
        )
        self.run = self.root / "run"
        save(self.run / "plan.json", self.plan)
        source = self.run / "attempts" / task.task_id / "source"
        save(source / "task.json", task)
        attempt = next(a for a in self.plan.attempts() if a.task_id == task.task_id)
        save(source.parent / "attempt.json", {"plan_fingerprint": fingerprint(self.plan), "attempt": attempt.model_dump(mode="json")})
        save(source.parent / "source-outcome.json", SourceOutcome(
            plan_fingerprint=fingerprint(self.plan), attempt_binding_sha256=file_sha256(source.parent / "attempt.json"),
            attempt=attempt, status="source_ready", task_fingerprint=fingerprint(task), reason="Controlled test fixture.",
            artifact_sha256={"task.json": file_sha256(source / "task.json")},
        ))
        self.inputs = write_inputs(self.root, (self.case,))
        self.native = self.root / "native"
        self.native_binding = NativeBinding(
            task_fingerprint=fingerprint(task), plan_fingerprint=fingerprint(self.plan), serving_view_id=task.serving_view_id,
            native_snapshot_sha256=self.plan.native_snapshot_sha256, native_indexes_sha256=self.plan.native_indexes_sha256,
            model=self.plan.model, student_query_limits=self.plan.query_limits,
            grader_query_limits=self.plan.query_limits.model_copy(update={"timeout_ms": 120000}),
            implementation_sha256={name: file_sha256(MODULES / name) for name in NATIVE_RUNTIME_FILES},
        )
        save(self.native / "binding.json", self.native_binding)
        save(self.native / "private-pilot-validation.json", self.case.validation)

        def score(component_id, kind):
            return ScoreComponent(
                component_id=component_id, kind=kind, status="complete", score=0.0, max_score=1.0, weight=1.0,
                evidence=(), trajectory_steps=(), first_completion_step=None,
                explanation="Controlled unsuccessful student, not a bad question.", evaluator_version=VERIFIER_VERSION,
            )

        self.evaluations = {}
        for backend in ("secrl", "acesevals"):
            evaluation = aggregate_evaluation(
                task, run_id="fixture-" + backend, backend=backend, trajectory_ref=str(self.native / (backend + ".json")),
                answer_correctness=score("final-answer", "answer_correctness"), final_evidence=score("final-evidence", "final_evidence"),
                checkpoints=(score(task.private_gold.checkpoints[0].checkpoint_id, "checkpoint"),),
            )
            self.evaluations[backend] = evaluation
            save(self.native / (backend + ".json"), {"current_episode": {"evaluation": evaluation.model_dump(mode="json")}})
        save(self.native / "evaluation_report.json", {
            "status": "private_pilot_completed", "task_fingerprint": fingerprint(task),
            "serving_view_id": task.serving_view_id, "candidate_checks_passed": True,
            "adapter_components_equal": True, "student_grounded_success": False,
        })
        self.robust = self.root / "robust"
        ref = task.evidence[0]
        self.robust_plan = RobustnessPlan(
            task_fingerprint=fingerprint(task), cases=(RobustnessCase(
                case_id="source-control", rationale="Controlled test counterfactual.", scope="serving_contract",
                edits=(CellEdit(citation=PublicCitation(table=ref.table, record_id=ref.public_record_id),
                                column="Note", value="changed"),),
                expected=tuple(ClaimExpectation(claim_id=key, answer="baseline", witnesses="baseline", support="baseline")
                               for key in ("final", task.private_gold.checkpoints[0].checkpoint_id)),
            ),),
        )
        self.robust_report = RobustnessReport(
            task_fingerprint=fingerprint(task), plan_fingerprint=fingerprint(self.robust_plan),
            serving_view_id=task.serving_view_id, status="pass", query_limits=self.plan.query_limits,
            implementation_sha256={name: file_sha256(MODULES / name) for name in ROBUSTNESS_FILES},
            source_records_sha256="a" * 64, backend_versions={"duckdb": "fixture", "mysql": "fixture"},
            probes=((PublicCitation(table=ref.table, record_id=ref.public_record_id),), ()), checks=tuple(
                RobustnessCheck(case_id=case, claim_id=key, engine=backend, status="pass",
                                observed=ObservedClaim(answers=(claim.expected,), witnesses=_groups((
                                    {PublicCitation(table=ref.table, record_id=ref.public_record_id)},
                                )), support=(True, False)), reasons=())
                for case in ("baseline", "source-control")
                for key, claim in (("final", task.private_gold.final), (task.private_gold.checkpoints[0].checkpoint_id, task.private_gold.checkpoints[0].claim))
                for backend in ("duckdb", "mysql")
            ), cases_not_run=(),
        )
        save(self.robust / "plan.json", self.robust_plan)
        save(self.robust / "report.json", self.robust_report)
        self.robust_review = self.review(fingerprint(self.robust_plan))
        save(self.robust / "review.json", self.robust_review)
        self.difficulty = self.root / "difficulty"
        plan = plan_for(self.case)
        review = review_for(plan)
        self.sidecar = measure_difficulty(self.case, plan=plan, review=review)
        save(self.difficulty / "difficulty-plan.json", plan)
        save(self.difficulty / "difficulty-review.json", review)
        assessment = DifficultyAssessment(review=review)
        proposal = DifficultyProposal(routes=plan.routes, limitations=plan.limitations)
        save(self.difficulty / "reviewer/result.json", assessment)
        save(self.difficulty / "curator/result.json", proposal)
        save(self.difficulty / "reviewer/complete.json", {"result_fingerprint": fingerprint(assessment)})
        save(self.difficulty / "curator/complete.json", {"result_fingerprint": fingerprint(proposal)})
        save(self.difficulty / "difficulty-sidecar.json", self.sidecar)
        save(self.difficulty / "binding.json", {
            "implementation_sha256": difficulty_hashes(), "question_binding": self.sidecar.binding.model_dump(mode="json"),
        })
        save(self.difficulty / "difficulty-report.json", {
            "task_fingerprint": fingerprint(task), "task_defect_reasons": [], "sidecar_fingerprint": fingerprint(self.sidecar),
            "plan_fingerprint": fingerprint(plan), "review_fingerprint": fingerprint(review),
            "model_performance_used_as_feature": False, "status": "difficulty_reviewed",
        })
        save(self.root / "grading-review.json", self.review(fingerprint(task.private_gold)))
        self.objective = ObjectiveReview(**self.review(fingerprint(objective_inventory(self.plan, self.run))).model_dump())
        save(self.root / "objective-review.json", self.objective)
        self.files = AdmissionFiles(
            question_inputs=str(self.inputs), native_directory=str(self.native), native_binding=str(self.native / "binding.json"),
            robustness_directory=str(self.robust), robustness_review=str(self.robust / "review.json"),
            objective_review=str(self.root / "objective-review.json"), difficulty_directory=str(self.difficulty),
            grading_review=str(self.root / "grading-review.json"),
        )
        patcher = patch("secgym.qagen.agentic.preproduction_admission.validate_quality_gate")
        self.quality = patcher.start()
        self.addCleanup(patcher.stop)

    def review(self, subject):
        return FinalReview(task_fingerprint=fingerprint(self.case.task), subject_fingerprint=subject,
                           recommendation="pass", reviewer="controlled-fixture",
                           reasons=("Synthetic admission-binding test, not a real source review.",))

    def admit(self):
        return record_admission(self.plan, self.run, self.files)

    def test_all_gates_can_admit_a_question_even_when_the_student_failed(self):
        receipt = self.admit()
        self.assertFalse(receipt.student_grounded_success)
        self.assertEqual(receipt.task.task_id, self.case.task.task_id)
        self.assertFalse(receipt.release_approved)
        self.quality.assert_called_once()
        self.assertEqual(self.admit(), receipt)
        progress = admission_progress(self.plan, self.run)
        self.assertEqual(progress["validated_new_questions"], 1)
        self.assertEqual(progress["buckets"]["incident:34"]["validated_shortfall"], 49)
        self.assertEqual(len(admitted_receipts(self.plan, self.run)), 1)
        with patch("secgym.qagen.agentic.preproduction_admission.objective_inventory",
                   side_effect=AssertionError("accepted questions must not be re-reviewed against a later pool")):
            self.assertEqual(self.admit(), receipt)

    def test_missing_native_artifact_is_not_a_source_ready_success(self):
        (self.native / "acesevals.json").unlink()
        with self.assertRaises(FileNotFoundError):
            self.admit()
        self.assertFalse((self.run / "admissions").exists())

    def test_explicit_revalidation_checks_all_gates_without_overwriting_or_recounting_admission(self):
        admitted = self.admit()
        original = self.run / "admissions" / (admitted.task.task_id + ".json")
        before = original.read_bytes()
        destination = self.run / "revalidations" / admitted.task.task_id / "fresh01.json"
        self.quality.reset_mock()
        refreshed = record_admission(self.plan, self.run, self.files, revalidation_receipt=destination)
        self.quality.assert_called_once()
        self.assertTrue(destination.is_file())
        self.assertEqual(refreshed.source_artifacts_sha256[str(original.resolve())], file_sha256(original))
        self.assertEqual(original.read_bytes(), before)
        self.assertEqual(len(admitted_receipts(self.plan, self.run)), 1)

    def test_revalidation_is_not_an_already_admitted_shortcut_around_a_failed_new_review(self):
        self.admit()
        failed = self.root / "failed-fresh-review.json"
        save(failed, self.review(fingerprint(self.case.task.private_gold)).model_copy(update={"recommendation": "revise"}))
        files = self.files.model_copy(update={"grading_review": str(failed)})
        destination = self.run / "revalidations" / self.case.task.task_id / "fresh01.json"
        with self.assertRaisesRegex(ValueError, "final review"):
            record_admission(self.plan, self.run, files, revalidation_receipt=destination)
        self.assertFalse(destination.exists())
        self.assertEqual(len(admitted_receipts(self.plan, self.run)), 1)

    def test_revalidation_cannot_write_into_admissions_or_certify_an_unadmitted_question(self):
        destination = self.run / "revalidations" / self.case.task.task_id / "fresh01.json"
        with self.assertRaisesRegex(ValueError, "existing admission"):
            record_admission(self.plan, self.run, self.files, revalidation_receipt=destination)
        self.admit()
        with self.assertRaisesRegex(ValueError, "separate owned certificate"):
            record_admission(self.plan, self.run, self.files,
                             revalidation_receipt=self.run / "admissions" / (self.case.task.task_id + ".json"))

    def test_native_model_snapshot_index_and_student_limits_are_pinned(self):
        for change in (
            {"native_indexes_sha256": "0" * 64},
            {"student_query_limits": self.plan.query_limits.model_copy(update={"timeout_ms": 120000})},
            {"grader_query_limits": self.plan.query_limits.model_copy(update={"timeout_ms": 999999})},
            {"implementation_sha256": {}},
        ):
            save(self.native / "binding.json", self.native_binding.model_copy(update=change))
            with self.assertRaisesRegex(ValueError, "native"):
                self.admit()

    def test_explicit_index_history_accepts_new_native_binding_without_changing_student_limits(self):
        indexes = (self.plan.native_indexes_sha256, "f" * 64)
        save(self.native / "binding.json", self.native_binding.model_copy(update={"native_indexes_sha256": indexes[-1]}))
        with patch("secgym.qagen.agentic.preproduction_revisions.native_index_history", return_value=indexes):
            receipt = self.admit()
        self.assertEqual(receipt.task.task_id, self.case.task.task_id)
        self.assertFalse(receipt.student_grounded_success)
        self.assertEqual(self.plan.query_limits.timeout_ms, 30000)

    def test_explicit_index_history_keeps_original_completed_native_binding_valid(self):
        before = {path: file_sha256(path) for path in self.native.rglob("*.json")}
        with patch("secgym.qagen.agentic.preproduction_revisions.native_index_history",
                   return_value=(self.plan.native_indexes_sha256, "f" * 64)):
            self.admit()
        self.assertEqual({path: file_sha256(path) for path in before}, before)

    def test_failed_or_incomplete_robustness_matrix_cannot_be_waived_by_the_summary(self):
        for altered in (
            self.robust_report.model_copy(update={"checks": self.robust_report.checks[:-1]}),
            self.robust_report.model_copy(update={"checks": (
                self.robust_report.checks[0].model_copy(update={"status": "mismatch"}), *self.robust_report.checks[1:],
            )}),
            self.robust_report.model_copy(update={"cases_not_run": ("source-control",)}),
        ):
            save(self.robust / "report.json", altered)
            with self.assertRaisesRegex(ValueError, "robustness"):
                self.admit()

    def test_program_bound_robustness_expectations_are_verified_at_admission(self):
        claims = {"final": self.case.task.private_gold.final,
                  **{c.checkpoint_id: c.claim for c in self.case.task.private_gold.checkpoints}}
        case = self.robust_plan.cases[0]
        expectations = tuple(entry.model_copy(update={"answer": ProgramAnswers(by_program={
            p.program_id: claims[entry.claim_id].expected for p in claims[entry.claim_id].programs
        })}) for entry in case.expected)
        plan = self.robust_plan.model_copy(update={"cases": (case.model_copy(update={"expected": expectations}),)})
        save(self.robust / "plan.json", plan)
        save(self.robust / "review.json", self.review(fingerprint(plan)))
        save(self.robust / "report.json", self.robust_report.model_copy(update={"plan_fingerprint": fingerprint(plan)}))
        self.assertEqual(self.admit().task.task_id, self.case.task.task_id)

    def test_forged_answer_vector_cannot_hide_missing_or_extra_program_results(self):
        for case_id in ("baseline", "source-control"):
            for extra in (False, True):
                checks = tuple(
                    check.model_copy(update={"observed": check.observed.model_copy(update={
                        "answers": check.observed.answers * 2 if extra else (),
                    })}) if check.case_id == case_id else check
                    for check in self.robust_report.checks
                )
                save(self.robust / "report.json", self.robust_report.model_copy(update={"checks": checks}))
                with self.assertRaisesRegex(ValueError, "robustness"):
                    self.admit()

    def test_admission_rejects_incomplete_or_unknown_program_answer_ids(self):
        claim = self.case.task.private_gold.final
        answers = {p.program_id: claim.expected for p in claim.programs}
        case = self.robust_plan.cases[0]
        for by_program in ({claim.programs[0].program_id: claim.expected}, {**answers, "unknown": claim.expected}):
            changed = case.model_copy(update={"expected": (
                case.expected[0].model_copy(update={"answer": ProgramAnswers(by_program=by_program)}),
                *case.expected[1:],
            )})
            plan = self.robust_plan.model_copy(update={"cases": (changed,)})
            save(self.robust / "plan.json", plan)
            save(self.robust / "review.json", self.review(fingerprint(plan)))
            save(self.robust / "report.json", self.robust_report.model_copy(update={"plan_fingerprint": fingerprint(plan)}))
            with self.assertRaisesRegex(ValueError, "exactly every claim answer-program ID"):
                self.admit()

    def test_duplicate_or_stale_objective_review_cannot_admit(self):
        for review in (self.objective.model_copy(update={"recommendation": "reject", "duplicate_task_ids": ("development-seed",)}),
                       self.objective.model_copy(update={"subject_fingerprint": "0" * 64})):
            save(self.root / "objective-review.json", review)
            with self.assertRaisesRegex(ValueError, "final review"):
                self.admit()

    def test_task_defect_from_difficulty_review_blocks_admission_without_a_band_quota(self):
        path = self.difficulty / "difficulty-report.json"
        data = json.loads(path.read_bytes())
        data["task_defect_reasons"] = ["A required proof member is missing."]
        save(path, data)
        with self.assertRaisesRegex(ValueError, "source-quality review"):
            self.admit()
        self.assertEqual(self.sidecar.band, "easy")

    def test_grading_contract_needs_its_own_bound_review(self):
        save(self.root / "grading-review.json", self.review(fingerprint(self.robust_plan)))
        with self.assertRaisesRegex(ValueError, "final review"):
            self.admit()

    def test_accepted_artifact_changes_are_detected_and_old_receipts_are_not_overwritten(self):
        receipt = self.admit()
        path = self.run / "admissions" / (receipt.task.task_id + ".json")
        old = path.read_bytes()
        target = self.native / "evaluation_report.json"
        target.write_text(target.read_text() + " ")
        with self.assertRaisesRegex(ValueError, "source artifacts changed"):
            admission_progress(self.plan, self.run)
        self.assertEqual(path.read_bytes(), old)

    def test_receipt_pins_runtime_archives_for_later_progress_checks(self):
        archive = self.run / "runtime.zip"
        with zipfile.ZipFile(archive, "x") as saved:
            for name in self.plan.implementation_sha256:
                saved.write(MODULES / name, arcname=name)
        updated = {**self.plan.implementation_sha256, "preproduction.py": "a" * 64}
        with patch("secgym.qagen.agentic.preproduction_revisions.runtime_hashes", return_value=updated):
            record_runtime_amendment(self.plan, self.run, archive=archive,
                                     reason="Controlled test of immutable runtime-archive provenance.")
        with patch("secgym.qagen.agentic.preproduction.runtime_hashes", return_value=updated):
            receipt = self.admit()
        self.assertEqual(receipt.source_artifacts_sha256.get(str(archive.resolve())), file_sha256(archive))
        archive.write_bytes(archive.read_bytes() + b"changed")
        with self.assertRaisesRegex(ValueError, "source artifacts changed"):
            admission_progress(self.plan, self.run)

    def test_receipt_pins_imported_native_dependencies_not_only_its_certificate(self):
        original = self.run / "retained-student-source.json"
        save(original, {"original": "captured result"})
        task = self.case.task
        retained = NativeStudentImport(
            task_fingerprint=fingerprint(task), recorded_task_fingerprint=fingerprint(task),
            plan_fingerprint=fingerprint(self.plan), parent_pipeline=str(self.run / "parent"),
            recorded_task=str(original), runtime_archive=str(self.run / "producer.zip"),
            source_artifacts_sha256={str(original): file_sha256(original)},
        )
        save(self.native / "retained-student.json", retained)
        report_path = self.native / "evaluation_report.json"
        report = json.loads(report_path.read_bytes())
        report["retained_native_student"] = True
        save(report_path, report)
        with patch("secgym.qagen.agentic.preproduction_admission.validate_native_import") as validate:
            receipt = self.admit()
        validate.assert_called_once()
        self.assertEqual(receipt.source_artifacts_sha256[str(original)], file_sha256(original))
        save(original, {"changed": "captured result"})
        with self.assertRaisesRegex(ValueError, "source artifacts changed"):
            admission_progress(self.plan, self.run)

    def test_unknown_difficulty_keeps_no_score_and_does_not_create_a_difficulty_quota(self):
        plan = plan_for(self.case, probes=None)
        review = review_for(plan)
        sidecar = measure_difficulty(self.case, plan=plan, review=review)
        self.assertEqual(sidecar.status, "incomplete")
        proposal = DifficultyProposal(routes=plan.routes, limitations=plan.limitations)
        assessment = DifficultyAssessment(review=review)
        for path, value in (
            ("difficulty-plan.json", plan), ("difficulty-review.json", review),
            ("difficulty-sidecar.json", sidecar), ("curator/result.json", proposal),
            ("reviewer/result.json", assessment),
            ("curator/complete.json", {"result_fingerprint": fingerprint(proposal)}),
            ("reviewer/complete.json", {"result_fingerprint": fingerprint(assessment)}),
            ("difficulty-report.json", {
                "task_fingerprint": fingerprint(self.case.task), "task_defect_reasons": [],
                "sidecar_fingerprint": fingerprint(sidecar), "plan_fingerprint": fingerprint(plan),
                "review_fingerprint": fingerprint(review), "model_performance_used_as_feature": False,
                "status": "measurement_incomplete",
            }),
        ):
            save(self.difficulty / path, value)
        receipt = self.admit()
        self.assertIsNone(receipt.difficulty_score)
        self.assertIsNone(receipt.difficulty_band)
        self.assertEqual(admission_progress(self.plan, self.run)["buckets"]["incident:34"]["difficulty_unmeasured"], 1)

    def test_cli_writes_an_admission_only_after_the_same_strict_checks(self):
        packet = self.root / "packet.json"
        save(packet, self.files)
        with patch("sys.argv", ["agentic", "admit-preproduction", "--run", str(self.run), "--files", str(packet)]):
            with contextlib.redirect_stdout(io.StringIO()) as stream:
                main()
        self.assertTrue(json.loads(stream.getvalue())["admitted"])
        with patch("sys.argv", ["agentic", "preproduction-progress", "--run", str(self.run)]):
            with contextlib.redirect_stdout(io.StringIO()) as stream:
                main()
        self.assertEqual(json.loads(stream.getvalue())["validated_new_questions"], 1)
        for kind in ("preproduction-admission-files", "preproduction-admission", "preproduction-objective-review",
                     "preproduction-final-review", "preproduction-native-binding"):
            with patch("sys.argv", ["agentic", "schema", kind]), contextlib.redirect_stdout(io.StringIO()) as stream:
                main()
            self.assertIn("properties", json.loads(stream.getvalue()))


if __name__ == "__main__":
    unittest.main()
