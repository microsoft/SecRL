import hashlib
import contextlib
from contextlib import ExitStack
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from zipfile import ZipFile

import test_agentic_preproduction as fixtures
import test_agentic_robustness as robustness_fixtures
from test_agentic_generation import call
from test_agentic_model_panel import ConfiguredFake
from secgym.qagen.agentic.contracts import Contract, PublicCitation, fingerprint
from secgym.qagen.agentic.__main__ import main
from secgym.qagen.agentic.ledger import file_sha256
from secgym.qagen.agentic.model_panel import immutable_json
from secgym.qagen.agentic.preproduction_pipeline import (
    AnnotationJournalLossApproval, StageResult, _continuation, _json_hashes,
    _journal_loss_continuation, _NonStudentSourceQueryEngine, inspected_role, robustness_candidate,
    run_candidate_pipeline, run_stage,
)
from secgym.qagen.agentic.preproduction_admission import FinalReview
from secgym.qagen.agentic.query import PublicQueryEngine
from secgym.qagen.agentic.robustness import CellEdit, ClaimExpectation, RobustnessCase, RobustnessPlan

MODULE = "secgym.qagen.agentic.preproduction_pipeline"


class ReadyOutcome(Contract):
    status: str = "source_ready"


class AnnotationJournalLossTests(unittest.TestCase):
    def setUp(self):
        fixtures.PreproductionTests.setUp(self)
        self.run = self.output
        self.run.mkdir()
        immutable_json(self.run / "plan.json", self.plan)
        attempt = self.plan.attempts()[0]
        self.task = self.seed.model_copy(update={"task_id": attempt.task_id, "lineage_group": attempt.task_id, "revision_id": "r1"})
        self.source = self.run / "attempts" / self.task.task_id / "source"
        self.source.mkdir(parents=True)
        immutable_json(self.source / "task.json", self.task)
        immutable_json(self.source.parent / "source-outcome.json", {"status": "source_ready"})
        self.parent = self.source.parent / "pipeline/r1"
        self.parent.mkdir(parents=True)
        self.target = self.parent.parent / "loss-recovery"
        self.outcome = ReadyOutcome()
        self.modules = {"preproduction_pipeline.py": b"original orchestration", "evidence.py": b"protected kernel"}
        self.binding = {
            "version": "preproduction-candidate-pipeline-v1", "task_fingerprint": fingerprint(self.task),
            "plan_fingerprint": fingerprint(self.plan), "source_outcome_fingerprint": "c" * 64,
            "grading_policy_fingerprint": None,
            "implementation_sha256": {name: hashlib.sha256(value).hexdigest() for name, value in self.modules.items()},
        }
        self.current = {**self.binding, "implementation_sha256": {
            **self.binding["implementation_sha256"], "preproduction_pipeline.py": hashlib.sha256(b"new orchestration").hexdigest(),
        }}
        immutable_json(self.parent / "binding.json", self.binding)
        self.archive = self.run / "original-runtime.zip"
        with ZipFile(self.archive, "w") as archive:
            for name, content in self.modules.items():
                archive.writestr(name, content)
        current = patch(MODULE + ".current_source", return_value=(self.source, self.outcome, 0))
        current.start()
        self.addCleanup(current.stop)

    def prepare(self, interrupted_stage):
        prefixes = {
            "robustness": ("grading", "native", "baseline"),
            "difficulty": ("grading", "native", "baseline", "robustness", "canonical"),
            "objective": ("grading", "native", "baseline", "robustness", "canonical", "difficulty"),
        }
        completed = {}
        for name in prefixes[interrupted_stage]:
            run_stage(self.parent / name, {"pipeline": self.binding, "prior_stage_receipts": dict(completed)},
                      lambda folder: StageResult(status="pass", reason="Original completed stage."))
            completed[name] = file_sha256(self.parent / name / "stage-receipt.json")
        role_name = {"robustness": "robustness/reviewer", "difficulty": "difficulty/curation/curator",
                     "objective": "objective-0123456789abcdef/reviewer"}[interrupted_stage]
        stage = self.parent / Path(role_name).parts[0]
        stage.mkdir(exist_ok=True)
        immutable_json(stage / "stage-binding.json", {"pipeline": self.binding, "prior_stage_receipts": completed})
        role = self.parent / role_name
        role.mkdir(parents=True)
        immutable_json(role / "0000-request.json", {"role": "unfinished-nonstudent", "original": True})
        for name in ("0001-request.json", "0001-error.json"):
            (role / name).write_bytes(b"")
        if interrupted_stage == "robustness":
            reference = self.task.evidence[0]
            citation = PublicCitation(table=reference.table, record_id=reference.public_record_id)
            self.matrix = RobustnessPlan(
                task_fingerprint=fingerprint(self.task),
                cases=(RobustnessCase(
                    case_id="original_control", rationale="Original source-bound control.", scope="serving_contract",
                    edits=(CellEdit(citation=citation, column="ActionType", value="changed"),),
                    expected=(ClaimExpectation(claim_id="final", answer="baseline", witnesses="baseline", support="baseline"),),
                ),),
            )
            author = stage / "author"
            author.mkdir()
            immutable_json(stage / "proposed-plan.json", self.matrix)
            immutable_json(author / "result.json", self.matrix)
            immutable_json(author / "complete.json", {
                "role": "robustness-author", "calls": 1, "result_fingerprint": fingerprint(self.matrix),
            })
            immutable_json(author / "0000-request.json", {
                "role": "robustness-author",
                "messages": [{"role": "system", "content": "Original author"},
                             {"role": "user", "content": json.dumps({"task": self.task.model_dump(mode="json"),
                                                                    "task_fingerprint": fingerprint(self.task)})}],
                "tools": [{"function": {"name": "finish", "parameters": RobustnessPlan.model_json_schema()}}],
            })
            immutable_json(author / "0000-response.json", {"choices": [{"finish_reason": "tool_calls"}]})
        losses = [{"task_id": self.task.task_id, "path": str(path), "sha256": file_sha256(path), "bytes": 0}
                  for path in sorted(role.glob("*.json")) if path.stat().st_size == 0]
        source_hashes, parent_hashes = _json_hashes(self.source), _json_hashes(self.parent)
        self.boundary = self.run / "checkpoint-repairs/batch/disconnect/authorization.json"
        self.boundary.parent.mkdir(parents=True)
        immutable_json(self.boundary, {
            "status": "disconnect_boundary_preserved_not_replayed", "plan_fingerprint": fingerprint(self.plan),
            "send_state": "unknown", "empty_files_are_not_unsent_certificates": True,
            "completed_or_interrupted_students_replay_authorized": False,
            "malformed_original_artifacts": losses,
            "state": {"interrupted": {self.task.task_id: {
                "task_fingerprint": fingerprint(self.task), "pipeline_sha256": parent_hashes, "source_sha256": source_hashes,
            }}, "source_outcomes": {str(self.source.parent / "source-outcome.json"): file_sha256(self.source.parent / "source-outcome.json")}},
        })
        failure = self.source.parent / "checkpoint-pipeline-result.json"
        immutable_json(failure, {
            "status": "operational_error", "interrupted_role": role_name, "original_send_state": "unknown",
            "recovery_authorization": str(self.boundary), "recovery_authorization_sha256": file_sha256(self.boundary),
            "student_rerolls": False, "admitted": False, "question_invalid": False, "exclusion_certified": False,
            "malformed_artifacts": losses,
        })
        self.approval = AnnotationJournalLossApproval(
            plan_fingerprint=fingerprint(self.plan), task_fingerprint=fingerprint(self.task),
            parent_pipeline=str(self.parent), output_directory=str(self.target), runtime_archive=str(self.archive),
            runtime_archive_sha256=file_sha256(self.archive), interruption_authorization=str(self.boundary),
            interruption_authorization_sha256=file_sha256(self.boundary), interrupted_stage=interrupted_stage,
            interrupted_role=role_name, parent_artifacts_sha256=parent_hashes, source_artifacts_sha256=source_hashes,
            source_outcome_sha256=file_sha256(self.source.parent / "source-outcome.json"), failure_sha256=file_sha256(failure),
            reason="Retain all original students/completed stages and preserve unknown lost nonstudent contents.",
            approved=True,
        )
        self.approval_path = self.run / "checkpoint-repairs/loss-approval.json"
        immutable_json(self.approval_path, self.approval)
        return prefixes[interrupted_stage]

    def qualify(self, *, binding=None, approval=None, target=None):
        return _journal_loss_continuation(self.parent, self.archive, binding or self.current, self.run,
                                          self.parent.parent, approval or self.approval_path, target or self.target)

    def test_completed_robustness_author_is_imported_without_restarting_it(self):
        expected = self.prepare("robustness")
        before = _json_hashes(self.parent)
        result = self.qualify()
        self.assertEqual(tuple(result["imported_stage_paths"]), expected)
        self.assertEqual(result["completed_author_plan"], str(self.parent / "robustness/proposed-plan.json"))
        self.assertIs(result["students_or_completed_roles_resampled"], False)
        self.assertEqual(result["original_send_and_completion_state"], "unknown")
        self.assertEqual(_json_hashes(self.parent), before)
        self.assertFalse(Path(result["usage_path"]).exists())

    def test_difficulty_recovery_retains_completed_canonical_stage(self):
        expected = self.prepare("difficulty")
        result = self.qualify()
        self.assertEqual(tuple(result["imported_stage_paths"]), expected)
        self.assertIn("canonical", result["imported_stage_paths"])
        self.assertNotIn("difficulty", result["imported_stage_paths"])

    def test_objective_recovery_retains_all_six_passed_stages(self):
        expected = self.prepare("objective")
        result = self.qualify()
        self.assertEqual(tuple(result["imported_stage_paths"]), expected)
        self.assertIn("difficulty", result["imported_stage_paths"])
        self.assertIsNone(result["completed_author_plan"])

    def test_continuation_entrypoint_requires_explicit_approval(self):
        self.prepare("difficulty")
        with self.assertRaises(FileNotFoundError):
            _continuation(self.parent, self.archive, self.current, self.run, self.parent.parent)
        result = _continuation(self.parent, self.archive, self.current, self.run, self.parent.parent,
                               interruption_approval=self.approval_path, output=self.target)
        self.assertEqual(result, self.qualify())

    def test_protected_kernel_and_task_changes_rejected(self):
        self.prepare("difficulty")
        for binding in (
            {**self.current, "task_fingerprint": "d" * 64},
            {**self.current, "implementation_sha256": {**self.current["implementation_sha256"], "evidence.py": "e" * 64}},
        ):
            with self.subTest(binding=binding), self.assertRaises(ValueError):
                self.qualify(binding=binding)

    def test_wrong_archive_rejected(self):
        self.prepare("difficulty")
        self.archive.write_bytes(b"changed")
        with self.assertRaises(ValueError):
            self.qualify()

    def test_changed_original_source_rejected(self):
        self.prepare("difficulty")
        (self.source / "task.json").write_text("{}")
        with self.assertRaises((ValueError, KeyError)):
            self.qualify()

    def test_changed_original_pipeline_or_restored_empty_file_rejected(self):
        self.prepare("difficulty")
        (self.parent / "difficulty/curation/curator/0001-request.json").write_text("{}")
        with self.assertRaises(ValueError):
            self.qualify()

    def test_completed_interrupted_role_cannot_be_replaced(self):
        self.prepare("difficulty")
        immutable_json(self.parent / "difficulty/curation/curator/complete.json", {"calls": 2})
        with self.assertRaises(ValueError):
            self.qualify()

    def test_missing_passed_stage_rejected(self):
        self.prepare("difficulty")
        (self.parent / "canonical/stage-receipt.json").unlink()
        with self.assertRaises(ValueError):
            self.qualify()

    def test_completed_author_result_change_rejected(self):
        self.prepare("robustness")
        (self.parent / "robustness/author/result.json").write_text("{}")
        with self.assertRaises(ValueError):
            self.qualify()

    def test_one_use_binding_cannot_move_to_another_output(self):
        self.prepare("objective")
        result = self.qualify()
        usage = Path(result["usage_path"])
        usage.parent.mkdir()
        immutable_json(usage, result)
        other = self.parent.parent / "second-recovery"
        approval = self.approval.model_copy(update={"output_directory": str(other)})
        path = self.run / "checkpoint-repairs/second-approval.json"
        immutable_json(path, approval)
        with self.assertRaisesRegex(ValueError, "another bounded continuation"):
            self.qualify(approval=path, target=other)

    def test_existing_child_requires_original_one_use_record(self):
        self.prepare("objective")
        self.target.mkdir()
        immutable_json(self.target / "binding.json", self.current)
        with self.assertRaisesRegex(ValueError, "one-use"):
            self.qualify()

    def test_later_held_child_preserves_exact_interrupted_ancestry(self):
        names = self.prepare("robustness")
        restored = self.qualify()
        usage = Path(restored["usage_path"])
        usage.parent.mkdir()
        immutable_json(usage, restored)
        child_binding = {**self.current, "continuation": restored}
        self.target.mkdir()
        immutable_json(self.target / "binding.json", child_binding)
        completed = {name: file_sha256(self.parent / name / "stage-receipt.json") for name in names}
        run_stage(self.target / "robustness", {"pipeline": child_binding, "prior_stage_receipts": completed},
                  lambda folder: StageResult(status="held", reason="Fresh independent reviewer finding."))
        completed["robustness"] = file_sha256(self.target / "robustness/stage-receipt.json")
        immutable_json(self.target / "pipeline-report.json", {
            "task_fingerprint": fingerprint(self.task), "status": "held", "stage": "robustness",
            "stage_receipts": completed, "artifacts_sha256": _json_hashes(self.target),
        })
        current_archive = self.run / "current-runtime.zip"
        with ZipFile(current_archive, "w") as archive:
            archive.writestr("preproduction_pipeline.py", b"new orchestration")
            archive.writestr("evidence.py", self.modules["evidence.py"])
        continued = _continuation(self.target, current_archive, self.current, self.run, self.parent.parent)
        self.assertEqual(continued["imported_stage_paths"]["native"], str(self.parent / "native"))
        usage.unlink()
        with self.assertRaisesRegex(ValueError, "one-use"):
            _continuation(self.target, current_archive, self.current, self.run, self.parent.parent)

    def test_native_role_cannot_use_nonstudent_recovery(self):
        self.prepare("difficulty")
        path = self.run / "checkpoint-repairs/native-role-approval.json"
        immutable_json(path, self.approval.model_copy(update={"interrupted_role": "native/student"}))
        with self.assertRaises(ValueError):
            self.qualify(approval=path)

    def test_no_inferred_unsent_boundary(self):
        self.prepare("objective")
        record = json.loads(self.boundary.read_bytes())
        record["send_state"] = "unsent"
        self.boundary.write_text(json.dumps(record))
        with self.assertRaises(ValueError):
            self.qualify()

    def test_api_rejects_mixed_recovery_modes_before_execution(self):
        parameters = dict(
            plan=self.plan, run=self.run, task_id=self.task.task_id, client=self.client,
            source=None, mysql=None, student=None, serving_bundle=self.serving, mysql_bundle=self.root / "mysql",
            graph_bundle=self.graph, mysqld=self.root / "mysqld", workdir=self.root, output=self.target,
            parent_pipeline=self.parent, parent_runtime_archive=self.archive,
            annotation_journal_loss_approval=self.run / "approval.json", fresh_validation=True,
        )
        for override in ({"fresh_validation": False}, {"difficulty_feedback": "change features"},
                         {"prepared_robustness_plan": self.run / "plan-extra.json"},
                         {"retained_native_pipeline": self.parent}):
            with self.subTest(override=override), patch(MODULE + ".effective_runtime", return_value=self.plan.implementation_sha256), \
                 patch(MODULE + ".configured_model_binding", return_value=self.plan.model), self.assertRaises(ValueError):
                run_candidate_pipeline(**{**parameters, **override})

    def run_routing_fixture(self, interrupted_stage):
        names = self.prepare(interrupted_stage)
        continuation = self.qualify()
        immutable_json(self.parent / "native/private-pilot-validation.json", {})
        immutable_json(self.parent / "baseline/footprint.json", {})
        native_role = self.parent / "native/student"
        native_role.mkdir()
        immutable_json(native_role / "0000-request.json", {"original_native": True})
        if interrupted_stage == "objective":
            immutable_json(self.parent / "robustness/selected-measurement.json", {"directory": "original"})
        immutable_json(self.source / "draft.json", {})
        mysql_bundle = self.root / "mysql-routing"
        mysql_bundle.mkdir()
        immutable_json(mysql_bundle / "mysql_report.json", {"routing_fixture": True})
        plan = self.plan.model_copy(update={
            "native_snapshot_sha256": file_sha256(mysql_bundle / "mysql_report.json"),
            "native_indexes_sha256": "d" * 64,
        })
        source_engine = PublicQueryEngine(None, "duckdb", set(), plan.query_limits, plan.serving_view_id)
        source = SimpleNamespace(
            engine=source_engine,
            report={"serving_view_id": plan.serving_view_id}, allowed_literals=frozenset(),
        )

        def guarded_curation(**kwargs):
            self.assertIs(kwargs["verifier"], source)
            self.assertIsInstance(source.engine, _NonStudentSourceQueryEngine)
            self.assertIsNot(source.engine, source_engine)
            return {"status": "needs_feature_revision", "task_defect_reasons": []}

        with ExitStack() as patches:
            patches.enter_context(patch(MODULE + ".effective_runtime", return_value=plan.implementation_sha256))
            patches.enter_context(patch(MODULE + ".configured_model_binding", return_value=plan.model))
            patches.enter_context(patch(MODULE + ".admitted_receipts", return_value=()))
            patches.enter_context(patch(MODULE + ".validate_quality_gate"))
            patches.enter_context(patch(MODULE + ".TaskDraft.model_validate_json", return_value=SimpleNamespace(allowed_literals=())))
            patches.enter_context(patch("secgym.qagen.agentic.preproduction_revisions.native_index_manifest", return_value={"verified": "fixture"}))
            patches.enter_context(patch("secgym.qagen.agentic.preproduction_revisions.native_index_digest", return_value=plan.native_indexes_sha256))
            patches.enter_context(patch("secgym.qagen.agentic.preproduction_revisions.effective_native_plan", return_value=plan))
            patches.enter_context(patch(MODULE + "._continuation", return_value=continuation))
            patches.enter_context(patch(MODULE + ".ValidationReport.model_validate_json", return_value=SimpleNamespace()))
            patches.enter_context(patch(MODULE + ".EvidenceFootprint.model_validate_json", return_value=SimpleNamespace()))
            patches.enter_context(patch(MODULE + ".load_questions", return_value=SimpleNamespace(questions=(SimpleNamespace(task=self.task),))))
            grading = patches.enter_context(patch(MODULE + ".review_contract", side_effect=AssertionError("completed grading repeated")))
            native = patches.enter_context(patch(MODULE + ".native_candidate", side_effect=AssertionError("native student repeated")))
            baseline = patches.enter_context(patch(MODULE + ".build_unit_footprints", side_effect=AssertionError("completed baseline repeated")))
            canonical = patches.enter_context(patch(MODULE + ".canonical_candidate", side_effect=AssertionError("completed canonical repeated")))
            robust = patches.enter_context(patch(MODULE + ".robustness_candidate",
                                                  return_value=StageResult(status="held", reason="Fresh independent reviewer ran.")))
            difficulty = patches.enter_context(patch(MODULE + ".curate_difficulty", side_effect=guarded_curation))
            objective = patches.enter_context(patch(MODULE + ".objective_candidate",
                                                     return_value=StageResult(status="pass", reason="Current objective inventory reviewed.")))
            patches.enter_context(patch(MODULE + ".objective_inventory", return_value=self.task))
            admission = patches.enter_context(patch(MODULE + ".record_admission", return_value=self.task))
            native_lease = patches.enter_context(patch(MODULE + ".native_import_artifacts",
                                                        side_effect=AssertionError("unnecessary native episode import")))

            def no_native_engine():
                raise AssertionError("completed native episode leased another student engine")

            result = run_candidate_pipeline(
                plan=plan, run=self.run, task_id=self.task.task_id, client=self.client, source=source,
                mysql=None, student=None, serving_bundle=self.serving, mysql_bundle=mysql_bundle,
                graph_bundle=self.graph, mysqld=self.root / "mysqld", workdir=self.root, output=self.target,
                parent_pipeline=self.parent, parent_runtime_archive=self.archive,
                annotation_journal_loss_approval=self.approval_path, fresh_validation=True,
                native_engines=no_native_engine,
            )
            for called in (grading, native, baseline, canonical, native_lease):
                called.assert_not_called()
            if interrupted_stage == "robustness":
                robust.assert_called_once()
                self.assertEqual(robust.call_args.kwargs["completed_author_stage"], self.parent / "robustness")
                self.assertEqual(robust.call_args.kwargs["prepared_plan"], self.parent / "robustness/proposed-plan.json")
                self.assertIsNone(robust.call_args.kwargs["revision_from"])
                difficulty.assert_not_called()
                objective.assert_not_called()
                admission.assert_not_called()
            elif interrupted_stage == "difficulty":
                robust.assert_not_called()
                difficulty.assert_called_once()
                self.assertIsNone(difficulty.call_args.kwargs["revision_from"])
                self.assertFalse(difficulty.call_args.kwargs["resume"])
                objective.assert_not_called()
                admission.assert_not_called()
            else:
                robust.assert_not_called()
                difficulty.assert_not_called()
                objective.assert_called_once()
                admission.assert_called_once()
                files = admission.call_args.args[2]
                self.assertEqual(Path(files.difficulty_directory), self.parent / "difficulty/curation")
                self.assertEqual(Path(files.native_directory), self.parent / "native")
                self.assertEqual(Path(files.grading_review), self.parent / "grading/review.json")
                self.assertNotEqual(Path(files.objective_review).parent.name, "objective-0123456789abcdef")
        self.assertFalse((self.target / "native/student").exists())
        self.assertIs(source.engine, source_engine)
        self.assertEqual(list(result["stage_receipts"])[:len(names)], list(names))
        return result

    def test_robustness_flow_reuses_original_author_and_never_reruns_native(self):
        self.assertEqual(self.run_routing_fixture("robustness")["stage"], "robustness")

    def test_difficulty_flow_starts_only_fresh_missing_curation(self):
        self.assertEqual(self.run_routing_fixture("difficulty")["stage"], "difficulty")

    def test_objective_flow_imports_difficulty_and_uses_current_inventory(self):
        self.assertEqual(self.run_routing_fixture("objective")["status"], "admitted")

    def test_cli_wires_explicit_journal_loss_approval(self):
        args = ["agentic", "finish-preproduction", "--task-id", self.task.task_id, "--fresh-validation"]
        for name in ("run", "serving-bundle", "graph-bundle", "mysql-bundle", "env-file", "workdir", "output",
                     "parent-pipeline", "parent-runtime-archive", "annotation-journal-loss-approval"):
            args.extend(["--" + name, str(self.root / name)])
        with patch(MODULE + ".run_owned_candidate_pipeline", return_value={"status": "held"}) as runner:
            with patch("sys.argv", args), contextlib.redirect_stdout(io.StringIO()):
                main()
        self.assertEqual(runner.call_args.kwargs["annotation_journal_loss_approval"], self.root / "annotation-journal-loss-approval")
        self.assertTrue(runner.call_args.kwargs["fresh_validation"])


@unittest.skipUnless(os.environ.get("SECRL_MYSQLD"), "isolated native robustness validation requires MySQL")
class CompletedAuthorImportTests(unittest.TestCase):
    setUp = robustness_fixtures.RobustnessFixtureTests.setUp
    unchanged = robustness_fixtures.RobustnessFixtureTests.unchanged
    representation_case = robustness_fixtures.RobustnessFixtureTests.representation_case

    def test_completed_author_source_inspections_are_reused_but_reviewer_is_fresh(self):
        matrix = RobustnessPlan(task_fingerprint=fingerprint(self.task), cases=(self.representation_case(),))
        previous = self.root / "original-robustness"
        previous.mkdir()
        author = ConfiguredFake([
            call("sql", {"query": "SELECT * FROM DeviceProcessEvents"}),
            call("finish", matrix.model_dump(mode="json")),
        ])
        required = {PublicCitation(table=ref.table, record_id=ref.public_record_id) for ref in self.task.evidence}

        def validate(value, tools):
            if value != matrix or not required <= tools.observed:
                raise ValueError("The original author lacks its exact plan or source inspections")

        completed = inspected_role(
            author, self.verifier, previous / "author", "robustness-author", "Create a source-inspected plan.",
            {"task": self.task.model_dump(mode="json"), "task_fingerprint": fingerprint(self.task)},
            RobustnessPlan, validate,
        )
        immutable_json(previous / "proposed-plan.json", completed)
        damaged = previous / "reviewer"
        damaged.mkdir()
        (damaged / "0000-request.json").write_bytes(b"")
        before = _json_hashes(previous)
        assessment = FinalReview(
            task_fingerprint=fingerprint(self.task), subject_fingerprint=fingerprint(matrix),
            recommendation="pass", reviewer="fresh-independent", reasons=("Source inspected independently.",),
        )
        reviewer = ConfiguredFake([
            call("sql", {"query": "SELECT * FROM DeviceProcessEvents"}),
            call("finish", assessment.model_dump(mode="json")),
        ])
        output = self.root / "new-robustness"
        output.mkdir()
        result = robustness_candidate(
            self.task, self.verifier, reviewer, output, Path(os.environ["SECRL_MYSQLD"]), self.root,
            prepared_plan=previous / "proposed-plan.json", completed_author_stage=previous, run=self.root,
        )
        self.assertEqual(result.status, "pass")
        self.assertEqual(len(reviewer.contexts), 2)
        self.assertFalse((output / "author").exists())
        self.assertEqual(_json_hashes(previous), before)
        imported = json.loads((output / "completed-author-import.json").read_bytes())
        self.assertEqual(imported["author_model_calls"], 0)
        first = json.loads((output / "reviewer/0000-request.json").read_bytes())
        context = json.loads(first["messages"][1]["content"])
        self.assertNotIn("previous_review", context)
        self.assertNotIn("revision_feedback", context)
        self.assertEqual(RobustnessPlan.model_validate_json(json.dumps(context["plan"])), matrix)


if __name__ == "__main__":
    unittest.main()
