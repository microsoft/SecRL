# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from importlib.util import find_spec
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import DEFAULT, patch
import zipfile

from agentic_runtime_fixture import runtime_task
import test_agentic_canonical_facts as canonical_tests
import test_agentic_model_panel as panel_tests
import test_agentic_preproduction_admission as admission_tests
import test_agentic_robustness as robustness_tests
from test_agentic_generation import FakeClient, call
from test_agentic_model_panel import ConfiguredFake
from secgym.qagen.agentic.fact_curation import curate_source_facts
from secgym.qagen.agentic.contracts import PublicCitation, TaskRecord, fingerprint
from secgym.qagen.agentic.__main__ import main
from secgym.qagen.agentic.generation import RetryableCompletionError, RoleAbstained
from secgym.qagen.agentic.ledger import file_sha256
from secgym.qagen.agentic.model_panel import _native_replay
from secgym.qagen.agentic.preproduction import ModelBinding, PreproductionPlan
from secgym.qagen.agentic.preproduction_pipeline import (
    StageResult, _continuation, _json_hashes, _validate_plan_revision, canonical_candidate, contract_proof_diagnostics,
    _executable_contract, inspected_role, native_candidate, review_contract,
    robustness_candidate, robustness_review_context, run_candidate_pipeline, run_stage,
)
from secgym.qagen.agentic.preproduction_admission import (
    FinalReview, NativeStudentImport, NATIVE_RUNTIME_FILES, native_import_artifacts, validate_native_import,
)
from secgym.qagen.agentic.query import QueryFailure
from secgym.qagen.agentic.robustness import CellEdit, ClaimExpectation, RobustnessCase, RobustnessPlan


MODULE = "secgym.qagen.agentic.preproduction_pipeline"


class StageJournalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "stage"
        self.binding = {"task_fingerprint": "a" * 64, "runtime": {"pipeline": "b" * 64}}

    def test_completed_pass_and_hold_never_call_the_worker_again(self):
        for status in ("pass", "held"):
            directory = self.root / status
            expected = StageResult(status=status, reason="Source-backed decision.")
            actual = run_stage(directory, self.binding, lambda unused: expected)
            self.assertEqual(actual, expected)
            before = _json_hashes(directory)
            with patch(MODULE + ".safe_unfinished_roles", side_effect=AssertionError("terminal stage was restarted")):
                cached = run_stage(directory, self.binding, lambda unused: self.fail("completed worker called"))
            self.assertEqual(cached, expected)
            self.assertEqual(before, _json_hashes(directory))

    def test_changed_binding_or_completed_artifact_fails_before_any_worker(self):
        run_stage(self.root, self.binding, lambda path: StageResult(status="pass", reason="Verified fixture."))
        with self.assertRaisesRegex(ValueError, "immutable"):
            run_stage(self.root, {**self.binding, "task_fingerprint": "c" * 64}, lambda path: self.fail())
        (self.root / "unexpected.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "artifacts changed"):
            run_stage(self.root, self.binding, lambda path: self.fail())

    def test_operational_failure_is_explicit_and_preserves_partial_artifacts(self):
        def fail(path):
            (path / "partial.json").write_text('{"saved": true}')
            raise RuntimeError("Captured grading interruption.")

        with self.assertRaisesRegex(RuntimeError, "Captured grading"):
            run_stage(self.root, self.binding, fail)
        self.assertFalse((self.root / "stage-receipt.json").exists())
        self.assertEqual(json.loads((self.root / "errors/0000.json").read_bytes())["status"], "operational_error")
        before = file_sha256(self.root / "partial.json")
        result = run_stage(self.root, self.binding, lambda path: StageResult(status="pass", reason="Explicitly recovered."))
        self.assertEqual(result.status, "pass")
        self.assertEqual(file_sha256(self.root / "partial.json"), before)

    def test_abstention_is_an_immutable_hold_not_an_automatic_retry(self):
        def abstain(path):
            raise RoleAbstained("Required source unavailable.")

        result = run_stage(self.root, self.binding, abstain)
        self.assertEqual(result.status, "held")
        self.assertIn("Required source unavailable", result.reason)
        self.assertEqual(run_stage(self.root, self.binding, lambda unused: self.fail()), result)


class AnnotationContinuationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.parent = self.root / "pipeline/parent"
        self.parent.mkdir(parents=True)
        self.old_code = {"preproduction_pipeline.py": b"old orchestration", "evidence.py": b"unchanged verifier",
                         "robustness.py": b"old robustness", "preproduction_admission.py": b"old admission",
                         "difficulty_curation.py": b"old source context", "difficulty.py": b"unchanged difficulty rules"}
        self.old = {"version": "fixture", "task_fingerprint": "a" * 64, "plan_fingerprint": "b" * 64,
                    "source_outcome_fingerprint": "c" * 64, "grading_policy_fingerprint": None,
                    "implementation_sha256": {name: hashlib.sha256(value).hexdigest() for name, value in self.old_code.items()}}
        self.current = {**self.old, "implementation_sha256": {
            **self.old["implementation_sha256"], "preproduction_pipeline.py": hashlib.sha256(b"new orchestration").hexdigest(),
        }}
        self.archive = self.root / "old.zip"
        self.write_archive(self.archive, self.old_code)
        self.write(self.parent / "binding.json", self.old)
        self.stages = {}
        for name in ("grading", "native", "baseline", "robustness"):
            directory = self.parent / name
            directory.mkdir()
            self.write(directory / "payload.json", {"synthetic": name})
            run_stage(directory, {"pipeline": self.old}, lambda path, name=name: StageResult(
                status="held" if name == "robustness" else "pass", reason="Controlled annotation-continuation fixture.",
            ))
            self.stages[name] = file_sha256(directory / "stage-receipt.json")
        self.seal(self.parent, self.stages)

    def write(self, path, value):
        path.write_text(json.dumps(value))

    def write_archive(self, path, files):
        with zipfile.ZipFile(path, "w") as saved:
            for name, data in files.items():
                saved.writestr(name, data)

    def seal(self, path, stages):
        self.write(path / "pipeline-report.json", {
            "task_fingerprint": self.old["task_fingerprint"], "status": "held", "stage": "robustness",
            "stage_receipts": stages, "artifacts_sha256": _json_hashes(path, excluded=("pipeline-report.json",)),
        })

    def validate(self, **kwargs):
        return _continuation(kwargs.get("parent", self.parent), kwargs.get("archive", self.archive),
                             kwargs.get("binding", self.current), self.root, self.parent.parent)

    def test_exact_parent_imports_existing_passes_without_copying_or_changing_them(self):
        before = _json_hashes(self.parent)
        result = self.validate()
        self.assertEqual(result["imported_stage_paths"], {name: str(self.parent / name) for name in ("grading", "native", "baseline")})
        self.assertEqual(result["parent_report_sha256"], file_sha256(self.parent / "pipeline-report.json"))
        self.assertEqual(_json_hashes(self.parent), before)

    def test_changed_task_policy_or_protected_kernel_cannot_import_native_results(self):
        for update in ({"task_fingerprint": "d" * 64}, {"grading_policy_fingerprint": "e" * 64},
                       {"implementation_sha256": {**self.current["implementation_sha256"], "evidence.py": "f" * 64}}):
            with self.assertRaises(ValueError):
                self.validate(binding={**self.current, **update})

    def test_robustness_hold_can_replace_only_unimported_validation_stages(self):
        runtime = {**self.current["implementation_sha256"], "robustness.py": "1" * 64,
                   "preproduction_admission.py": "2" * 64}
        imported = self.validate(binding={**self.current, "implementation_sha256": runtime})
        self.assertEqual(set(imported["imported_stage_paths"]), {"grading", "native", "baseline"})
        for key in ("robustness.py", "evidence.py"):
            missing = {name: digest for name, digest in runtime.items() if name != key}
            with self.assertRaises(ValueError):
                self.validate(binding={**self.current, "implementation_sha256": missing})

    def test_wrong_archive_or_changed_parent_trace_is_rejected(self):
        self.write_archive(self.archive, {**self.old_code, "preproduction_pipeline.py": b"not original"})
        with self.assertRaisesRegex(ValueError, "exact producer"):
            self.validate()
        self.write_archive(self.archive, self.old_code)
        self.write(self.parent / "native/payload.json", {"changed": True})
        with self.assertRaisesRegex(ValueError, "artifacts changed"):
            self.validate()

    def test_repeated_annotation_revisions_keep_the_same_original_native_stage(self):
        first = self.validate()
        child = self.parent.parent / "child"
        child.mkdir()
        binding = {**self.current, "continuation": first}
        self.write(child / "binding.json", binding)
        run_stage(child / "robustness", {"pipeline": binding},
                  lambda path: StageResult(status="held", reason="Second controlled annotation hold."))
        stages = {**self.stages, "robustness": file_sha256(child / "robustness/stage-receipt.json")}
        self.seal(child, stages)
        archive = self.root / "child.zip"
        self.write_archive(archive, {**self.old_code, "preproduction_pipeline.py": b"new orchestration"})
        second = self.validate(parent=child, archive=archive)
        self.assertEqual(second["imported_stage_paths"], first["imported_stage_paths"])
        self.assertFalse((child / "native").exists())

    def test_canonical_hold_imports_completed_robustness_as_well_as_native(self):
        parent = self.parent.parent / "canonical-parent"
        parent.mkdir()
        self.write(parent / "binding.json", self.old)
        stages = {}
        for name in ("grading", "native", "baseline", "robustness", "canonical"):
            run_stage(parent / name, {"pipeline": self.old}, lambda path, name=name: StageResult(
                status="held" if name == "canonical" else "pass", reason="Controlled canonical hold.",
            ))
            stages[name] = file_sha256(parent / name / "stage-receipt.json")
        self.write(parent / "pipeline-report.json", {
            "task_fingerprint": self.old["task_fingerprint"], "status": "held", "stage": "canonical",
            "stage_receipts": stages, "artifacts_sha256": _json_hashes(parent, excluded=("pipeline-report.json",)),
        })
        before = _json_hashes(parent)
        imported = self.validate(parent=parent)
        self.assertEqual(set(imported["imported_stage_paths"]), {"grading", "native", "baseline", "robustness"})
        self.assertEqual(_json_hashes(parent), before)
        for name in ("robustness.py", "preproduction_admission.py"):
            runtime = {**self.current["implementation_sha256"], name: "f" * 64}
            with self.assertRaisesRegex(ValueError, "protected"):
                self.validate(parent=parent, binding={**self.current, "implementation_sha256": runtime})

    def test_plan_revision_cannot_reroll_by_prose_or_remove_a_negative_control(self):
        case = RobustnessCase(
            case_id="negative", rationale="Controlled intervention.", scope="serving_contract",
            edits=(CellEdit(citation=PublicCitation(table="T", record_id="r:" + "1" * 64), column="Value", value="changed"),),
            expected=(ClaimExpectation(claim_id="final", answer="baseline", witnesses="baseline", support="baseline"),),
        )
        old = RobustnessPlan(task_fingerprint="a" * 64, cases=(case,))
        for new in (old, old.model_copy(update={"cases": (case.model_copy(update={"rationale": "Different prose."}),)}),
                    old.model_copy(update={"cases": (case.model_copy(update={"case_id": "replacement"}),)})):
            with self.assertRaises(ValueError):
                _validate_plan_revision(old, new)
        new = old.model_copy(update={"cases": (case.model_copy(update={
            "expected": (case.expected[0].model_copy(update={"answer": None}),),
        }),)})
        _validate_plan_revision(old, new)

    def test_false_rationale_can_be_corrected_only_with_named_source_backed_authorization(self):
        case = RobustnessCase(
            case_id="boundary", rationale="Incorrectly claims no raw support when the answer is absent.",
            scope="serving_contract",
            edits=(CellEdit(citation=PublicCitation(table="T", record_id="r:" + "1" * 64), column="Value", value="changed"),),
            expected=(ClaimExpectation(claim_id="final", answer=None, witnesses="baseline", support="baseline"),),
        )
        previous = RobustnessPlan(task_fingerprint="a" * 64, cases=(case,))
        revised = previous.model_copy(update={"cases": (
            case.model_copy(update={"rationale": "Raw witness support survives; the absent answer still fails typed gold."}),
        )})
        with self.assertRaises(ValueError):
            _validate_plan_revision(previous, revised)
        _validate_plan_revision(previous, revised, control_repairs={
            "boundary": "The captured review identifies false rationale text contradicting the unchanged verified vectors.",
        })
        self.assertEqual(revised.cases[0].expected, previous.cases[0].expected)
        self.assertEqual(revised.cases[0].edits, previous.cases[0].edits)

    def test_difficulty_hold_reuses_all_five_verified_stages_but_not_its_failed_annotation(self):
        parent = self.parent.parent / "difficulty-parent"
        parent.mkdir()
        self.write(parent / "binding.json", self.old)
        stages = {}
        for name in ("grading", "native", "baseline", "robustness", "canonical", "difficulty"):
            run_stage(parent / name, {"pipeline": self.old}, lambda path, name=name: StageResult(
                status="held" if name == "difficulty" else "pass", reason="Controlled difficulty feature hold.",
            ))
            stages[name] = file_sha256(parent / name / "stage-receipt.json")
        self.write(parent / "pipeline-report.json", {
            "task_fingerprint": self.old["task_fingerprint"], "status": "held", "stage": "difficulty",
            "stage_receipts": stages, "artifacts_sha256": _json_hashes(parent, excluded=("pipeline-report.json",)),
        })
        before = _json_hashes(parent)
        imported = self.validate(parent=parent)
        self.assertEqual(set(imported["imported_stage_paths"]),
                         {"grading", "native", "baseline", "robustness", "canonical"})
        self.assertEqual(_json_hashes(parent), before)
        context_update = {**self.current["implementation_sha256"], "difficulty_curation.py": "e" * 64}
        self.validate(parent=parent, binding={**self.current, "implementation_sha256": context_update})
        with self.assertRaisesRegex(ValueError, "protected"):
            self.validate(parent=parent, binding={**self.current, "implementation_sha256": {
                **context_update, "difficulty.py": "f" * 64,
            }})
        runtime = {**self.current["implementation_sha256"], "robustness.py": "f" * 64}
        with self.assertRaisesRegex(ValueError, "protected"):
            self.validate(parent=parent, binding={**self.current, "implementation_sha256": runtime})

    def test_control_repair_is_explicit_scoped_and_cannot_drop_cases_or_existing_fixture_records(self):
        citation = PublicCitation(table="T", record_id="r:" + "1" * 64)
        case = RobustnessCase(
            case_id="boundary", rationale="An invalid chronology needs correction.", scope="serving_contract",
            edits=(CellEdit(citation=citation, column="Time", value="old"),),
            expected=(ClaimExpectation(claim_id="final", answer="baseline", witnesses="baseline", support="baseline"),),
        )
        old = RobustnessPlan(task_fingerprint="a" * 64, extra_source_records=(citation,), cases=(case,))
        changed = case.model_copy(update={"edits": (case.edits[0].model_copy(update={"value": "corrected"}),)})
        repaired = old.model_copy(update={"cases": (changed,)})
        with self.assertRaisesRegex(ValueError, "interventions"):
            _validate_plan_revision(old, repaired)
        authorization = {"boundary": "Correct the independently verified impossible chronology."}
        _validate_plan_revision(old, repaired, control_repairs=authorization)
        for invalid in (
            repaired.model_copy(update={"cases": (changed.model_copy(update={"case_id": "replacement"}),)}),
            repaired.model_copy(update={"extra_source_records": ()}),
            repaired.model_copy(update={"cases": (changed.model_copy(update={"scope": "portability_diagnostic"}),)}),
        ):
            with self.assertRaises(ValueError):
                _validate_plan_revision(old, invalid, control_repairs=authorization)
        for invalid_authorization in ({"unknown": "Not an original case."}, {"boundary": ""}):
            with self.assertRaises(ValueError):
                _validate_plan_revision(old, repaired, control_repairs=invalid_authorization)

    def test_independent_robustness_review_sees_only_current_expectations(self):
        case = RobustnessCase(
            case_id="boundary", rationale="Source-scoped boundary.", scope="serving_contract",
            removed_records=(PublicCitation(table="T", record_id="r:" + "1" * 64),),
            expected=(ClaimExpectation(claim_id="final", answer="baseline", witnesses=(), support=False),),
        )
        old = RobustnessPlan(task_fingerprint="a" * 64, cases=(case,))
        new = old.model_copy(update={"cases": (case.model_copy(update={"rationale": "Corrected rationale."}),)})
        context = {
            "task_fingerprint": old.task_fingerprint, "previous_plan": old.model_dump(mode="json"),
            "previous_review": {"recommendation": "revise"}, "revision_feedback": "Stale expectation.",
            "revision_instructions": "Author-only instructions.", "recorded_task": {"old": True},
            "authorized_control_repairs": {"boundary": "Correct the intervention."},
            "measurement_semantics": "Current program-support definition.",
        }
        result = robustness_review_context(context, new, old)
        self.assertEqual(result["plan"], new.model_dump(mode="json"))
        self.assertEqual(result["subject_fingerprint"], fingerprint(new))
        self.assertEqual(result["preserved_control_ids"], ["boundary"])
        self.assertNotIn("expected", result["previous_authorized_interventions"][0])
        for key in ("previous_plan", "previous_review", "revision_feedback", "revision_instructions", "recorded_task"):
            self.assertNotIn(key, result)
            self.assertIn(key, context)


class CanonicalPipelineTests(unittest.TestCase):
    setUp = canonical_tests.CanonicalFactTests.setUp
    proposal_data = canonical_tests.CanonicalFactTests.proposal_data
    resolve = canonical_tests.CanonicalFactTests.resolve
    review = canonical_tests.CanonicalFactTests.review
    curation_inputs = canonical_tests.CanonicalFactTests.curation_inputs

    def curate(self, client, baseline, directory):
        return canonical_candidate(self.task, self.validation, baseline, self.verifier, client, directory)

    def test_same_pinned_fact_semantics_and_independent_source_inspection(self):
        baseline, proposal, review, query = self.curation_inputs()
        previous = self.root / "original"
        responses = [query, call("finish", proposal), query, call("finish", review)]
        curate_source_facts(client=FakeClient(responses), task=self.task, validation=self.validation,
                            baseline=baseline, resolver=self.resolver, output=previous)
        output = self.root / "pipeline"
        output.mkdir()
        client = ConfiguredFake(responses)
        self.assertEqual(self.curate(client, baseline, output).status, "pass")
        for name in ("canonical-facts.json", "canonical-footprint.json", "fact_report.json"):
            self.assertEqual(json.loads((previous / name).read_bytes()), json.loads((output / name).read_bytes()))
        self.assertEqual(len(client.contexts[2]), 2)
        self.assertNotEqual(client.contexts[0][0], client.contexts[2][0])
        self.assertNotIn("student_grounded_success", json.dumps(client.contexts))
        binding = json.loads((output / "binding.json").read_bytes())
        self.assertIn("orchestration_sha256", binding)

    def test_interruption_after_curator_resumes_only_the_unstarted_reviewer(self):
        baseline, proposal, review, query = self.curation_inputs()
        output = self.root / "pipeline"
        output.mkdir()

        def interrupted(*args, **kwargs):
            if args[3] == "fact-reviewer":
                raise OSError("interruption before reviewer")
            return inspected_role(*args, **kwargs)

        with patch(MODULE + ".inspected_role", side_effect=interrupted):
            with self.assertRaisesRegex(OSError, "before reviewer"):
                self.curate(ConfiguredFake([query, call("finish", proposal)]), baseline, output)
        before = _json_hashes(output / "curator")
        client = ConfiguredFake([query, call("finish", review)])
        self.assertEqual(self.curate(client, baseline, output).status, "pass")
        self.assertEqual(len(client.contexts), 2)
        self.assertEqual(_json_hashes(output / "curator"), before)
        complete = _json_hashes(output)
        retained = ConfiguredFake([])
        self.assertEqual(self.curate(retained, baseline, output).status, "pass")
        self.assertEqual(retained.contexts, [])
        self.assertEqual(_json_hashes(output), complete)

    def test_ambiguous_request_boundary_cannot_be_resampled(self):
        baseline, _, _, _ = self.curation_inputs()
        output = self.root / "pipeline"
        output.mkdir()
        client = ConfiguredFake([])
        with patch.object(client, "complete", side_effect=RuntimeError("transport outcome unknown")):
            with self.assertRaisesRegex(RuntimeError, "unknown"):
                self.curate(client, baseline, output)
        retained = ConfiguredFake([])
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            self.curate(retained, baseline, output)
        self.assertEqual(retained.contexts, [])

    def test_rejected_completed_review_is_not_rerolled_for_success(self):
        baseline, proposal, review, query = self.curation_inputs()
        output = self.root / "pipeline"
        output.mkdir()
        review["recommendation"] = "revise"
        client = ConfiguredFake([query, call("finish", proposal), query, call("finish", review)])
        self.assertEqual(self.curate(client, baseline, output).status, "held")
        retained = ConfiguredFake([])
        self.assertEqual(self.curate(retained, baseline, output).status, "held")
        self.assertEqual(retained.contexts, [])
        self.assertFalse((output / "canonical-footprint.json").exists())

    def test_canonical_baseline_guards_precede_any_model_calls(self):
        baseline, _, _, _ = self.curation_inputs()
        for change in ({"feature_weight_version": "other-weights"}, {"graph_version": "graph:other"}):
            output = self.root / str(len(list(self.root.iterdir())))
            output.mkdir()
            client = ConfiguredFake([])
            with self.assertRaisesRegex(ValueError, "unit-weight"):
                self.curate(client, baseline.model_copy(update=change), output)
            self.assertEqual(client.contexts, [])
            self.assertFalse((output / "binding.json").exists())

    def test_canonical_revision_retains_old_roles_and_requires_material_source_references(self):
        baseline, proposal, review, query = self.curation_inputs()
        previous = self.root / "previous"
        previous.mkdir()
        hold = {**review, "recommendation": "revise", "claim_coverage_complete": False,
                "reasons": ["Include the material device-name scope predicate."]}
        self.assertEqual(self.curate(ConfiguredFake([query, call("finish", proposal), query, call("finish", hold)]),
                                     baseline, previous).status, "held")
        before = _json_hashes(previous)
        corrected = json.loads(json.dumps(proposal))
        for claim in corrected["claims"]:
            claim["references"].append({"citation": claim["references"][0]["citation"], "column": "DeviceName"})
        updated_review = self.review(self.resolve(corrected)).model_dump(mode="json")
        inspect = call("sql", {"query": "SELECT _record_id, FileName, ProcessId, DeviceName FROM DeviceProcessEvents"})
        client = ConfiguredFake([inspect, call("finish", proposal), call("finish", corrected),
                                 inspect, call("finish", updated_review)])
        output = self.root / "revised"
        output.mkdir()
        result = canonical_candidate(self.task, self.validation, baseline, self.verifier, client, output,
                                     revision_from=previous, feedback="Repair the missing scope predicate without changing the task.")
        self.assertEqual(result.status, "pass")
        self.assertEqual(_json_hashes(previous), before)
        rejected = json.loads((output / "curator/0001-tool-results.json").read_bytes())[0]["content"]
        self.assertIn("material reference change", rejected)
        self.assertIn("previous_annotation", json.loads(client.contexts[0][1]["content"]))
        binding = json.loads((output / "binding.json").read_bytes())
        self.assertEqual(binding["revision_artifacts_sha256"]["curator/result.json"], file_sha256(previous / "curator/result.json"))
        retained = ConfiguredFake([])
        self.assertEqual(canonical_candidate(self.task, self.validation, baseline, self.verifier, retained, output,
                                            revision_from=previous, feedback="Repair the missing scope predicate without changing the task.").status, "pass")
        self.assertEqual(retained.contexts, [])

    def test_canonical_revision_rejects_changed_previous_binding_before_inference(self):
        baseline, proposal, review, query = self.curation_inputs()
        previous = self.root / "previous"
        previous.mkdir()
        review["recommendation"] = "revise"
        self.curate(ConfiguredFake([query, call("finish", proposal), query, call("finish", review)]), baseline, previous)
        path = previous / "binding.json"
        binding = json.loads(path.read_bytes())
        binding["validation_fingerprint"] = "0" * 64
        path.write_text(json.dumps(binding))
        output = self.root / "revised"
        output.mkdir()
        client = ConfiguredFake([])
        with self.assertRaisesRegex(ValueError, "unchanged inputs"):
            canonical_candidate(self.task, self.validation, baseline, self.verifier, client, output,
                                revision_from=previous, feedback="Repair the scope selection.")
        self.assertEqual(client.contexts, [])


class PipelineEntryTests(unittest.TestCase):
    setUp = admission_tests.AdmissionTests.setUp
    review = admission_tests.AdmissionTests.review
    admit = admission_tests.AdmissionTests.admit

    def test_existing_admission_short_circuits_without_any_role_or_engine_calls(self):
        receipt = self.admit()
        directory = self.run / "attempts" / receipt.task.task_id / "pipeline/recovery"
        with patch(MODULE + ".configured_model_binding", return_value=self.plan.model), \
             patch(MODULE + ".run_stage", side_effect=AssertionError("admitted task was rerun")):
            result = run_candidate_pipeline(
                plan=self.plan, run=self.run, task_id=receipt.task.task_id, client=ConfiguredFake([]),
                source=None, mysql=None, student=None, serving_bundle=self.root / "unused",
                mysql_bundle=self.root / "unused", graph_bundle=self.root / "unused",
                mysqld=self.root / "unused", workdir=self.root, output=directory, resume=True,
            )
        self.assertEqual(result["status"], "already_admitted")
        self.assertEqual(result["new_model_calls"], 0)
        self.assertFalse(directory.exists())

    def test_fresh_validation_never_starts_another_student_for_an_admitted_question(self):
        receipt = self.admit()
        directory = self.run / "attempts" / receipt.task.task_id / "pipeline/fresh"
        with patch(MODULE + ".configured_model_binding", return_value=self.plan.model):
            with self.assertRaisesRegex(ValueError, "requires its retained native student"):
                run_candidate_pipeline(
                    plan=self.plan, run=self.run, task_id=receipt.task.task_id, client=ConfiguredFake([]),
                    source=None, mysql=None, student=None, serving_bundle=self.root / "unused",
                    mysql_bundle=self.root / "unused", graph_bundle=self.root / "unused",
                    mysqld=self.root / "unused", workdir=self.root, output=directory, fresh_validation=True,
                )
        self.assertFalse(directory.exists())

    def test_pipeline_cannot_write_into_original_or_revised_source_history(self):
        receipt = self.admit()
        for suffix in ("source", "revisions/0001/source"):
            directory = self.run / "attempts" / receipt.task.task_id / suffix
            with patch(MODULE + ".configured_model_binding", return_value=self.plan.model):
                with self.assertRaisesRegex(ValueError, "pipeline namespace"):
                    run_candidate_pipeline(
                        plan=self.plan, run=self.run, task_id=receipt.task.task_id, client=ConfiguredFake([]),
                        source=None, mysql=None, student=None, serving_bundle=self.root / "unused",
                        mysql_bundle=self.root / "unused", graph_bundle=self.root / "unused",
                        mysqld=self.root / "unused", workdir=self.root, output=directory, resume=True,
                    )

    def test_cli_wires_explicit_owned_paths_and_resume_without_starting_a_server(self):
        args = ["agentic", "finish-preproduction", "--task-id", self.case.task.task_id, "--resume"]
        for name in ("run", "serving-bundle", "graph-bundle", "mysql-bundle", "env-file", "workdir", "output"):
            args.extend(["--" + name, str(self.root / name)])
        for name in ("retained-native-pipeline", "retained-native-task", "retained-native-runtime-archive"):
            args.extend(["--" + name, str(self.root / name)])
        with patch(MODULE + ".run_owned_candidate_pipeline", return_value={"status": "held", "release_approved": False}) as runner:
            with patch("sys.argv", args), contextlib.redirect_stdout(io.StringIO()) as stream:
                main()
        self.assertEqual(json.loads(stream.getvalue())["status"], "held")
        self.assertTrue(runner.call_args.kwargs["resume"])
        self.assertEqual(runner.call_args.kwargs["task_id"], self.case.task.task_id)
        self.assertEqual(runner.call_args.kwargs["mysql_bundle"], self.root / "mysql-bundle")
        self.assertEqual(runner.call_args.kwargs["retained_native_task"], self.root / "retained-native-task")

    def test_new_pipeline_revision_cannot_reroll_a_previously_started_native_student(self):
        task_id = self.case.task.task_id
        student = self.run / "attempts" / task_id / "pipeline/old/native/student"
        student.mkdir(parents=True)
        (student / "0000-request.json").write_text("{}")
        with patch(MODULE + ".configured_model_binding", return_value=self.plan.model):
            with self.assertRaisesRegex(ValueError, "retained-trace import"):
                run_candidate_pipeline(
                    plan=self.plan, run=self.run, task_id=task_id, client=ConfiguredFake([]),
                    source=None, mysql=None, student=None, serving_bundle=self.root / "unused",
                    mysql_bundle=self.root / "unused", graph_bundle=self.root / "unused",
                    mysqld=self.root / "unused", workdir=self.root,
                    output=self.run / "attempts" / task_id / "pipeline/new",
                )

    def test_retained_native_import_does_not_waive_an_unrelated_student_recording(self):
        task_id = self.case.task.task_id
        attempt = self.run / "attempts" / task_id
        for name in ("selected", "unrelated"):
            role = attempt / "pipeline" / name / "native/student"
            role.mkdir(parents=True)
            (role / "0000-request.json").write_text("{}")
        with patch(MODULE + ".configured_model_binding", return_value=self.plan.model), \
             patch(MODULE + ".native_import_artifacts", return_value={}), \
             patch(MODULE + ".validate_native_import"):
            with self.assertRaisesRegex(ValueError, "retained-trace import"):
                run_candidate_pipeline(
                    plan=self.plan, run=self.run, task_id=task_id, client=ConfiguredFake([]),
                    source=None, mysql=None, student=None, serving_bundle=self.root / "unused",
                    mysql_bundle=self.root / "unused", graph_bundle=self.root / "unused",
                    mysqld=self.root / "unused", workdir=self.root, output=attempt / "pipeline/new",
                    retained_native_pipeline=attempt / "pipeline/selected", retained_native_task=attempt / "source/task.json",
                    retained_native_runtime_archive=self.root / "old.zip",
                    prepared_robustness_plan=self.root / "prepared.json", robustness_feedback="Preserve original controls.",
                )


class ContractProofDiagnosticsTests(unittest.TestCase):
    setUp = robustness_tests.RobustnessFixtureTests.setUp

    def test_qualified_representatives_have_actual_source_bound_omission_results(self):
        diagnostics = contract_proof_diagnostics(self.task, self.verifier)
        final = diagnostics["final"]
        self.assertEqual(final["witness_policy"], "source-qualified-obligations-v1")
        self.assertTrue(final["requires_behavior_or_security_control"])
        self.assertFalse(final["all_possible_equivalent_proofs_enumerated"])
        self.assertTrue(final["omission_probes"][0]["accepted_by_actual_verifier"])
        self.assertTrue(final["omission_probes"][0]["complete_proof_observed"])
        self.assertTrue(all(not p["accepted_by_actual_verifier"] for p in final["omission_probes"][1:]))
        self.assertTrue(all(not p["complete_proof_observed"] for p in final["omission_probes"][1:]))
        self.assertNotIn("student", json.dumps(diagnostics))

    def test_complete_observation_and_submitted_relevance_are_distinct_diagnostics(self):
        with patch.object(self.verifier, "evidence_matches", return_value=False), \
             patch.object(self.verifier, "complete_witness_observed", return_value=True):
            final = contract_proof_diagnostics(self.task, self.verifier)["final"]
        self.assertTrue(all(p["complete_proof_observed"] for p in final["omission_probes"]))
        self.assertTrue(all(p["rejection_category"] == "qualified_citation_relevance" for p in final["omission_probes"]))

    def test_enumerated_witness_policy_is_not_reported_as_qualified(self):
        task = runtime_task(self.serving, self.source_report)
        self.verifier.allowed_literals = frozenset({"host.test"})
        diagnostics = contract_proof_diagnostics(task, self.verifier)
        self.assertEqual(diagnostics["final"]["witness_policy"], "enumerated")
        self.assertTrue(diagnostics["final"]["omission_probes"][0]["accepted_by_actual_verifier"])

    def test_native_physical_semantics_reach_both_contract_reviewers(self):
        context = {
            "policy_version": "native-physical-text-semantics-v1",
            "task_fingerprint": fingerprint(self.task), "serving_view_id": self.task.serving_view_id,
            "physical_text_columns": {"DeviceProcessEvents": {"utf8mb4_0900_bin / NO PAD": ["DeviceName"]}},
        }
        review = FinalReview(task_fingerprint=fingerprint(self.task), subject_fingerprint=fingerprint(self.task.private_gold),
                             recommendation="pass", reviewer="fixture", reasons=("Exact physical metadata inspected.",))
        query = call("sql", {"query": "SELECT * FROM DeviceProcessEvents"})
        client = ConfiguredFake([query, call("finish", review.model_dump(mode="json")),
                                 query, call("finish", review.model_dump(mode="json"))])
        output = self.root / "native-context-review"
        output.mkdir()
        self.assertEqual(review_contract(self.task, self.verifier, client, output, None,
                                         native_context=context).status, "pass")
        for role in ("reviewer", "reflection"):
            request = json.loads((output / role / "0000-request.json").read_bytes())
            captured = json.loads(request["messages"][1]["content"])
            self.assertEqual(captured["verified_native_text_semantics"], context)
            self.assertIn("not generic MySQL defaults", request["messages"][0]["content"])
        with self.assertRaisesRegex(ValueError, "another task"):
            review_contract(self.task, self.verifier, client, output, None,
                            native_context={**context, "task_fingerprint": "f" * 64})


class NativeJournalIntegrityTests(unittest.TestCase):
    def test_only_exact_completed_token_waits_fill_missing_response_slots(self):
        from secgym.qagen.agentic.preproduction_admission import _validate_completed_native_journal

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mutations = (
                None,
                lambda p: (p / "0000-error.json").unlink(),
                lambda p: (p / "0001-response.json").unlink(),
                lambda p: (p / "0000-request.json").unlink(),
                lambda p: (p / "0000-tool-results.json").write_text("[]"),
                lambda p: (p / "0002-response.json").write_text("{}"),
                lambda p: (p / "0001-request.json").write_text('{"role":"native-blind","messages":["changed"]}'),
                lambda p: (p / "0000-error.json").write_text('{"status":"error","role":"native-blind","call_index":0}'),
                lambda p: (p / "0000-error.json").write_text(
                    '{"status":"retry_wait","role":"native-blind","call_index":true,"delay_seconds":0}'),
                lambda p: (p / "0000-error.json").write_text(
                    '{"status":"retry_wait","role":"native-blind","call_index":0,"delay_seconds":-1}'),
            )
            for index, mutate in enumerate(mutations):
                role = root / str(index)
                role.mkdir()
                for request in ("0000-request.json", "0001-request.json"):
                    (role / request).write_text('{"role":"native-blind","messages":[],"tools":[]}')
                (role / "0000-error.json").write_text(
                    '{"status":"retry_wait","role":"native-blind","call_index":0,"delay_seconds":0}')
                (role / "0001-response.json").write_text("{}")
                complete = {"role": "native-blind", "calls": 2}
                with self.subTest(case=index):
                    if mutate is None:
                        _validate_completed_native_journal(role, complete)
                    else:
                        mutate(role)
                        with self.assertRaisesRegex(ValueError, "retained native"):
                            _validate_completed_native_journal(role, complete)


class RobustnessSupportContextTests(unittest.TestCase):
    setUp = robustness_tests.RobustnessFixtureTests.setUp
    unchanged = robustness_tests.RobustnessFixtureTests.unchanged
    representation_case = robustness_tests.RobustnessFixtureTests.representation_case

    def captured_contexts(self, task, native_context=None):
        plan = RobustnessPlan(task_fingerprint=fingerprint(task), cases=(self.representation_case(task),))
        review = FinalReview(task_fingerprint=fingerprint(task), subject_fingerprint=fingerprint(plan),
                             recommendation="revise", reviewer="fixture", reasons=("Controlled semantic hold.",))
        query = call("sql", {"query": "SELECT * FROM DeviceProcessEvents"})
        client = ConfiguredFake([query, call("finish", plan.model_dump(mode="json")),
                                 query, call("finish", review.model_dump(mode="json"))])
        output = self.root / "context"
        output.mkdir()
        with patch(MODULE + ".run_robustness", side_effect=AssertionError("a held review must not run measurements")):
            result = robustness_candidate(task, self.verifier, client, output, Path("unused"), self.root,
                                          native_context=native_context)
        self.assertEqual(result.status, "held")
        return [
            json.loads(json.loads((output / role / "0000-request.json").read_bytes())["messages"][1]["content"])
            for role in ("author", "reviewer")
        ]

    def test_qualified_support_has_no_representative_containment_prerequisite(self):
        for context in self.captured_contexts(self.task):
            policy = context["program_support_policies"]["final"]
            self.assertEqual(policy["witness_policy"], "source-qualified-obligations-v1")
            self.assertFalse(policy["representative_group_containment_required"])
            self.assertIn("DIFFERENT support algorithm", context["measurement_semantics"])
            self.assertNotIn("Qualified support additionally executes", context["measurement_semantics"])
            self.assertNotIn("student_outcomes", context)

    def test_verified_physical_collation_reaches_robustness_author_and_reviewer(self):
        native = {
            "policy_version": "native-physical-text-semantics-v1",
            "task_fingerprint": fingerprint(self.task), "serving_view_id": self.task.serving_view_id,
            "physical_text_columns": {"DeviceProcessEvents": {"utf8mb4_0900_bin / NO PAD": ["DeviceName"]}},
        }
        for context in self.captured_contexts(self.task, native):
            self.assertEqual(context["verified_native_text_semantics"], native)
            self.assertIn("not generic MySQL", context["measurement_semantics"])
        client = ConfiguredFake([])
        with self.assertRaisesRegex(ValueError, "another task"):
            robustness_candidate(self.task, self.verifier, client, self.root, Path("unused"), self.root,
                                 native_context={**native, "task_fingerprint": "f" * 64})
        self.assertEqual(client.contexts, [])

    def test_enumerated_support_still_requires_whole_group_containment(self):
        task = runtime_task(self.serving, self.source_report)
        self.verifier.allowed_literals = frozenset({"host.test"})
        reference = task.evidence[0]
        self.citation = PublicCitation(table=reference.table, record_id=reference.public_record_id)
        _, self.row = self.verifier.record_values(self.citation)
        for context in self.captured_contexts(task):
            self.assertEqual(context["program_support_policies"]["final"]["witness_policy"], "enumerated")
            self.assertTrue(context["program_support_policies"]["final"]["representative_group_containment_required"])

    def test_executable_contract_ignores_revision_names_whitespace_and_comments(self):
        final = self.task.private_gold.final
        programs = tuple(p.model_copy(update={"query": p.query + " /* documentation only */",
                                             "program_id": p.program_id + "-renamed"}) for p in reversed(final.programs))
        revised = self.task.model_copy(update={
            "revision_id": "r2", "private_gold": self.task.private_gold.model_copy(update={
                "final": final.model_copy(update={"programs": programs}),
            }),
        })
        self.assertEqual(_executable_contract(self.task), _executable_contract(revised))

    def test_changed_executable_contract_keeps_controls_but_requires_fresh_review(self):
        final = self.task.private_gold.final
        programs = tuple(p.model_copy(update={
            "query": "SELECT CAST(DeviceName AS CHAR) FROM (SELECT DISTINCT CAST(DeviceName AS BINARY) AS DeviceName "
                     "FROM DeviceProcessEvents WHERE ProcessId=43) AS exact_names",
        }) if p.engine == "mysql" else p for p in final.programs)
        revised = self.task.model_copy(update={
            "revision_id": "r2", "private_gold": self.task.private_gold.model_copy(update={
                "final": final.model_copy(update={"programs": programs}),
            }),
        })
        previous = RobustnessPlan(task_fingerprint=fingerprint(self.task), cases=(self.representation_case(),))
        controls = previous.model_copy(update={"task_fingerprint": fingerprint(revised)})
        prior = self.root / "prior"
        prior.mkdir()
        (prior / "proposed-plan.json").write_text(previous.model_dump_json())
        (prior / "review.json").write_text(FinalReview(
            task_fingerprint=fingerprint(self.task), subject_fingerprint=fingerprint(previous),
            recommendation="revise", reviewer="fixture", reasons=("Native exactness needs repair.",),
        ).model_dump_json())
        prepared = self.root / "controls.json"
        prepared.write_text(controls.model_dump_json())
        review = FinalReview(task_fingerprint=fingerprint(revised), subject_fingerprint=fingerprint(controls),
                             recommendation="revise", reviewer="fixture", reasons=("Independent review still required.",))
        client = ConfiguredFake([call("sql", {"query": "SELECT * FROM DeviceProcessEvents"}),
                                 call("finish", review.model_dump(mode="json"))])
        output = self.root / "revised"
        output.mkdir()
        with patch(MODULE + ".run_robustness", side_effect=AssertionError("a held review cannot pass the matrix gate")):
            result = robustness_candidate(
                revised, self.verifier, client, output, Path("unused"), self.root,
                revision_from=prior, prepared_plan=prepared, feedback="Correct the actual native executable contract.",
                recorded_task=self.task,
            )
        self.assertEqual(result.status, "held")
        self.assertFalse((output / "author").exists())
        receipt = json.loads((output / "retained-control-contract-revision.json").read_bytes())
        self.assertFalse(receipt["interventions_and_expectations_changed"])
        self.assertTrue(receipt["fresh_semantic_review_and_backend_measurement_required"])
        self.assertEqual(len(client.contexts), 2)

    def test_revision_identifier_alone_cannot_resample_the_unchanged_control_plan(self):
        revised = self.task.model_copy(update={"revision_id": "r2"})
        previous = RobustnessPlan(task_fingerprint=fingerprint(self.task), cases=(self.representation_case(),))
        prior = self.root / "prior"
        prior.mkdir()
        (prior / "proposed-plan.json").write_text(previous.model_dump_json())
        (prior / "review.json").write_text(FinalReview(
            task_fingerprint=fingerprint(self.task), subject_fingerprint=fingerprint(previous),
            recommendation="revise", reviewer="fixture", reasons=("Unchanged controlled hold.",),
        ).model_dump_json())
        prepared = self.root / "unchanged.json"
        prepared.write_text(previous.model_copy(update={"task_fingerprint": fingerprint(revised)}).model_dump_json())
        output = self.root / "revised"
        output.mkdir()
        client = ConfiguredFake([])
        with self.assertRaisesRegex(ValueError, "resampled unchanged"):
            robustness_candidate(
                revised, self.verifier, client, output, Path("unused"), self.root,
                revision_from=prior, prepared_plan=prepared, feedback="No executable correction.",
                recorded_task=self.task,
            )
        self.assertEqual(client.contexts, [])
        self.assertFalse((output / "retained-control-contract-revision.json").exists())


@unittest.skipUnless(os.environ.get("SECRL_MYSQLD"), "set SECRL_MYSQLD for actual isolated backend measurements")
class PipelineRobustnessTests(unittest.TestCase):
    setUp = robustness_tests.RobustnessFixtureTests.setUp
    unchanged = robustness_tests.RobustnessFixtureTests.unchanged
    representation_case = robustness_tests.RobustnessFixtureTests.representation_case

    def test_semantic_review_precedes_actual_backends_and_completed_measurement_is_reused(self):
        plan = RobustnessPlan(task_fingerprint=fingerprint(self.task), cases=(self.representation_case(),))
        review = FinalReview(task_fingerprint=fingerprint(self.task), subject_fingerprint=fingerprint(plan),
                             recommendation="pass", reviewer="fixture", reasons=("Finite representation control.",))
        query = call("sql", {"query": "SELECT * FROM DeviceProcessEvents"})
        client = ConfiguredFake([query, call("finish", plan.model_dump(mode="json")),
                                 query, call("finish", review.model_dump(mode="json"))])
        output = self.root / "pipeline"
        output.mkdir()
        result = robustness_candidate(self.task, self.verifier, client, output, Path(os.environ["SECRL_MYSQLD"]), self.root)
        self.assertEqual(result.status, "pass")
        before = _json_hashes(output)
        retained = ConfiguredFake([])
        with patch(MODULE + ".run_robustness", side_effect=AssertionError("completed backend matrix rerun")):
            cached = robustness_candidate(self.task, self.verifier, retained, output, Path(os.environ["SECRL_MYSQLD"]), self.root)
        self.assertEqual(cached, result)
        self.assertEqual(retained.contexts, [])
        self.assertEqual(_json_hashes(output), before)
        self.assertEqual(list(self.root.glob(".secrl-robustness-*")), [])

    def test_prepared_correction_preserves_the_held_plan_and_still_requires_fresh_source_review(self):
        case = self.representation_case()
        plan = RobustnessPlan(task_fingerprint=fingerprint(self.task), cases=(case,))
        old = plan.model_copy(update={"cases": (case.model_copy(update={
            "expected": (case.expected[0].model_copy(update={"answer": None}), *case.expected[1:]),
        }),)})
        prior = self.root / "prior"
        prior.mkdir()
        (prior / "proposed-plan.json").write_text(old.model_dump_json())
        (prior / "review.json").write_text(FinalReview(
            task_fingerprint=fingerprint(self.task), subject_fingerprint=fingerprint(old),
            recommendation="revise", reviewer="fixture", reasons=("The representation edit leaves the answer unchanged.",),
        ).model_dump_json())
        before = _json_hashes(prior)
        prepared = self.root / "prepared.json"
        prepared.write_text(plan.model_dump_json())
        review = FinalReview(task_fingerprint=fingerprint(self.task), subject_fingerprint=fingerprint(plan),
                             recommendation="pass", reviewer="independent-fixture", reasons=("Actual source inspected.",))
        client = ConfiguredFake([call("sql", {"query": "SELECT * FROM DeviceProcessEvents"}),
                                 call("finish", review.model_dump(mode="json"))])
        output = self.root / "revised"
        output.mkdir()
        result = robustness_candidate(self.task, self.verifier, client, output, Path(os.environ["SECRL_MYSQLD"]), self.root,
                                       revision_from=prior, prepared_plan=prepared, feedback="Correct only the false null expectation.")
        self.assertEqual(result.status, "pass")
        self.assertEqual(len(client.contexts), 2)
        self.assertFalse((output / "author").exists())
        self.assertEqual(_json_hashes(prior), before)
        self.assertEqual(json.loads((output / "prepared-plan-binding.json").read_bytes())["author_model_calls"], 0)

    def test_goal_equivalent_task_revision_retains_original_controls_and_their_fingerprint(self):
        old_task = self.task
        revised_task = old_task.model_copy(update={"revision_id": "r2"})
        case = self.representation_case()
        prior_plan = RobustnessPlan(task_fingerprint=fingerprint(old_task), cases=(case.model_copy(update={
            "expected": (case.expected[0].model_copy(update={"answer": None}), *case.expected[1:]),
        }),))
        revised_plan = RobustnessPlan(task_fingerprint=fingerprint(revised_task), cases=(case,))
        prior = self.root / "prior-task-plan"
        prior.mkdir()
        (prior / "proposed-plan.json").write_text(prior_plan.model_dump_json())
        (prior / "review.json").write_text(FinalReview(
            task_fingerprint=fingerprint(old_task), subject_fingerprint=fingerprint(prior_plan),
            recommendation="revise", reviewer="fixture", reasons=("The original expectation was incorrect.",),
        ).model_dump_json())
        before = _json_hashes(prior)
        prepared = self.root / "new-task-plan.json"
        prepared.write_text(revised_plan.model_dump_json())
        review = FinalReview(task_fingerprint=fingerprint(revised_task), subject_fingerprint=fingerprint(revised_plan),
                             recommendation="pass", reviewer="fixture", reasons=("The goals and control are unchanged.",))
        client = ConfiguredFake([call("sql", {"query": "SELECT * FROM DeviceProcessEvents"}),
                                 call("finish", review.model_dump(mode="json"))])
        output = self.root / "revised-task-plan"
        output.mkdir()
        result = robustness_candidate(
            revised_task, self.verifier, client, output, Path(os.environ["SECRL_MYSQLD"]), self.root,
            revision_from=prior, prepared_plan=prepared, feedback="Retain the original intervention.",
            recorded_task=old_task,
        )
        self.assertEqual(result.status, "pass")
        self.assertEqual(_json_hashes(prior), before)
        self.assertFalse((output / "author").exists())


@unittest.skipUnless(find_spec("saber") and find_spec("inspect_ai"), "native replay requires SABER/Inspect")
class NativePipelineTests(unittest.TestCase):
    setUp = panel_tests.CapturedAdapterTests.setUp

    def plan(self):
        return PreproductionPlan(
            batch_id="pipeline", serving_view_id=self.task.serving_view_id, graph_id=self.task.graph_version,
            serving_report_sha256="a" * 64, graph_report_sha256="b" * 64,
            native_snapshot_sha256="c" * 64, native_indexes_sha256="d" * 64,
            model=ModelBinding(deployment="gpt-6-sol", endpoint_sha256="e" * 64, api_version="fixture",
                               request_timeout_seconds=300, max_completion_tokens=16000, reasoning_effort=None),
            query_limits=self.engine.limits, grader_timeout_ms=self.engine.limits.timeout_ms, checkpoint_cap=0.5,
            seed_questions=(self.task,), implementation_sha256={"pipeline": "a" * 64},
        )

    def run_native(self, client):
        output = self.root / "native"
        output.mkdir(exist_ok=True)
        with patch(MODULE + ".private_pilot_validation", return_value=self.validation):
            return native_candidate(self.plan(), self.root / "candidate", self.task, self.verifier, self.verifier,
                                    self.engine, client, output, None, self.serving)

    def responses(self, correct=False):
        answer = self.task.private_gold.final.expected.model_dump(mode="json")
        if not correct:
            answer["value"] = "wrong.exe"
        return [call("sql", {"query": self.query}), call("finish", {
            "answer": answer, "citations": self.citations, "confidence": "supported", "explanation": "Controlled native fixture.",
        })]

    def test_failed_grading_retains_completed_unsuccessful_student_for_recovery(self):
        with patch(MODULE + "._native_replay", side_effect=RuntimeError("private grading interrupted")):
            with self.assertRaisesRegex(RuntimeError, "private grading"):
                self.run_native(ConfiguredFake(self.responses()))
        student = self.root / "native/student"
        before = _json_hashes(student)
        retained = ConfiguredFake([])
        self.assertEqual(self.run_native(retained).status, "pass")
        self.assertEqual(_json_hashes(student), before)
        self.assertEqual(retained.contexts, [])
        report = json.loads((self.root / "native/evaluation_report.json").read_bytes())
        self.assertFalse(report["student_grounded_success"])
        self.assertEqual(len(list((self.root / "native/grading-attempts").iterdir())), 2)

    def test_publish_interruption_reuses_completed_replay_without_regrading(self):
        from secgym.qagen.agentic.model_panel import immutable_json

        def interrupted(path, value):
            if path == self.root / "native/acesevals.json":
                raise OSError("publication interrupted")
            return immutable_json(path, value)

        with patch(MODULE + ".immutable_json", side_effect=interrupted):
            with self.assertRaisesRegex(OSError, "publication interrupted"):
                self.run_native(ConfiguredFake(self.responses(correct=True)))
        before = _json_hashes(self.root / "native/student")
        retained = ConfiguredFake([])
        with patch(MODULE + "._native_replay", side_effect=AssertionError("completed replay executed again")):
            self.assertEqual(self.run_native(retained).status, "pass")
        self.assertEqual(retained.contexts, [])
        self.assertEqual(_json_hashes(self.root / "native/student"), before)
        self.assertTrue(json.loads((self.root / "native/evaluation_report.json").read_bytes())["student_grounded_success"])

    def test_student_abstention_is_preserved_as_a_complete_measured_outcome(self):
        client = ConfiguredFake([call("abstain", {"reason": "Insufficient confidence in this fixture."})])
        self.assertEqual(self.run_native(client).status, "pass")
        before = _json_hashes(self.root / "native/student")
        self.assertEqual(self.run_native(ConfiguredFake([])).status, "pass")
        self.assertEqual(_json_hashes(self.root / "native/student"), before)
        report = json.loads((self.root / "native/evaluation_report.json").read_bytes())
        self.assertTrue(report["student_abstained"])
        self.assertFalse(report["student_grounded_success"])

    def test_continuation_tracks_original_student_through_verified_native_replay(self):
        from secgym.qagen.agentic.preproduction_pipeline import _native_student_roots

        fixture = self.retained_fixture()
        run, plan, task, retained = fixture
        _, native = self.replay_retained(fixture)
        before = _json_hashes(Path(retained.parent_pipeline))
        self.assertEqual(_native_student_roots(plan, task, run, native), {
            (native / "student").resolve(), (Path(retained.parent_pipeline) / "native/student").resolve(),
        })
        self.assertEqual(_json_hashes(Path(retained.parent_pipeline)), before)
        self.assertFalse((native / "student").exists())
        certificate = native / "retained-student.json"
        altered = json.loads(certificate.read_bytes())
        altered["plan_fingerprint"] = "f" * 64
        certificate.write_text(json.dumps(altered))
        with self.assertRaisesRegex(ValueError, "task, plan or source artifacts"):
            _native_student_roots(plan, task, run, native)

    def test_explicit_interrupted_native_prefix_import_preserves_student_and_error_history(self):
        from secgym.qagen.agentic.preproduction_admission import record_native_prefix_import_authorization

        fixture = self.retained_fixture()
        run, plan, task, retained = fixture
        parent = Path(retained.parent_pipeline)
        (run / "plan.json").write_text(plan.model_dump_json())
        (parent / "pipeline-report.json").unlink()
        errors = parent / "robustness/errors"
        errors.mkdir(parents=True)
        (errors / "0000.json").write_text(json.dumps({
            "status": "operational_error", "detail": "counterfactual expects unknown source witnesses",
        }))
        before = _json_hashes(parent)
        refreshed = retained.model_copy(update={"source_artifacts_sha256": native_import_artifacts(
            run, task.task_id, parent, Path(retained.recorded_task), Path(retained.runtime_archive),
        )})
        with self.assertRaises(FileNotFoundError):
            self.replay_retained((run, plan, task, refreshed))
        authorization = record_native_prefix_import_authorization(
            plan, run, parent, archive=Path(retained.runtime_archive),
            reason="Controlled interrupted robustness annotation; retain the exact completed native episode.",
        )
        self.assertFalse(authorization.question_admitted)
        refreshed = retained.model_copy(update={"source_artifacts_sha256": native_import_artifacts(
            run, task.task_id, parent, Path(retained.recorded_task), Path(retained.runtime_archive),
        )})
        result, output = self.replay_retained((run, plan, task, refreshed))
        self.assertEqual(result.status, "pass")
        self.assertFalse((parent / "pipeline-report.json").exists())
        self.assertFalse((output / "student").exists())
        self.assertEqual({name: file_sha256(parent / name) for name in before}, before)
        (errors / "0000.json").write_text('{"status":"changed"}')
        changed = refreshed.model_copy(update={"source_artifacts_sha256": native_import_artifacts(
            run, task.task_id, parent, Path(retained.recorded_task), Path(retained.runtime_archive),
        )})
        with self.assertRaisesRegex(ValueError, "interrupted native prefix changed"):
            self.replay_retained((run, plan, task, changed))

    def test_prefix_authorization_cannot_replace_a_completed_pipeline(self):
        from secgym.qagen.agentic.preproduction_admission import record_native_prefix_import_authorization

        run, plan, _, retained = self.retained_fixture()
        (run / "plan.json").write_text(plan.model_dump_json())
        with self.assertRaisesRegex(ValueError, "completed pipeline"):
            record_native_prefix_import_authorization(
                plan, run, Path(retained.parent_pipeline), archive=Path(retained.runtime_archive),
                reason="Not eligible: completed parent must use normal retained import.",
            )

    def test_prefix_authorization_rejects_an_active_candidate(self):
        import fcntl
        from secgym.qagen.agentic.preproduction_admission import record_native_prefix_import_authorization

        run, plan, _, retained = self.retained_fixture()
        parent = Path(retained.parent_pipeline)
        (run / "plan.json").write_text(plan.model_dump_json())
        (parent / "pipeline-report.json").unlink()
        with (parent.parent.parent / "candidate-pipeline.lock").open("a+") as owner:
            fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(ValueError, "active candidate"):
                record_native_prefix_import_authorization(
                    plan, run, parent, archive=Path(retained.runtime_archive),
                    reason="An active candidate must not be certified as interrupted.",
                )
        self.assertFalse((parent / "native-prefix-import-authorization.json").exists())

    def test_prefix_authorization_requires_a_recorded_operational_interruption(self):
        from secgym.qagen.agentic.preproduction_admission import record_native_prefix_import_authorization

        run, plan, _, retained = self.retained_fixture()
        parent = Path(retained.parent_pipeline)
        (run / "plan.json").write_text(plan.model_dump_json())
        (parent / "pipeline-report.json").unlink()
        with self.assertRaisesRegex(ValueError, "recorded downstream operational interruption"):
            record_native_prefix_import_authorization(
                plan, run, parent, archive=Path(retained.runtime_archive),
                reason="An absent pipeline report alone is not interruption evidence.",
            )
        self.assertFalse((parent / "native-prefix-import-authorization.json").exists())

    def test_prefix_authorization_rejects_an_incomplete_native_stage(self):
        from secgym.qagen.agentic.preproduction_admission import record_native_prefix_import_authorization

        run, plan, _, retained = self.retained_fixture()
        parent = Path(retained.parent_pipeline)
        (run / "plan.json").write_text(plan.model_dump_json())
        (parent / "pipeline-report.json").unlink()
        errors = parent / "robustness/errors"
        errors.mkdir(parents=True)
        (errors / "0000.json").write_text('{"status":"operational_error","detail":"Controlled interruption."}')
        receipt_path = parent / "native/stage-receipt.json"
        receipt = json.loads(receipt_path.read_bytes())
        receipt["result"]["status"] = "held"
        receipt_path.write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, "exact completed native stage"):
            record_native_prefix_import_authorization(
                plan, run, parent, archive=Path(retained.runtime_archive),
                reason="An interrupted later stage cannot substitute for completed native validation.",
            )
        self.assertFalse((parent / "native-prefix-import-authorization.json").exists())

    def test_completed_student_tampering_blocks_grading_without_inference(self):
        self.run_native(ConfiguredFake(self.responses()))
        path = self.root / "native/student/result.json"
        path.write_text(path.read_text() + " ")
        with self.assertRaisesRegex(ValueError, "student trace changed"):
            self.run_native(ConfiguredFake([]))

    def retained_fixture(self, *, correct=True, failed_query=False, abstained=False, rate_limited=False):
        plan = self.plan()
        responses = self.responses(correct=correct)
        if failed_query:
            responses[0] = call("sql", {"query": "SELECT MissingColumn FROM DeviceProcessEvents"})
        if abstained:
            responses = [call("abstain", {"reason": "Retained abstention."})]
        client = ConfiguredFake(responses)
        if rate_limited:
            with patch.object(client, "complete", wraps=client.complete, side_effect=[
                RetryableCompletionError("Controlled token-rate limit.", delay_seconds=0), *([DEFAULT] * len(responses)),
            ]):
                self.assertEqual(self.run_native(client).status, "pass")
        else:
            self.assertEqual(self.run_native(client).status, "pass")
        run = self.root / "run"
        parent = run / "attempts" / self.task.task_id / "pipeline/r1"
        parent.mkdir(parents=True)
        (self.root / "native").rename(parent / "native")
        recorded = run / "attempts" / self.task.task_id / "source/task.json"
        recorded.parent.mkdir()
        recorded.write_text(self.task.model_dump_json())
        files = (*NATIVE_RUNTIME_FILES, "pilot.py", "model_panel.py", "preproduction_pipeline.py")
        implementation = {name: file_sha256(admission_tests.MODULES / name) for name in files}
        binding = {
            "version": "fixture", "task_fingerprint": fingerprint(self.task), "plan_fingerprint": fingerprint(plan),
            "implementation_sha256": implementation, "grading_policy_fingerprint": None,
        }
        (parent / "binding.json").write_text(json.dumps(binding))
        run_stage(parent / "native", {"pipeline": binding}, lambda path: StageResult(status="pass", reason="Completed native fixture."))
        (parent / "pipeline-report.json").write_text(json.dumps({
            "status": "held", "stage": "robustness", "task_fingerprint": fingerprint(self.task),
            "stage_receipts": {"native": file_sha256(parent / "native/stage-receipt.json")},
            "artifacts_sha256": _json_hashes(parent),
        }))
        archive = run / "native-producer.zip"
        with zipfile.ZipFile(archive, "x") as saved:
            for name in files:
                saved.write(admission_tests.MODULES / name, name)
        revised = self.task.model_copy(update={"revision_id": "r2"})
        retained = NativeStudentImport(
            task_fingerprint=fingerprint(revised), recorded_task_fingerprint=fingerprint(self.task),
            plan_fingerprint=fingerprint(plan), parent_pipeline=str(parent), recorded_task=str(recorded),
            runtime_archive=str(archive),
            source_artifacts_sha256=native_import_artifacts(run, self.task.task_id, parent, recorded, archive),
        )
        return run, plan, revised, retained

    def replay_retained(self, fixture):
        run, plan, task, retained = fixture
        output = run / "attempts" / task.task_id / "pipeline/r2/native"
        output.mkdir(parents=True, exist_ok=True)
        validation = self.validation.model_copy(update={"task_fingerprint": fingerprint(task)})
        client = ConfiguredFake([])
        with patch(MODULE + ".private_pilot_validation", return_value=validation) as validate, \
             patch(MODULE + ".run_role", side_effect=AssertionError("retained student was rerolled")):
            result = native_candidate(plan, self.root / "candidate", task, self.verifier, self.verifier,
                                      self.engine, client, output, None, self.serving, retained_student=retained, run=run)
        self.assertEqual(validate.call_count, 1)
        self.assertEqual(client.contexts, [])
        self.assertFalse((output / "student").exists())
        return result, output

    def test_goal_equivalent_revision_revalidates_and_replays_without_student_inference(self):
        fixture = self.retained_fixture()
        before = _json_hashes(Path(fixture[3].parent_pipeline))
        result, output = self.replay_retained(fixture)
        self.assertEqual(result.status, "pass")
        self.assertEqual(_json_hashes(Path(fixture[3].parent_pipeline)), before)
        report = json.loads((output / "evaluation_report.json").read_bytes())
        self.assertTrue(report["retained_native_student"])
        self.assertTrue(report["student_grounded_success"])
        self.assertEqual(report["task_fingerprint"], fingerprint(fixture[2]))

    def test_retained_native_token_wait_is_not_a_missing_response_or_new_student(self):
        fixture = self.retained_fixture(rate_limited=True)
        parent = Path(fixture[3].parent_pipeline)
        role = parent / "native/student"
        self.assertEqual(json.loads((role / "complete.json").read_bytes())["calls"], 3)
        self.assertEqual(len(list(role.glob("*-response.json"))), 2)
        before = _json_hashes(parent)
        result, output = self.replay_retained(fixture)
        self.assertEqual(result.status, "pass")
        self.assertEqual(_json_hashes(parent), before)
        self.assertFalse((output / "student").exists())

    def test_retained_failed_sql_is_not_reexecuted_or_credited(self):
        fixture = self.retained_fixture(failed_query=True)
        original = self.engine.execute

        def execute(query, **kwargs):
            if "MissingColumn" in query:
                self.fail("failed student SQL was rerun")
            return original(query, **kwargs)

        def captured(*args, **kwargs):
            self.assertTrue(any(isinstance(action.result, QueryFailure) for action in args[3] if action.kind == "sql"))
            return _native_replay(*args, **kwargs)

        with patch.object(self.engine, "execute", side_effect=execute), patch(MODULE + "._native_replay", side_effect=captured):
            result, output = self.replay_retained(fixture)
        self.assertEqual(result.status, "pass")
        self.assertFalse(json.loads((output / "evaluation_report.json").read_bytes())["student_grounded_success"])

    def test_imported_native_stage_cannot_be_reopened_without_its_import_arguments(self):
        fixture = self.retained_fixture()
        _, output = self.replay_retained(fixture)
        run, plan, task, _ = fixture
        with patch(MODULE + ".private_pilot_validation") as validation, \
             patch(MODULE + ".run_role", side_effect=AssertionError("imported student was rerolled")):
            with self.assertRaisesRegex(ValueError, "explicit retained-student import"):
                native_candidate(plan, self.root / "candidate", task, self.verifier, self.verifier,
                                 self.engine, ConfiguredFake([]), output, None, self.serving, run=run)
        validation.assert_not_called()

    def test_retained_abstention_and_interrupted_grading_never_reroll(self):
        fixture = self.retained_fixture(abstained=True)
        with patch(MODULE + "._native_replay", side_effect=RuntimeError("interrupted imported replay")):
            with self.assertRaisesRegex(RuntimeError, "interrupted imported replay"):
                self.replay_retained(fixture)
        result, output = self.replay_retained(fixture)
        self.assertEqual(result.status, "pass")
        self.assertTrue(json.loads((output / "evaluation_report.json").read_bytes())["student_abstained"])

    def test_retained_import_rejects_changed_goals_source_trace_and_archive(self):
        run, plan, task, retained = self.retained_fixture()
        variants = (
            task.model_copy(update={"question": task.question + " Return extra facts."}),
            task.model_copy(update={"reward_policy": task.reward_policy.model_copy(update={"checkpoint_cap": 0.4})}),
            task.model_copy(update={"private_gold": task.private_gold.model_copy(update={
                "final": task.private_gold.final.model_copy(update={
                    "expected": task.private_gold.final.expected.model_copy(update={"value": "different.exe"}),
                }),
            })}),
        )
        for changed in variants:
            certificate = retained.model_copy(update={"task_fingerprint": fingerprint(changed)})
            with self.assertRaises(ValueError):
                validate_native_import(certificate, plan, changed, run)
        altered_plan = plan.model_copy(update={"model": plan.model.model_copy(update={"request_timeout_seconds": 400})})
        with self.assertRaises(ValueError):
            validate_native_import(retained.model_copy(update={"plan_fingerprint": fingerprint(altered_plan)}), altered_plan, task, run)
        path = Path(retained.parent_pipeline) / "native/student/result.json"
        original = path.read_bytes()
        path.write_bytes(original + b" ")
        with self.assertRaisesRegex(ValueError, "source artifacts changed"):
            validate_native_import(retained, plan, task, run)
        path.write_bytes(original)
        archive = Path(retained.runtime_archive)
        archive.write_bytes(archive.read_bytes() + b"changed")
        with self.assertRaisesRegex(ValueError, "source artifacts changed"):
            validate_native_import(retained, plan, task, run)


if __name__ == "__main__":
    unittest.main()
