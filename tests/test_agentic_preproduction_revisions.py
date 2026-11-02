# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import ast
import hashlib
import json
from pathlib import Path
import zipfile
from unittest import TestCase
from unittest.mock import patch

import test_agentic_preproduction as source_tests
from secgym.qagen.agentic.contracts import TaskRecord, fingerprint
from secgym.qagen.agentic.ledger import file_sha256
from secgym.qagen.agentic.preproduction import SourceOutcome, _artifacts, source_progress
from secgym.qagen.agentic.preproduction_revisions import (
    SourceRevision, current_source, effective_runtime, record_runtime_amendment, run_source_revision,
    validate_source_audit_runtime, _validate_empty_array_change, EMPTY_ARRAY_AMENDMENT,
)


MODULES = Path(__file__).resolve().parents[1] / "secgym/qagen/agentic"


def legacy_canonical_source(current):
    tree = ast.parse(current)
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "FactKind":
            node.value = ast.parse('Literal["property_value", "json_member_presence"]', mode="eval").body
        if isinstance(node, ast.FunctionDef) and node.name in ("source_leaf", "presence_path", "atomic_value"):
            node.body = [statement for statement in node.body if not (
                isinstance(statement, ast.If) and "json_array_empty_v1" in ast.unparse(statement.test)
            )]
    return ast.unparse(tree).encode()


class SourceRevisionTests(TestCase):
    setUp = source_tests.PreproductionTests.setUp
    wave = source_tests.PreproductionTests.wave
    runner = source_tests.PreproductionTests.runner

    def held(self, runner=None):
        self.wave(1, runner=runner or self.runner)
        task_id = self.calls[-1]["task_id"]
        return task_id, self.output / "attempts" / task_id / "source"

    def repaired_runner(self, **kwargs):
        old = TaskRecord.model_validate_json((kwargs["revision_from"] / "task.json").read_bytes())
        data = old.model_dump(mode="json")
        data["revision_id"] = "r4"
        data["question"] += " Exact public alert title."
        data["scope"]["relevance_rationale"] += " Wording clarified."
        task = TaskRecord.model_validate_json(json.dumps(data))
        kwargs["output"].mkdir(parents=True, exist_ok=kwargs["resume"])
        (kwargs["output"] / "task.json").write_text(task.model_dump_json())
        result = {"status": "candidate_for_mysql_validation", "task_fingerprint": fingerprint(task)}
        (kwargs["output"] / "pilot_report.json").write_text(json.dumps(result))
        return result

    def revise(self, task_id, **kwargs):
        return run_source_revision(plan=self.plan, client=self.client, serving_bundle=self.serving,
                                   graph_bundle=self.graph, output=self.output, task_id=task_id,
                                   feedback="Publish the exact public alert title; preserve all final/checkpoint goals.",
                                   runner=kwargs.pop("runner", self.repaired_runner), **kwargs)

    def test_revision_counts_once_preserves_history_and_updates_the_current_source(self):
        task_id, original = self.held()
        before = {path: file_sha256(path) for path in original.rglob("*.json")}
        old_outcome = file_sha256(original.parent / "source-outcome.json")
        with patch("secgym.qagen.agentic.quality.validate_quality_gate"):
            result = self.revise(task_id)
        self.assertEqual(result.status, "source_ready")
        latest, stored, count = current_source(self.plan, self.output, task_id)
        self.assertEqual(latest, (original.parent / "revisions/0001/source").resolve())
        self.assertEqual(stored, result)
        self.assertEqual(count, 1)
        self.assertEqual(file_sha256(original.parent / "source-outcome.json"), old_outcome)
        self.assertEqual({path: file_sha256(path) for path in before}, before)
        report = source_progress(self.plan, self.output)
        self.assertEqual(report["logical_attempts_started"], 1)
        self.assertEqual(report["source_ready"], 1)
        self.assertEqual(report["validated_new_questions"], 0)
        self.assertEqual(report["buckets"]["incident:5"]["source_revisions"], 1)
        self.assertEqual(report["buckets"]["incident:5"]["historical_quality_holds"], 1)

    def test_revised_tuple_report_matches_the_same_saved_json_representation(self):
        task_id, _ = self.held()

        def tuple_report(**kwargs):
            report = self.repaired_runner(**kwargs)
            report["mechanical_release_blockers"] = ("split_review: missing", "release_review: missing")
            (kwargs["output"] / "pilot_report.json").write_text(json.dumps(report))
            return report

        with patch("secgym.qagen.agentic.quality.validate_quality_gate"):
            result = self.revise(task_id, runner=tuple_report)
        self.assertEqual(result.status, "source_ready")
        self.assertEqual(source_progress(self.plan, self.output)["logical_attempts_started"], 1)

    def test_new_attempts_receive_the_current_revised_novelty_context(self):
        task_id, _ = self.held()
        with patch("secgym.qagen.agentic.quality.validate_quality_gate"):
            self.revise(task_id)
        self.wave(11, resume=True)
        self.assertEqual(self.calls[-1]["incident_id"], 5)
        self.assertIn("Exact public alert title.", self.calls[-1]["prior_questions"][0])

    def test_started_student_is_never_rerolled_for_a_quality_repair(self):
        def held_with_student(**kwargs):
            report = self.runner(**kwargs)
            (kwargs["output"] / "blind").mkdir()
            (kwargs["output"] / "blind/0000-request.json").write_text("{}")
            return report

        task_id, _ = self.held(held_with_student)
        with patch.object(self, "repaired_runner") as generator:
            with self.assertRaisesRegex(ValueError, "never reroll"):
                self.revise(task_id, runner=generator)
            generator.assert_not_called()

    def test_retained_source_student_certificate_also_prevents_automatic_reroll(self):
        def held_with_retained_student(**kwargs):
            report = self.runner(**kwargs)
            (kwargs["output"] / "retained-source-student.json").write_text('{"source_directory":"retained"}')
            return report

        task_id, _ = self.held(held_with_retained_student)
        with patch.object(self, "repaired_runner") as generator:
            with self.assertRaisesRegex(ValueError, "never reroll"):
                self.revise(task_id, runner=generator)
            generator.assert_not_called()

    def test_preserved_goal_change_is_retained_as_an_error_not_an_accepted_repair(self):
        task_id, _ = self.held()
        def changed_goal(**kwargs):
            result = self.repaired_runner(**kwargs)
            path = kwargs["output"] / "task.json"
            data = json.loads(path.read_bytes())
            data["private_gold"]["final"]["expected"]["value"] = "different.exe"
            path.write_text(json.dumps(data))
            return result

        with self.assertRaisesRegex(RuntimeError, "preserved"):
            self.revise(task_id, runner=changed_goal)
        report = source_progress(self.plan, self.output)
        self.assertEqual(report["logical_attempts_started"], 1)
        self.assertEqual(report["buckets"]["incident:5"]["operational_errors"], 1)
        self.assertEqual(report["source_ready"], 0)
        source, outcome, _ = current_source(self.plan, self.output, task_id)
        self.assertEqual(outcome.task_fingerprint, fingerprint(TaskRecord.model_validate_json((source / "task.json").read_bytes())))

    def test_compiled_goal_change_stops_before_another_model_call(self):
        task_id, _ = self.held()

        def changed_objective(**kwargs):
            self.repaired_runner(**kwargs)
            path = kwargs["output"] / "task.json"
            data = json.loads(path.read_bytes())
            data["private_gold"]["checkpoints"][0]["objective"] += " Paraphrased."
            path.write_text(json.dumps(data))
            kwargs["client"].complete([], [])
            self.fail("goal mismatch must stop before any reviewer or blind inference")

        with patch.object(self.client, "complete", create=True) as inference:
            with self.assertRaisesRegex(RuntimeError, "preserved"):
                self.revise(task_id, runner=changed_objective)
            inference.assert_not_called()
        source, outcome, _ = current_source(self.plan, self.output, task_id)
        self.assertEqual(outcome.status, "operational_error")
        self.assertEqual(outcome.task_fingerprint, fingerprint(TaskRecord.model_validate_json((source / "task.json").read_bytes())))
        self.assertFalse((source / "blind").exists())

    def test_legacy_unbound_error_recovery_is_explicit_and_never_rewrites_the_error(self):
        task_id, original = self.held()
        path = original.parent / "source-outcome.json"
        outcome = SourceOutcome.model_validate_json(path.read_bytes()).model_copy(update={
            "status": "operational_error", "task_fingerprint": None, "reason": "Controlled legacy unbound-error fixture.",
        })
        path.write_text(outcome.model_dump_json())
        before = path.read_bytes()
        old = TaskRecord.model_validate_json((original / "task.json").read_bytes())
        folder = original.parent / "revisions/0001"
        source = folder / "source"
        self.repaired_runner(revision_from=original, output=source, resume=False)
        task = TaskRecord.model_validate_json((source / "task.json").read_bytes())
        revised = outcome.model_copy(update={
            "status": "needs_revision", "task_fingerprint": fingerprint(task), "artifact_sha256": _artifacts(source),
        })
        (folder / "source-outcome.json").write_text(revised.model_dump_json())
        request = folder / "request.json"
        request.write_text('{"recovering_unbound_operational_task":false}')

        def receipt(previous_fp):
            value = SourceRevision(
                plan_fingerprint=fingerprint(self.plan), task_id=task_id, sequence=1,
                previous_source=str(original.relative_to(self.output)), previous_outcome_sha256=file_sha256(path),
                previous_task_fingerprint=previous_fp, source_directory=str(source.relative_to(self.output)),
                source_outcome_sha256=file_sha256(folder / "source-outcome.json"), request_sha256=file_sha256(request),
            )
            (folder / "revision.json").write_text(value.model_dump_json())

        receipt(fingerprint(old))
        with self.assertRaisesRegex(ValueError, "explicit recovery"):
            current_source(self.plan, self.output, task_id)
        request.write_text('{"recovering_unbound_operational_task":true}')
        receipt("0" * 64)
        with self.assertRaisesRegex(ValueError, "preceding task"):
            current_source(self.plan, self.output, task_id)
        receipt(fingerprint(old))
        current, stored, sequence = current_source(self.plan, self.output, task_id)
        self.assertEqual((current, stored, sequence), (source.resolve(), revised, 1))
        self.assertEqual(path.read_bytes(), before)

    def test_revised_outcome_tampering_is_detected_before_another_wave(self):
        task_id, _ = self.held()
        with patch("secgym.qagen.agentic.quality.validate_quality_gate"):
            self.revise(task_id)
        path = self.output / "attempts" / task_id / "revisions/0001/source-outcome.json"
        path.write_text(path.read_text() + " ")
        with self.assertRaisesRegex(ValueError, "outcome changed"):
            source_progress(self.plan, self.output)

    def test_only_archived_orchestration_changes_can_amend_runtime(self):
        self.held()
        archive = self.output / "runtime.zip"
        with zipfile.ZipFile(archive, "x") as saved:
            for name in self.plan.implementation_sha256:
                saved.write(MODULES / name, arcname=name)
        updated = {**self.plan.implementation_sha256, "preproduction.py": "a" * 64}
        with patch("secgym.qagen.agentic.preproduction_revisions.runtime_hashes", return_value=updated):
            record_runtime_amendment(self.plan, self.output, archive=archive, reason="Controlled orchestration-only fixture.")
        self.assertEqual(effective_runtime(self.plan, self.output), updated)
        path = self.output / "runtime-amendments/0000.json"
        value = json.loads(path.read_bytes())
        value["current_runtime_sha256"]["evidence.py"] = "0" * 64
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "cannot change"):
            effective_runtime(self.plan, self.output)

    def test_annotation_context_amendment_preserves_source_audit_without_changing_curation_logic(self):
        task_id, candidate = self.held()
        task = TaskRecord.model_validate_json((candidate / "task.json").read_bytes())
        before, after = self.output / "before.zip", self.output / "after.zip"
        updated = dict(self.plan.implementation_sha256)
        with zipfile.ZipFile(before, "x") as old, zipfile.ZipFile(after, "x") as new:
            for name in updated:
                data = (MODULES / name).read_bytes()
                old.writestr(name, data)
                if name == "difficulty_curation.py":
                    data = data.replace(b"difficulty-feature-curation-v0.4", b"difficulty-feature-curation-v0.5")
                    updated[name] = hashlib.sha256(data).hexdigest()
                new.writestr(name, data)
        from secgym.qagen.agentic.quality import runtime_hashes as source_hashes
        recorded = source_hashes()
        current_source_hashes = {name: updated[name] for name in recorded}
        with patch("secgym.qagen.agentic.preproduction_revisions.runtime_hashes", return_value=updated), \
             patch("secgym.qagen.agentic.quality.runtime_hashes", return_value=current_source_hashes):
            amendment = record_runtime_amendment(self.plan, self.output, archive=before, current_archive=after,
                                                  reason="Controlled context-only version update.")
            self.assertEqual(amendment.policy_version, "preproduction-annotation-context-amendment-v2")
            validate_source_audit_runtime(candidate, task, recorded)
            with self.assertRaisesRegex(ValueError, "explicit revalidation"):
                validate_source_audit_runtime(candidate, task, {**recorded, "evidence.py": "f" * 64})
        self.assertEqual(task.task_id, task_id)
        with after.open("ab") as stream:
            stream.write(b"tamper")
        with self.assertRaisesRegex(ValueError, "updated annotation producer changed"):
            effective_runtime(self.plan, self.output)

    def test_context_amendment_cannot_change_curation_validation(self):
        self.held()
        before, after = self.output / "before.zip", self.output / "after.zip"
        updated = dict(self.plan.implementation_sha256)
        with zipfile.ZipFile(before, "x") as old, zipfile.ZipFile(after, "x") as new:
            for name in updated:
                data = (MODULES / name).read_bytes()
                old.writestr(name, data)
                if name == "difficulty_curation.py":
                    data = data.replace(b"question = SplitQuestion.model_validate(question)", b"question = question")
                    updated[name] = hashlib.sha256(data).hexdigest()
                new.writestr(name, data)
        with patch("secgym.qagen.agentic.preproduction_revisions.runtime_hashes", return_value=updated):
            with self.assertRaisesRegex(ValueError, "curation or measurement kernels"):
                record_runtime_amendment(self.plan, self.output, archive=before, current_archive=after,
                                         reason="Invalid validation change.")
        self.assertFalse(any((self.output / "runtime-amendments").glob("*.json")))

    def test_empty_array_amendment_preserves_exact_legacy_source_audits(self):
        _, candidate = self.held()
        task = TaskRecord.model_validate_json((candidate / "task.json").read_bytes())
        before, after = self.output / "before-empty.zip", self.output / "after-empty.zip"
        previous = dict(self.plan.implementation_sha256)
        with zipfile.ZipFile(before, "x") as old, zipfile.ZipFile(after, "x") as new:
            for name in previous:
                data = (MODULES / name).read_bytes()
                new.writestr(name, data)
                if name == "canonical_facts.py":
                    data = legacy_canonical_source(data)
                elif name == "fact_curation.py":
                    data = data.replace(b"source-fact-curation-v1.2", b"source-fact-curation-v1.1")
                old.writestr(name, data)
                previous[name] = hashlib.sha256(data).hexdigest()
        self.plan = self.plan.model_copy(update={"implementation_sha256": previous})
        (self.output / "plan.json").write_text(self.plan.model_dump_json())
        with self.assertRaisesRegex(ValueError, "both exact"):
            record_runtime_amendment(self.plan, self.output, archive=before, empty_array_facts=True,
                                     reason="Missing current archive.")
        amendment = record_runtime_amendment(
            self.plan, self.output, archive=before, current_archive=after, empty_array_facts=True,
            reason="Exact additive empty-array structural observation, preserving legacy resolution and identity.",
        )
        self.assertEqual(amendment.policy_version, EMPTY_ARRAY_AMENDMENT)
        from secgym.qagen.agentic.quality import runtime_hashes as source_hashes
        recorded = {name: previous[name] for name in source_hashes()}
        validate_source_audit_runtime(candidate, task, recorded)
        with self.assertRaisesRegex(ValueError, "historical producer"):
            validate_source_audit_runtime(candidate, task, {**recorded, "canonical_facts.py": "f" * 64})
        from secgym.qagen.agentic.preproduction_pipeline import _canonical_abstention_extension, _json_hashes
        parent = candidate.parent / "pipeline/unsupported"
        canonical = parent / "canonical"
        (canonical / "curator").mkdir(parents=True)
        binding = {
            "task_fingerprint": fingerprint(task), "curation_version": "source-fact-curation-v1.1",
            "implementation_sha256": previous,
        }
        (canonical / "binding.json").write_text(json.dumps(binding))
        (canonical / "curator/abstention.json").write_text(json.dumps({
            "status": "no_supported_result", "role": "fact-curator", "reason": "Empty array has no scalar leaf.",
        }))
        (parent / "pipeline-report.json").write_text(json.dumps({
            "status": "held", "stage": "canonical", "task_fingerprint": fingerprint(task),
            "artifacts_sha256": _json_hashes(parent),
        }))
        destination = parent.parent / "extended/canonical"
        context = _canonical_abstention_extension(canonical, binding, destination)
        self.assertEqual(context["approved_annotation_extension"], EMPTY_ARRAY_AMENDMENT)
        self.assertEqual(_canonical_abstention_extension(canonical, binding, destination), context)
        with self.assertRaisesRegex(ValueError, "immutable"):
            _canonical_abstention_extension(canonical, binding, parent.parent / "resampled/canonical")
        with self.assertRaisesRegex(ValueError, "original unsupported"):
            _canonical_abstention_extension(canonical, {**binding, "curation_version": "source-fact-curation-v1.2"}, destination)
        with self.assertRaisesRegex(ValueError, "exact additive"):
            _canonical_abstention_extension(canonical, {
                **binding, "implementation_sha256": {**previous, "canonical_facts.py": "f" * 64},
            }, destination)
        with after.open("ab") as stream:
            stream.write(b"changed")
        with self.assertRaisesRegex(ValueError, "updated annotation producer"):
            effective_runtime(self.plan, self.output)

    def test_empty_array_amendment_cannot_change_old_semantics_or_weaken_the_new_guard(self):
        current = (MODULES / "canonical_facts.py").read_bytes()
        previous = legacy_canonical_source(current)
        _validate_empty_array_change("canonical_facts.py", previous, current)
        for before, after in (
            (b"weight=1.0", b"weight=2.0"),
            (b'FACT_VERSION = "canonical-source-facts-v2"', b'FACT_VERSION = "canonical-source-facts-v3"'),
            (b'        return "true"', b'        return "false"'),
            (b"if not isinstance(observed, list) or observed:", b"if not isinstance(observed, list):"),
        ):
            changed = current.replace(before, after)
            self.assertNotEqual(changed, current)
            with self.subTest(change=before), self.assertRaises(ValueError):
                _validate_empty_array_change("canonical_facts.py", previous, changed)
        curation = (MODULES / "fact_curation.py").read_bytes()
        old = curation.replace(b"source-fact-curation-v1.2", b"source-fact-curation-v1.1")
        with self.assertRaisesRegex(ValueError, "curation kernels"):
            _validate_empty_array_change(
                "fact_curation.py", old, curation.replace(b"validation.pilot_blockers(task)", b"()"),
            )

    def test_wrong_archive_cannot_rebind_the_original_producer(self):
        self.held()
        archive = self.output / "runtime.zip"
        with zipfile.ZipFile(archive, "x") as saved:
            for name in self.plan.implementation_sha256:
                saved.writestr(name, "not the original producer")
        updated = {**self.plan.implementation_sha256, "preproduction.py": "a" * 64}
        with patch("secgym.qagen.agentic.preproduction_revisions.runtime_hashes", return_value=updated):
            with self.assertRaisesRegex(ValueError, "exact previous"):
                record_runtime_amendment(self.plan, self.output, archive=archive, reason="Invalid fixture.")
