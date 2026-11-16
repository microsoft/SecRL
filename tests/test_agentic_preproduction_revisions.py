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
from secgym.qagen.agentic.difficulty_curation import CURATION_VERSION
from secgym.qagen.agentic.ledger import file_sha256
from secgym.qagen.agentic.preproduction import SourceOutcome, _artifacts, source_progress
from secgym.qagen.agentic.preproduction_revisions import (
    SourceRevision, current_source, effective_runtime, record_runtime_amendment, run_source_revision,
    validate_source_audit_runtime, _validate_empty_array_change, EMPTY_ARRAY_AMENDMENT,
    _validate_array_length_change, ARRAY_LENGTH_AMENDMENT,
    _validate_difficulty_guidance_change, DIFFICULTY_GUIDANCE_AMENDMENT,
    _validate_difficulty_identity_change, DIFFICULTY_IDENTITY_AMENDMENT, RuntimeAmendment, _validate_runtime_amendment,
    _validate_multi_record_fact_change, MULTI_RECORD_FACT_AMENDMENT,
    _validate_nested_json_fact_change, NESTED_JSON_FACT_AMENDMENT,
)


MODULES = Path(__file__).resolve().parents[1] / "secgym/qagen/agentic"


def before_identity_guard(current):
    tree = ast.parse(current)
    function, = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_probe"]
    condition = ast.parse('probe.identity_kind == "source_observation"', mode="eval").body
    branch, = [node for node in ast.walk(function) if isinstance(node, ast.If)
               and ast.dump(node.test) == ast.dump(condition)]
    branch.orelse.pop(2)
    return ast.unparse(tree).encode()


def before_nested_json(current, name="canonical_facts.py"):
    if name == "canonical_facts.py":
        for variable in (b"current", b"observed", b"parent"):
            current = current.replace(
                b"while isinstance(" + variable + b", str):", b"if isinstance(" + variable + b", str):",
            )
    elif name == "fact_curation.py":
        current = current.replace(
            b"Repeated JSON-string serialization layers are decoded when locating a container for traversal or a\n"
            b"structural fact. Keep the same source path and exact keys; no extra path component denotes decoding.\n"
            b"Literal scalar columns and selected scalar leaves retain their original quoting, types and precision.\n",
            b"",
        ).replace(b"source-fact-curation-v1.5", b"source-fact-curation-v1.4")
    return current


def before_multi_record(current, name="canonical_facts.py"):
    current = before_nested_json(current, name)
    if name == "fact_curation.py":
        return current.replace(b"source-fact-curation-v1.4", b"source-fact-curation-v1.3").replace(
            b"claim.expanded_references", b"claim.references",
        )
    if name != "canonical_facts.py" or b"class SourceFactReferenceBatch(" not in current:
        return current
    start = current.index(b"class SourceFactReferenceBatch(")
    end = current.index(b"class ClaimFactSelection(", start)
    current = current[:start] + current[end:]
    current = current.replace(
        b"    references: Annotated[\n"
        b"        tuple[SourceFactReference | SourceFactReferenceGroup | SourceFactReferenceBatch, ...], Field(min_length=1)\n"
        b"    ]",
        b"    references: Annotated[tuple[SourceFactReference | SourceFactReferenceGroup, ...], Field(min_length=1)]",
    )
    current = current.replace(
        b"                citations = (reference.citation,) if isinstance(reference, SourceFactReferenceGroup) else reference.citations\n",
        b"",
    )
    return current.replace(b"citation=citation, column=selection.column", b"citation=reference.citation, column=selection.column").replace(
        b"for citation in citations for selection in reference.properties)", b"for selection in reference.properties)",
    )


def before_array_length(current):
    current = before_multi_record(current)
    tree = ast.parse(current)
    tree.body = [node for node in tree.body if not (
        isinstance(node, ast.ClassDef) and node.name in {"SourcePropertySelection", "SourceFactReferenceGroup"}
    )]
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "FactKind":
            node.value = ast.parse(
                'Literal["property_value", "json_member_presence", "json_array_empty_v1"]', mode="eval",
            ).body
        if isinstance(node, ast.FunctionDef) and node.name in ("source_leaf", "presence_path", "atomic_value"):
            node.body = [statement for statement in node.body if not (
                isinstance(statement, ast.If) and "json_array_length_v1" in ast.unparse(statement.test)
            )]
        if isinstance(node, ast.ClassDef) and node.name == "ClaimFactSelection":
            node.body = [method for method in node.body if not (
                isinstance(method, ast.FunctionDef) and method.name == "expanded_references"
            )]
            reference, = [field for field in node.body if isinstance(field, ast.AnnAssign)
                          and isinstance(field.target, ast.Name) and field.target.id == "references"]
            reference.annotation = ast.parse(
                "Annotated[tuple[SourceFactReference, ...], Field(min_length=1)]", mode="eval",
            ).body
        if isinstance(node, ast.Attribute) and node.attr == "expanded_references":
            node.attr = "references"
    return ast.unparse(tree).encode()


def legacy_canonical_source(current):
    current = before_array_length(current)
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
                    data = data.replace(CURATION_VERSION.encode(), (CURATION_VERSION + "-context-test").encode())
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

    def test_difficulty_guidance_amendment_preserves_exact_historical_source_audits(self):
        _, candidate = self.held()
        task = TaskRecord.model_validate_json((candidate / "task.json").read_bytes())
        before, after = self.output / "before-guidance.zip", self.output / "after-guidance.zip"
        updated = dict(self.plan.implementation_sha256)
        with zipfile.ZipFile(before, "x") as old, zipfile.ZipFile(after, "x") as new:
            for name in updated:
                data = (MODULES / name).read_bytes()
                old.writestr(name, data)
                if name == "difficulty_curation.py":
                    data = data.replace(CURATION_VERSION.encode(), (CURATION_VERSION + "-guidance-test").encode())
                    data = data.replace(b"This is private feature measurement", b"This is source-only feature measurement")
                    data = data.replace(b"not a numerical difficulty score", b"never a numerical difficulty score")
                    updated[name] = hashlib.sha256(data).hexdigest()
                new.writestr(name, data)
        from secgym.qagen.agentic.quality import runtime_hashes as source_hashes
        recorded = source_hashes()
        with patch("secgym.qagen.agentic.preproduction_revisions.runtime_hashes", return_value=updated), \
             patch("secgym.qagen.agentic.quality.runtime_hashes",
                   return_value={name: updated[name] for name in recorded}):
            with self.assertRaisesRegex(ValueError, "both exact"):
                record_runtime_amendment(self.plan, self.output, archive=before, difficulty_guidance=True,
                                         reason="Missing prompt archive.")
            with self.assertRaisesRegex(ValueError, "separate prompt-only"):
                record_runtime_amendment(self.plan, self.output, archive=before, current_archive=after,
                                         difficulty_guidance=True, empty_array_facts=True, reason="Mixed changes.")
            with self.assertRaisesRegex(ValueError, "curation or measurement kernels"):
                record_runtime_amendment(self.plan, self.output, archive=before, current_archive=after,
                                         reason="The old context policy must not authorize prompt changes.")
            amendment = record_runtime_amendment(
                self.plan, self.output, archive=before, current_archive=after, difficulty_guidance=True,
                reason="Controlled independently reviewed source-necessity prompt clarification.",
            )
            self.assertEqual(amendment.policy_version, DIFFICULTY_GUIDANCE_AMENDMENT)
            self.assertEqual(effective_runtime(self.plan, self.output), updated)
            validate_source_audit_runtime(candidate, task, recorded)
        with after.open("ab") as stream:
            stream.write(b"tamper")
        with self.assertRaisesRegex(ValueError, "updated annotation producer changed"):
            effective_runtime(self.plan, self.output)

    def test_difficulty_guidance_rejects_code_context_domain_and_unversioned_changes(self):
        original = (MODULES / "difficulty_curation.py").read_bytes()
        versioned = original.replace(CURATION_VERSION.encode(), (CURATION_VERSION + "-guidance-test").encode())
        replacements = (
            (original, "new curation version"),
            (versioned.replace(b"question = SplitQuestion.model_validate(question)", b"question = question"),
             "curation, context or measurement kernels"),
            (versioned.replace(b"task = question.task", b"task = None"), "curation, context or measurement kernels"),
            (versioned.replace(b"Cross-domain means", b"Cross-domain always means"),
             "curation, context or measurement kernels"),
            (versioned.replace(b'CURATOR_INSTRUCTIONS = """', b'CURATOR_INSTRUCTIONS = str() + """', 1),
             "only static instruction text"),
        )
        for changed, message in replacements:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                _validate_difficulty_guidance_change("difficulty_curation.py", original, changed)
        with self.assertRaisesRegex(ValueError, "another annotation module"):
            _validate_difficulty_guidance_change("difficulty.py", original, versioned)

    def test_difficulty_identity_amendment_accepts_only_the_exact_guard_and_static_guidance(self):
        self.output.mkdir()
        before, after = self.output / "before-identity.zip", self.output / "after-identity.zip"
        previous, current = {}, {}
        with zipfile.ZipFile(before, "x") as old, zipfile.ZipFile(after, "x") as new:
            for name in self.plan.implementation_sha256:
                source = (MODULES / name).read_bytes()
                old_source = before_identity_guard(source) if name == "difficulty.py" else source
                new_source = source.replace(CURATION_VERSION.encode(), (CURATION_VERSION + "-identity-test").encode()) \
                    if name == "difficulty_curation.py" else source
                previous[name], current[name] = hashlib.sha256(old_source).hexdigest(), hashlib.sha256(new_source).hexdigest()
                old.writestr(name, old_source)
                new.writestr(name, new_source)
        amendment = RuntimeAmendment(
            policy_version=DIFFICULTY_IDENTITY_AMENDMENT, plan_fingerprint=fingerprint(self.plan),
            previous_runtime_sha256=previous, current_runtime_sha256=current,
            archive=before.name, archive_sha256=file_sha256(before),
            current_archive=after.name, current_archive_sha256=file_sha256(after),
            reason="Controlled source identity projection guard and prompt-only clarification.",
        )
        _validate_runtime_amendment(amendment, self.output, previous)
        for policy in ("preproduction-annotation-context-amendment-v2", DIFFICULTY_GUIDANCE_AMENDMENT):
            with self.subTest(policy=policy), self.assertRaisesRegex(ValueError, "cannot change"):
                _validate_runtime_amendment(amendment.model_copy(update={"policy_version": policy}), self.output, previous)
        missing_guidance = {**current, "difficulty_curation.py": previous["difficulty_curation.py"]}
        with self.assertRaisesRegex(ValueError, "both the exact guard and versioned guidance"):
            _validate_runtime_amendment(amendment.model_copy(update={"current_runtime_sha256": missing_guidance}),
                                        self.output, previous)
        with after.open("ab") as stream:
            stream.write(b"tamper")
        with self.assertRaisesRegex(ValueError, "updated annotation producer changed"):
            _validate_runtime_amendment(amendment, self.output, previous)

    def test_difficulty_identity_amendment_rejects_changed_guard_or_other_measurement_logic(self):
        current = (MODULES / "difficulty.py").read_bytes()
        previous = before_identity_guard(current)
        _validate_difficulty_identity_change(previous, current)
        for changed in (
            current.replace(b'column in result.columns and (', b'column not in result.columns and ('),
            current.replace(b'1 <= self.candidate_count', b'0 <= self.candidate_count'),
            current.replace(b'candidate_count=len(keys)', b'candidate_count=len(rows)'),
        ):
            with self.subTest(change=hashlib.sha256(changed).hexdigest()), self.assertRaisesRegex(ValueError, "difficulty identity"):
                _validate_difficulty_identity_change(previous, changed)

    def test_empty_array_amendment_preserves_exact_legacy_source_audits(self):
        _, candidate = self.held()
        task = TaskRecord.model_validate_json((candidate / "task.json").read_bytes())
        before, after = self.output / "before-empty.zip", self.output / "after-empty.zip"
        previous = dict(self.plan.implementation_sha256)
        intermediate = {}
        with zipfile.ZipFile(before, "x") as old, zipfile.ZipFile(after, "x") as new:
            for name in previous:
                data = before_multi_record((MODULES / name).read_bytes(), name)
                if name == "canonical_facts.py":
                    data = before_array_length(data)
                elif name == "fact_curation.py":
                    data = data.replace(b"source-fact-curation-v1.3", b"source-fact-curation-v1.2")
                new.writestr(name, data)
                intermediate[name] = hashlib.sha256(data).hexdigest()
                if name == "canonical_facts.py":
                    data = legacy_canonical_source(data)
                elif name == "fact_curation.py":
                    data = data.replace(b"source-fact-curation-v1.2", b"source-fact-curation-v1.1")
                old.writestr(name, data)
                previous[name] = hashlib.sha256(data).hexdigest()
        for target, value in (
            ("secgym.qagen.agentic.preproduction_revisions.runtime_hashes", intermediate),
            ("secgym.qagen.agentic.preproduction.runtime_hashes", intermediate),
        ):
            patched = patch(target, return_value=value)
            patched.start()
            self.addCleanup(patched.stop)
        version = patch("secgym.qagen.agentic.preproduction_pipeline.CURATION_VERSION", "source-fact-curation-v1.2")
        version.start()
        self.addCleanup(version.stop)
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
        current = before_array_length((MODULES / "canonical_facts.py").read_bytes())
        previous = legacy_canonical_source(current)
        _validate_empty_array_change("canonical_facts.py", previous, current)
        for before, after in (
            (b"weight=1.0", b"weight=2.0"),
            (b"FACT_VERSION = 'canonical-source-facts-v2'", b"FACT_VERSION = 'canonical-source-facts-v3'"),
            (b"        return 'true'", b"        return 'false'"),
            (b"if not isinstance(observed, list) or observed:", b"if not isinstance(observed, list):"),
        ):
            changed = current.replace(before, after)
            self.assertNotEqual(changed, current)
            with self.subTest(change=before), self.assertRaises(ValueError):
                _validate_empty_array_change("canonical_facts.py", previous, changed)
        curation = before_multi_record((MODULES / "fact_curation.py").read_bytes(), "fact_curation.py").replace(
            b"source-fact-curation-v1.3", b"source-fact-curation-v1.2",
        )
        old = curation.replace(b"source-fact-curation-v1.2", b"source-fact-curation-v1.1")
        with self.assertRaisesRegex(ValueError, "curation kernels"):
            _validate_empty_array_change(
                "fact_curation.py", old, curation.replace(b"validation.pilot_blockers(task)", b"()"),
            )

    def test_array_length_amendment_is_strictly_additive(self):
        current = before_multi_record((MODULES / "canonical_facts.py").read_bytes())
        previous = before_array_length(current)
        _validate_array_length_change("canonical_facts.py", previous, current)
        for before, after in (
            (b"weight=1.0", b"weight=2.0"),
            (b'FACT_VERSION = "canonical-source-facts-v2"', b'FACT_VERSION = "canonical-source-facts-v3"'),
            (b"return str(len(observed))", b'return "1"'),
            (b"if not isinstance(observed, list) or not observed:", b"if not isinstance(observed, list):"),
            (b"int(value.text) <= 0", b"int(value.text) < 0"),
            (b"for selection in reference.properties)", b"for selection in reference.properties[:1])"),
            (b"json_path=selection.json_path", b"json_path=None"),
            (b"class SourceFactResolver:", b"class RenamedFactResolver:"),
            (b'        return "true"', b'        return "false"'),
        ):
            changed = current.replace(before, after)
            self.assertNotEqual(changed, current)
            with self.subTest(change=before), self.assertRaises(ValueError):
                _validate_array_length_change("canonical_facts.py", previous, changed)
        curation = before_multi_record((MODULES / "fact_curation.py").read_bytes(), "fact_curation.py")
        old = curation.replace(b"source-fact-curation-v1.3", b"source-fact-curation-v1.2")
        _validate_array_length_change("fact_curation.py", old, curation)
        with self.assertRaisesRegex(ValueError, "curation kernels"):
            _validate_array_length_change(
                "fact_curation.py", old, curation.replace(b"validation.pilot_blockers(task)", b"()"),
            )
        with self.assertRaises(ValueError):
            _validate_array_length_change("fact_curation.py", old, old)

    def array_extension_archives(self):
        hashes = {version: {} for version in ("old", "middle", "current")}
        paths = {version: self.output / f"array-{version}.zip" for version in hashes}
        for version, path in paths.items():
            with zipfile.ZipFile(path, "x") as saved:
                for name in self.plan.implementation_sha256:
                    data = before_multi_record((MODULES / name).read_bytes(), name)
                    if version != "current":
                        if name == "canonical_facts.py":
                            data = before_array_length(data) if version == "middle" else legacy_canonical_source(data)
                        elif name == "fact_curation.py":
                            data = data.replace(
                                b"source-fact-curation-v1.3",
                                b"source-fact-curation-v1.2" if version == "middle" else b"source-fact-curation-v1.1",
                            )
                    saved.writestr(name, data)
                    hashes[version][name] = hashlib.sha256(data).hexdigest()
        for target in ("secgym.qagen.agentic.preproduction_revisions.runtime_hashes",
                       "secgym.qagen.agentic.preproduction.runtime_hashes"):
            patched = patch(target, return_value=hashes["current"])
            patched.start()
            self.addCleanup(patched.stop)
        version = patch("secgym.qagen.agentic.preproduction_pipeline.CURATION_VERSION", "source-fact-curation-v1.3")
        version.start()
        self.addCleanup(version.stop)
        return hashes, paths

    def test_multi_record_amendment_is_exactly_lossless_and_checks_every_inspection(self):
        for name in ("canonical_facts.py", "fact_curation.py"):
            current = before_nested_json((MODULES / name).read_bytes(), name)
            previous = before_multi_record(current, name)
            _validate_multi_record_fact_change(name, previous, current)
            changes = (
                (b"else reference.citations", b"else reference.citations[:1]"),
                (b"require_unique(self.record_ids", b"require_unique(()"),
                (b"json_path=selection.json_path", b"json_path=None"),
                (b"weight=1.0", b"weight=2.0"),
            ) if name == "canonical_facts.py" else (
                (b"claim.expanded_references", b"claim.references"),
                (b"validation.pilot_blockers(task)", b"()"),
            )
            for original, replacement in changes:
                modified = current.replace(original, replacement)
                self.assertNotEqual(modified, current)
                with self.subTest(name=name, change=original), self.assertRaisesRegex(ValueError, "multi-record"):
                    _validate_multi_record_fact_change(name, previous, modified)

    def test_multi_record_amendment_requires_exact_archives_and_its_separate_policy(self):
        self.output.mkdir()
        before, after = self.output / "before-batches.zip", self.output / "after-batches.zip"
        previous, current = {}, {}
        with zipfile.ZipFile(before, "x") as old, zipfile.ZipFile(after, "x") as new:
            for name in self.plan.implementation_sha256:
                data = before_nested_json((MODULES / name).read_bytes(), name)
                old_data = before_multi_record(data, name)
                previous[name], current[name] = hashlib.sha256(old_data).hexdigest(), hashlib.sha256(data).hexdigest()
                old.writestr(name, old_data)
                new.writestr(name, data)
        self.plan = self.plan.model_copy(update={"implementation_sha256": previous})
        (self.output / "plan.json").write_text(self.plan.model_dump_json())
        runtime = patch("secgym.qagen.agentic.preproduction_revisions.runtime_hashes", return_value=current)
        runtime.start()
        self.addCleanup(runtime.stop)
        with self.assertRaisesRegex(ValueError, "both exact"):
            record_runtime_amendment(self.plan, self.output, archive=before, multi_record_facts=True,
                                     reason="Missing exact new producer.")
        with self.assertRaisesRegex(ValueError, "separate transport-only"):
            record_runtime_amendment(self.plan, self.output, archive=before, current_archive=after,
                                     multi_record_facts=True, array_length_facts=True, reason="Mixed policies.")
        amendment = record_runtime_amendment(
            self.plan, self.output, archive=before, current_archive=after, multi_record_facts=True,
            reason="Exact lossless source-reference batching without source, grading or fact-identity changes.",
        )
        self.assertEqual(amendment.policy_version, MULTI_RECORD_FACT_AMENDMENT)
        self.assertEqual(effective_runtime(self.plan, self.output), current)
        with self.assertRaises(ValueError):
            _validate_runtime_amendment(amendment.model_copy(update={"policy_version": ARRAY_LENGTH_AMENDMENT}),
                                        self.output, previous)
        with after.open("ab") as stream:
            stream.write(b"changed")
        with self.assertRaisesRegex(ValueError, "updated annotation producer"):
            effective_runtime(self.plan, self.output)

    def test_nested_json_amendment_only_repeats_container_decoding(self):
        for name in ("canonical_facts.py", "fact_curation.py"):
            current = (MODULES / name).read_bytes()
            previous = before_nested_json(current, name)
            _validate_nested_json_fact_change(name, previous, current)
            changes = (
                (b"while isinstance(current, str):", b"if isinstance(current, str):"),
                (b"return encode_json(current)", b"return encode_json(str(current))"),
                (b"weight=1.0", b"weight=2.0"),
                (b"return str(len(observed))", b'return "1"'),
                (b'        return "true"', b'        return "false"'),
            ) if name == "canonical_facts.py" else (
                (b"source-fact-curation-v1.5", b"source-fact-curation-v1.6"),
                (b"validation.pilot_blockers(task)", b"()"),
                (b"claim.expanded_references", b"claim.references"),
            )
            for old, new in changes:
                modified = current.replace(old, new)
                self.assertNotEqual(modified, current)
                with self.subTest(name=name, change=old), self.assertRaisesRegex(ValueError, "nested JSON"):
                    _validate_nested_json_fact_change(name, previous, modified)
            with self.assertRaises(ValueError):
                _validate_nested_json_fact_change(name, current, current)

    def test_nested_json_amendment_requires_both_exact_archives_and_separate_policy(self):
        self.output.mkdir()
        before, after = self.output / "before-nested-json.zip", self.output / "after-nested-json.zip"
        previous, current = {}, {}
        with zipfile.ZipFile(before, "x") as old, zipfile.ZipFile(after, "x") as new:
            for name in self.plan.implementation_sha256:
                data = (MODULES / name).read_bytes()
                old_data = before_nested_json(data, name)
                previous[name], current[name] = hashlib.sha256(old_data).hexdigest(), hashlib.sha256(data).hexdigest()
                old.writestr(name, old_data)
                new.writestr(name, data)
        self.plan = self.plan.model_copy(update={"implementation_sha256": previous})
        (self.output / "plan.json").write_text(self.plan.model_dump_json())
        with self.assertRaisesRegex(ValueError, "both exact"):
            record_runtime_amendment(
                self.plan, self.output, archive=before, nested_json_facts=True, reason="Missing current archive.",
            )
        with self.assertRaisesRegex(ValueError, "separate"):
            record_runtime_amendment(
                self.plan, self.output, archive=before, current_archive=after,
                nested_json_facts=True, multi_record_facts=True, reason="Mixed policies.",
            )
        amendment = record_runtime_amendment(
            self.plan, self.output, archive=before, current_archive=after, nested_json_facts=True,
            reason="Decode only container serialization layers without changing scalar leaves or identities.",
        )
        self.assertEqual(amendment.policy_version, NESTED_JSON_FACT_AMENDMENT)
        self.assertEqual(effective_runtime(self.plan, self.output), current)
        with self.assertRaises(ValueError):
            _validate_runtime_amendment(amendment.model_copy(update={"policy_version": MULTI_RECORD_FACT_AMENDMENT}),
                                        self.output, previous)
        with after.open("ab") as stream:
            stream.write(b"changed")
        with self.assertRaisesRegex(ValueError, "updated annotation producer"):
            effective_runtime(self.plan, self.output)

    def test_array_length_amendment_preserves_historical_audits_and_recovers_unsupported_annotations(self):
        _, candidate = self.held()
        task = TaskRecord.model_validate_json((candidate / "task.json").read_bytes())
        hashes, paths = self.array_extension_archives()
        self.plan = self.plan.model_copy(update={"implementation_sha256": hashes["middle"]})
        (self.output / "plan.json").write_text(self.plan.model_dump_json())
        with self.assertRaisesRegex(ValueError, "both exact"):
            record_runtime_amendment(self.plan, self.output, archive=paths["middle"], array_length_facts=True,
                                     reason="Missing current archive.")
        with self.assertRaisesRegex(ValueError, "two structural"):
            record_runtime_amendment(self.plan, self.output, archive=paths["middle"], current_archive=paths["current"],
                                     array_length_facts=True, empty_array_facts=True, reason="Ambiguous extension.")
        amendment = record_runtime_amendment(
            self.plan, self.output, archive=paths["middle"], current_archive=paths["current"], array_length_facts=True,
            reason="Add exact nonempty-array extent without changing legacy facts.",
        )
        self.assertEqual(amendment.policy_version, ARRAY_LENGTH_AMENDMENT)
        self.assertEqual(effective_runtime(self.plan, self.output), hashes["current"])
        from secgym.qagen.agentic.quality import runtime_hashes as source_hashes
        validate_source_audit_runtime(candidate, task, {name: hashes["middle"][name] for name in source_hashes()})
        self.check_array_abstention(task, candidate, hashes["middle"], "source-fact-curation-v1.2")
        with paths["current"].open("ab") as stream:
            stream.write(b"changed")
        with self.assertRaisesRegex(ValueError, "updated annotation producer"):
            effective_runtime(self.plan, self.output)

    def check_array_abstention(self, task, candidate, previous, version):
        from secgym.qagen.agentic.preproduction_pipeline import _canonical_abstention_extension, _json_hashes
        parent = candidate.parent / "pipeline/unsupported-array"
        canonical = parent / "canonical"
        (canonical / "curator").mkdir(parents=True)
        binding = {"task_fingerprint": fingerprint(task), "curation_version": version,
                   "implementation_sha256": previous}
        (canonical / "binding.json").write_text(json.dumps(binding))
        (canonical / "curator/abstention.json").write_text(json.dumps({
            "status": "no_supported_result", "role": "fact-curator", "reason": "Array extent is not expressible.",
        }))
        (parent / "pipeline-report.json").write_text(json.dumps({
            "status": "held", "stage": "canonical", "task_fingerprint": fingerprint(task),
            "artifacts_sha256": _json_hashes(parent),
        }))
        destination = parent.parent / "extended-array/canonical"
        context = _canonical_abstention_extension(canonical, binding, destination)
        self.assertEqual(context["approved_annotation_extension"], ARRAY_LENGTH_AMENDMENT)
        self.assertEqual(_canonical_abstention_extension(canonical, binding, destination), context)
        with self.assertRaisesRegex(ValueError, "immutable"):
            _canonical_abstention_extension(canonical, binding, parent.parent / "resampled-array/canonical")
        with self.assertRaisesRegex(ValueError, "exact additive"):
            _canonical_abstention_extension(
                canonical, {**binding, "implementation_sha256": {**previous, "canonical_facts.py": "f" * 64}}, destination,
            )

    def test_chained_empty_and_length_extensions_preserve_original_abstention_boundary(self):
        _, candidate = self.held()
        task = TaskRecord.model_validate_json((candidate / "task.json").read_bytes())
        hashes, paths = self.array_extension_archives()
        self.plan = self.plan.model_copy(update={"implementation_sha256": hashes["old"]})
        (self.output / "plan.json").write_text(self.plan.model_dump_json())
        with patch("secgym.qagen.agentic.preproduction_revisions.runtime_hashes", return_value=hashes["middle"]):
            record_runtime_amendment(
                self.plan, self.output, archive=paths["old"], current_archive=paths["middle"], empty_array_facts=True,
                reason="First exact empty-array extension.",
            )
        record_runtime_amendment(
            self.plan, self.output, archive=paths["middle"], current_archive=paths["current"], array_length_facts=True,
            reason="Second exact nonempty-array extent extension.",
        )
        self.check_array_abstention(task, candidate, hashes["old"], "source-fact-curation-v1.1")
        certificate, = (self.output / "canonical-extension-recoveries").glob("*.json")
        self.assertEqual(len(json.loads(certificate.read_bytes())["runtime_amendment_fingerprints"]), 2)

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
