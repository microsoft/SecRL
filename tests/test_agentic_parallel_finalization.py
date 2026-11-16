# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import hashlib
import fcntl
import json
import os
import shutil
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
import tempfile
from threading import Barrier, Lock
import unittest
from unittest.mock import patch
import zipfile

import test_agentic_preproduction_admission as admission_tests
from test_agentic_model_panel import ConfiguredFake
from secgym.qagen.agentic.preproduction_admission import (
    AdmissionSnapshotStore, ArtifactVerification, InventoryAdvanced, ObjectiveInventory, ObjectiveReview,
    ObjectiveReviewCoverage, ObjectiveReviewPart, admission_progress, admitted_receipts, commit_prepared_admission, prepare_admission,
)
from secgym.qagen.agentic.contracts import fingerprint
from secgym.qagen.agentic.ledger import file_sha256
from secgym.qagen.agentic.preproduction import SourceOutcome
from secgym.qagen.agentic.preproduction_revisions import SourceRevision
from secgym.qagen.agentic.preproduction_pipeline import (
    StageResult, parallel_finalize, run_candidate_pipeline, run_stage,
)


MODULE = "secgym.qagen.agentic.preproduction_admission"


class ArtifactVerificationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = self.root / "artifact.json"
        self.path.write_bytes(b'{"value":1}')

    def test_one_content_hash_per_unchanged_artifact_and_conflicting_references_fail(self):
        verifier = ArtifactVerification()
        expected = hashlib.sha256(self.path.read_bytes()).hexdigest()
        with patch(MODULE + ".file_sha256", wraps=lambda path: hashlib.sha256(path.read_bytes()).hexdigest()) as hashed:
            verifier.require(self.path, expected, "conflicting reference")
            verifier.require(self.path, expected, "conflicting reference")
            verifier.verify_unchanged()
            self.assertEqual(hashed.call_count, 1)
            with self.assertRaisesRegex(ValueError, "conflicting reference"):
                verifier.require(self.path, "0" * 64, "conflicting reference")

    def test_same_size_change_with_restored_mtime_cannot_reuse_a_cached_hash(self):
        verifier = ArtifactVerification()
        verifier.digest(self.path)
        original = self.path.stat()
        self.path.write_bytes(b'{"value":2}')
        os.utime(self.path, ns=(original.st_atime_ns, original.st_mtime_ns))
        with self.assertRaisesRegex(ValueError, "validated artifact changed"):
            verifier.verify_unchanged()

    def test_change_during_hashing_is_not_a_valid_snapshot(self):
        verifier = ArtifactVerification()

        def changing_hash(path):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            path.write_bytes(b'{"value":2}')
            return digest

        with patch(MODULE + ".file_sha256", side_effect=changing_hash):
            with self.assertRaisesRegex(ValueError, "changed while hashing"):
                verifier.digest(self.path)

    def test_added_json_artifact_invalidates_a_closed_directory(self):
        verifier = ArtifactVerification()
        verifier.watch_json_tree(self.root)
        (self.root / "unexpected.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "artifact inventory changed"):
            verifier.verify_unchanged()


class AdmissionSnapshotTests(unittest.TestCase):
    setUp = admission_tests.AdmissionTests.setUp
    review = admission_tests.AdmissionTests.review
    admit = admission_tests.AdmissionTests.admit

    def test_progress_cache_reuses_hashes_but_observes_new_admissions(self):
        verification = ArtifactVerification()
        with patch(MODULE + ".file_sha256", wraps=file_sha256) as hashed:
            before = admission_progress(self.plan, self.run, verification=verification)
            initial = hashed.call_count
            self.assertGreater(initial, 0)
            self.assertEqual(admission_progress(self.plan, self.run, verification=verification), before)
            self.assertEqual(hashed.call_count, initial)
        self.admit()
        with patch(MODULE + ".file_sha256", wraps=file_sha256) as hashed:
            after = admission_progress(self.plan, self.run, verification=verification)
            initial = hashed.call_count
            self.assertGreater(initial, 0)
            self.assertEqual(admission_progress(self.plan, self.run, verification=verification), after)
            self.assertEqual(hashed.call_count, initial)
        self.assertEqual(after, admission_progress(self.plan, self.run))
        self.assertEqual(after["validated_new_questions"], 1)

    def test_progress_cache_observes_a_newly_closed_source_without_sealing_the_wave(self):
        verification = ArtifactVerification()
        before = admission_progress(self.plan, self.run, verification=verification)
        attempt = next(value for value in self.plan.attempts() if value.task_id != self.case.task.task_id)
        directory = self.run / "attempts" / attempt.task_id
        admission_tests.save(directory / "attempt.json", {
            "plan_fingerprint": fingerprint(self.plan), "attempt": attempt.model_dump(mode="json"),
        })
        (directory / "source").mkdir()
        admission_tests.save(directory / "source-outcome.json", SourceOutcome(
            plan_fingerprint=fingerprint(self.plan), attempt_binding_sha256=file_sha256(directory / "attempt.json"),
            attempt=attempt, status="operational_error", task_fingerprint=None,
            reason="Controlled newly closed source outcome.", artifact_sha256={},
        ))
        after = admission_progress(self.plan, self.run, verification=verification)
        self.assertEqual(after, admission_progress(self.plan, self.run))
        self.assertEqual(after["logical_attempts_started"], before["logical_attempts_started"] + 1)
        self.assertEqual(after["source_outcomes_recorded"], before["source_outcomes_recorded"] + 1)

    def test_progress_cache_observes_an_append_only_source_revision(self):
        verification = ArtifactVerification()
        admission_progress(self.plan, self.run, verification=verification)
        attempt = self.run / "attempts" / self.case.task.task_id
        previous = attempt / "source"
        revision = attempt / "revisions/0001"
        source = revision / "source"
        task = self.case.task.model_copy(update={"revision_id": "source-r2"})
        admission_tests.save(source / "task.json", task)
        admission_tests.save(revision / "request.json", {"feedback": "Controlled immutable source revision."})
        old = SourceOutcome.model_validate_json((attempt / "source-outcome.json").read_bytes())
        admission_tests.save(revision / "source-outcome.json", old.model_copy(update={
            "status": "needs_revision", "task_fingerprint": fingerprint(task),
            "artifact_sha256": {"task.json": file_sha256(source / "task.json")},
        }))
        admission_tests.save(revision / "revision.json", SourceRevision(
            plan_fingerprint=fingerprint(self.plan), task_id=task.task_id, sequence=1,
            previous_source=str(previous.relative_to(self.run)),
            previous_outcome_sha256=file_sha256(attempt / "source-outcome.json"),
            previous_task_fingerprint=fingerprint(self.case.task), source_directory=str(source.relative_to(self.run)),
            source_outcome_sha256=file_sha256(revision / "source-outcome.json"),
            request_sha256=file_sha256(revision / "request.json"),
        ))
        current = admission_progress(self.plan, self.run, verification=verification)
        self.assertEqual(current, admission_progress(self.plan, self.run))
        self.assertEqual(current["source_ready"], 0)
        self.assertEqual(current["buckets"]["incident:34"]["source_revisions"], 1)

    def test_progress_readers_can_share_verified_hashes_without_sharing_results(self):
        self.admit()
        verification = ArtifactVerification()
        expected = admission_progress(self.plan, self.run, verification=verification)
        with ThreadPoolExecutor(max_workers=3) as executor:
            results = list(executor.map(
                lambda _: admission_progress(self.plan, self.run, verification=verification), range(3)))
        self.assertTrue(all(value == expected for value in results))
        results[0]["validated_new_questions"] = 999
        self.assertEqual(admission_progress(self.plan, self.run, verification=verification), expected)

    def test_progress_cache_does_not_hide_source_mutation_or_added_artifacts(self):
        source = self.run / "attempts" / self.case.task.task_id / "source"
        for change in ("changed", "added"):
            with self.subTest(change=change):
                verification = ArtifactVerification()
                admission_progress(self.plan, self.run, verification=verification)
                task = source / "task.json"
                original = task.read_bytes()
                extra = source / "unexpected.json"
                try:
                    if change == "changed":
                        task.write_bytes(original + b" ")
                    else:
                        extra.write_text("{}")
                    with self.assertRaisesRegex(ValueError, "validated artifact changed|source attempt artifacts changed"):
                        admission_progress(self.plan, self.run, verification=verification)
                finally:
                    task.write_bytes(original)
                    extra.unlink(missing_ok=True)

    def test_progress_cache_rejects_disappearing_admissions(self):
        self.admit()
        verification = ArtifactVerification()
        admission_progress(self.plan, self.run, verification=verification)
        (self.run / "admissions" / (self.case.task.task_id + ".json")).unlink()
        with self.assertRaises(FileNotFoundError):
            admission_progress(self.plan, self.run, verification=verification)

    def test_snapshot_reuses_verified_history_but_detects_artifact_mutation(self):
        receipt = self.admit()
        store = AdmissionSnapshotStore(self.plan, self.run)
        with patch(MODULE + ".file_sha256", wraps=file_sha256) as hashed:
            before = store.snapshot()
            initial_hashes = hashed.call_count
            self.assertGreater(initial_hashes, 0)
            self.assertIs(store.snapshot(), before)
            self.assertEqual(hashed.call_count, initial_hashes)
        self.assertEqual(before.receipts, (receipt,))
        source = self.run / "attempts" / self.case.task.task_id / "source/task.json"
        source.write_text(source.read_text() + " ")
        with self.assertRaisesRegex(ValueError, "validated artifact changed"):
            store.snapshot()

    def test_explicit_archived_producer_preserves_original_receipt_without_accepting_other_mutations(self):
        receipt = self.admit()
        producer = self.run / "historical-package/preproduction.py"
        producer.parent.mkdir()
        original = b"original historical producer\n"
        digest = hashlib.sha256(original).hexdigest()
        producer.write_bytes(b"new installed producer\n")
        receipt = receipt.model_copy(update={
            "source_artifacts_sha256": {**receipt.source_artifacts_sha256, str(producer): digest},
        })
        receipt_path = self.run / "admissions" / (receipt.task.task_id + ".json")
        receipt_path.write_text(receipt.model_dump_json())
        recorded = receipt_path.read_bytes()
        with self.assertRaisesRegex(ValueError, "source artifacts changed"):
            admitted_receipts(self.plan, self.run)
        archive = self.run / "original-runtime.zip"
        with zipfile.ZipFile(archive, "w") as saved:
            saved.writestr("preproduction.py", original)
        references = {(receipt_path, producer, digest): (archive, file_sha256(archive), "preproduction.py")}
        dependencies = {archive: file_sha256(archive), receipt_path: file_sha256(receipt_path)}
        with patch("secgym.qagen.agentic.transport_amendments.archived_admission_producers",
                   return_value=(references, dependencies)):
            self.assertEqual(admitted_receipts(self.plan, self.run), (receipt,))
            store = AdmissionSnapshotStore(self.plan, self.run)
            self.assertEqual(store.snapshot().receipts, (receipt,))
            self.assertEqual(receipt_path.read_bytes(), recorded)
            archive.write_bytes(archive.read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "changed"):
                store.snapshot()
        self.assertEqual(receipt_path.read_bytes(), recorded)

    def test_wrong_archive_member_content_cannot_satisfy_historical_reference(self):
        receipt = self.admit()
        producer = self.run / "preproduction.py"
        producer.write_bytes(b"new producer")
        expected = hashlib.sha256(b"old producer").hexdigest()
        receipt = receipt.model_copy(update={
            "source_artifacts_sha256": {**receipt.source_artifacts_sha256, str(producer): expected},
        })
        receipt_path = self.run / "admissions" / (receipt.task.task_id + ".json")
        receipt_path.write_text(receipt.model_dump_json())
        archive = self.run / "wrong-runtime.zip"
        with zipfile.ZipFile(archive, "w") as saved:
            saved.writestr("preproduction.py", b"different producer")
        references = {(receipt_path, producer, expected): (archive, file_sha256(archive), "preproduction.py")}
        with patch("secgym.qagen.agentic.transport_amendments.archived_admission_producers",
                   return_value=(references, {archive: file_sha256(archive)})), \
             self.assertRaisesRegex(ValueError, "differs from the original admitted reference"):
            admitted_receipts(self.plan, self.run)

    def test_inventory_growth_requires_refresh_and_removal_is_not_a_delta(self):
        store = AdmissionSnapshotStore(self.plan, self.run)
        before = store.snapshot()
        receipt = self.admit()
        with self.assertRaises(InventoryAdvanced):
            before.require_current()
        after = store.snapshot()
        self.assertEqual(after.receipts, (receipt,))
        after.require_current()
        (self.run / "admissions" / (receipt.task.task_id + ".json")).unlink()
        with self.assertRaises((ValueError, FileNotFoundError)):
            store.snapshot()

    def test_preparation_does_not_publish_or_require_an_objective_review(self):
        snapshot = AdmissionSnapshotStore(self.plan, self.run).snapshot()
        Path(self.files.objective_review).unlink()
        prepared = prepare_admission(self.plan, self.run, self.files, snapshot)
        self.assertFalse((self.run / "admissions").exists())
        self.assertFalse(prepared.student_grounded_success)
        with self.assertRaises(FileNotFoundError):
            commit_prepared_admission(self.plan, self.run, prepared, snapshot, Path(self.files.objective_review))
        self.assertFalse((self.run / "admissions").exists())

    def test_atomic_commit_preserves_failed_student_and_detects_stale_inventory(self):
        store = AdmissionSnapshotStore(self.plan, self.run)
        snapshot = store.snapshot()
        prepared = prepare_admission(self.plan, self.run, self.files, snapshot)
        receipt = commit_prepared_admission(
            self.plan, self.run, prepared, snapshot, Path(self.files.objective_review))
        self.assertFalse(receipt.student_grounded_success)
        with self.assertRaises(InventoryAdvanced):
            commit_prepared_admission(self.plan, self.run, prepared, snapshot, Path(self.files.objective_review))
        self.assertEqual(commit_prepared_admission(
            self.plan, self.run, prepared, store.snapshot(), Path(self.files.objective_review)), receipt)
        self.assertEqual(len(list((self.run / "admissions").glob("*.json"))), 1)

    def test_mutated_prepared_gate_and_unverified_preparation_cannot_commit(self):
        snapshot = AdmissionSnapshotStore(self.plan, self.run).snapshot()
        prepared = prepare_admission(self.plan, self.run, self.files, snapshot)
        with self.assertRaisesRegex(ValueError, "prepared admission belongs"):
            commit_prepared_admission(
                self.plan, self.run, replace(prepared, _authority=None), snapshot, Path(self.files.objective_review))
        path = self.difficulty / "difficulty-review.json"
        data = json.loads(path.read_bytes())
        data["recommendation"] = "reject"
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "validated artifact changed"):
            commit_prepared_admission(self.plan, self.run, prepared, snapshot, Path(self.files.objective_review))
        self.assertFalse((self.run / "admissions").exists())

    def test_incremental_objective_coverage_is_bound_and_legacy_review_remains_valid(self):
        snapshot = AdmissionSnapshotStore(self.plan, self.run).snapshot()
        inventory = snapshot.inventory(self.plan, excluding=self.case.task.task_id)
        prepared = prepare_admission(self.plan, self.run, self.files, snapshot)
        original = Path(self.files.objective_review)
        path = self.root / "objective-coverage.json"
        part = ObjectiveReviewPart(
            inventory=inventory, review=original.name,
            review_sha256=hashlib.sha256(original.read_bytes()).hexdigest(),
        )
        coverage = ObjectiveReviewCoverage(
            task_fingerprint=fingerprint(self.case.task), inventory=inventory, parts=(part,),
        )
        path.write_text(coverage.model_dump_json())
        receipt = commit_prepared_admission(self.plan, self.run, prepared, snapshot, path)
        self.assertIn(str(original), receipt.source_artifacts_sha256)
        self.assertIn(str(path), receipt.source_artifacts_sha256)

    def test_in_memory_preparation_changes_cannot_omit_provenance_or_change_student_results(self):
        snapshot = AdmissionSnapshotStore(self.plan, self.run).snapshot()
        prepared = prepare_admission(self.plan, self.run, self.files, snapshot)
        changed_provenance = replace(prepared, hashes=dict(prepared.hashes))
        changed_provenance.hashes.pop(str(self.difficulty / "difficulty-review.json"))
        for changed in (changed_provenance, replace(prepared, student_grounded_success=True)):
            with self.subTest(student_success=changed.student_grounded_success):
                with self.assertRaisesRegex(ValueError, "preparation changed in memory"):
                    commit_prepared_admission(
                        self.plan, self.run, changed, snapshot, Path(self.files.objective_review))
        self.assertFalse((self.run / "admissions").exists())


class ObjectiveCoverageTests(unittest.TestCase):
    def test_missing_and_overlapping_comparisons_are_not_complete_coverage(self):
        inventory = ObjectiveInventory(questions=(("one", "a" * 64), ("two", "b" * 64)))
        first = ObjectiveReviewPart(inventory=ObjectiveInventory(questions=inventory.questions[:1]),
                                    review="first/review.json", review_sha256="c" * 64)
        for parts in ((first,), (first, first)):
            with self.subTest(parts=len(parts)), self.assertRaises(ValueError):
                ObjectiveReviewCoverage(task_fingerprint="d" * 64, inventory=inventory, parts=parts)

    def test_empty_parts_cannot_repeat_an_unchanged_review(self):
        with self.assertRaisesRegex(ValueError, "actual new comparisons"):
            ObjectiveReviewPart(inventory=ObjectiveInventory(questions=()), review="empty/review.json",
                                review_sha256="a" * 64)


class ParallelFinalizationTests(unittest.TestCase):
    def fixture(self, task_id):
        fixture = admission_tests.AdmissionTests()
        original_question = admission_tests.question

        def question(name):
            return original_question(task_id if name == "new-incident-34-01" else name)

        with patch.object(admission_tests, "question", side_effect=question):
            fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def setUp(self):
        self.first = self.fixture("new-incident-34-01")
        self.second = self.fixture("new-incident-34-02")
        self.assertEqual(self.first.plan, self.second.plan)
        self.run, self.plan = self.first.run, self.first.plan
        shutil.copytree(
            self.second.run / "attempts" / self.second.case.task.task_id,
            self.run / "attempts" / self.second.case.task.task_id,
        )
        self.store = AdmissionSnapshotStore(self.plan, self.run)

    def runner(self, fixture):
        output = Path(fixture.files.question_inputs).parent
        completed = {}
        binding = {"fixture_pipeline": fingerprint(fixture.case.task)}

        def stage(name, action):
            result = run_stage(output / name, {"pipeline": binding, "prior_stage_receipts": dict(completed)}, action)
            completed[name] = file_sha256(output / name / "stage-receipt.json")
            if result.status == "held":
                return {"task_id": fixture.case.task.task_id, "status": "held", "stage": name, "reason": result.reason}
            return None

        for name in ("grading", "native", "baseline", "robustness", "canonical", "difficulty"):
            stage(name, lambda folder: StageResult(status="pass", reason="Controlled completed-stage fixture."))

        def run():
            return parallel_finalize(
                plan=self.plan, run=self.run, task=fixture.case.task, source=None, client=None,
                output=output, files=fixture.files, store=self.store, completed=completed, stage=stage,
            )

        return run

    def exercise(self, *, duplicates):
        first, second = self.runner(self.first), self.runner(self.second)
        barrier, probe_lock, calls_lock = Barrier(2), Lock(), Lock()
        calls = []

        def reviewer(client, source, directory, role, instructions, context, result_type, validate):
            ids = tuple(value["task_id"] for value in context["comparisons"])
            with probe_lock, (self.run / "admission-finalization.lock").open("a+") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(lock, fcntl.LOCK_UN)
            with calls_lock:
                calls.append((context["task_fingerprint"], ids))
            peer = tuple(task_id for task_id in ids if task_id.startswith("new-incident-"))
            if not peer:
                barrier.wait(timeout=10)
            return ObjectiveReview(
                task_fingerprint=context["task_fingerprint"], subject_fingerprint=context["subject_fingerprint"],
                recommendation="reject" if duplicates and peer else "pass",
                reviewer="controlled-concurrency-fixture", reasons=("Exact supplied comparison set inspected.",),
                duplicate_task_ids=peer if duplicates else (),
            )

        with patch("secgym.qagen.agentic.preproduction_pipeline.inspected_role", side_effect=reviewer):
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(first), executor.submit(second)]
                results = [future.result(timeout=30) for future in futures]
        return results, calls

    def test_simultaneous_duplicates_cannot_both_be_admitted(self):
        results, calls = self.exercise(duplicates=True)
        self.assertEqual(sorted(result["status"] for result in results), ["admitted", "held"])
        self.assertEqual(len(list((self.run / "admissions").glob("*.json"))), 1)
        self.assertEqual(len(calls), 3)
        self.assertEqual(sum(ids == ("development-seed",) for _, ids in calls), 2)
        self.assertEqual(sum(len(ids) == 1 and ids[0].startswith("new-incident-") for _, ids in calls), 1)

    def test_inventory_advance_reviews_only_the_new_peer_and_preserves_old_reviews(self):
        results, calls = self.exercise(duplicates=False)
        self.assertTrue(all(result["status"] == "admitted" for result in results))
        self.assertEqual(len(calls), 3)
        receipts = self.store.snapshot().receipts
        self.assertEqual(len(receipts), 2)
        part_counts = []
        for fixture in (self.first, self.second):
            output = Path(fixture.files.question_inputs).parent
            files = json.loads((output / "admission-files.json").read_bytes())
            coverage = ObjectiveReviewCoverage.model_validate_json(Path(files["objective_review"]).read_bytes())
            part_counts.append(len(coverage.parts))
            all_ids = [task_id for part in coverage.parts for task_id, _ in part.inventory.questions]
            self.assertEqual(len(all_ids), len(set(all_ids)))
        self.assertEqual(sorted(part_counts), [1, 2])

    def test_committed_receipt_can_finish_publication_without_another_model_call(self):
        output = self.run / "attempts" / self.first.case.task.task_id / "pipeline/parallel"
        inputs = admission_tests.write_inputs(output, (self.first.case,))
        self.first.files = self.first.files.model_copy(update={"question_inputs": str(inputs)})
        (output / "binding.json").write_text(json.dumps({
            "parallel_finalization": "incremental-objective-review-v1",
        }))
        run = self.runner(self.first)
        snapshot = self.store.snapshot()

        def review(client, source, directory, role, instructions, context, result_type, validate):
            return ObjectiveReview(
                task_fingerprint=context["task_fingerprint"], subject_fingerprint=context["subject_fingerprint"],
                recommendation="pass", reviewer="fixture", reasons=("Initial inventory compared.",),
            )

        with patch("secgym.qagen.agentic.preproduction_pipeline.inspected_role", side_effect=review) as model, \
             patch("secgym.qagen.agentic.preproduction_pipeline._publish_parallel_admission",
                   side_effect=OSError("publication interrupted")):
            with self.assertRaisesRegex(OSError, "publication interrupted"):
                run()
        self.assertEqual(model.call_count, 1)
        with self.assertRaises(InventoryAdvanced):
            snapshot.require_current()
        receipt, = self.store.snapshot().receipts
        with patch("secgym.qagen.agentic.preproduction_pipeline.inspected_role",
                   side_effect=AssertionError("completed review repeated")), \
             patch("secgym.qagen.agentic.preproduction_pipeline.run_stage",
                   side_effect=AssertionError("completed candidate stage repeated")), \
             patch("secgym.qagen.agentic.preproduction_pipeline.configured_model_binding",
                   return_value=self.plan.model):
            arguments = dict(
                plan=self.plan, run=self.run, task_id=receipt.task.task_id, client=ConfiguredFake([]),
                source=None, mysql=None, student=None, serving_bundle=self.first.root / "unused",
                mysql_bundle=self.first.root / "unused", graph_bundle=self.first.root / "unused",
                mysqld=self.first.root / "unused", workdir=self.first.root, output=output, resume=True,
                finalization_store=self.store,
            )
            result = run_candidate_pipeline(**arguments)
            self.assertEqual(run_candidate_pipeline(**arguments), result)
        self.assertEqual(result["status"], "admitted")
        self.assertEqual(len(list((self.run / "admissions").glob("*.json"))), 1)

    def test_eight_candidate_objective_reviews_overlap_before_atomic_commits(self):
        fixtures = [self.first, self.second]
        for number in range(3, 9):
            fixture = self.fixture(f"new-incident-34-{number:02d}")
            self.assertEqual(fixture.plan, self.plan)
            shutil.copytree(
                fixture.run / "attempts" / fixture.case.task.task_id,
                self.run / "attempts" / fixture.case.task.task_id,
            )
            fixtures.append(fixture)
        runners = [self.runner(fixture) for fixture in fixtures]
        barrier, lock = Barrier(8), Lock()
        active = peak = 0

        def review(client, source, directory, role, instructions, context, result_type, validate):
            nonlocal active, peak
            self.assertEqual(role, "objective-reviewer")
            ids = {value["task_id"] for value in context["comparisons"]}
            if ids == {"development-seed"}:
                with lock:
                    active += 1
                    peak = max(peak, active)
                barrier.wait(timeout=20)
                with lock:
                    active -= 1
            return ObjectiveReview(
                task_fingerprint=context["task_fingerprint"], subject_fingerprint=context["subject_fingerprint"],
                recommendation="pass", reviewer="eight-worker-fixture", reasons=("Exact supplied inventory compared.",),
            )

        with patch("secgym.qagen.agentic.preproduction_pipeline.inspected_role", side_effect=review):
            with ThreadPoolExecutor(max_workers=8) as executor:
                futures = [executor.submit(run) for run in runners]
                results = [future.result(timeout=90) for future in futures]
        self.assertEqual(peak, 8)
        self.assertTrue(all(result["status"] == "admitted" for result in results))
        self.assertEqual(len(list((self.run / "admissions").glob("*.json"))), 8)


if __name__ == "__main__":
    unittest.main()
