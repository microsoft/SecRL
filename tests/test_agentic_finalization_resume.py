# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import fcntl
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile

import test_agentic_preproduction as preproduction_tests
from secgym.qagen.agentic.contracts import fingerprint
from secgym.qagen.agentic.preproduction_admission import ObjectiveReview, objective_inventory
from secgym.qagen.agentic.preproduction_pipeline import StageResult, _json_hashes, _resume_finalization, objective_candidate, run_stage


MODULE = "secgym.qagen.agentic.preproduction_pipeline"


class FinalizationLockTests(unittest.TestCase):
    def setUp(self):
        preproduction_tests.PreproductionTests.setUp(self)
        self.output.mkdir()

    def test_objective_review_does_not_reacquire_its_callers_exclusive_lock(self):
        task = self.seed.model_copy(update={"task_id": "preprod-fixture-tenant-01"})
        inventory = objective_inventory(self.plan, self.output, excluding=task.task_id)
        review = ObjectiveReview(
            task_fingerprint=fingerprint(task), subject_fingerprint=fingerprint(inventory),
            recommendation="pass", reviewer="fixture", reasons=("Distinct scoped objective.",),
        )
        directory = self.root / "objective"
        directory.mkdir()
        real_flock = fcntl.flock

        def nonblocking(file, mode):
            return real_flock(file, mode | fcntl.LOCK_NB)

        with (self.output / "admission-finalization.lock").open("a+") as owner:
            real_flock(owner, fcntl.LOCK_EX)
            with patch(MODULE + ".fcntl.flock", side_effect=nonblocking), \
                 patch(MODULE + ".inspected_role", return_value=review):
                result = objective_candidate(self.plan, self.output, task, None, None, directory)
        self.assertEqual(result.status, "pass")


class CompletedPrefixResumeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.run = Path(self.temporary.name)
        self.output = self.run / "attempts/task/pipeline/r1"
        self.output.mkdir(parents=True)
        self.modules = {"preproduction_pipeline.py": b"original orchestration", "evidence.py": b"unchanged scoring"}
        self.original = {"task_fingerprint": "a" * 64, "plan_fingerprint": "b" * 64,
                         "native_execution": "leased-stage-v1",
                         "implementation_sha256": {name: hashlib.sha256(data).hexdigest() for name, data in self.modules.items()}}
        self.current = {**self.original, "implementation_sha256": {
            **self.original["implementation_sha256"], "preproduction_pipeline.py": hashlib.sha256(b"fixed orchestration").hexdigest(),
        }}
        (self.output / "binding.json").write_text(json.dumps(self.original))
        for name in ("grading", "native", "baseline", "robustness", "canonical", "difficulty"):
            run_stage(self.output / name, {"pipeline": self.original},
                      lambda folder: StageResult(status="pass", reason="Verified original completed stage."))
        self.archive = self.run / "original.zip"
        with ZipFile(self.archive, "w") as archive:
            for name, data in self.modules.items():
                archive.writestr(name, data)

    def test_append_only_execution_record_keeps_all_original_bindings_and_stages(self):
        before = _json_hashes(self.output)
        self.assertEqual(_resume_finalization(self.output, self.run, self.current, self.archive), self.original)
        self.assertEqual({name: _json_hashes(self.output)[name] for name in before}, before)
        after = _json_hashes(self.output)
        self.assertEqual(set(after) - before.keys(), {"finalization-resume.json"})
        self.assertEqual(_resume_finalization(self.output, self.run, self.current, self.archive), self.original)
        self.assertEqual(_json_hashes(self.output), after)

    def test_changed_task_and_scoring_kernel_cannot_resume(self):
        for current in (
            {**self.current, "task_fingerprint": "c" * 64},
            {**self.current, "implementation_sha256": {**self.current["implementation_sha256"], "evidence.py": "d" * 64}},
        ):
            with self.assertRaises(ValueError):
                _resume_finalization(self.output, self.run, current, self.archive)
        self.assertFalse((self.output / "finalization-resume.json").exists())

    def test_changed_passed_stage_and_wrong_archive_fail_closed(self):
        wrong = self.run / "wrong.zip"
        with ZipFile(wrong, "w") as archive:
            for name in self.modules:
                archive.writestr(name, b"wrong")
        with self.assertRaisesRegex(ValueError, "exact original producer"):
            _resume_finalization(self.output, self.run, self.current, wrong)
        (self.output / "native/changed.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "passed and unchanged"):
            _resume_finalization(self.output, self.run, self.current, self.archive)

    def test_started_objective_and_terminal_pipeline_cannot_restart(self):
        role = self.output / "objective-original/reviewer"
        role.mkdir(parents=True)
        request = role / "0000-request.json"
        request.write_text("{}")
        with self.assertRaisesRegex(ValueError, "started objective review"):
            _resume_finalization(self.output, self.run, self.current, self.archive)
        request.unlink()
        (self.output / "pipeline-report.json").write_text('{"status":"held"}')
        with self.assertRaisesRegex(ValueError, "unfinished pipeline"):
            _resume_finalization(self.output, self.run, self.current, self.archive)

    def test_resume_certificate_cannot_hide_mutated_original_history(self):
        _resume_finalization(self.output, self.run, self.current, self.archive)
        (self.output / "binding.json").write_text(json.dumps({**self.original, "plan_fingerprint": "e" * 64}))
        with self.assertRaises(ValueError):
            _resume_finalization(self.output, self.run, self.current, self.archive)


if __name__ == "__main__":
    unittest.main()
