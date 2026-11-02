# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import csv
import contextlib
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from test_agentic_difficulty import plan_for, review_for
import test_agentic_preproduction_admission as admission_tests
from test_agentic_question_splits import question, write_inputs
from secgym.qagen.agentic.contracts import fingerprint
from secgym.qagen.agentic.__main__ import main
from secgym.qagen.agentic.difficulty import measure_difficulty
from secgym.qagen.agentic.ledger import file_sha256
from secgym.qagen.agentic.private_bundle import export_private_bundle, load_private_bundle
from secgym.qagen.agentic.question_splits import Assignment, SplitPlan, cohort_fingerprint, load_questions


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value.model_dump_json() if hasattr(value, "model_dump_json") else json.dumps(value))


class PrivateBundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.questions = (question("development-one"), question("development-two", value="secret-answer-two"))
        self.development, self.index = self.development_fixture(self.questions)

    def development_fixture(self, questions, name="development"):
        directory = self.root / name
        inputs = write_inputs(directory, questions)
        loaded = load_questions(inputs)
        split = SplitPlan(cohort_fingerprint=cohort_fingerprint(questions), assignments=tuple(
            Assignment(task_id=q.task.task_id, task_fingerprint=fingerprint(q.task), partition="train" if i == 0 else "test")
            for i, q in enumerate(questions)
        ))
        split_path = directory / "membership/split-plan.json"
        save(split_path, split)
        entries, rows = [], []
        for q in questions:
            plan = plan_for(q)
            review = review_for(plan)
            sidecar = measure_difficulty(q, plan=plan, review=review)
            paths = {}
            for kind, value in (("plan", plan), ("review", review), ("sidecar", sidecar)):
                path = directory / "difficulty" / q.task.task_id / ("difficulty-" + kind + ".json")
                save(path, value)
                paths[kind] = str(path.relative_to(directory))
                paths[kind + "_sha256"] = file_sha256(path)
            entries.append({"task_id": q.task.task_id, **paths})
            axes = next(route.combined.axes for route in sidecar.routes if route.route_id == sidecar.selected_route)
            rows.append({"task_id": q.task.task_id, "task_fingerprint": fingerprint(q.task), "status": sidecar.status,
                         "score": sidecar.score, "band": sidecar.band, **axes.model_dump()})
        index = directory / "difficulty-index.json"
        save(index, {"entries": entries})
        csv_path = directory / "difficulty.csv"
        with csv_path.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        approval = {
            "status": "user_approved", "user_selection": "approve_refreshed_snapshot", "split_method": "explicit",
            "cohort_fingerprint": cohort_fingerprint(questions), "questions": len(questions), "train": 1, "test": len(questions) - 1,
            "source_artifacts_sha256": loaded.source_hashes,
            "reviewed_artifact_sha256": {str(path): file_sha256(path) for path in (inputs, split_path, csv_path)},
            "grading_amendments": [], "training_approved": False, "release_approved": False,
        }
        save(directory / "development-snapshot-approval.json", approval)
        return directory, index

    def export(self):
        output = self.root / "packet"
        manifest = export_private_bundle(development=self.development, difficulty_index=self.index, output=output)
        return output, manifest

    def reseal(self, output, name):
        path = output / "manifest.json"
        manifest = json.loads(path.read_bytes())
        manifest["artifacts_sha256"][name] = file_sha256(output / name)
        save(path, manifest)

    def test_relocation_uses_only_bundled_data_and_preserves_exact_bindings(self):
        output, before = self.export()
        relocated = self.root / "relocated"
        shutil.copytree(output, relocated)
        self.development.rename(self.root / "originals-unavailable")
        manifest, questions = load_private_bundle(relocated)
        self.assertEqual(manifest, before)
        self.assertEqual(cohort_fingerprint(questions), cohort_fingerprint(self.questions))
        self.assertEqual([q.partition for q in manifest.questions], ["train", "test"])
        public = (relocated / manifest.student_tasks).read_text()
        self.assertNotIn("private_gold", public)
        self.assertNotIn("secret-answer-two", public)
        self.assertFalse(manifest.release_approved)
        self.assertFalse(manifest.training_approved)
        self.assertFalse(manifest.source_snapshot_embedded)

    def test_changed_bytes_and_resealed_gold_leak_are_rejected(self):
        output, manifest = self.export()
        path = output / manifest.student_tasks
        original = path.read_bytes()
        path.write_bytes(original + b" ")
        with self.assertRaisesRegex(ValueError, "artifact changed"):
            load_private_bundle(output)
        data = json.loads(original)
        data[0]["private_gold"] = {"answer": "leaked"}
        save(path, data)
        self.reseal(output, manifest.student_tasks)
        with self.assertRaisesRegex(ValueError, "public-only"):
            load_private_bundle(output)

    def test_split_and_difficulty_cannot_be_retagged(self):
        output, manifest = self.export()
        manifest_path = output / "manifest.json"
        data = json.loads(manifest_path.read_bytes())
        data["questions"][0]["partition"] = "test"
        save(manifest_path, data)
        with self.assertRaisesRegex(ValueError, "assignment"):
            load_private_bundle(output)
        save(manifest_path, manifest)
        name = manifest.questions[0].difficulty_directory + "/difficulty-sidecar.json"
        sidecar = json.loads((output / name).read_bytes())
        sidecar["score"] += 1
        save(output / name, sidecar)
        self.reseal(output, name)
        with self.assertRaises(ValueError):
            load_private_bundle(output)

    def test_path_escape_unknown_file_and_existing_output_fail_closed(self):
        output, manifest = self.export()
        data = manifest.model_dump(mode="json")
        data["inputs"] = "../outside.json"
        save(output / "manifest.json", data)
        with self.assertRaisesRegex(ValueError, "public-only|portable relative"):
            load_private_bundle(output)
        save(output / "manifest.json", manifest)
        save(output / "unregistered.json", {})
        with self.assertRaisesRegex(ValueError, "inventory"):
            load_private_bundle(output)
        with self.assertRaisesRegex(ValueError, "new directory"):
            export_private_bundle(development=self.development, difficulty_index=self.index, output=output)

    def test_student_subdirectory_cannot_hide_an_extra_private_artifact(self):
        output, manifest = self.export()
        name = "student/hidden-gold.json"
        save(output / name, {"private_gold": "not student-visible"})
        data = manifest.model_dump(mode="json")
        data["artifacts_sha256"][name] = file_sha256(output / name)
        save(output / "manifest.json", data)
        with self.assertRaisesRegex(ValueError, "student directory public-only"):
            load_private_bundle(output)

    def test_cli_schema_export_and_relocated_check(self):
        for kind in ("private-bundle", "private-difficulty-index"):
            with patch("sys.argv", ["agentic", "schema", kind]), contextlib.redirect_stdout(io.StringIO()) as stream:
                main()
            self.assertIn("properties", json.loads(stream.getvalue()))
        output = self.root / "cli-packet"
        args = ["agentic", "export-private-bundle", "--development", str(self.development),
                "--difficulty-index", str(self.index), "--output", str(output)]
        with patch("sys.argv", args), contextlib.redirect_stdout(io.StringIO()) as stream:
            main()
        self.assertEqual(json.loads(stream.getvalue())["questions"], 2)
        with patch("sys.argv", ["agentic", "check-private-bundle", "--bundle", str(output)]), \
             contextlib.redirect_stdout(io.StringIO()) as stream:
            main()
        self.assertEqual(json.loads(stream.getvalue())["status"], "private_bundle_verified")

    def test_changed_source_difficulty_is_rejected_before_export(self):
        index = json.loads(self.index.read_bytes())
        path = self.development / index["entries"][0]["sidecar"]
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "source difficulty artifact changed"):
            self.export()
        self.assertFalse((self.root / "packet").exists())

    def test_admitted_new_questions_remain_unassigned_and_carry_all_dependencies(self):
        fixture = admission_tests.AdmissionTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        receipt = fixture.admit()
        development, index = self.development_fixture((question("development-seed"),), "production-development")
        output = self.root / "with-admission"
        manifest = export_private_bundle(development=development, difficulty_index=index,
                                         preproduction_run=fixture.run, output=output)
        entries = [entry for entry in manifest.questions if entry.origin == "preproduction"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].binding, receipt.task)
        self.assertEqual(entries[0].partition, "unassigned")
        for name, digest in receipt.source_artifacts_sha256.items():
            self.assertEqual(manifest.artifacts_sha256[manifest.original_paths[name]], digest)
        development.rename(self.root / "production-originals-unavailable")
        fixture.root.rename(fixture.root.with_name(fixture.root.name + "-unavailable"))
        self.addCleanup(shutil.rmtree, fixture.root.with_name(fixture.root.name + "-unavailable"))
        self.assertEqual(len(load_private_bundle(output)[1]), 2)


if __name__ == "__main__":
    unittest.main()
