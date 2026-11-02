# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_agentic_preproduction_admission as fixtures
from secgym.qagen.agentic.contracts import fingerprint
from secgym.qagen.agentic.ledger import file_sha256
from secgym.qagen.agentic.preproduction import SourceOutcome
from secgym.qagen.agentic.preproduction_admission import (
    admitted_receipts, admitted_task, objective_inventory, record_admission,
    record_admitted_contract_revision, validate_admitted_contract_revision,
)
from secgym.qagen.agentic.preproduction_revisions import SourceRevision


class AdmittedContractRevisionTests(unittest.TestCase):
    setUp = fixtures.AdmissionTests.setUp
    review = fixtures.AdmissionTests.review
    admit = fixtures.AdmissionTests.admit

    def revised_task(self):
        task = self.case.task
        claim = task.private_gold.final
        witnesses = tuple(p.model_copy(update={"query": p.query + "\n"}) for p in claim.witness_programs)
        return task.model_copy(update={"revision_id": "r2", "private_gold": task.private_gold.model_copy(update={
            "final": claim.model_copy(update={"witness_programs": witnesses}),
        })})

    def stage(self, task):
        original = self.run / "attempts" / task.task_id / "source"
        outcome = SourceOutcome.model_validate_json((original.parent / "source-outcome.json").read_bytes())
        revision = original.parent / "revisions/0001"
        source = revision / "source"
        fixtures.save(source / "task.json", task)
        fixtures.save(revision / "request.json", {"private_contract_repair": True})
        fixtures.save(revision / "source-outcome.json", outcome.model_copy(update={
            "task_fingerprint": fingerprint(task), "artifact_sha256": {"task.json": file_sha256(source / "task.json")},
        }))
        fixtures.save(revision / "revision.json", SourceRevision(
            plan_fingerprint=fingerprint(self.plan), task_id=task.task_id, sequence=1,
            previous_source=str(original.relative_to(self.run)),
            previous_outcome_sha256=file_sha256(original.parent / "source-outcome.json"),
            previous_task_fingerprint=fingerprint(self.case.task), source_directory=str(source.relative_to(self.run)),
            source_outcome_sha256=file_sha256(revision / "source-outcome.json"),
            request_sha256=file_sha256(revision / "request.json"),
        ))
        return self.run / "admission-contract-revisions" / task.task_id / "0001.json"

    def authorize(self, task, path):
        return record_admitted_contract_revision(
            self.plan, self.run, task, destination=path,
            reason="Controlled private witness-contract revision preserving the exact public and typed goals.",
        )

    def test_revision_preserves_historical_receipt_count_and_objective_descriptor(self):
        original = self.admit()
        receipt_path = self.run / "admissions" / (original.task.task_id + ".json")
        before = receipt_path.read_bytes()
        inventory = objective_inventory(self.plan, self.run)
        task = self.revised_task()
        path = self.stage(task)
        revision = self.authorize(task, path)
        self.assertEqual(validate_admitted_contract_revision(self.plan, self.run, task, path), revision)
        self.assertEqual(revision.original_task_fingerprint, fingerprint(self.case.task))
        self.assertEqual(revision.revised_task_fingerprint, fingerprint(task))
        self.assertEqual(receipt_path.read_bytes(), before)
        self.assertEqual(len(admitted_receipts(self.plan, self.run)), 1)
        self.assertEqual(admitted_task(self.run, original), self.case.task)
        self.assertEqual(objective_inventory(self.plan, self.run), inventory)

    def test_public_goal_or_lineage_changes_cannot_receive_authorization(self):
        self.admit()
        task = self.revised_task()
        for changed in (
            task.model_copy(update={"question": task.question + " Different question."}),
            task.model_copy(update={"private_gold": task.private_gold.model_copy(update={
                "final": task.private_gold.final.model_copy(update={
                    "requires_behavior_evidence": not task.private_gold.final.requires_behavior_evidence,
                }),
            })}),
        ):
            path = self.stage(changed)
            with self.assertRaises(ValueError):
                self.authorize(changed, path)
            self.assertFalse(path.exists())

    def test_authorization_and_historical_receipt_tampering_are_detected(self):
        self.admit()
        task = self.revised_task()
        path = self.stage(task)
        self.authorize(task, path)
        original = path.read_bytes()
        data = json.loads(original)
        data["source_revision_sha256"] = "0" * 64
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "bindings changed"):
            validate_admitted_contract_revision(self.plan, self.run, task, path)
        path.write_bytes(original)
        receipt = self.run / "admissions" / (task.task_id + ".json")
        receipt.write_bytes(receipt.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "bindings changed"):
            validate_admitted_contract_revision(self.plan, self.run, task, path)

    def test_contract_authorization_neither_overwrites_admission_nor_waives_retained_student(self):
        self.admit()
        task = self.revised_task()
        path = self.stage(task)
        self.authorize(task, path)
        with self.assertRaisesRegex(ValueError, "separate fresh certificate"):
            record_admission(self.plan, self.run, self.files, admitted_contract_revision=path)
        revised_question = self.case.model_copy(update={"task": task})
        with patch("secgym.qagen.agentic.preproduction_admission.load_questions",
                   return_value=SimpleNamespace(questions=(revised_question,), source_hashes={})):
            with self.assertRaisesRegex(ValueError, "original retained native student"):
                record_admission(
                    self.plan, self.run, self.files, admitted_contract_revision=path,
                    revalidation_receipt=self.run / "revalidations" / task.task_id / "repaired.json",
                )
        self.assertEqual(len(admitted_receipts(self.plan, self.run)), 1)
