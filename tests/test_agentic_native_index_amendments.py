# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_agentic_preproduction import PreproductionTests
from secgym.qagen.agentic.contracts import fingerprint
from secgym.qagen.agentic.ledger import file_sha256
from secgym.qagen.agentic.preproduction_revisions import (
    GRAPH_METHOD_TIME_INDEX, effective_native_plan, native_index_digest, native_index_history,
    native_index_manifest, record_native_index_amendment,
)
from secgym.qagen.agentic.shared_validation import register_snapshot_service, registered_snapshot_pool
from secgym.qagen.agentic.snapshot_service import SnapshotServiceBinding


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


class NativeIndexAmendmentTests(unittest.TestCase):
    setUp = PreproductionTests.setUp

    def prepare(self, **changes):
        self.mysql = self.root / "mysql"
        save(self.mysql / "mysql_report.json", {"status": "complete"})
        save(self.mysql / "index_report-v6.json", {"policy_version": "mysql-access-indexes-v6"})
        previous = {"index_report-v6.json": file_sha256(self.mysql / "index_report-v6.json")}
        self.plan = self.plan.model_copy(update={
            "native_snapshot_sha256": file_sha256(self.mysql / "mysql_report.json"),
            "native_indexes_sha256": native_index_digest(previous),
        })
        save(self.output / "plan.json", self.plan.model_dump(mode="json"))
        self.approval = self.output / "repair/approval.json"
        save(self.approval, {"approved": True})
        report = {
            "policy_version": "mysql-access-indexes-v7", "status": "complete",
            "previous_manifest": previous, "added_indexes": [GRAPH_METHOD_TIME_INDEX],
            "serving_report_sha256": self.plan.serving_report_sha256,
            "native_snapshot_sha256": self.plan.native_snapshot_sha256,
            "source_rows_modified": False, "verification_scope": "all_rows_of_indexed_tables",
            "unaffected_tables_retain_original_snapshot_verification": True,
            "verified_rows": 2, "verified_table_rows": {"MicrosoftGraphActivityLogs": 2},
            **changes,
        }
        self.report = self.output / "repair/index-report.json"
        save(self.report, report)
        save(self.mysql / "index_report-v7.json", report)

    def record(self):
        with patch("secgym.qagen.agentic.mysql_serving.load_serving_report", return_value={
            "tables": [{"table": "MicrosoftGraphActivityLogs", "rows": 2, "status": "public"}],
        }):
            return record_native_index_amendment(
                self.plan, self.output, mysql_bundle=self.mysql, serving_bundle=self.serving,
                report=self.report, approval=self.approval,
            )

    def test_explicit_upgrade_preserves_plan_and_history_and_changes_only_execution_indexes(self):
        self.prepare()
        original = (self.output / "plan.json").read_bytes()
        self.assertEqual(effective_native_plan(self.plan, self.output), self.plan)
        self.record()
        effective = effective_native_plan(self.plan, self.output)
        self.assertEqual(effective.native_indexes_sha256, native_index_digest(native_index_manifest(self.mysql)))
        self.assertEqual(native_index_history(self.plan, self.output),
                         (self.plan.native_indexes_sha256, effective.native_indexes_sha256))
        self.assertEqual(effective.model_copy(update={"native_indexes_sha256": self.plan.native_indexes_sha256}), self.plan)
        self.assertEqual((self.output / "plan.json").read_bytes(), original)
        with self.assertRaisesRegex(ValueError, "historical reports"):
            self.record()

    def test_incomplete_or_wrong_upgrade_never_publishes_an_amendment(self):
        for change in (
            {"verified_rows": 1}, {"verification_scope": "sample"}, {"source_rows_modified": True},
            {"verified_table_rows": {"MicrosoftGraphActivityLogs": 1}},
            {"unaffected_tables_retain_original_snapshot_verification": False},
            {"added_indexes": []}, {"native_snapshot_sha256": "f" * 64}, {"status": "partial"},
        ):
            with self.subTest(change=change):
                self.prepare(**change)
                with self.assertRaises(ValueError):
                    self.record()
                self.assertFalse(any((self.output / "native-index-amendments").glob("*.json")))

    def test_missing_approval_and_modified_historical_manifests_are_rejected(self):
        self.prepare()
        save(self.approval, {"approved": False})
        with self.assertRaisesRegex(ValueError, "approved"):
            self.record()
        save(self.approval, {"approved": True})
        save(self.mysql / "index_report-v6.json", {"changed": True})
        with self.assertRaisesRegex(ValueError, "historical"):
            self.record()

    def test_changed_evidence_or_broken_chain_is_rejected_after_publication(self):
        self.prepare()
        self.record()
        original = self.approval.read_bytes()
        save(self.approval, {"approved": False})
        with self.assertRaisesRegex(ValueError, "approval changed"):
            effective_native_plan(self.plan, self.output)
        self.approval.write_bytes(original)
        path = self.output / "native-index-amendments/0000.json"
        data = json.loads(path.read_bytes())
        data["previous_manifest"]["index_report-v6.json"] = "f" * 64
        save(path, data)
        with self.assertRaisesRegex(ValueError, "previous manifest"):
            effective_native_plan(self.plan, self.output)

    def test_service_routing_preserves_old_registration_and_requires_a_stopped_owner(self):
        self.prepare()
        self.record()
        effective = effective_native_plan(self.plan, self.output)
        old, new = self.root / "service-old", self.root / "service-new"
        base = dict(
            serving_view_id=self.plan.serving_view_id, serving_bundle=str(self.serving),
            mysql_bundle=str(self.mysql), serving_report_sha256=self.plan.serving_report_sha256,
            mysql_report_sha256=self.plan.native_snapshot_sha256, implementation_sha256="b" * 64,
        )
        old_binding = SnapshotServiceBinding(native_indexes_sha256=self.plan.native_indexes_sha256, **base)
        new_binding = SnapshotServiceBinding(native_indexes_sha256=effective.native_indexes_sha256, **base)
        save(old / "binding.json", old_binding.model_dump(mode="json"))
        save(new / "binding.json", new_binding.model_dump(mode="json"))
        save(old / "current.json", {"instance_id": "old-instance"})
        registration = self.output / "shared-sql-service.json"
        save(registration, {
            "policy_version": "shared-native-service-routing-v1", "plan_fingerprint": fingerprint(self.plan),
            "service_directory": str(old), "service_binding_fingerprint": fingerprint(old_binding),
            "service_binding_sha256": file_sha256(old / "binding.json"),
        })
        original = registration.read_bytes()
        pool = SimpleNamespace(binding=new_binding, plan=effective, status=lambda: {"status": "ready"})
        with patch("secgym.qagen.agentic.shared_validation.SnapshotServicePool", return_value=pool) as constructor:
            with self.assertRaisesRegex(ValueError, "must be stopped"):
                register_snapshot_service(self.output, new)
            save(old / "instances/old-instance/stopped.json", {"server_returncode": 0})
            register_snapshot_service(self.output, new)
            self.assertIs(registered_snapshot_pool(self.output), pool)
            self.assertEqual(constructor.call_args.args[1], effective)
            register_snapshot_service(self.output, new)
        self.assertEqual(registration.read_bytes(), original)
        self.assertEqual(len(list((self.output / "shared-sql-service-revisions").glob("*.json"))), 1)
