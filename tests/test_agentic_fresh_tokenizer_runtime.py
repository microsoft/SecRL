"""Synthetic metadata/lock fixtures; no live authority or historical SQL execution."""

import ast
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch
import zipfile

from secgym.qagen.agentic import checkpoint_batches as batches
from secgym.qagen.agentic import preproduction_admission as admission
from secgym.qagen.agentic import transport_amendments as amendments
from secgym.qagen.agentic.contracts import Contract, fingerprint
from secgym.qagen.agentic.ledger import file_sha256
from secgym.qagen.agentic.preproduction import PreproductionPlan, runtime_hashes
from secgym.qagen.agentic.preproduction_revisions import validate_source_audit_runtime
from secgym.qagen.agentic.quality import runtime_hashes as quality_hashes


ROOT = Path(__file__).resolve().parents[2]
RUN = ROOT.parents[2]
OUTPUT = Path(os.environ["FRESH_GUARD_TEST_OUTPUT"]).resolve() if "FRESH_GUARD_TEST_OUTPUT" in os.environ else None
if OUTPUT is not None:
    assert OUTPUT.is_relative_to(ROOT)


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def archive(path, directory):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as stream:
        for file in sorted(directory.glob("*.py")):
            stream.writestr(file.name, file.read_bytes())
    return amendments._archive_manifest(path)


def helper_module():
    path = ROOT / "private/historical_controller_readback_v2.py"
    spec = importlib.util.spec_from_file_location("guard_readback_test_helper", path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = value
    spec.loader.exec_module(value)
    return value


class Task(Contract):
    task_id: str


class Fixture:
    def __init__(self, root):
        self.run = root
        root.mkdir(parents=True)
        self.plan = PreproductionPlan.model_validate_json((RUN / "plan.json").read_bytes()).model_copy(
            update={"implementation_sha256": runtime_hashes()})
        save(root / "plan.json", self.plan.model_dump(mode="json"))
        self.before_path, self.after_path = root / "m5.zip", root / "guard.zip"
        self.before = archive(self.before_path, ROOT / "baseline/secgym/qagen/agentic")
        self.after = archive(self.after_path, ROOT / "worktree/secgym/qagen/agentic")
        save(root / "synthetic-transport.json", {"fixture": "metadata-chain-input"})
        save(root / "prior-qualification.json", {"fixture": "existing-ancestor-input"})
        self.prior_approval = amendments.ParallelFinalizationApproval(
            plan_fingerprint=fingerprint(self.plan),
            previous_manifest_sha256=amendments._manifest_digest(self.before),
            current_manifest_sha256=amendments._manifest_digest(self.before),
            qualification="prior-qualification.json", qualification_sha256=file_sha256(root / "prior-qualification.json"),
            approval_context="Synthetic registered ancestor fixture, not a real transport transition.",
            approved=True,
        )
        save(root / "prior-approval.json", self.prior_approval.model_dump(mode="json"))
        envelope = {name: self.before[name] for name in runtime_hashes()}
        self.prior = amendments.ParallelFinalizationRuntime(
            plan_fingerprint=fingerprint(self.plan), previous_runtime_sha256=envelope,
            current_runtime_sha256=envelope, archive="m5.zip", archive_sha256=file_sha256(self.before_path),
            approval="prior-approval.json", approval_sha256=file_sha256(root / "prior-approval.json"),
            transport_amendment_sha256=file_sha256(root / "synthetic-transport.json"),
            reason="Synthetic metadata ancestor; no actual provider authority.",
        )
        save(root / "parallel-finalization-runtime/0000.json", self.prior.model_dump(mode="json"))
        self.task = Task(task_id="guard-history-fixture")
        self.certificate = root / "campaign-control/reviewed-attempts/guard-history-fixture.json"
        self.record = {
            "policy": "reviewed-completed-source-student-failure-v3",
            "task_id": self.task.task_id, "task_fingerprint": fingerprint(self.task),
            "retry_or_admission_authorized": False,
            "capture_kernel_sha256": {name: self.before[name] for name in ("evidence.py", "generation.py", "query.py")},
        }
        save(self.certificate, self.record)
        self.carrier = root / "carrier"
        modules = self.carrier / "secgym/qagen/agentic"
        modules.mkdir(parents=True)
        with zipfile.ZipFile(self.before_path) as stream:
            for name in self.before:
                (modules / name).write_bytes(stream.read(name))
        self.inventory = amendments.HistoricalReadbackInventory(
            plan_fingerprint=fingerprint(self.plan), ancestor_manifest_sha256=amendments._manifest_digest(self.before),
            certificate_sha256={str(self.certificate.relative_to(root)): file_sha256(self.certificate)},
            worker_policy_sha256={}, other_artifacts_sha256={},
        )
        save(root / "history.json", self.inventory.model_dump(mode="json"))
        save(root / "receipts.json", {"plan_fingerprint": fingerprint(self.plan), "receipt_sha256": {}})
        shutil.copyfile(ROOT / "private/checkpoint_campaign_worker8_cached_v5.py", root / "controller.py")
        shutil.copyfile(ROOT / "private/historical_controller_readback_v2.py", root / "helper.py")
        self.history = amendments.GuardHistoryScope(
            snapshot_status="final", groups=(amendments.GuardHistoryGroup(
                ancestor_runtime="parallel-finalization-runtime/0000.json",
                ancestor_runtime_sha256=file_sha256(root / "parallel-finalization-runtime/0000.json"),
                inventory="history.json", inventory_sha256=file_sha256(root / "history.json"),
                carrier_repository="carrier",
            ),),
            receipt_inventory="receipts.json", receipt_inventory_sha256=file_sha256(root / "receipts.json"),
            controller_source="controller.py", controller_source_sha256=file_sha256(root / "controller.py"),
            helper_source="helper.py", helper_source_sha256=file_sha256(root / "helper.py"),
        )
        evidence = {}
        for index, attempt in enumerate(self.plan.attempts()[:100]):
            item = root / "generation-batches/astra100-12/items" / (attempt.task_id + ".json")
            save(item, {"attempt": attempt.model_dump(mode="json")})
            result = root / "attempts" / attempt.task_id / "checkpoint-review-result.json"
            save(result, {"task_id": attempt.task_id, "status": "needs_revision"})
            evidence[str(result.relative_to(root))] = file_sha256(result)
        report = root / "generation-batches/astra100-12/checkpoint-report.json"
        save(report, {"batch_id": "astra100-12", "drafts": {"draft_ready": 100},
                      "source_reviews": {"needs_revision": 100}})
        process = subprocess.Popen([sys.executable, "-c", "pass"], cwd=root)
        process.wait()
        save(root / "closed-owner.json", {"pid": process.pid, "exit_code": 0, "synthetic_fixture": True})
        evidence["closed-owner.json"] = file_sha256(root / "closed-owner.json")
        self.drain = amendments.GuardDrainInventory(
            plan_fingerprint=fingerprint(self.plan), closed_owner_pids=(process.pid,),
            owner_evidence_sha256=evidence,
            completed_batch_reports_sha256={str(report.relative_to(root)): file_sha256(report)},
            required_locks=("campaign-control/controller.lock", "checkpoint-workflow.lock"),
            original_native_wave_drained=True, source_audit_drained=True, all_m5_repair_owners_drained=True,
        )
        save(root / "drain.json", self.drain.model_dump(mode="json"))
        for name in self.drain.required_locks:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        (root / "run.lock").touch()
        self.scope = amendments.QueryTokenizationScope()
        self.qualification = {
            "status": "pass", "current_manifest_sha256": amendments._manifest_digest(self.after),
            "query_tokenization_scope": self.scope.model_dump(mode="json"),
            "historical_readback_scope": self.history.model_dump(mode="json"),
            **{name: True for name in (
                "guard_tests_passed", "readback_tests_passed", "old_execution_rejected", "fresh_policy_tests_passed",
                "actual_controller_qualified", "all_current_receipts_verified", "old_dispositions_unchanged",
                "m5_native_audit_repair_owners_drained",
            )},
            "model_calls": 0, "evidence_sha256": {"closed-owner.json": file_sha256(root / "closed-owner.json")},
            "fixture_only": "Synthetic final qualification input, never a real-run approval.",
        }
        self.refresh_approval()
        self.runtime = amendments.QueryTokenizationRuntime(
            plan_fingerprint=fingerprint(self.plan), previous_runtime_sha256=self.prior.current_runtime_sha256,
            current_runtime_sha256=runtime_hashes(), archive="guard.zip", archive_sha256=file_sha256(self.after_path),
            approval="guard-approval.json", approval_sha256=file_sha256(root / "guard-approval.json"),
            previous_parallel_sha256=file_sha256(root / "parallel-finalization-runtime/0000.json"),
            transport_amendment_sha256=file_sha256(root / "synthetic-transport.json"),
            reason="Synthetic fresh-only guard transition.",
        )

    def refresh_approval(self):
        save(self.run / "qualification.json", self.qualification)
        self.approval = amendments.QueryTokenizationApproval(
            plan_fingerprint=fingerprint(self.plan),
            previous_manifest_sha256=amendments._manifest_digest(self.before),
            current_manifest_sha256=amendments._manifest_digest(self.after),
            qualification="qualification.json", qualification_sha256=file_sha256(self.run / "qualification.json"),
            approved=True, approval_context="Synthetic unit fixture only.",
            query_tokenization_scope=self.scope, historical_readback_scope=self.history,
            drain_inventory="drain.json", drain_inventory_sha256=file_sha256(self.run / "drain.json"),
        )
        save(self.run / "guard-approval.json", self.approval.model_dump(mode="json"))


@unittest.skipUnless(OUTPUT is not None, "requires the explicit private FRESH_GUARD_TEST_OUTPUT qualification fixture")
class FreshGuardTests(unittest.TestCase):
    def setUp(self):
        assert OUTPUT is not None
        self.f = Fixture(OUTPUT / self.id().split(".")[-1])

    def test_guard_discriminators_preserve_truthful_fresh_only_scope(self):
        runtime = amendments.parse_finalization_runtime(self.f.runtime.model_dump_json().encode())
        approval = amendments.parse_finalization_approval(self.f.approval.model_dump_json().encode())
        self.assertIsInstance(runtime, amendments.QueryTokenizationRuntime)
        self.assertIsInstance(approval, amendments.QueryTokenizationApproval)
        for name, value in (("fresh_tasks_only", False), ("successful_query_serialization_changed", True),
                            ("old_source_worker_native_execution_compatibility", True),
                            ("journal_recovery_authorized", True)):
            altered = self.f.scope.model_dump(mode="json")
            altered[name] = value
            with self.subTest(name=name), self.assertRaises(ValueError):
                amendments.QueryTokenizationScope.model_validate_json(json.dumps(altered))
        with self.assertRaises(ValueError):
            amendments.QuerySerializationApproval.model_validate_json(self.f.approval.model_dump_json())

    def test_exact_archive_pair_accepts_only_token_error_catch_and_authority_plumbing(self):
        amendments._validate_tokenization_sources(self.f.before_path, self.f.after_path, self.f.scope)
        bad = self.f.run / "bad.zip"
        with zipfile.ZipFile(self.f.after_path) as current, zipfile.ZipFile(bad, "w") as output:
            for name in current.namelist():
                data = current.read(name) + (b"\n# changed protected scorer\n" if name == "scoring.py" else b"")
                output.writestr(name, data)
        with self.assertRaisesRegex(ValueError, "only its exact M5"):
            amendments._validate_tokenization_sources(self.f.before_path, bad, self.f.scope)
        with self.assertRaises(ValueError):
            amendments._validate_tokenization_sources(self.f.after_path, self.f.before_path, self.f.scope)

    def test_provisional_history_missing_final_evidence_and_live_owners_refuse_recording(self):
        provisional = self.f.approval.model_copy(update={
            "historical_readback_scope": self.f.history.model_copy(update={"snapshot_status": "provisional"}),
        })
        with self.assertRaisesRegex(ValueError, "provisional"):
            with amendments.query_guard_cutover_fences(self.f.plan, self.f.run, provisional):
                self.fail("provisional history accepted")
        with (self.f.run / "campaign-control/controller.lock").open("rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(ValueError, "not drained"):
                with amendments.query_guard_cutover_fences(self.f.plan, self.f.run, self.f.approval):
                    self.fail("held original controller accepted")
        drain = self.f.drain.model_copy(update={"closed_owner_pids": (os.getpid(),)})
        save(self.f.run / "drain.json", drain.model_dump(mode="json"))
        approval = self.f.approval.model_copy(update={"drain_inventory_sha256": file_sha256(self.f.run / "drain.json")})
        with self.assertRaisesRegex(ValueError, "alive"):
            with amendments.query_guard_cutover_fences(self.f.plan, self.f.run, approval):
                self.fail("live original owner accepted")

    def test_final_qualification_is_hash_bound_and_failed_checks_are_not_waived(self):
        amendments._validate_tokenization_qualification(self.f.plan, self.f.run, self.f.approval, self.f.after)
        self.f.qualification["all_current_receipts_verified"] = False
        self.f.refresh_approval()
        with self.assertRaisesRegex(ValueError, "post-drain"):
            amendments._validate_tokenization_qualification(self.f.plan, self.f.run, self.f.approval, self.f.after)

    def test_readback_uses_exact_carrier_and_rejects_unregistered_mutated_or_wrong_task_records(self):
        _, groups, _ = amendments._guard_history_artifacts(self.f.plan, self.f.run, self.f.history)
        module = helper_module()
        history = module.HistoricalReadback(self.f.plan, self.f.run, self.f.run / "controller.py",
                                           self.f.history, groups)
        history.require_source_certificate(self.f.certificate, self.f.task, self.f.record)
        self.assertEqual(history.repository_for_certificate(self.f.certificate, self.f.task, self.f.record),
                         self.f.carrier)
        with self.assertRaises(ValueError):
            history.require_source_certificate(self.f.certificate, Task(task_id="wrong"), self.f.record)
        unregistered = self.f.certificate.with_name("unregistered.json")
        save(unregistered, self.f.record)
        with self.assertRaisesRegex(ValueError, "unregistered"):
            history.require_source_certificate(unregistered, self.f.task, self.f.record)
        (self.f.carrier / "secgym/qagen/agentic/query.py").write_text("# mutated carrier\n")
        with self.assertRaisesRegex(ValueError, "carrier"):
            history.repository_for_certificate(self.f.certificate, self.f.task, self.f.record)
        with self.assertRaises(ValueError):
            amendments._guard_history_artifacts(self.f.plan, self.f.run, self.f.history)

    def test_archive_reference_is_exact_and_cannot_grandfather_unrelated_sources(self):
        artifact = self.f.run / "historical-package/query.py"
        artifact.parent.mkdir()
        artifact.write_bytes((ROOT / "baseline/secgym/qagen/agentic/query.py").read_bytes())
        receipt = self.f.run / "admissions/fixture.json"
        save(receipt, {"task": {"task_id": "fixture"},
                       "source_artifacts_sha256": {str(artifact): self.f.before["query.py"]}})
        reference = amendments.ArchivedProducerReference(
            receipt="admissions/fixture.json", receipt_sha256=file_sha256(receipt), artifact=str(artifact),
            artifact_sha256=self.f.before["query.py"], archive_member="query.py",
        )
        amendments._validate_guard_archived_references(self.f.run, (reference,), self.f.before)
        bad = reference.model_copy(update={"archive_member": "scoring.py"})
        with self.assertRaises(ValueError):
            amendments._validate_guard_archived_references(self.f.run, (bad,), self.f.before)

    def test_fresh_policy_creation_works_but_old_source_and_batch_execution_stay_rejected(self):
        run = self.f.run / "fresh-run"
        save(run / "plan.json", self.f.plan.model_dump(mode="json"))
        policy = batches.create_batch(run, "fresh-only-probe", checkpoint_size=1)
        self.assertEqual(policy.source_generation_runtime_sha256["query.py"], self.f.scope.current_query_sha256)
        old = policy.model_copy(update={"source_generation_runtime_sha256": {
            **policy.source_generation_runtime_sha256, "query.py": self.f.scope.previous_query_sha256,
        }})
        old_run = self.f.run / "old-run"
        save(old_run / "plan.json", self.f.plan.model_dump(mode="json"))
        save(old_run / "generation-batches" / old.batch_id / "policy.json", old.model_dump(mode="json"))
        with self.assertRaisesRegex(ValueError, "pinned source runtime"):
            batches._check_policy(self.f.plan, old_run, old)
        task = self.f.task
        source = run / "attempts" / task.task_id / "source"
        source.mkdir(parents=True)
        old_quality = {**quality_hashes(), "query.py": self.f.scope.previous_query_sha256}
        with self.assertRaisesRegex(ValueError, "explicit revalidation"):
            validate_source_audit_runtime(source, task, old_quality)
        old_quality["query.py"] = "1d82b8bb635b667e3a47f738362abce24c9114cc6e45c5e1da93b0c4138ff1aa"
        with self.assertRaisesRegex(ValueError, "explicit revalidation"):
            validate_source_audit_runtime(source, task, old_quality)

    def test_actual_native_runtime_guard_rejects_both_old_query_hashes(self):
        tree = ast.parse(Path(admission.__file__).read_bytes())
        message = "native grading result bounds or runtime changed"
        conditions = [
            node for node in ast.walk(tree) if isinstance(node, ast.If)
            and any(isinstance(child, ast.Raise) and any(
                isinstance(value, ast.Constant) and value.value == message for value in ast.walk(child)
            ) for child in node.body)
        ]
        self.assertEqual(len(conditions), 1)
        code = compile(ast.fix_missing_locations(ast.Module(body=conditions, type_ignores=[])), admission.__file__, "exec")
        from types import SimpleNamespace
        limits = self.f.plan.query_limits.model_copy(update={
            "timeout_ms": self.f.plan.grader_timeout_ms or self.f.plan.query_limits.timeout_ms})
        current = {name: file_sha256(Path(admission.__file__).with_name(name)) for name in admission.NATIVE_RUNTIME_FILES}
        context = {
            "plan": self.f.plan, "Path": Path, "__file__": admission.__file__,
            "NATIVE_RUNTIME_FILES": admission.NATIVE_RUNTIME_FILES, "file_sha256": file_sha256,
        }
        exec(code, {**context, "native_binding": SimpleNamespace(grader_query_limits=limits,
                                                                implementation_sha256=current)})
        for old in (self.f.scope.previous_query_sha256,
                    "1d82b8bb635b667e3a47f738362abce24c9114cc6e45c5e1da93b0c4138ff1aa"):
            with self.subTest(old=old), self.assertRaisesRegex(ValueError, message):
                exec(code, {**context, "native_binding": SimpleNamespace(
                    grader_query_limits=limits, implementation_sha256={**current, "query.py": old})})

    def test_publication_context_holds_one_fence_and_cannot_escape_its_lifetime(self):
        def record(*args, **kwargs):
            for name in self.f.drain.required_locks:
                with (self.f.run / name).open("rb") as competing:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(competing, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return self.f.runtime

        with patch.object(amendments, "_record_finalization_correction", side_effect=record) as recorder:
            with amendments.query_guard_publication(
                self.f.plan, self.f.run, approval=self.f.run / "guard-approval.json",
            ) as publish:
                (self.f.run / "simulated-installed-marker").write_text("owned fixture only")
                self.assertEqual(publish(archive=self.f.after_path, reason="Synthetic guarded installation."),
                                 self.f.runtime)
            with self.assertRaisesRegex(ValueError, "ownership fence"):
                publish(archive=self.f.after_path, reason="Must refuse after lock release.")
            self.assertEqual(recorder.call_count, 1)

    def test_publication_context_refuses_approval_replacement(self):
        approval = self.f.run / "guard-approval.json"
        with patch.object(amendments, "_record_finalization_correction") as recorder:
            with amendments.query_guard_publication(self.f.plan, self.f.run, approval=approval) as publish:
                approval.write_bytes(approval.read_bytes() + b"\n")
                with self.assertRaisesRegex(ValueError, "exact approval"):
                    publish(archive=self.f.after_path, reason="Must not adopt a changed approval.")
            recorder.assert_not_called()

    def test_recorder_appends_new_discriminator_only_after_real_guard_checks(self):
        # Isolate the existing provider/transport prefix; guard qualification,
        # locks, recorder, predecessor binding and immutable append execute normally.
        transport = amendments.TransportAmendment(
            plan_fingerprint=fingerprint(self.f.plan), authority_sha256=file_sha256(self.f.run / "plan.json"),
            previous_runtime_sha256=self.f.prior.current_runtime_sha256,
            current_runtime_sha256=self.f.prior.current_runtime_sha256,
            archive="m5.zip", archive_sha256=file_sha256(self.f.before_path),
            current_archive="m5.zip", current_archive_sha256=file_sha256(self.f.before_path),
            reason="Synthetic upstream transport fixture.",
        )
        save(self.f.run / "transport-amendments/0000.json", transport.model_dump(mode="json"))

        def validate(plan, run, recorded, *, pending_parallel):
            self.assertEqual(recorded, transport)
            return amendments._parallel_step(
                plan, run, transport, self.f.before, self.f.before, self.f.prior.current_runtime_sha256,
                file_sha256(run / "parallel-finalization-runtime/0000.json"),
                pending_parallel, self.f.before_path,
            )

        original = (self.f.run / "parallel-finalization-runtime/0000.json").read_bytes()
        with patch.object(amendments, "_validate", side_effect=validate):
            value = amendments.record_query_tokenization_correction(
                self.f.plan, self.f.run, archive=self.f.after_path,
                approval=self.f.run / "guard-approval.json", reason="Synthetic fresh-only transition.",
            )
        self.assertIsInstance(value, amendments.QueryTokenizationRuntime)
        self.assertEqual((self.f.run / "parallel-finalization-runtime/0000.json").read_bytes(), original)
        self.assertIsInstance(amendments.parse_finalization_runtime(
            (self.f.run / "parallel-finalization-runtime/0001.json").read_bytes()), amendments.QueryTokenizationRuntime)


if __name__ == "__main__":
    unittest.main()
