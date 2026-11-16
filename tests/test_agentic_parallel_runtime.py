# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from contextlib import contextmanager
import hashlib
import inspect
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

import test_agentic_provider_defaults as provider_tests
from secgym.qagen.agentic import transport_amendments as amendments
from secgym.qagen.agentic.contracts import fingerprint
from secgym.qagen.agentic.ledger import file_sha256
from secgym.qagen.agentic.model_panel import immutable_json
from secgym.qagen.agentic.preproduction_revisions import effective_runtime
from secgym.qagen.agentic import preproduction_admission, query
from secgym.qagen.agentic.preproduction import runtime_hashes


class ParallelRuntimeTests(unittest.TestCase):
    setUp = provider_tests.TransportAmendmentTests.setUp
    record = provider_tests.TransportAmendmentTests.record
    save_archive = staticmethod(provider_tests.TransportAmendmentTests.save_archive)

    def candidate(self, *, change="preproduction_admission.py", status="pass"):
        transport = self.record()
        sources = {**self.sources, change: self.sources[change] + b"\n# controlled parallel-runtime fixture\n"}
        hashes = {name: hashlib.sha256(data).hexdigest() for name, data in sources.items()}
        archive = self.output / "parallel.zip"
        self.save_archive(archive, sources)
        qualification = self.output / "qualification.json"
        immutable_json(qualification, {
            "status": status, "current_manifest_sha256": amendments._manifest_digest(hashes),
        })
        approval = self.output / "parallel-approval.json"
        immutable_json(approval, amendments.ParallelFinalizationApproval(
            plan_fingerprint=fingerprint(self.plan),
            previous_manifest_sha256=amendments._manifest_digest({
                name: hashlib.sha256(data).hexdigest() for name, data in self.sources.items()}),
            current_manifest_sha256=amendments._manifest_digest(hashes),
            qualification=str(qualification.relative_to(self.output)),
            qualification_sha256=file_sha256(qualification), approval_context="Controlled runtime authority test.",
            approved=True,
        ))
        return transport, hashes, archive, approval

    @contextmanager
    def installed(self, transport, hashes):
        root = Path(amendments.__file__).parent
        expected = {name: hashes[name] for name in transport.current_runtime_sha256}

        def digest(path):
            return hashes[path.name] if path.parent == root and path.name in hashes else file_sha256(path)

        with patch.object(amendments, "file_sha256", side_effect=digest), \
             patch("secgym.qagen.agentic.preproduction.runtime_hashes", return_value=expected):
            yield expected

    def test_exact_post_transport_runtime_keeps_original_authority_and_plan(self):
        transport, hashes, archive, approval = self.candidate()
        original = (self.output / "transport-amendments/0000.json").read_bytes()
        plan = (self.output / "plan.json").read_bytes()
        with self.installed(transport, hashes) as expected:
            with self.assertRaisesRegex(ValueError, "installed audited runtime"):
                effective_runtime(self.plan, self.output)
            value = amendments.record_parallel_finalization_runtime(
                self.plan, self.output, archive=archive, approval=approval, reason="Exact tested orchestration change.",
            )
            self.assertEqual(effective_runtime(self.plan, self.output), expected)
            self.assertFalse(value.source_query_generation_scoring_kernels_changed)
            self.assertEqual(amendments.load_parallel_finalization_runtime(self.plan, self.output), value)
            with self.assertRaisesRegex(ValueError, "already exists"):
                amendments.record_parallel_finalization_runtime(
                    self.plan, self.output, archive=archive, approval=approval, reason="Duplicate.",
                )
        self.assertEqual((self.output / "transport-amendments/0000.json").read_bytes(), original)
        self.assertEqual((self.output / "plan.json").read_bytes(), plan)

    def test_protected_kernel_cannot_be_authorized_by_parallel_policy(self):
        transport, hashes, archive, approval = self.candidate(change="scoring.py")
        with self.installed(transport, hashes), self.assertRaisesRegex(ValueError, "protected kernels"):
            amendments.record_parallel_finalization_runtime(
                self.plan, self.output, archive=archive, approval=approval, reason="Must reject.",
            )
        self.assertFalse((self.output / amendments.PARALLEL_RUNTIME).exists())

    def test_provider_change_is_not_implied_by_parallel_finalization_approval(self):
        transport, hashes, archive, approval = self.candidate(change="provider_defaults.py")
        with self.installed(transport, hashes), self.assertRaisesRegex(ValueError, "protected kernels"):
            amendments.record_parallel_finalization_runtime(
                self.plan, self.output, archive=archive, approval=approval, reason="No provider recovery scope.",
            )
        self.assertFalse((self.output / amendments.PARALLEL_RUNTIME).exists())

    def test_checkpoint_change_requires_an_explicit_progress_caching_scope(self):
        transport, hashes, archive, approval = self.candidate(change="checkpoint_batches.py")
        with self.installed(transport, hashes), self.assertRaisesRegex(ValueError, "protected kernels"):
            amendments.record_parallel_finalization_runtime(
                self.plan, self.output, archive=archive, approval=approval, reason="No progress-cache scope.")

    def caching_candidate(self, *, unrelated=None):
        transport = self.record()
        names = ("preproduction_admission.py", "checkpoint_batches.py")
        contents = dict(self.sources)
        for name in names:
            contents[name] += b"\n# Controlled exact progress-cache fixture.\n"
        if unrelated is not None:
            contents[unrelated] += b"\nUNRELATED_BEHAVIOR = True\n"
        before = {name: hashlib.sha256(value).hexdigest() for name, value in self.sources.items()}
        after = {name: hashlib.sha256(value).hexdigest() for name, value in contents.items()}
        scope = amendments.ProgressCachingScope(
            previous_modules_sha256={name: before[name] for name in names},
            current_modules_sha256={name: after[name] for name in names},
        )
        archive = self.output / "progress-cache.zip"
        self.save_archive(archive, contents)
        qualification = self.output / "progress-cache-qualification.json"
        immutable_json(qualification, {
            "status": "pass", "current_manifest_sha256": amendments._manifest_digest(after),
            "progress_caching_scope": scope.model_dump(mode="json"), "progress_cache_tests_passed": True,
            "historical_admissions_verified": True,
        })
        approval = self.output / "progress-cache-approval.json"
        immutable_json(approval, amendments.ParallelFinalizationApproval(
            plan_fingerprint=fingerprint(self.plan), previous_manifest_sha256=amendments._manifest_digest(before),
            current_manifest_sha256=amendments._manifest_digest(after), qualification=str(qualification.relative_to(self.output)),
            qualification_sha256=file_sha256(qualification), approval_context="Exact read-only progress-cache fixture.",
            approved=True, progress_caching_scope=scope,
        ))
        return transport, after, archive, approval

    def test_progress_cache_scope_preserves_the_original_authorities(self):
        transport, hashes, archive, approval = self.caching_candidate()
        original = (self.output / "transport-amendments/0000.json").read_bytes()
        with self.installed(transport, hashes) as expected:
            amendments.record_parallel_finalization_runtime(
                self.plan, self.output, archive=archive, approval=approval, reason="Qualified immutable-history reuse.")
            self.assertEqual(effective_runtime(self.plan, self.output), expected)
        self.assertEqual((self.output / "transport-amendments/0000.json").read_bytes(), original)

    def assert_cache_scope_refuses_unrelated_code(self, name):
        transport, hashes, archive, approval = self.caching_candidate(unrelated=name)
        with self.installed(transport, hashes), self.assertRaisesRegex(ValueError, "non-progress code"):
            amendments.record_parallel_finalization_runtime(
                self.plan, self.output, archive=archive, approval=approval, reason="Must reject unrelated changes.")
        self.assertFalse((self.output / amendments.PARALLEL_RUNTIME).exists())

    def test_progress_cache_scope_cannot_change_other_admission_behavior(self):
        self.assert_cache_scope_refuses_unrelated_code("preproduction_admission.py")

    def test_progress_cache_scope_cannot_change_other_checkpoint_behavior(self):
        self.assert_cache_scope_refuses_unrelated_code("checkpoint_batches.py")

    def test_failed_qualification_does_not_authorize_deployment(self):
        transport, hashes, archive, approval = self.candidate(status="fail")
        with self.installed(transport, hashes), self.assertRaisesRegex(ValueError, "passing qualification"):
            amendments.record_parallel_finalization_runtime(
                self.plan, self.output, archive=archive, approval=approval, reason="Must reject.",
            )

    def test_approval_or_archive_mutation_invalidates_the_runtime(self):
        transport, hashes, archive, approval = self.candidate()
        with self.installed(transport, hashes):
            amendments.record_parallel_finalization_runtime(
                self.plan, self.output, archive=archive, approval=approval, reason="Exact tested change.",
            )
            original = approval.read_bytes()
            approval.write_bytes(original + b"\n")
            with self.assertRaisesRegex(ValueError, "archive or approval changed"):
                effective_runtime(self.plan, self.output)
            approval.write_bytes(original)
            archive.write_bytes(archive.read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "archive or approval changed"):
                effective_runtime(self.plan, self.output)

    def test_historical_copilot_runtime_requires_its_exact_approved_state(self):
        transport, hashes, archive, approval = self.candidate()
        before = dict(transport.current_runtime_sha256)
        with self.installed(transport, hashes) as current:
            amendments.record_parallel_finalization_runtime(
                self.plan, self.output, archive=archive, approval=approval, reason="Exact tested change.",
            )
            self.assertTrue(amendments.transport_runtime_matches(self.plan, self.output, before, current))
            changed = {**before, "evidence.py": "0" * 64}
            self.assertFalse(amendments.transport_runtime_matches(self.plan, self.output, changed, current))

    def correction(self, first_archive, first_hashes, *, references=()):
        with zipfile.ZipFile(first_archive) as source:
            contents = {name: source.read(name) for name in source.namelist()}
        for name in ("transport_amendments.py", "preproduction.py"):
            contents[name] += b"\n# controlled append-only correction fixture\n"
        hashes = {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()}
        archive = self.output / "parallel-correction.zip"
        self.save_archive(archive, contents)
        qualification = self.output / "correction-qualification.json"
        immutable_json(qualification, {
            "status": "pass", "current_manifest_sha256": amendments._manifest_digest(hashes),
            "archived_producer_references": [reference.model_dump(mode="json") for reference in references],
            "historical_admissions_verified": True,
        })
        approval = self.output / "correction-approval.json"
        immutable_json(approval, amendments.ParallelFinalizationApproval(
            plan_fingerprint=fingerprint(self.plan),
            previous_manifest_sha256=amendments._manifest_digest(first_hashes),
            current_manifest_sha256=amendments._manifest_digest(hashes),
            qualification=str(qualification.relative_to(self.output)),
            qualification_sha256=file_sha256(qualification), approval_context="Controlled historical-producer correction.",
            approved=True, archived_producer_references=references,
        ))
        return hashes, archive, approval

    def first(self):
        transport, hashes, archive, approval = self.candidate()
        with self.installed(transport, hashes):
            amendments.record_parallel_finalization_runtime(
                self.plan, self.output, archive=archive, approval=approval, reason="Initial exact test runtime.")
        return transport, hashes, archive

    def reference(self, name="preproduction.py"):
        artifact = self.output / "historical-package" / name
        artifact.parent.mkdir(exist_ok=True)
        artifact.write_bytes(self.sources[name] + b"\n# current producer differs\n")
        old_digest = hashlib.sha256(self.sources[name]).hexdigest()
        receipt = self.output / "admissions/preprod-v1-tenant-1.json"
        receipt.parent.mkdir(exist_ok=True)
        immutable_json(receipt, {
            "task": {"task_id": "preprod-v1-tenant-1"},
            "source_artifacts_sha256": {str(artifact): old_digest},
        })
        return amendments.ArchivedProducerReference(
            receipt=str(receipt.relative_to(self.output)), receipt_sha256=file_sha256(receipt),
            artifact=str(artifact), artifact_sha256=old_digest, archive_member=name,
        )

    def test_append_only_correction_preserves_previous_runtime_and_rejects_mixtures(self):
        transport, first_hashes, first_archive = self.first()
        first_path = self.output / amendments.PARALLEL_RUNTIME
        original = first_path.read_bytes()
        hashes, archive, approval = self.correction(first_archive, first_hashes)
        with self.installed(transport, hashes) as current:
            value = amendments.record_parallel_finalization_correction(
                self.plan, self.output, archive=archive, approval=approval, reason="Exact qualified correction.")
            self.assertEqual(value.previous_parallel_sha256, file_sha256(first_path))
            self.assertEqual(amendments.load_parallel_finalization_runtime(self.plan, self.output), value)
            self.assertEqual(effective_runtime(self.plan, self.output), current)
            first_scope = {name: first_hashes[name] for name in current}
            self.assertTrue(amendments.transport_runtime_matches(self.plan, self.output, first_scope, current))
            self.assertTrue(amendments.transport_runtime_matches(
                self.plan, self.output, transport.current_runtime_sha256, current))
            mixture = {**first_scope, "preproduction.py": hashes["preproduction.py"]}
            self.assertFalse(amendments.transport_runtime_matches(self.plan, self.output, mixture, current))
        self.assertEqual(first_path.read_bytes(), original)
        self.assertEqual([p.name for p in amendments._parallel_paths(self.output)], ["0000.json", "0001.json"])

    def test_archival_reference_binds_unchanged_receipt_and_exact_original_archive_member(self):
        transport, first_hashes, first_archive = self.first()
        reference = self.reference()
        receipt = self.output / reference.receipt
        original = receipt.read_bytes()
        hashes, archive, approval = self.correction(first_archive, first_hashes, references=(reference,))
        with self.installed(transport, hashes):
            amendments.record_parallel_finalization_correction(
                self.plan, self.output, archive=archive, approval=approval, reason="Exact archive preservation.")
            bindings, dependencies = amendments.archived_admission_producers(self.plan, self.output)
            carrier, expected, member = bindings[(receipt, Path(reference.artifact), reference.artifact_sha256)]
            self.assertEqual(file_sha256(carrier), expected)
            with zipfile.ZipFile(carrier) as source:
                self.assertEqual(hashlib.sha256(source.read(member)).hexdigest(), reference.artifact_sha256)
            self.assertNotEqual(file_sha256(Path(reference.artifact)), reference.artifact_sha256)
            self.assertEqual(dependencies[receipt], reference.receipt_sha256)
            receipt.write_bytes(original + b"\n")
            with self.assertRaisesRegex(ValueError, "unchanged admission receipt"):
                amendments.archived_admission_producers(self.plan, self.output)
        receipt.write_bytes(original)
        self.assertEqual(receipt.read_bytes(), original)

    def test_archival_authority_cannot_substitute_a_protected_data_or_scoring_reference(self):
        transport, first_hashes, first_archive = self.first()
        reference = self.reference("scoring.py")
        hashes, archive, approval = self.correction(first_archive, first_hashes, references=(reference,))
        with self.installed(transport, hashes), self.assertRaisesRegex(ValueError, "pre-parallel producer"):
            amendments.record_parallel_finalization_correction(
                self.plan, self.output, archive=archive, approval=approval, reason="Must reject protected member.")
        self.assertFalse((self.output / "parallel-finalization-runtime/0001.json").exists())

    def test_changed_predecessor_bytes_invalidate_correction_chain(self):
        transport, first_hashes, first_archive = self.first()
        hashes, archive, approval = self.correction(first_archive, first_hashes)
        with self.installed(transport, hashes):
            amendments.record_parallel_finalization_correction(
                self.plan, self.output, archive=archive, approval=approval, reason="Exact correction.")
            path = self.output / amendments.PARALLEL_RUNTIME
            path.write_bytes(path.read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "exact approved predecessor"):
                effective_runtime(self.plan, self.output)

    def provider_correction(self, first_archive, first_hashes, *, extra_change=None, qualified=True, before=None, references=()):
        with zipfile.ZipFile(first_archive) as source:
            contents = {name: source.read(name) for name in source.namelist()}
        for name in ("provider_defaults.py", "transport_amendments.py", *([extra_change] if extra_change else [])):
            contents[name] += b"\n# controlled provider-recovery fixture\n"
        hashes = {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()}
        archive = self.output / "provider-recovery.zip"
        self.save_archive(archive, contents)
        scope = amendments.ProviderRecoveryScope(
            previous_provider_sha256=before or first_hashes["provider_defaults.py"],
            current_provider_sha256=hashes["provider_defaults.py"],
        )
        qualification = self.output / "provider-qualification.json"
        immutable_json(qualification, {
            "status": "pass", "current_manifest_sha256": amendments._manifest_digest(hashes),
            "provider_recovery_scope": scope.model_dump(mode="json"),
            "provider_bound_recovery_tests_passed": qualified, "historical_admissions_verified": True,
            "archived_producer_references": [reference.model_dump(mode="json") for reference in references],
        })
        approval = self.output / "provider-approval.json"
        immutable_json(approval, amendments.ParallelFinalizationApproval(
            plan_fingerprint=fingerprint(self.plan),
            previous_manifest_sha256=amendments._manifest_digest(first_hashes),
            current_manifest_sha256=amendments._manifest_digest(hashes),
            qualification=str(qualification.relative_to(self.output)),
            qualification_sha256=file_sha256(qualification), approved=True,
            approval_context="Exact provider-bound HTTP500 recovery; all other kernels preserved.",
            provider_recovery_scope=scope, archived_producer_references=references,
        ))
        return hashes, archive, approval

    def test_provider_recovery_scope_preserves_exact_historical_runtime_and_authority(self):
        transport, first_hashes, first_archive = self.first()
        original_authority = (self.output / provider_tests.AUTHORITY).read_bytes()
        original_runtime = (self.output / amendments.PARALLEL_RUNTIME).read_bytes()
        reference = self.reference("provider_defaults.py")
        original_manifest = {name: hashlib.sha256(data).hexdigest() for name, data in self.sources.items()}
        with self.assertRaisesRegex(ValueError, "pre-parallel producer"):
            amendments._validate_archived_references(self.output, (reference,), original_manifest)
        hashes, archive, approval = self.provider_correction(first_archive, first_hashes, references=(reference,))
        with self.installed(transport, hashes) as current:
            amendments.record_parallel_finalization_correction(
                self.plan, self.output, archive=archive, approval=approval, reason="Qualified exact provider correction.")
            self.assertEqual(effective_runtime(self.plan, self.output), current)
            self.assertTrue(amendments.transport_runtime_matches(
                self.plan, self.output, {name: first_hashes[name] for name in current}, current))
            bindings, _ = amendments.archived_admission_producers(self.plan, self.output)
            carrier, expected, member = bindings[(self.output / reference.receipt, Path(reference.artifact), reference.artifact_sha256)]
            self.assertEqual(file_sha256(carrier), expected)
            with zipfile.ZipFile(carrier) as source:
                self.assertEqual(source.read(member), self.sources["provider_defaults.py"])
        self.assertEqual((self.output / amendments.PARALLEL_RUNTIME).read_bytes(), original_runtime)
        self.assertEqual((self.output / provider_tests.AUTHORITY).read_bytes(), original_authority)

    def test_provider_scope_refuses_other_module_changes(self):
        transport, first_hashes, first_archive = self.first()
        hashes, archive, approval = self.provider_correction(first_archive, first_hashes, extra_change="preproduction.py")
        with self.installed(transport, hashes), self.assertRaisesRegex(ValueError, "protected kernels"):
            amendments.record_parallel_finalization_correction(
                self.plan, self.output, archive=archive, approval=approval, reason="Must reject unrelated orchestration.")
        self.assertFalse((self.output / "parallel-finalization-runtime/0001.json").exists())

    def test_provider_scope_requires_exact_provider_pair_and_verified_tests(self):
        transport, first_hashes, first_archive = self.first()
        hashes, archive, approval = self.provider_correction(first_archive, first_hashes, before="0" * 64)
        with self.installed(transport, hashes), self.assertRaisesRegex(ValueError, "exact before/after provider"):
            amendments.record_parallel_finalization_correction(
                self.plan, self.output, archive=archive, approval=approval, reason="Must reject wrong provider predecessor.")
        value = json.loads(approval.read_bytes())
        value["provider_recovery_scope"]["previous_provider_sha256"] = first_hashes["provider_defaults.py"]
        qualification = self.output / value["qualification"]
        report = json.loads(qualification.read_bytes())
        report["provider_recovery_scope"] = value["provider_recovery_scope"]
        report["provider_bound_recovery_tests_passed"] = False
        qualification.write_text(json.dumps(report))
        value["qualification_sha256"] = file_sha256(qualification)
        approval.write_text(json.dumps(value))
        with self.installed(transport, hashes), self.assertRaisesRegex(ValueError, "provider-bound and historical"):
            amendments.record_parallel_finalization_correction(
                self.plan, self.output, archive=archive, approval=approval, reason="Must reject missing integration tests.")


class QuerySerializationRuntimeTests(unittest.TestCase):
    installed = ParallelRuntimeTests.installed
    save_archive = staticmethod(ParallelRuntimeTests.save_archive)
    caching_candidate = ParallelRuntimeTests.caching_candidate
    correction = ParallelRuntimeTests.correction

    def setUp(self):
        provider_tests.TransportAmendmentTests.setUp(self)
        # Keep this historical M3-to-M5 fixture independent of the later tokenizer guard.
        self.fixed_query = Path(query.__file__).read_text().replace(
            "except (sqlglot.errors.ParseError, sqlglot.errors.TokenError) as error:",
            "except sqlglot.errors.ParseError as error:",
        ).encode()
        original = self.fixed_query.decode().replace(inspect.getsource(query._MySQLQueryParser) + "\n\n", "")
        original = original.replace("from sqlglot.dialects.mysql import MySQL\n", "")
        original = original.replace("from sqlglot.tokens import TokenType\n", "")
        original = original.replace(
            '        if engine == "mysql":\n'
            '            dialect = MySQL()\n'
            '            statements = _MySQLQueryParser(dialect=dialect).parse(dialect.tokenize(query), query)\n'
            '        else:\n'
            '            statements = sqlglot.parse(query, read=engine)\n',
            '        statements = sqlglot.parse(query, read=engine)\n',
        ).encode()
        self.scope = amendments.QuerySerializationScope()
        self.assertEqual(hashlib.sha256(original).hexdigest(), self.scope.previous_query_sha256)
        self.assertEqual(hashlib.sha256(self.fixed_query).hexdigest(), self.scope.current_query_sha256)
        self.sources["query.py"] = self.old["query.py"] = original
        admission = Path(preproduction_admission.__file__).read_text().replace(
            "PARALLEL_RUNTIME, parse_finalization_approval,", "PARALLEL_RUNTIME, ParallelFinalizationApproval,"
        ).replace("approved = parse_finalization_approval(", "approved = ParallelFinalizationApproval.model_validate_json(")
        self.sources["preproduction_admission.py"] = self.old["preproduction_admission.py"] = admission.encode()
        self.old_hashes = {name: hashlib.sha256(data).hexdigest() for name, data in self.old.items()}
        self.plan = self.plan.model_copy(update={
            "implementation_sha256": {name: self.old_hashes[name] for name in self.plan.implementation_sha256},
        })
        (self.output / "plan.json").write_text(self.plan.model_dump_json())
        (self.output / provider_tests.AUTHORITY).write_text(
            json.dumps(provider_tests.authority_value(self.plan, self.root / "unused.env")))
        self.save_archive(self.archive, self.old)
        self.save_archive(self.current_archive, self.sources)
        self.enterContext(patch.object(amendments, "BEFORE_MANIFEST_SHA256", amendments._manifest_digest(self.old_hashes)))
        self.enterContext(patch.object(amendments, "UPDATED_MODULES", {
            name: hashlib.sha256(self.sources[name]).hexdigest() for name in amendments.UPDATED_MODULES
        }))

    def record(self):
        hashes = {name: hashlib.sha256(data).hexdigest() for name, data in self.sources.items()}
        with self.installed(SimpleNamespace(current_runtime_sha256=runtime_hashes()), hashes):
            return provider_tests.TransportAmendmentTests.record(self)

    def cache(self):
        transport, hashes, archive, approval = self.caching_candidate()
        with self.installed(transport, hashes):
            amendments.record_parallel_finalization_runtime(
                self.plan, self.output, archive=archive, approval=approval, reason="Separate original cache scope.")
        return transport, hashes, archive

    def serializer(self, before, before_hashes, *, extra_change=None):
        with zipfile.ZipFile(before) as archive:
            contents = {name: archive.read(name) for name in archive.namelist()}
        contents["query.py"] = self.fixed_query
        contents["preproduction_admission.py"] = Path(preproduction_admission.__file__).read_bytes()
        if extra_change:
            contents[extra_change] += b"\nUNAPPROVED_CHANGE = True\n"
        hashes = {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()}
        archive = self.output / "serializer.zip"
        self.save_archive(archive, contents)
        receipt = self.output / "admissions/preprod-v1-tenant-313.json"
        receipt.parent.mkdir()
        artifact = "/home/amudgerikar/repos/secrl/secgym/qagen/agentic/query.py"
        immutable_json(receipt, {
            "task": {"task_id": "preprod-v1-tenant-313"},
            "source_artifacts_sha256": {artifact: self.scope.previous_query_sha256},
        })
        reference = amendments.ArchivedProducerReference(
            receipt=str(receipt.relative_to(self.output)), receipt_sha256=file_sha256(receipt),
            artifact=artifact, artifact_sha256=self.scope.previous_query_sha256, archive_member="query.py",
        )
        log = self.output / "regression.log"
        log.write_text("Synthetic unit-test evidence fixture\nRan 166 tests in 1.0s\n\nOK\n")
        mysql = self.output / "mysql.json"
        immutable_json(mysql, {
            "status": "passed", "cases": 29, "runtime_before_sha256": self.scope.previous_query_sha256,
            "runtime_after_sha256": self.scope.current_query_sha256, "source_table_queries": 0,
            "original_student_sql_replayed": False, "new_model_or_student_calls": 0,
        })
        qualification = self.output / "serializer-qualification.json"
        immutable_json(qualification, {
            "status": "pass", "current_manifest_sha256": amendments._manifest_digest(hashes),
            "query_serialization_scope": self.scope.model_dump(mode="json"),
            "query_guard_tests_passed": True, "historical_admissions_verified": True,
            "regression_log": log.name, "regression_log_sha256": file_sha256(log),
            "mysql_qualification": mysql.name, "mysql_qualification_sha256": file_sha256(mysql),
            "archived_producer_references": [reference.model_dump(mode="json")],
        })
        approval = self.output / "serializer-approval.json"
        immutable_json(approval, amendments.QuerySerializationApproval(
            plan_fingerprint=fingerprint(self.plan), previous_manifest_sha256=amendments._manifest_digest(before_hashes),
            current_manifest_sha256=amendments._manifest_digest(hashes),
            qualification=qualification.name, qualification_sha256=file_sha256(qualification),
            approval_context="Synthetic exact serializer authority fixture, not deployment.", approved=True,
            query_serialization_scope=self.scope, archived_producer_references=(reference,),
        ))
        return hashes, archive, approval

    def publish_fixture(self, transport, hashes, archive, approval):
        with self.installed(transport, hashes):
            return amendments.record_query_serialization_correction(
                self.plan, self.output, archive=archive, approval=approval,
                reason="Synthetic serializer transition after separate cache authority.")

    def test_ordered_cache_serializer_and_later_orchestration_correction(self):
        transport, before, before_archive = self.cache()
        cache_bytes = (self.output / amendments.PARALLEL_RUNTIME).read_bytes()
        hashes, archive, approval = self.serializer(before_archive, before)
        value = self.publish_fixture(transport, hashes, archive, approval)
        self.assertTrue(value.source_query_generation_scoring_kernels_changed)
        with self.installed(transport, hashes):
            self.assertEqual(effective_runtime(self.plan, self.output),
                             {name: hashes[name] for name in transport.current_runtime_sha256})
            self.assertFalse(amendments.transport_runtime_matches(
                self.plan, self.output, {name: before[name] for name in transport.current_runtime_sha256},
                {name: hashes[name] for name in transport.current_runtime_sha256}))
            bindings, _ = amendments.archived_admission_producers(self.plan, self.output)
            key, = bindings
            self.assertEqual(key[0].name, "preprod-v1-tenant-313.json")
            carrier, _, member = bindings[key]
            with zipfile.ZipFile(carrier) as saved:
                self.assertEqual(hashlib.sha256(saved.read(member)).hexdigest(), self.scope.previous_query_sha256)
        later_hashes, later_archive, later_approval = self.correction(archive, hashes)
        with self.installed(transport, later_hashes):
            later = amendments.record_parallel_finalization_correction(
                self.plan, self.output, archive=later_archive, approval=later_approval, reason="Later orchestration only.")
            self.assertFalse(later.source_query_generation_scoring_kernels_changed)
            current = effective_runtime(self.plan, self.output)
            self.assertTrue(amendments.transport_runtime_matches(
                self.plan, self.output, {name: hashes[name] for name in current}, current))
        self.assertEqual((self.output / amendments.PARALLEL_RUNTIME).read_bytes(), cache_bytes)
        self.assertEqual([path.name for path in amendments._parallel_paths(self.output)],
                         ["0000.json", "0001.json", "0002.json"])

    def test_serializer_cannot_be_smuggled_through_legacy_runtime(self):
        transport, before, before_archive = self.cache()
        hashes, archive, approval = self.serializer(before_archive, before)
        with self.installed(transport, hashes), self.assertRaisesRegex(ValueError, "separately versioned"):
            amendments.record_parallel_finalization_correction(
                self.plan, self.output, archive=archive, approval=approval, reason="Must reject.")
        with self.assertRaises(ValueError):
            amendments.QuerySerializationScope(current_query_sha256="0" * 64)
        with self.assertRaises(ValueError):
            amendments.QuerySerializationScope(retained_native_runtime_compatibility_authorized=True)
        value = json.loads(approval.read_bytes())
        with self.assertRaises(ValueError):
            amendments.parse_finalization_approval(json.dumps({
                **value, "source_query_generation_scoring_kernels_changed": False,
            }).encode())

    def test_arbitrary_query_source_and_admission_gate_changes_are_rejected(self):
        transport, before, before_archive = self.cache()
        hashes, archive, approval = self.serializer(before_archive, before, extra_change="query.py")
        with self.assertRaisesRegex(ValueError, "exact before/after"):
            self.publish_fixture(transport, hashes, archive, approval)
        with zipfile.ZipFile(archive) as saved:
            contents = {name: saved.read(name) for name in saved.namelist()}
        contents["query.py"] = self.fixed_query
        contents["preproduction_admission.py"] += b"\nUNAPPROVED_ADMISSION_CHANGE = True\n"
        self.save_archive(archive, contents)
        with self.assertRaisesRegex(ValueError, "beyond versioned approval parsing"):
            amendments._validate_query_serialization_sources(before_archive, archive)

    def test_other_protected_source_changes_are_rejected(self):
        transport, before, before_archive = self.cache()
        hashes, archive, approval = self.serializer(before_archive, before, extra_change="scoring.py")
        with self.assertRaisesRegex(ValueError, "protected kernels"):
            self.publish_fixture(transport, hashes, archive, approval)

    def test_carrier_scope_is_only_exact_tenant313_live_query_reference(self):
        transport, before, before_archive = self.cache()
        hashes, archive, approval_path = self.serializer(before_archive, before)
        approval = amendments.parse_finalization_approval(approval_path.read_bytes())
        reference, = approval.archived_producer_references
        for update in (
            {"receipt": "admissions/preprod-v1-tenant-314.json"},
            {"artifact": str(self.output / "query.py")},
            {"artifact_sha256": "0" * 64},
            {"archive_member": "scoring.py"},
        ):
            with self.subTest(update=update), self.assertRaises(ValueError):
                amendments._validate_archived_references(
                    self.output, (reference.model_copy(update=update),), before, query_serialization_scope=self.scope)
        with self.assertRaisesRegex(ValueError, "pre-parallel producer"):
            amendments._validate_archived_references(self.output, (reference,), before)
        with self.assertRaises(ValueError):
            amendments._validate_archived_references(self.output, (), before, query_serialization_scope=self.scope)
        with self.assertRaises(ValueError):
            amendments._validate_archived_references(self.output, (reference, reference), before,
                                                     query_serialization_scope=self.scope)

    def test_failed_or_unbound_qualification_cannot_authorize_serializer(self):
        _, before, before_archive = self.cache()
        _, _, approval_path = self.serializer(before_archive, before)
        approval = amendments.parse_finalization_approval(approval_path.read_bytes())
        qualification = json.loads((self.output / approval.qualification).read_bytes())
        for update in ({"query_guard_tests_passed": False}, {"historical_admissions_verified": False},
                       {"query_serialization_scope": {}}, {"mysql_qualification_sha256": "0" * 64}):
            with self.subTest(update=update), self.assertRaises(ValueError):
                amendments._validate_query_qualification(self.output, {**qualification, **update}, self.scope)
        log = self.output / qualification["regression_log"]
        log.write_text("Ran 165 tests in 1.0s\n\nOK\n")
        with self.assertRaisesRegex(ValueError, "166 passing"):
            amendments._validate_query_qualification(
                self.output, {**qualification, "regression_log_sha256": file_sha256(log)}, self.scope)
        log.write_text("Ran 166 tests in 1.0s\n\nOK\n")
        mysql = self.output / qualification["mysql_qualification"]
        original = json.loads(mysql.read_bytes())
        for update in ({"cases": 28}, {"status": "failed"}, {"runtime_after_sha256": "0" * 64},
                       {"original_student_sql_replayed": True}):
            mysql.write_text(json.dumps({**original, **update}))
            with self.subTest(update=update), self.assertRaisesRegex(ValueError, "synthetic MySQL"):
                amendments._validate_query_qualification(self.output, {
                    **qualification, "regression_log_sha256": file_sha256(log),
                    "mysql_qualification_sha256": file_sha256(mysql),
                }, self.scope)


if __name__ == "__main__":
    unittest.main()
