# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""One audited provider cutover, not a general runtime-compatibility permission."""

import ast
from contextlib import ExitStack, contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Literal
import zipfile

from .contracts import Contract, Digest, Text, fingerprint
from .ledger import file_sha256
from .provider_defaults import AUTHORITY, load_provider_default


VERSION = "qa-copilot-forward-transport-amendment-v1"
# Content manifests, not ZIP metadata: only the reviewed before/after source pair is eligible.
BEFORE_MANIFEST_SHA256 = "09c21f1a4552cc8db14c19b8057934bf8c08e36795eafc62ec710968cd64858e"
UPDATED_MODULES = {
    "__main__.py": "e1b1c99111e2d178c300fe191a3012cf3aab043e701ad9defa8a803173ba428b",
    "azure_generation.py": "6f36622e7236e325f89b0c273c7eae270a6e9a5cfafd2c2cf469d1874f8192fa",
    "checkpoint_batches.py": "2b816928dc71f86a4de99cce4ebe62b80087c1d85f95dbe9bca3a63df52e4820",
    "gateway.py": "2c4353e95995a9e867a8dfd86ecda7c894bdc65c24a7c65f23912fd0d0eaedd1",
    "model_panel.py": "b6a54e997f72812bac2acd03f7283aa78cbc98dd7105515cadf14d146e6b8a04",
    "preproduction.py": "ab82967d9a49e7a82f42abd772229a8e7031500c59f18c6bba7f952f1feb0450",
    "preproduction_admission.py": "49dae96c4a8d2b355d7495781f0c06d216a9c9685762392682898ceb63d2e2ef",
    "preproduction_pipeline.py": "5cf38409696a070343194da7c49b962d5fa27a75bcb711b8333a97d15f68d4c2",
    "preproduction_revisions.py": "8b50dbb47eb1d38e9d3afbb704056cfed31d6f9ded416bef306e107ac1bc1602",
    "provider_defaults.py": "14f509e864e221bf738bfd98df14160949ab93f7e720a93898d8419cc9357285",
    "quality.py": "79d7249692c0f465490de03f2643221ef35b14c3d1172392442e958e3ab13b6f",
    "review_execution.py": "59588e84648dd19b3b022d8e55beacf0b22bee38a59813d5ae27b81da5e06354",
    "review_transport.py": "62af769730afd7446bc792e3682e939e32d32ca7d23a18c1e14b0daa559e2084",
    "shared_validation.py": "e4adb0faa335c7d11f93230b2e53fb98101d0515dc20fefde182fa4b4cafc85d",
}
ADDED_MODULES = frozenset({"gateway.py", "provider_defaults.py", "transport_amendments.py"})
TRANSPORT_MODULE_SHA256 = "803e2e9d7c60ea2f962f4baf26b1189446444dfd0d116e87a152a3cbb046dd5a"
PARALLEL_RUNTIME = "parallel-finalization-runtime/0000.json"
PARALLEL_MODULES = frozenset({
    "__main__.py", "preproduction.py", "preproduction_admission.py", "preproduction_pipeline.py",
    "preproduction_revisions.py", "shared_validation.py", "transport_amendments.py",
})
PROVIDER_RECOVERY_MODULES = frozenset({"provider_defaults.py", "transport_amendments.py"})
PROGRESS_CACHING_MODULES = frozenset({"preproduction_admission.py", "checkpoint_batches.py", "transport_amendments.py"})


class TransportAmendment(Contract):
    policy_version: Literal["qa-copilot-forward-transport-amendment-v1"] = VERSION
    plan_fingerprint: Digest
    authority_sha256: Digest
    previous_runtime_sha256: dict[str, Digest]
    current_runtime_sha256: dict[str, Digest]
    archive: Text
    archive_sha256: Digest
    current_archive: Text
    current_archive_sha256: Digest
    reason: Text
    source_query_generation_scoring_kernels_changed: Literal[False] = False
    retained_native_runtime_compatibility_authorized: Literal[False] = False
    old_roles_migrated_or_resampled: Literal[False] = False


class ArchivedProducerReference(Contract):
    receipt: Text
    receipt_sha256: Digest
    artifact: Text
    artifact_sha256: Digest
    archive_member: Text


class ProviderRecoveryScope(Contract):
    policy_version: Literal["provider-bound-http500-recovery-scope-v1"] = "provider-bound-http500-recovery-scope-v1"
    previous_provider_sha256: Digest
    current_provider_sha256: Digest
    explicit_nonstudent_recovery_only: Literal[True] = True
    original_provider_and_model_profile_preserved: Literal[True] = True
    student_or_terminal_role_recovery_authorized: Literal[False] = False
    unapproved_pending_request_retries_authorized: Literal[False] = False
    already_stranded_recoveries_retried: Literal[False] = False


class ProgressCachingScope(Contract):
    policy_version: Literal["verified-progress-caching-scope-v1"] = "verified-progress-caching-scope-v1"
    previous_modules_sha256: dict[str, Digest]
    current_modules_sha256: dict[str, Digest]
    process_local_verified_hashes_only: Literal[True] = True
    current_counts_recomputed: Literal[True] = True
    admission_or_objective_decisions_cached: Literal[False] = False
    generation_query_scoring_kernels_changed: Literal[False] = False


class ParallelFinalizationApproval(Contract):
    policy_version: Literal["parallel-finalization-approval-v1"] = "parallel-finalization-approval-v1"
    plan_fingerprint: Digest
    previous_manifest_sha256: Digest
    current_manifest_sha256: Digest
    qualification: Text
    qualification_sha256: Digest
    approval_context: Text
    approved: Literal[True]
    model_workers: Literal[8] = 8
    native_sql_slots: Literal[4] = 4
    protected_kernels_unchanged: Literal[True] = True
    completed_students_resampled: Literal[False] = False
    release_approved: Literal[False] = False
    archived_producer_references: tuple[ArchivedProducerReference, ...] = ()
    provider_recovery_scope: ProviderRecoveryScope | None = None
    progress_caching_scope: ProgressCachingScope | None = None


class ParallelFinalizationRuntime(Contract):
    policy_version: Literal["parallel-finalization-runtime-v1"] = "parallel-finalization-runtime-v1"
    plan_fingerprint: Digest
    transport_amendment_sha256: Digest
    previous_runtime_sha256: dict[str, Digest]
    current_runtime_sha256: dict[str, Digest]
    archive: Text
    archive_sha256: Digest
    approval: Text
    approval_sha256: Digest
    reason: Text
    source_query_generation_scoring_kernels_changed: Literal[False] = False
    completed_students_resampled: Literal[False] = False
    release_approved: Literal[False] = False
    previous_parallel_sha256: Digest | None = None


class QuerySerializationScope(Contract):
    policy_version: Literal["mysql-explicit-join-serialization-scope-v1"] = "mysql-explicit-join-serialization-scope-v1"
    previous_query_sha256: Literal["1d82b8bb635b667e3a47f738362abce24c9114cc6e45c5e1da93b0c4138ff1aa"] = (
        "1d82b8bb635b667e3a47f738362abce24c9114cc6e45c5e1da93b0c4138ff1aa")
    current_query_sha256: Literal["d704276529891194ec7103bc0fd7427afb84e1b9f3505f7006c73f1d880c211d"] = (
        "d704276529891194ec7103bc0fd7427afb84e1b9f3505f7006c73f1d880c211d")
    query_serialization_changed: Literal[True] = True
    sql_guards_limits_and_duckdb_unchanged: Literal[True] = True
    source_capture_generation_scoring_kernels_changed: Literal[False] = False
    fresh_tasks_only: Literal[True] = True
    retained_native_runtime_compatibility_authorized: Literal[False] = False


class HistoricalReadbackInventory(Contract):
    policy_version: Literal["historical-controller-readback-inventory-v1"] = "historical-controller-readback-inventory-v1"
    plan_fingerprint: Digest
    ancestor_manifest_sha256: Digest
    certificate_sha256: dict[Text, Digest]
    worker_policy_sha256: dict[Text, Digest]
    other_artifacts_sha256: dict[Text, Digest]


class HistoricalReadbackScope(Contract):
    policy_version: Literal["historical-controller-readback-scope-v1"] = "historical-controller-readback-scope-v1"
    inventory: Text
    inventory_sha256: Digest
    ancestor_runtime: Text
    ancestor_runtime_sha256: Digest
    controller_source: Text
    controller_source_sha256: Digest
    helper_source: Text
    helper_source_sha256: Digest
    read_only_sealed_history: Literal[True] = True
    new_publication_or_execution_compatibility_authorized: Literal[False] = False


class QuerySerializationApproval(Contract):
    policy_version: Literal["mysql-explicit-join-serialization-approval-v1"] = "mysql-explicit-join-serialization-approval-v1"
    plan_fingerprint: Digest
    previous_manifest_sha256: Digest
    current_manifest_sha256: Digest
    qualification: Text
    qualification_sha256: Digest
    approval_context: Text
    approved: Literal[True]
    query_serialization_scope: QuerySerializationScope
    source_query_generation_scoring_kernels_changed: Literal[True] = True
    model_workers: Literal[8] = 8
    native_sql_slots: Literal[4] = 4
    completed_students_resampled: Literal[False] = False
    release_approved: Literal[False] = False
    archived_producer_references: tuple[ArchivedProducerReference, ...]
    historical_readback_scope: HistoricalReadbackScope | None = None


class QuerySerializationRuntime(Contract):
    policy_version: Literal["mysql-explicit-join-serialization-runtime-v1"] = "mysql-explicit-join-serialization-runtime-v1"
    plan_fingerprint: Digest
    transport_amendment_sha256: Digest
    previous_runtime_sha256: dict[str, Digest]
    current_runtime_sha256: dict[str, Digest]
    archive: Text
    archive_sha256: Digest
    approval: Text
    approval_sha256: Digest
    reason: Text
    source_query_generation_scoring_kernels_changed: Literal[True] = True
    fresh_tasks_only: Literal[True] = True
    retained_native_runtime_compatibility_authorized: Literal[False] = False
    completed_students_resampled: Literal[False] = False
    release_approved: Literal[False] = False
    previous_parallel_sha256: Digest


class QueryTokenizationScope(Contract):
    policy_version: Literal["fresh-query-tokenization-scope-v1"] = "fresh-query-tokenization-scope-v1"
    previous_query_sha256: Literal["d704276529891194ec7103bc0fd7427afb84e1b9f3505f7006c73f1d880c211d"] = (
        "d704276529891194ec7103bc0fd7427afb84e1b9f3505f7006c73f1d880c211d")
    current_query_sha256: Literal["68e3ac217089fc105397cde5bcaf5101ef723d888124b2b6851a849157fa7188"] = (
        "68e3ac217089fc105397cde5bcaf5101ef723d888124b2b6851a849157fa7188")
    tokenization_refusal_changed: Literal[True] = True
    successful_query_serialization_changed: Literal[False] = False
    source_capture_generation_scoring_changed: Literal[False] = False
    fresh_tasks_only: Literal[True] = True
    old_source_worker_native_execution_compatibility: Literal[False] = False
    journal_recovery_authorized: Literal[False] = False


class GuardHistoryGroup(Contract):
    ancestor_runtime: Text
    ancestor_runtime_sha256: Digest
    inventory: Text
    inventory_sha256: Digest
    carrier_repository: Text
    archived_python_execution_authorized: Literal[False] = False


class GuardHistoryScope(Contract):
    policy_version: Literal["fresh-guard-read-only-history-v1"] = "fresh-guard-read-only-history-v1"
    snapshot_status: Literal["provisional", "final"]
    groups: tuple[GuardHistoryGroup, ...]
    receipt_inventory: Text
    receipt_inventory_sha256: Digest
    controller_source: Text
    controller_source_sha256: Digest
    helper_source: Text
    helper_source_sha256: Digest
    historical_execution_authorized: Literal[False] = False


class GuardDrainInventory(Contract):
    policy_version: Literal["fresh-guard-closed-m5-boundary-v1"] = "fresh-guard-closed-m5-boundary-v1"
    plan_fingerprint: Digest
    closed_owner_pids: tuple[int, ...]
    owner_evidence_sha256: dict[Text, Digest]
    completed_batch_reports_sha256: dict[Text, Digest]
    required_locks: tuple[Text, ...]
    original_native_wave_drained: Literal[True]
    source_audit_drained: Literal[True]
    all_m5_repair_owners_drained: Literal[True]


class QueryTokenizationApproval(Contract):
    policy_version: Literal["fresh-query-tokenization-approval-v1"] = "fresh-query-tokenization-approval-v1"
    plan_fingerprint: Digest
    previous_manifest_sha256: Digest
    current_manifest_sha256: Digest
    qualification: Text
    qualification_sha256: Digest
    approval_context: Text
    approved: Literal[True]
    query_tokenization_scope: QueryTokenizationScope
    historical_readback_scope: GuardHistoryScope
    drain_inventory: Text
    drain_inventory_sha256: Digest
    archived_producer_references: tuple[ArchivedProducerReference, ...] = ()
    model_workers: Literal[8] = 8
    native_sql_slots: Literal[4] = 4
    completed_students_resampled: Literal[False] = False
    release_approved: Literal[False] = False


class QueryTokenizationRuntime(Contract):
    policy_version: Literal["fresh-query-tokenization-runtime-v1"] = "fresh-query-tokenization-runtime-v1"
    plan_fingerprint: Digest
    transport_amendment_sha256: Digest
    previous_runtime_sha256: dict[str, Digest]
    current_runtime_sha256: dict[str, Digest]
    archive: Text
    archive_sha256: Digest
    approval: Text
    approval_sha256: Digest
    reason: Text
    previous_parallel_sha256: Digest
    tokenization_refusal_changed: Literal[True] = True
    successful_query_serialization_changed: Literal[False] = False
    source_capture_generation_scoring_changed: Literal[False] = False
    fresh_tasks_only: Literal[True] = True
    old_source_worker_native_execution_compatibility: Literal[False] = False
    journal_recovery_authorized: Literal[False] = False
    completed_students_resampled: Literal[False] = False
    release_approved: Literal[False] = False


def parse_finalization_runtime(data: bytes) -> ParallelFinalizationRuntime | QuerySerializationRuntime | QueryTokenizationRuntime:
    value = json.loads(data)
    if value.get("policy_version") == "fresh-query-tokenization-runtime-v1":
        return QueryTokenizationRuntime.model_validate_json(data)
    model = QuerySerializationRuntime if value.get("policy_version") == (
        "mysql-explicit-join-serialization-runtime-v1") else ParallelFinalizationRuntime
    return model.model_validate_json(data)


def parse_finalization_approval(data: bytes) -> ParallelFinalizationApproval | QuerySerializationApproval | QueryTokenizationApproval:
    value = json.loads(data)
    if value.get("policy_version") == "fresh-query-tokenization-approval-v1":
        return QueryTokenizationApproval.model_validate_json(data)
    model = QuerySerializationApproval if value.get("policy_version") == (
        "mysql-explicit-join-serialization-approval-v1") else ParallelFinalizationApproval
    return model.model_validate_json(data)


def _archive_manifest(path: Path) -> dict[str, str]:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(set(names)) != len(names) or any(Path(name).name != name or not name.endswith(".py") for name in names):
            raise ValueError("transport archives require unique flat Python source entries")
        return {name: hashlib.sha256(archive.read(name)).hexdigest() for name in names}


def _manifest_digest(values: dict[str, str]) -> str:
    return hashlib.sha256(json.dumps(values, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate_archive_pair(previous: Path, current: Path, *, verify_installed: bool = True) -> tuple[dict[str, str], dict[str, str]]:
    old, new = _archive_manifest(previous), _archive_manifest(current)
    if _manifest_digest(old) != BEFORE_MANIFEST_SHA256:
        raise ValueError("transport amendment requires the exact audited pre-cutover source archive")
    if set(new) != set(old) | ADDED_MODULES:
        raise ValueError("transport amendment cannot omit protected kernels or add unrelated modules")
    expected = {**old, **UPDATED_MODULES, "transport_amendments.py": TRANSPORT_MODULE_SHA256}
    if new != expected:
        raise ValueError("transport amendment changed protected kernels or differs from the exact versioned transport patch")
    if verify_installed and any(file_sha256(Path(__file__).with_name(name)) != digest for name, digest in new.items()):
        raise ValueError("transport archive differs from the installed audited runtime")
    return old, new


def _parallel_paths(run: Path) -> tuple[Path, ...]:
    directory = (run / PARALLEL_RUNTIME).parent
    paths = tuple(sorted(directory.glob("*.json")))
    if [path.name for path in paths] != [f"{index:04d}.json" for index in range(len(paths))]:
        raise ValueError("parallel-finalization runtime corrections must be contiguous and append-only")
    return paths


def _validate_archived_references(run: Path, references: tuple[ArchivedProducerReference, ...],
                                  transport_manifest: dict[str, str], *,
                                  provider_recovery_scope: ProviderRecoveryScope | None = None,
                                  query_serialization_scope: QuerySerializationScope | None = None) -> None:
    from .preproduction_revisions import _within

    identities = set()
    allowed = PARALLEL_MODULES | ({"provider_defaults.py"} if provider_recovery_scope is not None else set())
    if query_serialization_scope is not None:
        if len(references) != 1 or (
            references[0].receipt != "admissions/preprod-v1-tenant-313.json"
            or references[0].artifact != "/home/amudgerikar/repos/secrl/secgym/qagen/agentic/query.py"
            or references[0].artifact_sha256 != query_serialization_scope.previous_query_sha256
        ):
            raise ValueError("serializer archival authority requires only tenant-313's exact original live query reference")
        allowed = {"query.py"}
    for reference in references:
        receipt = _within(run, reference.receipt)
        artifact = Path(reference.artifact)
        if receipt.parent != run.resolve() / "admissions" or file_sha256(receipt) != reference.receipt_sha256:
            raise ValueError("archived producer reference must bind an unchanged admission receipt")
        if not artifact.is_absolute() or artifact != artifact.resolve() or (
            reference.archive_member != artifact.name or reference.archive_member not in allowed
            or transport_manifest.get(reference.archive_member) != reference.artifact_sha256
        ):
            raise ValueError("only exact audited pre-parallel producer members may be archived")
        recorded = json.loads(receipt.read_bytes())
        if receipt.name != recorded["task"]["task_id"] + ".json" or (
            recorded["source_artifacts_sha256"].get(reference.artifact) != reference.artifact_sha256
        ):
            raise ValueError("archival authority cannot invent or change a historical artifact reference")
        identity = (str(receipt), reference.artifact)
        if identity in identities:
            raise ValueError("archived producer references must be unique per admission and artifact")
        identities.add(identity)


def _parallel_runtime(plan, run: Path, transport: TransportAmendment, baseline: dict[str, str], *,
                      pending: ParallelFinalizationRuntime | QuerySerializationRuntime | QueryTokenizationRuntime | None = None) -> dict[str, str]:
    from .preproduction_revisions import _within

    paths = _parallel_paths(run)
    if not paths and pending is None:
        return baseline
    amendments = [(path, parse_finalization_runtime(path.read_bytes())) for path in paths]
    if pending is not None:
        amendments.append((None, pending))
    prior_hash = None
    previous_scope = transport.current_runtime_sha256
    original_manifest = baseline
    previous_archive = _within(run, transport.current_archive)
    for path, amendment in amendments:
        baseline = _parallel_step(
            plan, run, transport, baseline, original_manifest, previous_scope, prior_hash, amendment, previous_archive)
        previous_scope = amendment.current_runtime_sha256
        prior_hash = file_sha256(path) if path is not None else None
        previous_archive = _within(run, amendment.archive)
    return baseline


def _validate_progress_caching_sources(previous: Path, current: Path, scope: ProgressCachingScope) -> None:
    allowed = {
        "preproduction_admission.py": {"admission_progress", "admitted_receipts"},
        "checkpoint_batches.py": {"checkpoint_progress", "checkpoint_progress_with_campaign"},
    }
    if set(scope.previous_modules_sha256) != set(allowed) or set(scope.current_modules_sha256) != set(allowed):
        raise ValueError("progress caching requires the exact two progress producer bindings")
    with zipfile.ZipFile(previous) as before, zipfile.ZipFile(current) as after:
        for name, functions in allowed.items():
            trees = []
            for archive, expected in ((before, scope.previous_modules_sha256), (after, scope.current_modules_sha256)):
                data = archive.read(name)
                if hashlib.sha256(data).hexdigest() != expected[name]:
                    raise ValueError("progress caching source differs from its exact archive binding")
                tree = ast.parse(data)
                tree.body = [node for node in tree.body if not (
                    isinstance(node, ast.FunctionDef) and node.name in functions)]
                if name == "checkpoint_batches.py":
                    for node in tree.body:
                        if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module == "preproduction_admission":
                            node.names = [alias for alias in node.names
                                          if alias.name != "ArtifactVerification" or alias.asname is not None]
                trees.append(ast.dump(tree, include_attributes=False))
            if trees[0] != trees[1]:
                raise ValueError(f"progress caching changed non-progress code: {name}")


def _validate_query_serialization_sources(previous: Path, current: Path) -> None:
    with zipfile.ZipFile(previous) as before, zipfile.ZipFile(current) as after:
        old = ast.parse(before.read("preproduction_admission.py"))
        new = ast.parse(after.read("preproduction_admission.py"))
    for node in ast.walk(old):
        if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module == "transport_amendments":
            for alias in node.names:
                if alias.name == "ParallelFinalizationApproval" and alias.asname is None:
                    alias.name = "parse_finalization_approval"
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and (
            isinstance(node.func.value, ast.Name) and node.func.value.id == "ParallelFinalizationApproval"
            and node.func.attr == "model_validate_json"
        ):
            node.func = ast.Name(id="parse_finalization_approval", ctx=ast.Load())
    if ast.dump(old, include_attributes=False) != ast.dump(new, include_attributes=False):
        raise ValueError("query serialization changed admission code beyond versioned approval parsing")


def _query_qualification_artifacts(run: Path, qualification: dict) -> dict[Path, str]:
    from .preproduction_revisions import _within

    names = ["regression_log", "mysql_qualification"]
    if qualification.get("historical_readback_scope") is not None:
        names.append("historical_readback_tests")
    return {_within(run, qualification[name]): qualification[name + "_sha256"]
            for name in names}


def _validate_query_qualification(run: Path, qualification: dict, scope: QuerySerializationScope) -> None:
    from .preproduction_revisions import _within

    if qualification.get("query_serialization_scope") != scope.model_dump(mode="json") or (
        qualification.get("query_guard_tests_passed") is not True
        or qualification.get("historical_admissions_verified") is not True
    ):
        raise ValueError("query serialization lacks exact guard and historical qualification")
    for path, expected in _query_qualification_artifacts(run, qualification).items():
        if file_sha256(path) != expected:
            raise ValueError("query serialization qualification evidence changed")
    log = _within(run, qualification["regression_log"]).read_text()
    tests = re.search(r"(?:\A|\n)Ran (\d+) tests in [^\n]+\n\nOK\s*\Z", log)
    if tests is None or int(tests[1]) < 166:
        raise ValueError("query serialization requires at least 166 passing regression tests")
    mysql = json.loads(_within(run, qualification["mysql_qualification"]).read_bytes())
    if mysql.get("status") != "passed" or type(mysql.get("cases")) is not int or mysql["cases"] < 29 or (
        mysql.get("runtime_before_sha256") != scope.previous_query_sha256
        or mysql.get("runtime_after_sha256") != scope.current_query_sha256
        or mysql.get("source_table_queries") != 0
        or mysql.get("original_student_sql_replayed") is not False
        or mysql.get("new_model_or_student_calls") != 0
    ):
        raise ValueError("query serialization requires the bound passing synthetic MySQL qualification")


def _historical_readback_artifacts(run: Path, scope: HistoricalReadbackScope) -> dict[Path, str]:
    from .preproduction_revisions import _within

    return {_within(run, getattr(scope, name)): getattr(scope, name + "_sha256")
            for name in ("inventory", "ancestor_runtime", "controller_source", "helper_source")}


def _validate_historical_readback(plan, run: Path, scope: HistoricalReadbackScope,
                                  query_scope: QuerySerializationScope) -> tuple[HistoricalReadbackInventory, dict[str, str]]:
    from .preproduction_revisions import _within

    for path, expected in _historical_readback_artifacts(run, scope).items():
        if file_sha256(path) != expected:
            raise ValueError("historical readback scope artifact changed")
    ancestor_path = _within(run, scope.ancestor_runtime)
    if ancestor_path not in _parallel_paths(run):
        raise ValueError("historical readback requires a registered approved ancestor")
    ancestor = parse_finalization_runtime(ancestor_path.read_bytes())
    if not isinstance(ancestor, ParallelFinalizationRuntime) or ancestor.plan_fingerprint != fingerprint(plan):
        raise ValueError("historical readback ancestor belongs to another runtime or plan")
    archive = _within(run, ancestor.archive)
    if file_sha256(archive) != ancestor.archive_sha256:
        raise ValueError("historical readback ancestor archive changed")
    manifest = _archive_manifest(archive)
    inventory = HistoricalReadbackInventory.model_validate_json(_within(run, scope.inventory).read_bytes())
    if inventory.plan_fingerprint != fingerprint(plan) or (
        inventory.ancestor_manifest_sha256 != _manifest_digest(manifest)
        or manifest.get("query.py") != query_scope.previous_query_sha256
    ):
        raise ValueError("historical readback inventory differs from its exact pre-serializer ancestor")
    groups = (inventory.certificate_sha256, inventory.worker_policy_sha256, inventory.other_artifacts_sha256)
    if len(set().union(*groups)) != sum(len(group) for group in groups):
        raise ValueError("historical readback record groups overlap")
    for group in groups:
        for name, expected in group.items():
            path = _within(run, name)
            if name != str(path.relative_to(run.resolve())) or file_sha256(path) != expected:
                raise ValueError("a sealed historical readback record changed or has a noncanonical path")
    return inventory, manifest


def historical_readback_authority(plan, run: Path):
    from .preproduction_revisions import _within

    load_transport_amendment(plan, run)
    for path in reversed(_parallel_paths(run)):
        runtime = parse_finalization_runtime(path.read_bytes())
        approval = parse_finalization_approval(_within(run, runtime.approval).read_bytes())
        if isinstance(approval, QuerySerializationApproval) and approval.historical_readback_scope is not None:
            scope = approval.historical_readback_scope
            inventory, manifest = _validate_historical_readback(plan, run, scope, approval.query_serialization_scope)
            return scope, inventory, manifest
    return None


def _guard_path(run: Path, name: str) -> Path:
    relative = Path(name)
    path = run.resolve() / relative
    if relative.is_absolute() or str(relative) != name or ".." in relative.parts or (
        path == run.resolve() or path.resolve() != path
    ):
        raise ValueError("guard history requires canonical run-owned paths without symlinks")
    return path


def _guard_history_artifacts(plan, run: Path, scope: GuardHistoryScope):
    artifacts = {}
    for name in ("receipt_inventory", "controller_source", "helper_source"):
        artifacts[_guard_path(run, getattr(scope, name))] = getattr(scope, name + "_sha256")
    groups, identities = [], set()
    if not scope.groups:
        raise ValueError("guard history needs at least one exact approved ancestor")
    for group in scope.groups:
        ancestor_path = _guard_path(run, group.ancestor_runtime)
        transport_path = run.resolve() / "transport-amendments/0000.json"
        if ancestor_path not in (*_parallel_paths(run), transport_path):
            raise ValueError("guard readback ancestor must be an existing registered runtime")
        if ancestor_path in identities:
            raise ValueError("guard history ancestors must be unique")
        identities.add(ancestor_path)
        artifacts[ancestor_path] = group.ancestor_runtime_sha256
        inventory_path = _guard_path(run, group.inventory)
        artifacts[inventory_path] = group.inventory_sha256
        if ancestor_path == transport_path:
            ancestor = TransportAmendment.model_validate_json(ancestor_path.read_bytes())
            archive = _guard_path(run, ancestor.current_archive)
            previous = _guard_path(run, ancestor.archive)
            artifacts[archive], artifacts[previous] = ancestor.current_archive_sha256, ancestor.archive_sha256
            artifacts[run / AUTHORITY] = ancestor.authority_sha256
            if ancestor.plan_fingerprint != fingerprint(plan) or load_provider_default(plan, run) is None:
                raise ValueError("guard transport history lacks its original provider authority")
            _, manifest = validate_archive_pair(previous, archive, verify_installed=False)
        else:
            ancestor = parse_finalization_runtime(ancestor_path.read_bytes())
            if isinstance(ancestor, QueryTokenizationRuntime) or ancestor.plan_fingerprint != fingerprint(plan):
                raise ValueError("guard history cannot invent an ancestor or adopt another plan")
            archive = _guard_path(run, ancestor.archive)
            artifacts[archive] = ancestor.archive_sha256
            manifest = _archive_manifest(archive)
            approval_path = _guard_path(run, ancestor.approval)
            artifacts[approval_path] = ancestor.approval_sha256
            approved = parse_finalization_approval(approval_path.read_bytes())
            if approved.plan_fingerprint != fingerprint(plan) or approved.current_manifest_sha256 != _manifest_digest(manifest):
                raise ValueError("guard history ancestor differs from its approved archive")
        inventory = HistoricalReadbackInventory.model_validate_json(inventory_path.read_bytes())
        if inventory.plan_fingerprint != fingerprint(plan) or inventory.ancestor_manifest_sha256 != _manifest_digest(manifest):
            raise ValueError("guard history inventory differs from its exact ancestor")
        carrier = _guard_path(run, group.carrier_repository)
        modules = carrier / "secgym/qagen/agentic"
        if {p.name for p in modules.glob("*.py")} != set(manifest):
            raise ValueError("guard history hash-only carrier has missing or extra Python members")
        for name, expected in manifest.items():
            path = modules / name
            if path.resolve() != path:
                raise ValueError("guard history carrier cannot follow symlinks")
            artifacts[path] = expected
        for collection in (inventory.certificate_sha256, inventory.worker_policy_sha256,
                           inventory.other_artifacts_sha256):
            for name, expected in collection.items():
                path = _guard_path(run, name)
                if path in artifacts and artifacts[path] != expected:
                    raise ValueError("guard history contains contradictory artifact bindings")
                artifacts[path] = expected
        groups.append((group, inventory, manifest))
    receipt_path = _guard_path(run, scope.receipt_inventory)
    receipts = json.loads(receipt_path.read_bytes())
    if receipts.get("plan_fingerprint") != fingerprint(plan) or not isinstance(receipts.get("receipt_sha256"), dict):
        raise ValueError("guard receipt inventory belongs to another plan")
    for name, expected in receipts["receipt_sha256"].items():
        path = _guard_path(run, name)
        if path.parent != run.resolve() / "admissions" or path.suffix != ".json":
            raise ValueError("guard historical receipts must be original admission records")
        artifacts[path] = expected
    for path, expected in artifacts.items():
        if file_sha256(path) != expected:
            raise ValueError("guard history archive, carrier or sealed artifact changed: " + str(path))
    covered = set()
    for _, inventory, _ in groups:
        names = set(inventory.certificate_sha256) | set(inventory.worker_policy_sha256)
        if len(names) != len(inventory.certificate_sha256) + len(inventory.worker_policy_sha256) or covered & names:
            raise ValueError("guard historical certificate/worker identities cannot overlap")
        covered.update(names)
    return artifacts, tuple(groups), receipts["receipt_sha256"]


def guard_historical_readback_authority(plan, run: Path):
    load_transport_amendment(plan, run)
    paths = _parallel_paths(run)
    if not paths:
        return None
    runtime = parse_finalization_runtime(paths[-1].read_bytes())
    if not isinstance(runtime, QueryTokenizationRuntime):
        return None
    approval = parse_finalization_approval(_guard_path(run, runtime.approval).read_bytes())
    if not isinstance(approval, QueryTokenizationApproval):
        raise ValueError("guard readback requires its distinct fresh-only approval")
    scope = approval.historical_readback_scope
    _, groups, _ = _guard_history_artifacts(plan, run, scope)
    return scope, groups


def _validate_tokenization_sources(previous: Path, current: Path, scope: QueryTokenizationScope) -> None:
    old, new = _archive_manifest(previous), _archive_manifest(current)
    changed = {name for name in old.keys() | new.keys() if old.get(name) != new.get(name)}
    if old.keys() != new.keys() or changed != {"query.py", "transport_amendments.py"} or (
        old.get("query.py") != scope.previous_query_sha256 or new.get("query.py") != scope.current_query_sha256
    ):
        raise ValueError("fresh tokenizer authority permits only its exact M5 query guard and authority plumbing")
    with zipfile.ZipFile(previous) as before, zipfile.ZipFile(current) as after:
        expected = before.read("query.py").replace(
            b"except sqlglot.errors.ParseError as error:",
            b"except (sqlglot.errors.ParseError, sqlglot.errors.TokenError) as error:",
        )
        if after.read("query.py") != expected:
            raise ValueError("tokenizer guard changed successful serialization, capture, scoring or other query behavior")


def _validate_guard_archived_references(run, references, previous_manifest):
    for reference in references:
        receipt = _guard_path(run, reference.receipt)
        artifact = Path(reference.artifact)
        if receipt.parent != run.resolve() / "admissions" or file_sha256(receipt) != reference.receipt_sha256:
            raise ValueError("guard archive reference lacks its exact sealed admission")
        if reference.archive_member not in {"query.py", "transport_amendments.py"} or (
            not artifact.is_absolute() or artifact.resolve() != artifact
            or artifact.name != reference.archive_member
            or previous_manifest.get(reference.archive_member) != reference.artifact_sha256
        ):
            raise ValueError("guard archival authority cannot substitute unrelated or changed kernels")
        value = json.loads(receipt.read_bytes())
        if receipt.name != value["task"]["task_id"] + ".json" or (
            value["source_artifacts_sha256"].get(reference.artifact) != reference.artifact_sha256
        ):
            raise ValueError("guard archival reference was not present in the original admission")
    if len({(r.receipt, r.artifact) for r in references}) != len(references):
        raise ValueError("guard archival references must be unique")


def _guard_drain(plan, run, approval):
    path = _guard_path(run, approval.drain_inventory)
    if file_sha256(path) != approval.drain_inventory_sha256:
        raise ValueError("guard final M5 drain inventory changed")
    value = GuardDrainInventory.model_validate_json(path.read_bytes())
    if value.plan_fingerprint != fingerprint(plan) or not value.closed_owner_pids or (
        len(set(value.closed_owner_pids)) != len(value.closed_owner_pids)
        or any(pid <= 0 for pid in value.closed_owner_pids)
        or not value.owner_evidence_sha256
        or "generation-batches/astra100-12/checkpoint-report.json" not in value.completed_batch_reports_sha256
    ):
        raise ValueError("fresh guard authority needs exact post-drain owner and completed-batch evidence")
    for files in (value.owner_evidence_sha256, value.completed_batch_reports_sha256):
        for name, expected in files.items():
            if file_sha256(_guard_path(run, name)) != expected:
                raise ValueError("guard post-drain evidence changed")
    report_path = _guard_path(run, "generation-batches/astra100-12/checkpoint-report.json")
    report = json.loads(report_path.read_bytes())
    if report.get("batch_id") != "astra100-12" or report.get("drafts") != {"draft_ready": 100} or (
        report.get("source_reviews", {}).get("pending", 0)
        or sum(report.get("source_reviews", {}).values()) != 100
    ):
        raise ValueError("guard cutover requires the completed original batch12 source barrier")
    items = sorted((report_path.parent / "items").glob("*.json"))
    if len(items) != 100:
        raise ValueError("guard drain report must retain the original 100 batch items")
    for item_path in items:
        item = json.loads(item_path.read_bytes())
        task_id = item["attempt"]["task_id"]
        review_name = f"attempts/{task_id}/checkpoint-review-result.json"
        if review_name not in value.owner_evidence_sha256:
            raise ValueError("guard drain evidence omits an original source result")
        review = json.loads(_guard_path(run, review_name).read_bytes())
        if review.get("status") == "source_ready":
            pipeline_name = f"attempts/{task_id}/checkpoint-pipeline-result.json"
            if pipeline_name not in value.owner_evidence_sha256:
                raise ValueError("guard drain evidence omits original native candidate work")
            pipeline = json.loads(_guard_path(run, pipeline_name).read_bytes())
            if pipeline.get("status") not in ("admitted", "already_admitted", "held", "operational_error"):
                raise ValueError("original native candidate is not terminal")
    required = {"campaign-control/controller.lock", "checkpoint-workflow.lock"}
    if not required <= set(value.required_locks) or len(set(value.required_locks)) != len(value.required_locks):
        raise ValueError("fresh guard cutover must fence the original controller and workflow")
    return value


@contextmanager
def query_guard_cutover_fences(plan, run, approval):
    """Publication only after final drain; history inspection never takes execution ownership."""
    if approval.historical_readback_scope.snapshot_status != "final":
        raise ValueError("provisional M5 history cannot authorize a runtime cutover")
    drain = _guard_drain(plan, run, approval)
    with ExitStack() as stack:
        for name in drain.required_locks:
            if name == "run.lock":
                raise ValueError("run.lock is acquired by the existing finalization recorder")
            stream = stack.enter_context(_guard_path(run, name).open("rb"))
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise ValueError("M5 owners have not drained; fresh guard publication is blocked") from error
        for pid in drain.closed_owner_pids:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                continue
            raise ValueError("an original M5 owner is alive or its PID was reused")
        yield


def _validate_tokenization_qualification(plan, run, approval, current):
    scope = approval.query_tokenization_scope
    if approval.historical_readback_scope.snapshot_status != "final":
        raise ValueError("provisional history is not final fresh-guard authority")
    _guard_drain(plan, run, approval)
    _guard_history_artifacts(plan, run, approval.historical_readback_scope)
    path = _guard_path(run, approval.qualification)
    if file_sha256(path) != approval.qualification_sha256:
        raise ValueError("fresh guard qualification evidence changed")
    value = json.loads(path.read_bytes())
    fields = ("guard_tests_passed", "readback_tests_passed", "old_execution_rejected",
              "fresh_policy_tests_passed", "actual_controller_qualified", "all_current_receipts_verified",
              "old_dispositions_unchanged", "m5_native_audit_repair_owners_drained")
    if value.get("status") != "pass" or any(value.get(name) is not True for name in fields) or (
        value.get("query_tokenization_scope") != scope.model_dump(mode="json")
        or value.get("historical_readback_scope") != approval.historical_readback_scope.model_dump(mode="json")
        or value.get("current_manifest_sha256") != _manifest_digest(current)
        or value.get("model_calls") != 0
        or value.get("archived_producer_references", []) != [
            r.model_dump(mode="json") for r in approval.archived_producer_references]
    ):
        raise ValueError("fresh guard lacks its exact post-drain controller/receipt/execution qualification")
    evidence = value.get("evidence_sha256")
    if not isinstance(evidence, dict) or not evidence:
        raise ValueError("fresh guard qualification must retain its test and readback evidence")
    for name, expected in evidence.items():
        if file_sha256(_guard_path(run, name)) != expected:
            raise ValueError("fresh guard qualification test evidence changed")


def _parallel_step(plan, run: Path, transport: TransportAmendment, baseline: dict[str, str],
                   original_manifest: dict[str, str], previous_scope: dict[str, str],
                   prior_hash: str | None, amendment: ParallelFinalizationRuntime | QuerySerializationRuntime | QueryTokenizationRuntime,
                   previous_archive: Path) -> dict[str, str]:
    from .preproduction_revisions import _within

    if amendment.plan_fingerprint != fingerprint(plan) or (
        amendment.transport_amendment_sha256 != file_sha256(run / "transport-amendments/0000.json")
        or amendment.previous_runtime_sha256 != previous_scope
        or amendment.previous_parallel_sha256 != prior_hash
    ):
        raise ValueError("parallel finalization is not continuous from its exact approved predecessor")
    archive, approval_path = _within(run, amendment.archive), _within(run, amendment.approval)
    if file_sha256(archive) != amendment.archive_sha256 or file_sha256(approval_path) != amendment.approval_sha256:
        raise ValueError("parallel-finalization archive or approval changed")
    current = _archive_manifest(archive)
    changed = {name for name in baseline.keys() | current.keys() if baseline.get(name) != current.get(name)}
    approval = parse_finalization_approval(approval_path.read_bytes())
    if isinstance(amendment, QueryTokenizationRuntime) or isinstance(approval, QueryTokenizationApproval):
        if not isinstance(amendment, QueryTokenizationRuntime) or not isinstance(approval, QueryTokenizationApproval):
            raise ValueError("fresh tokenizer runtime must use its separate truthful guard discriminator")
        if amendment.current_runtime_sha256 != {name: current[name] for name in amendment.previous_runtime_sha256} or (
            approval.plan_fingerprint != fingerprint(plan)
            or approval.previous_manifest_sha256 != _manifest_digest(baseline)
            or approval.current_manifest_sha256 != _manifest_digest(current)
        ):
            raise ValueError("fresh guard runtime does not bind its exact before/after archives")
        _validate_tokenization_sources(previous_archive, archive, approval.query_tokenization_scope)
        _validate_guard_archived_references(run, approval.archived_producer_references, baseline)
        _validate_tokenization_qualification(plan, run, approval, current)
        return current
    if isinstance(amendment, QuerySerializationRuntime) != isinstance(approval, QuerySerializationApproval):
        raise ValueError("runtime and approval must use the same separately versioned serializer semantics")
    query_scope = approval.query_serialization_scope if isinstance(approval, QuerySerializationApproval) else None
    caching_scope = getattr(approval, "progress_caching_scope", None)
    provider_scope = getattr(approval, "provider_recovery_scope", None)
    if caching_scope is not None and provider_scope is not None:
        raise ValueError("progress caching cannot authorize a provider recovery change")
    allowed = ({"query.py", "transport_amendments.py", "preproduction_admission.py"} if query_scope is not None else
               PROGRESS_CACHING_MODULES if caching_scope is not None else
               PROVIDER_RECOVERY_MODULES if provider_scope is not None else PARALLEL_MODULES)
    if baseline.keys() != current.keys() or not changed or not changed <= allowed:
        raise ValueError("parallel finalization cannot change protected kernels or add unrelated modules")
    if amendment.current_runtime_sha256 != {name: current[name] for name in amendment.previous_runtime_sha256}:
        raise ValueError("parallel-finalization runtime envelope differs from its archived producer")
    if query_scope is not None:
        if baseline.get("query.py") != query_scope.previous_query_sha256 or (
            current.get("query.py") != query_scope.current_query_sha256
        ):
            raise ValueError("query serialization requires its one exact before/after query source pair")
        _validate_query_serialization_sources(previous_archive, archive)
    if provider_scope is not None and (
        "provider_defaults.py" not in changed
        or provider_scope.previous_provider_sha256 != baseline.get("provider_defaults.py")
        or provider_scope.current_provider_sha256 != current.get("provider_defaults.py")
    ):
        raise ValueError("provider recovery requires its exact before/after provider implementation")
    if caching_scope is not None:
        names = {"preproduction_admission.py", "checkpoint_batches.py"}
        if not names <= changed or caching_scope.previous_modules_sha256 != {name: baseline[name] for name in names} or (
            caching_scope.current_modules_sha256 != {name: current[name] for name in names}
        ):
            raise ValueError("progress caching requires its exact before/after progress implementations")
        _validate_progress_caching_sources(previous_archive, archive, caching_scope)
    if (approval.plan_fingerprint, approval.previous_manifest_sha256, approval.current_manifest_sha256) != (
        fingerprint(plan), _manifest_digest(baseline), _manifest_digest(current),
    ):
        raise ValueError("parallel-finalization approval does not bind the exact source pair")
    qualification_path = _within(run, approval.qualification)
    if file_sha256(qualification_path) != approval.qualification_sha256:
        raise ValueError("parallel-finalization qualification evidence changed")
    qualification = json.loads(qualification_path.read_bytes())
    if qualification.get("status") != "pass" or qualification.get("current_manifest_sha256") != _manifest_digest(current):
        raise ValueError("parallel finalization lacks passing qualification for its exact producer")
    if query_scope is not None:
        _validate_query_qualification(run, qualification, query_scope)
        if approval.historical_readback_scope is not None:
            if qualification.get("historical_readback_scope") != approval.historical_readback_scope.model_dump(mode="json") or (
                qualification.get("historical_readback_tests_passed") is not True
            ):
                raise ValueError("historical readback lacks its exact separately qualified inventory and readers")
            _validate_historical_readback(plan, run, approval.historical_readback_scope, query_scope)
    if provider_scope is not None and (
        qualification.get("provider_recovery_scope") != provider_scope.model_dump(mode="json")
        or qualification.get("provider_bound_recovery_tests_passed") is not True
        or qualification.get("historical_admissions_verified") is not True
    ):
        raise ValueError("provider recovery lacks exact provider-bound and historical-admission qualification")
    if caching_scope is not None and (
        qualification.get("progress_caching_scope") != caching_scope.model_dump(mode="json")
        or qualification.get("progress_cache_tests_passed") is not True
        or qualification.get("historical_admissions_verified") is not True
    ):
        raise ValueError("progress caching lacks exact cache-integrity and historical-admission qualification")
    if qualification.get("archived_producer_references", []) != [
        value.model_dump(mode="json") for value in approval.archived_producer_references
    ] or (approval.archived_producer_references and qualification.get("historical_admissions_verified") is not True):
        raise ValueError("archived producer references lack exact historical-admission qualification")
    _validate_archived_references(
        run, approval.archived_producer_references, original_manifest,
        provider_recovery_scope=provider_scope,
        query_serialization_scope=query_scope,
    )
    return current


def _validate(plan, run: Path, amendment: TransportAmendment, previous=None, *,
              pending_parallel: ParallelFinalizationRuntime | QuerySerializationRuntime | QueryTokenizationRuntime | None = None):
    from .preproduction_revisions import _within

    authority = load_provider_default(plan, run)
    if authority is None or amendment.authority_sha256 != file_sha256(run / AUTHORITY) or (
        amendment.plan_fingerprint != fingerprint(plan)
    ):
        raise ValueError("transport amendment lacks its exact explicit provider-default authority")
    if previous is not None and amendment.previous_runtime_sha256 != previous:
        raise ValueError("transport amendment is not continuous from the unchanged original runtime plan")
    old_path, new_path = _within(run, amendment.archive), _within(run, amendment.current_archive)
    if (file_sha256(old_path), file_sha256(new_path)) != (amendment.archive_sha256, amendment.current_archive_sha256):
        raise ValueError("transport amendment archive bytes changed")
    old, new = validate_archive_pair(old_path, new_path, verify_installed=False)
    before, after = amendment.previous_runtime_sha256, amendment.current_runtime_sha256
    from .preproduction import runtime_hashes
    if set(before) != set(after) - ADDED_MODULES or (
        before != {name: old.get(name) for name in before}
        or after != {name: new.get(name) for name in after}
    ):
        raise ValueError("transport amendment changed its exact source runtime envelope")
    current = _parallel_runtime(plan, run, amendment, new, pending=pending_parallel)
    if any(file_sha256(Path(__file__).with_name(name)) != digest for name, digest in current.items()) or (
        runtime_hashes() != {name: current[name] for name in after}
    ):
        raise ValueError("transport archive differs from the installed audited runtime")
    return old, current


def load_transport_amendment(plan, run: Path):
    directory = run / "transport-amendments"
    if not directory.exists():
        return None
    if sorted(path.name for path in directory.iterdir()) != ["0000.json"]:
        raise ValueError("only one exact versioned forward transport amendment is supported")
    amendment = TransportAmendment.model_validate_json((directory / "0000.json").read_bytes())
    old, new = _validate(plan, run, amendment)
    return amendment, old, new


def effective_transport_runtime(plan, run: Path, previous: dict[str, str]) -> dict[str, str]:
    loaded = load_transport_amendment(plan, run)
    if loaded is None:
        return previous
    amendment, _, current = loaded
    if amendment.previous_runtime_sha256 != previous:
        raise ValueError("transport amendment is not continuous from the unchanged original runtime plan")
    return {name: current[name] for name in amendment.current_runtime_sha256}


def transport_runtime_matches(plan, run: Path, recorded: dict[str, str], current: dict[str, str]) -> bool:
    loaded = load_transport_amendment(plan, run)
    if loaded is None:
        return False
    if "query.py" in current and recorded.get("query.py") != current["query.py"]:
        return False
    amendment, old, new = loaded
    states = [old]
    if (run / PARALLEL_RUNTIME).exists():
        states.append(_archive_manifest(run / amendment.current_archive))
        states.extend(_archive_manifest(run / parse_finalization_runtime(path.read_bytes()).archive)
                      for path in _parallel_paths(run)[:-1])
    return (
        any(recorded == {name: state[name] for name in current if name in state} for state in states)
        and current == {name: new.get(name) for name in current}
    )


def load_parallel_finalization_runtime(plan, run: Path) -> ParallelFinalizationRuntime | QuerySerializationRuntime | QueryTokenizationRuntime | None:
    path = run / PARALLEL_RUNTIME
    if not path.exists():
        return None
    load_transport_amendment(plan, run)
    return parse_finalization_runtime(_parallel_paths(run)[-1].read_bytes())


def record_parallel_finalization_runtime(plan, run: Path, *, archive: Path, approval: Path,
                                         reason: str) -> ParallelFinalizationRuntime:
    from .model_panel import immutable_json
    from .preproduction import PreproductionPlan, locked_run, runtime_hashes
    from .preproduction_revisions import _within

    if PreproductionPlan.model_validate_json((run / "plan.json").read_bytes()) != plan:
        raise ValueError("parallel finalization requires the unchanged original run plan")
    path = run / PARALLEL_RUNTIME
    with locked_run(run, wait=True):
        if path.exists():
            raise ValueError("parallel-finalization runtime amendment already exists")
        transport_path = run / "transport-amendments/0000.json"
        transport = TransportAmendment.model_validate_json(transport_path.read_bytes())
        archive, approval = _within(run, str(archive)), _within(run, str(approval))
        value = ParallelFinalizationRuntime(
            plan_fingerprint=fingerprint(plan), transport_amendment_sha256=file_sha256(transport_path),
            previous_runtime_sha256=transport.current_runtime_sha256, current_runtime_sha256=runtime_hashes(),
            archive=str(archive.relative_to(run.resolve())), archive_sha256=file_sha256(archive),
            approval=str(approval.relative_to(run.resolve())), approval_sha256=file_sha256(approval), reason=reason,
        )
        _validate(plan, run, transport, pending_parallel=value)
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        immutable_json(path, value)
        return value


def record_parallel_finalization_correction(plan, run: Path, *, archive: Path, approval: Path,
                                            reason: str) -> ParallelFinalizationRuntime:
    return _record_finalization_correction(plan, run, archive=archive, approval=approval, reason=reason,
                                           runtime_type=ParallelFinalizationRuntime)


def record_query_serialization_correction(plan, run: Path, *, archive: Path, approval: Path,
                                          reason: str) -> QuerySerializationRuntime:
    return _record_finalization_correction(plan, run, archive=archive, approval=approval, reason=reason,
                                           runtime_type=QuerySerializationRuntime)


@contextmanager
def query_guard_publication(plan, run: Path, *, approval: Path):
    """Hold one ownership fence across installation and its exact authority publication."""
    approval_sha256 = file_sha256(approval)
    approved = QueryTokenizationApproval.model_validate_json(approval.read_bytes())
    with query_guard_cutover_fences(plan, run, approved):
        active = True

        def publish(*, archive: Path, reason: str) -> QueryTokenizationRuntime:
            if not active or file_sha256(approval) != approval_sha256:
                raise ValueError("guard publication lost its ownership fence or exact approval")
            _guard_drain(plan, run, approved)
            _, groups, receipts = _guard_history_artifacts(plan, run, approved.historical_readback_scope)
            if set(receipts) != {str(p.relative_to(run)) for p in (run / "admissions").glob("*.json")}:
                raise ValueError("final guard history must include every admission present after M5 drains")
            covered_workers = set().union(*(set(inventory.worker_policy_sha256) for _, inventory, _ in groups))
            actual_workers = {str(p.relative_to(run)) for p in
                              (run / "generation-batches").glob("*/model-worker-execution.json")}
            if covered_workers != actual_workers:
                raise ValueError("final guard history must include every original worker policy")
            covered_certificates = set().union(*(set(inventory.certificate_sha256) for _, inventory, _ in groups))
            for path in (run / "campaign-control/reviewed-attempts").glob("*.json"):
                value = json.loads(path.read_bytes())
                kernels = value.get("capture_kernel_sha256", value.get("kernel_sha256", {}))
                if kernels.get("query.py") not in (None, approved.query_tokenization_scope.current_query_sha256) and (
                    str(path.relative_to(run)) not in covered_certificates
                ):
                    raise ValueError("final guard history omits an original historical kernel certificate")
            return _record_finalization_correction(
                plan, run, archive=archive, approval=approval, reason=reason,
                runtime_type=QueryTokenizationRuntime,
            )

        try:
            yield publish
        finally:
            active = False


def record_query_tokenization_correction(plan, run: Path, *, archive: Path, approval: Path,
                                        reason: str) -> QueryTokenizationRuntime:
    with query_guard_publication(plan, run, approval=approval) as publish:
        return publish(archive=archive, reason=reason)


def _record_finalization_correction(plan, run: Path, *, archive: Path, approval: Path, reason: str,
                                    runtime_type):
    from .model_panel import immutable_json
    from .preproduction import PreproductionPlan, locked_run, runtime_hashes
    from .preproduction_revisions import _within

    if PreproductionPlan.model_validate_json((run / "plan.json").read_bytes()) != plan:
        raise ValueError("parallel correction requires the unchanged original run plan")
    with locked_run(run, wait=True):
        paths = _parallel_paths(run)
        if not paths:
            raise ValueError("a parallel correction requires an existing approved predecessor")
        previous = parse_finalization_runtime(paths[-1].read_bytes())
        transport_path = run / "transport-amendments/0000.json"
        transport = TransportAmendment.model_validate_json(transport_path.read_bytes())
        archive, approval = _within(run, str(archive)), _within(run, str(approval))
        value = runtime_type(
            plan_fingerprint=fingerprint(plan), transport_amendment_sha256=file_sha256(transport_path),
            previous_runtime_sha256=previous.current_runtime_sha256, current_runtime_sha256=runtime_hashes(),
            archive=str(archive.relative_to(run.resolve())), archive_sha256=file_sha256(archive),
            approval=str(approval.relative_to(run.resolve())), approval_sha256=file_sha256(approval),
            reason=reason, previous_parallel_sha256=file_sha256(paths[-1]),
        )
        _validate(plan, run, transport, pending_parallel=value)
        immutable_json(paths[-1].parent / f"{len(paths):04d}.json", value)
        return value


def archived_admission_producers(plan, run: Path) -> tuple[
    dict[tuple[Path, Path, str], tuple[Path, str, str]], dict[Path, str],
]:
    from .preproduction_revisions import _within

    paths = _parallel_paths(run)
    if not paths:
        return {}, {}
    loaded = load_transport_amendment(plan, run)
    if loaded is None:
        raise ValueError("archived producer references require the approved transport archive")
    transport, _, _ = loaded
    archive = _within(run, transport.current_archive)
    previous_archive, previous_archive_sha256 = archive, transport.current_archive_sha256
    bindings: dict[tuple[Path, Path, str], tuple[Path, str, str]] = {}
    dependencies = {run / "transport-amendments/0000.json": file_sha256(run / "transport-amendments/0000.json"),
                    archive: transport.current_archive_sha256}
    for path in paths:
        amendment = parse_finalization_runtime(path.read_bytes())
        approval_path = _within(run, amendment.approval)
        approval = parse_finalization_approval(approval_path.read_bytes())
        dependencies.update({
            path: file_sha256(path), approval_path: amendment.approval_sha256,
            _within(run, approval.qualification): approval.qualification_sha256,
            _within(run, amendment.archive): amendment.archive_sha256,
        })
        if isinstance(approval, QuerySerializationApproval):
            qualification = json.loads(_within(run, approval.qualification).read_bytes())
            dependencies.update(_query_qualification_artifacts(run, qualification))
            if approval.historical_readback_scope is not None:
                scope = approval.historical_readback_scope
                dependencies.update(_historical_readback_artifacts(run, scope))
                inventory = HistoricalReadbackInventory.model_validate_json(_within(run, scope.inventory).read_bytes())
                for group in (inventory.certificate_sha256, inventory.worker_policy_sha256,
                              inventory.other_artifacts_sha256):
                    dependencies.update({_within(run, name): digest for name, digest in group.items()})
        if isinstance(approval, QueryTokenizationApproval):
            history, _, _ = _guard_history_artifacts(plan, run, approval.historical_readback_scope)
            dependencies.update(history)
            dependencies[_guard_path(run, approval.drain_inventory)] = approval.drain_inventory_sha256
            qualification = json.loads(_guard_path(run, approval.qualification).read_bytes())
            dependencies.update({_guard_path(run, name): expected
                                 for name, expected in qualification["evidence_sha256"].items()})
        for reference in approval.archived_producer_references:
            receipt = _within(run, reference.receipt)
            dependencies[receipt] = reference.receipt_sha256
            key = (receipt, Path(reference.artifact), reference.artifact_sha256)
            bindings[key] = (
                (previous_archive, previous_archive_sha256, reference.archive_member)
                if isinstance(approval, QueryTokenizationApproval)
                else (archive, transport.current_archive_sha256, reference.archive_member)
            )
        previous_archive, previous_archive_sha256 = _within(run, amendment.archive), amendment.archive_sha256
    if bindings:
        dependencies.update({Path(__file__).with_name(name): file_sha256(Path(__file__).with_name(name))
                             for name in _archive_manifest(_within(run, parse_finalization_runtime(
                                 paths[-1].read_bytes()).archive))})
    return bindings, dependencies if bindings else {}


def transport_checkpoint_producer(plan, run: Path, recorded: str) -> str:
    loaded = load_transport_amendment(plan, run)
    if loaded is None:
        return recorded
    _, old, new = loaded
    return new["checkpoint_batches.py"] if recorded == old["checkpoint_batches.py"] else recorded


def record_transport_amendment(plan, run: Path, *, archive: Path, current_archive: Path, reason: str) -> TransportAmendment:
    from .model_panel import immutable_json
    from .preproduction import PreproductionPlan, locked_run, runtime_hashes
    from .preproduction_revisions import _within, effective_runtime
    from .review_transport import NonStudentTransportPolicy

    if PreproductionPlan.model_validate_json((run / "plan.json").read_bytes()) != plan:
        raise ValueError("transport amendment cannot rewrite the original plan")
    archive, current_archive = _within(run, str(archive)), _within(run, str(current_archive))
    with locked_run(run, wait=True):
        if (run / "transport-amendments").exists():
            raise ValueError("the single transport amendment already exists; validate it instead of replacing it")
        previous = effective_runtime(plan, run)
        amendment = TransportAmendment(
            plan_fingerprint=fingerprint(plan), authority_sha256=file_sha256(run / AUTHORITY),
            previous_runtime_sha256=previous, current_runtime_sha256=runtime_hashes(),
            archive=str(archive.relative_to(run.resolve())), archive_sha256=file_sha256(archive),
            current_archive=str(current_archive.relative_to(run.resolve())),
            current_archive_sha256=file_sha256(current_archive), reason=reason,
        )
        old, new = _validate(plan, run, amendment, previous)
        policy_path = run / "review-transport-policy02.json"
        policy = None
        folder = run / "review-transport-amendments"
        paths = sorted(folder.glob("*.json"))
        if policy_path.exists():
            policy = NonStudentTransportPolicy.model_validate_json(policy_path.read_bytes())
            for sequence, path in enumerate(paths):
                revised = NonStudentTransportPolicy.model_validate_json(path.read_bytes())
                if path.name != f"{sequence:04d}.json" or revised.previous_policy_fingerprint != fingerprint(policy) or (
                    revised.model_dump(exclude={"previous_policy_fingerprint", "implementation_sha256"})
                    != policy.model_dump(exclude={"previous_policy_fingerprint", "implementation_sha256"})
                ):
                    raise ValueError("transport cutover cannot change the approved reviewer policy chain")
                policy = revised
            if policy.plan_fingerprint != fingerprint(plan) or policy.implementation_sha256 != old["review_transport.py"]:
                raise ValueError("transport cutover requires the exact pre-cutover nonstudent policy")
        destination = run / "transport-amendments"
        destination.mkdir(mode=0o700)
        immutable_json(destination / "0000.json", amendment)
        if policy is not None:
            folder.mkdir(mode=0o700, exist_ok=True)
            immutable_json(folder / f"{len(paths):04d}.json", policy.model_copy(update={
                "previous_policy_fingerprint": fingerprint(policy), "implementation_sha256": new["review_transport.py"],
            }))
        return amendment
