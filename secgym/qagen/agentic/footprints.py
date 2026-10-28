# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Private evidence footprints for calibrated overlap, not automatic split decisions."""

import json
from collections.abc import Iterable
from pathlib import Path

import duckdb

from .contracts import TaskRecord, ValidationReport, fingerprint, require_unique
from .ledger import file_sha256
from .similarity import EvidenceFootprint, WeightedFeature
from .sources import digest


def build_unit_footprint(task: TaskRecord, validation: ValidationReport, graph_bundle: Path) -> EvidenceFootprint:
    """An explicit unit-weight baseline; no production weighting is selected here."""
    return build_unit_footprints(((task, validation),), graph_bundle)[0]


def build_unit_footprints(
    tasks: Iterable[tuple[TaskRecord, ValidationReport]], graph_bundle: Path,
) -> tuple[EvidenceFootprint, ...]:
    """Verify one immutable graph once and build a validated batch on one read-only connection."""
    tasks = tuple(tasks)
    if not tasks:
        raise ValueError("footprint batch must be nonempty")
    require_unique(tuple(fingerprint(task) for task, _ in tasks), "footprint task fingerprints")
    for task, validation in tasks:
        blockers = validation.pilot_blockers(task)
        if blockers:
            raise ValueError("footprint requires validated private-pilot evidence: " + "; ".join(blockers))
    report = json.loads((graph_bundle / "graph_report.json").read_text())
    name = report["database"]["path"]
    graph = graph_bundle / name
    if Path(name).name != name or graph.is_symlink() or report["status"] != "complete":
        raise ValueError("invalid graph bundle")
    if any(report["graph_id"] != task.graph_version for task, _ in tasks) or file_sha256(graph) != report["database"]["sha256"]:
        raise ValueError("task and verified graph differ")
    with duckdb.connect(str(graph), read_only=True, config={"threads": 1, "memory_limit": "512MB"}) as con:
        return tuple(_unit_footprint(task, con) for task, _ in tasks)


def _unit_footprint(task: TaskRecord, con: duckdb.DuckDBPyConnection) -> EvidenceFootprint:
    references = {e.evidence_id: e for e in task.evidence}
    claims = (task.private_gold.final, *(c.claim for c in task.private_gold.checkpoints))
    used = set(task.scope.anchor_evidence_ids)
    for claim in claims:
        used.update(eid for group in claim.evidence_sets for eid in group.evidence_ids)
    observations = sorted({references[eid].private_locator for eid in used})
    placeholders = ",".join("?" for _ in observations)
    found = {row[0] for row in con.execute(
        f"SELECT observation_id FROM observations WHERE observation_id IN ({placeholders})", observations,
    ).fetchall()}
    if found != set(observations):
        raise ValueError("evidence observation missing from the declared graph")
    edges = con.execute(
        f"SELECT DISTINCT observation_id,src,dst,relation,semantics FROM edges WHERE observation_id IN ({placeholders})",
        observations,
    ).fetchall()
    facts = []
    for claim in claims:
        supports = sorted(sorted(references[eid].private_locator for eid in group.evidence_ids) for group in claim.evidence_sets)
        facts.append("fact:" + digest([claim.expected.model_dump(mode="json"), supports]))
    return EvidenceFootprint(
        task_fingerprint=fingerprint(task), snapshot_id=task.snapshot_id, graph_version=task.graph_version,
        feature_weight_version="unit-evidence-audit-v1",
        edges=tuple(WeightedFeature(feature_id=value, weight=1.0) for value in sorted({"edge:" + digest(row) for row in edges})) or None,
        observations=tuple(WeightedFeature(feature_id=oid, weight=1.0) for oid in observations),
        facts=tuple(WeightedFeature(feature_id=value, weight=1.0) for value in sorted(set(facts))),
    )
