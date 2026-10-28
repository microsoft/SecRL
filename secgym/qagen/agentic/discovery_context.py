# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Source-scoped generation contexts and bounded graph pivots, never student tools."""

import json
from pathlib import Path
from threading import Timer

import duckdb

from .contracts import PublicCitation, SELECTED_INCIDENTS
from .evidence import EvidenceFailure, EvidenceVerifier
from .ledger import attach_readonly, file_sha256
from .query import PublicQueryEngine, QueryFailure


def scope_context(engine: PublicQueryEngine, mode: str, incident_id: int | None) -> dict:
    if mode not in ("tenant", "incident") or (mode == "tenant") != (incident_id is None):
        raise ValueError("invalid benchmark scope")
    context = {
        "mode": mode, "incident_id": incident_id,
        "data_limits": [
            "Observed source coverage only, not complete acquisition.",
            "Both scopes use the full tenant; an incident question must remain incident-anchored.",
            "FP/BP/benignness/authorization tasks are deferred.",
            "Private adjudications and investigation annotations were removed; raw event observations remain.",
        ],
    }
    if mode == "incident":
        if incident_id not in SELECTED_INCIDENTS:
            raise ValueError("incident is not in the selected scenario pool")
        result = engine.execute(
            "SELECT _record_id,IncidentNumber,Title,AlertIds,FirstActivityTime,LastActivityTime "
            f"FROM SecurityIncident WHERE IncidentNumber={incident_id}"
        )
        if len(result.rows) != 1:
            raise EvidenceFailure("incident must have one current source row")
        context["incident"] = dict(zip(result.columns, result.rows[0]))
        context["case_exclusions"] = (
            ["missing-alert:46f3d4b8-060c-4022-c190-4d88954a6a2e"] if incident_id == 5
            else ["missing-source:SquidProxy"] if incident_id == 322 else []
        )
    else:
        result = engine.execute(
            "SELECT COUNT(*) AS current_incidents,MIN(FirstActivityTime) AS earliest_incident_activity,"
            "MAX(LastActivityTime) AS latest_incident_activity FROM SecurityIncident"
        )
        context["inventory"] = dict(zip(result.columns, result.rows[0]))
    return context


class GraphDiscovery:
    def __init__(self, bundle: Path, verifier: EvidenceVerifier):
        report = json.loads((bundle / "graph_report.json").read_text())
        if report["graph_id"] != verifier.report["graph_id"]:
            raise EvidenceFailure("generation graph is not bound to the serving snapshot")
        database = bundle / report["database"]["path"]
        if database.name != report["database"]["path"] or database.is_symlink() or file_sha256(database) != report["database"]["sha256"]:
            raise EvidenceFailure("invalid generation graph artifact")
        self.con = duckdb.connect(config={"threads": 1, "memory_limit": "512MB"})
        attach_readonly(self.con, database, "graph")
        self.verifier = verifier

    def close(self):
        self.con.close()

    def neighbors(self, citation: PublicCitation) -> dict:
        self.verifier.citation_lineage(citation)
        origin = self.verifier.private.execute(
            "SELECT observation_id FROM mapping.record_map WHERE table_name=? AND record_id=?",
            [citation.table, citation.record_id],
        ).fetchone()
        if origin is None:
            raise EvidenceFailure("generation record lacks private provenance")
        timer = Timer(self.verifier.engine.limits.timeout_ms / 1000, self.con.interrupt)
        timer.start()
        try:
            participants = self.con.execute("""
                SELECT n.node_id,n.kind,n.value,e.relation,e.source_path,e.semantics
                FROM graph.edges e JOIN graph.nodes n ON n.node_id=e.dst WHERE e.observation_id=?
                ORDER BY n.kind,n.value,e.source_path LIMIT 501
            """, [origin[0]]).fetchall()
            if len(participants) > 500:
                raise QueryFailure("graph_result_limit", "Observation has more than 500 participant mentions; use raw SQL.")
            neighbors = self.con.execute("""
                SELECT DISTINCT o.observation_id,o.table_name,o.event_time,o.action,o.lineage
                FROM graph.edges seed JOIN graph.nodes n ON n.node_id=seed.dst
                JOIN graph.edges e ON e.dst=seed.dst JOIN graph.observations o ON o.observation_id=e.observation_id
                WHERE seed.observation_id=? AND e.observation_id<>?
                  AND n.kind IN ('process','sha256','sha1','message_id','directory_object','application_id','mde_device')
                ORDER BY o.event_time,o.observation_id LIMIT 21
            """, [origin[0], origin[0]]).fetchall()
        except duckdb.Error as error:
            raise QueryFailure("graph_query", str(error)) from error
        finally:
            timer.cancel()
            timer.join()
        candidates = []
        for oid, table, timestamp, action, lineage in neighbors[:20]:
            mapping = self.verifier.private.execute("SELECT record_id FROM mapping.record_map WHERE table_name=? AND observation_id=?",
                                                     [table, oid]).fetchone()
            if mapping is not None:
                candidates.append({"table": table, "record_id": mapping[0], "event_time": timestamp.isoformat() if timestamp else None,
                                   "action": action, "lineage": lineage})
        return {
            "participant_columns": ["node_id", "kind", "value", "role", "source_path", "semantics"],
            "participants": participants, "neighbor_sample": candidates, "neighbors_sampled": True,
            "limit": "Up to 20 early strong-identifier-sharing observations; not exhaustive or causal.",
        }
