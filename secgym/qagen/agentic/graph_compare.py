# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Read-only graph coverage comparison; coverage is not semantic equivalence."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

import duckdb

from .graph_entities import effective_kind, normalize_entity
from .ledger import attach_readonly, file_sha256


LEGACY_FIELD_KINDS = {
    ("host", "HostName"): "host", ("host", "AadDeviceId"): "directory_object",
    ("ip", "Address"): "ip", ("account", "Sid"): "sid", ("account", "AadUserId"): "directory_object",
    ("account", "Email"): "upn", ("url", "Url"): "address", ("file", "Name"): "file_reference",
    ("account", "Name"): "account_name_reference",
    ("process", "ExtractedFileName"): "file_reference", ("mailbox", "MailboxPrimaryAddress"): "upn",
    ("mailmessage", "Recipient"): "upn", ("mailmessage", "Sender"): "upn", ("mailmessage", "SenderIP"): "ip",
    ("cloud-application", "AppId"): "cloud_application_id", ("azure-resource", "ResourceId"): "azure_resource",
    ("oauth-application", "OAuthAppId"): "application_id", ("oauth-application", "OAuthObjectId"): "directory_object",
}


def old_graph_nodes(path: Path) -> tuple[dict[str, dict[str, str]], list[tuple[str, str]]]:
    ns = {"g": "http://graphml.graphdrawing.org/xmlns"}
    root = ET.parse(path).getroot()
    keys = {key.attrib["id"]: key.attrib.get("attr.name", "") for key in root.findall("g:key", ns)}
    nodes = {
        node.attrib["id"]: {keys[d.attrib["key"]]: d.text or "" for d in node.findall("g:data", ns)}
        for node in root.findall(".//g:node", ns)
    }
    edges = [(e.attrib["source"], e.attrib["target"]) for e in root.findall(".//g:edge", ns)]
    return nodes, edges


def compare_legacy_alert_graphs(con: duckdb.DuckDBPyConnection, paths: list[Path]) -> list[dict[str, object]]:
    con.execute("""
        CREATE OR REPLACE TEMP TABLE comparison_alert_records AS
        SELECT dst,observation_id FROM new.edges WHERE relation='alert_record'
    """)
    con.execute("""
        CREATE OR REPLACE TEMP TABLE comparison_entity_mentions AS
        SELECT dst,observation_id,relation FROM new.edges WHERE relation IN ('alert_entity','url_host_reference')
    """)
    reported = {}
    for alert, tenant, kind, value, relation in con.execute("""
        SELECT a.dst,n.tenant_id,n.kind,n.value,e.relation FROM comparison_alert_records a
        JOIN comparison_entity_mentions e USING(observation_id) JOIN new.nodes n ON n.node_id=e.dst
    """).fetchall():
        reported.setdefault((alert, tenant, kind, value), set()).add(relation)
    alert_keys = {}
    for node, tenant, value in con.execute("SELECT node_id,tenant_id,value FROM new.nodes WHERE kind='alert'").fetchall():
        alert_keys.setdefault((tenant, value), []).append(node)
    elsewhere = {}
    result = []
    for path in paths:
        nodes, edges = old_graph_nodes(path)
        alerts = {}
        for node_id, node in nodes.items():
            if node.get("type") != "alert":
                continue
            data = json.loads(node["entry"])
            aid = data["SystemAlertId"].lower()
            tenant = data["TenantId"].lower()
            matches = alert_keys.get((tenant, aid), [])
            if len(matches) == 1:
                alerts[node_id] = (matches[0], tenant)
            else:
                alerts[node_id] = None
        mapped_edges = []
        for first, second in edges:
            if first not in alerts:
                first, second = second, first
            if first not in alerts:
                mapped_edges.append({"source": first, "target": second, "status": "not_alert_entity_edge"})
                continue
            node = nodes[second]
            kind = LEGACY_FIELD_KINDS.get((node.get("node_type", ""), node.get("identifier_fields", "")))
            entry = {
                "alert_node": first, "entity_node": second, "entity_type": node.get("node_type"),
                "identifier_fields": node.get("identifier_fields"),
            }
            match = alerts[first]
            if match is None:
                status = "alert_identity_missing_or_ambiguous"
            elif kind is None:
                status = "requires_contextual_identity_mapping"
            else:
                value = normalize_entity(kind, node.get("value"))
                if value is None:
                    status = "invalid_or_unsupported_legacy_identifier"
                else:
                    kind = effective_kind(kind, value)
                    if (match[0], match[1], kind, value) in reported:
                        roles = reported[(match[0], match[1], kind, value)]
                        status = "reported_reference_preserved" if kind.endswith("_reference") or "alert_entity" not in roles else "reported_entity_preserved"
                    else:
                        key = (match[1], kind, value)
                        if key not in elsewhere:
                            elsewhere[key] = con.execute(
                                "SELECT count(*) FROM new.nodes WHERE tenant_id=? AND kind=? AND value=?", key,
                            ).fetchone()[0] > 0
                        status = "identifier_elsewhere_not_same_alert" if elsewhere[key] else "identifier_not_represented"
                        if status == "identifier_not_represented" and kind == "file_reference":
                            variants = con.execute(
                                "SELECT value FROM new.nodes WHERE tenant_id=? AND kind='file_reference' AND lower(value)=lower(?) LIMIT 3",
                                [match[1], value],
                            ).fetchall()
                            if variants:
                                status = "case_variant_requires_platform_context"
                                entry["case_variants"] = [v[0] for v in variants]
                            else:
                                paths = con.execute(
                                    r"""SELECT value FROM new.nodes WHERE tenant_id=? AND kind='file_reference'
                                      AND lower(regexp_extract(value,'[^\\/]+$',0))=lower(?) LIMIT 3""",
                                    [match[1], value],
                                ).fetchall()
                                if paths:
                                    status = "path_component_requires_context"
                                    entry["path_variants"] = [v[0] for v in paths]
            mapped_edges.append({**entry, "status": status})
        result.append({
            "file": str(path), "sha256": file_sha256(path), "legacy_nodes": len(nodes),
            "legacy_edges": len(edges), "legacy_alerts": len(alerts),
            "resolved_alerts": sum(v is not None for v in alerts.values()),
            "edge_status_counts": dict(Counter(e["status"] for e in mapped_edges)),
            "edge_checks": mapped_edges,
        })
    return result


def compare_graphs(new_bundle: Path, old_graph: Path, legacy_graphs: Path, output: Path) -> dict[str, object]:
    new_bundle, old_graph, legacy_graphs, output = (
        new_bundle.resolve(), old_graph.resolve(), legacy_graphs.resolve(), output.resolve(),
    )
    if output.exists() or output.is_relative_to(new_bundle) or output.is_relative_to(old_graph.parent) or output.is_relative_to(legacy_graphs):
        raise ValueError("comparison output must be new and outside input directories")
    new_report = json.loads((new_bundle / "graph_report.json").read_text())
    if new_report.get("status") != "complete":
        raise ValueError("cannot compare an incomplete graph")
    name = new_report["database"]["path"]
    if Path(name).name != name:
        raise ValueError("invalid graph database name")
    new_db = new_bundle / name
    if file_sha256(new_db) != new_report["database"]["sha256"]:
        raise ValueError("new graph checksum mismatch")
    ledger_bundle = Path(new_report["ledger_bundle"])
    ledger_report = json.loads((ledger_bundle / "ledger_report.json").read_text())
    ledger_name = ledger_report["database"]["path"]
    if Path(ledger_name).name != ledger_name or ledger_report["ledger_id"] != new_report["ledger_id"]:
        raise ValueError("graph/ledger identity mismatch")
    ledger_db = ledger_bundle / ledger_name
    if file_sha256(ledger_db) != new_report["ledger_database_sha256"]:
        raise ValueError("ledger checksum mismatch")
    old_sha = file_sha256(old_graph)
    legacy_paths = sorted(legacy_graphs.glob("incident_*.graphml"))
    if not legacy_paths:
        raise ValueError("no legacy incident graphs found")
    before = {p: (p.stat().st_size, p.stat().st_mtime_ns) for p in [new_db, old_graph, ledger_db, *legacy_paths]}
    with duckdb.connect(config={"threads": 1, "memory_limit": "1GB"}) as con:
        attach_readonly(con, new_db, "new")
        attach_readonly(con, old_graph, "old")
        attach_readonly(con, ledger_db, "ledger")
        counts = []
        for (table,) in con.execute("SELECT DISTINCT tbl FROM old.edges ORDER BY tbl").fetchall():
            con.execute("CREATE OR REPLACE TEMP TABLE old_refs AS SELECT DISTINCT rid FROM old.edges WHERE tbl=?", [table])
            con.execute("""
                CREATE OR REPLACE TEMP TABLE matches AS SELECT DISTINCT o.source_record AS rid,o.observation_id
                FROM ledger._origins o JOIN old_refs r ON r.rid=o.source_record
                WHERE o.table_name=? AND o.locator_kind='duckdb_rid'
            """, [table])
            con.execute("""
                CREATE OR REPLACE TEMP TABLE represented AS SELECT DISTINCT e.observation_id FROM new.edges e
                SEMI JOIN matches m ON e.observation_id=m.observation_id
            """)
            total = con.execute("SELECT count(*) FROM old_refs").fetchone()[0]
            resolved = con.execute("SELECT count(DISTINCT rid) FROM matches").fetchone()[0]
            represented = con.execute("SELECT count(DISTINCT m.rid) FROM matches m JOIN represented r USING(observation_id)").fetchone()[0]
            counts.append({
                "table": table, "old_source_rows": total, "mapped_to_active_ledger": resolved,
                "with_new_participant_edges": represented, "active_source_only_rows": resolved - represented,
                "not_in_active_ledger": total - resolved,
            })
        legacy = compare_legacy_alert_graphs(con, legacy_paths)
        relation_counts = con.execute("SELECT relation,semantics,count(*) FROM new.edges GROUP BY 1,2 ORDER BY 3 DESC").fetchall()
        old_types = con.execute("SELECT etype,count(*) FROM old.edges GROUP BY 1 ORDER BY 1").fetchall()
        source_only = [r for r in new_report["tables"] if r["status"] == "source_only"]
    for path, stat in before.items():
        if (path.stat().st_size, path.stat().st_mtime_ns) != stat:
            raise ValueError("graph input changed during comparison")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir()
    report = {
        "schema_version": "1", "status": "compared_not_certified", "graph_id": new_report["graph_id"],
        "old_graph_sha256": old_sha, "source_row_coverage": counts, "legacy_graphs": legacy,
        "new_relations": [{"relation": r, "semantics": s, "edges": n} for r, s, n in relation_counts],
        "old_relations": [{"relation": r, "edges": n} for r, n in old_types],
        "source_only_tables": source_only, "inputs_unchanged": True,
        "summary": {
            "legacy_alerts": sum(r["legacy_alerts"] for r in legacy),
            "legacy_alerts_resolved": sum(r["resolved_alerts"] for r in legacy),
            "old_distinct_source_rows": sum(r["old_source_rows"] for r in counts),
            "old_source_rows_mapped_to_active_ledger": sum(r["mapped_to_active_ledger"] for r in counts),
            "old_source_rows_with_participant_edges": sum(r["with_new_participant_edges"] for r in counts),
        },
        "limits": [
            "Observation coverage and identifier preservation are not proof of semantic equivalence between graph paths.",
            "The new graph reifies source observations; edge counts and graph depths are not comparable to old all-pair relationships.",
            "Legacy process/name/compound identifiers need contextual mapping; they are reported rather than matched by guesswork.",
            "Filename case variants are recorded separately: case-insensitive string similarity is not automatically physical file identity.",
            "Historical source versions omitted from active latest-only tables may legitimately lack active observation edges.",
            "All remaining source-only or missing identifiers require a reason or follow-up before claiming complete graph parity.",
        ],
    }
    (output / "comparison_report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report
