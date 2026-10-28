# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
from pathlib import Path

import duckdb

from secgym.qagen.agentic.graph import build_graph
from secgym.qagen.agentic.ledger import file_sha256
from secgym.qagen.agentic.serving import ServingPolicy, export_public_view
from secgym.qagen.agentic.contracts import TaskRecord


def runtime_fixture(root: Path, extra_rows=0):
    root.mkdir(parents=True, exist_ok=True)
    ledger = root / "ledger"
    ledger.mkdir()
    db = ledger / "observations.duckdb"
    with duckdb.connect(str(db)) as con:
        con.execute("CREATE TABLE _core_source_references(observation_id VARCHAR,\"table\" VARCHAR,content_sha256 VARCHAR,origins JSON)")
        con.execute("CREATE TABLE _historical_memberships(tenant_id VARCHAR,membership JSON)")
        con.execute("CREATE TABLE _cases(incident_id INTEGER)")
        con.execute("CREATE TABLE _origins(table_name VARCHAR,observation_id VARCHAR,source_id VARCHAR)")
        con.execute("""CREATE TABLE DeviceProcessEvents(
            _observation_id VARCHAR,_source_schema_id VARCHAR,_field_quality VARCHAR,TenantId VARCHAR,
            Timestamp TIMESTAMPTZ,DeviceName VARCHAR,FileName VARCHAR,ProcessId BIGINT,
            Classification VARCHAR,AdditionalFields VARCHAR,Sequence INTEGER,Weight DOUBLE,IsActive BOOLEAN,BigCount BIGINT,Note VARCHAR,
            identity_claim_http_schemas_microsoft_com_claims_authnmethodsreferences_s VARCHAR)""")
        con.executemany("INSERT INTO DeviceProcessEvents VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", [
            ("obs:1", "schema:fixture", "[]", "tenant", "2024-01-01T12:00:00Z", "host.test", "Tool.EXE", 42,
             "private-verdict", '{"Visible":9007199254740993,"LastVerdict":"private-verdict","Nested":"{\\"Count\\":1.00000000000000000001,\\"Verdict\\":\\"private-verdict\\"}"}',
             -2147483648, 0.1, True, 9007199254740993, "space \u00e9 ", "method-one"),
            ("obs:2", "schema:fixture", "[]", "tenant", "2024-01-01T12:01:00Z", "other.test", "Other.EXE", 43,
             "private-verdict", '{"Visible":null,"LastVerdict":"private-verdict","Nested":"{\\"Count\\":2}"}',
             2, None, False, -9223372036854775808, "", "method-two"),
            ("obs:3", "schema:fixture", '[{"column_name":"AdditionalFields","raw_hash":"bad"}]', "tenant",
             "2024-01-01T12:02:00Z", "quarantined.test", "Untrusted.EXE", 44, "private-verdict",
             "malformed", 3, None, None, 0, None, None),
        ])
        con.execute("INSERT INTO _origins VALUES ('DeviceProcessEvents','obs:1','source:fixture'),('DeviceProcessEvents','obs:2','source:fixture')")
        con.execute("ALTER TABLE DeviceProcessEvents ADD COLUMN ScriptContent VARCHAR")
        con.execute("UPDATE DeviceProcessEvents SET ScriptContent=? WHERE _observation_id='obs:1'",
                    ["#!/bin/bash\n# Preserve quoted payload, not SQL\nprintf '%s' \"x'\\\"; -- /* */\"\nDELIMITER $$\nSELECT 'not executable';\n"])
        if extra_rows:
            con.execute("""
                INSERT INTO DeviceProcessEvents SELECT 'obs:bulk:'||i,_source_schema_id,_field_quality,TenantId,
                Timestamp,'bulk.test',FileName,ProcessId,Classification,AdditionalFields,CAST(i AS INTEGER),
                Weight,IsActive,BigCount,Note,identity_claim_http_schemas_microsoft_com_claims_authnmethodsreferences_s,ScriptContent
                FROM DeviceProcessEvents CROSS JOIN range(?) AS numbers(i)
                WHERE _observation_id='obs:2'
            """, [extra_rows])
    ledger_report = {
        "status": "complete", "ledger_id": "ledger:fixture", "source_snapshot_id": "snapshot:fixture",
        "tables": [{"table": "DeviceProcessEvents", "observations": 3 + extra_rows}], "summary": {"observations": 3 + extra_rows},
        "database": {"path": db.name, "sha256": file_sha256(db), "size_bytes": db.stat().st_size},
    }
    (ledger / "ledger_report.json").write_text(json.dumps(ledger_report))
    graph = root / "graph"
    build_graph(ledger, graph)
    columns = []
    for name in ("TenantId", "Timestamp", "DeviceName", "FileName", "ProcessId", "Classification", "AdditionalFields",
                 "Sequence", "Weight", "IsActive", "BigCount", "Note",
                 "identity_claim_http_schemas_microsoft_com_claims_authnmethodsreferences_s", "ScriptContent"):
        item = {"name": name, "action": "keep", "reason": "Synthetic reviewed activity field."}
        if name == "Classification":
            item.update(action="drop", reason="Private verdict must not enter the serving view.")
        if name == "AdditionalFields":
            item.update(action="json", json_paths=[["Visible"], ["Nested", "Count"]])
        columns.append(item)
    policy = ServingPolicy.model_validate_json(json.dumps({
        "policy_version": "fixture-projection", "review_ref": "fixture:review",
        "source_snapshot_id": ledger_report["source_snapshot_id"],
        "source_ledger_sha256": ledger_report["database"]["sha256"],
        "tables": [{"table": "DeviceProcessEvents", "columns": columns}],
    }))
    serving = root / "serving"
    report = export_public_view(graph, policy, serving)
    return graph, policy, serving, report


def runtime_task(serving: Path, report: dict) -> TaskRecord:
    data = json.loads((Path(__file__).parent / "fixtures/agentic_task.json").read_text())
    with duckdb.connect(str(serving / "private_mapping.duckdb"), read_only=True) as con:
        record_id, digest = con.execute("SELECT record_id,private_sha256 FROM record_map WHERE observation_id='obs:1'").fetchone()
    data.update(snapshot_id=report["snapshot_id"], serving_view_id=report["serving_view_id"],
                graph_version=report["graph_id"], scope={
                    "mode": "tenant", "incident_id": None, "anchor_evidence_ids": ["private-evidence"],
                    "relevance_rationale": "Synthetic event with a public host anchor.",
                    "answer_window": {"start": "2024-01-01T12:00:00Z", "end": "2024-01-01T12:02:00Z"},
                },
                context="Synthetic offline fixture. Investigate the recorded event on host.test.",
                question="Which executable was recorded on host.test? Cite the supporting record.")
    data["evidence"][0].update(snapshot_id=report["snapshot_id"], source_id="source:fixture",
                               private_locator="obs:1", content_sha256=digest, public_record_id=record_id)
    final = data["private_gold"]["final"]
    final["expected"]["value"] = "Tool.EXE"
    checkpoint = data["private_gold"]["checkpoints"][0]
    checkpoint["objective"] = "Identify the process identifier on the source event."
    checkpoint["claim"]["expected"] = {
        "format": {"kind": "number", "semantic_kind": "process_id", "units": "pid"}, "value": 42,
    }
    for label, claim, column in (("final", final, "FileName"), ("checkpoint", checkpoint["claim"], "ProcessId")):
        claim["programs"] = [
            {"program_id": f"{label}-{engine}", "engine": engine,
             "query": f"SELECT {column} FROM DeviceProcessEvents WHERE DeviceName='host.test'"}
            for engine in ("duckdb", "mysql")
        ]
        claim["witness_programs"] = [
            {"program_id": f"{label}-witness-{engine}", "engine": engine,
             "query": "SELECT _record_id AS evidence_group,'DeviceProcessEvents' AS table_name,_record_id AS record_id FROM DeviceProcessEvents WHERE DeviceName='host.test'"}
            for engine in ("duckdb", "mysql")
        ]
    return TaskRecord.model_validate_json(json.dumps(data))
