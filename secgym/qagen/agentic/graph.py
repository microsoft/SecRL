# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Clean observation-centered graph build with executable source provenance."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import duckdb

from .graph_entities import (
    command_references, effective_kind, graph_api_targets, normalize_entity, walk_alert_entities,
    url_hostname,
)
from .graph_rules import CLOUD_DETECTOR_ACTIONS, ENDPOINT, FIELD_RULES, JSON_RULES, LINEAGE_TABLES
from .ledger import attach_readonly, file_sha256
from .sources import TIME_COLUMNS, digest, quote_identifier


GRAPH_POLICY_VERSION = "evidence-graph-v1.4"
SOURCE_ONLY_TABLES = {
    "Watchlist": "Watchlist rows remain queryable; no universal search-key identity is assumed.",
    "HuntingBookmark": "Bookmark query/results are retained as source data, not independent event proof.",
}


def sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def load_ledger(bundle: Path) -> tuple[Path, dict]:
    report = json.loads((bundle / "ledger_report.json").read_text())
    if report.get("status") != "complete":
        raise ValueError("graph build requires a completed, unblocked observation ledger")
    name = report["database"]["path"]
    if Path(name).name != name or (bundle / name).is_symlink():
        raise ValueError("invalid ledger database path")
    database = (bundle / name).resolve()
    if database.stat().st_size != report["database"]["size_bytes"] or file_sha256(database) != report["database"]["sha256"]:
        raise ValueError("ledger database checksum mismatch")
    return database, report


def initialize_graph(con: duckdb.DuckDBPyConnection) -> None:
    con.create_function("g_normalize", normalize_entity, ["VARCHAR", "VARCHAR"], "VARCHAR", null_handling="special")
    con.create_function("g_effective_kind", effective_kind, ["VARCHAR", "VARCHAR"], "VARCHAR")
    con.create_function("g_command_refs", command_references, ["VARCHAR"], "VARCHAR", null_handling="special")
    con.create_function("g_graph_targets", graph_api_targets, ["VARCHAR"], "VARCHAR", null_handling="special")
    con.create_function("g_url_host", url_hostname, ["VARCHAR"], "VARCHAR", null_handling="special")
    con.execute("""
        CREATE MACRO g_key(kind,tenant,value) AS
        'entity:'||sha256(to_json(struct_pack(kind:=kind,tenant:=tenant,value:=value))::VARCHAR)
    """)
    con.execute("""
        CREATE TABLE observations(
            observation_id VARCHAR,table_name VARCHAR,tenant_id VARCHAR,event_time TIMESTAMPTZ,
            action VARCHAR,lineage VARCHAR,quarantined BOOLEAN
        )
    """)
    con.execute("""
        CREATE TABLE edges(
            src VARCHAR,dst VARCHAR,relation VARCHAR,observation_id VARCHAR,supporting_observation_id VARCHAR,
            rule_id VARCHAR,source_path VARCHAR,semantics VARCHAR
        )
    """)
    con.execute("CREATE TABLE node_mentions(node_id VARCHAR,kind VARCHAR,tenant_id VARCHAR,value VARCHAR)")
    con.execute("""
        CREATE TABLE rule_runs(
            rule_id VARCHAR,table_name VARCHAR,source_fields VARCHAR,emitted BIGINT,rejected_values BIGINT,
            quarantined_rows BIGINT,semantics VARCHAR
        )
    """)
    con.execute("CREATE TABLE exclusions(observation_id VARCHAR,rule_id VARCHAR,source_path VARCHAR,reason VARCHAR,value VARCHAR)")
    con.execute("CREATE TABLE historical_evidence AS SELECT * FROM ledger._core_source_references WHERE \"table\"='SecurityIncident'")


def prepare_table(con: duckdb.DuckDBPyConnection, table: str) -> set[str]:
    columns = {r[0] for r in con.execute(f"DESCRIBE ledger.{quote_identifier(table)}").fetchall()}
    if "TenantId" not in columns:
        raise ValueError(f"source table lacks a tenant namespace: {table}")
    time_column = next((name for name in TIME_COLUMNS if name in columns), None)
    # Alert StartTime describes activity; TimeGenerated can be a re-ingestion time.
    if table == "SecurityAlert" and "StartTime" in columns:
        time_column = "StartTime"
    action_column = next((name for name in ("ActionType", "OperationName", "AlertName", "Title") if name in columns), None)
    event_time = quote_identifier(time_column) if time_column else "NULL::TIMESTAMPTZ"
    action = f"CAST({quote_identifier(action_column)} AS VARCHAR)" if action_column else "NULL::VARCHAR"
    default = LINEAGE_TABLES.get(table, "behavior")
    lineage = sql_literal(default)
    if table == "DeviceEvents":
        lineage = (
            "CASE WHEN ActionType='OtherAlertRelatedActivity' THEN 'detector_derived' "
            "WHEN regexp_matches(ActionType,'^(Asr|Antivirus|ExploitGuard|Firewall|ControlledFolder)') "
            "THEN 'security_control' ELSE 'behavior' END"
        )
    elif table == "CloudAppEvents" and "ActionType" in columns:
        detector_actions = ",".join(sql_literal(action) for action in CLOUD_DETECTOR_ACTIONS)
        lineage = (
            f"CASE WHEN ActionType IN ({detector_actions}) THEN 'detector_derived' "
            "WHEN ActionType='AirInvestigationData' THEN 'metadata' ELSE 'behavior' END"
        )
    con.execute(
        "CREATE OR REPLACE TEMP VIEW source AS SELECT *,lower(TenantId) AS _tenant,"
        f"{event_time} AS _event_time,{action} AS _action,{lineage} AS _lineage "
        f"FROM ledger.{quote_identifier(table)}"
    )
    if con.execute("SELECT count(*) FROM source WHERE _tenant IS NULL OR trim(_tenant)=''").fetchone()[0]:
        raise ValueError(f"empty tenant namespace in {table}")
    con.execute(
        "INSERT INTO observations SELECT _observation_id,?,_tenant,_event_time,_action,_lineage,"
        "_field_quality<>'[]' FROM source", [table],
    )
    return columns


def emit(
    con: duckdb.DuckDBPyConnection, *, table: str, rule_id: str, fields: str,
    query: str, semantics: str = "observed_participation",
) -> int:
    """A candidate supplies observation/tenant/kind/value/role/path; source rows are prevalidated."""
    con.execute("CREATE OR REPLACE TEMP TABLE candidates AS " + query)
    con.execute("""
        CREATE OR REPLACE TEMP TABLE normalized AS
        SELECT *,g_normalize(kind,CAST(value AS VARCHAR)) AS normalized_value FROM candidates
        WHERE value IS NOT NULL AND CAST(value AS VARCHAR)<>''
    """)
    con.execute("""
        INSERT INTO exclusions SELECT observation_id,?,path,'invalid_or_placeholder_identity',CAST(value AS VARCHAR)
        FROM normalized WHERE normalized_value IS NULL
    """, [rule_id])
    rejected = con.execute("SELECT count(*) FROM normalized WHERE normalized_value IS NULL").fetchone()[0]
    con.execute("""
        CREATE OR REPLACE TEMP TABLE emitted AS SELECT DISTINCT observation_id,tenant,
          g_effective_kind(kind,normalized_value) AS entity_kind,normalized_value,role,path
        FROM normalized WHERE normalized_value IS NOT NULL
    """)
    con.execute("""
        INSERT INTO emitted SELECT DISTINCT observation_id,tenant,'domain',g_url_host(normalized_value),
          'url_host_reference',path||'/hostname' FROM emitted
        WHERE entity_kind='url' AND g_url_host(normalized_value) IS NOT NULL
    """)
    count = con.execute("SELECT count(*) FROM emitted").fetchone()[0]
    con.execute("""
        INSERT INTO node_mentions SELECT DISTINCT g_key(entity_kind,tenant,normalized_value),
          entity_kind,tenant,normalized_value FROM emitted
    """)
    con.execute("""
        INSERT INTO edges SELECT observation_id,g_key(entity_kind,tenant,normalized_value),role,
          observation_id,NULL,?,path,
          CASE WHEN entity_kind IN ('account_name_reference','application_name_reference') THEN 'contextual_reference'
               WHEN ends_with(entity_kind,'_reference') OR role='url_host_reference' THEN 'lexical_reference'
               ELSE ? END FROM emitted
    """, [rule_id, semantics])
    quarantined = con.execute("SELECT count(*) FROM source WHERE _field_quality<>'[]'").fetchone()[0]
    con.execute("INSERT INTO rule_runs VALUES (?,?,?,?,?,?,?)",
                [rule_id, table, fields, count, rejected, quarantined, semantics])
    return count


def scalar_rules(con: duckdb.DuckDBPyConnection, table: str, columns: set[str]) -> int:
    count = 0
    rules = [r for r in FIELD_RULES if table in r.tables and r.column in columns]
    for rule in rules:
        count += emit(
            con, table=table, rule_id=f"field:{table}:{rule.column}:{rule.role}", fields=rule.column,
            query=f"""
                SELECT _observation_id AS observation_id,_tenant AS tenant,{sql_literal(rule.kind)} AS kind,
                  CAST({quote_identifier(rule.column)} AS VARCHAR) AS value,
                  {sql_literal(rule.role)} AS role,{sql_literal(rule.column)} AS path
                FROM source WHERE _field_quality='[]'
            """,
            semantics="contextual" if LINEAGE_TABLES.get(table) in ("context", "metadata") else "observed_participation",
        )
    if table == "ThreatIntelligenceIndicator" and {"FileHashType", "FileHashValue"} <= columns:
        count += emit(
            con, table=table, rule_id="threat_intel:file_hash", fields="FileHashType,FileHashValue",
            semantics="contextual",
            query="""SELECT _observation_id AS observation_id,_tenant AS tenant,
              lower(FileHashType) AS kind,FileHashValue AS value,'indicator_content' AS role,
              'FileHashType+FileHashValue' AS path FROM source
              WHERE _field_quality='[]' AND lower(FileHashType) IN ('sha256','sha1','md5')""",
        )
    return count


def json_rules(con: duckdb.DuckDBPyConnection, table: str, columns: set[str]) -> int:
    count = 0
    for rule in JSON_RULES:
        if rule.table != table or rule.column not in columns:
            continue
        col = "x." + quote_identifier(rule.column)
        if rule.array:
            value = f"json_extract_string(j.value,{sql_literal(rule.path)})"
            clause = f"source x,json_each({col}) j"
            path = f"{sql_literal(rule.column)}||'['||j.key||']'||{sql_literal(rule.path.removeprefix('$'))}"
        else:
            value = f"json_extract_string({col},{sql_literal(rule.path)})"
            clause = "source x"
            path = sql_literal(rule.column + rule.path.removeprefix("$"))
        # Invalid structured fields fail the build, not silently disappearing into a default.
        bad = con.execute(
            f"SELECT count(*) FROM source x WHERE _field_quality='[]' AND {col} IS NOT NULL AND NOT json_valid({col})"
        ).fetchone()[0]
        if bad:
            raise ValueError(f"unquarantined malformed JSON in {table}.{rule.column}")
        count += emit(con, table=table, rule_id=f"json:{table}:{rule.column}:{rule.path}", fields=rule.column,
                      query=f"""SELECT x._observation_id AS observation_id,x._tenant AS tenant,
                        {sql_literal(rule.kind)} AS kind,{value} AS value,{sql_literal(rule.role)} AS role,{path} AS path
                        FROM {clause} WHERE x._field_quality='[]'""")
    if table == "CloudAppEvents" and "ActivityObjects" in columns:
        count += emit(con, table=table, rule_id="cloud:all_activity_objects", fields="ActivityObjects,ApplicationId",
                      query="""SELECT x._observation_id AS observation_id,x._tenant AS tenant,
                        CASE WHEN json_extract_string(j.value,'$.Type')='Resource' AND starts_with(json_extract_string(j.value,'$.Id'),'/')
                          THEN 'azure_resource' ELSE 'cloud_object' END AS kind,
                        CASE WHEN json_extract_string(j.value,'$.Type')='Resource' AND starts_with(json_extract_string(j.value,'$.Id'),'/')
                          THEN json_extract_string(j.value,'$.Id')
                          WHEN nullif(json_extract_string(j.value,'$.Id'),'') IS NOT NULL
                          THEN to_json(struct_pack(application:=ApplicationId,type:=json_extract_string(j.value,'$.Type'),
                            id:=json_extract_string(j.value,'$.Id')))::VARCHAR END AS value,
                        'cloud_participant:'||coalesce(json_extract_string(j.value,'$.Role'),'unspecified') AS role,
                        'ActivityObjects['||j.key||'].Id' AS path
                        FROM source x,json_each(x.ActivityObjects) j WHERE x._field_quality='[]'""")
        if "AppInstanceId" in columns:
            count += emit(con, table=table, rule_id="cloud:application_instance", fields="ApplicationId,AppInstanceId",
                          query="""SELECT _observation_id AS observation_id,_tenant AS tenant,'cloud_application_instance' AS kind,
                            CASE WHEN ApplicationId IS NOT NULL AND AppInstanceId IS NOT NULL
                            THEN to_json(struct_pack(app:=ApplicationId,instance:=AppInstanceId))::VARCHAR END AS value,
                            'cloud_application_instance' AS role,'ApplicationId+AppInstanceId' AS path
                            FROM source WHERE _field_quality='[]'""")
    if table == "IntuneAuditLogs" and "Properties" in columns:
        count += emit(con, table=table, rule_id="intune:all_targets", fields="Properties.TargetObjectIds",
                      query="""SELECT x._observation_id AS observation_id,x._tenant AS tenant,'intune_object' AS kind,
                        json_extract_string(j.value,'$') AS value,'intune_target' AS role,
                        'Properties.TargetObjectIds['||j.key||']' AS path
                        FROM source x,json_each(json_extract(x.Properties,'$.TargetObjectIds')) j
                        WHERE x._field_quality='[]'""")
    if table == "MicrosoftGraphActivityLogs" and "RequestUri" in columns:
        count += emit(con, table=table, rule_id="graph_api:resource_targets", fields="RequestUri",
                      query="""SELECT x._observation_id AS observation_id,x._tenant AS tenant,'directory_object' AS kind,
                        json_extract_string(j.value,'$.id') AS value,
                        'request_target:'||json_extract_string(j.value,'$.collection') AS role,
                        'RequestUri/path/'||json_extract_string(j.value,'$.segment') AS path
                        FROM source x,json_each(g_graph_targets(x.RequestUri)) j WHERE x._field_quality='[]'""")
    return count


def process_rules(con: duckdb.DuckDBPyConnection, table: str, columns: set[str]) -> int:
    count = 0
    if table not in ENDPOINT:
        return count
    for prefix, role in (("", "subject_process"), ("Initiating", "initiating_process")):
        pid, created = prefix + "ProcessId", prefix + "ProcessCreationTime"
        if not {pid, created, "DeviceName"} <= columns:
            continue
        con.execute(
            f"""INSERT INTO exclusions SELECT _observation_id,?,?,
              'missing_invalid_or_future_process_identity',NULL FROM source
              WHERE _field_quality='[]' AND {quote_identifier(pid)} IS NOT NULL
              AND ({quote_identifier(pid)}<=0 OR {quote_identifier(created)} IS NULL
                OR nullif(DeviceName,'') IS NULL OR {quote_identifier(created)}>_event_time)""",
            [f"process:{table}:{role}", f"DeviceName+{pid}+{created}"],
        )
        # Exact source process identity only; recovered identities are not silently asserted.
        expression = (
            f"CASE WHEN {quote_identifier(pid)}>0 AND {quote_identifier(created)} IS NOT NULL "
            f"AND nullif(DeviceName,'') IS NOT NULL AND ({quote_identifier(created)}<=_event_time OR _event_time IS NULL) "
            f"THEN to_json(struct_pack(host:=lower(DeviceName),pid:={quote_identifier(pid)},"
            f"created:={quote_identifier(created)}))::VARCHAR END"
        )
        count += emit(con, table=table, rule_id=f"process:{table}:{role}", fields=f"DeviceName,{pid},{created}",
                      query=f"""SELECT _observation_id AS observation_id,_tenant AS tenant,'process' AS kind,
                       {expression} AS value,{sql_literal(role)} AS role,{sql_literal(pid+'+'+created)} AS path
                       FROM source WHERE _field_quality='[]'""")
    for command in ("ProcessCommandLine", "InitiatingProcessCommandLine"):
        if command not in columns:
            continue
        count += emit(con, table=table, rule_id=f"command:{table}:{command}", fields=command,
                      semantics="lexical_reference",
                      query=f"""SELECT x._observation_id AS observation_id,x._tenant AS tenant,
                        json_extract_string(j.value,'$.kind') AS kind,json_extract_string(j.value,'$.value') AS value,
                        'command_reference' AS role,{sql_literal(command)}||'@'||json_extract_string(j.value,'$.offset') AS path
                        FROM source x,json_each(g_command_refs(x.{quote_identifier(command)})) j WHERE x._field_quality='[]'""")
    if {"DeviceName", "FileName", "FolderPath"} <= columns:
        count += emit(con, table=table, rule_id=f"file_path:{table}", fields="DeviceName,FileName,FolderPath",
                      query="""SELECT _observation_id AS observation_id,_tenant AS tenant,'host_file_path' AS kind,
                       CASE WHEN nullif(DeviceName,'') IS NOT NULL AND nullif(FileName,'') IS NOT NULL
                       THEN to_json(struct_pack(host:=lower(DeviceName),folder:=FolderPath,name:=FileName))::VARCHAR END AS value,
                       'subject_file_path' AS role,'DeviceName+FolderPath+FileName' AS path
                       FROM source WHERE _field_quality='[]'""")
    if "RegistryKey" in columns:
        count += emit(con, table=table, rule_id=f"registry:{table}", fields="DeviceName,RegistryKey",
                      query="""SELECT _observation_id AS observation_id,_tenant AS tenant,'host_registry' AS kind,
                       CASE WHEN nullif(DeviceName,'') IS NOT NULL AND nullif(RegistryKey,'') IS NOT NULL
                       THEN to_json(struct_pack(host:=lower(DeviceName),key:=RegistryKey))::VARCHAR END AS value,
                       'registry_key' AS role,'DeviceName+RegistryKey' AS path
                       FROM source WHERE _field_quality='[]'""")
    return count


def alert_entities(con: duckdb.DuckDBPyConnection, table: str, columns: set[str]) -> int:
    if table not in ("SecurityAlert", "Anomalies", "HuntingBookmark") or "Entities" not in columns:
        return 0
    role = "bookmark_entity" if table == "HuntingBookmark" else "alert_entity"
    con.execute("CREATE OR REPLACE TEMP TABLE alert_mentions(observation_id VARCHAR,tenant VARCHAR,kind VARCHAR,value VARCHAR,role VARCHAR,path VARCHAR)")
    cursor = con.execute("SELECT _observation_id,_tenant,Entities FROM source WHERE _field_quality='[]'")
    rows = cursor.fetchall()
    mentions = []
    issues = []
    for oid, tenant, text in rows:
        found, omitted = walk_alert_entities(text)
        mentions.extend((oid, tenant, kind, value, role, "Entities" + path.removeprefix("$"))
                        for kind, value, path in found)
        issues.extend((oid, "alert:entities", path, reason, None) for path, reason in omitted)
    if mentions:
        con.executemany("INSERT INTO alert_mentions VALUES (?,?,?,?,?,?)", mentions)
    if issues:
        con.executemany("INSERT INTO exclusions VALUES (?,?,?,?,?)", issues)
    return emit(con, table=table, rule_id=f"alert_entities:{table}", fields="Entities", query="SELECT * FROM alert_mentions",
                semantics="contextual" if table == "HuntingBookmark" else "reported_entity")


def identity_labels(con: duckdb.DuckDBPyConnection, table: str, columns: set[str]) -> int:
    """Scoped account labels are not automatically strong identity resolution."""
    count = 0
    for prefix in ("", "InitiatingProcess"):
        name, domain = prefix + "AccountName", prefix + "AccountDomain"
        if not {name, domain} <= columns:
            continue
        count += emit(con, table=table, rule_id=f"account_label:{table}:{prefix or 'subject'}",
                      fields=f"{name},{domain}", semantics="contextual",
                      query=f"""SELECT _observation_id AS observation_id,_tenant AS tenant,'account_label' AS kind,
                       CASE WHEN nullif({quote_identifier(domain)},'') IS NOT NULL AND nullif({quote_identifier(name)},'') IS NOT NULL
                       THEN lower({quote_identifier(domain)})||'\\\\'||lower({quote_identifier(name)}) END AS value,
                       {sql_literal(prefix+'account_label')} AS role,{sql_literal(domain+'+'+name)} AS path
                       FROM source WHERE _field_quality='[]'""")
    return count


def incident_and_alert_links(con: duckdb.DuckDBPyConnection, table: str) -> int:
    count = 0
    if table == "SecurityIncident":
        count += emit(con, table=table, rule_id="incident:identity", fields="IncidentNumber",
                      query="""SELECT _observation_id AS observation_id,_tenant AS tenant,'incident' AS kind,
                       CAST(IncidentNumber AS VARCHAR) AS value,'incident_record' AS role,'IncidentNumber' AS path FROM source""")
        count += emit(con, table=table, rule_id="incident:current_members", fields="AlertIds",
                      query="""SELECT x._observation_id AS observation_id,x._tenant AS tenant,'alert' AS kind,
                       json_extract_string(j.value,'$') AS value,'current_member' AS role,'AlertIds['||j.key||']' AS path
                       FROM source x,json_each(x.AlertIds) j WHERE x._field_quality='[]'""",
                      semantics="current_membership")
    if table == "SecurityAlert":
        count += emit(con, table=table, rule_id="alert:identity", fields="SystemAlertId",
                      query="""SELECT _observation_id AS observation_id,_tenant AS tenant,'alert' AS kind,
                       SystemAlertId AS value,'alert_record' AS role,'SystemAlertId' AS path FROM source""")
        if "VendorOriginalId" in {r[0] for r in con.execute("DESCRIBE source").fetchall()}:
            count += emit(con, table=table, rule_id="alert:provider_id", fields="VendorOriginalId",
                          query="""SELECT _observation_id AS observation_id,_tenant AS tenant,'provider_alert' AS kind,
                           VendorOriginalId AS value,'provider_alert_id' AS role,'VendorOriginalId' AS path
                           FROM source WHERE _field_quality='[]'""", semantics="reported_alias")
    return count


def historical_links(con: duckdb.DuckDBPyConnection) -> int:
    con.execute("""
        CREATE TEMP TABLE removed AS SELECT tenant_id,
          json_extract_string(membership,'$.incident_id') AS incident,
          lower(json_extract_string(membership,'$.alert_id')) AS alert,
          json_extract_string(membership,'$.before_evidence_id') AS before_id,
          json_extract_string(membership,'$.after_evidence_id') AS after_id
        FROM ledger._historical_memberships
    """)
    invalid = con.execute("""
        SELECT count(*) FROM removed r WHERE before_id IS NULL OR after_id IS NULL
        OR NOT EXISTS(SELECT 1 FROM historical_evidence h WHERE h.observation_id=r.before_id)
        OR NOT EXISTS(SELECT 1 FROM historical_evidence h WHERE h.observation_id=r.after_id)
    """).fetchone()[0]
    if invalid:
        raise ValueError("historical membership evidence is unresolved")
    for kind, field in (("incident", "incident"), ("alert", "alert")):
        con.execute(f"INSERT INTO node_mentions SELECT DISTINCT g_key(?,tenant_id,{field}),?,tenant_id,{field} FROM removed", [kind, kind])
    con.execute("""
        INSERT INTO edges SELECT g_key('incident',tenant_id,incident),g_key('alert',tenant_id,alert),
          'historical_removed_member',before_id,after_id,'incident:historical_members',
          'AlertIds','historical_membership' FROM removed
    """)
    return con.execute("SELECT count(*) FROM removed").fetchone()[0]


def build_graph(ledger_bundle: Path, output: Path) -> dict[str, object]:
    ledger_bundle, output = ledger_bundle.resolve(), output.resolve()
    database, ledger_report = load_ledger(ledger_bundle)
    if output.exists() or output.is_relative_to(ledger_bundle) or ledger_bundle.is_relative_to(output):
        raise ValueError("graph output must be a new directory outside the ledger bundle")
    implementation = {name: file_sha256(Path(__file__).with_name(name))
                      for name in ("graph.py", "graph_rules.py", "graph_entities.py")}
    input_stat = (database.stat().st_size, database.stat().st_mtime_ns)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir()
    result_db = output / "graph.duckdb"
    tables = []
    with tempfile.TemporaryDirectory(prefix="spill-", dir=output) as spill:
        with duckdb.connect(str(result_db), config={"threads": 1, "memory_limit": "1GB"}) as con:
            con.execute("SET TimeZone='UTC'")
            con.execute("SET temp_directory=?", [spill])
            con.execute("SET max_temp_directory_size='32GB'")
            attach_readonly(con, database, "ledger")
            initialize_graph(con)
            for record in ledger_report["tables"]:
                table = record["table"]
                columns = prepare_table(con, table)
                count = scalar_rules(con, table, columns)
                count += json_rules(con, table, columns)
                count += process_rules(con, table, columns)
                count += identity_labels(con, table, columns)
                count += alert_entities(con, table, columns)
                count += incident_and_alert_links(con, table)
                tables.append({
                    "table": table, "observations": record["observations"], "participant_edges": count,
                    "status": "extracted" if count else "source_only",
                    "source_only_reason": None if count else SOURCE_ONLY_TABLES.get(table, "No supported participant field populated."),
                })
                print(f"[graph] {table}: {record['observations']} observations / {count} participant edges", flush=True)
                con.execute("CHECKPOINT")
            removed = historical_links(con)
            con.execute("CREATE TABLE nodes AS SELECT DISTINCT * FROM node_mentions")
            con.execute("DROP TABLE node_mentions")
            node_conflicts = con.execute("SELECT count(*) FROM(SELECT node_id FROM nodes GROUP BY 1 HAVING count(*)>1)").fetchone()[0]
            if node_conflicts:
                raise ValueError("entity-key collision")
            edge_count = con.execute("SELECT count(*) FROM edges").fetchone()[0]
            unresolved = con.execute("""
                SELECT count(*) FROM edges e WHERE NOT EXISTS(SELECT 1 FROM nodes n WHERE n.node_id=e.dst)
                  OR (NOT EXISTS(SELECT 1 FROM observations o WHERE o.observation_id=e.observation_id)
                  AND NOT EXISTS(SELECT 1 FROM historical_evidence h WHERE h.observation_id=e.observation_id))
            """).fetchone()[0]
            if unresolved:
                raise ValueError("graph relationship has an unresolved source or endpoint")
            counts = {
                "observations": con.execute("SELECT count(*) FROM observations").fetchone()[0],
                "entity_nodes": con.execute("SELECT count(*) FROM nodes").fetchone()[0],
                "edges": edge_count, "historical_removed_links": removed,
                "rejected_identity_mentions": con.execute("SELECT count(*) FROM exclusions").fetchone()[0],
                "rule_runs": con.execute("SELECT count(*) FROM rule_runs").fetchone()[0],
            }
            if counts["observations"] != ledger_report["summary"]["observations"]:
                raise ValueError("graph observation inventory differs from the ledger")
            con.execute("CREATE TABLE case_manifests AS SELECT * FROM ledger._cases")
            con.execute("DETACH ledger")
            con.execute("CHECKPOINT")
    if input_stat != (database.stat().st_size, database.stat().st_mtime_ns):
        raise ValueError("ledger changed during graph build")
    for name, sha in implementation.items():
        if file_sha256(Path(__file__).with_name(name)) != sha:
            raise ValueError("graph implementation changed during build")
    report = {
        "schema_version": "1", "status": "complete", "visibility": "private_build",
        "graph_policy_version": GRAPH_POLICY_VERSION,
        "graph_id": "graph:" + digest([ledger_report["ledger_id"], GRAPH_POLICY_VERSION, implementation]),
        "ledger_id": ledger_report["ledger_id"], "ledger_database_sha256": ledger_report["database"]["sha256"],
        "ledger_bundle": str(ledger_bundle), "implementation_sha256": implementation,
        "summary": counts, "tables": tables, "inputs_unchanged": True,
        "database": {"path": result_db.name, "sha256": file_sha256(result_db), "size_bytes": result_db.stat().st_size},
        "limitations": [
            "Observation-centered participant links are not causal attack edges or benign/malicious verdicts.",
            "Shared observation nodes let investigators traverse actors, targets and context without all-pairs causal expansion.",
            "Quarantined observations remain inventoried but participant extraction is conservatively disabled.",
            "Exact process host/PID/start identities only; absent/conflicting timestamps are not recovered through nearest-event guessing.",
            "Different full hostnames, local labels, app IDs, directory objects and display names are not blindly merged.",
            "Kubernetes/container/blob names and MAC addresses are references, not runtime-incarnation or physical-device identities.",
            "IoT device IDs retain their explicit hub/resource scope; no equivalence with MDE or Entra device IDs is inferred.",
            "Sentinel reported resource metadata and bookmark entities are context, not independent proof of the referenced behavior.",
            "Unverified JSON fields and unsupported table relationships remain in the ledger; source-only dispositions do not assert absence of behavior.",
            "Graph comparison and coverage of alternative evidence paths must be evaluated separately; edge-count parity is not claimed.",
        ],
    }
    (output / "graph_report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report
