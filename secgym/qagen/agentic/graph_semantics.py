# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Source-backed dispositions for legacy alert/entity relationships.

These checks reproduce the meaning of legacy identifiers, including lossy
reference labels. They do not turn those labels into physical entity identity.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import duckdb

from .graph import load_ledger
from .graph_compare import LEGACY_FIELD_KINDS, old_graph_nodes
from .graph_entities import effective_kind, normalize_entity, url_hostname
from .ledger import attach_readonly, file_sha256


SEMANTIC_POLICY_VERSION = "legacy-source-semantics-v1"


@dataclass(frozen=True)
class EntityObject:
    path: str
    fields: dict


@dataclass(frozen=True)
class GraphMention:
    node_id: str
    kind: str
    value: str
    role: str
    source_path: str
    semantics: str


@dataclass(frozen=True)
class AlertContext:
    observation_id: str
    tenant_id: str
    alert_id: str
    entities: tuple[EntityObject, ...]
    mentions: tuple[GraphMention, ...]
    start_time: datetime | None = None


def entity_objects(text: str) -> tuple[EntityObject, ...]:
    roots = json.loads(text)
    if not isinstance(roots, list):
        raise ValueError("expected an entity array")
    found = []
    definitions = {}

    def visit(value: object, path: str, depth: int) -> None:
        if depth > 64:
            raise ValueError("entity structure exceeds depth limit")
        if isinstance(value, list):
            for i, item in enumerate(value):
                visit(item, f"{path}[{i}]", depth + 1)
        elif isinstance(value, dict):
            if "$id" in value:
                identifier = value["$id"]
                if not isinstance(identifier, str):
                    raise ValueError("non-string entity definition ID")
                if identifier in definitions and definitions[identifier] != value:
                    raise ValueError("conflicting entity definitions")
                definitions[identifier] = value
            if "Type" in value:
                found.append(EntityObject(path, value))
            for key, item in value.items():
                visit(item, path + "." + key, depth + 1)

    # Definitions are sufficient for identifier comparison: repeated $refs do
    # not add distinct facts. Every returned object retains its definition path.
    visit(roots, "Entities", 0)
    return tuple(found)


def timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith(("z", "Z")) else value)
    except ValueError:
        return None
    if result.tzinfo is None or result.utcoffset() is None:
        return None
    return result.astimezone(timezone.utc)


def same_source_timestamp(left: object, right: object) -> bool:
    a, b = timestamp(left), timestamp(right)
    return a is not None and b is not None and a == b


def string_fields(value: object, path: str) -> Iterator[tuple[str, str]]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from string_fields(item, path + "." + key)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from string_fields(item, f"{path}[{index}]")


def evidence(context: AlertContext, mention: GraphMention, source_path: str | None = None) -> dict:
    return {
        "observation_id": context.observation_id,
        "entity_node_id": mention.node_id,
        "source_path": source_path or mention.source_path,
        "graph_source_path": mention.source_path,
        "graph_relation": mention.role,
        "graph_semantics": mention.semantics,
        "kind": mention.kind,
        "value": mention.value,
    }


def disposition(status: str, category: str, reason: str, proof: list[dict] | None = None) -> dict:
    return {"status": status, "category": category, "reason": reason, "evidence": proof or []}


def process_check(value: str, context: AlertContext) -> dict:
    parts = value.split("__", 2)
    if len(parts) != 3 or not parts[0].isdigit():
        return disposition("invalid_legacy_process_tuple", "unresolved", "Legacy process tuple cannot be parsed without guessing.")
    pid, created, command = parts
    time = timestamp(created)
    if time is None:
        # A timestamp without timezone is not silently assigned UTC.
        return disposition("legacy_process_time_unqualified", "unresolved", "Legacy process time is invalid or timezone-free.")
    processes = [e for e in context.entities if e.fields.get("Type") == "process"
                 and str(e.fields.get("ProcessId")) == pid
                 and isinstance(e.fields.get("CommandLine"), str)
                 and e.fields["CommandLine"].lower() == command]
    matches = [e for e in processes if same_source_timestamp(e.fields.get("CreationTimeUtc"), created)]
    graph = []
    for mention in context.mentions:
        if mention.kind != "process" or mention.role != "alert_entity":
            continue
        key = json.loads(mention.value)
        if isinstance(key, list) and len(key) == 3 and str(key[1]) == pid and same_source_timestamp(key[2], created):
            graph.append(mention)
    proofs = []
    hosts = {e.fields.get("FQDN") or e.fields.get("HostName") for e in context.entities
             if e.fields.get("Type") == "host"}
    hosts.discard(None)
    normalized_hosts = {normalize_entity("host", h) for h in hosts if isinstance(h, str)}
    for entity in matches:
        for mention in graph:
            host = json.loads(mention.value)[0]
            if host not in normalized_hosts or len(normalized_hosts) != 1:
                continue
            proofs.append({
                **evidence(context, mention, entity.path),
                "checks": ["same_alert", "single_source_host", "exact_pid", "exact_creation_time", "legacy_lowercase_command_projection"],
                "source_command": entity.fields["CommandLine"],
                "source_creation_time": entity.fields["CreationTimeUtc"],
                "source_host": host,
            })
    if proofs:
        return disposition(
            "process_tuple_source_and_graph_verified", "supported_identity",
            "Source host/PID/start and command reproduce the legacy tuple; command lowercasing is only the old label projection, not a general identity rule.",
            proofs,
        )
    return disposition(
        "process_tuple_requires_source_resolution", "unresolved",
        "No unique source-and-graph process match passed every host/PID/start/command check.",
        [{"observation_id": context.observation_id, "source_path": e.path,
          "creation_time": e.fields.get("CreationTimeUtc"), "alternate_created_time": e.fields.get("CreatedTimeUtc"),
          "command_matches_legacy_projection": True} for e in processes],
    )


def synthesized_email_check(value: str, context: AlertContext) -> dict | None:
    for entity in context.entities:
        source = entity.fields
        if source.get("Type") != "account" or not source.get("Name") or not source.get("UPNSuffix"):
            continue
        fabricated = str(source["Name"]) + "@" + str(source["UPNSuffix"])
        actual = source.get("UserPrincipalName")
        if fabricated.lower() != value.lower() or not isinstance(actual, str) or actual.lower() == value.lower():
            continue
        actual = normalize_entity("upn", actual)
        for mention in context.mentions:
            if actual is not None and mention.kind == "upn" and mention.value == actual and mention.role == "alert_entity":
                return disposition(
                    "legacy_synthesized_email_corrected", "source_correction",
                    "The old name@suffix fabrication differs from the authoritative UPN on the same source account; the graph retains that UPN.",
                    [{**evidence(context, mention, entity.path + ".UserPrincipalName"),
                      "legacy_synthesized_value": value, "source_account_name": source.get("AccountName"),
                      "source_sid": source.get("Sid"), "source_object_id": source.get("AadUserId")}],
                )
    return None


def reference_check(node: dict[str, str], context: AlertContext) -> dict | None:
    entity_type, field, value = node.get("node_type"), node.get("identifier_fields"), node.get("value", "")
    if entity_type in ("file", "process") and field in ("Name", "ExtractedFileName"):
        proofs = []
        for mention in context.mentions:
            if mention.kind != "file_reference" or mention.role != "alert_entity":
                continue
            basename = re.split(r"[\\/]", mention.value)[-1]
            if value.lower() not in (mention.value.lower(), basename.lower()):
                continue
            # Verify the graph reference occurs in current source content;
            # only file names and process command lines qualify.
            for entity in context.entities:
                source = entity.fields
                if source.get("Type") == "file" and isinstance(source.get("Name"), str):
                    text, path = source["Name"], entity.path + ".Name"
                    present = text.lower() == value.lower()
                elif source.get("Type") == "process" and isinstance(source.get("CommandLine"), str):
                    text, path = source["CommandLine"], entity.path + ".CommandLine"
                    pattern = r'([^\\/\s"\']*\.(?:exe|pdf|dll|xlsx|docx|zip|png|txt|ps1|html|tmp))'
                    present = value.lower() in re.findall(pattern, text.lower())
                else:
                    continue
                if present:
                    proofs.append({
                        **evidence(context, mention, path), "source_text": text,
                        "legacy_projection": "lowercase_filename_or_command_basename",
                        "physical_file_identity_claimed": False,
                    })
        if proofs:
            return disposition(
                "lexical_file_reference_source_verified", "supported_reference",
                "The source reproduces the old filename label and the same-alert graph retains the reference; basename/case matching is not physical file identity.",
                proofs,
            )
    if entity_type == "url" and field == "Url":
        for entity in context.entities:
            if entity.fields.get("Type") != "url":
                continue
            raw = entity.fields.get("Url")
            if not isinstance(raw, str) or raw.lower() != value.lower():
                continue
            normalized = normalize_entity("address", raw)
            if normalized is None:
                continue
            kind = effective_kind("address", normalized)
            for mention in context.mentions:
                if mention.kind == kind and mention.value == normalized and mention.role == "alert_entity":
                    return disposition(
                        "legacy_url_case_projection_verified", "supported_reference",
                        "The old extractor lowercased the source URL; the graph preserves its path/query case. No case-insensitive URL equivalence is assumed.",
                        [evidence(context, mention, entity.path + ".Url")],
                    )
    if entity_type == "cloud-application" and field == "Name__InstanceName":
        for entity in context.entities:
            source = entity.fields
            if source.get("Type") != "cloud-application" or "__".join(str(source.get(k, "")).lower() for k in ("Name", "InstanceName")) != value:
                continue
            labels = [str(source["Name"]), str(source["InstanceName"])]
            matched = [m for m in context.mentions if m.kind == "application_name_reference" and m.value in labels and m.role == "alert_entity"]
            if all(any(m.value == label for m in matched) for label in labels):
                return disposition(
                    "application_labels_source_verified", "supported_reference",
                    "Both labels are retained as same-alert references, not merged into a global application identity.",
                    [evidence(context, m, entity.path) for m in matched],
                )
    if entity_type == "azure-resource" and field in ("SubscriptionId", "ResourceGroup"):
        for entity in context.entities:
            raw = entity.fields.get("ResourceId")
            if entity.fields.get("Type") != "azure-resource" or not isinstance(raw, str):
                continue
            segment = "subscriptions" if field == "SubscriptionId" else "resourcegroups"
            parts = raw.lower().split("/")
            if not any(a == segment and b == value.lower() for a, b in zip(parts, parts[1:])):
                continue
            normalized = normalize_entity("azure_resource", raw)
            for mention in context.mentions:
                if mention.kind == "azure_resource" and mention.value == normalized and mention.role == "alert_entity":
                    return disposition(
                        "resource_component_in_source_uri", "supported_reference",
                        "The component is preserved within the scoped resource URI; it is not promoted to an unscoped standalone resource identity.",
                        [evidence(context, mention, entity.path + ".ResourceId")],
                    )
    return None


def direct_source_paths(node: dict[str, str], context: AlertContext, kind: str, normalized: str) -> list[str]:
    fields = {
        ("host", "HostName"): ("HostName",),
        ("host", "AadDeviceId"): ("AadDeviceId",),
        ("ip", "Address"): ("Address",),
        ("account", "Name"): ("Name",),
        ("account", "Sid"): ("Sid",),
        ("account", "AadUserId"): ("AadUserId",),
        ("account", "Email"): ("UserPrincipalName",),
        ("url", "Url"): ("Url",),
        ("mailbox", "MailboxPrimaryAddress"): ("MailboxPrimaryAddress", "Upn"),
        ("mailmessage", "Recipient"): ("Recipient",),
        ("mailmessage", "Sender"): ("Sender",),
        ("mailmessage", "SenderIP"): ("SenderIP",),
        ("cloud-application", "AppId"): ("AppId",),
        ("azure-resource", "ResourceId"): ("ResourceId",),
        ("oauth-application", "OAuthAppId"): ("OAuthAppId",),
        ("oauth-application", "OAuthObjectId"): ("OAuthObjectId",),
    }.get((node.get("node_type"), node.get("identifier_fields")), ())
    paths = []
    for entity in context.entities:
        if str(entity.fields.get("Type", "")).lower() != node.get("node_type"):
            continue
        for field in fields:
            raw = entity.fields.get(field)
            if not isinstance(raw, (str, int)) or isinstance(raw, bool):
                continue
            if normalize_entity(kind, str(raw)) == normalized:
                paths.append(entity.path + "." + field)
            elif kind == "domain" and node.get("node_type") == "url" and url_hostname(str(raw)) == normalized:
                paths.append(entity.path + "." + field + "/hostname")
        if node.get("node_type") == "account" and node.get("identifier_fields") == "Email":
            account = entity.fields
            if not account.get("UserPrincipalName") and account.get("Name") and account.get("UPNSuffix"):
                if normalize_entity("upn", str(account["Name"]) + "@" + str(account["UPNSuffix"])) == normalized:
                    paths.append(entity.path + ".Name+UPNSuffix")
    return paths


def check_legacy_edge(node: dict[str, str], context: AlertContext) -> dict:
    value = node.get("value", "")
    if node.get("identifier_fields") == "ProcessId__CreatedTimeUtc__CommandLine":
        return process_check(value, context)
    if (node.get("node_type"), node.get("identifier_fields")) == ("account", "Email"):
        corrected = synthesized_email_check(value, context)
        if corrected is not None:
            return corrected
    referenced = reference_check(node, context)
    if referenced is not None:
        return referenced
    kind = LEGACY_FIELD_KINDS.get((node.get("node_type", ""), node.get("identifier_fields", "")))
    if kind:
        normalized = normalize_entity(kind, value)
        if normalized is not None:
            kind = effective_kind(kind, normalized)
            matches = [m for m in context.mentions if m.kind == kind and m.value == normalized
                       and m.role in ("alert_entity", "url_host_reference")]
            source_paths = direct_source_paths(node, context, kind, normalized)
            if matches and source_paths:
                category = "supported_reference" if kind.endswith("_reference") or any(m.role == "url_host_reference" for m in matches) else "reported_identifier"
                return disposition(
                    "same_alert_graph_identifier", category,
                    "The current source-linked graph records this identifier on the same alert; this is not an independent behavioral verdict.",
                    [evidence(context, m, path) for m in matches for path in source_paths],
                )
    return disposition("requires_additional_source_or_path_check", "unresolved",
                       "No same-alert source/graph check passed. An identifier elsewhere is not sufficient evidence.")


def load_contexts(con: duckdb.DuckDBPyConnection) -> dict[tuple[str, str], AlertContext]:
    con.execute("""
        CREATE TEMP TABLE semantic_mentions AS
        SELECT e.observation_id,e.dst,e.relation,e.source_path,e.semantics
        FROM graph.edges e WHERE e.relation IN ('alert_entity','url_host_reference')
          AND e.observation_id IN (SELECT _observation_id FROM ledger.SecurityAlert)
    """)
    mentions: dict[str, list[GraphMention]] = defaultdict(list)
    for oid, node, kind, value, role, path, semantics in con.execute("""
        SELECT e.observation_id,n.node_id,n.kind,n.value,e.relation,e.source_path,e.semantics
        FROM semantic_mentions e JOIN graph.nodes n ON e.dst=n.node_id
    """).fetchall():
        mentions[oid].append(GraphMention(node, kind, value, role, path, semantics))
    contexts = {}
    for oid, tenant, aid, entities, start in con.execute(
        "SELECT _observation_id,TenantId,SystemAlertId,Entities,StartTime FROM ledger.SecurityAlert"
    ).fetchall():
        key = (tenant.lower(), aid.lower())
        if key in contexts:
            raise ValueError("ambiguous latest alert identity")
        contexts[key] = AlertContext(oid, key[0], key[1], entity_objects(entities or "[]"), tuple(mentions[oid]), start)
    return contexts


def observation_mentions(con: duckdb.DuckDBPyConnection, observation_id: str) -> tuple[GraphMention, ...]:
    return tuple(GraphMention(*row) for row in con.execute("""
        SELECT n.node_id,n.kind,n.value,e.relation,e.source_path,e.semantics
        FROM graph.edges e JOIN graph.nodes n ON n.node_id=e.dst WHERE e.observation_id=?
    """, [observation_id]).fetchall())


def message_path_check(node: dict[str, str], context: AlertContext, con: duckdb.DuckDBPyConnection) -> dict | None:
    subject = (node.get("node_type"), node.get("identifier_fields"))
    if subject not in (("mailmessage", "Sender"), ("mailmessage", "SenderIP"), ("url", "Url")):
        return None
    candidates = []
    for entity in context.entities:
        message_id = entity.fields.get("NetworkMessageId")
        if str(entity.fields.get("Type", "")).lower() != "mailmessage" or not isinstance(message_id, str):
            continue
        message_id = normalize_entity("message_id", message_id)
        anchors = [m for m in context.mentions if m.kind == "message_id" and m.value == message_id
                   and m.role == "alert_entity" and m.source_path == f"{entity.path}.NetworkMessageId"]
        recipient = entity.fields.get("Recipient")
        if not anchors or not isinstance(recipient, str):
            continue
        if subject[0] == "mailmessage":
            rows = con.execute("""
                SELECT _observation_id,SenderFromAddress,SenderIPv4,SenderIPv6
                FROM ledger.EmailEvents WHERE lower(TenantId)=? AND lower(NetworkMessageId)=?
                 AND lower(RecipientEmailAddress)=?
            """, [context.tenant_id, message_id, recipient.lower()]).fetchall()
            kind, role = ("upn", "sender_address") if subject[1] == "Sender" else ("ip", "sender_ip")
            expected = normalize_entity(kind, node["value"])
            variants = {
                normalize_entity(kind, raw)
                for row in rows for raw in ((row[1],) if kind == "upn" else (row[2], row[3]))
                if isinstance(raw, str) and raw
            }
            if expected is None or variants != {expected}:
                continue
            source_rows = []
            for row in rows:
                fields = (("SenderFromAddress", row[1]),) if kind == "upn" else (
                    ("SenderIPv4", row[2]), ("SenderIPv6", row[3]),
                )
                for field, raw in fields:
                    if isinstance(raw, str) and normalize_entity(kind, raw) == expected:
                        source_rows.append((row[0], kind, expected, (role,), field))
        else:
            expected = normalize_entity("address", node["value"])
            if expected is None:
                continue
            kind = effective_kind("address", expected)
            rows = con.execute("""
                SELECT _observation_id,Url,UrlChain FROM ledger.UrlClickEvents
                WHERE lower(TenantId)=? AND lower(NetworkMessageId)=? AND lower(AccountUpn)=?
            """, [context.tenant_id, message_id, recipient.lower()]).fetchall()
            source_rows = []
            for oid, url, chain_text in rows:
                chain = json.loads(chain_text or "[]")
                if not isinstance(chain, list):
                    raise ValueError("click redirect chain is not an array")
                observed = [("Url", url, "url")]
                observed.extend((f"UrlChain[{index}]", raw, "redirect_chain_member") for index, raw in enumerate(chain))
                for field, raw, role in observed:
                    if isinstance(raw, str) and normalize_entity("address", raw) == expected:
                        source_rows.append((oid, kind, expected, (role,), field))
        for oid, kind, expected, roles, source_path in source_rows:
            mentions = observation_mentions(con, oid)
            bridges = [m for m in mentions if m.kind == "message_id" and m.value == message_id and m.role == "message"]
            targets = [m for m in mentions if m.kind == kind and m.value == expected and m.role in roles]
            shared_anchors = [a for a in anchors if any(a.node_id == b.node_id for b in bridges)]
            if not shared_anchors or not targets:
                continue
            anchor = shared_anchors[0]
            bridge = next(b for b in bridges if b.node_id == anchor.node_id)
            candidates.append({
                "alert_observation_id": context.observation_id, "raw_observation_id": oid,
                "message_id": message_id, "source_recipient": recipient,
                "source_path": source_path,
                "graph_path": [context.observation_id, anchor.node_id, oid, targets[0].node_id],
                "graph_edges": [
                    {"observation_id": observation_id, "node_id": m.node_id, "role": m.role,
                     "source_path": m.source_path, "semantics": m.semantics}
                    for observation_id, m in ((context.observation_id, anchor), (oid, bridge), (oid, targets[0]))
                ],
                "checks": ["exact_message_id", "same_tenant", "same_recipient", "raw_target_value", "graph_bridge_and_target_roles"],
                "target_value": expected,
            })
    if candidates:
        return disposition(
            "exact_message_evidence_path_verified", "supported_alternative_path",
            "The latest alert omits or changes a direct field, but exact message/recipient-linked telemetry and graph roles preserve the evidence path; no URL scheme equivalence was assumed.",
            candidates,
        )
    return None


def excluded_process_time_check(node: dict[str, str], context: AlertContext, con: duckdb.DuckDBPyConnection) -> dict | None:
    if node.get("identifier_fields") != "ProcessId__CreatedTimeUtc__CommandLine":
        return None
    parts = node.get("value", "").split("__", 2)
    if len(parts) != 3 or not parts[0].isdigit() or timestamp(parts[1]) is not None:
        return None
    processes = [e for e in context.entities if e.fields.get("Type") == "process"
                 and str(e.fields.get("ProcessId")) == parts[0]
                 and e.fields.get("CreationTimeUtc") is None
                 and str(e.fields.get("CreatedTimeUtc", "")).lower() == parts[1]
                 and isinstance(e.fields.get("CommandLine"), str) and e.fields["CommandLine"].lower() == parts[2]]
    hosts = {e.fields.get("FQDN") or e.fields.get("HostName") for e in context.entities if e.fields.get("Type") == "host"}
    hosts.discard(None)
    if len(processes) != 1 or len(hosts) != 1 or context.start_time is None:
        return None
    if timestamp(context.start_time.isoformat()) is None:
        return None
    host = next(iter(hosts))
    if not isinstance(host, str):
        return None
    process = processes[0]
    # Raw candidates are evidence of a different qualified identity, never a
    # license to assign a timezone to the invalid legacy timestamp.
    rows = con.execute("""
        SELECT _observation_id,DeviceName,ProcessId,ProcessCreationTime,ProcessCommandLine
        FROM ledger.DeviceProcessEvents WHERE lower(TenantId)=? AND lower(DeviceName)=?
          AND ProcessId=? AND ProcessCommandLine=? AND ProcessCreationTime<=?
    """, [context.tenant_id, host.lower(), int(parts[0]), process.fields["CommandLine"], context.start_time]).fetchall()
    if len(rows) != 1:
        return None
    oid, device, pid, created, command = rows[0]
    identity = normalize_entity("process", json.dumps({"host": device, "pid": pid, "created": created.isoformat()}))
    matches = [m for m in observation_mentions(con, oid) if m.kind == "process"
               and m.value == identity and m.role == "subject_process"]
    if not matches:
        return None
    return disposition(
        "unqualified_legacy_process_identity_excluded", "intentional_exclusion",
        "The legacy tuple uses timezone-free CreatedTimeUtc, not a qualified process start. Preserve the separate source-backed raw process identity; do not fabricate an equivalence or silently recover the old timestamp.",
        [{
            "alert_observation_id": context.observation_id, "source_entity_path": process.path,
            "legacy_created_time": process.fields["CreatedTimeUtc"],
            "raw_observation_id": oid, "raw_process_node": matches[0].node_id,
            "raw_host": device, "raw_pid": pid, "raw_creation_time": created.isoformat(),
            "raw_command": command, "legacy_timestamp_equivalence_claimed": False,
        }],
    )


def check_graph_semantics(graph_bundle: Path, legacy_graphs: Path, output: Path) -> dict:
    graph_bundle, legacy_graphs, output = graph_bundle.resolve(), legacy_graphs.resolve(), output.resolve()
    report_path = graph_bundle / "graph_report.json"
    graph_report = json.loads(report_path.read_text())
    if graph_report.get("status") != "complete":
        raise ValueError("graph is not a completed build")
    name = graph_report["database"]["path"]
    if Path(name).name != name or (graph_bundle / name).is_symlink():
        raise ValueError("invalid graph database path")
    graph_db = graph_bundle / name
    if file_sha256(graph_db) != graph_report["database"]["sha256"]:
        raise ValueError("graph checksum mismatch")
    ledger_bundle = Path(graph_report["ledger_bundle"])
    ledger_db, ledger_report = load_ledger(ledger_bundle)
    if ledger_report["ledger_id"] != graph_report["ledger_id"]:
        raise ValueError("graph and ledger identities differ")
    if ledger_report["database"]["sha256"] != graph_report["ledger_database_sha256"]:
        raise ValueError("graph and ledger database checksums differ")
    paths = sorted(legacy_graphs.glob("incident_*.graphml"))
    if not paths:
        raise ValueError("no legacy graphs supplied")
    if output.exists() or any(output.is_relative_to(p) or p.is_relative_to(output)
                              for p in (graph_bundle, ledger_bundle, legacy_graphs)):
        raise ValueError("output must be new and outside the input directories")
    fingerprints = {str(path): file_sha256(path) for path in paths}
    initial_stats = {p: (p.stat().st_size, p.stat().st_mtime_ns) for p in [graph_db, ledger_db, *paths]}
    results = []
    with duckdb.connect(config={"threads": 1, "memory_limit": "1GB"}) as con:
        attach_readonly(con, graph_db, "graph")
        attach_readonly(con, ledger_db, "ledger")
        contexts = load_contexts(con)
        for path in paths:
            nodes, edges = old_graph_nodes(path)
            for a, b in edges:
                if nodes[a].get("type") != "alert":
                    a, b = b, a
                if nodes[a].get("type") != "alert" or nodes[b].get("type") != "entity":
                    raise ValueError("legacy graph contains a non alert/entity edge")
                entry = json.loads(nodes[a]["entry"])
                key = (entry["TenantId"].lower(), entry["SystemAlertId"].lower())
                context = contexts.get(key)
                checked = check_legacy_edge(nodes[b], context) if context else disposition(
                    "missing_latest_alert", "unresolved", "No latest source alert with this tenant and ID.",
                )
                if context and checked["category"] == "unresolved":
                    checked = (
                        message_path_check(nodes[b], context, con)
                        or excluded_process_time_check(nodes[b], context, con)
                        or checked
                    )
                results.append({
                    "legacy_graph": path.name, "legacy_alert_node": a, "legacy_entity_node": b,
                    "alert_id": key[1], "tenant_id": key[0], "legacy_entity_type": nodes[b].get("node_type"),
                    "legacy_identifier_fields": nodes[b].get("identifier_fields"),
                    "legacy_value": nodes[b].get("value"), **checked,
                })
    for path, before in initial_stats.items():
        if (path.stat().st_size, path.stat().st_mtime_ns) != before:
            raise ValueError("semantic-check input changed during run")
    counts = dict(Counter(r["category"] for r in results))
    report = {
        "schema_version": "1", "visibility": "private_build",
        "status": "needs_review" if counts.get("unresolved", 0) else "legacy_edges_accounted",
        "policy_version": SEMANTIC_POLICY_VERSION,
        "graph_id": graph_report["graph_id"], "ledger_id": ledger_report["ledger_id"],
        "graph_sha256": graph_report["database"]["sha256"], "legacy_graph_sha256": fingerprints,
        "ledger_sha256": ledger_report["database"]["sha256"],
        "implementation_sha256": {n: file_sha256(Path(__file__).with_name(n))
                                  for n in ("graph_semantics.py", "graph_compare.py", "graph_entities.py")},
        "summary": {"legacy_edges": len(results), "categories": counts, "statuses": dict(Counter(r["status"] for r in results))},
        "edge_checks": results, "inputs_unchanged": True,
        "limits": [
            "Checks apply to the supplied legacy alert/entity relationships, not every possible tenant-graph relationship.",
            "Legacy lowercasing/basename projections are reproduced only to classify reference labels, not to merge physical identities.",
            "Reported identifiers and detector-derived entities are not independent behavioral or maliciousness proof.",
            "No raw source, graph, dataset or task is rewritten by this comparator.",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir()
    (output / "semantic_report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report
