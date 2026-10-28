# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

import duckdb

from secgym.qagen.agentic.graph_entities import normalize_entity
from secgym.qagen.agentic.graph_semantics import (
    AlertContext, GraphMention, check_graph_semantics, check_legacy_edge, entity_objects, excluded_process_time_check,
    load_contexts, message_path_check, timestamp,
)
from secgym.qagen.agentic.ledger import file_sha256


def mention(kind, value, role="alert_entity"):
    return GraphMention("node:" + kind, kind, value, role, "Entities[0]", "reported_entity")


def context(entities, mentions):
    return AlertContext("obs:alert", "tenant", "alert", entity_objects(json.dumps(entities)), tuple(mentions))


def node(kind, field, value):
    return {"node_type": kind, "identifier_fields": field, "value": value}


class EntityParsingTests(unittest.TestCase):
    def test_nested_definitions_and_reference_duplicates_do_not_invent_facts(self):
        parsed = entity_objects(json.dumps([
            {"Type": "process", "ParentProcess": {"$id": "p", "Type": "process", "ProcessId": "1"}},
            {"$ref": "p"},
        ]))
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[1].path, "Entities[0].ParentProcess")

    def test_conflicting_definitions_and_non_arrays_fail(self):
        for value in ({}, [{"$id": "a", "Type": "host"}, {"$id": "a", "Type": "ip"}]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                entity_objects(json.dumps(value))

    def test_timestamps_require_explicit_timezone(self):
        self.assertIsNone(timestamp("2024-01-01T10:00:00"))
        self.assertIsNone(timestamp("invalid"))
        self.assertEqual(timestamp("2024-01-01t10:00:00z"), timestamp("2024-01-01T11:00:00+01:00"))


class SemanticProcessTests(unittest.TestCase):
    def process_context(self, *, command="Tool.EXE /Key:AbC", created="2024-01-01T10:00:00Z", host="host.test"):
        process = {"Type": "process", "ProcessId": "42", "CreationTimeUtc": created, "CommandLine": command}
        identity = normalize_entity("process", json.dumps({"host": host, "pid": "42", "created": created}))
        return context([{"Type": "host", "FQDN": host}, process], [mention("process", identity)] if identity else [])

    def test_source_command_projection_pid_time_host_and_graph_all_checked(self):
        ctx = self.process_context()
        legacy = node("process", "ProcessId__CreatedTimeUtc__CommandLine", "42__2024-01-01t10:00:00z__tool.exe /key:abc")
        result = check_legacy_edge(legacy, ctx)
        self.assertEqual(result["category"], "supported_identity")
        self.assertEqual(result["evidence"][0]["source_command"], "Tool.EXE /Key:AbC")
        self.assertIn("legacy_lowercase_command_projection", result["evidence"][0]["checks"])

    def test_matching_pid_time_without_command_agreement_is_insufficient(self):
        result = check_legacy_edge(node("process", "ProcessId__CreatedTimeUtc__CommandLine",
                                       "42__2024-01-01t10:00:00z__different.exe"), self.process_context())
        self.assertEqual(result["category"], "unresolved")

    def test_same_command_without_graph_process_is_insufficient(self):
        ctx = self.process_context()
        empty = AlertContext(ctx.observation_id, ctx.tenant_id, ctx.alert_id, ctx.entities, ())
        result = check_legacy_edge(node("process", "ProcessId__CreatedTimeUtc__CommandLine",
                                       "42__2024-01-01t10:00:00z__tool.exe /key:abc"), empty)
        self.assertEqual(result["category"], "unresolved")

    def test_wrong_host_or_multiple_hosts_are_not_implicitly_equated(self):
        ctx = self.process_context()
        other_key = normalize_entity("process", json.dumps({"host": "other", "pid": "42", "created": "2024-01-01T10:00:00Z"}))
        wrong = AlertContext(ctx.observation_id, ctx.tenant_id, ctx.alert_id, ctx.entities, (mention("process", other_key),))
        legacy = node("process", "ProcessId__CreatedTimeUtc__CommandLine", "42__2024-01-01t10:00:00z__tool.exe /key:abc")
        self.assertEqual(check_legacy_edge(legacy, wrong)["category"], "unresolved")
        more = ctx.entities + entity_objects('[{"Type":"host","FQDN":"other"}]')
        multiple = AlertContext(ctx.observation_id, ctx.tenant_id, ctx.alert_id, more, ctx.mentions)
        self.assertEqual(check_legacy_edge(legacy, multiple)["category"], "unresolved")

    def test_alternate_creation_timestamp_is_not_a_blind_fallback(self):
        ctx = context([
            {"Type": "host", "FQDN": "host"},
            {"Type": "process", "ProcessId": "42", "CreatedTimeUtc": "2024-01-01T10:00:00Z", "CommandLine": "tool"},
        ], [])
        result = check_legacy_edge(node("process", "ProcessId__CreatedTimeUtc__CommandLine",
                                       "42__2024-01-01t10:00:00z__tool"), ctx)
        self.assertEqual(result["category"], "unresolved")
        self.assertEqual(result["evidence"][0]["alternate_created_time"], "2024-01-01T10:00:00Z")


class SemanticReferenceTests(unittest.TestCase):
    def test_filename_case_and_basename_are_only_reference_equivalence(self):
        ctx = context([{"Type": "process", "CommandLine": "powershell C:\\Scripts\\Tool.ps1"}],
                      [mention("file_reference", "C:\\Scripts\\Tool.ps1")])
        result = check_legacy_edge(node("process", "ExtractedFileName", "tool.ps1"), ctx)
        self.assertEqual(result["category"], "supported_reference")
        self.assertFalse(result["evidence"][0]["physical_file_identity_claimed"])

    def test_mention_without_matching_source_reference_is_not_enough(self):
        ctx = context([{"Type": "process", "CommandLine": "other.exe"}], [mention("file_reference", "tool.exe")])
        result = check_legacy_edge(node("process", "ExtractedFileName", "tool.exe"), ctx)
        self.assertEqual(result["category"], "unresolved")

    def test_url_case_projection_does_not_lowercase_current_url(self):
        url = "https://example.test/Case?Key=Value"
        ctx = context([{"Type": "url", "Url": url}], [mention("url", url)])
        result = check_legacy_edge(node("url", "Url", url.lower()), ctx)
        self.assertEqual(result["category"], "supported_reference")
        self.assertEqual(result["evidence"][0]["value"], url)

    def test_no_added_scheme_or_changed_url_is_accepted(self):
        ctx = context([{"Type": "url", "Url": "example.test/Path"}], [mention("url_reference", "example.test/Path")])
        result = check_legacy_edge(node("url", "Url", "https://example.test/path"), ctx)
        self.assertEqual(result["category"], "unresolved")

    def test_resource_component_preserved_in_full_uri(self):
        uri = "/subscriptions/sub/resourceGroups/Group/providers/type/item"
        ctx = context([{"Type": "azure-resource", "ResourceId": uri}], [mention("azure_resource", uri.lower())])
        result = check_legacy_edge(node("azure-resource", "ResourceGroup", "group"), ctx)
        self.assertEqual(result["category"], "supported_reference")
        self.assertEqual(result["evidence"][0]["value"], uri.lower())

    def test_both_application_labels_must_be_supported(self):
        entities = [{"Type": "cloud-application", "Name": "App", "InstanceName": "Instance"}]
        ctx = context(entities, [mention("application_name_reference", "App")])
        legacy = node("cloud-application", "Name__InstanceName", "app__instance")
        self.assertEqual(check_legacy_edge(legacy, ctx)["category"], "unresolved")
        ctx = context(entities, [mention("application_name_reference", "App"), mention("application_name_reference", "Instance")])
        self.assertEqual(check_legacy_edge(legacy, ctx)["category"], "supported_reference")

    def test_fabricated_email_uses_authoritative_same_account_upn(self):
        ctx = context([{"Type": "account", "Name": "Display Name", "UPNSuffix": "example.test",
                        "UserPrincipalName": "actual@example.test", "AccountName": "actual"}],
                      [mention("upn", "actual@example.test")])
        result = check_legacy_edge(node("account", "Email", "Display Name@example.test"), ctx)
        self.assertEqual(result["category"], "source_correction")
        self.assertEqual(result["evidence"][0]["value"], "actual@example.test")

    def test_other_account_upn_cannot_correct_a_fabricated_email(self):
        ctx = context([{"Type": "account", "Name": "Display Name", "UPNSuffix": "example.test"},
                       {"Type": "account", "Name": "Other", "UserPrincipalName": "actual@example.test"}],
                      [mention("upn", "actual@example.test")])
        self.assertEqual(check_legacy_edge(node("account", "Email", "Display Name@example.test"), ctx)["category"], "unresolved")

    def test_simple_identifier_must_appear_in_both_source_and_graph(self):
        legacy = node("ip", "Address", "192.0.2.1")
        ctx = context([{"Type": "ip", "Address": "192.0.2.1"}], [mention("ip", "192.0.2.1")])
        self.assertEqual(check_legacy_edge(legacy, ctx)["category"], "reported_identifier")
        wrong = context([{"Type": "ip", "Address": "192.0.2.2"}], ctx.mentions)
        self.assertEqual(check_legacy_edge(legacy, wrong)["category"], "unresolved")


class SemanticContextTests(unittest.TestCase):
    def test_latest_alert_context_does_not_borrow_other_alerts_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "check.duckdb"
            with duckdb.connect(str(path)) as con:
                con.execute("CREATE SCHEMA graph")
                con.execute("CREATE SCHEMA ledger")
                con.execute("CREATE TABLE graph.edges(observation_id VARCHAR,dst VARCHAR,relation VARCHAR,source_path VARCHAR,semantics VARCHAR)")
                con.execute("CREATE TABLE graph.nodes(node_id VARCHAR,kind VARCHAR,value VARCHAR)")
                con.execute("CREATE TABLE ledger.SecurityAlert(_observation_id VARCHAR,TenantId VARCHAR,SystemAlertId VARCHAR,Entities VARCHAR,StartTime TIMESTAMPTZ DEFAULT NULL)")
                con.execute("""INSERT INTO ledger.SecurityAlert VALUES
                    ('obs:a','tenant','a','[{"Type":"ip","Address":"192.0.2.1"}]',NULL),
                    ('obs:b','tenant','b','[{"Type":"ip","Address":"192.0.2.1"}]',NULL)""")
                con.execute("INSERT INTO graph.nodes VALUES ('ip','ip','192.0.2.1')")
                con.execute("INSERT INTO graph.edges VALUES ('obs:b','ip','alert_entity','Entities[0].Address','reported_entity')")
                contexts = load_contexts(con)
                self.assertFalse(contexts[("tenant", "a")].mentions)
                self.assertEqual(len(contexts[("tenant", "b")].mentions), 1)


class AlternativeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.con = duckdb.connect(config={"threads": 1, "memory_limit": "256MB"})
        self.addCleanup(self.con.close)
        self.con.execute("CREATE SCHEMA graph")
        self.con.execute("CREATE SCHEMA ledger")
        self.con.execute("CREATE TABLE graph.edges(observation_id VARCHAR,dst VARCHAR,relation VARCHAR,source_path VARCHAR,semantics VARCHAR)")
        self.con.execute("CREATE TABLE graph.nodes(node_id VARCHAR,kind VARCHAR,value VARCHAR)")
        self.mid = "11111111-1111-4111-8111-111111111111"
        self.ctx = context([{"Type": "mailMessage", "NetworkMessageId": self.mid, "Recipient": "recipient@example.test"}],
                           [GraphMention("node:message_id", "message_id", self.mid, "alert_entity",
                                         "Entities[0].NetworkMessageId", "reported_entity")])
        self.con.execute("CREATE TABLE ledger.EmailEvents(_observation_id VARCHAR,TenantId VARCHAR,NetworkMessageId VARCHAR,RecipientEmailAddress VARCHAR,SenderFromAddress VARCHAR,SenderIPv4 VARCHAR,SenderIPv6 VARCHAR)")
        self.con.execute("CREATE TABLE ledger.UrlClickEvents(_observation_id VARCHAR,TenantId VARCHAR,NetworkMessageId VARCHAR,AccountUpn VARCHAR,Url VARCHAR,UrlChain VARCHAR)")

    def add_participant(self, oid, kind, value, role):
        nid = "node:message_id" if kind == "message_id" else oid + ":" + role
        self.con.execute("INSERT INTO graph.nodes VALUES (?,?,?)", [nid, kind, value])
        self.con.execute("INSERT INTO graph.edges VALUES (?,?,?,'SourceField','observed_participation')", [oid, nid, role])

    def email(self, recipient="recipient@example.test", sender="sender@example.test"):
        self.con.execute("INSERT INTO ledger.EmailEvents VALUES ('obs:mail','tenant',?,?,?,'192.0.2.1',NULL)",
                         [self.mid, recipient, sender])
        self.add_participant("obs:mail", "message_id", self.mid, "message")
        self.add_participant("obs:mail", "upn", sender, "sender_address")

    def test_sender_requires_message_recipient_raw_field_and_graph_roles(self):
        self.email()
        result = message_path_check(node("mailmessage", "Sender", "sender@example.test"), self.ctx, self.con)
        self.assertIsNotNone(result)
        self.assertEqual(result["category"], "supported_alternative_path")
        self.con.execute("UPDATE graph.nodes SET node_id='different-node' WHERE kind='message_id'")
        self.con.execute("UPDATE graph.edges SET dst='different-node' WHERE relation='message'")
        self.assertIsNone(message_path_check(node("mailmessage", "Sender", "sender@example.test"), self.ctx, self.con))
        self.con.execute("DELETE FROM graph.edges WHERE relation='message'")
        self.assertIsNone(message_path_check(node("mailmessage", "Sender", "sender@example.test"), self.ctx, self.con))

    def test_wrong_recipient_and_conflicting_sender_are_not_accepted(self):
        self.email(recipient="other@example.test")
        legacy = node("mailmessage", "Sender", "sender@example.test")
        self.assertIsNone(message_path_check(legacy, self.ctx, self.con))
        self.con.execute("UPDATE ledger.EmailEvents SET RecipientEmailAddress='recipient@example.test'")
        self.con.execute("INSERT INTO ledger.EmailEvents SELECT * REPLACE('obs:other' AS _observation_id,'different@example.test' AS SenderFromAddress) FROM ledger.EmailEvents")
        self.assertIsNone(message_path_check(legacy, self.ctx, self.con))

    def test_wrong_tenant_or_message_or_target_role_is_not_accepted(self):
        self.email()
        legacy = node("mailmessage", "Sender", "sender@example.test")
        for field, wrong, correct in (
            ("TenantId", "other-tenant", "tenant"), ("NetworkMessageId", "different-message", self.mid),
        ):
            with self.subTest(field=field):
                self.con.execute(f"UPDATE ledger.EmailEvents SET {field}=?", [wrong])
                self.assertIsNone(message_path_check(legacy, self.ctx, self.con))
                self.con.execute(f"UPDATE ledger.EmailEvents SET {field}=?", [correct])
        self.con.execute("UPDATE graph.edges SET relation='recipient' WHERE relation='sender_address'")
        self.assertIsNone(message_path_check(legacy, self.ctx, self.con))

    def test_raw_value_on_one_row_cannot_prove_a_different_rows_graph_edge(self):
        self.email()
        self.con.execute("INSERT INTO ledger.EmailEvents SELECT * REPLACE ('obs:raw-only' AS _observation_id) FROM ledger.EmailEvents")
        self.con.execute("UPDATE ledger.EmailEvents SET SenderFromAddress=NULL WHERE _observation_id='obs:mail'")
        self.assertIsNone(message_path_check(node("mailmessage", "Sender", "sender@example.test"), self.ctx, self.con))

    def test_sender_ip_and_direct_mailmessage_binding(self):
        self.email()
        self.add_participant("obs:mail", "ip", "192.0.2.1", "sender_ip")
        legacy = node("mailmessage", "SenderIP", "192.0.2.1")
        result = message_path_check(legacy, self.ctx, self.con)
        self.assertIsNotNone(result)
        self.assertEqual(result["evidence"][0]["source_path"], "SenderIPv4")
        cluster = context([{"Type": "mailCluster", "NetworkMessageId": self.mid, "Recipient": "recipient@example.test"}],
                          self.ctx.mentions)
        self.assertIsNone(message_path_check(legacy, cluster, self.con))
        cluster_edge = context([{"Type": "mailMessage", "NetworkMessageId": self.mid, "Recipient": "recipient@example.test"}],
                               [GraphMention("node:message_id", "message_id", self.mid, "alert_entity",
                                             "Entities[1].NetworkMessageIds[0]", "reported_entity")])
        self.assertIsNone(message_path_check(legacy, cluster_edge, self.con))

    def test_redirect_url_requires_an_explicit_chain_not_scheme_guessing(self):
        url = "https://example.test/Path"
        self.con.execute("INSERT INTO ledger.UrlClickEvents VALUES ('obs:click','tenant',?,'recipient@example.test','http://example.test/Path',?)",
                         [self.mid, json.dumps(["http://example.test/Path", url])])
        self.add_participant("obs:click", "message_id", self.mid, "message")
        self.add_participant("obs:click", "url", url, "redirect_chain_member")
        legacy = node("url", "Url", url)
        self.assertIsNotNone(message_path_check(legacy, self.ctx, self.con))
        self.assertIsNone(message_path_check(node("url", "Url", url.lower()), self.ctx, self.con))
        self.con.execute("UPDATE ledger.UrlClickEvents SET AccountUpn='other@example.test'")
        self.assertIsNone(message_path_check(legacy, self.ctx, self.con))
        self.con.execute("UPDATE ledger.UrlClickEvents SET AccountUpn='recipient@example.test'")
        self.con.execute("UPDATE ledger.UrlClickEvents SET UrlChain='[]'")
        self.assertIsNone(message_path_check(legacy, self.ctx, self.con))

    def test_invalid_legacy_time_is_excluded_not_mapped_to_nearby_process(self):
        self.con.execute("CREATE TABLE ledger.DeviceProcessEvents(_observation_id VARCHAR,TenantId VARCHAR,DeviceName VARCHAR,ProcessId BIGINT,ProcessCreationTime TIMESTAMPTZ,ProcessCommandLine VARCHAR)")
        self.con.execute("INSERT INTO ledger.DeviceProcessEvents VALUES ('obs:process','tenant','host',42,'2024-01-01T10:00:00Z','Tool.EXE')")
        identity = normalize_entity("process", json.dumps({"host": "host", "pid": 42, "created": "2024-01-01T10:00:00Z"}))
        self.add_participant("obs:process", "process", identity, "subject_process")
        ctx = context([{"Type": "host", "FQDN": "host"}, {"Type": "process", "ProcessId": "42",
                       "CreatedTimeUtc": "2024-01-01T12:00:00", "CommandLine": "Tool.EXE"}], [])
        ctx = AlertContext(ctx.observation_id, ctx.tenant_id, ctx.alert_id, ctx.entities, ctx.mentions,
                           datetime(2024, 1, 1, 11, tzinfo=timezone.utc))
        legacy = node("process", "ProcessId__CreatedTimeUtc__CommandLine", "42__2024-01-01t12:00:00__tool.exe")
        result = excluded_process_time_check(legacy, ctx, self.con)
        self.assertIsNotNone(result)
        self.assertEqual(result["category"], "intentional_exclusion")
        self.assertFalse(result["evidence"][0]["legacy_timestamp_equivalence_claimed"])
        self.con.execute("INSERT INTO ledger.DeviceProcessEvents SELECT * REPLACE ('obs:second' AS _observation_id) FROM ledger.DeviceProcessEvents")
        self.assertIsNone(excluded_process_time_check(legacy, ctx, self.con))


class SemanticReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ledger = self.root / "ledger"
        self.graph = self.root / "graph"
        self.legacy = self.root / "legacy"
        for directory in (self.ledger, self.graph, self.legacy):
            directory.mkdir()
        db = self.ledger / "observations.duckdb"
        with duckdb.connect(str(db)) as con:
            con.execute("CREATE TABLE SecurityAlert(_observation_id VARCHAR,TenantId VARCHAR,SystemAlertId VARCHAR,Entities VARCHAR,StartTime TIMESTAMPTZ)")
            con.execute("""INSERT INTO SecurityAlert VALUES ('obs:a','tenant','alert-a',
                '[{"Type":"ip","Address":"192.0.2.1"}]','2024-01-01T00:00:00Z')""")
        (self.ledger / "ledger_report.json").write_text(json.dumps({
            "status": "complete", "ledger_id": "fixture-ledger",
            "database": {"path": db.name, "sha256": file_sha256(db), "size_bytes": db.stat().st_size},
        }))
        db = self.graph / "graph.duckdb"
        with duckdb.connect(str(db)) as con:
            con.execute("CREATE TABLE edges(observation_id VARCHAR,dst VARCHAR,relation VARCHAR,source_path VARCHAR,semantics VARCHAR)")
            con.execute("CREATE TABLE nodes(node_id VARCHAR,kind VARCHAR,value VARCHAR)")
            con.execute("INSERT INTO nodes VALUES ('ip','ip','192.0.2.1')")
            con.execute("INSERT INTO edges VALUES ('obs:a','ip','alert_entity','Entities[0].Address','reported_entity')")
        (self.graph / "graph_report.json").write_text(json.dumps({
            "status": "complete", "graph_id": "fixture-graph", "ledger_id": "fixture-ledger", "ledger_bundle": str(self.ledger),
            "ledger_database_sha256": file_sha256(self.ledger / "observations.duckdb"),
            "database": {"path": db.name, "sha256": file_sha256(db), "size_bytes": db.stat().st_size},
        }))
        self.write_legacy("192.0.2.1")

    def write_legacy(self, value):
        root = ET.Element("graphml", xmlns="http://graphml.graphdrawing.org/xmlns")
        for key in ("type", "entry", "node_type", "identifier_fields", "value"):
            ET.SubElement(root, "key", {"id": key, "attr.name": key})
        graph = ET.SubElement(root, "graph", edgedefault="undirected")
        for nid, fields in (
            ("0", {"type": "alert", "entry": json.dumps({"TenantId": "tenant", "SystemAlertId": "alert-a"})}),
            ("1", {"type": "entity", "node_type": "ip", "identifier_fields": "Address", "value": value}),
        ):
            item = ET.SubElement(graph, "node", id=nid)
            for key, content in fields.items():
                ET.SubElement(item, "data", key=key).text = content
        ET.SubElement(graph, "edge", source="0", target="1")
        ET.ElementTree(root).write(self.legacy / "incident_34.graphml", encoding="utf-8", xml_declaration=True)

    def test_complete_report_binds_sources_and_preserves_inputs(self):
        before = file_sha256(self.graph / "graph.duckdb")
        output = self.root / "comparison"
        report = check_graph_semantics(self.graph, self.legacy, output)
        self.assertEqual(report["status"], "legacy_edges_accounted")
        self.assertEqual(report["summary"]["legacy_edges"], 1)
        self.assertEqual(report["edge_checks"][0]["evidence"][0]["observation_id"], "obs:a")
        self.assertEqual(report["graph_sha256"], before)
        self.assertEqual(file_sha256(self.graph / "graph.duckdb"), before)
        self.assertTrue((output / "semantic_report.json").is_file())
        with self.assertRaisesRegex(ValueError, "new and outside"):
            check_graph_semantics(self.graph, self.legacy, output)

    def test_invalid_bundle_hash_does_not_publish_report(self):
        with duckdb.connect(str(self.graph / "graph.duckdb")) as con:
            con.execute("DELETE FROM edges")
        output = self.root / "bad"
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            check_graph_semantics(self.graph, self.legacy, output)
        self.assertFalse(output.exists())

    def test_graph_requires_exact_ledger_digest_not_only_id(self):
        ledger_db = self.ledger / "observations.duckdb"
        with duckdb.connect(str(ledger_db)) as con:
            con.execute("UPDATE SecurityAlert SET StartTime=StartTime+INTERVAL '1 hour'")
        ledger_report_path = self.ledger / "ledger_report.json"
        ledger_report = json.loads(ledger_report_path.read_text())
        ledger_report["database"]["sha256"] = file_sha256(ledger_db)
        ledger_report["database"]["size_bytes"] = ledger_db.stat().st_size
        ledger_report_path.write_text(json.dumps(ledger_report))
        output = self.root / "wrong-ledger"
        with self.assertRaisesRegex(ValueError, "graph and ledger database checksums differ"):
            check_graph_semantics(self.graph, self.legacy, output)
        self.assertFalse(output.exists())

    def test_unresolved_relationship_returns_nonzero_and_explicit_report(self):
        self.write_legacy("192.0.2.99")
        output = self.root / "unresolved"
        result = subprocess.run([
            sys.executable, "-m", "secgym.qagen.agentic", "check-graph-semantics",
            "--graph-bundle", str(self.graph), "--legacy-graphs", str(self.legacy), "--output", str(output),
        ], cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "needs_review")
        report = json.loads((output / "semantic_report.json").read_text())
        self.assertEqual(report["summary"]["categories"], {"unresolved": 1})


if __name__ == "__main__":
    unittest.main()
