# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import duckdb

from secgym.qagen.agentic.graph import build_graph
from secgym.qagen.agentic.graph_entities import (
    command_references, effective_kind, graph_api_targets, normalize_entity, walk_alert_entities,
)
from secgym.qagen.agentic.ledger import file_sha256


TENANT = "tenant-a"
GUID_A = "11111111-1111-4111-8111-111111111111"
GUID_B = "22222222-2222-4222-8222-222222222222"


class EntityRulesTests(unittest.TestCase):
    def test_namespaces_are_not_collapsed(self):
        self.assertEqual(normalize_entity("host", "HOST.example.test"), "host.example.test")
        self.assertNotEqual(normalize_entity("host", "host"), normalize_entity("host", "host.example.test"))
        self.assertNotEqual(normalize_entity("upn", "user@a.test"), normalize_entity("upn", "user@b.test"))
        self.assertIsNone(normalize_entity("host", "127.0.0.1"))
        self.assertIsNone(normalize_entity("application_id", "Microsoft Outlook"))

    def test_ip_identity_validates_and_preserves_loopback_context(self):
        self.assertEqual(normalize_entity("ip", "::ffff:192.0.2.1"), "192.0.2.1")
        self.assertEqual(normalize_entity("ip_port", "[2001:db8::1]:443"), "2001:db8::1")
        self.assertEqual(normalize_entity("ip", "127.0.0.1"), "127.0.0.1")
        self.assertIsNone(normalize_entity("ip", "999.1.2.3"))
        self.assertIsNone(normalize_entity("ip", "not:ipv6"))

    def test_url_paths_and_query_case_are_preserved(self):
        self.assertEqual(normalize_entity("url", "HTTPS://Example.TEST/Ab?Token=X"), "https://example.test/Ab?Token=X")
        self.assertNotEqual(normalize_entity("url", "https://example.test/Ab"), normalize_entity("url", "https://example.test/ab"))
        self.assertIsNone(normalize_entity("url", "https://user:secret@example.test/"))

    def test_schemeless_addresses_are_references_not_invented_urls(self):
        raw = "EXAMPLE.test/Path?Query=A"
        normalized = normalize_entity("address", raw)
        self.assertEqual(normalized, "example.test/Path?Query=A")
        assert normalized is not None
        self.assertEqual(effective_kind("address", normalized), "url_reference")
        self.assertIsNone(normalize_entity("address", "/relative/path"))

    def test_graph_api_targets_require_exact_endpoint_and_namespace(self):
        uri = f"https://graph.microsoft.com/v1.0/users/{GUID_A}/memberOf/{GUID_B}"
        targets = json.loads(graph_api_targets(uri))
        self.assertEqual([r["id"] for r in targets], [GUID_A])
        self.assertEqual(json.loads(graph_api_targets(f"https://other.test/users/{GUID_A}")), [])
        self.assertEqual(json.loads(graph_api_targets("https://graph.microsoft.com/v1.0/users/me")), [])

    def test_command_extraction_reads_beyond_legacy_truncation(self):
        text = "powershell " + "x" * 11000 + " C:\\Scripts\\payload.ps1 https://example.test/A"
        refs = json.loads(command_references(text))
        self.assertTrue(any(r["value"] == "C:\\Scripts\\payload.ps1" and r["offset"] > 400 for r in refs))
        self.assertTrue(any(r["value"] == "https://example.test/A" for r in refs))

    def test_text_artifact_reference_and_extension_boundaries(self):
        references = json.loads(command_references("tool.exe /ticket:AdminTicket.txt fake.exeExtra file.ps1.bak"))
        self.assertTrue(any(r["value"] == "AdminTicket.txt" for r in references))
        self.assertFalse(any(r["value"] in ("fake.exe", "file.ps1") for r in references))

    def test_nested_entities_refs_and_orphan_entities_all_retained(self):
        entities = [
            {"$id": "1", "Type": "host", "HostName": "host", "FQDN": "host.example.test"},
            {"Type": "process", "ImageFile": {"$id": "2", "Type": "file", "Name": "tool.exe",
             "FileHashes": [{"Algorithm": "SHA256", "Value": "a" * 64}]}},
            {"$ref": "2"}, {"Type": "ip", "Address": "192.0.2.9"},
        ]
        mentions, issues = walk_alert_entities(json.dumps(entities))
        self.assertTrue(any(k == "sha256" and v == "a" * 64 for k, v, _ in mentions))
        self.assertTrue(any(k == "ip" and v == "192.0.2.9" for k, v, _ in mentions))
        self.assertTrue(any(path.startswith("$[2]") for _, _, path in mentions))
        self.assertTrue(all(reason == "incomplete_or_ambiguous_process_identity" for _, reason in issues))

    def test_process_timestamp_forms_resolve_to_the_same_exact_identity(self):
        a = json.dumps({"host": "HOST.test", "pid": 42, "created": "2024-01-01 10:00:00+00"})
        b = json.dumps({"host": "host.test", "pid": "42", "created": "2024-01-01T10:00:00.0000000Z"})
        self.assertEqual(normalize_entity("process", a), normalize_entity("process", b))

    def test_process_json_does_not_coerce_fractional_or_boolean_pids(self):
        for pid in (True, 1.5, "1.5", "bad", 0):
            with self.subTest(pid=pid):
                self.assertIsNone(normalize_entity("process", json.dumps({
                    "host": "host", "pid": pid, "created": "2024-01-01T00:00:00Z",
                })))
        self.assertIsNone(normalize_entity("process", "not-json"))

    def test_mail_cluster_and_field_only_sender_ip_are_extracted(self):
        mentions, issues = walk_alert_entities(json.dumps([
            {"Type": "mailCluster", "NetworkMessageIds": [GUID_A, GUID_B]},
            {"Type": "mailMessage", "SenderIP": "192.0.2.1", "Urls": ["https://example.test/X"]},
            {"Type": "host", "HostName": "host", "LastIpAddress": {"Address": "192.0.2.5"}},
        ]))
        self.assertTrue(any(k == "message_id" and v == GUID_B for k, v, _ in mentions))
        self.assertTrue(any(k == "ip" and v == "192.0.2.1" for k, v, _ in mentions))
        self.assertTrue(any(k == "ip" and v == "192.0.2.5" for k, v, _ in mentions))
        self.assertFalse(issues)

    def test_broken_and_cyclic_refs_are_explicit(self):
        mentions, issues = walk_alert_entities(json.dumps([
            {"$id": "a", "Type": "host", "HostName": "host", "Other": {"$ref": "a"}},
            {"$ref": "missing"},
        ]))
        self.assertTrue(mentions)
        self.assertTrue(any(reason == "cyclic_entity_reference" for _, reason in issues))
        self.assertTrue(any(reason == "unresolved_entity_reference" for _, reason in issues))
        with self.assertRaises(ValueError):
            walk_alert_entities('{"Type":"host"}')
        with self.assertRaises(ValueError):
            walk_alert_entities('[{"$id":"a","Type":"host"},{"$id":"a","Type":"ip"}]')


class ScopedEntityRulesTests(unittest.TestCase):
    def workload(self, cluster="/clusters/one", namespace="default", name="workload", kind="K8s-pod"):
        return [
            {"$id": "arm", "Type": "azure-resource", "ResourceId": cluster},
            {"Type": kind, "Name": name, "Namespace": {
                "Type": "K8s-namespace", "Name": namespace,
                "Cluster": {"Type": "K8s-cluster", "CloudResource": {"$ref": "arm"}},
            }},
        ]

    def test_kubernetes_names_retain_cluster_namespace_and_kind(self):
        identities = []
        for cluster, ns, kind in (("/clusters/one", "default", "K8s-pod"),
                                   ("/clusters/two", "default", "K8s-pod"),
                                   ("/clusters/one", "other", "K8s-pod"),
                                   ("/clusters/one", "default", "K8s-service")):
            mentions, issues = walk_alert_entities(json.dumps(self.workload(cluster, ns, kind=kind)))
            target = "k8s_pod_reference" if kind == "K8s-pod" else "k8s_service_reference"
            self.assertFalse(issues)
            values = [(k, v) for k, v, _ in mentions if k == target]
            self.assertEqual(values, [(target, json.dumps([cluster, ns, "workload"], separators=(",", ":")))])
            identities.extend(values)
        self.assertEqual(len(set(identities)), 4)

    def test_container_name_scopes_to_pod_and_image_is_only_a_reference(self):
        roots = self.workload()
        roots[1] = {"Type": "container", "Name": "sidecar", "Pod": roots[1],
                    "Image": {"Type": "container-image", "ImageId": "nginx"}}
        mentions, issues = walk_alert_entities(json.dumps(roots))
        self.assertFalse(issues)
        value, path = next((v, p) for k, v, p in mentions if k == "k8s_container_reference")
        self.assertEqual(json.loads(value), ["/clusters/one", "default", "workload", "sidecar"])
        self.assertIn("Pod.Namespace.Name+Pod.Name+Name", path)
        self.assertIn(("container_image_reference", "nginx", "$[1].Image.ImageId"), mentions)
        self.assertFalse(any(k == "sha256" for k, _, _ in mentions))

    def test_missing_wrong_type_and_cyclic_scope_do_not_create_named_identities(self):
        for scope in ({"$ref": "missing"}, {"Type": "host", "ResourceId": "/clusters/one"},
                      {"$id": "cycle", "$ref": "cycle"}):
            roots = [{"Type": "K8s-namespace", "Name": "default",
                      "Cluster": {"Type": "K8s-cluster", "CloudResource": scope}}]
            with self.subTest(scope=scope):
                mentions, issues = walk_alert_entities(json.dumps(roots))
                self.assertFalse(any(k == "k8s_namespace_reference" for k, _, _ in mentions))
                self.assertTrue(any(r == "incomplete_scoped_entity_reference:K8s-namespace" for _, r in issues))

    def test_iot_id_is_scoped_without_mde_or_hostname_inference(self):
        identities = []
        for hub in ("/iot/sites/one", "/iot/sites/two"):
            roots = [
                {"$id": "hub", "Type": "azure-resource", "ResourceId": hub},
                {"Type": "iotdevice", "DeviceId": GUID_A, "DeviceName": "192.0.2.1", "IoTHub": {"$ref": "hub"}},
            ]
            mentions, issues = walk_alert_entities(json.dumps(roots))
            self.assertFalse(issues)
            identities.append(next(v for k, v, _ in mentions if k == "iot_device"))
            self.assertFalse(any(k in ("host", "mde_device", "directory_object") for k, _, _ in mentions))
        self.assertNotEqual(*identities)

    def test_mac_forms_are_references_and_placeholder_values_fail(self):
        self.assertEqual(normalize_entity("mac_reference", "58-52-8A-B4-B1-4D"), "58:52:8a:b4:b1:4d")
        for value in ("not-a-mac", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            self.assertIsNone(normalize_entity("mac_reference", value))
        mentions, issues = walk_alert_entities('[{"Type":"nic","MacAddress":"58-52-8A-B4-B1-4D","IpAddress":{"Type":"ip","Address":"192.0.2.1"}}]')
        self.assertFalse(issues)
        self.assertEqual({k for k, _, _ in mentions}, {"ip", "mac_reference"})

    def test_blob_container_name_requires_its_storage_resource(self):
        roots = [
            {"$id": "storage", "Type": "azure-resource", "ResourceId": "/storage/account-one"},
            {"Type": "blob-container", "Name": "data", "StorageResource": {"$ref": "storage"}},
        ]
        mentions, issues = walk_alert_entities(json.dumps(roots))
        self.assertFalse(issues)
        value = next(v for k, v, _ in mentions if k == "blob_container_reference")
        self.assertEqual(json.loads(value), ["/storage/account-one", "data"])
        roots[1].pop("StorageResource")
        mentions, issues = walk_alert_entities(json.dumps(roots))
        self.assertFalse(any(k == "blob_container_reference" for k, _, _ in mentions))
        self.assertTrue(issues)


class GraphBuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle = self.root / "ledger"
        self.bundle.mkdir()
        self.db = self.bundle / "observations.duckdb"
        self.con = duckdb.connect(str(self.db))
        self.con.execute("CREATE TABLE _core_source_references(observation_id VARCHAR,\"table\" VARCHAR,content_sha256 VARCHAR,origins JSON)")
        self.con.execute("CREATE TABLE _historical_memberships(tenant_id VARCHAR,membership JSON)")
        self.con.execute("CREATE TABLE _cases(incident_id INTEGER)")
        self.tables = []

    def tearDown(self):
        self.con.close()

    def add_table(self, name, definitions, rows):
        self.con.execute(f'CREATE TABLE "{name}"(_observation_id VARCHAR,_field_quality VARCHAR,TenantId VARCHAR,{definitions})')
        placeholders = ",".join("?" for _ in rows[0]) if rows else ""
        if rows:
            self.con.executemany(f'INSERT INTO "{name}" VALUES ({placeholders})', rows)
        self.tables.append({"table": name, "observations": len(rows)})

    def run_build(self):
        self.con.close()
        report = {
            "status": "complete", "ledger_id": "fixture-ledger", "tables": self.tables,
            "summary": {"observations": sum(t["observations"] for t in self.tables)},
            "database": {"path": self.db.name, "sha256": file_sha256(self.db), "size_bytes": self.db.stat().st_size},
        }
        (self.bundle / "ledger_report.json").write_text(json.dumps(report))
        output = self.root / "graph"
        result = build_graph(self.bundle, output)
        return output, result

    def test_all_audit_targets_and_actor_roles_keep_paths_and_provenance(self):
        self.add_table("AuditLogs", "TimeGenerated TIMESTAMPTZ,OperationName VARCHAR,InitiatedBy VARCHAR,TargetResources VARCHAR", [
            ("obs:audit", "[]", TENANT, "2024-01-01", "Add member",
             json.dumps({"user": {"id": GUID_A, "userPrincipalName": "u@example.test"}}),
             json.dumps([{"type": "User", "id": GUID_A}, {"type": "Group", "id": GUID_B}]))
        ])
        output, result = self.run_build()
        with duckdb.connect(str(output / "graph.duckdb"), read_only=True) as graph:
            targets = graph.execute("SELECT n.value,e.source_path FROM edges e JOIN nodes n ON n.node_id=e.dst WHERE relation='audit_target' ORDER BY 2").fetchall()
            self.assertEqual(targets, [(GUID_A, "TargetResources[0].id"), (GUID_B, "TargetResources[1].id")])
            self.assertEqual(graph.execute("SELECT count(*) FROM edges WHERE src<>observation_id").fetchone()[0], 0)
        self.assertEqual(result["summary"]["observations"], 1)

    def test_url_click_message_ip_and_every_redirect(self):
        self.add_table("UrlClickEvents", "Timestamp TIMESTAMPTZ,ActionType VARCHAR,AccountUpn VARCHAR,NetworkMessageId VARCHAR,IPAddress VARCHAR,Url VARCHAR,UrlChain VARCHAR", [
            ("obs:click", "[]", TENANT, "2024-01-01", "ClickAllowed", "user@example.test", GUID_A, "192.0.2.1",
             "https://example.test/A", '["http://example.test/A","https://example.test/A"]')
        ])
        output, _ = self.run_build()
        with duckdb.connect(str(output / "graph.duckdb"), read_only=True) as graph:
            roles = {r[0] for r in graph.execute("SELECT relation FROM edges").fetchall()}
            self.assertTrue({"message", "click_ip", "clicking_account", "redirect_chain_member"} <= roles)
            self.assertEqual(graph.execute("SELECT count(*) FROM edges WHERE relation='redirect_chain_member'").fetchone()[0], 2)

    def test_cloud_participants_and_graph_targets_not_first_only(self):
        self.add_table("CloudAppEvents", "Timestamp TIMESTAMPTZ,ApplicationId INTEGER,ActivityObjects VARCHAR", [
            ("obs:cloud", "[]", TENANT, "2024-01-01", 123,
             json.dumps([{"Type": "Account", "Id": GUID_A, "Role": "Actor"},
                         {"Type": "Resource", "Id": "/subscriptions/example", "Role": "Target object"}]))
        ])
        self.add_table("MicrosoftGraphActivityLogs", "TimeGenerated TIMESTAMPTZ,RequestUri VARCHAR,RequestMethod VARCHAR", [
            ("obs:api", "[]", TENANT, "2024-01-01", f"https://graph.microsoft.com/v1.0/users/{GUID_A}/memberOf", "GET")
        ])
        output, _ = self.run_build()
        with duckdb.connect(str(output / "graph.duckdb"), read_only=True) as graph:
            self.assertEqual(graph.execute("SELECT count(*) FROM edges WHERE rule_id='cloud:all_activity_objects'").fetchone()[0], 2)
            self.assertEqual(graph.execute("SELECT count(*) FROM edges WHERE relation='request_target:users'").fetchone()[0], 1)

    def test_graph_signin_reference_joins_token_not_request_identity(self):
        self.add_table("SigninLogs", "CreatedDateTime TIMESTAMPTZ,Id VARCHAR,UniqueTokenIdentifier VARCHAR", [
            ("obs:signin", "[]", TENANT, "2024-01-01", GUID_A, "caseSensitiveToken")
        ])
        self.add_table("MicrosoftGraphActivityLogs", "TimeGenerated TIMESTAMPTZ,SignInActivityId VARCHAR", [
            ("obs:api", "[]", TENANT, "2024-01-01", "caseSensitiveToken")
        ])
        output, _ = self.run_build()
        with duckdb.connect(str(output / "graph.duckdb"), read_only=True) as graph:
            self.assertEqual(graph.execute("SELECT count(*) FROM nodes WHERE kind='token'").fetchone()[0], 1)
            self.assertEqual(graph.execute("SELECT count(*) FROM edges e JOIN nodes n ON n.node_id=e.dst WHERE n.kind='token'").fetchone()[0], 2)
            self.assertEqual(graph.execute("SELECT count(*) FROM edges WHERE relation='signin_token_reference'").fetchone()[0], 1)

    def test_intune_inventory_namespaces_are_not_application_ids(self):
        self.add_table("IntuneDevices", "TimeGenerated TIMESTAMPTZ,DeviceId VARCHAR,DeviceName VARCHAR,PrimaryUser VARCHAR,UserEmail VARCHAR", [
            ("obs:intune", "[]", TENANT, "2024-01-01", GUID_A, "HOST", GUID_B, "user@example.test")
        ])
        output, result = self.run_build()
        self.assertEqual(result["tables"][0]["status"], "extracted")
        with duckdb.connect(str(output / "graph.duckdb"), read_only=True) as graph:
            kinds = {r[0] for r in graph.execute("SELECT kind FROM nodes").fetchall()}
            self.assertEqual(kinds, {"intune_device", "host", "intune_user", "upn"})

    def test_process_identity_is_exact_and_bad_start_is_not_recovered(self):
        self.add_table("DeviceProcessEvents",
                       "Timestamp TIMESTAMPTZ,DeviceName VARCHAR,ProcessId BIGINT,ProcessCreationTime TIMESTAMPTZ,"
                       "InitiatingProcessId BIGINT,InitiatingProcessCreationTime TIMESTAMPTZ,ProcessCommandLine VARCHAR", [
            ("obs:process", "[]", TENANT, "2024-01-01 10:00:00", "host.example.test", 42,
             "2024-01-01 09:59:00", 10, None, "run " + "x" * 11000 + " payload.ps1"),
            ("obs:future", "[]", TENANT, "2024-01-01 10:00:00", "host.example.test", 43,
             "2024-01-02", 11, "2024-01-02", "nothing")
        ])
        output, _ = self.run_build()
        with duckdb.connect(str(output / "graph.duckdb"), read_only=True) as graph:
            self.assertEqual(graph.execute("SELECT count(*) FROM edges WHERE relation='subject_process'").fetchone()[0], 1)
            self.assertEqual(graph.execute("SELECT count(*) FROM edges WHERE relation='initiating_process'").fetchone()[0], 0)
            self.assertEqual(graph.execute("SELECT count(*) FROM edges WHERE semantics='lexical_reference'").fetchone()[0], 1)
            self.assertGreater(graph.execute("SELECT count(*) FROM exclusions").fetchone()[0], 0)

    def test_detector_echo_and_quarantine_are_not_independent_evidence(self):
        self.add_table("DeviceEvents", "Timestamp TIMESTAMPTZ,ActionType VARCHAR,DeviceName VARCHAR", [
            ("obs:echo", "[]", TENANT, "2024-01-01", "OtherAlertRelatedActivity", "host"),
            ("obs:blocked", '[{"column":"DeviceName"}]', TENANT, "2024-01-01", "Event", "host"),
        ])
        output, _ = self.run_build()
        with duckdb.connect(str(output / "graph.duckdb"), read_only=True) as graph:
            self.assertEqual(graph.execute("SELECT lineage FROM observations WHERE observation_id='obs:echo'").fetchone()[0], "detector_derived")
            self.assertEqual(graph.execute("SELECT count(*) FROM edges WHERE observation_id='obs:blocked'").fetchone()[0], 0)
            self.assertTrue(graph.execute("SELECT quarantined FROM observations WHERE observation_id='obs:blocked'").fetchone()[0])

    def test_current_and_historical_memberships_never_merge(self):
        self.add_table("SecurityIncident", "TimeGenerated TIMESTAMPTZ,IncidentNumber INTEGER,AlertIds VARCHAR", [
            ("obs:latest", "[]", TENANT, "2024-01-02", 34, '["alert-current"]')
        ])
        for oid in ("obs:before", "obs:after"):
            self.con.execute("INSERT INTO _core_source_references VALUES (?,'SecurityIncident','hash','[]')", [oid])
        history = {"incident_id": 34, "alert_id": "alert-old", "before_evidence_id": "obs:before", "after_evidence_id": "obs:after"}
        self.con.execute("INSERT INTO _historical_memberships VALUES (?,?)", [TENANT, json.dumps(history)])
        output, result = self.run_build()
        self.assertEqual(result["summary"]["historical_removed_links"], 1)
        with duckdb.connect(str(output / "graph.duckdb"), read_only=True) as graph:
            self.assertEqual(graph.execute("SELECT relation FROM edges e JOIN nodes n ON n.node_id=e.dst WHERE n.value='alert-old'").fetchall(), [("historical_removed_member",)])
            self.assertEqual(graph.execute("SELECT supporting_observation_id FROM edges WHERE relation='historical_removed_member'").fetchone()[0], "obs:after")

    def test_private_alert_entities_include_nonshared_identifiers(self):
        self.add_table("SecurityAlert", "StartTime TIMESTAMPTZ,SystemAlertId VARCHAR,Entities VARCHAR", [
            ("obs:alert", "[]", TENANT, "2024-01-01", "alert-a",
             json.dumps([{"Type": "ip", "Address": "192.0.2.99"}, {"Type": "cloud-logon-request", "RequestId": GUID_A}]))
        ])
        output, _ = self.run_build()
        with duckdb.connect(str(output / "graph.duckdb"), read_only=True) as graph:
            self.assertEqual(graph.execute("SELECT count(*) FROM edges WHERE relation='alert_entity'").fetchone()[0], 2)
            self.assertEqual(graph.execute("SELECT lineage FROM observations").fetchone()[0], "detector_derived")

    def test_file_hash_threat_intel_retains_contextual_source_evidence(self):
        self.add_table("ThreatIntelligenceIndicator", "TimeGenerated TIMESTAMPTZ,FileHashType VARCHAR,FileHashValue VARCHAR", [
            ("obs:ti", "[]", TENANT, "2024-01-01", "SHA256", "A" * 64),
            ("obs:bad-ti", "[]", TENANT, "2024-01-01", "SHA256", "invalid"),
        ])
        output, result = self.run_build()
        with duckdb.connect(str(output / "graph.duckdb"), read_only=True) as graph:
            self.assertEqual(graph.execute("SELECT n.kind,n.value,e.semantics FROM edges e JOIN nodes n ON n.node_id=e.dst").fetchall(),
                             [("sha256", "a" * 64, "contextual")])
            self.assertEqual(graph.execute("SELECT lineage FROM observations WHERE observation_id='obs:ti'").fetchone()[0], "context")
        self.assertEqual(result["summary"]["rejected_identity_mentions"], 1)

    def test_url_domain_and_account_names_are_not_identity_alias_merges(self):
        self.add_table("SecurityAlert", "StartTime TIMESTAMPTZ,SystemAlertId VARCHAR,Entities VARCHAR", [
            ("obs:a", "[]", TENANT, "2024-01-01", "alert-a", json.dumps([
                {"Type": "url", "Url": "https://example.test/Path"},
                {"Type": "account", "Name": "same-name"},
            ]))
        ])
        output, _ = self.run_build()
        with duckdb.connect(str(output / "graph.duckdb"), read_only=True) as graph:
            rows = graph.execute("SELECT n.kind,e.relation,e.semantics FROM edges e JOIN nodes n ON n.node_id=e.dst").fetchall()
            self.assertIn(("domain", "url_host_reference", "lexical_reference"), rows)
            self.assertIn(("account_name_reference", "alert_entity", "contextual_reference"), rows)
            self.assertNotIn("resolved_identity", {r[2] for r in rows})

    def test_source_only_tables_have_explicit_disposition(self):
        self.add_table("Watchlist", "TimeGenerated TIMESTAMPTZ,SearchKey VARCHAR", [("obs:w", "[]", TENANT, "2024-01-01", "key")])
        _, result = self.run_build()
        self.assertEqual(result["tables"][0]["status"], "source_only")
        self.assertTrue(result["tables"][0]["source_only_reason"])

    def test_monitoring_participants_keep_context_lineage_and_exact_source_fields(self):
        arm = "/subscriptions/sub/resourceGroups/rg/providers/type/resource"
        self.add_table("Alert", "TimeGenerated TIMESTAMPTZ,ResourceId VARCHAR", [
            ("obs:alert-context", "[]", TENANT, "2024-01-01", arm)])
        self.add_table("Operation", "TimeGenerated TIMESTAMPTZ,SourceComputerId VARCHAR", [
            ("obs:operation", "[]", TENANT, "2024-01-01", GUID_A)])
        self.add_table("SentinelAudit", "TimeGenerated TIMESTAMPTZ,SentinelResourceId VARCHAR,ExtendedProperties VARCHAR", [
            ("obs:audit", "[]", TENANT, "2024-01-01", arm,
             '{"CallerIpAddress":"192.0.2.1","CallerName":"user@example.test"}')])
        self.add_table("SentinelHealth", "TimeGenerated TIMESTAMPTZ,SentinelResourceId VARCHAR", [
            ("obs:health", "[]", TENANT, "2024-01-01", arm)])
        self.add_table("Usage", "TimeGenerated TIMESTAMPTZ,ResourceUri VARCHAR", [
            ("obs:usage", "[]", TENANT, "2024-01-01", arm)])
        output, result = self.run_build()
        self.assertTrue(all(t["status"] == "extracted" for t in result["tables"]))
        with duckdb.connect(str(output / "graph.duckdb"), read_only=True) as graph:
            rows = graph.execute("SELECT o.table_name,o.lineage,e.relation,e.source_path FROM observations o JOIN edges e USING(observation_id)").fetchall()
            self.assertIn(("SentinelAudit", "metadata", "reported_caller_upn", "ExtendedProperties.CallerName"), rows)
            self.assertIn(("SentinelHealth", "context", "reported_sentinel_resource", "SentinelResourceId"), rows)
            self.assertIn(("Usage", "context", "usage_resource", "ResourceUri"), rows)
            self.assertIn(("Operation", "context", "monitor_source_computer", "SourceComputerId"), rows)

    def test_bookmark_entities_are_context_not_alert_or_independent_behavior(self):
        entities = json.dumps([{"Type": "ip", "Address": "192.0.2.1"},
                               {"Type": "nic", "MacAddress": "58-52-8A-B4-B1-4D"}])
        self.add_table("HuntingBookmark", "TimeGenerated TIMESTAMPTZ,Entities VARCHAR", [
            ("obs:bookmark", "[]", TENANT, "2024-01-01", entities),
            ("obs:quarantined-bookmark", '["Entities"]', TENANT, "2024-01-01", entities),
        ])
        output, _ = self.run_build()
        with duckdb.connect(str(output / "graph.duckdb"), read_only=True) as graph:
            rows = graph.execute("SELECT n.kind,e.relation,e.semantics FROM edges e JOIN nodes n ON n.node_id=e.dst").fetchall()
            self.assertIn(("ip", "bookmark_entity", "contextual"), rows)
            self.assertIn(("mac_reference", "bookmark_entity", "lexical_reference"), rows)
            self.assertEqual(graph.execute("SELECT count(*) FROM edges WHERE observation_id='obs:quarantined-bookmark'").fetchone()[0], 0)
            self.assertEqual(graph.execute("SELECT DISTINCT lineage FROM observations").fetchall(), [("context",)])

    def test_cloud_detection_copies_are_not_independent_behavior(self):
        self.add_table("CloudAppEvents", "Timestamp TIMESTAMPTZ,ActionType VARCHAR,IPAddress VARCHAR", [
            ("obs:detector", "[]", TENANT, "2024-01-01", "TIMailData-Inline", "192.0.2.1"),
            ("obs:investigation", "[]", TENANT, "2024-01-01", "AirInvestigationData", "192.0.2.1"),
            ("obs:action", "[]", TENANT, "2024-01-01", "AdminSubmission", "192.0.2.1"),
        ])
        output, _ = self.run_build()
        with duckdb.connect(str(output / "graph.duckdb"), read_only=True) as graph:
            lineages = dict(graph.execute("SELECT observation_id,lineage FROM observations").fetchall())
            self.assertEqual(lineages, {"obs:detector": "detector_derived", "obs:investigation": "metadata", "obs:action": "behavior"})

    def test_completion_checksum_and_output_guard(self):
        self.add_table("DeviceInfo", "Timestamp TIMESTAMPTZ,DeviceName VARCHAR", [("obs:host", "[]", TENANT, "2024-01-01", "host")])
        before = None
        self.con.execute("CHECKPOINT")
        before = file_sha256(self.db)
        output, result = self.run_build()
        self.assertEqual(file_sha256(self.db), before)
        self.assertEqual(file_sha256(output / "graph.duckdb"), result["database"]["sha256"])
        with self.assertRaisesRegex(ValueError, "new directory"):
            build_graph(self.bundle, output)

    def test_failure_does_not_publish_completed_graph(self):
        self.add_table("DeviceInfo", "Timestamp TIMESTAMPTZ,DeviceName VARCHAR", [("obs:host", "[]", TENANT, "2024-01-01", "host")])
        with patch("secgym.qagen.agentic.graph.scalar_rules", side_effect=ValueError("fixture error")):
            with self.assertRaisesRegex(ValueError, "fixture error"):
                self.run_build()
        self.assertFalse((self.root / "graph/graph_report.json").exists())


if __name__ == "__main__":
    unittest.main()
