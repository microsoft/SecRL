# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

import duckdb

from secgym.qagen.agentic.graph_compare import compare_legacy_alert_graphs, old_graph_nodes


class LegacyComparisonTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "incident_34.graphml"
        self.con = duckdb.connect(config={"memory_limit": "256MB", "threads": 1})
        self.addCleanup(self.con.close)
        self.con.execute("CREATE SCHEMA new")
        self.con.execute("CREATE TABLE new.nodes(node_id VARCHAR,tenant_id VARCHAR,kind VARCHAR,value VARCHAR)")
        self.con.execute("CREATE TABLE new.edges(dst VARCHAR,observation_id VARCHAR,relation VARCHAR)")
        self.con.execute("INSERT INTO new.nodes VALUES ('alert-node','tenant','alert','alert-a'),('ip-node','tenant','ip','192.0.2.1')")
        self.con.execute("INSERT INTO new.edges VALUES ('alert-node','obs:a','alert_record'),('ip-node','obs:a','alert_entity')")

    def graphml(self, field="Address", value="192.0.2.1", kind="ip"):
        root = ET.Element("graphml", xmlns="http://graphml.graphdrawing.org/xmlns")
        keys = ("type", "entry", "node_type", "identifier_fields", "value")
        for key in keys:
            ET.SubElement(root, "key", {"id": key, "attr.name": key})
        graph = ET.SubElement(root, "graph", edgedefault="undirected")
        for nid, data in (("0", {"type": "alert", "entry": json.dumps({"SystemAlertId": "alert-a", "TenantId": "tenant"})}),
                          ("1", {"type": "entity", "node_type": kind, "identifier_fields": field, "value": value})):
            node = ET.SubElement(graph, "node", id=nid)
            for k, v in data.items():
                ET.SubElement(node, "data", key=k).text = v
        ET.SubElement(graph, "edge", source="0", target="1")
        ET.ElementTree(root).write(self.path, encoding="utf-8", xml_declaration=True)

    def test_preserved_identifier_and_relationship(self):
        self.graphml()
        nodes, edges = old_graph_nodes(self.path)
        self.assertEqual((len(nodes), len(edges)), (2, 1))
        result = compare_legacy_alert_graphs(self.con, [self.path])[0]
        self.assertEqual(result["resolved_alerts"], 1)
        self.assertEqual(result["edge_status_counts"], {"reported_entity_preserved": 1})

    def test_node_elsewhere_does_not_count_as_same_alert_relationship(self):
        self.graphml()
        self.con.execute("UPDATE new.edges SET observation_id='obs:other' WHERE relation='alert_entity'")
        result = compare_legacy_alert_graphs(self.con, [self.path])[0]
        self.assertEqual(result["edge_status_counts"], {"identifier_elsewhere_not_same_alert": 1})

    def test_compound_process_identity_is_not_guessed(self):
        self.graphml(field="ProcessId__CreatedTimeUtc__CommandLine", value="42|ambiguous", kind="process")
        result = compare_legacy_alert_graphs(self.con, [self.path])[0]
        self.assertEqual(result["edge_status_counts"], {"requires_contextual_identity_mapping": 1})

    def test_case_variant_is_not_claimed_as_exact_preservation_or_total_absence(self):
        self.graphml(field="Name", value="tool.exe", kind="file")
        self.con.execute("INSERT INTO new.nodes VALUES ('file','tenant','file_reference','Tool.exe')")
        result = compare_legacy_alert_graphs(self.con, [self.path])[0]
        self.assertEqual(result["edge_status_counts"], {"case_variant_requires_platform_context": 1})

    def test_account_name_preserved_only_as_weak_reference(self):
        self.graphml(field="Name", value="local-user", kind="account")
        self.con.execute("INSERT INTO new.nodes VALUES ('name','tenant','account_name_reference','local-user')")
        self.con.execute("INSERT INTO new.edges VALUES ('name','obs:a','alert_entity')")
        result = compare_legacy_alert_graphs(self.con, [self.path])[0]
        self.assertEqual(result["edge_status_counts"], {"reported_reference_preserved": 1})

    def test_basename_inside_source_path_is_not_missing_or_identity_proof(self):
        self.graphml(field="ExtractedFileName", value="tool.ps1", kind="process")
        self.con.execute("INSERT INTO new.nodes VALUES ('path','tenant','file_reference','C:\\Scripts\\tool.ps1')")
        result = compare_legacy_alert_graphs(self.con, [self.path])[0]
        self.assertEqual(result["edge_status_counts"], {"path_component_requires_context": 1})

    def test_invalid_ip_and_missing_identifier_are_visible(self):
        for value, expected in (("999.1.1.1", "invalid_or_unsupported_legacy_identifier"),
                                ("192.0.2.44", "identifier_not_represented")):
            with self.subTest(value=value):
                self.graphml(value=value)
                self.assertEqual(compare_legacy_alert_graphs(self.con, [self.path])[0]["edge_status_counts"], {expected: 1})

    def test_tenant_ambiguity_never_picks_an_arbitrary_alert(self):
        self.graphml()
        self.con.execute("DELETE FROM new.nodes WHERE kind='alert'")
        self.con.execute("INSERT INTO new.nodes VALUES ('a1','other','alert','alert-a'),('a2','third','alert','alert-a')")
        result = compare_legacy_alert_graphs(self.con, [self.path])[0]
        self.assertEqual(result["resolved_alerts"], 0)
        self.assertEqual(result["edge_status_counts"], {"alert_identity_missing_or_ambiguous": 1})

    def test_single_alert_in_wrong_tenant_is_not_a_match(self):
        self.graphml()
        self.con.execute("UPDATE new.nodes SET tenant_id='other' WHERE kind='alert'")
        self.assertEqual(compare_legacy_alert_graphs(self.con, [self.path])[0]["resolved_alerts"], 0)


if __name__ == "__main__":
    unittest.main()
