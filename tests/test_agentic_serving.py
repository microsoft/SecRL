# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

import duckdb
import sqlglot

from agentic_runtime_fixture import runtime_fixture
from secgym.qagen.agentic.query import PublicQueryEngine, QueryFailure, QueryLimits, checked_select
from secgym.qagen.agentic.mysql_serving import prepared_insert_statement
from secgym.qagen.agentic.serving import ColumnProjection, ConditionalJsonRemoval, ServingPolicy, export_public_view, project_json, redact_json, row_digest


class ServingProjectionTests(unittest.TestCase):
    def test_prepared_batches_reuse_native_placeholders_with_a_bounded_parameter_count(self):
        statement = prepared_insert_statement("Events", 60, 512, True)
        self.assertIs(statement, prepared_insert_statement("Events", 60, 512, True))
        self.assertNotIn("%s", statement)
        self.assertEqual(statement.count("?"), 30720)
        self.assertIn("ON DUPLICATE KEY UPDATE _record_id=_record_id", statement)
        with self.assertRaises(ValueError):
            prepared_insert_statement("Events", 405, 512, False)
    def test_cached_row_hash_preserves_the_original_serialization_contract(self):
        columns, row = ("A", "B", "C"), ("space \u00e9 ", 1.25, None)
        expected = hashlib.sha256(json.dumps([columns, row], separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()).hexdigest()
        self.assertEqual(row_digest(columns, row), expected)
        self.assertEqual(row_digest(columns, row), expected)

    def test_native_underscore_columns_are_not_confused_with_internal_ids(self):
        self.assertEqual(ColumnProjection(name="_ResourceId", action="keep", reason="Native source resource.").name, "_ResourceId")

    def test_projection_streams_across_transaction_batches_without_losing_rows(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, _, serving, report = runtime_fixture(Path(temporary), extra_rows=600)
            self.assertEqual(report["tables"][0]["rows"], 602)
            with duckdb.connect(str(serving / "private_mapping.duckdb"), read_only=True) as con:
                self.assertEqual(con.execute("SELECT count(*),count(DISTINCT record_id) FROM record_map").fetchone(), (602, 602))

    def test_nested_encoded_projection_preserves_numbers_and_array_positions(self):
        value = '[{"Keep":9007199254740993,"Verdict":"hidden"},{"Verdict":"hidden"}]'
        self.assertEqual(project_json(value, (("*", "Keep"),)), '[{"Keep":9007199254740993},{}]')
        self.assertEqual(project_json('{"Encoded":"{\\"Keep\\":1.00000000000000000001,\\"Verdict\\":\\"hidden\\"}"}',
                                      (("Encoded", "Keep"),)), '{"Encoded":"{\\"Keep\\":1.00000000000000000001}"}')
        with self.assertRaises(ValueError):
            project_json('{"Keep":"{\\"Verdict\\":\\"hidden\\"}"}', (("Keep",),))
        with self.assertRaises(ValueError):
            project_json('{"Keep":1,"Keep":2}', (("Keep",),))

    def test_targeted_redaction_preserves_native_verdicts_and_literal_commands(self):
        source = '{"Classification":"BenignPositive","Verdict":"Malware","CommandLine":"[System.Environment]::Exit(0)","Data":"{\\"Investigations\\":[{\\"Id\\":1,\\"InvestigationStatus\\":\\"Safe\\"}],\\"Count\\":1.00000000000000000001}"}'
        result = redact_json(source, (("Classification",), ("Data", "Investigations", "*", "InvestigationStatus")))
        self.assertNotIn("BenignPositive", result)
        self.assertNotIn("InvestigationStatus", result)
        self.assertIn('"Verdict":"Malware"', result)
        self.assertIn("1.00000000000000000001", result)
        self.assertEqual(json.loads(result)["CommandLine"], "[System.Environment]::Exit(0)")
        untouched = '{ "CommandLine" : "[not JSON]", "Count": 1.00000000000000000001 }'
        self.assertEqual(redact_json(untouched, (("Classification",),)), untouched)

    def test_investigation_only_payload_can_be_removed_without_parsing_duplicate_keys(self):
        condition = ConditionalJsonRemoval(field="Operation", values=("AirInvestigationData",), paths=(("Data",), ("Status",)))
        source = '{"Operation":"AirInvestigationData","Status":"Resolved","Data":"{\\"Status\\":\\"A\\",\\"Status\\":\\"B\\"}","UserId":"actor"}'
        result = json.loads(redact_json(source, (), (condition,)))
        self.assertEqual(result, {"Operation": "AirInvestigationData", "UserId": "actor"})
        unrelated = source.replace("AirInvestigationData", "ConcreteResponseAction")
        self.assertEqual(redact_json(unrelated, (), (condition,)), unrelated)

    def test_public_database_excludes_private_metadata_and_policy_is_exhaustive(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            graph, policy, serving, report = runtime_fixture(root)
            with duckdb.connect(str(serving / "public.duckdb"), read_only=True) as con:
                self.assertEqual(con.execute("SHOW TABLES").fetchall(), [("DeviceProcessEvents",)])
                columns = [row[0] for row in con.execute("DESCRIBE DeviceProcessEvents").fetchall()]
                self.assertNotIn("Classification", columns)
                self.assertNotIn("_observation_id", columns)
                self.assertNotIn("_field_quality", columns)
                self.assertNotIn("private-verdict", str(con.execute("SELECT * FROM DeviceProcessEvents").fetchall()))
            self.assertFalse(report["release_approved"])
            self.assertEqual(report["tables"][0]["quarantined_rows_excluded"], 1)
            with duckdb.connect(str(serving / "private_mapping.duckdb"), read_only=True) as con:
                self.assertEqual(con.execute("SELECT count(*) FROM record_map").fetchone()[0], 2)
            bad = policy.model_dump(mode="json")
            bad["source_ledger_sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "exact source snapshot"):
                export_public_view(graph, ServingPolicy.model_validate_json(json.dumps(bad)), root / "wrong-source")
            self.assertFalse((root / "wrong-source").exists())
            bad = policy.model_dump(mode="json")
            bad["tables"][0]["columns"].pop()
            with self.assertRaisesRegex(ValueError, "policy/schema mismatch"):
                export_public_view(graph, ServingPolicy.model_validate_json(json.dumps(bad)), root / "bad")
            self.assertFalse((root / "bad/serving_report.json").exists())


class QueryGuardTests(unittest.TestCase):
    def test_record_id_counts_are_not_literal_record_id_selection(self):
        for engine in ("duckdb", "mysql"):
            query = "SELECT Name FROM Events GROUP BY Name HAVING COUNT(DISTINCT _record_id)=2"
            with self.subTest(engine=engine):
                checked_select(query, engine, {"Events"}, gold=True, allowed_literals=frozenset({"2"}))
            for predicate in (
                "_record_id='r:gold'",
                "_RECORD_ID='r:gold'",
                "MIN(_record_id)='r:gold'",
                "MAX(_record_id)='r:gold'",
                "COUNT(CASE WHEN _record_id='r:gold' THEN 1 END)=2",
            ):
                with self.subTest(engine=engine, predicate=predicate), self.assertRaisesRegex(QueryFailure, "literal record IDs"):
                    checked_select(f"SELECT COUNT(*) FROM Events HAVING {predicate}", engine, {"Events"}, gold=True,
                                   allowed_literals=frozenset({"r:gold", "1", "2"}))
        with duckdb.connect() as con:
            con.execute("CREATE TABLE Events(_record_id VARCHAR, Name VARCHAR)")
            con.execute("INSERT INTO Events VALUES ('r:a','pair'),('r:b','pair'),('r:c','single')")
            engine = PublicQueryEngine(con, "duckdb", {"Events"}, QueryLimits(max_rows=10, max_bytes=4096, timeout_ms=1000))
            self.assertEqual(engine.execute(query, gold=True, allowed_literals=frozenset({"2"})).rows, (("pair",),))

    def test_reviewed_date_arithmetic_preserves_nested_source_and_function_restrictions(self):
        for query in (
            "SELECT DATE_ADD(Started, INTERVAL 5 MINUTE) FROM Events",
            "SELECT DATE_SUB(Started, INTERVAL 5 MINUTE) FROM Events",
            "SELECT TIMESTAMPDIFF(MICROSECOND, Started, Finished) FROM Events",
            "SELECT TRIM(CHAR(92) FROM CommandLine) FROM Events",
        ):
            with self.subTest(query=query):
                checked_select(query, "mysql", {"Events"})
        for query in (
            "SELECT DATE_SUB((SELECT secret FROM private_mapping), INTERVAL 5 MINUTE) FROM Events",
            "SELECT TIMESTAMPDIFF(SECOND, LOAD_FILE(Name), Finished) FROM Events",
        ):
            with self.subTest(query=query), self.assertRaises(QueryFailure):
                checked_select(query, "mysql", {"Events"})
        with self.assertRaisesRegex(QueryFailure, "unreviewed literal"):
            checked_select("SELECT DATE_SUB(Started, INTERVAL 5 MINUTE) FROM Events",
                           "mysql", {"Events"}, gold=True)
        checked_select("SELECT DATE_SUB(Started, INTERVAL 5 MINUTE) FROM Events",
                       "mysql", {"Events"}, gold=True, allowed_literals=frozenset({"5"}))

    def test_json_array_expansion_matches_parameters_by_name_not_position(self):
        with duckdb.connect() as con:
            con.execute("CREATE TABLE Events(Details VARCHAR)")
            values = [{"Name": "Subject", "Value": "message"}, {"Name": "ForwardTo", "Value": "user@example.test"}]
            con.executemany("INSERT INTO Events VALUES (?)", [(json.dumps(values),), (json.dumps(list(reversed(values))),)])
            engine = PublicQueryEngine(con, "duckdb", {"Events"}, QueryLimits(max_rows=10, max_bytes=4096, timeout_ms=1000))
            result = engine.execute("SELECT json_extract_string(j.value,'$.Value') FROM Events e, json_each(e.Details) AS j WHERE json_extract_string(j.value,'$.Name')='ForwardTo'")
            self.assertEqual(result.rows, (("user@example.test",), ("user@example.test",)))
        for sql in ("SELECT * FROM json_each((SELECT secret FROM private_table))",
                    "SELECT * FROM json_each(read_json('/etc/passwd'))",
                    "SELECT * FROM json_each(query_table('private_table'))"):
            with self.subTest(sql=sql), self.assertRaises(QueryFailure):
                checked_select(sql, "duckdb", {"Events"})

    def test_disallowed_sql_and_hidden_sources_fail_closed(self):
        for query in (
            "DELETE FROM Events", "SELECT 1; SELECT 2", "SELECT * FROM private_mapping",
            "SELECT * FROM information_schema.tables", "SELECT * FROM read_csv('/etc/passwd')",
            "SELECT load_file('/etc/passwd')", "SELECT sleep(20)", "SELECT @@version",
            "SELECT _observation_id FROM Events", "SELECT * FROM Events FOR UPDATE",
            "WITH private_mapping AS (SELECT * FROM private_mapping) SELECT * FROM private_mapping",
            "SELECT /*+ SET_VAR(max_execution_time=0) */ * FROM Events",
        ):
            with self.subTest(query=query), self.assertRaises(QueryFailure):
                checked_select(query, "mysql", {"Events"})

    def test_gold_limited_constant_and_hidden_selector_queries_are_rejected(self):
        for query in ("SELECT 1", "SELECT FileName FROM Events LIMIT 1",
                      "SELECT FileName FROM Events WHERE Name='private-gold'",
                      "SELECT FileName FROM Events WHERE _record_id='r:gold'"):
            with self.subTest(query=query), self.assertRaises(QueryFailure):
                checked_select(query, "duckdb", {"Events"}, gold=True, allowed_literals=frozenset({"r:gold"}))
        checked_select("WITH x AS (SELECT FileName FROM Events) SELECT * FROM x", "duckdb", {"Events"}, gold=True)
        checked_select("SELECT _ResourceId FROM Events", "duckdb", {"Events"})
        checked_select("SELECT LEFT(Name,3) FROM Events WHERE A=1 AND (B=2 OR NOT C=3)", "duckdb", {"Events"})
        checked_select("SELECT LOCATE(Path,CommandLine) FROM Events", "mysql", {"Events"})
        checked_select("SELECT STRPOS(CommandLine,Path) FROM Events", "duckdb", {"Events"})
        checked_select("SELECT JSON_LENGTH(Details) FROM Events", "mysql", {"Events"})

    def test_result_limits_are_errors_not_partial_success_and_order_is_preserved(self):
        with duckdb.connect() as con:
            con.execute("CREATE TABLE Events(n INTEGER)")
            con.execute("INSERT INTO Events VALUES (2),(1),(3)")
            engine = PublicQueryEngine(con, "duckdb", {"Events"}, QueryLimits(max_rows=2, max_bytes=1024, timeout_ms=1000))
            with self.assertRaisesRegex(QueryFailure, "row limit"):
                engine.execute("SELECT n FROM Events ORDER BY n")
            self.assertEqual(engine.execute("SELECT n FROM Events ORDER BY n DESC LIMIT 2").rows, ((3,), (2,)))
            self.assertEqual(engine.execute("SELECT COUNT(*) FROM Events").rows, ((3,),))


class MySQLQuerySerializationTests(unittest.TestCase):
    def setUp(self):
        self.connection = Mock()
        self.cursor = self.connection.cursor.return_value
        self.cursor.description = (("UserId",),)
        self.cursor.fetchall.return_value = [("u",), ("v",)]
        self.engine = PublicQueryEngine(
            self.connection, "mysql", set(), QueryLimits(max_rows=2, max_bytes=4096, timeout_ms=1000),
        )
        self.query = (
            "WITH s AS (SELECT 'u' AS UserId, '[1]' AS details UNION ALL SELECT 'v','[2]'), "
            "i AS (SELECT 1 n), r AS (SELECT 'u' AS UserId UNION ALL SELECT 'v') "
            "SELECT s.UserId FROM s JOIN i ON i.n=1 "
            "JOIN JSON_TABLE(s.details,'$[*]' COLUMNS(v TEXT PATH '$')) p "
            "LEFT JOIN r ON r.UserId=s.UserId"
        )

    def emitted(self, query):
        self.engine.execute(query)
        self.cursor.close.assert_called()
        return self.cursor.execute.call_args.args[0]

    def test_explicit_json_table_join_keeps_its_precedence_when_bounded(self):
        expected = self.query.replace("JOIN JSON_TABLE", "INNER JOIN JSON_TABLE")
        self.assertEqual(
            self.emitted(self.query),
            sqlglot.parse_one(expected, read="mysql").limit(3).sql(dialect="mysql", comments=False),
        )
        for query in (
            self.query.replace("JOIN JSON_TABLE", "join /* JOIN fake, */ JSON_TABLE"),
            "SELECT * FROM (" + self.query + ") nested",
            "WITH nested AS (" + self.query + ") SELECT * FROM nested",
            self.query + " UNION ALL SELECT 'w'",
        ):
            with self.subTest(query=query):
                rendered = self.emitted(query)
                self.assertIn("INNER JOIN JSON_TABLE", rendered)
                self.assertNotIn("fake", rendered)

    def test_real_comma_joins_are_not_promoted_to_explicit_joins(self):
        prefix = "WITH a AS (SELECT 1 x WHERE FALSE), b AS (SELECT 1 x), c AS (SELECT 1 x) "
        for source, expected in (
            ("a, b RIGHT JOIN c ON c.x=b.x", "a, b RIGHT JOIN c ON c.x=b.x"),
            ("a JOIN b RIGHT JOIN c ON c.x=b.x", "a INNER JOIN b RIGHT JOIN c ON c.x=b.x"),
            ("a JOIN b, c", "a INNER JOIN b, c"),
            ("a, b JOIN c", "a, b INNER JOIN c"),
            ("a JOIN (b JOIN c)", "a INNER JOIN (b INNER JOIN c)"),
        ):
            with self.subTest(source=source):
                self.assertEqual(
                    self.emitted(prefix + "SELECT c.x FROM " + source),
                    sqlglot.parse_one(prefix + "SELECT c.x FROM " + expected, read="mysql")
                    .limit(3).sql(dialect="mysql", comments=False),
                )
        query = self.query.replace("JOIN JSON_TABLE", ", JSON_TABLE")
        self.assertEqual(
            self.emitted(query), sqlglot.parse_one(query, read="mysql").limit(3).sql(dialect="mysql"),
        )

    def test_join_conditions_modifiers_and_delayed_conditions_are_unchanged(self):
        prefix = "WITH a AS (SELECT 1 x), b AS (SELECT 1 x), c AS (SELECT 1 x) SELECT a.x FROM a "
        for join in (
            "JOIN b ON a.x=b.x", "JOIN b USING(x)", "NATURAL JOIN b", "CROSS JOIN b",
            "INNER JOIN b", "LEFT JOIN b ON a.x=b.x", "RIGHT OUTER JOIN b USING(x)",
            "JOIN b JOIN c ON b.x=c.x ON a.x=b.x", "LEFT JOIN b",
        ):
            with self.subTest(join=join):
                query = prefix + join
                self.assertEqual(
                    self.emitted(query), sqlglot.parse_one(query, read="mysql").limit(3).sql(dialect="mysql"),
                )
        query = "SELECT 'JOIN b, c' AS `JOIN` FROM (SELECT 1 x) a JOIN (SELECT 2 x) b"
        rendered = self.emitted(query)
        self.assertIn("'JOIN b, c' AS `JOIN`", rendered)
        self.assertIn("INNER JOIN (SELECT 2 AS x)", rendered)

    def test_join_fix_keeps_limits_and_validation_failures(self):
        self.cursor.fetchall.return_value = [("v",)]
        rendered = self.emitted(self.query + " LIMIT 1 OFFSET 1")
        self.assertTrue(rendered.endswith("LIMIT 1 OFFSET 1"))
        self.assertIn("INNER JOIN JSON_TABLE", rendered)
        for query, code in (
            (self.query + " LIMIT 1.5", "sql_limit"),
            (self.query + "; SELECT 2", "sql_not_select"),
            (self.query + " FOR UPDATE", "sql_disallowed"),
            (self.query.replace("s.details,", "LOAD_FILE('x'),"), "sql_function"),
            (self.query.replace("s.details,", "(SELECT x FROM private_table),"), "sql_private_table"),
            (self.query.replace("LEFT JOIN r", "LEFT JOIN hidden.r"), "sql_external_source"),
            (self.query.replace("SELECT s.UserId FROM s", "SELECT s._observation_id FROM s"), "sql_private_column"),
            (self.query.replace("JOIN JSON_TABLE", "JOIN ON JSON_TABLE"), "sql_parse"),
        ):
            with self.subTest(query=query):
                self.connection.reset_mock()
                with self.assertRaises(QueryFailure) as caught:
                    self.engine.execute(query)
                self.assertEqual(caught.exception.code, code)
                self.connection.cursor.assert_not_called()
        self.cursor.fetchall.return_value = [("u",), ("v",), ("w",)]
        with self.assertRaises(QueryFailure) as caught:
            self.engine.execute(self.query)
        self.assertEqual(caught.exception.code, "row_limit")


if __name__ == "__main__":
    unittest.main()
