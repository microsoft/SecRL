import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import sqlglot

from secgym.qagen.agentic import query as kernel
from secgym.qagen.agentic.contracts import Contract
from secgym.qagen.agentic.fact_curation import FactInspectionTools
from secgym.qagen.agentic.generation import DiscoveryTools, run_role


ROOT = Path(__file__).resolve().parents[2]
MALFORMED = ("SELECT 'unfinished", "SELECT 1 /* unfinished")
LIMITS = kernel.QueryLimits(max_rows=2, max_bytes=4096, timeout_ms=1000)


class SyntheticFinish(Contract):
    acknowledged: bool


class ScriptedClient:
    def __init__(self, query):
        self.query = query
        self.contexts = []

    def complete(self, messages, tools):
        self.contexts.append(json.loads(json.dumps(messages)))
        assert len(self.contexts) <= 2, "unexpected additional synthetic model call"
        name = "sql" if len(self.contexts) == 1 else "finish"
        arguments = {"query": self.query} if name == "sql" else {"acknowledged": True}
        return {"choices": [{"finish_reason": "tool_calls", "message": {
            "role": "assistant", "tool_calls": [{
                "id": "synthetic-" + name, "type": "function",
                "function": {"name": name, "arguments": json.dumps(arguments)},
            }],
        }}]}


def inspection_tools(engine):
    verifier = SimpleNamespace(engine=engine, tables={}, observed_citations=Mock())
    return FactInspectionTools(SimpleNamespace(verifier=verifier)), verifier


class TokenizerGuardTests(unittest.TestCase):
    def test_string_and_comment_refusals_are_query_failures_for_both_dialects_and_gold(self):
        for dialect in ("duckdb", "mysql"):
            for sql in MALFORMED:
                for gold in (False, True):
                    with self.subTest(dialect=dialect, sql=sql, gold=gold):
                        with self.assertRaises(kernel.QueryFailure) as caught:
                            kernel.checked_select(sql, dialect, set(), gold=gold)
                        self.assertEqual(caught.exception.code, "sql_parse")
                        self.assertIsInstance(caught.exception.__cause__, sqlglot.errors.TokenError)
                        self.assertEqual(str(caught.exception), str(caught.exception.__cause__))

    def test_rejected_sql_never_opens_cursor_executes_or_starts_timer(self):
        for dialect in ("duckdb", "mysql"):
            for sql in MALFORMED:
                with self.subTest(dialect=dialect, sql=sql):
                    connection = Mock()
                    engine = kernel.PublicQueryEngine(connection, dialect, set(), LIMITS)
                    with patch.object(kernel, "Timer") as timer:
                        with self.assertRaises(kernel.QueryFailure) as caught:
                            engine.execute(sql)
                        timer.assert_not_called()
                    self.assertEqual(caught.exception.code, "sql_parse")
                    self.assertEqual(connection.mock_calls, [])

    def test_actual_discovery_and_fact_dispatch_preserve_explicit_error_without_credit(self):
        for dialect in ("duckdb", "mysql"):
            for sql in MALFORMED:
                for inspected in (False, True):
                    with self.subTest(dialect=dialect, sql=sql, inspected=inspected):
                        connection = Mock()
                        engine = kernel.PublicQueryEngine(connection, dialect, set(), LIMITS)
                        tools, verifier = inspection_tools(engine)
                        dispatch = tools if inspected else DiscoveryTools(engine, {})
                        with self.assertRaises(kernel.QueryFailure) as caught:
                            dispatch.dispatch("sql", {"query": sql})
                        self.assertEqual(caught.exception.code, "sql_parse")
                        self.assertEqual(connection.mock_calls, [])
                        verifier.observed_citations.assert_not_called()
                        self.assertEqual(tools.observed, set())

    def test_synthetic_role_journals_refusal_then_can_finish_without_backend_or_observations(self):
        configured = os.environ.get("TOKENIZER_TEST_OUTPUT")
        if configured is not None:
            outputs = Path(configured).resolve()
            self.assertTrue(outputs.is_relative_to(ROOT))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="tokenizer-guard-test-")
            self.addCleanup(temporary.cleanup)
            outputs = Path(temporary.name)
        for dialect in ("duckdb", "mysql"):
            for index, sql in enumerate(MALFORMED):
                with self.subTest(dialect=dialect, sql=sql):
                    connection = Mock()
                    engine = kernel.PublicQueryEngine(connection, dialect, set(), LIMITS)
                    tools, verifier = inspection_tools(engine)
                    client = ScriptedClient(sql)
                    output = outputs / f"{dialect}-{index}"
                    result = run_role(client, tools, "quality-refuter", "Synthetic guard test only.",
                                      {}, SyntheticFinish, output)
                    self.assertTrue(result.acknowledged)
                    first_results = json.loads((output / "0000-tool-results.json").read_bytes())
                    self.assertEqual(len(first_results), 1)
                    self.assertEqual(first_results[0]["tool_call_id"], "synthetic-sql")
                    feedback = json.loads(first_results[0]["content"])
                    self.assertEqual(set(feedback), {"error", "detail"})
                    self.assertEqual(feedback["error"], "sql_parse")
                    self.assertIn("Error tokenizing", feedback["detail"])
                    self.assertEqual(client.contexts[1][-1], first_results[0])
                    self.assertEqual(json.loads((output / "complete.json").read_bytes())["calls"], 2)
                    self.assertEqual(connection.mock_calls, [])
                    verifier.observed_citations.assert_not_called()
                    self.assertEqual(tools.observed, set())

    def test_unrelated_parser_faults_are_not_misclassified_as_invalid_sql(self):
        for dialect in ("duckdb", "mysql"):
            parser = kernel._MySQLQueryParser if dialect == "mysql" else sqlglot
            with self.subTest(dialect=dialect), patch.object(parser, "parse", side_effect=RuntimeError("bug")):
                with self.assertRaisesRegex(RuntimeError, "bug"):
                    kernel.checked_select("SELECT 1", dialect, set())


@unittest.skipUnless((ROOT / "baseline/secgym/qagen/agentic/query.py").is_file(),
                     "requires the explicit private M5 baseline qualification fixture")
class M5SerializationPreservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        name = "secgym.qagen.agentic._tokenizer_m5_baseline"
        spec = importlib.util.spec_from_file_location(name, ROOT / "baseline/secgym/qagen/agentic/query.py")
        cls.baseline = importlib.util.module_from_spec(spec)
        sys.modules[name] = cls.baseline
        spec.loader.exec_module(cls.baseline)

    def test_valid_ast_bounded_sql_and_result_serialization_match_m5_exactly(self):
        prefix = "WITH a AS (SELECT 1 x), b AS (SELECT 1 x), c AS (SELECT 1 x) "
        mysql_only = [
            prefix + "SELECT a.x FROM a " + join for join in (
                "JOIN b RIGHT JOIN c ON c.x=b.x", ", b RIGHT JOIN c ON c.x=b.x",
                "JOIN b, c", ", b JOIN c", "JOIN (b JOIN c)",
                "JOIN b ON a.x=b.x", "JOIN b USING(x)", "NATURAL JOIN b",
                "CROSS JOIN b", "INNER JOIN b", "LEFT JOIN b ON a.x=b.x",
                "JOIN b JOIN c ON b.x=c.x ON a.x=b.x",
            )
        ]
        mysql_only.append(
            "WITH s AS (SELECT 'u' UserId, '[1]' details), r AS (SELECT 'u' UserId) "
            "SELECT s.UserId FROM s JOIN /* not a comma */ "
            "JSON_TABLE(s.details, '$[*]' COLUMNS(v TEXT PATH '$')) p "
            "LEFT JOIN r ON r.UserId=s.UserId"
        )
        common = [
            "SELECT 1 AS value", "SELECT 'it''s valid' AS value /* closed */",
            "SELECT 'JOIN x, y' AS value -- complete line comment",
            "WITH a AS (SELECT 1 x) SELECT x FROM a LIMIT 1 OFFSET 1",
            "SELECT 1 AS value UNION ALL SELECT 2",
        ]
        for dialect in ("duckdb", "mysql"):
            cases = common + (mysql_only if dialect == "mysql" else [])
            for sql in cases:
                with self.subTest(dialect=dialect, sql=sql):
                    old = self.baseline.checked_select(sql, dialect, set())
                    new = kernel.checked_select(sql, dialect, set())
                    self.assertEqual(new.dump(), old.dump())
                    self.assertEqual(new.limit(3).sql(dialect=dialect, comments=False),
                                     old.limit(3).sql(dialect=dialect, comments=False))
                    emitted = []
                    for module in (self.baseline, kernel):
                        connection = Mock()
                        cursor = connection if dialect == "duckdb" else connection.cursor.return_value
                        cursor.description = (("value",),)
                        cursor.fetchall.return_value = [("unchanged",)]
                        result = module.PublicQueryEngine(connection, dialect, set(), LIMITS).execute(sql)
                        emitted.append((cursor.execute.call_args_list,
                                        json.dumps({"columns": result.columns, "rows": result.rows})))
                    self.assertEqual(emitted[0], emitted[1])


if __name__ == "__main__":
    unittest.main()
