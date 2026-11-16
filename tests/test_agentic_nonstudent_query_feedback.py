import json
import unittest

import sqlglot

import test_agentic_robustness as fixtures
from test_agentic_generation import FakeClient, call
from secgym.qagen.agentic.contracts import fingerprint
from secgym.qagen.agentic.preproduction_pipeline import (
    _NonStudentSourceQueryEngine, _nonstudent_source_queries, inspected_role,
)
from secgym.qagen.agentic.query import QueryFailure
from secgym.qagen.agentic.robustness import RobustnessPlan


class NonstudentQueryFeedbackTests(unittest.TestCase):
    setUp = fixtures.RobustnessFixtureTests.setUp
    unchanged = fixtures.RobustnessFixtureTests.unchanged
    representation_case = fixtures.RobustnessFixtureTests.representation_case

    def test_registered_author_receives_explicit_parser_feedback_without_citation_credit(self):
        proposal = RobustnessPlan(task_fingerprint=fingerprint(self.task), cases=(self.representation_case(),))
        client = FakeClient([call("sql", {"query": "SELECT 'unfinished"}),
                             call("finish", proposal.model_dump(mode="json"))])
        original = self.verifier.engine
        observed = []
        result = inspected_role(
            client, self.verifier, self.root / "author", "robustness-author", "Inspect sources.",
            {"task_fingerprint": fingerprint(self.task)}, RobustnessPlan,
            lambda value, tools: observed.append(set(tools.observed)),
        )
        self.assertEqual(result, proposal)
        self.assertEqual(observed, [set()])
        self.assertEqual(len(client.contexts), 2)
        feedback = json.loads(client.contexts[1][-1]["content"])
        self.assertEqual(feedback["error"], "sql_parse")
        self.assertIn("Error tokenizing", feedback["detail"])
        self.assertIs(self.verifier.engine, original)
        self.assertEqual(json.loads((self.root / "author/complete.json").read_bytes())["calls"], 2)

    def test_student_role_and_original_engine_receive_root_tokenizer_refusal(self):
        original = self.verifier.engine
        proposal = RobustnessPlan(task_fingerprint=fingerprint(self.task), cases=(self.representation_case(),))
        for role in ("blind", "native-blind"):
            client = FakeClient([call("sql", {"query": "SELECT 'unfinished"}),
                                 call("finish", proposal.model_dump(mode="json"))])
            observed = []
            with self.subTest(role=role):
                result = inspected_role(
                    client, self.verifier, self.root / role, role, "Synthetic student guard test.",
                    {}, RobustnessPlan, lambda value, tools: observed.append(set(tools.observed)),
                )
                self.assertEqual(result, proposal)
                self.assertEqual(observed, [set()])
                feedback = json.loads(client.contexts[1][-1]["content"])
                self.assertEqual(feedback["error"], "sql_parse")
                self.assertTrue((self.root / role / "0000-tool-results.json").exists())
            self.assertIs(self.verifier.engine, original)
        with self.assertRaises(QueryFailure) as caught:
            original.execute("SELECT 'unfinished")
        self.assertEqual(caught.exception.code, "sql_parse")
        self.assertIsInstance(caught.exception.__cause__, sqlglot.errors.TokenError)

    def test_scoped_guard_preserves_root_gold_refusal(self):
        original = self.verifier.engine
        with _nonstudent_source_queries(self.verifier):
            self.assertIsInstance(self.verifier.engine, _NonStudentSourceQueryEngine)
            with self.assertRaises(QueryFailure) as caught:
                self.verifier.engine.execute("SELECT 'unfinished", gold=True)
            self.assertEqual(caught.exception.code, "sql_parse")
            self.assertIsInstance(caught.exception.__cause__, sqlglot.errors.TokenError)
        self.assertIs(self.verifier.engine, original)

    def test_successful_queries_schema_limits_and_connection_are_unchanged(self):
        original = self.verifier.engine
        expected = original.execute("SELECT * FROM DeviceProcessEvents")
        with _nonstudent_source_queries(self.verifier):
            guarded = self.verifier.engine
            self.assertIs(guarded.connection, original.connection)
            self.assertEqual((guarded.tables, guarded.limits, guarded.serving_view_id),
                             (original.tables, original.limits, original.serving_view_id))
            self.assertEqual(guarded.execute("SELECT * FROM DeviceProcessEvents"), expected)
            with self.assertRaises(QueryFailure):
                guarded.execute("DELETE FROM DeviceProcessEvents")
        self.assertIs(self.verifier.engine, original)

    def test_scoped_guard_restores_engine_after_exception_and_nested_scope(self):
        original = self.verifier.engine
        with self.assertRaises(QueryFailure):
            with _nonstudent_source_queries(self.verifier):
                outer = self.verifier.engine
                with _nonstudent_source_queries(self.verifier):
                    self.assertIsNot(self.verifier.engine, outer)
                self.assertIs(self.verifier.engine, outer)
                self.verifier.engine.execute("SELECT 'unfinished")
        self.assertIs(self.verifier.engine, original)


if __name__ == "__main__":
    unittest.main()
