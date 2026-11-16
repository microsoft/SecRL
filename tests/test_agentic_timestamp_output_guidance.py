import json
import unittest

from secgym.qagen.agentic.checkpoint_batches import AUTHOR_INSTRUCTIONS, DRAFT_INSTRUCTIONS
from secgym.qagen.agentic.contracts import TypedAnswer, exact_timestamp_seconds
from secgym.qagen.agentic.scoring import compare_typed_answers


class TimestampOutputGuidanceTests(unittest.TestCase):
    def test_new_checkpoint_authors_receive_complete_lexical_requirements(self):
        for requirement in (
            "semantic_kind does not normalize collection members",
            "required lexical output format in the public question",
            "matching the actual answer-program",
            "date/time separator, timezone suffix (+00:00 versus Z)",
            "presence and exact fractional",
            "Preserve all source precision",
            "without disclosing any actual answer or intermediate value",
        ):
            with self.subTest(requirement=requirement):
                self.assertIn(requirement, DRAFT_INSTRUCTIONS)

    def test_guidance_does_not_change_legacy_authorship_or_authorize_retained_answer_repairs(self):
        self.assertNotIn("semantic_kind does not normalize collection members", AUTHOR_INSTRUCTIONS)
        self.assertIn("never rewrite completed questions or student answers", DRAFT_INSTRUCTIONS)
        self.assertIn("manufacture a different expected spelling to fit a retained student", DRAFT_INSTRUCTIONS)

    def test_exact_timestamp_set_and_scalar_timestamp_remain_distinct(self):
        left, right = "2024-07-05T00:01:21.177384+00:00", "2024-07-05T00:01:21.177384Z"
        self.assertEqual(exact_timestamp_seconds(left), exact_timestamp_seconds(right))
        for kind, expected_match in (("set", False), ("timestamp", True)):
            with self.subTest(kind=kind):
                def answer(value):
                    return TypedAnswer.model_validate_json(json.dumps({
                        "format": {"kind": kind, "semantic_kind": "utc_timestamp", "normalization": "exact",
                                   "tolerance": 0.0, "units": "seconds" if kind == "timestamp" else None},
                        "value": [value] if kind == "set" else value,
                    }))
                self.assertIs(compare_typed_answers(answer(left), answer(right)), expected_match)


if __name__ == "__main__":
    unittest.main()
