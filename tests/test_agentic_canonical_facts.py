# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import tempfile
import unittest
from pathlib import Path

from agentic_runtime_fixture import runtime_fixture, runtime_task
from test_agentic_adapters import reviewed_fixture
from test_agentic_generation import FakeClient, call
from secgym.qagen.agentic.canonical_facts import (
    CanonicalFactReview, CanonicalSourceFact, SourceFactProposal, SourceFactReference, SourceFactResolver,
    canonical_fact_footprint, source_leaf,
)
from secgym.qagen.agentic.contracts import TaskRecord, ValidationReport, fingerprint
from secgym.qagen.agentic.evidence import EvidenceFailure, EvidenceVerifier
from secgym.qagen.agentic.footprints import build_unit_footprint
from secgym.qagen.agentic.fact_curation import curate_source_facts
from secgym.qagen.agentic.mysql_serving import open_duckdb_engine
from secgym.qagen.agentic.query import QueryLimits
from secgym.qagen.agentic.similarity import weighted_overlap


class CanonicalFactTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.graph, _, self.serving, report = runtime_fixture(self.root / "fixture")
        self.task = runtime_task(self.serving, report)
        self.engine = open_duckdb_engine(self.serving, QueryLimits(max_rows=100, max_bytes=65536, timeout_ms=3000))
        self.addCleanup(self.engine.connection.close)
        self.verifier = EvidenceVerifier(self.serving, self.engine, frozenset({"host.test"}))
        self.addCleanup(self.verifier.close)
        self.resolver = SourceFactResolver(self.verifier)
        self.validation = reviewed_fixture(self.task)

    def proposal_data(self):
        citation = {"table": "DeviceProcessEvents", "record_id": self.task.evidence[0].public_record_id}
        return {"claims": [
            {"claim_id": "final", "references": [{"citation": citation, "column": "FileName"}],
             "rationale": "The reported executable field is the final target."},
            {"claim_id": self.task.private_gold.checkpoints[0].checkpoint_id,
             "references": [{"citation": citation, "column": "ProcessId"}],
             "rationale": "The reported process identifier is the intermediate target."},
        ]}

    def resolve(self, data=None, task=None):
        task = task or self.task
        proposal = SourceFactProposal.model_validate_json(json.dumps(data or self.proposal_data()))
        return self.resolver.resolve(task, reviewed_fixture(task), proposal)

    def review(self, bundle):
        return CanonicalFactReview(
            bundle_fingerprint=fingerprint(bundle), recommendation="pass",
            source_properties_relevant=True, subjects_roles_times_preserved=True,
            claim_coverage_complete=True, no_value_only_merging=True, reasons=("Verified fixture.",),
        )

    def test_source_values_not_labels_or_answer_comparison_policy_define_facts(self):
        first = self.resolve()
        data = self.task.model_dump(mode="json")
        data["task_id"] = "different-objective"
        data["context"] = "Another public context for the same verified source properties."
        data["private_gold"]["final"]["expected"]["format"].update(
            semantic_kind="another_descriptive_label", normalization="casefold",
        )
        second_task = TaskRecord.model_validate_json(json.dumps(data))
        second = self.resolve(task=second_task)
        self.assertNotEqual(first.task_fingerprint, second.task_fingerprint)
        self.assertEqual({fact.fact_id for fact in first.facts}, {fact.fact_id for fact in second.facts})
        self.assertEqual({fact.column: fact.value_json for fact in first.facts},
                         {"FileName": '"Tool.EXE"', "ProcessId": "42"})
        self.assertEqual(first.facts[0].source_times[0].value_json, '"2024-01-01T12:00:00.000000+00:00"')

    def test_same_value_different_subject_property_role_or_time_is_not_the_same_fact(self):
        original = next(fact for fact in self.resolve().facts if fact.column == "FileName")
        changes = (
            {"subject_observation_id": "obs:other-event"},
            {"column": "InitiatingProcessFileName"},
            {"column": "AdditionalFields", "json_path": ["target", "FileName"]},
            {"snapshot_id": "snapshot:other"},
            {"source_times": [{"column": "Timestamp", "value_json": '"2024-01-02T12:00:00+00:00"'}]},
        )
        for change in changes:
            data = original.model_dump(mode="json")
            data.update(change)
            with self.subTest(change=change):
                other = CanonicalSourceFact.model_validate_json(json.dumps(data))
                self.assertEqual(other.value_json, original.value_json)
                self.assertNotEqual(other.fact_id, original.fact_id)

    def test_json_leaf_resolution_preserves_exact_values_and_role_paths(self):
        data = self.proposal_data()
        data["claims"][0]["references"][0].update(column="AdditionalFields", json_path=["Nested", "Count"])
        bundle = self.resolve(data)
        fact = next(fact for fact in bundle.facts if fact.column == "AdditionalFields")
        self.assertEqual(fact.value_json, "1.00000000000000000001")
        self.assertEqual(source_leaf('{"Visible":9007199254740993}', ("Visible",)), "9007199254740993")
        self.assertEqual(source_leaf('{"actor":{"Name":"same"},"target":{"Name":"same"}}', ("actor", "Name")), '"same"')
        self.assertNotEqual(source_leaf("true", None), source_leaf("true", ()))
        self.assertEqual(source_leaf(None, None), "null")

    def test_repeated_encoded_containers_preserve_exact_scalar_leaves(self):
        nested = '{"Id":"001","Count":9007199254740993,"Fraction":1.00000000000000000001,"Quoted":"\\"value\\""}'
        for depth in (1, 2, 3):
            encoded = nested
            for _ in range(depth):
                encoded = json.dumps(encoded)
            source = json.dumps({"Policy": encoded})
            with self.subTest(depth=depth):
                self.assertEqual(source_leaf(source, ("Policy", "Id")), '"001"')
                self.assertEqual(source_leaf(source, ("Policy", "Count")), "9007199254740993")
                self.assertEqual(source_leaf(source, ("Policy", "Fraction")), "1.00000000000000000001")
                self.assertEqual(source_leaf(source, ("Policy", "Quoted")), '"\\"value\\""')
                with self.assertRaisesRegex(ValueError, "atomic"):
                    source_leaf(source, ("Policy",))

    def test_repeated_encoded_structural_containers_keep_their_kind_guards(self):
        for original, kind, expected in (
            ([], "json_array_empty_v1", "true"),
            (["same", None, "same"], "json_array_length_v1", "3"),
        ):
            for depth in (1, 2, 3):
                encoded = original
                for _ in range(depth):
                    encoded = json.dumps(encoded)
                with self.subTest(kind=kind, depth=depth):
                    self.assertEqual(source_leaf(encoded, (), kind=kind), expected)
                    self.assertEqual(source_leaf(json.dumps({"Items": encoded}), ("Items",), kind=kind), expected)
                    other = "json_array_length_v1" if not original else "json_array_empty_v1"
                    with self.assertRaises(ValueError):
                        source_leaf(encoded, (), kind=other)

    def test_repeated_encoded_presence_does_not_invent_missing_ancestors(self):
        for depth in (1, 2, 3):
            encoded = {"Present": None}
            for _ in range(depth):
                encoded = json.dumps(encoded)
            source = json.dumps({"Nested": encoded})
            with self.subTest(depth=depth):
                self.assertEqual(source_leaf(source, ("Nested", "Present"), kind="json_member_presence"), "true")
                self.assertEqual(source_leaf(source, ("Nested", "Absent"), kind="json_member_presence"), "false")
                self.assertEqual(source_leaf(source, ("Nested", "Present")), "null")
                with self.assertRaises(ValueError):
                    source_leaf(source, ("Missing", "Absent"), kind="json_member_presence")

    def test_repeated_decoding_still_rejects_malformed_duplicate_and_scalar_containers(self):
        for nested in ('{"Id":1,"Id":2}', "not JSON", "1", "null", '"scalar"'):
            source = json.dumps({"Nested": json.dumps(json.dumps(nested))})
            with self.subTest(nested=nested), self.assertRaises(ValueError):
                source_leaf(source, ("Nested", "Id"))
        for literal in ('"001"', '"\\"quoted\\""', "not JSON", "1", "null"):
            self.assertEqual(source_leaf(literal, None), json.dumps(literal, ensure_ascii=False))

    def test_invalid_missing_ambiguous_and_container_paths_fail_explicitly(self):
        for value, path in (
            ('{"Name":"x"}', ("missing",)),
            ('{"Name":1,"Name":2}', ("Name",)),
            ('{"Items":["x"]}', ("Items", 1)),
            ('{"Items":["x"]}', ("Items", -1)),
            ('{"Items":["x"]}', ("Items",)),
            ('{"Nested":"not JSON"}', ("Nested", "Name")),
            (42, ("Name",)),
        ):
            with self.subTest(value=value, path=path), self.assertRaises(ValueError):
                source_leaf(value, path)

    def test_serialized_containers_cannot_bypass_atomic_fact_selection(self):
        for value, path in (
            ('["alert-a","alert-b"]', None),
            ('{"Actor":"someone"}', None),
            ('{"Nested":"{\\"Actor\\":\\"someone\\"}"}', ("Nested",)),
            (json.dumps(json.dumps(["alert-a"])), None),
        ):
            with self.subTest(value=value, path=path), self.assertRaisesRegex(ValueError, "atomic"):
                source_leaf(value, path)
        self.assertEqual(source_leaf('["alert-a","alert-b"]', (0,)), '"alert-a"')
        self.assertEqual(source_leaf("[opaque process text]", None), '"[opaque process text]"')
        self.assertEqual(source_leaf("NaN", None), '"NaN"')
        self.assertEqual(source_leaf('"quoted scalar"', None), '"\\"quoted scalar\\""')
        fact = next(fact for fact in self.resolve().facts if fact.column == "FileName")
        data = fact.model_dump(mode="json")
        data["value_json"] = json.dumps('["alert-a","alert-b"]')
        with self.assertRaisesRegex(ValueError, "atomic"):
            CanonicalSourceFact.model_validate_json(json.dumps(data))
        with self.assertRaises(ValueError):
            source_leaf('{"Name":1,"Name":2}', None)
        data.update(column="AdditionalFields", json_path=["Flag"], value_json="true")
        property_fact = CanonicalSourceFact.model_validate_json(json.dumps(data))
        presence_fact = CanonicalSourceFact.model_validate_json(json.dumps({**data, "kind": "json_member_presence"}))
        self.assertNotEqual(property_fact.fact_id, presence_fact.fact_id)

    def test_explicit_member_presence_distinguishes_missing_from_null(self):
        path = ("Exec", "Arguments")
        self.assertEqual(source_leaf('{"Exec":{"Command":"run"}}', path, kind="json_member_presence"), "false")
        self.assertEqual(source_leaf('{"Exec":{"Arguments":null}}', path, kind="json_member_presence"), "true")
        self.assertEqual(source_leaf('{"Exec":{"Arguments":null}}', path), "null")
        self.assertEqual(source_leaf('{"Exec":"{\\"Command\\":\\"run\\"}"}', path,
                                     kind="json_member_presence"), "false")
        with self.assertRaises(EvidenceFailure):
            source_leaf('{"Exec":{"Command":"run"}}', path)
        for value, bad_path in (
            ('{}', path), ('{"Exec":null}', path), ('{"Exec":[]}', path),
            ('{"Exec":1}', path), ('{"Exec":{}}', None), ('{"Exec":{}}', ()),
            ('{"Exec":[1]}', ("Exec", 0)), ('{"Exec":{"A":1,"A":2}}', path),
        ):
            with self.subTest(value=value, path=bad_path), self.assertRaises(ValueError):
                source_leaf(value, bad_path, kind="json_member_presence")

    def test_member_presence_is_source_bound_and_cannot_invent_missing_ancestors(self):
        data = self.proposal_data()
        data["claims"][0]["references"][0].update(
            column="AdditionalFields", json_path=["Nested", "Absent"], kind="json_member_presence",
        )
        bundle = self.resolve(data)
        fact = next(fact for fact in bundle.facts if fact.kind == "json_member_presence")
        self.assertEqual(fact.value_json, "false")
        self.assertEqual(fact.json_path, ("Nested", "Absent"))
        data["claims"][0]["references"][0]["json_path"] = ["NotReported", "Absent"]
        with self.assertRaises(EvidenceFailure):
            self.resolve(data)
        ref = data["claims"][0]["references"][0]
        for path in (None, [], ["Nested", 0]):
            with self.subTest(path=path), self.assertRaises(ValueError):
                SourceFactReference.model_validate_json(json.dumps({**ref, "json_path": path}))

    def test_versioned_empty_array_observation_requires_an_actual_empty_array(self):
        for value, path in (
            ("[]", ()),
            ('{"Policies":[{"Controls":[]}]}', ("Policies", 0, "Controls")),
            ('{"Controls":"[]"}', ("Controls",)),
        ):
            with self.subTest(value=value, path=path):
                self.assertEqual(source_leaf(value, path, kind="json_array_empty_v1"), "true")
        for value, path in (
            ("[]", None), ("{}", ()), ("null", ()), ("[null]", ()), ("[[]]", ()),
            ('{"Controls":null}', ("Controls",)), ('{"Controls":[1]}', ("Controls",)),
            ('{}', ("Controls",)), ('{"Controls":[],"Controls":[]}', ("Controls",)),
        ):
            with self.subTest(value=value, path=path), self.assertRaises(ValueError):
                source_leaf(value, path, kind="json_array_empty_v1")

    def test_empty_array_fact_does_not_change_scalar_or_member_presence_identity(self):
        reference = self.proposal_data()["claims"][0]["references"][0]
        reference.update(column="AdditionalFields", json_path=[], kind="json_array_empty_v1")
        parsed = SourceFactReference.model_validate_json(json.dumps(reference))
        self.assertEqual(parsed.json_path, ())
        with self.assertRaises(ValueError):
            SourceFactReference.model_validate_json(json.dumps({**reference, "json_path": None}))
        original = self.resolve().facts[0]
        data = original.model_dump(mode="json")
        data.update(column="AdditionalFields", json_path=["Controls"], value_json="true")
        scalar = CanonicalSourceFact.model_validate_json(json.dumps(data))
        member = CanonicalSourceFact.model_validate_json(json.dumps({**data, "kind": "json_member_presence"}))
        empty = CanonicalSourceFact.model_validate_json(json.dumps({**data, "kind": "json_array_empty_v1"}))
        self.assertEqual(len({scalar.fact_id, member.fact_id, empty.fact_id}), 3)
        for changes in ({"value_json": "false"}, {"value_json": "null"}, {"value_json": "[]"}, {"json_path": None}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                CanonicalSourceFact.model_validate_json(json.dumps({
                    **data, "kind": "json_array_empty_v1", **changes,
                }))

    def test_nonempty_array_length_counts_positions_not_distinct_values(self):
        for value, path, expected in (
            ('["same","same",null,{}]', (), "4"),
            ('{"Items":[1]}', ("Items",), "1"),
            ('{"Outer":[{"Items":[1,2,3]}]}', ("Outer", 0, "Items"), "3"),
            ('{"Items":"[1,2]"}', ("Items",), "2"),
            (json.dumps({"Items": ["same"] * 96}), ("Items",), "96"),
        ):
            with self.subTest(value=value, path=path):
                self.assertEqual(source_leaf(value, path, kind="json_array_length_v1"), expected)

    def test_grouped_references_resolve_to_identical_legacy_facts(self):
        flat = self.proposal_data()
        grouped = self.proposal_data()
        for claim in grouped["claims"]:
            reference, = claim["references"]
            claim["references"] = [{
                "citation": reference["citation"],
                "properties": [{name: value for name, value in reference.items() if name != "citation"}],
            }]
        flat_proposal = SourceFactProposal.model_validate_json(json.dumps(flat))
        grouped_proposal = SourceFactProposal.model_validate_json(json.dumps(grouped))
        self.assertEqual(
            [[fingerprint(ref) for ref in claim.expanded_references] for claim in flat_proposal.claims],
            [[fingerprint(ref) for ref in claim.expanded_references] for claim in grouped_proposal.claims],
        )
        flat_bundle, grouped_bundle = self.resolve(flat), self.resolve(grouped)
        self.assertNotEqual(flat_bundle.proposal_fingerprint, grouped_bundle.proposal_fingerprint)
        self.assertEqual(flat_bundle.model_dump(exclude={"proposal_fingerprint"}),
                         grouped_bundle.model_dump(exclude={"proposal_fingerprint"}))
        reference = flat["claims"][0]["references"][0]
        grouped["claims"][0]["references"].append(reference)
        with self.assertRaisesRegex(ValueError, "claim fact references"):
            SourceFactProposal.model_validate_json(json.dumps(grouped))

    def test_grouped_references_keep_original_scope_path_and_atomicity_guards(self):
        for properties in (
            [], [{"column": "_record_id"}],
            [{"column": "AdditionalFields", "json_path": ["missing"]}],
            [{"column": "AdditionalFields", "json_path": []}],
            [{"column": "AdditionalFields", "kind": "json_array_length_v1"}],
            [{"column": "FileName"}, {"column": "FileName"}],
        ):
            data = self.proposal_data()
            reference, = data["claims"][0]["references"]
            data["claims"][0]["references"] = [{"citation": reference["citation"], "properties": properties}]
            with self.subTest(properties=properties), self.assertRaises(ValueError):
                self.resolve(data)
        data = self.proposal_data()
        reference, = data["claims"][0]["references"]
        data["claims"][0]["references"] = [{
            "citation": {**reference["citation"], "record_id": "r:outside-claim"},
            "properties": [{"column": "FileName"}],
        }]
        with self.assertRaisesRegex(EvidenceFailure, "outside this claim"):
            self.resolve(data)

    def batched_proposal_data(self):
        data = self.proposal_data()
        for claim in data["claims"]:
            reference, = claim["references"]
            claim["references"] = [{
                "table": reference["citation"]["table"],
                "record_ids": [reference["citation"]["record_id"]],
                "properties": [{key: value for key, value in reference.items() if key != "citation"}],
            }]
        return data

    def test_multi_record_transport_preserves_facts_source_times_and_footprints(self):
        flat = self.resolve()
        batched = self.resolve(self.batched_proposal_data())
        self.assertNotEqual(flat.proposal_fingerprint, batched.proposal_fingerprint)
        self.assertEqual(flat.model_dump(exclude={"proposal_fingerprint"}),
                         batched.model_dump(exclude={"proposal_fingerprint"}))
        baseline = build_unit_footprint(self.task, self.validation, self.graph)
        self.assertEqual(canonical_fact_footprint(baseline, flat, self.review(flat)),
                         canonical_fact_footprint(baseline, batched, self.review(batched)))

    def test_multi_record_transport_expands_every_record_property_pair(self):
        data = self.batched_proposal_data()
        batch = data["claims"][0]["references"][0]
        batch["record_ids"].append("r:second-observation")
        batch["properties"].append({"column": "ProcessId"})
        proposal = SourceFactProposal.model_validate_json(json.dumps(data))
        references = proposal.claims[0].expanded_references
        self.assertEqual([(ref.citation.table, ref.citation.record_id, ref.column) for ref in references],
                         [(batch["table"], record_id, column) for record_id in batch["record_ids"]
                          for column in ("FileName", "ProcessId")])

    def test_multi_record_transport_rejects_duplicates_and_retains_scope_and_path_guards(self):
        for change in (
            {"record_ids": []},
            {"record_ids": [self.task.evidence[0].public_record_id] * 2},
            {"properties": []},
            {"properties": [{"column": "FileName"}, {"column": "FileName"}]},
            {"properties": [{"column": "AdditionalFields", "json_path": []}]},
            {"properties": [{"column": "AdditionalFields", "json_path": ["missing"]}]},
            {"properties": [{"column": "_record_id"}]},
            {"record_ids": [self.task.evidence[0].public_record_id, "r:outside-claim"]},
        ):
            data = self.batched_proposal_data()
            data["claims"][0]["references"][0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.resolve(data)
        data = self.batched_proposal_data()
        data["claims"][0]["references"].extend(self.proposal_data()["claims"][0]["references"])
        with self.assertRaisesRegex(ValueError, "claim fact references"):
            SourceFactProposal.model_validate_json(json.dumps(data))

    def test_multi_record_curator_and_reviewer_must_both_inspect_selected_records(self):
        baseline, _, _, query = self.curation_inputs()
        proposal = self.batched_proposal_data()
        review = self.review(self.resolve(proposal)).model_dump(mode="json")
        client = FakeClient([
            call("finish", proposal), query, call("finish", proposal),
            call("finish", review), query, call("finish", review),
        ])
        report = curate_source_facts(
            client=client, task=self.task, validation=self.validation, baseline=baseline,
            resolver=self.resolver, output=self.root / "batch-inspection",
        )
        self.assertEqual(report["status"], "canonical_facts_reviewed")
        self.assertIn("curator must inspect", json.dumps(client.contexts[1]))
        self.assertIn("independently inspect", json.dumps(client.contexts[4]))

    def test_array_length_rejects_missing_empty_and_nonarray_sources(self):
        for value, path in (
            ("[1]", None), ("[]", ()), ("{}", ()), ("null", ()), ("true", ()), ("1", ()),
            ('{"Items":null}', ("Items",)), ('{}', ("Items",)),
            ('{"Items":[1],"Items":[2]}', ("Items",)), ('{"Items":[1]}', ("Items", 1)),
        ):
            with self.subTest(value=value, path=path), self.assertRaises(ValueError):
                source_leaf(value, path, kind="json_array_length_v1")
        self.assertEqual(source_leaf("[]", (), kind="json_array_empty_v1"), "true")
        self.assertEqual(source_leaf('["same","same"]', (1,)), '"same"')
        with self.assertRaisesRegex(ValueError, "atomic"):
            source_leaf('["same","same"]', ())

    def test_array_length_facts_require_positive_integer_extent_and_preserve_kind_identity(self):
        reference = self.proposal_data()["claims"][0]["references"][0]
        reference.update(column="AdditionalFields", json_path=["Items"], kind="json_array_length_v1")
        self.assertEqual(SourceFactReference.model_validate_json(json.dumps(reference)).kind, "json_array_length_v1")
        with self.assertRaises(ValueError):
            SourceFactReference.model_validate_json(json.dumps({**reference, "json_path": None}))
        data = self.resolve().facts[0].model_dump(mode="json")
        data.update(column="AdditionalFields", json_path=["Items"], value_json="96")
        scalar = CanonicalSourceFact.model_validate_json(json.dumps(data))
        extent = CanonicalSourceFact.model_validate_json(json.dumps({**data, "kind": "json_array_length_v1"}))
        self.assertNotEqual(scalar.fact_id, extent.fact_id)
        for change in (
            {"json_path": None}, {"value_json": "0"}, {"value_json": "-1"},
            {"value_json": "1.0"}, {"value_json": "1e2"}, {"value_json": '"96"'},
            {"value_json": "true"}, {"value_json": "null"}, {"value_json": "[]"},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                CanonicalSourceFact.model_validate_json(json.dumps({
                    **data, "kind": "json_array_length_v1", **change,
                }))

    def test_only_claim_bound_public_properties_are_accepted(self):
        mutations = (
            ("column", "Classification"),
            ("column", "_record_id"),
            ("citation", {"table": "DeviceProcessEvents", "record_id": "r:not-in-claim"}),
        )
        for key, value in mutations:
            data = self.proposal_data()
            data["claims"][0]["references"][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(EvidenceFailure):
                self.resolve(data)
        data = self.proposal_data()
        data["claims"].pop()
        with self.assertRaisesRegex(EvidenceFailure, "every checkpoint"):
            self.resolve(data)

    def test_source_hash_and_task_validation_cannot_be_bypassed(self):
        proposal = SourceFactProposal.model_validate_json(json.dumps(self.proposal_data()))
        invalid = ValidationReport(task_id=self.task.task_id, task_fingerprint=fingerprint(self.task),
                                   evaluator_version="fixture", gates=())
        with self.assertRaisesRegex(EvidenceFailure, "validated private-pilot"):
            self.resolver.resolve(self.task, invalid, proposal)
        data = self.task.model_dump(mode="json")
        data["evidence"][0]["content_sha256"] = "0" * 64
        tampered = TaskRecord.model_validate_json(json.dumps(data))
        with self.assertRaisesRegex(EvidenceFailure, "content hash"):
            self.resolve(task=tampered)

    def test_review_bound_canonical_footprint_keeps_old_diagnostics_and_does_not_change_grading(self):
        before = self.task.model_dump_json()
        baseline = build_unit_footprint(self.task, self.validation, self.graph)
        bundle = self.resolve()
        canonical = canonical_fact_footprint(baseline, bundle, self.review(bundle))
        self.assertEqual(canonical.edges, baseline.edges)
        self.assertEqual(canonical.observations, baseline.observations)
        self.assertNotEqual(canonical.facts, baseline.facts)
        self.assertEqual(baseline.feature_weight_version, "unit-evidence-audit-v1")
        self.assertEqual(canonical.feature_weight_version, "unit-canonical-source-facts-v2.1")
        self.assertEqual(weighted_overlap(canonical.facts, canonical.facts), (1.0, 1.0))
        self.assertEqual(self.task.model_dump_json(), before)
        bad_review = self.review(bundle).model_dump(mode="json")
        bad_review["claim_coverage_complete"] = False
        with self.assertRaisesRegex(EvidenceFailure, "independent relevance"):
            canonical_fact_footprint(baseline, bundle, CanonicalFactReview.model_validate_json(json.dumps(bad_review)))
        bad_review["claim_coverage_complete"] = True
        bad_review["bundle_fingerprint"] = "0" * 64
        with self.assertRaisesRegex(EvidenceFailure, "does not bind"):
            canonical_fact_footprint(baseline, bundle, CanonicalFactReview.model_validate_json(json.dumps(bad_review)))

    def curation_inputs(self):
        baseline = build_unit_footprint(self.task, self.validation, self.graph)
        proposal = SourceFactProposal.model_validate_json(json.dumps(self.proposal_data()))
        review = self.review(self.resolve()).model_dump(mode="json")
        query = call("sql", {"query": "SELECT _record_id, FileName, ProcessId FROM DeviceProcessEvents"})
        return baseline, proposal.model_dump(mode="json"), review, query

    def test_curation_inspects_source_in_isolated_roles_and_retains_diagnostics(self):
        baseline, proposal, review, query = self.curation_inputs()
        client = FakeClient([query, call("finish", proposal), query, call("finish", review)])
        before = self.task.model_dump_json()
        output = self.root / "curation"
        report = curate_source_facts(client=client, task=self.task, validation=self.validation,
                                     baseline=baseline, resolver=self.resolver, output=output)
        self.assertEqual(report["status"], "canonical_facts_reviewed")
        self.assertEqual(report["exact_claim_signature_ids"], [f.feature_id for f in baseline.facts])
        self.assertTrue((output / "canonical-footprint.json").exists())
        self.assertEqual(len(client.contexts[2]), 2)
        self.assertNotEqual(client.contexts[0][0], client.contexts[2][0])
        self.assertEqual(self.task.model_dump_json(), before)
        with self.assertRaises(FileExistsError):
            curate_source_facts(client=client, task=self.task, validation=self.validation,
                                baseline=baseline, resolver=self.resolver, output=output)

    def test_uninspected_or_unbound_review_is_corrected_before_acceptance(self):
        baseline, proposal, review, query = self.curation_inputs()
        bad_review = {**review, "bundle_fingerprint": "0" * 64}
        client = FakeClient([
            call("finish", proposal), query, call("finish", proposal),
            call("finish", bad_review), call("finish", review), query, call("finish", review),
        ])
        report = curate_source_facts(client=client, task=self.task, validation=self.validation,
                                     baseline=baseline, resolver=self.resolver, output=self.root / "corrected")
        self.assertEqual(report["status"], "canonical_facts_reviewed")
        self.assertIn("curator must inspect", json.dumps(client.contexts[1]))
        self.assertIn("unbound bundle", json.dumps(client.contexts[4]))
        self.assertIn("independently inspect", json.dumps(client.contexts[5]))

    def test_failed_semantic_review_is_explicitly_unscorable_not_zero(self):
        baseline, proposal, review, query = self.curation_inputs()
        for index, change in enumerate((
            {"recommendation": "revise", "claim_coverage_complete": False},
            {"source_properties_relevant": False},
        )):
            output = self.root / f"held-{index}"
            client = FakeClient([query, call("finish", proposal), query, call("finish", {**review, **change})])
            report = curate_source_facts(client=client, task=self.task, validation=self.validation,
                                         baseline=baseline, resolver=self.resolver, output=output)
            self.assertEqual(report["status"], "needs_fact_revision")
            self.assertTrue((output / "canonical-facts.json").exists())
            self.assertFalse((output / "canonical-footprint.json").exists())

    def test_curation_rejects_mismatched_baseline_before_any_model_call(self):
        baseline, _, _, _ = self.curation_inputs()
        client = FakeClient([])
        with self.assertRaisesRegex(ValueError, "matching validated"):
            curate_source_facts(
                client=client, task=self.task, validation=self.validation,
                baseline=baseline.model_copy(update={"task_fingerprint": "0" * 64}),
                resolver=self.resolver, output=self.root / "mismatched",
            )
        self.assertEqual(client.contexts, [])
        self.assertFalse((self.root / "mismatched").exists())

    def test_fact_revision_preserves_history_and_keeps_review_context_independent(self):
        baseline, proposal, review, query = self.curation_inputs()
        previous = self.root / "previous"
        feedback = {**review, "recommendation": "revise", "claim_coverage_complete": False,
                    "reasons": ["Unique earlier reviewer diagnostic."]}
        curate_source_facts(
            client=FakeClient([query, call("finish", proposal), query, call("finish", feedback)]),
            task=self.task, validation=self.validation, baseline=baseline, resolver=self.resolver, output=previous,
        )
        old_report = (previous / "fact_report.json").read_bytes()
        client = FakeClient([query, call("finish", proposal), query, call("finish", review)])
        report = curate_source_facts(
            client=client, task=self.task, validation=self.validation, baseline=baseline,
            resolver=self.resolver, output=self.root / "revision", revision_from=previous,
        )
        self.assertEqual(report["status"], "canonical_facts_reviewed")
        self.assertIn("Unique earlier reviewer diagnostic.", json.dumps(client.contexts[0]))
        self.assertNotIn("Unique earlier reviewer diagnostic.", json.dumps(client.contexts[2]))
        self.assertEqual((previous / "fact_report.json").read_bytes(), old_report)
        changed = self.task.model_copy(update={"context": "Changed scope."})
        with self.assertRaisesRegex(ValueError, "unchanged task"):
            curate_source_facts(
                client=FakeClient([]), task=changed, validation=reviewed_fixture(changed),
                baseline=baseline.model_copy(update={"task_fingerprint": fingerprint(changed)}),
                resolver=self.resolver, output=self.root / "invalid-revision", revision_from=previous,
            )

    def test_mechanical_invalidation_retains_review_but_supplies_curator_feedback(self):
        baseline, proposal, review, query = self.curation_inputs()
        previous = self.root / "mechanically-held"
        curate_source_facts(
            client=FakeClient([query, call("finish", proposal), query, call("finish", review)]),
            task=self.task, validation=self.validation, baseline=baseline, resolver=self.resolver, output=previous,
        )
        path = previous / "fact_report.json"
        report = json.loads(path.read_text())
        report.update(status="needs_fact_revision", mechanical_issues=["Select only atomic source leaves."])
        path.write_text(json.dumps(report))
        client = FakeClient([query, call("finish", proposal), query, call("finish", review)])
        revised = curate_source_facts(
            client=client, task=self.task, validation=self.validation, baseline=baseline,
            resolver=self.resolver, output=self.root / "mechanically-revised", revision_from=previous,
        )
        self.assertEqual(revised["status"], "canonical_facts_reviewed")
        self.assertIn("Select only atomic source leaves.", json.dumps(client.contexts[0]))
        self.assertNotIn("Select only atomic source leaves.", json.dumps(client.contexts[2]))
        self.assertEqual(json.loads((previous / "reviewer/result.json").read_text()), review)


if __name__ == "__main__":
    unittest.main()
