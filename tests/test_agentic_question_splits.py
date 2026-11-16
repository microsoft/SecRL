# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import csv
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from test_agentic_adapters import reviewed_fixture
from test_agentic_i0 import parse_task, task_data
from secgym.qagen.agentic.canonical_facts import CanonicalFactBundle, CanonicalFactReview, CanonicalSourceFact, ResolvedClaimFacts
from secgym.qagen.agentic.contracts import SimilarityWeights, fingerprint
from secgym.qagen.agentic.fact_curation import CURATION_VERSION
from secgym.qagen.agentic.question_splits import (
    RUNTIME_FILES, BucketCounts, SplitPlan, SplitQuestion, SplitRequest,
    audit_splits, checked_cohort, cohort_fingerprint, load_questions, propose_split, write_split_audit,
)
from secgym.qagen.agentic.similarity import EvidenceFootprint, WeightedFeature


ROOT = Path(__file__).resolve().parents[1]


def question(task_id, *, incident=34, column="FileName", value="private-gold.exe", edges=True, subject=None):
    data = task_data()
    data["task_id"] = task_id
    data["question"] = f"Synthetic question about {column}."
    data["private_gold"]["final"]["expected"]["value"] = value
    data["private_gold"]["final"]["programs"][0]["query"] = f"SELECT {column} FROM synthetic_event"
    data["scope"].update(mode="tenant" if incident is None else "incident", incident_id=incident)
    if subject is not None:
        data["evidence"][0]["private_locator"] = subject
    task = parse_task(data)
    reference = task.evidence[0]
    final = CanonicalSourceFact(
        snapshot_id=task.snapshot_id, subject_observation_id=reference.private_locator,
        table=reference.table, column=column, json_path=None, value_json=json.dumps(value),
        lineage="behavior", source_times=(),
    )
    checkpoint = CanonicalSourceFact(
        snapshot_id=task.snapshot_id, subject_observation_id=reference.private_locator,
        table=reference.table, column="DeviceName", json_path=None, value_json='"private-gold-host"',
        lineage="behavior", source_times=(),
    )
    bundle = CanonicalFactBundle(
        task_fingerprint=fingerprint(task), snapshot_id=task.snapshot_id, graph_version=task.graph_version,
        serving_view_id=task.serving_view_id, proposal_fingerprint="a" * 64, facts=(final, checkpoint),
        claims=(ResolvedClaimFacts(claim_id="final", fact_ids=(final.fact_id,)),
                ResolvedClaimFacts(claim_id="private-checkpoint", fact_ids=(checkpoint.fact_id,))),
        limitations=("Synthetic binding fixture, not a real source review.",),
    )
    review = CanonicalFactReview(
        bundle_fingerprint=fingerprint(bundle), recommendation="pass", source_properties_relevant=True,
        subjects_roles_times_preserved=True, claim_coverage_complete=True, no_value_only_merging=True,
        reasons=("Controlled synthetic binding fixture.",),
    )
    baseline = EvidenceFootprint(
        task_fingerprint=fingerprint(task), snapshot_id=task.snapshot_id, graph_version=task.graph_version,
        feature_weight_version="unit-evidence-audit-v1",
        edges=(WeightedFeature(feature_id="edge:fixture", weight=1.0),) if edges else None,
        observations=(WeightedFeature(feature_id=reference.private_locator, weight=1.0),),
        facts=(WeightedFeature(feature_id=f"exact:{task_id}", weight=1.0),),
    )
    return SplitQuestion(task=task, validation=reviewed_fixture(task), baseline=baseline, facts=bundle, review=review)


def write_inputs(root, questions):
    rows = []
    for case in questions:
        folder = root / "cases" / case.task.task_id
        annotation = folder / "annotation"
        (annotation / "reviewer").mkdir(parents=True)
        for path, value in (
            (folder / "task.json", case.task), (folder / "validation.json", case.validation),
            (folder / "baseline.json", case.baseline), (annotation / "canonical-facts.json", case.facts),
            (annotation / "reviewer/result.json", case.review), (annotation / "canonical-footprint.json", case.footprint),
        ):
            path.write_text(value.model_dump_json(indent=2))
        binding = {
            "task_fingerprint": fingerprint(case.task), "validation_fingerprint": fingerprint(case.validation),
            "baseline_fingerprint": fingerprint(case.baseline), "curation_version": CURATION_VERSION,
            "implementation_sha256": {
                name: hashlib.sha256((ROOT / "secgym/qagen/agentic" / name).read_bytes()).hexdigest()
                for name in RUNTIME_FILES
            },
        }
        (annotation / "binding.json").write_text(json.dumps(binding))
        (annotation / "fact_report.json").write_text(json.dumps({
            "task_id": case.task.task_id, "status": "canonical_facts_reviewed",
            "bundle_fingerprint": fingerprint(case.facts),
        }))
        rows.append({
            "task": str((folder / "task.json").relative_to(root)),
            "validation": str((folder / "validation.json").relative_to(root)),
            "baseline": str((folder / "baseline.json").relative_to(root)),
            "annotation": str(annotation.relative_to(root)),
        })
    manifest = root / "inputs.json"
    manifest.write_text(json.dumps({"cohort_label": "fixture-cohort", "questions": rows}))
    return manifest


class QuestionSplitTests(unittest.TestCase):
    def setUp(self):
        self.a = question("first")
        self.b = question("second", column="ProcessCommandLine", value="private-other-command")
        self.cases = (self.a, self.b)

    def request(self, seed=17):
        return SplitRequest(seed=seed, counts=(BucketCounts(bucket="incident:34", train=1, test=1),))

    def legacy_run(self, root, *, historical_layout=False):
        from test_agentic_preproduction_revisions import before_array_length, before_multi_record, before_nested_json
        from secgym.qagen.agentic.preproduction import ModelBinding, PreproductionPlan, runtime_hashes
        from secgym.qagen.agentic.query import QueryLimits

        seed = question("seed").task
        previous = {}
        before, after = root / "before.zip", root / "after.zip"
        with (
            zipfile.ZipFile(before, "x") as old,
            zipfile.ZipFile(after, "x") as new,
            zipfile.ZipFile(root / "before-batches.zip", "x") as intermediate,
            zipfile.ZipFile(root / "before-nested-json.zip", "x") as before_nested,
        ):
            for name in runtime_hashes():
                data = (ROOT / "secgym/qagen/agentic" / name).read_bytes()
                new.writestr(name, data)
                data = before_nested_json(data, name)
                before_nested.writestr(name, data)
                data = before_multi_record(data, name)
                intermediate.writestr(name, data)
                if name == "canonical_facts.py":
                    data = before_array_length(data)
                elif name == "fact_curation.py":
                    data = data.replace(b"source-fact-curation-v1.3", b"source-fact-curation-v1.2")
                previous[name] = hashlib.sha256(data).hexdigest()
                old.writestr(name, data)
        plan = PreproductionPlan(
            batch_id="loader", serving_view_id=seed.serving_view_id, graph_id=seed.graph_version,
            serving_report_sha256="a" * 64, graph_report_sha256="b" * 64,
            model=ModelBinding(deployment="gpt-6-sol", endpoint_sha256="c" * 64, api_version="fixture",
                               request_timeout_seconds=300, max_completion_tokens=16000, reasoning_effort=None),
            query_limits=QueryLimits(max_rows=100, max_bytes=65536, timeout_ms=3000),
            checkpoint_cap=0.5, seed_questions=(seed,), implementation_sha256=previous,
        )
        (root / "plan.json").write_text(plan.model_dump_json())
        case = question(plan.attempts()[0].task_id, incident=5)
        attempt = root / "attempts" / case.task.task_id
        base = attempt / "annotations-r5" if historical_layout else attempt / "pipeline/retained"
        manifest = write_inputs(base, (case,))
        annotation = base / "cases" / case.task.task_id / "annotation"
        binding = json.loads((annotation / "binding.json").read_bytes())
        binding.update(curation_version="source-fact-curation-v1.2",
                       implementation_sha256={name: previous[name] for name in RUNTIME_FILES})
        (annotation / "binding.json").write_text(json.dumps(binding))
        return plan, case, manifest, annotation, before, after

    def approve_legacy_run(self, plan, root, before, after):
        from secgym.qagen.agentic.preproduction_revisions import record_runtime_amendment

        intermediate = root / "before-batches.zip"
        with zipfile.ZipFile(intermediate) as saved:
            hashes = {name: hashlib.sha256(saved.read(name)).hexdigest() for name in plan.implementation_sha256}
        with patch("secgym.qagen.agentic.preproduction_revisions.runtime_hashes", return_value=hashes):
            record_runtime_amendment(
                plan, root, archive=before, current_archive=intermediate, array_length_facts=True,
                reason="Exact additive array/grouping extension for a retained canonical fixture.",
            )
        self.approve_multi_record_and_nested(plan, root, intermediate, after)

    def approve_multi_record_and_nested(self, plan, root, before, after):
        from secgym.qagen.agentic.preproduction_revisions import record_runtime_amendment

        middle = root / "before-nested-json.zip"
        with zipfile.ZipFile(middle) as saved:
            hashes = {name: hashlib.sha256(saved.read(name)).hexdigest() for name in plan.implementation_sha256}
        with patch("secgym.qagen.agentic.preproduction_revisions.runtime_hashes", return_value=hashes):
            record_runtime_amendment(
                plan, root, archive=before, current_archive=middle, multi_record_facts=True,
                reason="Exact lossless multi-record transport extension for retained canonical fixtures.",
            )
        record_runtime_amendment(
            plan, root, archive=middle, current_archive=after, nested_json_facts=True,
            reason="Exact repeated container decoding with unchanged retained scalar facts.",
        )

    def test_legacy_canonical_loader_requires_exact_additive_runtime_approval(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan, case, manifest, annotation, before, after = self.legacy_run(root)
            with self.assertRaisesRegex(ValueError, "annotation binding/runtime"):
                load_questions(manifest)
            self.approve_legacy_run(plan, root, before, after)
            original = {p: p.read_bytes() for p in annotation.rglob("*.json")}
            loaded = load_questions(manifest)
            self.assertEqual(loaded.questions, (case,))
            self.assertIn(str((root / "plan.json").resolve()), loaded.source_hashes)
            self.assertIn(str(before.resolve()), loaded.source_hashes)
            self.assertIn(str(after.resolve()), loaded.source_hashes)
            self.assertIn(str((root / "before-batches.zip").resolve()), loaded.source_hashes)
            self.assertTrue(any("runtime-amendments" in name for name in loaded.source_hashes))
            self.assertEqual({p: p.read_bytes() for p in original}, original)
            with after.open("ab") as stream:
                stream.write(b"changed")
            with self.assertRaisesRegex(ValueError, "updated annotation producer"):
                load_questions(manifest)

    def test_v11_legacy_loader_requires_all_exact_ordered_extensions(self):
        from test_agentic_preproduction_revisions import legacy_canonical_source
        from secgym.qagen.agentic.preproduction_revisions import record_runtime_amendment

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan, case, manifest, annotation, middle, after = self.legacy_run(root)
            before = root / "before-empty.zip"
            previous = {}
            with zipfile.ZipFile(middle) as intermediate, zipfile.ZipFile(before, "x") as old:
                for name in plan.implementation_sha256:
                    data = intermediate.read(name)
                    if name == "canonical_facts.py":
                        data = legacy_canonical_source(data)
                    elif name == "fact_curation.py":
                        data = data.replace(b"source-fact-curation-v1.2", b"source-fact-curation-v1.1")
                    previous[name] = hashlib.sha256(data).hexdigest()
                    old.writestr(name, data)
            intermediate_runtime = plan.implementation_sha256
            plan = plan.model_copy(update={"implementation_sha256": previous})
            (root / "plan.json").write_text(plan.model_dump_json())
            binding_path = annotation / "binding.json"
            binding = json.loads(binding_path.read_bytes())
            binding.update(curation_version="source-fact-curation-v1.1",
                           implementation_sha256={name: previous[name] for name in RUNTIME_FILES})
            binding_path.write_text(json.dumps(binding))
            originals = {path: path.read_bytes() for path in annotation.rglob("*.json")}
            with self.assertRaisesRegex(ValueError, "annotation binding/runtime"):
                load_questions(manifest)
            with patch("secgym.qagen.agentic.preproduction_revisions.runtime_hashes", return_value=intermediate_runtime):
                record_runtime_amendment(
                    plan, root, archive=before, current_archive=middle, empty_array_facts=True,
                    reason="Exact first additive extension.",
                )
            with self.assertRaisesRegex(ValueError, "annotation binding/runtime"):
                load_questions(manifest)
            self.approve_legacy_run(plan, root, middle, after)
            loaded = load_questions(manifest)
            self.assertEqual(loaded.questions, (case,))
            for archive in (before, middle, root / "before-batches.zip", root / "before-nested-json.zip", after):
                self.assertIn(str(archive.resolve()), loaded.source_hashes)
            self.assertEqual(len(list((root / "runtime-amendments").glob("*.json"))), 4)
            self.assertEqual({path: path.read_bytes() for path in originals}, originals)
            (root / "runtime-amendments/0000.json").unlink()
            with self.assertRaisesRegex(ValueError, "continuous chain"):
                load_questions(manifest)

    def test_v13_loader_requires_exact_multi_record_and_nested_chain(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan, case, manifest, annotation, _, after = self.legacy_run(root)
            before = root / "before-batches.zip"
            with zipfile.ZipFile(before) as saved:
                previous = {name: hashlib.sha256(saved.read(name)).hexdigest() for name in plan.implementation_sha256}
            plan = plan.model_copy(update={"implementation_sha256": previous})
            (root / "plan.json").write_text(plan.model_dump_json())
            binding_path = annotation / "binding.json"
            binding = json.loads(binding_path.read_bytes())
            binding.update(curation_version="source-fact-curation-v1.3",
                           implementation_sha256={name: previous[name] for name in RUNTIME_FILES})
            binding_path.write_text(json.dumps(binding))
            original = {path: path.read_bytes() for path in annotation.rglob("*.json")}
            with self.assertRaisesRegex(ValueError, "annotation binding/runtime"):
                load_questions(manifest)
            self.approve_multi_record_and_nested(plan, root, before, after)
            loaded = load_questions(manifest)
            self.assertEqual(loaded.questions, (case,))
            self.assertIn(str(before.resolve()), loaded.source_hashes)
            self.assertEqual({path: path.read_bytes() for path in original}, original)

    def test_v14_loader_requires_exact_nested_json_approval_without_rewriting_facts(self):
        from secgym.qagen.agentic.preproduction_revisions import record_runtime_amendment

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan, case, manifest, annotation, _, after = self.legacy_run(root)
            before = root / "before-nested-json.zip"
            with zipfile.ZipFile(before) as saved:
                previous = {name: hashlib.sha256(saved.read(name)).hexdigest() for name in plan.implementation_sha256}
            plan = plan.model_copy(update={"implementation_sha256": previous})
            (root / "plan.json").write_text(plan.model_dump_json())
            binding_path = annotation / "binding.json"
            binding = json.loads(binding_path.read_bytes())
            binding.update(curation_version="source-fact-curation-v1.4",
                           implementation_sha256={name: previous[name] for name in RUNTIME_FILES})
            binding_path.write_text(json.dumps(binding))
            original = {path: path.read_bytes() for path in annotation.rglob("*.json")}
            with self.assertRaisesRegex(ValueError, "annotation binding/runtime"):
                load_questions(manifest)
            record_runtime_amendment(
                plan, root, archive=before, current_archive=after, nested_json_facts=True,
                reason="Exact nested container decoding; all historical scalar facts remain byte-identical.",
            )
            loaded = load_questions(manifest)
            self.assertEqual(loaded.questions, (case,))
            self.assertIn(str(before.resolve()), loaded.source_hashes)
            self.assertEqual({path: path.read_bytes() for path in original}, original)

    def test_legacy_loader_does_not_waive_version_producer_or_task_bindings(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan, case, manifest, annotation, before, after = self.legacy_run(root)
            self.approve_legacy_run(plan, root, before, after)
            path = annotation / "binding.json"
            original = json.loads(path.read_bytes())
            for change in (
                {"curation_version": "source-fact-curation-v1.1"},
                {"curation_version": CURATION_VERSION},
                {"task_fingerprint": "f" * 64},
                {"implementation_sha256": {**original["implementation_sha256"], "query.py": "f" * 64}},
                {"implementation_sha256": {**original["implementation_sha256"], "canonical_facts.py": "f" * 64}},
            ):
                path.write_text(json.dumps({**original, **change}))
                with self.subTest(change=change), self.assertRaisesRegex(ValueError, "annotation binding/runtime"):
                    load_questions(manifest)
            path.write_text(json.dumps(original))
            report = annotation / "fact_report.json"
            value = json.loads(report.read_bytes())
            report.write_text(json.dumps({**value, "status": "needs_fact_revision"}))
            with self.assertRaisesRegex(ValueError, "annotation report"):
                load_questions(manifest)

    def test_unowned_legacy_annotation_cannot_borrow_another_runs_approval(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = root / "run"
            run.mkdir()
            plan, case, manifest, annotation, before, after = self.legacy_run(run)
            self.approve_legacy_run(plan, run, before, after)
            standalone = write_inputs(root / "standalone", (case,))
            standalone_annotation = root / "standalone/cases" / case.task.task_id / "annotation"
            (standalone_annotation / "binding.json").write_bytes((annotation / "binding.json").read_bytes())
            with self.assertRaisesRegex(ValueError, "annotation binding/runtime"):
                load_questions(standalone)

    def test_owned_historical_layout_requires_an_exact_original_admission_receipt(self):
        from secgym.qagen.agentic.preproduction_admission import AdmissionReceipt
        from secgym.qagen.agentic.question_splits import binding_for

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan, case, manifest, annotation, before, after = self.legacy_run(root, historical_layout=True)
            self.approve_legacy_run(plan, root, before, after)
            with self.assertRaisesRegex(ValueError, "annotation binding/runtime"):
                load_questions(manifest)
            files = ("binding.json", "canonical-facts.json", "reviewer/result.json",
                     "fact_report.json", "canonical-footprint.json")
            receipt = AdmissionReceipt(
                plan_fingerprint=fingerprint(plan), task=binding_for(case), inputs_fingerprint="a" * 64,
                bucket="incident:5", objective_comparison_fingerprint="b" * 64,
                difficulty_status="fixture", difficulty_score=None, difficulty_band=None,
                student_grounded_success=True, implementation_sha256="c" * 64,
                source_artifacts_sha256={
                    str((annotation / name).resolve()): hashlib.sha256((annotation / name).read_bytes()).hexdigest()
                    for name in files
                },
            )
            path = root / "admissions" / (case.task.task_id + ".json")
            path.parent.mkdir()
            original_files = {file: file.read_bytes() for file in annotation.rglob("*.json")}
            path.write_text(receipt.model_dump_json())
            loaded = load_questions(manifest)
            self.assertEqual(loaded.questions, (case,))
            self.assertIn(str(path.resolve()), loaded.source_hashes)
            for change in (
                {"plan_fingerprint": "f" * 64},
                {"task": receipt.task.model_copy(update={"task_fingerprint": "f" * 64})},
                {"source_artifacts_sha256": {**receipt.source_artifacts_sha256,
                                             str((annotation / "binding.json").resolve()): "f" * 64}},
                {"source_artifacts_sha256": {key: value for key, value in receipt.source_artifacts_sha256.items()
                                             if key != str((annotation / "canonical-footprint.json").resolve())}},
            ):
                path.write_text(receipt.model_copy(update=change).model_dump_json())
                with self.subTest(change=tuple(change)), self.assertRaisesRegex(ValueError, "annotation binding/runtime"):
                    load_questions(manifest)
            path.write_text(receipt.model_dump_json())
            self.assertEqual({file: file.read_bytes() for file in original_files}, original_files)

    def test_inventory_does_not_invent_assignments_weights_or_approval(self):
        report = audit_splits(self.cases, cohort_label="fixture")
        self.assertIsNone(report.plan)
        self.assertIsNone(report.weights)
        self.assertEqual(report.counts["incident:34"], {"total": 2, "train": 0, "test": 0, "unassigned": 2})
        self.assertTrue(report.components_complete)
        self.assertIsNone(report.pairs[0].score)
        self.assertEqual(report.pairs[0].score_status, "unweighted")
        self.assertEqual(report.summaries["all"].metrics["score"].available_pairs, 0)
        self.assertFalse(report.shared_evidence_grouping)
        self.assertFalse(report.split_review_approved)
        self.assertFalse(report.release_approved)
        self.assertEqual(report.semantic_duplicate_review, "not_performed")

    def test_shared_checkpoint_records_and_lineage_do_not_force_groups(self):
        plan = propose_split(self.cases, self.request())
        report = audit_splits(self.cases, cohort_label="fixture", plan=plan)
        pair = report.pairs[0]
        self.assertEqual({item.partition for item in plan.assignments}, {"train", "test"})
        self.assertEqual(pair.partition_relation, "train_test")
        self.assertTrue(pair.same_lineage)
        self.assertEqual(pair.shared_observation_count, 1)
        self.assertEqual(pair.shared_fact_count, 1)
        self.assertEqual(pair.components.observations, 1)
        self.assertAlmostEqual(pair.components.facts, 1 / 3)
        self.assertFalse(report.shared_evidence_grouping)

    def test_proposal_is_input_order_independent_and_reproducible(self):
        first = propose_split(self.cases, self.request())
        self.assertEqual(first, propose_split(tuple(reversed(self.cases)), self.request()))
        self.assertEqual(cohort_fingerprint(self.cases), cohort_fingerprint(tuple(reversed(self.cases))))
        self.assertEqual(first.method, "sha256-ranked-v1")
        self.assertEqual(first.request.seed, 17)

    def test_counts_and_seed_are_required_and_counts_cover_every_bucket(self):
        for payload in ({}, {"seed": 1}, {"counts": []}, {"seed": True, "counts": []}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                SplitRequest.model_validate_json(json.dumps(payload))
        for counts in ((BucketCounts(bucket="tenant", train=1, test=1),),
                       (BucketCounts(bucket="incident:34", train=2, test=1),)):
            with self.subTest(counts=counts), self.assertRaises(ValueError):
                propose_split(self.cases, SplitRequest(seed=0, counts=counts))
        with self.assertRaises(ValueError):
            BucketCounts(bucket="incident:34", train=0, test=2)
        with self.assertRaises(ValueError):
            SplitRequest(seed=0, counts=(self.request().counts[0], self.request().counts[0]))

    def test_duplicate_task_ids_and_changed_revisions_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "IDs/revisions"):
            checked_cohort((self.a, self.a))
        with self.assertRaisesRegex(ValueError, "nonempty"):
            checked_cohort(())
        data = self.a.model_dump(mode="json")
        data["task"]["revision_id"] = "r2"
        with self.assertRaisesRegex(ValueError, "not admitted"):
            SplitQuestion.model_validate_json(json.dumps(data))

    def test_failed_native_gate_and_mismatched_fact_review_are_rejected(self):
        data = self.a.model_dump(mode="json")
        data["validation"]["gates"][0]["status"] = "fail"
        with self.assertRaisesRegex(ValueError, "not admitted"):
            SplitQuestion.model_validate_json(json.dumps(data))
        data = self.a.model_dump(mode="json")
        data["review"]["bundle_fingerprint"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "does not bind"):
            SplitQuestion.model_validate_json(json.dumps(data))

    def test_missing_checkpoint_annotation_cannot_enter_split_planning(self):
        data = self.a.model_dump(mode="json")
        data["facts"]["claims"] = [data["facts"]["claims"][0]]
        data["facts"]["facts"] = [data["facts"]["facts"][0]]
        with self.assertRaisesRegex(ValueError, "every checkpoint"):
            SplitQuestion.model_validate_json(json.dumps(data))

    def test_checkpoint_cannot_hide_behind_the_reserved_final_claim_id(self):
        data = self.a.model_dump(mode="json")
        data["task"]["private_gold"]["checkpoints"][0]["checkpoint_id"] = "final"
        task_fp = fingerprint(parse_task(data["task"]))
        data["validation"]["task_fingerprint"] = task_fp
        data["baseline"]["task_fingerprint"] = task_fp
        data["facts"]["task_fingerprint"] = task_fp
        data["facts"]["claims"] = [{
            "claim_id": "final",
            "fact_ids": [fact.fact_id for fact in self.a.facts.facts],
        }]
        data["review"]["bundle_fingerprint"] = fingerprint(CanonicalFactBundle.model_validate_json(json.dumps(data["facts"])))
        with self.assertRaisesRegex(ValueError, "checkpoint ID conflicts"):
            SplitQuestion.model_validate_json(json.dumps(data))

    def test_fact_from_another_claim_or_unused_source_is_rejected(self):
        data = self.a.model_dump(mode="json")
        extra = dict(data["task"]["evidence"][0])
        extra.update(evidence_id="other-evidence", public_record_id="other-public", private_locator="other-observation")
        data["task"]["evidence"].append(extra)
        task_fp = fingerprint(parse_task(data["task"]))
        data["validation"]["task_fingerprint"] = task_fp
        data["baseline"]["task_fingerprint"] = task_fp
        data["baseline"]["observations"].append({"feature_id": "other-observation", "weight": 1.0})
        data["facts"]["task_fingerprint"] = task_fp
        data["facts"]["facts"][0]["subject_observation_id"] = "other-observation"
        changed = CanonicalSourceFact.model_validate_json(json.dumps(data["facts"]["facts"][0]))
        data["facts"]["claims"][0]["fact_ids"] = [changed.fact_id]
        data["review"]["bundle_fingerprint"] = fingerprint(CanonicalFactBundle.model_validate_json(json.dumps(data["facts"])))
        with self.assertRaisesRegex(ValueError, "claim-bound"):
            SplitQuestion.model_validate_json(json.dumps(data))

    def test_cohort_rejects_mixed_source_contexts(self):
        data = self.b.model_dump(mode="json")
        data["task"]["serving_view_id"] = "other-view"
        data["validation"]["task_fingerprint"] = fingerprint(parse_task(data["task"]))
        data["baseline"]["task_fingerprint"] = data["validation"]["task_fingerprint"]
        data["facts"].update(serving_view_id="other-view", task_fingerprint=data["validation"]["task_fingerprint"])
        bundle = CanonicalFactBundle.model_validate_json(json.dumps(data["facts"]))
        data["review"]["bundle_fingerprint"] = fingerprint(bundle)
        different = SplitQuestion.model_validate_json(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "must share"):
            audit_splits((self.a, different), cohort_label="fixture")

    def test_explicit_plan_needs_exact_coverage_current_binding_and_both_sides(self):
        plan = propose_split(self.cases, self.request())
        for changes in (
            {"cohort_fingerprint": "b" * 64},
            {"assignments": [plan.assignments[0].model_dump(mode="json")]},
            {"assignments": [
                {"task_id": item.task_id, "task_fingerprint": item.task_fingerprint, "partition": "train"}
                for item in plan.assignments
            ]},
        ):
            data = plan.model_dump(mode="json")
            data.update(method="explicit", request=None, **changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                audit_splits(self.cases, cohort_label="fixture", plan=SplitPlan.model_validate_json(json.dumps(data)))
        data = plan.model_dump(mode="json")
        data["assignments"][0]["task_fingerprint"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "different task revision"):
            audit_splits(self.cases, cohort_label="fixture", plan=SplitPlan.model_validate_json(json.dumps(data)))

    def test_declared_seed_assignments_cannot_be_tampered_with(self):
        data = propose_split(self.cases, self.request()).model_dump(mode="json")
        for item in data["assignments"]:
            item["partition"] = "test" if item["partition"] == "train" else "train"
        with self.assertRaisesRegex(ValueError, "do not reproduce"):
            audit_splits(self.cases, cohort_label="fixture", plan=SplitPlan.model_validate_json(json.dumps(data)))

    def test_explicit_weights_use_existing_metric_and_zero_weights_do_not_hide_missing_components(self):
        weights = SimilarityWeights(edges=0.25, observations=0.25, facts=0.25, containment=0.25)
        report = audit_splits(self.cases, cohort_label="fixture", weights=weights)
        self.assertAlmostEqual(report.pairs[0].score, 0.75)
        missing = question("missing-edge", edges=False)
        report = audit_splits((self.a, missing), cohort_label="fixture",
                              weights=SimilarityWeights(edges=0.0, observations=1.0, facts=0.0, containment=0.0))
        self.assertFalse(report.components_complete)
        self.assertIsNone(report.pairs[0].components.edges)
        self.assertIsNone(report.pairs[0].score)
        self.assertEqual(report.pairs[0].score_status, "incomplete")
        self.assertEqual(report.summaries["all"].metrics["edges"].available_pairs, 0)
        self.assertIsNone(report.summaries["all"].metrics["edges"].mean)

    def test_equal_answer_strings_on_different_observations_are_not_merged(self):
        other = question("other-observation", subject="another-source-observation")
        report = audit_splits((self.a, other), cohort_label="fixture")
        self.assertEqual(len(report.questions), 2)
        self.assertEqual(report.pairs[0].shared_observation_count, 0)
        self.assertEqual(report.pairs[0].shared_fact_count, 0)
        self.assertEqual(report.pairs[0].components.facts, 0)

    def test_cross_incident_and_cross_benchmark_overlap_are_reported_separately(self):
        cases = (*self.cases, question("other-incident", incident=36),
                 question("tenant-a", incident=None), question("tenant-b", incident=None))
        report = audit_splits(cases, cohort_label="fixture")
        self.assertEqual(len(report.pairs), 10)
        self.assertEqual(report.summaries["same_incident/unassigned"].pair_count, 1)
        self.assertEqual(report.summaries["cross_incident/unassigned"].pair_count, 2)
        self.assertEqual(report.summaries["tenant_incident/unassigned"].pair_count, 6)
        self.assertEqual(report.summaries["tenant_tenant/unassigned"].pair_count, 1)
        self.assertEqual(report.counts["tenant"]["unassigned"], 2)

    def test_bucket_pair_summaries_do_not_depend_on_task_name_orientation(self):
        cases = (question("a", incident=34), question("b", incident=36),
                 question("c", incident=34), question("d", incident=36))
        report = audit_splits(cases, cohort_label="fixture")
        self.assertEqual(report.summaries["incident:34/incident:36/unassigned"].pair_count, 4)
        self.assertNotIn("incident:36/incident:34/unassigned", report.summaries)

    def test_single_question_has_no_fabricated_zero_statistics(self):
        report = audit_splits((self.a,), cohort_label="fixture")
        self.assertEqual(report.summaries["all"].pair_count, 0)
        self.assertIsNone(report.summaries["all"].metrics["facts"].mean)
        self.assertFalse(report.split_review_approved)

    def test_reports_do_not_export_answers_checkpoints_or_sql(self):
        encoded = audit_splits(self.cases, cohort_label="fixture").model_dump_json()
        for private in ("private-gold", "private-other-command", "SELECT", "private-checkpoint", "private-source"):
            self.assertNotIn(private, encoded)

    def test_loader_checks_exact_bindings_runtime_and_saved_footprint(self):
        for mutation in ("binding", "report", "footprint"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                manifest = write_inputs(root, self.cases)
                loaded = load_questions(manifest)
                self.assertEqual(loaded.questions, self.cases)
                self.assertIn(str(manifest.resolve()), loaded.source_hashes)
                folder = root / "cases/first/annotation"
                target = {"binding": "binding.json", "report": "fact_report.json",
                          "footprint": "canonical-footprint.json"}[mutation]
                data = json.loads((folder / target).read_text())
                if mutation == "binding":
                    data["implementation_sha256"]["query.py"] = "0" * 64
                elif mutation == "report":
                    data["status"] = "needs_fact_revision"
                else:
                    data["edges"] = []
                (folder / target).write_text(json.dumps(data))
                with self.assertRaises(ValueError):
                    load_questions(manifest)

    def test_writer_exports_complete_pairs_and_refuses_overwrite_or_annotation_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            loaded = load_questions(write_inputs(root, self.cases))
            report = audit_splits(loaded.questions, cohort_label=loaded.inputs.cohort_label)
            output = root / "audit"
            write_split_audit(report, output, loaded)
            saved = json.loads((output / "split-audit.json").read_text())
            self.assertEqual(saved["source_artifacts_sha256"], loaded.source_hashes)
            with (output / "pair-overlap.csv").open(newline="") as stream:
                pairs = list(csv.DictReader(stream))
            self.assertEqual(len(pairs), 1)
            self.assertEqual(pairs[0]["score"], "")
            self.assertEqual(pairs[0]["score_status"], "unweighted")
            self.assertIn("containment", pairs[0])
            self.assertFalse((output / "split-plan.json").exists())
            for target in (output, root / "cases/first/annotation/audit"):
                with self.assertRaises(ValueError):
                    write_split_audit(report, target, loaded)

    def test_cli_inventory_and_explicit_proposal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = write_inputs(root, self.cases)
            request = root / "request.json"
            request.write_text(self.request().model_dump_json())
            for command in ("audit-question-splits", "propose-question-splits"):
                output = root / command
                arguments = [sys.executable, "-m", "secgym.qagen.agentic", command,
                             "--inputs", str(manifest), "--output", str(output)]
                if command.startswith("propose"):
                    arguments.extend(("--request", str(request)))
                result = subprocess.run(arguments, cwd=ROOT, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                summary = json.loads(result.stdout)
                self.assertFalse(summary["release_approved"])
                self.assertFalse(summary["aggregate_weights_supplied"])
                self.assertEqual((output / "split-plan.json").exists(), command.startswith("propose"))
                self.assertEqual(summary["pairs"], 1)

    def test_cli_failure_does_not_emit_success_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = write_inputs(root, self.cases)
            path = root / "cases/first/task.json"
            data = json.loads(path.read_text())
            data["question"] += " Changed after review."
            path.write_text(json.dumps(data))
            result = subprocess.run(
                [sys.executable, "-m", "secgym.qagen.agentic", "audit-question-splits",
                 "--inputs", str(manifest), "--output", str(root / "audit")],
                cwd=ROOT, capture_output=True, text=True, timeout=30,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not admitted", result.stderr)
            self.assertFalse((root / "audit").exists())

    def test_new_cli_schemas_are_available(self):
        for kind in ("split-inputs", "split-request", "split-plan"):
            result = subprocess.run([sys.executable, "-m", "secgym.qagen.agentic", "schema", kind],
                                    cwd=ROOT, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("properties", json.loads(result.stdout))


if __name__ == "__main__":
    unittest.main()
