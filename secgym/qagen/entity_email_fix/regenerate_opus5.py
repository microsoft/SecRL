#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regenerate excytin QA with Opus 5 for the `latest_cleaned` dataset.

- Uses the entity-email-fixed graphs (``graph_files_fixed/``) so account Email
  entities carry the real UPN.
- Mirrors the exact alert paths used by the o3 (``latest``) dataset so the output
  aligns 1:1 with ``latest`` (same start/end alert + entities + shortest path).
- Resumable (skips questions already saved, keyed by start/end alert) and
  parallel across questions.

Output: ``secgym/questions/opus5/<split>/incident_<id>_qa_opus5_cleaned.json``
"""
import os
import sys
import json
import argparse
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

REPO = os.path.expanduser("~/repos/secrl")
os.chdir(REPO)
sys.path.insert(0, REPO)

from secgym.myconfig import CONFIG_LIST  # noqa: E402
from secgym.qagen.qa_gen import QAGen     # noqa: E402

INCIDENTS = ["5", "34", "38", "39", "55", "134", "166", "322"]
GRAPH = "secgym/qagen/graph_files_fixed/incident_{}.graphml"
O3 = {
    "test": "secgym/questions/o3/v0/test/incident_{}_qa_incident_o3_c100.json",
    "train": "secgym/questions/o3/v0/train/incident_{}_qa_incident_o3_c101_train.json",
}
OUT_DIR = "secgym/questions/opus5"
PATH_KEYS = ["start_alert", "end_alert", "start_entities", "end_entities", "shortest_alert_path"]


def regen_incident(inc, split, workers, limit=0):
    src = O3[split].format(inc)
    if not os.path.exists(src):
        print(f"[skip] no o3 source for incident_{inc}/{split}", flush=True)
        return
    o3_qs = json.load(open(src, encoding="utf-8"))
    if limit:
        o3_qs = o3_qs[:limit]
    out_path = f"{OUT_DIR}/{split}/incident_{inc}_qa_opus5_cleaned.json"
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    existing = {}
    if os.path.exists(out_path):
        for q in json.load(open(out_path, encoding="utf-8")):
            existing[(q.get("start_alert"), q.get("end_alert"))] = q

    qagen = QAGen(
        config_list=CONFIG_LIST, graph_path=GRAPH.format(inc),
        qa_gen_model="opus5", solution_gen_model="opus5",
        cache_seed=41, max_question_count=1,
    )
    results = [None] * len(o3_qs)
    lock = threading.Lock()

    def save():
        with lock:
            json.dump([r for r in results if r], open(out_path, "w", encoding="utf-8"), indent=2)

    def work(i, oq):
        key = (oq.get("start_alert"), oq.get("end_alert"))
        if key in existing:
            return i, existing[key], True
        path_dict = {k: oq[k] for k in PATH_KEYS if k in oq}
        qa = qagen.generate_one_question(path_dict)
        return i, qa, False

    todo = [(i, oq) for i, oq in enumerate(o3_qs)]
    done = 0
    reused = 0
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(work, i, oq): i for i, oq in todo}
        for fut in as_completed(futs):
            try:
                i, qa, was_reused = fut.result()
                results[i] = qa
                reused += 1 if was_reused else 0
            except Exception as e:  # leave unsaved -> retried on resume
                print(f"[{inc}/{split}] question failed: {type(e).__name__}: {str(e)[:120]}", flush=True)
            done += 1
            if done % 5 == 0 or done == len(todo):
                save()
                rate = (time.time() - t0) / max(done - reused, 1)
                print(f"[{inc}/{split}] {done}/{len(todo)} done "
                      f"({reused} reused, ~{rate:.1f}s/new)", flush=True)
    save()
    print(f"[done] incident_{inc}/{split}: {len([r for r in results if r])}/{len(o3_qs)} saved", flush=True)
    return out_path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--incidents", nargs="*", default=INCIDENTS)
    ap.add_argument("--splits", nargs="*", default=["test", "train"])
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--limit", type=int, default=0, help="cap questions per incident/split (smoke test)")
    args = ap.parse_args()

    for split in args.splits:
        for inc in args.incidents:
            regen_incident(inc, split, args.workers, limit=args.limit)


if __name__ == "__main__":
    main()
