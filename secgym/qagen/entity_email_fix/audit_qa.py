#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Audit QA JSON datasets for fabricated ``<DisplayName>@<domain>`` account emails.

Reports, per file, how many fabricated emails appear as the graded ``answer``
(scoring-critical) versus in ``context`` / ``solution`` / other fields.

Example::

    python audit_qa.py --glob "../../questions/o1/**/*.json" \
                       --glob "../../questions/o3/**/*.json"
"""
import argparse
import glob
import json
import os
import re
from collections import defaultdict

MAP_FILE = os.path.join(os.path.dirname(__file__), "fabricated_email_map.json")
TEXT_FIELDS = ["context", "question", "answer", "notes", "hint"]


def load_patterns(map_file):
    with open(map_file, encoding="utf-8") as f:
        doc = json.load(f)
    pats = []  # (regex, canonical_label)
    for fabricated, info in doc["mappings"].items():
        local, _, domain = fabricated.partition("@")
        for v in {fabricated, f"{local.replace(' ', '')}@{domain}"}:
            pats.append((re.compile(re.escape(v), re.IGNORECASE), fabricated))
    return pats


def item_fields(item):
    out = {}
    for k in TEXT_FIELDS:
        v = item.get(k)
        if isinstance(v, str):
            out[k] = v
    sol = item.get("solution")
    if isinstance(sol, list):
        out["solution"] = " \u2016 ".join(str(s) for s in sol)
    elif isinstance(sol, str):
        out["solution"] = sol
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--glob", action="append", required=True)
    parser.add_argument("--map", default=MAP_FILE)
    args = parser.parse_args()
    pats = load_patterns(args.map)

    files = []
    for g in args.glob:
        files.extend(glob.glob(os.path.expanduser(g), recursive=True))

    tot = defaultdict(int)
    per_file = {}
    for path in sorted(set(files)):
        try:
            data = json.load(open(path, encoding="utf-8"))
        except Exception:
            continue
        counts = {"answer": 0, "context": 0, "other": 0}
        for item in data:
            for field, text in item_fields(item).items():
                for rx, _label in pats:
                    hits = len(rx.findall(text))
                    if not hits:
                        continue
                    bucket = "answer" if field == "answer" else (
                        "context" if field == "context" else "other")
                    counts[bucket] += hits
        if any(counts.values()):
            per_file[path] = counts
            for k, v in counts.items():
                tot[k] += v

    for path in sorted(per_file):
        c = per_file[path]
        rel = os.path.relpath(path)
        print(f"  answer={c['answer']:3} context={c['context']:3} other={c['other']:3}  {rel}")
    print("-" * 70)
    print(f"TOTALS: answer(scoring-critical)={tot['answer']}  "
          f"context={tot['context']}  other={tot['other']}")


if __name__ == "__main__":
    main()
