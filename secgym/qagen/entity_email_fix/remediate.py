#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Replace fabricated ``<DisplayName>@<domain>`` account emails with the real UPN.

Reads ``fabricated_email_map.json`` and rewrites matching email tokens in QA
JSON files or task YAML files. Handles the with-space, no-space, and lowercase
variants that the QA-generation model produced. Bare display names (e.g. an
answer of ``Jordan P``) are never touched — only ``<name>@<domain>`` tokens.

Dry-run by default; pass ``--apply`` to write changes.

Examples::

    # remediate the versioned v1 QA JSON copies
    python remediate.py --glob "../../questions/o1/v1/**/*.json" --apply
    python remediate.py --glob "../../questions/o3/v1/**/*.json" --apply
"""
import argparse
import glob
import json
import os
import re
from collections import defaultdict

MAP_FILE = os.path.join(os.path.dirname(__file__), "fabricated_email_map.json")


def load_replacements(map_file):
    with open(map_file, encoding="utf-8") as f:
        doc = json.load(f)
    replacements = []  # (compiled_regex, correct_upn, label)
    for fabricated, info in doc["mappings"].items():
        correct = info["correct_upn"]
        local, _, domain = fabricated.partition("@")
        variants = {fabricated, f"{local.replace(' ', '')}@{domain}"}
        for v in variants:
            replacements.append((re.compile(re.escape(v), re.IGNORECASE), correct, v))
    # longest literal first to avoid partial overlaps
    replacements.sort(key=lambda r: -len(r[2]))
    return replacements


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--glob", action="append", required=True,
                        help="glob(s) of files to remediate (JSON or YAML)")
    parser.add_argument("--map", default=MAP_FILE)
    parser.add_argument("--apply", action="store_true", help="write changes")
    args = parser.parse_args()

    replacements = load_replacements(args.map)
    per_variant = defaultdict(int)
    files_changed = 0
    total = 0

    files = []
    for g in args.glob:
        files.extend(glob.glob(os.path.expanduser(g), recursive=True))
    for path in sorted(set(files)):
        if os.path.isdir(path):
            continue
        with open(path, encoding="utf-8") as f:
            text = f.read()
        new_text = text
        n_file = 0
        for rx, correct, label in replacements:
            new_text, n = rx.subn(correct, new_text)
            if n:
                n_file += n
                per_variant[label] += n
        if n_file:
            files_changed += 1
            total += n_file
            if args.apply:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(new_text)

    mode = "APPLIED" if args.apply else "DRY-RUN (no writes)"
    print(f"{mode}: {total} replacements across {files_changed} files "
          f"({len(files)} scanned)")
    for label, n in sorted(per_variant.items(), key=lambda x: -x[1]):
        print(f"  {n:4}  {label}")


if __name__ == "__main__":
    main()
