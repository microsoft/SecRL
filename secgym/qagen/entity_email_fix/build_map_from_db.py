#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regenerate ``fabricated_email_map.json`` from the excytin incident databases.

For every account entity in each incident's ``SecurityAlert.Entities`` we
replicate the (now-fixed) ``Name + "@" + UPNSuffix`` synthesis and compare it to
the authoritative ``UserPrincipalName`` / ``AccountName`` + ``DomainName``. Any
synthesized value that is not a real address (space in the local part, or
differs from the account's real UPN and is not a real UPN elsewhere) is recorded
as fabricated, mapped to its correct UPN.

Requires the excytin incident MySQL containers to be running
(``saber-excytin-incident-<id>``), e.g. via a permanent oss_saber environment.
"""
import argparse
import json
import os
import re
import subprocess
from collections import defaultdict

INCIDENTS = ["5", "34", "38", "39", "55", "134", "166", "322"]
CONTAINER = "saber-excytin-incident-{}"
DB = "env_monitor_db"
EXCLUDE = {"root", "system", "guest", "admin", "administrator", "user"}
OUT = os.path.join(os.path.dirname(__file__), "fabricated_email_map.json")


def fetch_account_entities(inc):
    container = CONTAINER.format(inc)
    sql = "SELECT Entities FROM SecurityAlert WHERE Entities LIKE '%\"Type\":\"account\"%';"
    proc = subprocess.run(
        ["docker", "exec", container, "mysql", "-uadmin", "-padmin", DB,
         "-N", "--raw", "--batch", "-e", sql],
        capture_output=True, text=False,
    )
    out = proc.stdout.decode("utf-8", errors="replace")
    accounts = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            arr = json.loads(line)
        except Exception:
            continue
        if isinstance(arr, list):
            for ent in arr:
                if isinstance(ent, dict) and str(ent.get("Type", "")).lower() == "account":
                    accounts.append(ent)
    return accounts


def synth_email(ent):
    name = ent.get("Name")
    suffix = ent.get("UPNSuffix")
    if name and str(name).strip().lower() not in EXCLUDE and suffix:
        return f"{name}@{suffix}"
    return None


def real_upn(ent):
    upn = ent.get("UserPrincipalName")
    if upn:
        return upn
    acct = ent.get("AccountName")
    dom = ent.get("DomainName") or ent.get("UPNSuffix")
    if acct and dom:
        return f"{acct}@{dom}"
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=OUT)
    args = parser.parse_args()

    entities_by_inc = {inc: fetch_account_entities(inc) for inc in INCIDENTS}
    global_real = set()
    for accounts in entities_by_inc.values():
        for ent in accounts:
            ru = real_upn(ent)
            if ru:
                global_real.add(ru.strip().lower())

    def is_fabricated(se, ru):
        if not se:
            return False
        sl = se.strip().lower()
        if sl in global_real:
            return False
        if " " in se.split("@")[0]:
            return True
        if ru and sl != ru.strip().lower():
            return True
        return False

    mappings = {}
    for inc, accounts in entities_by_inc.items():
        for ent in accounts:
            se = synth_email(ent)
            ru = real_upn(ent)
            if is_fabricated(se, ru) and ru:
                mappings[se] = {
                    "correct_upn": ru.strip().lower(),
                    "display_name": ent.get("Name"),
                    "account_name": ent.get("AccountName"),
                    "upn_suffix": ent.get("UPNSuffix"),
                    "incident": inc,
                }

    doc = {
        "description": (
            "Fabricated account emails synthesized as <DisplayName>@<UPNSuffix> "
            "by the pre-fix process_entity_identifiers(), mapped to the real UPN."
        ),
        "source": "excytin incident MySQL databases (SecurityAlert.Entities)",
        "count": len(mappings),
        "mappings": dict(sorted(mappings.items())),
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
    print(f"Wrote {len(mappings)} fabricated-email mappings to {args.out}")
    for k, v in doc["mappings"].items():
        print(f"  {k}  ->  {v['correct_upn']}")


if __name__ == "__main__":
    main()
