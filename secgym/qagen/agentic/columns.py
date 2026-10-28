# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Evidence-reviewed column aliases, never a blanket case-insensitive merge."""

from __future__ import annotations

from collections import defaultdict

import duckdb

from .contracts import Contract, NonnegativeInt, Text
from .sources import quote_identifier


COLUMN_POLICY_VERSION = "azure-diagnostics-aliases-v1"
DIAGNOSTIC_ALIASES = {
    "clientIp_s": ("clientIP_s", "clientIp_s"),
    "socketIp_s": ("socketIP_s", "socketIp_s"),
    "errorInfo_s": ("errorInfo_s", "ErrorInfo_s"),
    "hostName_s": ("hostName_s", "hostname_s"),
    "originIp_s": ("originIp_s", "originIP_s"),
    "pop_s": ("pop_s", "POP_s"),
    "probeUrl_s": ("probeUrl_s", "probeURL_s"),
}
# Verified physical names in the imported database, not a general "_1" rule.
BASELINE_ORIGINAL_NAMES = {
    "clientIp_s_1": "clientIp_s", "socketIp_s_1": "socketIp_s",
    "ErrorInfo_s_1": "ErrorInfo_s", "hostname_s_1": "hostname_s",
    "originIP_s_1": "originIP_s", "POP_s_1": "POP_s", "probeURL_s_1": "probeURL_s",
}


class ColumnBinding(Contract):
    position: NonnegativeInt
    original_name: Text
    storage_name: Text
    canonical_name: Text


def column_bindings(names: list[str], table: str, *, baseline: bool = False) -> tuple[ColumnBinding, ...]:
    if len(set(names)) != len(names) or any(not name.strip() for name in names):
        raise ValueError("duplicate or blank original column names")
    alias_lookup = {name: canonical for canonical, aliases in DIAGNOSTIC_ALIASES.items() for name in aliases}
    occupied = {name.casefold() for name in names}
    used = set()
    result = []
    for position, name in enumerate(names):
        original = BASELINE_ORIGINAL_NAMES.get(name, name) if baseline and table == "AzureDiagnostics" else name
        canonical = alias_lookup.get(original, original) if table == "AzureDiagnostics" else original
        storage = name
        if storage.casefold() in used:
            if baseline:
                raise ValueError("case-colliding physical baseline columns")
            suffix = 1
            while f"{name}_{suffix}".casefold() in occupied | used:
                suffix += 1
            storage = f"{name}_{suffix}"
        used.add(storage.casefold())
        result.append(ColumnBinding(position=position, original_name=original, storage_name=storage, canonical_name=canonical))
    return tuple(result)


def canonical_groups(bindings: tuple[ColumnBinding, ...]) -> dict[str, list[ColumnBinding]]:
    groups: dict[str, list[ColumnBinding]] = defaultdict(list)
    case_names = {}
    for binding in bindings:
        name = binding.canonical_name
        other = case_names.setdefault(name.casefold(), name)
        if other != name:
            raise ValueError(f"unapproved case-colliding fields: {other}, {name}")
        groups[name].append(binding)
    return dict(groups)


def checked_projection(
    con: duckdb.DuckDBPyConnection, relation: str, bindings: tuple[ColumnBinding, ...], locator: str,
    *, table: str,
) -> str:
    """Return a projection only after checking all populated aliases for conflicts."""
    types = {r[0]: r[1] for r in con.execute(f"DESCRIBE SELECT * FROM {relation}").fetchall()}
    projection = []
    for canonical, group in canonical_groups(bindings).items():
        columns = [quote_identifier(b.storage_name) for b in group]
        if table != "AzureDiagnostics" or canonical not in DIAGNOSTIC_ALIASES:
            if len(group) != 1:
                raise ValueError(f"unapproved duplicate field: {canonical}")
            expression = columns[0]
        else:
            if any(types[b.storage_name] != "VARCHAR" for b in group):
                raise ValueError(f"alias group requires text columns: {canonical}")
            values = [f"nullif({column},'')" for column in columns]
            conflicts = [f"({left} IS NOT NULL AND {right} IS NOT NULL AND {left}<>{right})"
                         for i, left in enumerate(values) for right in values[i + 1:]]
            if conflicts:
                rows = con.execute(
                    f"SELECT {quote_identifier(locator)} FROM {relation} WHERE "
                    + " OR ".join(conflicts) + f" ORDER BY {quote_identifier(locator)} LIMIT 5"
                ).fetchall()
                if rows:
                    raise ValueError(f"conflicting nonempty aliases for {canonical}; source records {[r[0] for r in rows]}")
            expression = values[0] if len(values) == 1 else f"coalesce({','.join(values)})"
        projection.append(f"{expression} AS {quote_identifier(canonical)}")
    return ", ".join(projection)
