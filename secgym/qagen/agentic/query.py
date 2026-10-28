# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Bounded SELECT execution over an explicitly public schema."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from threading import Timer
from typing import Literal

import duckdb
import mysql.connector
import sqlglot
from sqlglot import exp
from sqlglot.optimizer.scope import traverse_scope

from .contracts import Contract, PositiveInt


Scalar = str | int | float | bool | None
Engine = Literal["duckdb", "mysql"]
SAFE_FUNCTIONS = {
    "COUNT", "SUM", "MIN", "MAX", "AVG", "COALESCE", "NULLIF", "CAST", "TRY_CAST",
    "LOWER", "UPPER", "LENGTH", "CHAR_LENGTH", "CONCAT", "CONCAT_WS", "SUBSTRING", "TRIM",
    "ABS", "ROUND", "FLOOR", "CEIL", "JSON_EXTRACT", "JSON_EXTRACT_SCALAR", "JSON_UNQUOTE",
    "JSON_ARRAY_LENGTH", "JSON_LENGTH", "JSON_EACH", "J_S_O_N_TABLE",
    "DATE", "DATE_TRUNC", "DATE_DIFF", "DATE_ADD", "DATE_SUB", "TIMESTAMPDIFF", "YEAR", "MONTH", "DAY",
    "STRFTIME", "STRPTIME", "ROW_NUMBER", "RANK", "DENSE_RANK", "IF", "CASE",
    "AND", "OR", "NOT", "LEFT", "RIGHT",
    "STR_POSITION", "CHR",
}


class QueryLimits(Contract):
    max_rows: PositiveInt
    max_bytes: PositiveInt
    timeout_ms: PositiveInt


class QueryFailure(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class QueryResult:
    columns: tuple[str, ...]
    rows: tuple[tuple[Scalar, ...], ...]


def json_table_source(table: exp.Table, engine: Engine) -> bool:
    return (
        engine == "duckdb" and isinstance(table.this, exp.Anonymous) and table.this.name.upper() == "JSON_EACH"
    ) or (engine == "mysql" and isinstance(table.this, exp.JSONTable))


def checked_select(query: str, engine: Engine, tables: set[str], *, gold: bool = False,
                   allowed_literals: frozenset[str] = frozenset()) -> exp.Expression:
    try:
        statements = sqlglot.parse(query, read=engine)
    except sqlglot.errors.ParseError as error:
        raise QueryFailure("sql_parse", str(error)) from error
    if len(statements) != 1 or not isinstance(statements[0], (exp.Select, exp.SetOperation)):
        raise QueryFailure("sql_not_select", "Exactly one SELECT query is required.")
    tree = statements[0]
    physical = []
    for node in tree.walk():
        if isinstance(node, (exp.DDL, exp.DML, exp.Into, exp.Lock, exp.Command, exp.Parameter, exp.SessionParameter, exp.Hint)):
            raise QueryFailure("sql_disallowed", f"Disallowed SQL construct: {type(node).__name__}")
        if isinstance(node, exp.Func):
            name = node.name.upper() if isinstance(node, exp.Anonymous) else node.sql_name()
            if name not in SAFE_FUNCTIONS:
                raise QueryFailure("sql_function", f"Function is not in the reviewed allowlist: {name}")
        if isinstance(node, exp.Table):
            if node.catalog or node.db or (not isinstance(node.this, exp.Identifier) and not json_table_source(node, engine)):
                raise QueryFailure("sql_external_source", "External, qualified and table-function sources are not allowed.")
        if isinstance(node, exp.Column) and node.name.lower() in {"_observation_id", "_source_schema_id", "_field_quality", "_rid", "rn"}:
            raise QueryFailure("sql_private_column", "Private source columns are not available.")
    try:
        for scope in traverse_scope(tree):
            for _, source in scope.selected_sources.values():
                if isinstance(source, exp.Table):
                    if json_table_source(source, engine):
                        continue
                    if source.name not in tables:
                        raise QueryFailure("sql_private_table", f"Table is not public: {source.name}")
                    physical.append(source.name)
    except sqlglot.errors.OptimizeError as error:
        raise QueryFailure("sql_scope", str(error)) from error
    if gold:
        if not physical or tree.find(exp.Limit) or tree.find(exp.Offset):
            raise QueryFailure("gold_shortcut", "Gold queries require source tables and may not hide competing rows with LIMIT/OFFSET.")
        for literal in tree.find_all(exp.Literal):
            if literal.this not in allowed_literals:
                raise QueryFailure("gold_literal", f"Gold SQL contains an unreviewed literal: {literal.this!r}")
        for predicate in tree.find_all(exp.Predicate):
            # COUNT returns cardinality, not an identifier; inner predicates are still checked.
            values = predicate.walk(prune=lambda node: isinstance(node, exp.Count))
            if any(isinstance(c, exp.Column) and c.name.casefold() == "_record_id" for c in values) and predicate.find(exp.Literal):
                raise QueryFailure("gold_record_shortcut", "Gold SQL may not select evidence through literal record IDs.")
    return tree


def scalar_value(value: object) -> Scalar:
    if isinstance(value, float) and not math.isfinite(value):
        raise QueryFailure("nonfinite_result", "Nonfinite query values are not admissible.")
    if value is None or type(value) in (str, int, float, bool):
        return value
    if isinstance(value, datetime):
        value = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
        return value.isoformat(timespec="microseconds")
    if isinstance(value, Decimal) and value.is_finite() and value == value.to_integral_value():
        return int(value)
    raise QueryFailure("unsupported_result_type", f"Explicitly cast unsupported result type: {type(value).__name__}")


class PublicQueryEngine:
    """The connection must already have read-only access to a public-only database."""

    def __init__(self, connection, engine: Engine, tables: set[str], limits: QueryLimits, serving_view_id: str | None = None):
        self.connection, self.engine, self.tables, self.limits = connection, engine, frozenset(tables), limits
        self.serving_view_id = serving_view_id

    def execute(self, query: str, *, gold: bool = False,
                allowed_literals: frozenset[str] = frozenset()) -> QueryResult:
        if len(query.encode()) > self.limits.max_bytes:
            raise QueryFailure("query_size", "SQL exceeds the configured input byte limit.")
        tree = checked_select(query, self.engine, set(self.tables), gold=gold, allowed_literals=allowed_literals)
        existing = tree.args.get("limit")
        bound = self.limits.max_rows + 1
        if existing is not None:
            limit = existing.expression
            if not isinstance(limit, exp.Literal) or not limit.is_int:
                raise QueryFailure("sql_limit", "LIMIT must be an integer literal.")
            bound = min(bound, int(limit.this))
        bounded = tree.limit(bound).sql(dialect=self.engine, comments=False)
        timer = None
        cursor = None
        try:
            cursor = self.connection if self.engine == "duckdb" else self.connection.cursor()
            if self.engine == "duckdb":
                timer = Timer(self.limits.timeout_ms / 1000, self.connection.interrupt)
                timer.start()
            else:
                cursor.execute(f"SET SESSION MAX_EXECUTION_TIME={self.limits.timeout_ms}")
            cursor.execute(bounded)
            columns = tuple(item[0] for item in cursor.description)
            raw = cursor.fetchall()
            if len(raw) > self.limits.max_rows:
                raise QueryFailure("row_limit", "Query result exceeds the configured row limit; no partial result accepted.")
            rows = tuple(tuple(scalar_value(v) for v in row) for row in raw)
            if len(json.dumps([columns, rows], ensure_ascii=False, allow_nan=False).encode()) > self.limits.max_bytes:
                raise QueryFailure("byte_limit", "Query result exceeds the configured byte limit; no partial result accepted.")
            return QueryResult(columns, rows)
        except (duckdb.Error, mysql.connector.Error) as error:
            raise QueryFailure("query_execution", str(error)) from error
        finally:
            if timer:
                timer.cancel()
                timer.join()
            if self.engine == "mysql" and cursor is not None:
                cursor.close()
