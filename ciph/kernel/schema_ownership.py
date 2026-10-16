"""
ciph/kernel/schema_ownership - one SQL table name has at most one canonical owner.

This module exists because of R4: two subsystems both declared `ciph_observations`, with different
shapes and `CREATE TABLE IF NOT EXISTS`, so whichever initialized first silently won. The failure was
invisible until a `CiphRuntime` and the 4.2 epistemic ledger shared one database, at which point they
were mutually exclusive.

The fix was a rename, but a rename is not a guarantee. This module makes the guarantee structural:

    every `CREATE TABLE` in the project is scanned
    -> the table name and its canonical column set are recorded
    -> two INCOMPATIBLE declarations for one name is a reported defect

It also classifies a LIVE database by schema fingerprint rather than by guessing from a table name,
and performs the one explicit, verified migration that hands the legacy name back to the ledger.
"""

from dataclasses import dataclass
import hashlib
import json
import pathlib
import re
import sqlite3
from typing import Any, Dict, List, Optional, Sequence, Tuple

_CREATE_TABLE = re.compile(r"CREATE\s+TABLE\s+", re.IGNORECASE)
# The name is read in a second step, and it may be a TEMPLATE placeholder (`{HEADER_TABLE}`). A
# single regex that folds the optional `IF NOT EXISTS` into the name capture backtracks onto the word
# `IF` whenever the name is a placeholder, which silently invents a table called "if".
_TABLE_NAME = re.compile(
    r"\s*(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})",
    re.IGNORECASE)
_TABLE_NAME_LOOSE = re.compile(r"\s*(?:IF\s+NOT\s+EXISTS\s+)?(\S+)", re.IGNORECASE)
_OPEN_PAREN = re.compile(r"\s*\(")
_SQL_KEYWORDS = frozenset({"if", "not", "exists"})
_CONSTRAINT_KEYWORDS = frozenset({"primary", "foreign", "unique", "check", "constraint", "key"})

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]


class SchemaOwnershipError(Exception):
    """A schema-ownership operation was refused. Carries a stable reason."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass(frozen=True)
class TableDeclaration:
    table: str
    owner: str
    columns: Tuple[str, ...]
    fingerprint: str

    def as_dict(self) -> Dict[str, Any]:
        return {"table": self.table, "owner": self.owner, "columns": list(self.columns),
                "fingerprint": self.fingerprint}


def columns_fingerprint(columns: Sequence[str]) -> str:
    """A table's canonical identity is its ordered column set, not its name."""
    body = "|".join(str(column).lower() for column in columns)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _split_top_level(body: str) -> List[str]:
    parts: List[str] = []
    depth = 0
    current: List[str] = []
    for character in body:
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        if character == "," and depth == 0:
            parts.append("".join(current))
            current = []
            continue
        current.append(character)
    if current:
        parts.append("".join(current))
    return parts


def _extract_columns(body: str) -> Tuple[str, ...]:
    """Column names in declaration order; table-level constraints are skipped, not misread."""
    columns: List[str] = []
    for part in _split_top_level(body):
        text = part.strip()
        if not text:
            continue
        token = re.match(r"[A-Za-z_][A-Za-z0-9_]*", text)
        if token is None:
            continue
        name = token.group(0)
        if name.lower() in _CONSTRAINT_KEYWORDS:
            continue
        columns.append(name.lower())
    return tuple(columns)


def _table_name_after(text: str, position: int):
    """
    The table name following a `CREATE TABLE`, and where its column list begins.

    Something is only a declaration if a column list actually follows. Prose that merely mentions
    `CREATE TABLE IF NOT EXISTS` in backticks has no column list, and reading `IF` as the table name
    is exactly how a scanner invents a table that does not exist. Template placeholders
    (`{HEADER_TABLE}`) are kept verbatim so those tables stay covered.
    """
    for pattern in (_TABLE_NAME, _TABLE_NAME_LOOSE):
        match = pattern.match(text, position)
        if match is None:
            continue
        name = match.group(1)
        if name.lower() in _SQL_KEYWORDS:
            continue
        paren = _OPEN_PAREN.match(text, match.end())
        if paren is None:
            continue
        return name, match.end(), paren.end() - 1
    return None, None, None


def scan_text(text: str, owner: str) -> List[TableDeclaration]:
    """Every `CREATE TABLE` in one source text, with its canonical column set."""
    declarations: List[TableDeclaration] = []
    for match in _CREATE_TABLE.finditer(text):
        table, _name_end, open_paren = _table_name_after(text, match.end())
        if table is None:
            continue
        depth = 0
        close = -1
        for index in range(open_paren, len(text)):
            if text[index] == "(":
                depth += 1
            elif text[index] == ")":
                depth -= 1
                if depth == 0:
                    close = index
                    break
        if close == -1:
            continue
        columns = _extract_columns(text[open_paren + 1:close])
        if not columns:
            continue
        declarations.append(TableDeclaration(table=table.lower(), owner=owner, columns=columns,
                                             fingerprint=columns_fingerprint(columns)))
    return declarations


def scan_project(root: Optional[Any] = None, *, include_root_modules: bool = True
                 ) -> Tuple[TableDeclaration, ...]:
    """
    Every table declaration in the production tree.

    Root-level modules (`*.py` beside the package) are included by default because production code
    lives in both places here; test modules are excluded, since a test may legitimately build a
    deliberate variant to prove a refusal.
    """
    base = pathlib.Path(root) if root is not None else _PROJECT_ROOT
    declarations: List[TableDeclaration] = []
    for path in sorted(base.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        relative = path.relative_to(base).as_posix()
        if path.name.startswith("test_") or path.name.endswith("_test.py"):
            continue
        if "/tests/" in f"/{relative}" or relative.startswith("tests/"):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        declarations.extend(scan_text(text, relative))
    return tuple(declarations)


def declarations_by_table(root: Optional[Any] = None) -> Dict[str, List[TableDeclaration]]:
    grouped: Dict[str, List[TableDeclaration]] = {}
    for declaration in scan_project(root):
        grouped.setdefault(declaration.table, []).append(declaration)
    return grouped


def duplicate_canonical_table_owners(root: Optional[Any] = None) -> Tuple[str, ...]:
    """
    Table names claimed by two or more INCOMPATIBLE canonical shapes.

    Re-declaring a table with the same column set (the common `CREATE TABLE IF NOT EXISTS` idiom
    repeated across modules) is compatible and not reported. A different ordered column set for the
    same name is the R4 defect class and is always reported.
    """
    duplicates = []
    for table, declarations in sorted(declarations_by_table(root).items()):
        fingerprints = {declaration.fingerprint for declaration in declarations}
        if len(fingerprints) > 1:
            duplicates.append(table)
    return tuple(duplicates)


def ownership_report(root: Optional[Any] = None) -> List[Dict[str, Any]]:
    """Every table, every declarer, and whether the name is contested."""
    report = []
    for table, declarations in sorted(declarations_by_table(root).items()):
        fingerprints = {declaration.fingerprint for declaration in declarations}
        report.append({"table": table, "contested": len(fingerprints) > 1,
                       "declarations": [declaration.as_dict() for declaration in declarations]})
    return report


def live_table_columns(db_path: str, table: str) -> Optional[Tuple[str, ...]]:
    """The actual columns of a table in a database, or None when the table does not exist."""
    connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10.0)
    try:
        rows = list(connection.execute(f"PRAGMA table_info({table});"))
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    if not rows:
        return None
    return tuple(str(row[1]).lower() for row in rows)


RELATION_EXACT = "EXACT"
RELATION_EXTENDS = "EXTENDS"
RELATION_INCOMPATIBLE = "INCOMPATIBLE"


def column_relation(declared: Sequence[str], live: Sequence[str]) -> str:
    """
    How a live table relates to a declared shape.

    EXACT means byte-identical column order. EXTENDS means the declared shape is the table's prefix and
    the live table carries extra TRAILING columns - which is exactly what an additive
    `ALTER TABLE ADD COLUMN` upgrade produces. Production is not a clean declaration: the live legacy
    observation table has two extra columns from an upgrade, and a classifier that only understood
    EXACT would recognize nobody's table and then migrate nothing.
    """
    declared = tuple(str(column).lower() for column in declared)
    live = tuple(str(column).lower() for column in live)
    if declared == live:
        return RELATION_EXACT
    if live[:len(declared)] == declared and len(live) > len(declared):
        return RELATION_EXTENDS
    return RELATION_INCOMPATIBLE


def classify_live_table(db_path: str, table: str, root: Optional[Any] = None) -> Dict[str, Any]:
    """
    Classify a LIVE table by schema fingerprint, never by name.

    Returns which declared owner (if any) the live shape actually matches, plus the declaration
    fingerprint each owner expects. This is what makes "the live vault contains the legacy shape"
    a measured statement rather than an assumption.
    """
    columns = live_table_columns(db_path, table)
    fingerprint = None if columns is None else columns_fingerprint(columns)
    owners = []
    for declaration in declarations_by_table(root).get(table.lower(), []):
        relation = (RELATION_INCOMPATIBLE if columns is None
                    else column_relation(declaration.columns, columns))
        owners.append({"owner": declaration.owner, "fingerprint": declaration.fingerprint,
                       "relation": relation, "matches_live": relation == RELATION_EXACT})
    # Cross-name matches matter as much as same-name ones. The production question is not "is this
    # the ledger's table?" but "which DECLARED shape does this live table actually have?" - which is
    # how a pre-migration vault holding the legacy shape gets recognized at all.
    global_matches = []
    for candidate_table, declarations in sorted(declarations_by_table(root).items()):
        for declaration in declarations:
            relation = (RELATION_INCOMPATIBLE if columns is None
                        else column_relation(declaration.columns, columns))
            if relation != RELATION_INCOMPATIBLE:
                global_matches.append({"table": candidate_table, "owner": declaration.owner,
                                       "fingerprint": declaration.fingerprint,
                                       "relation": relation,
                                       "matches_live": relation == RELATION_EXACT})
    return {"table": table, "exists": columns is not None, "columns": list(columns or ()),
            "fingerprint": fingerprint, "declared_owners": owners,
            "global_matches": global_matches}


def migrate_legacy_observations(db_path: str, *, expected_fingerprint: str,
                                source_table: str = "ciph_observations",
                                destination_table: str = "ciph_mv_observations",
                                now: Optional[float] = None) -> Dict[str, Any]:
    """
    Hand one table name back to the ledger, atomically and with proof.

    Refuses unless the live shape is EXACTLY the one the caller expected, refuses if the destination
    already exists, and verifies row count and full content are identical across the rename. The
    canonical table is then created by the LEDGER's own schema, so the ledger stays the single owner
    of its definition.
    """
    moment = __import__("time").time() if now is None else float(now)
    connection = sqlite3.connect(db_path, timeout=10.0)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("BEGIN IMMEDIATE")
        columns = [str(row[1]).lower() for row in connection.execute(
            f"PRAGMA table_info({source_table});")]
        if not columns:
            connection.execute("ROLLBACK")
            raise SchemaOwnershipError("NO_SOURCE_TABLE", source_table)
        actual = columns_fingerprint(columns)
        if actual != expected_fingerprint:
            connection.execute("ROLLBACK")
            raise SchemaOwnershipError("SCHEMA_FINGERPRINT_MISMATCH",
                                       f"{source_table}: expected {expected_fingerprint[:12]}, "
                                       f"found {actual[:12]}")
        if list(connection.execute(f"PRAGMA table_info({destination_table});")):
            connection.execute("ROLLBACK")
            raise SchemaOwnershipError("DESTINATION_ALREADY_EXISTS", destination_table)

        rows_before = int(connection.execute(
            f"SELECT COUNT(*) FROM {source_table};").fetchone()[0])
        content_before = _content_digest(connection, source_table, columns)

        connection.execute(f"ALTER TABLE {source_table} RENAME TO {destination_table};")

        rows_after = int(connection.execute(
            f"SELECT COUNT(*) FROM {destination_table};").fetchone()[0])
        content_after = _content_digest(connection, destination_table, columns)
        if rows_before != rows_after or content_before != content_after:
            connection.execute("ROLLBACK")
            raise SchemaOwnershipError("CONTENT_CHANGED_BY_RENAME",
                                       f"{rows_before}->{rows_after}")

        from ciph.kernel.epistemic_ledger import init_schema
        init_schema(connection)

        ledger_fingerprint = columns_fingerprint([str(row[1]).lower() for row in
                                                  connection.execute(
                                                      f"PRAGMA table_info({source_table});")])
        connection.commit()
        return {"source_table": source_table, "destination_table": destination_table,
                "rows": rows_before, "content_digest": content_before,
                "migrated_at": moment, "legacy_fingerprint": actual,
                "ledger_fingerprint": ledger_fingerprint}
    except Exception:
        try:
            connection.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        connection.close()


def _content_digest(connection: sqlite3.Connection, table: str,
                    columns: Sequence[str]) -> str:
    """A full-content digest, ordered by the primary key so it is stable across a rename."""
    names = ",".join(columns)
    try:
        rows = list(connection.execute(f"SELECT {names} FROM {table} ORDER BY 1;"))
    except sqlite3.Error:
        rows = []
    payload = [[None if value is None else str(value) for value in row] for row in rows]
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
                          ).hexdigest()
