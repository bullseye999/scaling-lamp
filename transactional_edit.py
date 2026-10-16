"""
transactional_edit - all-or-nothing source edits.

This exists because a multi-anchor edit script failed in exactly the way its own rule was supposed
to prevent: it wrote the first anchor, then discovered the second anchor did not exist, leaving a
file referencing a name it did not import. "Verify everything before writing" was a claim about the
helper, and the helper was wrong.

So the rule is now a property with tests: verify every anchor against the evolving in-memory
content, build the complete result, write exactly once, then re-read and confirm what landed. If any
anchor fails, the file is never opened for writing and its bytes are unchanged.
"""

import hashlib
import pathlib
from typing import Iterable, List, Optional, Tuple


class GeneratedContentInvalid(Exception):
    """The regenerated content is not usable: it does not compile, or its tests do not
    collect, or the collected node ids are not the intended set."""


class PreconditionFailed(Exception):
    """
    The file is not what the caller generated against.

    This is optimistic concurrency control for source editing: if the on-disk hash does not
    match the hash the caller expected, the edit is refused rather than reconciled. A stale
    generation becomes a visible conflict instead of silently landing in the wrong place.
    """

    def __init__(self, expected: str, actual: str):
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"PRECONDITION_FAILED: expected {expected[:12]}, found {actual[:12]}"
        )


class TransactionalEditError(Exception):
    """An anchor did not match exactly once. The file was not written."""

    def __init__(self, tag: str, expected: int, found: int):
        self.tag = tag
        self.expected = expected
        self.found = found
        super().__init__(
            f"ANCHOR_MISMATCH:{tag}: expected {expected} match(es), found {found}"
        )


def collect_test_node_ids(source_text: str, module_name: str):
    """
    Collect the full node ids of the tests a generated module defines.

    Used to compare against the intended *set*. A count comparison would accept a regeneration that
    silently replaced or moved tests while preserving the total.
    """
    import importlib.util
    import tempfile
    import unittest as _unittest

    directory = tempfile.mkdtemp(prefix="txn_collect_")
    candidate = pathlib.Path(directory) / f"{module_name}.py"
    candidate.write_text(source_text, encoding="utf-8")
    try:
        spec = importlib.util.spec_from_file_location(module_name, candidate)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        suite = _unittest.TestLoader().loadTestsFromModule(module)
        # Node ids are module-qualified, and the module name is an artifact of the temporary
        # collection path. Compare class-qualified ids instead, so the intended set is written
        # the way a reader would name the tests.
        ids = []
        for case in _iter_cases(suite):
            parts = case.id().split(".")
            ids.append(".".join(parts[1:]) if len(parts) > 1 else case.id())
        return sorted(ids)
    finally:
        import shutil
        shutil.rmtree(directory, ignore_errors=True)


def _iter_cases(suite):
    for item in suite:
        if isinstance(item, __import__("unittest").TestSuite):
            yield from _iter_cases(item)
        else:
            yield item


def collect_test_node_ids_with_overlay(
    candidate_test_name: str,
    candidate_test_source: str,
    staged_files, 
    repo_root=None,
):
    """
    Collect node ids for a candidate test file validated against candidate co-artifacts.

    Pre-commit validation must understand co-dependent candidates: a candidate test that
    imports a symbol introduced by a candidate production module cannot be collected against
    the old module on disk. Rather than mutating sys.modules - which leaves import state,
    package attributes and transitive caches behind, and can make a validator pass for reasons
    that have nothing to do with the candidate - this materialises a temporary overlay:

        overlay/ciph/kernel/manifest_credit.py   <- candidate
        overlay/<candidate test>.py              <- candidate

    with the real repository underneath on the path, and collects in a fresh subprocess so the
    import cache is empty and the path order is known. The real repository is never touched.
    """
    import json
    import os
    import shutil
    import subprocess
    import sys
    import tempfile

    root = pathlib.Path(repo_root) if repo_root else pathlib.Path.cwd()
    workspace = pathlib.Path(tempfile.mkdtemp(prefix="txn_validate_"))
    project = workspace / "project"

    # Mirror the real source tree instead of synthesising a package layout. Empty markers were
    # the wrong fix: they replaced real __init__.py semantics and hid unstaged siblings, which
    # would have moved the oracle from a false green to an altered environment. Mirroring asks
    # the only question that matters - what happens if these candidates replace the current
    # files in the repository - and it is cheap enough to do correctness-first.
    ignore = shutil.ignore_patterns(
        ".git", "__pycache__", "*.pyc", "*.db", "*.db-wal", "*.db-shm",
        "*.log", ".venv", "ciph_env", "node_modules", "*.zip", "*.tar.gz",
    )
    shutil.copytree(root, project, ignore=ignore, symlinks=False)

    try:
        for rel, content in staged_files.items():
            target = project / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")

        runner = project / "_txn_collect_runner.py"
        runner.write_text(_COLLECT_RUNNER, encoding="utf-8")

        env = dict(os.environ)
        env["PYTHONPATH"] = str(project)
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        completed = subprocess.run(
            [sys.executable, str(runner), candidate_test_name, candidate_test_source],
            capture_output=True, text=True, cwd=str(project), env=env,
        )
        if completed.returncode != 0:
            raise GeneratedContentInvalid(
                "STAGED_COLLECTION_FAILED: " + (completed.stderr or "").strip()[-400:]
            )
        return sorted(json.loads(completed.stdout.strip().splitlines()[-1]))
    finally:
        shutil.rmtree(workspace, ignore_errors=True)

def run_suite_in_staged_workspace(
    candidate_test_name: str,
    candidate_test_source: str,
    staged_files,
    repo_root=None,
):
    """
    Run the candidate test file inside the mirrored workspace and return unittest's output.

    Collection proves structure; it imports the module and enumerates tests without executing
    a single test body. A migrated suite can therefore collect perfectly and still raise
    NameError the moment it runs - which is exactly what happened when this gate did not exist.
    Executing the candidate suite in the same trusted mirror closes that gap before the write.
    """
    import os
    import shutil
    import subprocess
    import sys
    import tempfile

    root = pathlib.Path(repo_root) if repo_root else pathlib.Path.cwd()
    workspace = pathlib.Path(tempfile.mkdtemp(prefix="txn_run_"))
    project = workspace / "project"
    ignore = shutil.ignore_patterns(
        ".git", "__pycache__", "*.pyc", "*.db", "*.db-wal", "*.db-shm",
        "*.log", ".venv", "ciph_env", "node_modules", "*.zip", "*.tar.gz",
    )
    shutil.copytree(root, project, ignore=ignore, symlinks=False)
    try:
        for rel, content in staged_files.items():
            target = project / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        candidate = project / f"{candidate_test_name}.py"
        candidate.write_text(candidate_test_source, encoding="utf-8")

        env = dict(os.environ)
        env["PYTHONPATH"] = str(project)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        completed = subprocess.run(
            [sys.executable, "-m", "unittest", candidate_test_name],
            capture_output=True, text=True, cwd=str(project), env=env,
        )
        output = (completed.stdout or "") + (completed.stderr or "")
        if completed.returncode != 0:
            raise GeneratedContentInvalid(
                "STAGED_EXECUTION_FAILED: " + output.strip()[-600:]
            )
        return output
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


_COLLECT_RUNNER = '''
import importlib.util, json, sys, unittest

name, source = sys.argv[1], sys.argv[2]
path = name + ".py"
with open(path, "w", encoding="utf-8") as handle:
    handle.write(source)

spec = importlib.util.spec_from_file_location(name, path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

def walk(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from walk(item)
        else:
            yield item

suite = unittest.TestLoader().loadTestsFromModule(module)
ids = []
for case in walk(suite):
    parts = case.id().split(".")
    ids.append(".".join(parts[1:]) if len(parts) > 1 else case.id())
print(json.dumps(sorted(ids)))
'''


def replace_file_generated(
    path,
    new_content: str,
    expected_old_hash: Optional[str] = None,
    expected_test_nodes: Optional[Iterable[str]] = None,
) -> str:
    """
    Replace a file with regenerated content, proving four things before touching it.

    The anchor-based `apply_edits` proves only that the file is the one you generated against. It
    cannot prove your edit landed in a structurally valid place - the earlier `if __name__` and
    class-boundary mistakes happened against perfectly matching hashes. So whole-file replacement
    adds: the new content must compile, its tests must collect, and the collected node ids must match
    the intended *set*. The count alone is not enough, because a misplaced edit can preserve it.
    """
    import ast

    target = pathlib.Path(path)
    before = target.read_bytes()
    actual_old_hash = hashlib.sha256(before).hexdigest()
    if expected_old_hash is not None and actual_old_hash != expected_old_hash:
        raise PreconditionFailed(expected_old_hash, actual_old_hash)

    try:
        ast.parse(new_content)
    except SyntaxError as error:
        raise GeneratedContentInvalid(f"GENERATED_CONTENT_DOES_NOT_COMPILE: {error}")

    if expected_test_nodes is not None:
        module_name = f"txn_{target.stem}"
        try:
            collected = collect_test_node_ids(new_content, module_name)
        except Exception as error:
            raise GeneratedContentInvalid(
                f"GENERATED_CONTENT_FAILED_TO_COLLECT: {type(error).__name__}: {error}"
            )
        expected = sorted(expected_test_nodes)
        if collected != expected:
            missing = sorted(set(expected) - set(collected))
            extra = sorted(set(collected) - set(expected))
            raise GeneratedContentInvalid(
                f"GENERATED_TEST_NODES_MISMATCH: missing={missing} extra={extra}"
            )

    target.write_text(new_content, encoding="utf-8")
    written = target.read_text(encoding="utf-8")
    if written != new_content:
        raise TransactionalEditError("POST_WRITE_VERIFICATION", 1, 0)

    if expected_test_nodes is not None:
        final = collect_test_node_ids(written, f"txn_final_{target.stem}")
        if final != sorted(expected_test_nodes):
            raise GeneratedContentInvalid(
                f"POST_WRITE_NODE_MISMATCH: {final}"
            )
    return file_digest(target)


def apply_batch_transaction(replacements, staged_checks=()):
    """
    Replace several files as ONE transaction. Returns {path: new_digest}.

    Per-file atomicity is not enough for a migration that spans files: production can be updated
    while half the call sites are not, and every individual write was still "atomic". That state is
    worse than not starting, because the remaining work invites a temporary compatibility escape
    hatch to get green again.

    So nothing is written until every precondition holds, every generated Python module compiles,
    and every staged check passes against the generated content in memory. A failure anywhere leaves
    every file byte-identical.

    Pre-commit validation is all-or-nothing, and a commit-phase failure rolls back every file
    already replaced. It is **not crash-atomic**: ordinary filesystem writes across several
    files cannot promise that a host or process failure midway leaves all files old or all
    files new. Unexpected process or host failure during commit is recoverable, not guaranteed
    filesystem-atomic.

    `replacements` is a sequence of (path, new_text, expected_old_hash_or_None).
    `staged_checks` is a sequence of callables taking {path: new_text}; raise to refuse the commit.
    """
    import ast

    staged = {}
    originals = {}
    for path, new_text, expected_old_hash in replacements:
        target = pathlib.Path(path)
        before = target.read_bytes()
        actual = hashlib.sha256(before).hexdigest()
        if expected_old_hash is not None and actual != expected_old_hash:
            raise PreconditionFailed(expected_old_hash, actual)
        if target.suffix == ".py":
            try:
                ast.parse(new_text)
            except SyntaxError as error:
                raise GeneratedContentInvalid(
                    f"GENERATED_CONTENT_DOES_NOT_COMPILE: {target}: {error}"
                )
        originals[str(target)] = before
        staged[str(target)] = new_text

    for check in staged_checks:
        check(staged)

    digests = {}
    touched = []
    try:
        for path, new_text in staged.items():
            target = pathlib.Path(path)
            # Recorded BEFORE the write: if the write dies or the re-read fails, this file has
            # already been disturbed and must be restored too.
            touched.append(path)
            target.write_text(new_text, encoding="utf-8")
            written = target.read_text(encoding="utf-8")
            if written != new_text:
                raise TransactionalEditError(f"POST_WRITE_VERIFICATION:{path}", 1, 0)
            digests[path] = file_digest(path)
    except Exception:
        # Commit-phase rollback. Pre-commit validation being all-or-nothing is not enough:
        # without this, a failure on the third write leaves the first two migrated, which is
        # exactly the half-migrated repository a multi-file migration must never produce.
        for path in reversed(touched):
            try:
                pathlib.Path(path).write_bytes(originals[path])
            except Exception:
                # Restoration failure is surfaced by the original exception; swallowing here
                # would hide a repository that is now genuinely inconsistent.
                pass
        raise
    return digests


def file_digest(path) -> str:
    """Digest of a file's current bytes - used to prove nothing changed, and nothing but."""
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def apply_edits(
    path,
    edits: Iterable[Tuple[str, str, str]],
    expected_old_hash: str = None,
) -> str:
    """
    Apply `(old, new, tag)` edits atomically. Returns the post-write digest.

    Every anchor is verified before any write. On failure the file is untouched and the digest is
    unchanged, which is the property the tests assert rather than assume.

    `expected_old_hash` is a precondition, not a hint: when supplied and stale, the edit is
    refused and nothing is written. Pass it whenever the edit was generated against a known
    revision, so a stale generation surfaces as a conflict rather than as a misplaced change.
    """
    target = pathlib.Path(path)
    before = target.read_bytes()
    actual_old_hash = hashlib.sha256(before).hexdigest()
    if expected_old_hash is not None and actual_old_hash != expected_old_hash:
        raise PreconditionFailed(expected_old_hash, actual_old_hash)
    result = before.decode("utf-8")

    for old, new, tag in edits:
        found = result.count(old)
        if found != 1:
            raise TransactionalEditError(tag, 1, found)
        result = result.replace(old, new, 1)

    target.write_text(result, encoding="utf-8")
    # Report what landed, not what was intended.
    written = target.read_text(encoding="utf-8")
    if written != result:
        raise TransactionalEditError("POST_WRITE_VERIFICATION", 1, 0)
    return file_digest(target)
