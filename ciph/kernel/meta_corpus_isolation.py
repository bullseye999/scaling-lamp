"""
ciph/kernel/meta_corpus_isolation - 4.7 G4: the sealed corpus is unreachable by construction.

`CandidateFacingCorpus` having no `reveal()` is necessary and not sufficient. The hostile case is a
candidate evaluator that ignores the API, lists a directory, finds the sealed database and opens it.

This module proves the stronger property using the EXISTING isolated-execution machinery - no second
sandbox: a candidate runs as a confined child process whose only readable paths are the runtime package
it was handed, so it cannot reach the sealed corpus, the public corpus, or the project tree at all,
even when it is told exactly where they are.

That turns the honest limitation in `meta_corpus` ("a process holding both paths could read the sealed
DB") into a deployment assumption that is actually enforced:

    trusted host orchestration knows both paths
    the candidate process knows only what the payload gives it, and can read no host file

STATED LIMIT: this is OS-level isolation (user/mount namespaces) on the host that runs the evaluation.
It is not cryptography, and it assumes the orchestrator does not hand the candidate a general
filesystem capability.
"""

import json
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from ciph.kernel.crucible_types import CrucibleError

REASON_REACHABLE = "SEALED_CORPUS_REACHABLE_FROM_CANDIDATE"
REASON_SANDBOX_UNAVAILABLE = "CANDIDATE_ISOLATION_UNAVAILABLE"

# The hostile candidate: it is TOLD where everything is, and it tries anyway.
HOSTILE_DISCOVERY_SOURCE = """
class HostileProbe:
    def run(self, params, context=None):
        import os, sqlite3
        attempts = {}

        def record(key, action):
            try:
                action()
                attempts[key] = 'SUCCEEDED'
            except Exception as exc:
                attempts[key] = type(exc).__name__

        sealed = params['sealed_path']
        public = params['public_path']
        root = params['project_root']
        record('open_sealed', lambda: open(sealed, 'rb').read())
        record('sqlite_sealed', lambda: sqlite3.connect(sealed))
        record('open_public', lambda: open(public, 'rb').read())
        record('sqlite_public', lambda: sqlite3.connect(public))
        record('listdir_parent', lambda: os.listdir(os.path.dirname(sealed)))
        record('listdir_root', lambda: os.listdir(root))
        record('traversal', lambda: open(os.path.join(os.path.dirname(sealed), '..', '..',
                                                      'etc', 'hostname'), 'rb').read())
        # Enumeration is recorded by SUBSTANCE. `os.walk` swallows permission errors, so "no
        # exception" is not the same as "found something" - a probe that reported success on an empty
        # walk would be measuring its own optimism.
        found = {}
        try:
            found['walk_root'] = len([p for p, _d, _f in os.walk(root)])
        except Exception as exc:
            found['walk_root'] = type(exc).__name__
        try:
            found['glob_sealed'] = len(__import__('glob').glob(
                os.path.join(root, '**', '*sealed*'), recursive=True))
        except Exception as exc:
            found['glob_sealed'] = type(exc).__name__
        return {'attempts': attempts, 'found': found}
"""

# A cooperative candidate: proves the child is not merely broken - it receives corpus DATA through the
# payload and returns a computed answer.
COOPERATIVE_SOURCE = """
class CooperativeProbe:
    def run(self, params, context=None):
        cases = params['cases']
        return {'verdicts': {case['case_id']: 'INVALID' for case in cases},
                'case_count': len(cases)}
"""


def _run(source: str, class_name: str, params: Dict[str, Any],
         budget: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    from ciph.evolution.isolated_execution import CandidateExecutionError, execute_candidate
    try:
        result, _duration = execute_candidate(source, class_name, params, 'DISPOSABLE_PROCESS',
                                              budget or {'max_runs': 8})
    except CandidateExecutionError as unavailable:
        raise CrucibleError(REASON_SANDBOX_UNAVAILABLE, str(unavailable)[:200])
    return result


def probe_host_filesystem(*, sealed_path: str, public_path: str,
                          project_root: Optional[str] = None) -> Dict[str, Any]:
    """Run the hostile probe in the real sandbox and report what it managed to do."""
    root = str(Path(project_root) if project_root is not None else Path(__file__).resolve().parents[2])
    return _run(HOSTILE_DISCOVERY_SOURCE, 'HostileProbe',
                {'sealed_path': str(sealed_path), 'public_path': str(public_path),
                 'project_root': root})


def assert_sealed_corpus_unreachable(*, sealed_path: str, public_path: str,
                                     project_root: Optional[str] = None) -> Dict[str, Any]:
    """
    THE G4 boundary specimen (laws 3). Every hostile attempt must fail; one success is a defect.
    """
    probe = probe_host_filesystem(sealed_path=sealed_path, public_path=public_path,
                                  project_root=project_root)
    attempts, found = probe['attempts'], probe['found']
    succeeded = sorted(key for key, outcome in attempts.items() if outcome == 'SUCCEEDED')
    discovered = sorted(f"{key}={count}" for key, count in found.items()
                        if isinstance(count, int) and count > 0)
    if succeeded or discovered:
        raise CrucibleError(REASON_REACHABLE, ','.join(succeeded + discovered))
    return probe


def probe_receives_corpus_as_data(*, cases: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """The candidate gets the corpus as DATA through the payload, which is the intended channel."""
    return _run(COOPERATIVE_SOURCE, 'CooperativeProbe', {'cases': [dict(case) for case in cases]})
