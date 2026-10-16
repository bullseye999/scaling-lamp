"""
swarm_test_support - the minimal WORKER RUNTIME used by the 6.x runtime torture.

This is deliberately not a kernel module. It is the mechanism side of the swarm: a process that
registers, gets attested, claims a delegation, computes something deterministic, submits a result, and
acknowledges a quiescence barrier. The kernel modules decide what any of that MEANS; this file only does
it - which is the same split the R10 census makes for the legacy queue and daemon.

The `--crash-after` switch exists so the torture can lose a worker at a chosen boundary (after claiming,
after submitting, before acknowledging) without pretending a clean shutdown happened.

Usage:
    python3 swarm_test_support.py <db> --worker W1 --delegations SD-...,SD-...
        [--crash-after claim|result|never] [--capabilities coding,research] [--model M1]
        [--ack-barrier]
"""

import argparse
import hashlib
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from ciph.kernel.crucible_types import CrucibleError                                # noqa: E402
from ciph.kernel.swarm_delegation import (REASON_ALREADY_CLAIMED, REASON_SWARM_FROZEN,  # noqa: E402
                                          claim_delegation, current_lease, get_delegation)
from ciph.kernel.swarm_quiescence import (ACK_SAFE_BOUNDARY, acknowledge,             # noqa: E402
                                          current_barrier)
from ciph.kernel.swarm_results import submit_result                                    # noqa: E402
from ciph.kernel.swarm_worker import (READY, attest_worker, get_worker,                # noqa: E402
                                      record_capability, register_worker, set_worker_status)


def compute_output(input_digest: str, worker_id: str, *, corrupt: bool = False) -> str:
    """Deterministic work: same input, same answer - unless the torture asks for a corrupt one."""
    payload = f"{input_digest}|{worker_id}".encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()[:24]
    return f"BROKEN-{digest}" if corrupt else digest


def run_worker(db: str, worker_id: str, *, delegations, crash_after: str = "never",
               capabilities=(), model_identity=None, lease_seconds: float = 120.0,
               corrupt: bool = False, ack_barrier: bool = False, actor: str = "operator:operator",
               hold_seconds: float = 0.0, now=None) -> dict:
    """One worker's whole life, with an optional crash injected at a named boundary."""
    moment = time.time() if now is None else float(now)
    code_digest = hashlib.sha256(b"swarm-test-code-v1").hexdigest()[:32]
    environment_digest = hashlib.sha256(b"swarm-test-env-v1").hexdigest()[:32]
    identity = register_worker(db, worker_id=worker_id, process_identity=str(os.getpid()),
                              code_digest=code_digest, environment_digest=environment_digest,
                              model_identity=model_identity, now=moment)
    attested = attest_worker(db, worker_id=worker_id,
                             generation=identity.instance_generation,
                             observed_code_digest=code_digest,
                             observed_environment_digest=environment_digest, actor=actor, now=moment)
    for capability in capabilities:
        record_capability(db, worker_id, identity.instance_generation, capability=capability,
                          level="INSTALLED", actor=f"worker:{worker_id}", now=moment)
        record_capability(db, worker_id, identity.instance_generation, capability=capability,
                          level="VERIFIED", actor=actor, evidence_ref="CAP-EVIDENCE-1", now=moment)
    # A frozen swarm refuses this, and that refusal is normal: a worker that arrives during a
    # quiescence barrier is attested and then waits, which is exactly what it should do.
    try:
        set_worker_status(db, worker_id, identity.instance_generation, status="BUSY",
                          actor=f"worker:{worker_id}", now=moment)
    except CrucibleError as refused:
        outcome_note = refused.reason
    else:
        outcome_note = None
    outcome = {"worker_id": worker_id, "generation": identity.instance_generation, "claimed": [],
               "submitted": [], "skipped": [], "crashed_after": None,
               "busy_refused": outcome_note}
    if hold_seconds:
        time.sleep(hold_seconds)
    for delegation_id in delegations:
        delegation = get_delegation(db, delegation_id)
        try:
            lease = claim_delegation(db, delegation_id, worker_id=worker_id,
                                     worker_generation=identity.instance_generation,
                                     input_digest=delegation.input_digest,
                                     lease_seconds=lease_seconds, now=moment)
        except CrucibleError as refused:
            if refused.reason in (REASON_ALREADY_CLAIMED, REASON_SWARM_FROZEN):
                outcome["skipped"].append({"delegation_id": delegation_id,
                                           "reason": refused.reason})
                continue
            raise
        outcome["claimed"].append(lease.lease_id)
        if crash_after == "claim":
            outcome["crashed_after"] = "claim"
            return outcome
        output = compute_output(delegation.input_digest, worker_id, corrupt=corrupt)
        result = submit_result(db, delegation_id=delegation_id, worker_id=worker_id,
                               worker_generation=identity.instance_generation,
                               output_digest=output, basis_digest=delegation.basis_digest,
                               evidence_refs=[f"SWARM-EVIDENCE:{worker_id}"],
                               source_dependency_refs=[f"SOURCE:{worker_id}"],
                               model_identity=model_identity, now=moment)
        outcome["submitted"].append({"result_id": result.result_id,
                                     "status": result.result_status})
        if crash_after == "result":
            outcome["crashed_after"] = "result"
            return outcome
        if corrupt:
            outcome["corrupt"] = True
    if ack_barrier:
        barrier = current_barrier(db)
        if barrier is not None and identity.instance_generation is not None:
            try:
                acknowledge(db, barrier.barrier_id, worker_id=worker_id,
                            instance_generation=identity.instance_generation,
                            outcome=ACK_SAFE_BOUNDARY, note="worker loop finished", now=moment)
                outcome["acknowledged"] = barrier.barrier_id
            except CrucibleError as refused:
                outcome["acknowledged"] = f"refused:{refused.reason}"
    return outcome


def main(argv) -> int:
    parser = argparse.ArgumentParser(description="6.x swarm worker runtime (test support)")
    parser.add_argument("db")
    parser.add_argument("--worker", required=True)
    parser.add_argument("--delegations", default="")
    parser.add_argument("--crash-after", default="never",
                        choices=("never", "claim", "result"))
    parser.add_argument("--capabilities", default="")
    parser.add_argument("--model", default=None)
    parser.add_argument("--lease-seconds", type=float, default=120.0)
    parser.add_argument("--corrupt", action="store_true")
    parser.add_argument("--ack-barrier", action="store_true")
    parser.add_argument("--hold-seconds", type=float, default=0.0)
    parser.add_argument("--exit-nonzero-on-crash", action="store_true")
    arguments = parser.parse_args(argv[1:])
    outcome = run_worker(arguments.db, arguments.worker,
                         delegations=[item for item in arguments.delegations.split(",") if item],
                         crash_after=arguments.crash_after,
                         capabilities=[item for item in arguments.capabilities.split(",") if item],
                         model_identity=arguments.model, lease_seconds=arguments.lease_seconds,
                         corrupt=arguments.corrupt, ack_barrier=arguments.ack_barrier,
                         hold_seconds=arguments.hold_seconds)
    print(json.dumps(outcome, sort_keys=True, default=str))
    if outcome.get("crashed_after") and arguments.exit_nonzero_on_crash:
        os._exit(3)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
