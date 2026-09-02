"""
ciph.capabilities.capability_ledger - Empirical Capability Ledger & Maintenance Leases (CIPH 4.0 Blueprint Phase 9).
Derives self-knowledge strictly from verified ExecutionReceipts, and manages exclusive idle maintenance leases.
"""

import time
import uuid
import json
import sqlite3
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from ciph.memory.event_store import EventStore
from ciph.capabilities.registry import CapabilityRegistry
from ciph.workers.receipts import ExecutionReceipt


@dataclass
class VerifiedCapabilityRecord:
    capability_name: str
    total_executions: int
    successful_executions: int
    failed_executions: int
    success_rate: float
    last_executed_at: Optional[float]
    verified_real: bool
    empirical_latency_avg_ms: float


class CapabilityLedger:
    """
    Empirical Capability Ledger (Blueprint Phase 9).
    Grounds CIPH's self-knowledge strictly in verifiable execution history from EventStore.
    """

    def __init__(self, event_store: EventStore, registry: CapabilityRegistry, worker_secret_key: Optional[bytes] = None):
        self.event_store = event_store
        self.registry = registry
        self.worker_secret_key = worker_secret_key

    def compile_empirical_ledger(self) -> Dict[str, VerifiedCapabilityRecord]:
        """Scans EventStore for ExecutionReceiptStoredEvent records and computes empirical metrics."""
        events = self.event_store.get_events(event_type="ExecutionReceiptStoredEvent")
        stats: Dict[str, Dict[str, Any]] = {}

        for ev in events:
            # Handle both dictionary and object formats
            if isinstance(ev, dict):
                payload = ev.get("payload", {})
            else:
                payload = getattr(ev, "payload", {})

            if isinstance(payload, str):
                try:
                    payload = json.loads(payload)
                except Exception:
                    continue

            cap_name = payload.get("capability")
            if not cap_name:
                continue

            # Verify receipt structure, output hash, and HMAC signature
            results = payload.get("results") or {}
            out_hash = payload.get("output_hash")
            computed_out_hash = ExecutionReceipt.hash_payload(results)
            
            # If output hash is tampered, reject this record
            if out_hash and out_hash != computed_out_hash:
                continue

            # Cryptographic HMAC signature verification
            if self.worker_secret_key:
                try:
                    receipt_obj = ExecutionReceipt.from_dict(payload)
                    if not receipt_obj.verify_signature(self.worker_secret_key):
                        continue
                except Exception:
                    continue
            else:
                # Fail-closed: Standalone ledger without key cannot establish cryptographic proof of execution
                continue

            if cap_name not in stats:
                stats[cap_name] = {
                    "total": 0,
                    "success": 0,
                    "failed": 0,
                    "last_at": 0.0,
                    "latencies": []
                }

            stats[cap_name]["total"] += 1
            if payload.get("exit_code") == 0:
                stats[cap_name]["success"] += 1
            else:
                stats[cap_name]["failed"] += 1

            t_start = payload.get("started_at", 0.0)
            t_end = payload.get("completed_at", 0.0)
            if t_end > t_start > 0:
                stats[cap_name]["latencies"].append((t_end - t_start) * 1000.0)

            stats[cap_name]["last_at"] = max(stats[cap_name]["last_at"], t_end)

        records: Dict[str, VerifiedCapabilityRecord] = {}
        for cap_name, s in stats.items():
            rate = round(s["success"] / max(s["total"], 1), 3)
            avg_lat = round(sum(s["latencies"]) / max(len(s["latencies"]), 1), 2)
            records[cap_name] = VerifiedCapabilityRecord(
                capability_name=cap_name,
                total_executions=s["total"],
                successful_executions=s["success"],
                failed_executions=s["failed"],
                success_rate=rate,
                last_executed_at=s["last_at"],
                verified_real=s["success"] >= 1,
                empirical_latency_avg_ms=avg_lat
            )

        return records

    def generate_self_knowledge_report(self) -> Dict[str, Any]:
        """Generate structured empirical self-knowledge summary."""
        ledger = self.compile_empirical_ledger()
        verified_caps = [r.capability_name for r in ledger.values() if r.verified_real]
        unverified_manifests = [
            m.name for m in self.registry.list_manifests()
            if m.name not in verified_caps
        ]

        return {
            "verified_active_capabilities_count": len(verified_caps),
            "empirically_verified_capabilities": verified_caps,
            "registered_unverified_capabilities": unverified_manifests,
            "records": {k: vars(v) for k, v in ledger.items()},
            "generated_at": time.time()
        }


class MaintenanceLeaseManager:
    """
    Blueprint Phase 9: Real Exclusive Idle Maintenance Lease System.
    Acquires exclusive lease records in SQLite to run background WAL checkpoints and integrity checks.
    """

    def __init__(self, db_path: str = "ciph_vault.db"):
        self.db_path = db_path
        self._init_table()

    def _init_table(self):
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ciph_maintenance_leases (
                    lease_name TEXT PRIMARY KEY,
                    holder_id TEXT NOT NULL,
                    acquired_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                );
            """)
            conn.commit()

    def acquire_lease(self, lease_name: str, holder_id: str, ttl_seconds: int = 30) -> bool:
        """Atomically acquire or renew an exclusive maintenance lease."""
        now = time.time()
        expires_at = now + ttl_seconds
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.isolation_level = "IMMEDIATE"
            # Delete expired leases
            conn.execute("DELETE FROM ciph_maintenance_leases WHERE lease_name = ? AND expires_at < ?;", (lease_name, now))
            try:
                conn.execute("""
                    INSERT INTO ciph_maintenance_leases (lease_name, holder_id, acquired_at, expires_at)
                    VALUES (?, ?, ?, ?);
                """, (lease_name, holder_id, now, expires_at))
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                # Check if this holder already owns active lease
                cursor = conn.execute("SELECT holder_id FROM ciph_maintenance_leases WHERE lease_name = ?;", (lease_name,))
                row = cursor.fetchone()
                if row and row[0] == holder_id:
                    conn.execute("UPDATE ciph_maintenance_leases SET expires_at = ? WHERE lease_name = ?;", (expires_at, lease_name))
                    conn.commit()
                    return True
                return False

    def release_lease(self, lease_name: str, holder_id: str) -> bool:
        """Release an active maintenance lease."""
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            cursor = conn.execute("DELETE FROM ciph_maintenance_leases WHERE lease_name = ? AND holder_id = ?;", (lease_name, holder_id))
            conn.commit()
            return cursor.rowcount > 0

    def run_idle_maintenance_cycle(self, holder_id: Optional[str] = None) -> Dict[str, Any]:
        """Execute exclusive maintenance tasks under a valid maintenance lease."""
        hid = holder_id or f"maint_daemon_{uuid.uuid4().hex[:6]}"
        lease_name = "global_db_maintenance"
        
        if not self.acquire_lease(lease_name, hid, ttl_seconds=30):
            return {
                "success": False,
                "status": "LEASE_ACQUISITION_FAILED_CONFLICT",
                "error": "Another maintenance process currently holds the exclusive lease."
            }

        results = {}
        try:
            with sqlite3.connect(self.db_path, timeout=10.0) as conn:
                # 1. PRAGMA wal_checkpoint(TRUNCATE)
                cursor = conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
                results["wal_checkpoint"] = cursor.fetchall()

                # 2. PRAGMA integrity_check
                cursor = conn.execute("PRAGMA integrity_check;")
                check_res = cursor.fetchone()
                results["integrity_check"] = check_res[0] if check_res else "UNKNOWN"

                # 3. PRAGMA optimize
                conn.execute("PRAGMA optimize;")
                results["optimized"] = True
                results["success"] = True
                results["status"] = "MAINTENANCE_COMPLETE"
        except Exception as ex:
            results["success"] = False
            results["error"] = str(ex)
        finally:
            self.release_lease(lease_name, hid)

        return results
