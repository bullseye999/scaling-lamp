#!/usr/bin/env python3
"""
run_worker.py - Standalone Out-Of-Process Worker Daemon for CIPH 4.0.
Can be started in the background (systemd, tmux, or CLI daemon) independently of the main chat process.
"""

import sys
import os
import time
import argparse
import signal
from ciph.workers.ipc_queue import IPCJobQueue
from ciph.workers.daemon import DurableWorkerDaemon
from ciph.capabilities.registry import (
    CapabilityRegistry,
    BountyScanCapability,
    OsintMonetizeCapability,
    SportsPredictCapability
)
from cipher_vault import CipherVault


def main():
    parser = argparse.ArgumentParser(description="CIPH 4.0 Standalone Out-of-Process Worker Daemon")
    parser.add_argument("--workers", type=int, default=2, help="Number of concurrent worker threads")
    parser.add_argument("--db", type=str, default="ciph_vault.db", help="Path to SQLite database")
    args = parser.parse_args()

    print(f"⚡ [CIPH 4.0 Worker] Initializing daemon with {args.workers} workers on {args.db}...")
    
    vault = CipherVault()
    queue = IPCJobQueue(args.db)
    registry = CapabilityRegistry()

    # Lazily register available root modules
    try:
        from bounty_hunter import BountyHunter
        from ciph_router import CiphRouter
        bounty = BountyHunter(vault, CiphRouter())
        registry.register(BountyScanCapability(bounty))
    except Exception as e:
        print(f"⚠️ [Worker] BountyHunter not available: {e}")

    try:
        from osint_miner import OSINTMiner
        osint = OSINTMiner(vault)
        registry.register(OsintMonetizeCapability(osint))
    except Exception as e:
        print(f"⚠️ [Worker] OSINTMiner not available: {e}")

    try:
        from sports_predictor import SportsPredictor
        sports = SportsPredictor(vault)
        registry.register(SportsPredictCapability(sports))
    except Exception as e:
        print(f"⚠️ [Worker] SportsPredictor not available: {e}")

    daemon = DurableWorkerDaemon(
        queue=queue,
        registry=registry,
        vault=vault,
        num_workers=args.workers,
        db_path=args.db
    )

    def handle_signal(sig, frame):
        print("\n🛑 [CIPH 4.0 Worker] Shutdown signal received. Draining workers...")
        daemon.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    daemon.start()
    print(f"✅ [CIPH 4.0 Worker] Daemon is running. (Registered: {', '.join(registry.list_names())})")

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        handle_signal(None, None)


if __name__ == "__main__":
    main()
