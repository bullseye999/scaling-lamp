#!/usr/bin/env python3
# test_ciph_project_suite.py - Dedicated Test Suite for CIPH_PROJECT
import os
import sys
import time
import json
from ciph_core import CiphCore

def run_suite():
    print("=" * 68)
    print("🧪 STARTING CIPH_PROJECT CUSTOM AUDIT SUITE (Zero-Regression Test)")
    print("=" * 68)

    t0 = time.time()
    core = CiphCore()

    test_commands = [
        # Cognitive, Evolution & Bridge (New Architecture + Historical)
        ("/bridge-status", "Bridge Status", False),
        ("/hypotheses", "Formulated Hypotheses", False),
        ("/reanalyze-blueprints", "Retroactive Blueprint Mining", False),
        ("/benchmark-proposals", "Historical Proposal Benchmark", False),
        ("/self-report", "Self-Awareness Architecture Report", False),
        ("/evolution", "Evolution History Log", False),
        ("/upgrades", "Staged Upgrades List", False),
        ("/code", "Code Staging List", False),
        ("/changelog", "Audit Changelog", False),

        # Personal Library & Wisdom Suite
        ("/library", "PDF Knowledge Library", False),
        ("/book-advice dealing with complex systems and adversaries", "Situational Advice Extraction", False),
        ("/operator-council", "Council Theses Consultation", False),

        # Private Recon, Darknet & OSINT
        ("/darknet-status", "Darknet Onion Sensor Status", False),
        ("/darknet-report", "Darknet Signal Report", False),
        ("/bounty-status", "Bounty Engine Status", False),
        ("/bounty-programs", "Bounty Programs Scopes", False),
        ("/war-room status", "War Room Session Status", False),
        ("/asset-inventory", "Asset Recon Inventory", False),

        # Security, Memory & Vault
        ("/auth-status", "Authentication & Cryptographic State", False),
        ("/alerts", "Security Alerts Feed", False),
        ("/memory-stats", "Smart Memory Statistics", False),
        ("/briefing", "Operator Morning Briefing", False),
        ("/reality-check", "Sensory Reality Check", False),
        ("/status", "System Live Telemetry", False),
        ("/modules", "Modular Subsystem States", False),
    ]

    passed = 0
    failed = 0
    results = []

    for cmd, name, is_prefix in test_commands:
        t_start = time.perf_counter()
        try:
            res = core.handle_command(cmd)
            duration_ms = round((time.perf_counter() - t_start) * 1000, 2)
            
            # Verify non-empty and no unhandled traceback crashes
            if res is not None and not str(res).startswith("Traceback") and "Unhandled Exception" not in str(res):
                passed += 1
                status = "PASS"
                preview = str(res).replace("\n", " ")[:60]
                print(f"  ✅ [PASS] {cmd:<38} ({duration_ms:>6.2f}ms) -> {preview}")
            else:
                failed += 1
                status = "FAIL"
                print(f"  ❌ [FAIL] {cmd:<38} ({duration_ms:>6.2f}ms) -> Return: {res}")
            
            results.append({
                "command": cmd,
                "name": name,
                "status": status,
                "duration_ms": duration_ms
            })
        except Exception as e:
            failed += 1
            duration_ms = round((time.perf_counter() - t_start) * 1000, 2)
            print(f"  ❌ [ERROR] {cmd:<38} ({duration_ms:>6.2f}ms) -> Exception: {e}")
            results.append({
                "command": cmd,
                "name": name,
                "status": "ERROR",
                "error": str(e),
                "duration_ms": duration_ms
            })

    total_time = round(time.time() - t0, 2)
    print("=" * 68)
    print(f"🏁 AUDIT COMPLETE: {passed}/{len(test_commands)} Passed ({failed} Failed) in {total_time}s")
    print("=" * 68)

    # Save local verification report
    with open("ciph_project_audit_results.json", "w") as f:
        json.dump({
            "timestamp": time.time(),
            "total_commands": len(test_commands),
            "passed": passed,
            "failed": failed,
            "duration_sec": total_time,
            "results": results
        }, f, indent=2)

    return failed == 0

if __name__ == "__main__":
    success = run_suite()
    sys.exit(0 if success else 1)
