#!/usr/bin/env python3
import sys
import os
import time
import traceback
import json

# Ensure the repository root is importable without exposing a local username/path.
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, REPO_ROOT)

from ciph_core import CiphCore

TEST_CATEGORIES = {
    "COGNITIVE EVOLUTION": [
        "/curiosity status",
        "/curiosity on",
        "/curiosity off",
        "/mind-log",
        "/mind-metrics",
        "/council",
        "/self-audit",
        "/fetch https://example.com",
        "/zeroize-mind"
    ],
    "AGENT ORCHESTRATION": [
        "/auto-mode",
        "/start-workflow",
        "/stop-workflow",
        "/workflow-status",
        "/stop-all-workflows"
    ],
    "REAL-WORLD & DARKNET INTEL": [
        "/world-brief",
        "/sync-reality",
        "/world-map",
        "/darknet-deep exploit",
        "/darknet-scan",
        "/darknet-report"
    ],
    "BOUNTY RECON & TRIAGE": [
        "/bounty-scope https://example.com",
        "/bounty-scan example.com",
        "/bounty-report example.com",
        "/bounty-list"
    ],
    "INTELLIGENCE & SENTRY": [
        "/what-changed example.com",
        "/hit-list example.com",
        "/chain-reaction example.com",
        "/watchtower",
        "/ghost-rating"
    ],
    "STRATEGY & WAR ROOM": [
        "/daily-brief",
        "/war-room Test adversarial penetration strategy",
        "/timeline"
    ],
    "PENTESTING": [
        "/port-scan",
        "/web-scan",
        "/security-audit",
        "/network-discovery",
        "/ssl-scan"
    ],
    "TRADING": [
        "/market-data",
        "/arbitrage-scan",
        "/market-trends",
        "/wealth-strategy",
        "/trading-signals",
        "/portfolio-health"
    ],
    "FILES": [
        "/scan-project",
        "/read-file README.md",
        "/search-in-files vault",
        "/project-status"
    ],
    "SECURITY": [
        "/security-scan",
        "/clean-footprints",
        "/integrity-check",
        "/backup-now",
        "/emergency-wipe"
    ],
    "SCHEDULER": [
        "/schedule-start",
        "/schedule-stop",
        "/schedule-status",
        "/schedule-update"
    ],
    "MODULES": [
        "/modules",
        "/load pentest",
        "/unload pentest"
    ],
    "MEMORY": [
        "/profile",
        "/profile-clear",
        "/memory-graph target",
        "/memory-status",
        "/retroactive-learn",
        "/timeline",
        "/search test",
        "/tag test"
    ],
    "CONVERSATION": [
        "/talk-test",
        "/convo-summary"
    ],
    "CORE": [
        "/exit",
        "/help",
        "/status",
        "/model-status",
        "/test-model",
        "/reality-check",
        "/ai",
        "/setkey"
    ]
}

def run_tests():
    print("==================================================")
    print("🚀 Initializing CIPH Core for Comprehensive Audit...")
    print("==================================================")
    
    start_init = time.time()
    try:
        ciph = CiphCore()
        print(f"✅ Core initialized in {time.time() - start_init:.2f}s\n")
    except Exception as e:
        print(f"❌ Core initialization failed: {e}")
        traceback.print_exc()
        return

    results = {}
    total_tests = sum(len(cmds) for cmds in TEST_CATEGORIES.values())
    executed = 0

    for category, commands in TEST_CATEGORIES.items():
        print(f"\n📂 [CATEGORY: {category}] ({len(commands)} commands)")
        print("─" * 60)
        results[category] = []
        
        for cmd in commands:
            executed += 1
            t0 = time.time()
            status = "UNKNOWN"
            output_str = ""
            err_details = None
            
            try:
                if cmd == "/exit":
                    # Special check for exit without killing test process
                    output = "‖ Graceful exit signal accepted ‖"
                    status = "PASS"
                else:
                    output = ciph.handle_command(cmd)
                    
                elapsed_ms = round((time.time() - t0) * 1000, 1)
                output_str = str(output) if output is not None else "None"
                
                # Analyze output quality
                if output is None:
                    status = "UNHANDLED (Returns None)"
                elif "Error:" in output_str or "error:" in output_str or "Exception" in output_str:
                    if "AttributeError" in output_str or "KeyError" in output_str or "TypeError" in output_str:
                        status = "CRASH / CODE_ERROR"
                    else:
                        status = "FUNCTIONAL_ERROR"
                elif "❌" in output_str or "🚨" in output_str:
                    status = "FAILED_CHECK / API_ERROR"
                elif "Unknown command" in output_str:
                    status = "UNKNOWN_COMMAND"
                elif "not implemented" in output_str.lower():
                    status = "NOT_IMPLEMENTED"
                else:
                    status = "PASS"

            except Exception as ex:
                elapsed_ms = round((time.time() - t0) * 1000, 1)
                status = "CRASH (Exception Raised)"
                output_str = str(ex)
                err_details = traceback.format_exc()

            test_record = {
                "command": cmd,
                "status": status,
                "latency_ms": elapsed_ms,
                "output_preview": output_str[:300].replace("\n", " "),
                "full_output": output_str,
                "error": err_details
            }
            results[category].append(test_record)

            icon = "✅" if status == "PASS" else ("⚠️" if "ERROR" in status or "FAILED" in status else "❌")
            print(f"  {icon} [{status}] {cmd:<35} ({elapsed_ms}ms)")
            if status != "PASS":
                print(f"     └─ Preview: {output_str[:160]}")

    # Save detailed JSON report
    with open(os.path.join(REPO_ROOT, 'test_audit_results.json'), 'w') as f:
        json.dump(results, f, indent=2)

    print("\n==================================================")
    print("📊 Audit Complete. Detailed JSON saved to test_audit_results.json")
    print("==================================================")

if __name__ == "__main__":
    run_tests()
