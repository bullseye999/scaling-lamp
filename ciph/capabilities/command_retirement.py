"""Explicit diagnostics for commands whose governed implementation is still missing."""
import json
from pathlib import Path


def legacy_inventory():
    return json.loads(Path(__file__).with_name("legacy_command_inventory.json").read_text())


def disposition(name):
    if name not in legacy_inventory():
        return "UNKNOWN_COMMAND", "Unknown command. Use /help for supported commands."
    if name in {"/emergency-wipe", "/zeroize-mind", "/clean-footprints"}:
        return "DESTRUCTIVE_WORKFLOW_RETIRED", "Destructive legacy workflow unavailable; no governed recovery and authorization adapter exists."
    if name.startswith("/set-") or name in {"/setkey", "/setup-email"}:
        return "SECRET_CONFIGURATION_RETIRED", "Credential configuration via chat commands is unavailable. Configure the service through its trusted local configuration interface."
    if any(word in name for word in ("ghost", "council", "evolution", "self-analyze", "cold-start", "retroactive", "ponder", "swarm", "blueprint")):
        return "EXPERIMENTAL_WORK_DEFERRED", "Experimental workflow unavailable pending its governed implementation after Program 2. Stored records are accessible via /blueprints and /memory-graph."
    if any(word in name for word in ("workflow", "schedule", "auto-mode", "daily-reports", "send-report")):
        return "SCHEDULER_ADAPTER_MISSING", "Legacy automation unavailable: durable scheduling and per-action authorization adapters are missing. Use /jobs and /curiosity-status to inspect governed work."
    if name in {"/load", "/unload", "/fix-all-modules", "/rollback", "/reject", "/reject-upgrade", "/review", "/review-code"}:
        return "CODE_LIFECYCLE_ADAPTER_MISSING", "Code lifecycle command unavailable pending a bounded artifact adapter. Use /upgrades to list proposals; /apply requires a bound authorization grant."
    if any(word in name for word in ("scan", "fetch", "market", "trading", "tor-", "model", "runpod", "deepseek", "darknet", "recon", "network", "sports", "identity")):
        return "EXTERNAL_ADAPTER_MISSING", "External operation unavailable: a real source-specific sandbox/broker adapter is required. Existing reports never substitute for a fresh execution."
    return "GOVERNED_ADAPTER_MISSING", "Legacy command unavailable: its original feature has no reviewed governed adapter. Use /command-status and /help for available controls."


def coverage(registry):
    inventory = legacy_inventory()
    restored = sorted(name for name in inventory if registry.find_command(name))
    pending = [{"command": name, "reason": disposition(name)[0]} for name in sorted(inventory) if not registry.find_command(name)]
    return {"legacy_total": len(inventory), "registered_legacy_names": len(restored),
            "unavailable_legacy_names": len(pending), "registered": restored, "unavailable": pending,
            "note": "Registered means command wiring exists; backend availability is established at execution."}
