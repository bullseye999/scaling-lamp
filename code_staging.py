#!/usr/bin/env python3
# code_staging.py - Unified Code Staging, Sandbox Execution & Hot-Patching Engine for CIPH

import os
import sys
import ast
import json
import time
import shutil
import subprocess
import importlib
import importlib.util
import py_compile
import fcntl
import uuid
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

class CodeStagingManager:
    """
    Unified Code Staging & Governed Hot-Patching Engine.
    - Stages generated code artifacts into ciph_staging/
    - Safely audits missing pip dependencies without unauthorized auto-install
    - Performs syntax inspection; execution requires the independent grant-bound harness
    - Generates clean ASCII Staging Cards (zero terminal clutter)
    - Requires deployment and canary evidence for atomic file application
    - Rollback failsafe (/rollback <file>)
    - Structured audit changelog tracking (ciph_changelog.json)
    """

    STAGING_DIR = "ciph_staging"
    PROPOSALS_DIR = "ciph_proposals"
    BACKUPS_DIR = "ciph_backups"
    CHANGELOG_FILE = "ciph_changelog.json"
    INDEX_FILE = "ciph_staging/staging_index.json"

    # Known built-in Python standard library modules to skip when checking third-party packages
    STDLIB_MODULES = {
        'os', 'sys', 'ast', 'json', 'time', 'datetime', 'math', 're', 'random',
        'subprocess', 'threading', 'queue', 'collections', 'typing', 'itertools',
        'functools', 'pathlib', 'shutil', 'hashlib', 'base64', 'socket', 'ssl',
        'http', 'urllib', 'email', 'sqlite3', 'copy', 'tempfile', 'logging',
        'signal', 'inspect', 'importlib', 'py_compile', 'traceback', 'uuid',
        'io', 'select', 'struct', 'enum', 'dataclasses', 'contextlib'
    }

    def __init__(self, vault=None):
        self.vault = vault
        os.makedirs(self.STAGING_DIR, exist_ok=True)
        os.makedirs(self.PROPOSALS_DIR, exist_ok=True)
        os.makedirs(self.BACKUPS_DIR, exist_ok=True)
        self.staged_items: List[Dict[str, Any]] = []
        self._load_index()

    # ─────────────────────────────────────────────
    # INDEX & PERSISTENCE
    # ─────────────────────────────────────────────

    def _load_index(self):
        """Load staged index from JSON"""
        if os.path.exists(self.INDEX_FILE):
            try:
                with open(self.INDEX_FILE, 'r') as f:
                    self.staged_items = json.load(f)
            except Exception:
                self.staged_items = []
        else:
            self.staged_items = []

    def _save_index(self):
        """Save staged index to JSON"""
        try:
            with open(self.INDEX_FILE, 'w') as f:
                json.dump(self.staged_items, f, indent=2)
        except Exception as e:
            print(f"‖ CodeStaging Error saving index: {e} ‖")

    def _next_stage_id(self) -> str:
        """Generate next STG-XXX identifier"""
        self._load_index()
        existing_nums = []
        for item in self.staged_items:
            sid = item.get('id', '')
            if sid.startswith('STG-'):
                try:
                    num = int(sid.replace('STG-', ''))
                    existing_nums.append(num)
                except ValueError:
                    pass
        next_num = max(existing_nums, default=0) + 1
        return f"STG-{next_num:03d}"

    # ─────────────────────────────────────────────
    # DEPENDENCY AUDITOR & INSPECTOR (SAFE)
    # ─────────────────────────────────────────────

    def extract_dependencies(self, code: str) -> List[str]:
        """Extract imported package names using AST analysis"""
        dependencies = set()
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        top_pkg = alias.name.split('.')[0]
                        if top_pkg not in self.STDLIB_MODULES:
                            dependencies.add(top_pkg)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        top_pkg = node.module.split('.')[0]
                        if top_pkg not in self.STDLIB_MODULES:
                            dependencies.add(top_pkg)
        except Exception:
            pass
        return sorted(list(dependencies))

    def resolve_dependencies(self, dependencies: List[str]) -> Dict[str, bool]:
        """
        Check installed status of dependencies safely without auto-installing.
        Per Phase 0 safety invariants, automatic pip execution is strictly prohibited.
        Missing packages are flagged for operator approval and manual installation.
        """
        status = {}
        for dep in dependencies:
            if not isinstance(dep,str) or '.' in dep or not dep.isidentifier():
                status[str(dep)] = False
                continue
            try:
                if hasattr(importlib.util, 'find_spec'):
                    spec = importlib.util.find_spec(dep)
                    status[dep] = (spec is not None)
                else:
                    status[dep] = False
            except (ImportError, ModuleNotFoundError, ValueError, AttributeError):
                status[dep] = False
            except Exception:
                status[dep] = False

            if not status[dep]:
                print(f"🔒 [Dependency Policy] Missing package '{dep}' flagged. Auto-installation blocked by kernel policy.")
        return status

    # ─────────────────────────────────────────────
    # AUTO-SANDBOX EXECUTION TEST
    # ─────────────────────────────────────────────

    def run_sandbox_test(self, code: str, filename: str = 'candidate.py'):
        """Legacy syntax inspection only. Never certify or execute a candidate."""
        result={'passed':False,'syntax_valid':False,'runtime_sec':0.0,'stdout':'','stderr':'',
                'error':'EVALUATION_GRANT_REQUIRED: use IndependentBenchmarkHarness'}
        try:
            if len(code.encode())>262144:raise ValueError('CANDIDATE_SIZE_LIMIT')
            ast.parse(code);result['syntax_valid']=True
        except (SyntaxError,ValueError) as exc:result['error']=str(exc)
        return result

    # ─────────────────────────────────────────────
    # CODE STAGING & CARD GENERATION
    # ─────────────────────────────────────────────

    def stage_code(self, title: str, description: str, target_file: str,
                   code_content: str, is_new_file: bool = None) -> Dict[str, Any]:
        """
        Save exact candidate bytes and syntax/dependency inspection results; never execute them.
        """
        stage_id = self._next_stage_id()
        base_name = os.path.basename(target_file)
        staged_filename = f"{stage_id}_{base_name}"
        staged_filepath = os.path.join(self.STAGING_DIR, staged_filename)

        if is_new_file is None:
            is_new_file = not os.path.exists(target_file)

        # 1. Save staged file
        with open(staged_filepath, 'w') as f:
            f.write(code_content)

        # 2. Dependency resolution
        deps = self.extract_dependencies(code_content)
        dep_status = self.resolve_dependencies(deps)

        # 3. Sandbox test
        sandbox_res = self.run_sandbox_test(code_content, base_name)

        # Inert staging is not evaluation authority. A separately signed evaluation
        # grant and the independent harness are required before any code executes.
        benchmark_data = None

        line_count = len(code_content.split('\n'))

        artifact = {
            'id': stage_id,
            'title': title,
            'description': description,
            'target_file': target_file,
            'staged_file': staged_filepath,
            'is_new_file': is_new_file,
            'line_count': line_count,
            'dependencies': deps,
            'dependencies_installed': all(dep_status.values()) if dep_status else True,
            'sandbox_passed': sandbox_res['passed'],
            'sandbox_runtime_sec': sandbox_res['runtime_sec'],
            'sandbox_error': sandbox_res.get('error'),
            'benchmark': benchmark_data,
            'staged_at': datetime.now().isoformat(),
            'status': 'PENDING'
        }

        self.staged_items.append(artifact)
        self._save_index()

        return artifact

    def format_staging_card(self, artifact: Dict[str, Any]) -> str:
        """Render the complete ASCII Staging Card"""
        stage_id = artifact['id']
        staged_path = artifact['staged_file']
        target = artifact['target_file']
        lines = artifact['line_count']
        desc = artifact['description']
        deps = artifact.get('dependencies', [])
        sandbox_pass = artifact.get('sandbox_passed', False)
        runtime = artifact.get('sandbox_runtime_sec', 0.0)
        bench = artifact.get('benchmark')

        dep_str = ", ".join(deps) if deps else "None (Pure Standard Library)"
        dep_status = "✅ All installed in venv" if artifact.get('dependencies_installed', True) else "⚠️ Some dependencies failed"
        sandbox_str = f"✅ PASSED ({runtime}s runtime, zero errors)" if sandbox_pass else f"❌ FAILED ({artifact.get('sandbox_error', 'Execution error')[:40]})"

        bench_block = ""
        if bench:
            b_emoji = "✅" if bench['verdict'] in ['IMPROVED', 'NEUTRAL'] else "❌"
            bench_str = f"{b_emoji} {bench['verdict']} ({bench['delta_pct']:+.1f}% vs baseline)"
            bench_block = f"│ Benchmark:    {bench_str:<49} │\n"

        card = f"""
┌─────────────────────────────────────────────────────────────────┐
│ 📦 CODE ARTIFACT STAGED: {staged_path:<38} │
│ Target: {target:<30} | Size: {lines:>3} lines       │
│ Syntax: ✅ VALID                                                │
│ Dependencies: {dep_str:<49} │
│   → {dep_status:<59} │
│ Sandbox Test: {sandbox_str:<49} │
{bench_block}│ Description: {desc[:50]:<50} │
│ Status: PENDING OPERATOR APPROVAL                               │
│                                                                 │
│ Actions:                                                        │
│   /apply {stage_id}   → Write to workspace (with backup)          │
│   /review {stage_id}  → Preview the code cleanly                  │
│   /reject {stage_id}  → Discard staged file                       │
│                                                                 │
│ Rollback available after apply: /rollback {os.path.basename(target):<22} │
└─────────────────────────────────────────────────────────────────┘"""
        return card

    # ─────────────────────────────────────────────
    # APPLY, REVIEW, REJECT & ROLLBACK
    # ─────────────────────────────────────────────

    def find_artifact(self, identifier: str) -> Optional[Dict[str, Any]]:
        """Find artifact by ID (supports STG-XXX, UP-XXX, or simple number)"""
        self._load_index()
        target_id = identifier.upper().strip()
        for item in self.staged_items:
            if item.get('id', '').upper() == target_id:
                return item

        # Also check proposals directory for UP-XXX if from self_awareness
        if target_id.startswith('UP-'):
            for item in self.staged_items:
                if item.get('id') == target_id:
                    return item
            # Look in ciph_proposals index
            prop_index = os.path.join(self.PROPOSALS_DIR, "pending_upgrades.json")
            if os.path.exists(prop_index):
                try:
                    with open(prop_index, 'r') as f:
                        props = json.load(f)
                        for p in props:
                            if p.get('id') == target_id:
                                return {
                                    'id': p['id'],
                                    'title': p['title'],
                                    'description': p.get('description', ''),
                                    'target_file': p.get('target_file', p.get('module', '')),
                                    'staged_file': p.get('proposal_file', ''),
                                    'is_new_file': p.get('is_new_file', False),
                                    'line_count': 0,
                                    'status': p.get('status', 'PENDING')
                                }
                except Exception:
                    pass
        return None

    def apply(self, identifier, deployment_grant=None, trust_registry=None, *, stage="PRODUCTION"):
        """Promotion requires authentic evidence and a completed governed canary."""
        from ciph.contracts.evolution import EvolutionDeploymentGrant
        from ciph.evolution.evidence import EvolutionEvidenceStore
        from ciph.evolution.file_activation import activate
        if not isinstance(deployment_grant, EvolutionDeploymentGrant) or trust_registry is None:
            return False, "Aborted: AUTHORIZATION_REQUIRED: EvolutionDeploymentGrant required"
        try:
            store = EvolutionEvidenceStore(trust_registry)
            store.validate_deployment(deployment_grant)
            if stage != "PRODUCTION" or stage not in deployment_grant.permitted_stages:
                raise ValueError("PRODUCTION_STAGE_NOT_AUTHORIZED")
            # A deployment approval alone cannot skip the canary gate.
            with store.events._get_connection() as conn:
                row = conn.execute("SELECT evidence_hash FROM ciph_canary_acceptance WHERE grant_id=?",
                                   (deployment_grant.grant_id,)).fetchone()
            if not row:
                raise ValueError("VERIFIED_CANARY_REQUIRED")
            evidence = store.verify(row[0], 'CANARY_ACCEPTED')
            if (evidence['grant_hash'] != hashlib.sha256(deployment_grant.compute_canonical_payload()).hexdigest()
                    or evidence['candidate_hash'] != deployment_grant.candidate_hash):
                raise ValueError("CANARY_BINDING_MISMATCH")
            shadow=store.verify(evidence['shadow_evidence'],'SHADOW_VERIFIED')
            if shadow['candidate_hash']!=deployment_grant.candidate_hash:
                raise ValueError('SHADOW_BINDING_MISMATCH')
            artifact = self.find_artifact(identifier)
            if not artifact:
                raise ValueError("STAGED_ARTIFACT_NOT_FOUND")
            if artifact.get('status') != 'PENDING':
                raise ValueError('STAGED_ARTIFACT_NOT_PENDING')
            applied,message = activate(artifact, deployment_grant, store)
            if applied:
                artifact['status']='APPLIED'
                artifact['applied_at']=datetime.now().isoformat()
                self._save_index()
            return applied,message
        except Exception as exc:
            return False, "Aborted: " + str(exc)

    def review(self, identifier: str) -> str:
        """Cleanly review staged code without dumping hundreds of lines to scrollback"""
        artifact = self.find_artifact(identifier)
        if not artifact:
            return f"‖ Artifact '{identifier}' not found. ‖"

        staged_file = artifact.get('staged_file', '')
        if not os.path.exists(staged_file):
            return f"‖ Staged file not found: {staged_file} ‖"

        # Read lines
        with open(staged_file, 'r') as f:
            lines = f.readlines()

        total = len(lines)
        preview = lines[:30]
        preview_text = "".join(preview)

        out = [
            f"📄 REVIEW STAGED ARTIFACT: {artifact['id']} ({staged_file})",
            f"Target: {artifact['target_file']} | Lines: {total}",
            "═" * 65,
            preview_text
        ]
        if total > 30:
            out.append(f"\n... [{total - 30} more lines in {staged_file}] ...")
            out.append(f"💡 Tip: Run 'cat {staged_file}' or 'nano {staged_file}' to inspect the full file.")

        return "\n".join(out)

    def reject(self, identifier: str, reason: str = "") -> str:
        """Reject and dismiss a staged code artifact"""
        artifact = self.find_artifact(identifier)
        if not artifact:
            return f"‖ Artifact '{identifier}' not found. ‖"

        artifact['status'] = 'REJECTED'
        artifact['rejected_at'] = datetime.now().isoformat()
        artifact['reject_reason'] = reason
        self._save_index()

        return f"🚫 Staged code artifact {artifact['id']} rejected and archived."

    def rollback(self, target_filename, candidate_hash=None, *, deployment_grant=None, trust_registry=None):
        """Restore only the exact grant-bound revision, never a basename-selected backup."""
        from ciph.contracts.evolution import EvolutionDeploymentGrant
        from ciph.evolution.evidence import EvolutionEvidenceStore
        from ciph.evolution.file_activation import restore
        if not isinstance(deployment_grant, EvolutionDeploymentGrant) or trust_registry is None:
            return False, "Rollback refused: AUTHORIZATION_REQUIRED"
        try:
            if os.path.abspath(target_filename) != os.path.abspath(deployment_grant.target_file_path) or candidate_hash != deployment_grant.candidate_hash:
                raise ValueError("ROLLBACK_BINDING_MISMATCH")
            return restore(deployment_grant, EvolutionEvidenceStore(trust_registry))
        except Exception as exc:
            return False, "Rollback refused: " + str(exc)

    def _record_changelog(self, item_id: str, target_file: str, action: str,
                          description: str, backup_file: Optional[str], line_count: int):
        """Append an entry to ciph_changelog.json"""
        entries = []
        if os.path.exists(self.CHANGELOG_FILE):
            try:
                with open(self.CHANGELOG_FILE, 'r') as f:
                    entries = json.load(f)
            except Exception:
                entries = []

        entry = {
            'id': item_id,
            'timestamp': datetime.now().isoformat(),
            'target_file': target_file,
            'action': action,
            'description': description,
            'line_count': line_count,
            'backup_file': backup_file,
            'author': "CIPH Autonomous Engine"
        }
        entries.append(entry)

        try:
            with open(self.CHANGELOG_FILE, 'w') as f:
                json.dump(entries, f, indent=2)
        except Exception as e:
            print(f"‖ Changelog Error: {e} ‖")

    def get_changelog(self, limit: int = 8) -> str:
        """Display recent changelog entries"""
        if not os.path.exists(self.CHANGELOG_FILE):
            return "‖ No changelog entries recorded yet. ‖"

        try:
            with open(self.CHANGELOG_FILE, 'r') as f:
                entries = json.load(f)
        except Exception as e:
            return f"‖ Failed to load changelog: {e} ‖"

        if not entries:
            return "‖ Changelog is currently empty. ‖"

        lines = ["📝 CIPH AUTONOMOUS CODE EVOLUTION CHANGELOG", "═" * 58]
        for e in entries[-limit:][::-1]:
            lines.append(f"• [{e.get('timestamp')[:16]}] {e.get('id')} — {e.get('action')}: {e.get('target_file')}")
            lines.append(f"  Summary: {e.get('description')}")
            if e.get('backup_file'):
                lines.append(f"  Backup: {os.path.basename(e.get('backup_file'))}")
            lines.append("")

        return "\n".join(lines)

    def list_staged(self) -> str:
        """List all staged items"""
        self._load_index()
        if not self.staged_items:
            return "‖ No code artifacts currently staged. ‖"

        lines = ["📦 CIPH STAGED CODE ARTIFACTS & PROPOSALS", "═" * 58]
        pending = [i for i in self.staged_items if i.get('status') == 'PENDING']
        applied = [i for i in self.staged_items if i.get('status') == 'APPLIED']

        if pending:
            lines.append("⏳ PENDING OPERATOR APPROVAL:")
            for p in pending:
                lines.append(f"  • [{p['id']}] {p['target_file']} ({p['line_count']} lines) - {p['title']}")
                lines.append(f"    Apply: /apply {p['id']} | Review: /review {p['id']}")
            lines.append("")

        if applied:
            lines.append("✅ RECENTLY APPLIED:")
            for a in applied[-3:]:
                lines.append(f"  • [{a['id']}] {a['target_file']} (Applied: {a.get('applied_at', '')[:16]})")

        return "\n".join(lines)
