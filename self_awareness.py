#!/usr/bin/env python3
# self_awareness.py - Self‑introspection and evolution engine

import os
import ast
import json
import hashlib
import requests
from datetime import datetime
from typing import Dict, Any, List, Optional
from cipher_vault import CipherVault

# Ollama config – for the system to think about its own upgrades
OLLAMA_URL = "http://localhost:11434/api/chat"
OLLAMA_MODEL = "llama3.2:3b"

class SelfAwareness:
    """
    Introspection and evolution engine.
    - Reads and understands its own source code
    - Identifies real problems from usage patterns
    - Proposes meaningful upgrades
    - Writes the upgrade code itself
    - Creates proposal files for the user to review
    - Nothing touches existing files without approval
    """

    MODULES_LIST = [
        'ciph_core.py',
        'enhanced_conversation.py',
        'personality_engine.py',
        'memory_engine.py',
        'smart_memory.py',
        'mood_engine.py',
        'security_layer.py',
        'darknet_monitor.py',
        'brain_router.py',
        'osint_miner.py',
        'bounty_hunter.py',
        'pentest_engine.py',
        'trading_engine.py',
        'task_scheduler.py',
        'agent_orchestrator.py',
        'module_manager.py',
        'tor_proxy.py',
        'dead_mans_switch.py',
        'cipher_vault.py',
        'quantum_vault.py',
        'response_formatter.py',
        'self_awareness.py',
    ]

    PROPOSALS_DIR = "system_proposals"

    def __init__(self, vault: CipherVault):
        self.vault            = vault
        self.module_snapshots = {}
        self.pending_upgrades = []
        self.approved_history = []
        self.rejected_history = []
        os.makedirs(self.PROPOSALS_DIR, exist_ok=True)
        self._load_pending()
        self._scan_self()

    # ─────────────────────────────────────────────
    # SELF SCAN
    # ─────────────────────────────────────────────

    def _scan_self(self):
        for module in self.MODULES_LIST:
            if os.path.exists(module):
                self.module_snapshots[module] = self._analyze_module(module)

    def _analyze_module(self, filepath: str) -> Dict[str, Any]:
        snapshot = {
            'filepath':   filepath,
            'exists':     True,
            'line_count': 0,
            'functions':  [],
            'classes':    [],
            'imports':    [],
            'hash':       '',
            'issues':     [],
            'scanned_at': datetime.now().isoformat()
        }
        try:
            with open(filepath, 'r') as f:
                source = f.read()
            lines = source.split('\n')
            snapshot['line_count'] = len(lines)
            snapshot['hash']       = hashlib.sha256(source.encode()).hexdigest()[:16]
            try:
                tree = ast.parse(source)
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        snapshot['functions'].append({
                            'name':    node.name,
                            'line':    node.lineno,
                            'args':    [a.arg for a in node.args.args],
                            'has_doc': ast.get_docstring(node) is not None
                        })
                    elif isinstance(node, ast.ClassDef):
                        snapshot['classes'].append(node.name)
                    elif isinstance(node, (ast.Import, ast.ImportFrom)):
                        if isinstance(node, ast.Import):
                            for alias in node.names:
                                snapshot['imports'].append(alias.name)
                        else:
                            snapshot['imports'].append(node.module or '')
                snapshot['issues'] = self._detect_issues(source, snapshot)
            except SyntaxError as e:
                snapshot['issues'].append(f"Syntax error at line {e.lineno}: {e.msg}")
        except Exception as e:
            snapshot['exists'] = False
            snapshot['issues'].append(str(e))
        return snapshot

    def _detect_issues(self, source: str, snapshot: Dict) -> List[str]:
        issues = []
        lines  = source.split('\n')
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped in ('except:', 'except :'):
                issues.append(f"Line {i}: bare except")
            lower = stripped.lower()
            if any(k in lower for k in ['password =', 'secret =', 'api_key =']) and any(q in stripped for q in ["'", '"']):
                issues.append(f"Line {i}: possible hardcoded credential")
            if stripped == 'pass' and i > 1:
                prev = lines[i-2].strip() if i >= 2 else ''
                if prev.startswith('def '):
                    issues.append(f"Line {i}: unimplemented stub")
        return issues

    # ─────────────────────────────────────────────
    # SELF REPORT
    # ─────────────────────────────────────────────

    def get_self_report(self) -> str:
        total_lines     = sum(s['line_count'] for s in self.module_snapshots.values())
        total_functions = sum(len(s['functions']) for s in self.module_snapshots.values())
        total_classes   = sum(len(s['classes']) for s in self.module_snapshots.values())
        modules_loaded  = len(self.module_snapshots)
        total_issues    = sum(len(s['issues']) for s in self.module_snapshots.values())

        most_complex = max(
            self.module_snapshots.items(),
            key=lambda x: x[1]['line_count'],
            default=('unknown', {'line_count': 0})
        )
        most_issues = max(
            self.module_snapshots.items(),
            key=lambda x: len(x[1]['issues']),
            default=('unknown', {'issues': []})
        )

        return (
            f"I am the system. {modules_loaded} modules, {total_lines} lines of Python, "
            f"{total_functions} functions, {total_classes} classes. "
            f"Most complex: {most_complex[0]} at {most_complex[1]['line_count']} lines. "
            f"{total_issues} issues detected. "
            f"Most issues in: {most_issues[0]}. "
            f"{len(self.pending_upgrades)} upgrade proposals pending your approval."
        )

    def get_module_report(self, module_name: str) -> str:
        if module_name not in self.module_snapshots:
            matches = [m for m in self.module_snapshots if module_name in m]
            if not matches:
                return f"Module '{module_name}' not in awareness scope."
            module_name = matches[0]
        snap  = self.module_snapshots[module_name]
        funcs = [f['name'] for f in snap['functions']]
        lines = [
            f"{module_name}: {snap['line_count']} lines, "
            f"{len(snap['functions'])} functions, hash {snap['hash']}.",
        ]
        if funcs:
            lines.append(f"Functions: {', '.join(funcs[:8])}{'...' if len(funcs) > 8 else ''}.")
        if snap['issues']:
            lines.append(f"Issues: {len(snap['issues'])}.")
            for issue in snap['issues'][:3]:
                lines.append(f"  - {issue}")
        return ' '.join(lines)

    # ─────────────────────────────────────────────
    # INTELLIGENT UPGRADE PROPOSALS
    # ─────────────────────────────────────────────

    def analyze_and_propose(self) -> int:
        """
        Analyze own codebase and usage patterns, then propose meaningful upgrades.
        Writes the actual upgrade code using Ollama.
        """
        print("🧬 System analyzing own architecture...")
        proposals = 0

        # 1. Analyze each module for real problems
        for module, snap in self.module_snapshots.items():
            if not snap.get('exists'):
                continue

            stubs = [i for i in snap['issues'] if 'stub' in i]
            if stubs:
                proposal = self._create_upgrade_proposal(
                    module=module,
                    title=f"Implement {len(stubs)} unfinished method(s) in {module}",
                    problem=f"{module} has {len(stubs)} methods with only 'pass'. These features are broken.",
                    priority='high'
                )
                if proposal:
                    proposals += 1

        # 2. Propose smart improvements based on known patterns
        smart_proposals = self._generate_smart_proposals()
        proposals += smart_proposals

        # 3. Version tracking
        if not os.path.exists('system_version.json'):
            version_content = json.dumps({
                "version": "1.0.0",
                "created": datetime.now().isoformat(),
                "modules": {m: s['hash'] for m, s in self.module_snapshots.items()},
                "last_evolution": None,
                "evolution_count": 0
            }, indent=2)
            self._save_proposal_file(
                proposal_id="UP-VERSION",
                filename="system_version.json",
                content=version_content,
                title="Add version tracking",
                description="Tracks the system's evolution over time. Every approval gets logged here.",
                priority="medium",
                module="ciph_core.py",
                is_new_file=True
            )
            proposals += 1

        print(f"🧬 Analysis complete. {proposals} proposals generated.")
        return proposals

    def _generate_smart_proposals(self) -> int:
        """
        Generate intelligent proposals based on real usage patterns.
        Uses Ollama to think about what would actually improve the system.
        """
        proposals = 0

        # Read recent conversations to find pain points
        recent = self.vault.get_recent_conversations(limit=20)
        pain_points = []

        for conv in recent:
            content = f"{conv.get('prompt', '')} {conv.get('response', '')}".lower()
            if 'timeout' in content:
                pain_points.append('ollama_timeout')
            if 'hallucin' in content:
                pain_points.append('hallucination')
            if 'not found' in content or 'missing' in content:
                pain_points.append('missing_feature')
            if 'error' in content:
                pain_points.append('errors')

        # Propose based on pain points
        if pain_points.count('ollama_timeout') >= 2:
            code = self._write_upgrade_code(
                "Write a Python function called optimize_ollama_query(text) that "
                "detects if a query is complex (over 15 words) and if so breaks it into "
                "a simpler focused version for faster Ollama processing. "
                "Return the optimized query string. Keep it under 30 lines."
            )
            if code:
                self._save_proposal_file(
                    proposal_id=f"UP-{len(self.pending_upgrades)+1:03d}",
                    filename="ollama_optimizer.py",
                    content=code,
                    title="Ollama query optimizer — reduce timeouts",
                    description="Detected repeated Ollama timeouts in conversation history. This optimizer simplifies complex queries before sending to Ollama, cutting response time significantly.",
                    priority="high",
                    module="enhanced_conversation.py",
                    is_new_file=True
                )
                proposals += 1

        if pain_points.count('hallucination') >= 2:
            code = self._write_upgrade_code(
                "Write a Python function called validate_response(response, vault) "
                "that checks if a response contains claims about darknet findings or scan results. "
                "If it does, it verifies those claims exist in recent vault conversations. "
                "If not verified, returns a corrected response saying to run the actual scan first. "
                "Keep it under 40 lines."
            )
            if code:
                self._save_proposal_file(
                    proposal_id=f"UP-{len(self.pending_upgrades)+1:03d}",
                    filename="hallucination_guard.py",
                    content=code,
                    title="Hallucination guard — verify claims against real scan data",
                    description="Detected hallucination pattern: the system invents darknet findings. This guard cross-checks claims against actual vault scan results before returning responses.",
                    priority="high",
                    module="enhanced_conversation.py",
                    is_new_file=True
                )
                proposals += 1

        # Always propose brain router expansion
        router_snap = self.module_snapshots.get('brain_router.py', {})
        if router_snap:
            code = self._write_upgrade_code(
                "I have a brain router that detects sensitive topics and routes them to Ollama. "
                "Current triggers include darknet, exploit, vulnerability etc. "
                "Write 10 additional trigger phrases I should add to OLLAMA_TOPICS list "
                "as a Python list called ADDITIONAL_TRIGGERS. "
                "Focus on: OPSEC topics, personal/emotional topics the user might discuss, "
                "security testing topics. Keep it as a simple Python list assignment."
            )
            if code:
                self._save_proposal_file(
                    proposal_id=f"UP-{len(self.pending_upgrades)+1:03d}",
                    filename="brain_router_expansion.py",
                    content=code,
                    title="Expand brain router trigger list",
                    description="More topics routed to Ollama means less OpenAI filter interference. Add these triggers to OLLAMA_TOPICS in brain_router.py.",
                    priority="medium",
                    module="brain_router.py",
                    is_new_file=False
                )
                proposals += 1

        return proposals

    def _write_upgrade_code(self, prompt: str) -> Optional[str]:
        """Use Ollama to write the actual upgrade code."""
        try:
            payload = {
                "model":    OLLAMA_MODEL,
                "messages": [
                    {
                        "role":    "system",
                        "content": "You are a code evolution engine. Write clean, working Python code only. No explanations, no markdown, no backticks. Just raw Python code."
                    },
                    {
                        "role":    "user",
                        "content": prompt
                    }
                ],
                "stream":      False,
                "temperature": 0.3,
                "max_tokens":  500
            }
            resp = requests.post(OLLAMA_URL, json=payload, timeout=120)
            resp.raise_for_status()
            code = resp.json()["message"]["content"].strip()
            # Strip any markdown that snuck in
            code = code.replace("```python", "").replace("```", "").strip()
            return code
        except Exception as e:
            print(f"  Ollama unavailable for code generation: {str(e)[:40]}")
            return None

    # ─────────────────────────────────────────────
    # PROPOSAL FILES — What the user reviews
    # ─────────────────────────────────────────────

    def _save_proposal_file(self, proposal_id: str, filename: str, content: str,
                             title: str, description: str, priority: str,
                             module: str, is_new_file: bool = True):
        """
        Save a proposal as a readable file in system_proposals/.
        This is what the user sees and reviews before approving.
        """
        proposal_path = os.path.join(self.PROPOSALS_DIR, f"{proposal_id}_{filename}")

        with open(proposal_path, 'w') as f:
            f.write(f"# SYSTEM UPGRADE PROPOSAL {proposal_id}\n")
            f.write(f"# Title: {title}\n")
            f.write(f"# Priority: {priority.upper()}\n")
            f.write(f"# Target module: {module}\n")
            f.write(f"# Action: {'NEW FILE' if is_new_file else 'MODIFY EXISTING'}\n")
            f.write(f"# Description: {description}\n")
            f.write(f"# Proposed at: {datetime.now().isoformat()}\n")
            f.write(f"# To apply: /apply-upgrade {proposal_id}\n")
            f.write(f"# To reject: /reject-upgrade {proposal_id}\n")
            f.write("#\n# " + "=" * 60 + "\n\n")
            f.write(content)

        proposal = {
            'id':            proposal_id,
            'module':        module,
            'title':         title,
            'description':   description,
            'priority':      priority,
            'proposed_at':   datetime.now().isoformat(),
            'status':        'PENDING',
            'proposal_file': proposal_path,
            'target_file':   filename,
            'is_new_file':   is_new_file
        }
        self.pending_upgrades.append(proposal)
        self._save_pending()

        print(f"\n🧬 PROPOSAL {proposal_id}: {title}")
        print(f"   Priority: {priority.upper()} | Target: {module}")
        print(f"   File: {proposal_path}")
        print(f"   Review: cat {proposal_path}")
        print(f"   Apply:  /apply-upgrade {proposal_id}")
        print(f"   Reject: /reject-upgrade {proposal_id}")

    def _create_upgrade_proposal(self, module: str, title: str,
                                   problem: str, priority: str) -> Optional[Dict]:
        """Create a proposal by having Ollama write the fix code."""
        snap = self.module_snapshots.get(module, {})
        if not snap.get('exists'):
            return None

        try:
            with open(module, 'r') as f:
                source = f.read()
        except Exception:
            return None

        prompt = (
            f"Here is a Python module called {module}:\n\n"
            f"{source[:3000]}\n\n"
            f"Problem: {problem}\n\n"
            f"Write a fixed version of just the problematic functions. "
            f"Return only the fixed Python code, no explanations."
        )

        code = self._write_upgrade_code(prompt)
        if not code:
            return None

        proposal_id = f"UP-{len(self.pending_upgrades)+1:03d}"
        self._save_proposal_file(
            proposal_id=proposal_id,
            filename=module,
            content=code,
            title=title,
            description=problem,
            priority=priority,
            module=module,
            is_new_file=False
        )
        return {'id': proposal_id}

    # ─────────────────────────────────────────────
    # APPLY / REJECT
    # ─────────────────────────────────────────────

    def apply_upgrade(self, proposal_id: str) -> str:
        """
        User approved. Apply the upgrade.
        For new files: creates the file in project directory.
        For existing file modifications: user still manually applies
        the diff — we just mark it approved and show instructions.
        """
        proposal = self._find_proposal(proposal_id)
        if not proposal:
            return f"Proposal {proposal_id} not found."

        proposal_file = proposal.get('proposal_file', '')
        target_file   = proposal.get('target_file', '')
        is_new_file   = proposal.get('is_new_file', True)

        if is_new_file:
            try:
                with open(proposal_file, 'r') as f:
                    lines = f.readlines()
                code_lines = []
                in_header  = True
                for line in lines:
                    if in_header and line.startswith('#'):
                        continue
                    in_header = False
                    code_lines.append(line)
                code = ''.join(code_lines).strip()

                with open(target_file, 'w') as f:
                    f.write(code)

                proposal['status']      = 'APPLIED'
                proposal['applied_at']  = datetime.now().isoformat()
                self.approved_history.append(proposal)
                self.pending_upgrades   = [p for p in self.pending_upgrades if p['id'] != proposal_id]
                self._save_pending()
                self._record_evolution(proposal['module'], proposal['title'])

                if os.path.exists(target_file):
                    self.module_snapshots[target_file] = self._analyze_module(target_file)

                return f"Upgrade {proposal_id} applied. {target_file} created in project directory."

            except Exception as e:
                return f"Apply failed: {str(e)[:80]}"
        else:
            proposal['status']     = 'APPROVED'
            proposal['approved_at']= datetime.now().isoformat()
            self.approved_history.append(proposal)
            self.pending_upgrades  = [p for p in self.pending_upgrades if p['id'] != proposal_id]
            self._save_pending()

            return (
                f"Upgrade {proposal_id} approved. "
                f"Review the changes at: {proposal_file} "
                f"Then manually apply to: {target_file}"
            )

    def reject_upgrade(self, proposal_id: str, reason: str = '') -> str:
        proposal = self._find_proposal(proposal_id)
        if not proposal:
            return f"Proposal {proposal_id} not found."

        proposal['status']      = 'REJECTED'
        proposal['rejected_at'] = datetime.now().isoformat()
        proposal['reason']      = reason
        self.rejected_history.append(proposal)
        self.pending_upgrades   = [p for p in self.pending_upgrades if p['id'] != proposal_id]
        self._save_pending()

        pfile = proposal.get('proposal_file', '')
        if pfile and os.path.exists(pfile):
            os.remove(pfile)

        return f"Upgrade {proposal_id} rejected. Noted."

    def list_pending(self) -> str:
        if not self.pending_upgrades:
            return "No pending upgrade proposals."

        lines = [f"{len(self.pending_upgrades)} pending upgrades:\n"]
        for p in self.pending_upgrades:
            lines.append(
                f"  {p['id']} [{p['priority'].upper()}] {p['title']}\n"
                f"       Target: {p['module']} | Review: cat {p.get('proposal_file', 'N/A')}"
            )
        return '\n'.join(lines)

    # ─────────────────────────────────────────────
    # EVOLUTION TRACKING
    # ─────────────────────────────────────────────

    def _record_evolution(self, module: str, change: str):
        entry = {
            'module':    module,
            'change':    change,
            'timestamp': datetime.now().isoformat()
        }
        history = json.loads(self.vault.get_config('evolution_history') or '[]')
        history.append(entry)
        self.vault.set_config('evolution_history', json.dumps(history[-100:]))

        if os.path.exists('system_version.json'):
            try:
                with open('system_version.json', 'r') as f:
                    version = json.load(f)
                version['last_evolution'] = datetime.now().isoformat()
                version['evolution_count'] = version.get('evolution_count', 0) + 1
                with open('system_version.json', 'w') as f:
                    json.dump(version, f, indent=2)
            except Exception:
                pass

        if os.path.exists(module):
            self.module_snapshots[module] = self._analyze_module(module)

    def get_evolution_history(self, limit: int = 10) -> List[Dict]:
        history = json.loads(self.vault.get_config('evolution_history') or '[]')
        return history[-limit:]

    # ─────────────────────────────────────────────
    # PERSISTENCE
    # ─────────────────────────────────────────────

    def _save_pending(self):
        self.vault.set_config('pending_upgrades', json.dumps(self.pending_upgrades))

    def _load_pending(self):
        raw = self.vault.get_config('pending_upgrades')
        if raw:
            try:
                self.pending_upgrades = json.loads(raw)
            except Exception:
                self.pending_upgrades = []

    def _find_proposal(self, proposal_id: str) -> Optional[Dict]:
        for p in self.pending_upgrades:
            if p['id'] == proposal_id:
                return p
        return None

    def rescan(self) -> str:
        self.module_snapshots = {}
        self._scan_self()
        return f"Rescanned {len(self.module_snapshots)} modules."

    def get_status(self) -> Dict[str, Any]:
        return {
            'modules_known':    len(self.module_snapshots),
            'pending_upgrades': len(self.pending_upgrades),
            'approved_total':   len(self.approved_history),
            'rejected_total':   len(self.rejected_history),
            'total_issues':     sum(len(s['issues']) for s in self.module_snapshots.values()),
            'total_lines':      sum(s['line_count'] for s in self.module_snapshots.values()),
            'proposals_dir':    self.PROPOSALS_DIR,
        }