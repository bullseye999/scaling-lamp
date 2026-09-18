#!/usr/bin/env python3
# evolution_bridge.py - Self-Relevance Analyzer & Hypothesis Bridge for CIPH
import os
import ast
import time
import json
import random
from typing import Dict, Any, List, Optional
from cipher_vault import CipherVault

class SelfRelevanceAnalyzer:
    """
    Connects Cognitive Curiosity (ciph_evolution.py) with Self-Modification (self_awareness.py).
    Evaluates newly discovered principles against Ciph's codebase to formulate
    testable engineering hypotheses.
    """

    CAPABILITY_MAPPINGS = {
        "verification": {
            "keywords": ["verify", "invariant", "integrity", "validate", "check", "proof", "falsification"],
            "targets": ["query_router.py", "security_layer.py", "code_staging.py"],
            "hypothesis": "Add deterministic validation gates to eliminate edge-case evaluation errors."
        },
        "compression": {
            "keywords": ["compression", "entropy", "sparse", "compact", "efficiency", "state space", "reduction"],
            "targets": ["smart_memory.py", "world_telemetry.py", "ciph_router.py"],
            "hypothesis": "Implement dynamic context pruning to optimize token usage and memory lookup speed."
        },
        "concurrency": {
            "keywords": ["concurrency", "asynchronous", "parallel", "non-blocking", "event loop", "thread"],
            "targets": ["bounty_hunter.py", "pentest_engine.py", "darknet_monitor.py"],
            "hypothesis": "Introduce non-blocking session pooling to accelerate multi-target recon sweeps."
        },
        "rate_limiting": {
            "keywords": ["jitter", "timing", "friction", "adversarial", "evasion", "rate-limit", "stealth"],
            "targets": ["ghost_transport.py", "bounty_hunter.py", "ciph_link_reader.py"],
            "hypothesis": "Enforce adaptive timing jitter to prevent WAF detection and Tor circuit exhaustion."
        },
        "resilience": {
            "keywords": ["antifragile", "resilience", "redundancy", "failover", "fallback", "stability", "decoupling"],
            "targets": ["ciph_core.py", "ciph_evolution.py", "module_manager.py"],
            "hypothesis": "Implement isolated failover fallbacks to guarantee uninterrupted operational uptime."
        }
    }

    def __init__(self, vault: CipherVault, project_dir: Optional[str] = None):
        self.vault = vault
        self.project_dir = project_dir or os.path.dirname(os.path.abspath(__file__))

    def evaluate_blueprint(self, blueprint: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Analyze a cognitive blueprint to determine architectural self-relevance to Ciph.
        Returns a structured Engineering Hypothesis if relevant, or None if no direct code mutation applies.
        """
        from ciph.evolution.gap_detector import EngineeringGapDetector
        from ciph.memory.event_store import EventStore
        import hashlib
        db_path=getattr(self.vault,'db_path',None)
        if not db_path:
            raise ValueError('DURABLE_EVOLUTION_STORE_REQUIRED')
        gap_id=blueprint.get('engineering_gap_id')
        if not gap_id:
            EventStore(db_path).append_event('NoRelevanceFoundEvent',blueprint.get('blueprint_id','unbound'),
                {'reason':'VERIFIED_ENGINEERING_GAP_REQUIRED','timestamp':time.time()})
            return None
        detector=EngineeringGapDetector(db_path)
        gap=detector.get_gap(gap_id)
        if not gap:
            detector.evidence.record('NO_RELEVANCE_FOUND',{'gap_id':gap_id,'reason':'UNKNOWN_ENGINEERING_GAP'})
            return None
        target=os.path.abspath(blueprint.get('target_path',''))
        if os.path.commonpath([target,os.path.abspath(self.project_dir)])!=os.path.abspath(self.project_dir):
            raise ValueError('EVOLUTION_TARGET_OUTSIDE_PROJECT')
        from ciph.evolution.file_activation import locked_target,read_at
        with locked_target(target) as (parent,name):source,_=read_at(parent,name)
        if hashlib.sha256(source).hexdigest()!=gap.affected_revision:
            raise ValueError('ENGINEERING_TARGET_REVISION_MISMATCH')
        hypothesis={'gap_id':gap.gap_id,'blueprint_id':blueprint.get('blueprint_id'),
            'domain':'engineering','topic':gap.target_capability,'concept_class':gap.category.value,
            'target_module':os.path.basename(target),'target_path':target,
            'module_health':self._inspect_target_module(target),'hypothesis_text':gap.testable_improvement_criterion,
            'expected_metric':gap.testable_improvement_criterion,'timestamp':time.time(),'status':'FORMULATED'}
        identity=detector.evidence.record('ENGINEERING_HYPOTHESIS_PROPOSED',hypothesis)
        return {**hypothesis,'hypothesis_id':identity}

    def reanalyze_historical_blueprints(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retroactively analyze stored blueprints in vault and extract testable hypotheses."""
        blueprints = self.vault.get_cognitive_blueprints(limit=limit)
        formulated = []
        for bp in blueprints:
            hyp = self.evaluate_blueprint(bp)
            if hyp:
                formulated.append(hyp)
        return formulated

    def _inspect_target_module(self, filepath: str) -> Dict[str, Any]:
        """Perform static analysis on the target file"""
        if not os.path.exists(filepath):
            return {"exists": False, "loc": 0, "functions": 0, "syntax_valid": False}
        
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            tree = ast.parse(content)
            loc = len(content.splitlines())
            functions = sum(1 for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)))
            classes = sum(1 for node in ast.walk(tree) if isinstance(node, ast.ClassDef))
            return {
                "exists": True,
                "loc": loc,
                "functions": functions,
                "classes": classes,
                "syntax_valid": True
            }
        except Exception as e:
            return {"exists": True, "syntax_valid": False, "error": str(e)}

    def _record_hypothesis(self, hypothesis: Dict[str, Any]) -> bool:
        """Store the hypothesis in the vault for tracking"""
        try:
            summary = f"[{hypothesis['hypothesis_id']}] {hypothesis['concept_class'].upper()} -> {hypothesis['target_module']}: {hypothesis['hypothesis_text']}"
            self.vault.store_conversation(
                prompt=f"ENGINEERING_HYPOTHESIS: {hypothesis['hypothesis_id']}",
                response=json.dumps(hypothesis, indent=2),
                context_tag="evolution_hypothesis"
            )
            return True
        except Exception:
            return False

    def format_hypothesis_card(self, hyp: Dict[str, Any]) -> str:
        """Format an ASCII hypothesis card for display"""
        hid = hyp.get("hypothesis_id", "UNKNOWN")
        mod = hyp.get("target_module", "unknown.py")
        concept = hyp.get("concept_class", "general").upper()
        text = hyp.get("hypothesis_text", "")
        domain = hyp.get("domain", "General")
        b_id = hyp.get("blueprint_id", "EXP-UNKNOWN")

        card = f"""
┌─────────────────────────────────────────────────────────────────┐
│ 💡 CIPH ENGINEERING HYPOTHESIS: {hid:<32}│
├─────────────────────────────────────────────────────────────────┤
│ Target Module : {mod:<48}│
│ Capability    : {concept:<48}│
│ Source Domain : {domain[:48]:<48}│
│ Blueprint ID  : {b_id:<48}│
│ Hypothesis    : {text[:60]:<48}│
└─────────────────────────────────────────────────────────────────┘"""
        return card.strip()

if __name__ == "__main__":
    vault = CipherVault()
    analyzer = SelfRelevanceAnalyzer(vault)
    sample_bp = {
        "blueprint_id": "EXP-SAMPLE-01",
        "domain": "Frontier AI & Neural Mathematics",
        "topic": "Test-Time Compute Scaling and Reasoning Verifiers",
        "core_axiom": "Verification gates reduce entropy and eliminate invalid claims in high-dimensional search spaces.",
        "mechanics": "Independent verifiers filter out hallucinations before final state output.",
        "strategic_application": "Deploy deterministic AST verification on all generated actions."
    }
    hyp = analyzer.evaluate_blueprint(sample_bp)
    print("Formulated Hypothesis:")
    print(analyzer.format_hypothesis_card(hyp) if hyp else "No direct code relevance found.")
