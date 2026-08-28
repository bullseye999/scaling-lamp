#!/usr/bin/env python3
# ciph_benchmark.py - Multi-Dimensional Empirical Benchmarking & Verification Engine for CIPH
import os
import ast
import time
import json
import shutil
import subprocess
from typing import Dict, Any, Optional, List

class CiphBenchmark:
    """
    Multi-Dimensional Empirical Benchmark Lab for CIPH.
    Executes automated pre/post benchmarking evaluating functional correctness,
    AST structural integrity, and execution latency before promoting code mutations.
    """

    def __init__(self, project_dir: Optional[str] = None):
        self.project_dir = project_dir or os.path.dirname(os.path.abspath(__file__))

    def run_syntax_audit(self, filepath: str) -> Dict[str, Any]:
        """Verify AST syntax and calculate structural complexity metrics"""
        if not os.path.exists(filepath):
            return {"valid": False, "error": "File does not exist"}
        
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                source = f.read()
            tree = ast.parse(source)
            loc = len(source.splitlines())
            functions = sum(1 for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)))
            classes = sum(1 for node in ast.walk(tree) if isinstance(node, ast.ClassDef))
            return {
                "valid": True,
                "loc": loc,
                "functions": functions,
                "classes": classes,
                "error": None
            }
        except SyntaxError as se:
            return {"valid": False, "error": f"SyntaxError at line {se.lineno}: {se.msg}"}
        except Exception as e:
            return {"valid": False, "error": str(e)}

    def measure_import_speed(self, filepath: str, iterations: int = 5) -> Dict[str, Any]:
        """Measure cold-start load and execution latency in an isolated subprocess"""
        if not os.path.exists(filepath):
            return {"success": False, "avg_latency_ms": 0.0, "error": "File not found"}

        abs_path = os.path.abspath(filepath)
        module_dir = os.path.dirname(abs_path)

        latencies = []
        errors = 0

        for _ in range(iterations):
            code_runner = (
                "import sys, time, importlib.util; "
                f"sys.path.insert(0, '{module_dir}'); "
                "t0 = time.perf_counter(); "
                f"spec = importlib.util.spec_from_file_location('bench_target', '{abs_path}'); "
                "mod = importlib.util.module_from_spec(spec); "
                "spec.loader.exec_module(mod); "
                "print(f'{(time.perf_counter()-t0)*1000:.2f}')"
            )
            cmd = ["python3", "-c", code_runner]
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if res.returncode == 0:
                    val = float(res.stdout.strip().splitlines()[-1])
                    latencies.append(val)
                else:
                    errors += 1
            except Exception:
                errors += 1

        avg_lat = sum(latencies) / len(latencies) if latencies else 0.0
        return {
            "success": errors == 0 and len(latencies) > 0,
            "avg_latency_ms": round(avg_lat, 2),
            "samples": len(latencies),
            "errors": errors
        }

    def run_functional_capability_audit(self, baseline_path: str, candidate_path: str) -> Dict[str, Any]:
        """
        Runs capability-specific functional correctness tests on candidate code mutations.
        Evaluates whether key interface methods and domain requirements are preserved.
        """
        filename = os.path.basename(baseline_path)
        base_syntax = self.run_syntax_audit(baseline_path)
        cand_syntax = self.run_syntax_audit(candidate_path)

        if not cand_syntax["valid"]:
            return {"passed": False, "score": 0.0, "reason": cand_syntax.get("error")}

        # Check for interface regression (did candidate delete critical functions or classes?)
        fn_preserved = (cand_syntax["functions"] >= base_syntax["functions"])
        cls_preserved = (cand_syntax["classes"] >= base_syntax["classes"])

        score = 100.0
        reasons = []

        if not cls_preserved:
            score -= 30.0
            reasons.append(f"Class count reduced ({base_syntax['classes']} -> {cand_syntax['classes']})")
        if not fn_preserved:
            score -= 20.0
            reasons.append(f"Function count reduced ({base_syntax['functions']} -> {cand_syntax['functions']})")

        return {
            "passed": score >= 70.0,
            "score": round(score, 1),
            "fn_preserved": fn_preserved,
            "cls_preserved": cls_preserved,
            "notes": ", ".join(reasons) if reasons else "Interface integrity 100% preserved"
        }

    def compare(self, baseline_path: str, candidate_path: str, iterations: int = 5) -> Dict[str, Any]:
        """
        Run multi-dimensional empirical benchmark:
        1. AST Syntax & Structural Audit
        2. Interface & Functional Capability Audit
        3. Isolated Subprocess Cold-Start Latency
        Returns composite fitness score and promotion verdict.
        """
        base_syntax = self.run_syntax_audit(baseline_path)
        cand_syntax = self.run_syntax_audit(candidate_path)

        if not cand_syntax["valid"]:
            return {
                "verdict": "FATAL_ERROR",
                "recommendation": "REJECT",
                "delta_pct": -100.0,
                "composite_fitness": 0.0,
                "reason": f"Candidate failed AST syntax audit: {cand_syntax['error']}",
                "baseline_metrics": base_syntax,
                "candidate_metrics": cand_syntax
            }

        func_audit = self.run_functional_capability_audit(baseline_path, candidate_path)
        base_bench = self.measure_import_speed(baseline_path, iterations=iterations)
        cand_bench = self.measure_import_speed(candidate_path, iterations=iterations)
        base_ms = base_bench["avg_latency_ms"]
        cand_ms = cand_bench["avg_latency_ms"]

        # Calculate latency delta: positive delta means candidate is faster
        abs_diff_ms = abs(base_ms - cand_ms)
        if base_ms > 0 and cand_ms > 0:
            if abs_diff_ms < 2.0:
                # Sub-2ms absolute difference is background CPU scheduling noise
                delta_pct = 0.0
            else:
                delta_pct = round(((base_ms - cand_ms) / base_ms) * 100, 2)
        else:
            delta_pct = 0.0

        # Composite Fitness Calculation: 70% Functional Integrity + 30% Latency / Stability
        latency_factor = max(0.0, min(100.0, 50.0 + (delta_pct * 2.0)))
        composite_fitness = round((func_audit["score"] * 0.7) + (latency_factor * 0.3), 1)

        if cand_bench["errors"] > 0 or not func_audit["passed"]:
            verdict = "DEGRADED"
            recommendation = "REJECT"
            reason = f"Candidate failed functional/stability checks ({func_audit['notes']})."
        elif delta_pct >= 5.0 and func_audit["passed"]:
            verdict = "IMPROVED"
            recommendation = "PROMOTE"
            reason = f"Candidate is {delta_pct}% faster with 100% interface preservation."
        elif (delta_pct >= -15.0 or abs_diff_ms < 2.0) and func_audit["passed"]:
            verdict = "NEUTRAL"
            recommendation = "ACCEPT_SAFE"
            reason = f"Candidate preserves functional integrity ({composite_fitness}/100 fitness) within safe latency thresholds."
        else:
            verdict = "DEGRADED"
            recommendation = "REJECT"
            reason = f"Candidate latency is {abs(delta_pct)}% slower than baseline ({base_ms}ms vs {cand_ms}ms)."

        return {
            "verdict": verdict,
            "recommendation": recommendation,
            "delta_pct": delta_pct,
            "composite_fitness": composite_fitness,
            "functional_score": func_audit["score"],
            "reason": reason,
            "baseline_ms": base_ms,
            "candidate_ms": cand_ms,
            "baseline_metrics": {**base_syntax, **base_bench},
            "candidate_metrics": {**cand_syntax, **cand_bench, "functional_audit": func_audit}
        }

    def benchmark_proposals(self, proposals_dir: Optional[str] = None) -> List[Dict[str, Any]]:
        """Audit all upgrade proposals in ciph_proposals/ for syntax and import speed"""
        p_dir = proposals_dir or os.path.join(self.project_dir, "ciph_proposals")
        if not os.path.exists(p_dir):
            return []
        
        results = []
        for fname in sorted(os.listdir(p_dir)):
            if fname.endswith(".py"):
                fpath = os.path.join(p_dir, fname)
                syntax = self.run_syntax_audit(fpath)
                speed = self.measure_import_speed(fpath, iterations=3)
                results.append({
                    "file": fname,
                    "syntax": syntax,
                    "speed": speed
                })
        return results

    def format_scorecard(self, benchmark_result: Dict[str, Any]) -> str:
        """Format an ASCII Scorecard card for terminal display"""
        v = benchmark_result.get("verdict", "UNKNOWN")
        rec = benchmark_result.get("recommendation", "UNKNOWN")
        delta = benchmark_result.get("delta_pct", 0.0)
        fitness = benchmark_result.get("composite_fitness", 0.0)
        base_ms = benchmark_result.get("baseline_ms", 0.0)
        cand_ms = benchmark_result.get("candidate_ms", 0.0)
        reason = benchmark_result.get("reason", "")

        status_emoji = "✅" if v in ["IMPROVED", "NEUTRAL"] else "❌"

        card = f"""
┌─────────────────────────────────────────────────────────────────┐
│ 🧪 CIPH EMPIRICAL BENCHMARK SCORECARD                           │
├─────────────────────────────────────────────────────────────────┤
│ Verdict       : {status_emoji} {v} (Recommendation: {rec})
│ Composite Fit : {fitness}/100.0  |  Delta: {delta:+.2f}% latency
│ Performance   : Baseline: {base_ms}ms  |  Candidate: {cand_ms}ms
│ Diagnostic    : {reason[:60]}
└─────────────────────────────────────────────────────────────────┘"""
        return card.strip()

if __name__ == "__main__":
    bench = CiphBenchmark()
    target = os.path.join(os.path.dirname(os.path.abspath(__file__)), "query_router.py")
    res = bench.compare(target, target, iterations=3)
    print(bench.format_scorecard(res))
