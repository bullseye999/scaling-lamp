#!/usr/bin/env python3
# ciph_benchmark.py - Empirical Benchmarking & Verification Engine for CIPH
import os
import ast
import time
import json
import shutil
import subprocess
from typing import Dict, Any, Optional, List

class CiphBenchmark:
    """
    Empirical Benchmark Lab for CIPH.
    Executes automated pre/post benchmarking to prove whether a staged code
    mutation is measurably better, neutral, or degraded before promotion.
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

    def compare(self, baseline_path: str, candidate_path: str, iterations: int = 5) -> Dict[str, Any]:
        """
        Run head-to-head empirical benchmark: Baseline Live Code vs Staged Candidate.
        Returns detailed score delta and selection verdict.
        """
        base_syntax = self.run_syntax_audit(baseline_path)
        cand_syntax = self.run_syntax_audit(candidate_path)

        if not cand_syntax["valid"]:
            return {
                "verdict": "FATAL_ERROR",
                "recommendation": "REJECT",
                "delta_pct": -100.0,
                "reason": f"Candidate failed AST syntax audit: {cand_syntax['error']}",
                "baseline_metrics": base_syntax,
                "candidate_metrics": cand_syntax
            }

        base_bench = self.measure_import_speed(baseline_path, iterations=iterations)
        cand_bench = self.measure_import_speed(candidate_path, iterations=iterations)

        base_ms = base_bench["avg_latency_ms"]
        cand_ms = cand_bench["avg_latency_ms"]

        # Calculate latency delta: positive delta means candidate is faster
        if base_ms > 0 and cand_ms > 0:
            delta_pct = round(((base_ms - cand_ms) / base_ms) * 100, 2)
        else:
            delta_pct = 0.0

        if cand_bench["errors"] > 0:
            verdict = "DEGRADED"
            recommendation = "REJECT"
            reason = f"Candidate encountered {cand_bench['errors']} execution errors during benchmarking."
        elif delta_pct >= 5.0:
            verdict = "IMPROVED"
            recommendation = "PROMOTE"
            reason = f"Candidate is {delta_pct}% faster than baseline with 0 errors."
        elif delta_pct >= -5.0:
            verdict = "NEUTRAL"
            recommendation = "ACCEPT_SAFE"
            reason = f"Candidate performance is equivalent to baseline ({delta_pct}% delta) with 0 errors."
        else:
            verdict = "DEGRADED"
            recommendation = "REJECT"
            reason = f"Candidate latency is {abs(delta_pct)}% slower than baseline."

        return {
            "verdict": verdict,
            "recommendation": recommendation,
            "delta_pct": delta_pct,
            "reason": reason,
            "baseline_ms": base_ms,
            "candidate_ms": cand_ms,
            "baseline_metrics": {**base_syntax, **base_bench},
            "candidate_metrics": {**cand_syntax, **cand_bench}
        }

    def format_scorecard(self, benchmark_result: Dict[str, Any]) -> str:
        """Format an ASCII Scorecard card for terminal display"""
        v = benchmark_result.get("verdict", "UNKNOWN")
        rec = benchmark_result.get("recommendation", "UNKNOWN")
        delta = benchmark_result.get("delta_pct", 0.0)
        base_ms = benchmark_result.get("baseline_ms", 0.0)
        cand_ms = benchmark_result.get("candidate_ms", 0.0)
        reason = benchmark_result.get("reason", "")

        status_emoji = "✅" if v in ["IMPROVED", "NEUTRAL"] else "❌"

        card = f"""
┌─────────────────────────────────────────────────────────────────┐
│ 🧪 CIPH EMPIRICAL BENCHMARK SCORECARD                           │
├─────────────────────────────────────────────────────────────────┤
│ Verdict       : {status_emoji} {v} (Recommendation: {rec})
│ Performance   : Baseline: {base_ms}ms  |  Candidate: {cand_ms}ms
│ Delta Score   : {delta:+.2f}% latency change
│ Diagnostic    : {reason[:60]}
└─────────────────────────────────────────────────────────────────┘"""
        return card.strip()

if __name__ == "__main__":
    bench = CiphBenchmark()
    target = os.path.join(os.path.dirname(os.path.abspath(__file__)), "query_router.py")
    res = bench.compare(target, target, iterations=3)
    print(bench.format_scorecard(res))
