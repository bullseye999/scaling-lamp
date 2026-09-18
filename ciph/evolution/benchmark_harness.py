"""
ciph.evolution.benchmark_harness - Independent Empirical Benchmark & Verification Harness (Phase 8).
Supervisor-controlled independent verification:
- Kernel-isolated execution with assertions kept in the trusted supervisor.
- Strict host filesystem write isolation.
- Functional test case execution with supervisor-controlled assertions.
- Baseline vs candidate elapsed-time measurement; memory limits are enforced.
- Produces cryptographic verification evidence hashes and EvolutionReceipt contracts.
"""

import os
import sys
import ast
import json
import time
import uuid
import tempfile
import subprocess
import hashlib
from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Tuple

from ciph.contracts.evolution import (
    EvolutionEvaluationGrant,
    EvolutionReceipt,
)
from ciph.contracts.base import canonical_json
from ciph.kernel.crypto_identity import TrustRegistry
from ciph.capabilities.evolution import HotReloadEngine


@dataclass(frozen=True)
class BenchmarkReport:
    report_id: str
    candidate_hash: str
    base_file_hash: str
    target_capability: str
    passed: bool
    tests_run: int
    tests_passed: int
    baseline_avg_ms: float
    candidate_avg_ms: float
    delta_pct: float
    notes: str
    verification_evidence_hash: str
    timestamp: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "candidate_hash": self.candidate_hash,
            "base_file_hash": self.base_file_hash,
            "target_capability": self.target_capability,
            "passed": self.passed,
            "tests_run": self.tests_run,
            "tests_passed": self.tests_passed,
            "baseline_avg_ms": self.baseline_avg_ms,
            "candidate_avg_ms": self.candidate_avg_ms,
            "delta_pct": self.delta_pct,
            "notes": self.notes,
            "verification_evidence_hash": self.verification_evidence_hash,
            "timestamp": self.timestamp,
        }


class IndependentBenchmarkHarness:
    """The parent owns assertions, grant consumption, timing and signed evidence."""
    def __init__(self):
        self.hot_reload = HotReloadEngine()

    def evaluate_candidate_against_baseline(self, baseline_code, candidate_code, class_name,
            evaluation_grant, trust_registry, test_cases, benchmark_iterations=3):
        from ciph.evolution.evidence import EvolutionEvidenceStore
        from ciph.evolution.isolated_execution import execute_candidate
        now = time.time()
        candidate_hash = hashlib.sha256(candidate_code.encode()).hexdigest()
        base_hash = hashlib.sha256(baseline_code.encode()).hexdigest()
        target = getattr(evaluation_grant, 'target_capability', '')
        tests_passed = 0
        report_id = 'RPT-'+uuid.uuid4().hex
        try:
            if not isinstance(evaluation_grant, EvolutionEvaluationGrant):
                raise ValueError('AUTHORIZATION_REQUIRED')
            valid, reason = evaluation_grant.verify_signature(trust_registry)
            if not valid:
                raise ValueError(reason)
            if candidate_hash != evaluation_grant.candidate_hash or base_hash != evaluation_grant.base_file_hash:
                raise ValueError('EVALUATION_BINDING_MISMATCH')
            if not isinstance(test_cases, list) or not 1 <= len(test_cases) <= 50:
                raise ValueError('NONEMPTY_BOUNDED_TEST_SUITE_REQUIRED')
            if isinstance(benchmark_iterations, bool) or not isinstance(benchmark_iterations,int) or not 1 <= benchmark_iterations <= 10:
                raise ValueError('INVALID_BENCHMARK_ITERATIONS')
            for case in test_cases:
                if not isinstance(case,dict) or not isinstance(case.get('params'),dict) or not isinstance(case.get('expected'),dict) or not case['expected']:
                    raise ValueError('INDEPENDENT_EXPECTATIONS_REQUIRED')
            if len(test_cases)+2*benchmark_iterations > evaluation_grant.max_resource_budget.get('max_runs',32):
                raise ValueError('EVALUATION_BUDGET_EXCEEDED')
            manifests=[]
            for code in (baseline_code,candidate_code):
                safe, errors = self.hot_reload.audit_code_safety(code)
                if not safe: raise ValueError('AST security veto: '+str(errors))
                if len(code.encode())>262144:raise ValueError('CANDIDATE_SIZE_LIMIT')
                classes=[n.name for n in ast.parse(code).body if isinstance(n,ast.ClassDef)]
                if classes != [class_name]:raise ValueError('SINGLE_BOUND_CANDIDATE_CLASS_REQUIRED')
                manifest = self.hot_reload.extract_static_manifest_info(code)
                manifests.append(manifest)
                if manifest.get('name') != target or manifest.get('network_policy') != 'OFFLINE_ONLY' or manifest.get('reversibility') != 'READ_ONLY':
                    raise ValueError('ONLY_BOUND_OFFLINE_READ_ONLY_CANDIDATES_SUPPORTED')
            from ciph.evolution.review import review_changes
            change_review=review_changes(baseline_code,candidate_code,manifests)
            def interfaces(code):
                def walk(nodes,prefix=''):
                    found={}
                    for node in nodes:
                        if isinstance(node,ast.ClassDef):found.update(walk(node.body,prefix+node.name+'.'))
                        elif isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and not node.name.startswith('_'):
                            found[prefix+node.name]=ast.dump(node.args,include_attributes=False)
                    return found
                return walk(ast.parse(code).body)
            before=interfaces(baseline_code);after=interfaces(candidate_code)
            if any(after.get(key)!=signature for key,signature in before.items()):
                raise ValueError('PUBLIC_INTERFACE_REGRESSION')
            store = EvolutionEvidenceStore(trust_registry)
            from ciph.evolution.gap_detector import EngineeringGapDetector
            gap=EngineeringGapDetector(trust_registry.db_path,trust_registry=trust_registry).get_gap(evaluation_grant.gap_id)
            if not gap or gap.target_capability != target or gap.affected_revision not in (base_hash,evaluation_grant.base_commit_id):
                raise ValueError('VERIFIED_ENGINEERING_GAP_REQUIRED')
            # Reserving before execution prevents repeated use after failure or crash.
            with store.events._get_connection() as conn:
                conn.execute('CREATE TABLE IF NOT EXISTS ciph_evaluation_attempts (grant_id TEXT PRIMARY KEY, candidate_hash TEXT, status TEXT)')
                conn.execute('INSERT INTO ciph_evaluation_attempts VALUES (?,?,?)', (evaluation_grant.grant_id,candidate_hash,'RESERVED'))
            from ciph.evolution.workflow import prepare_evaluation
            workflow_id=prepare_evaluation(store,gap,baseline_code,candidate_code,evaluation_grant,class_name,change_review)
            measurements=[]
            def run(code, params):
                if not evaluation_grant.verify_signature(trust_registry)[0]:
                    raise ValueError('GRANT_EXPIRED_OR_REVOKED')
                measurement={}
                answer=execute_candidate(code,class_name,params,evaluation_grant.allowed_isolation_tier,
                                         dict(evaluation_grant.max_resource_budget),measurements=measurement)
                measurements.append({'source_hash':hashlib.sha256(code.encode()).hexdigest(),**measurement})
                return answer
            for case in test_cases:
                result, _ = run(candidate_code,case['params'])
                if any(k not in result or canonical_json(result[k]) != canonical_json(v) for k,v in case['expected'].items()):
                    raise ValueError('Functional tests failed: independent expected output mismatch')
                tests_passed += 1
            base_times=[];candidate_times=[]
            for _ in range(benchmark_iterations):
                _, duration=run(baseline_code,test_cases[0]['params']);base_times.append(duration*1000)
                result,duration=run(candidate_code,test_cases[0]['params']);candidate_times.append(duration*1000)
                if any(k not in result or canonical_json(result[k]) != canonical_json(v) for k,v in test_cases[0]['expected'].items()):
                    raise ValueError('BENCHMARK_EXECUTION_FAILED_ASSERTIONS')
            base_lat=sum(base_times)/len(base_times);cand_lat=sum(candidate_times)/len(candidate_times)
            delta=(cand_lat-base_lat)/base_lat*100 if base_lat else 0.0
            data={'report_id':report_id,'candidate_hash':candidate_hash,'base_file_hash':base_hash,
                  'target_capability':target,'gap_id':evaluation_grant.gap_id,'passed':True,
                  'workflow_id':workflow_id,'change_review':change_review,'resource_measurements':measurements,
                  'verification_gates':{'static':True,'contract':True,'behavior':True,'security':True,'regression':True,'resources':True},
                  'tests_run':len(test_cases),'tests_passed':tests_passed,'baseline_avg_ms':base_lat,
                  'candidate_avg_ms':cand_lat,'delta_pct':delta,'test_suite_hash':hashlib.sha256(canonical_json(test_cases).encode()).hexdigest(),
                  'test_cases':test_cases,'class_name':class_name,'isolation_tier':evaluation_grant.allowed_isolation_tier,
                  'max_resource_budget':dict(evaluation_grant.max_resource_budget),'timestamp':now}
            proposal_id=store.record('EVOLUTION_OPERATOR_PROPOSAL',data)
            data['operator_review_id']=proposal_id
            evidence_hash=store.record('BENCHMARK_VERIFIED',data)
            with store.events._get_connection() as conn:
                conn.execute("UPDATE ciph_evaluation_attempts SET status='VERIFIED' WHERE grant_id=?",(evaluation_grant.grant_id,))
            notes='Supervisor assertions passed; elapsed time includes isolated process launch. Peak RSS and CPU usage come from the trusted launcher via wait4.'
            report=BenchmarkReport(report_id,candidate_hash,base_hash,target,True,len(test_cases),tests_passed,base_lat,cand_lat,delta,notes,evidence_hash,now)
            receipt=EvolutionReceipt('EVO-'+uuid.uuid4().hex,evaluation_grant.grant_id,candidate_hash,'BENCHMARK_VERIFIED',
                                    {'verification_evidence_hash':evidence_hash,**data},now)
            return True,report,receipt
        except Exception as exc:
            if 'store' in locals():
                store.record('EVOLUTION_EVALUATION_FAILED',{'grant_id':evaluation_grant.grant_id,'candidate_hash':candidate_hash,'reason':str(exc)})
            report=BenchmarkReport(report_id,candidate_hash,base_hash,target,False,len(test_cases) if isinstance(test_cases,list) else 0,
                tests_passed,0,0,0,str(exc),'',now)
            return False,report,None

    def _run_test_in_disposable_subprocess(self, *args, **kwargs):
        return False, {}, ['AUTHORIZATION_REQUIRED: use the grant-bound independent evaluation pipeline']

    def _measure_execution_latency(self, *args, **kwargs):
        raise PermissionError('AUTHORIZATION_REQUIRED: use the grant-bound independent evaluation pipeline')
