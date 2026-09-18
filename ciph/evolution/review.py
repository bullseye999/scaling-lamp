"""Deterministic dependency, manifest and resource review for operator proposals."""
import ast
import math
from ciph.contracts.base import ContractValidationError

APPROVED_STDLIB = frozenset('math statistics decimal fractions json re string collections typing dataclasses enum hashlib itertools functools bisect heapq datetime time copy operator pprint calendar numbers'.split())
FRAMEWORK_IMPORTS = frozenset({'ciph.capabilities.base', 'ciph.kernel.policy_engine', 'ciph.contracts.enums'})

def dependencies(source):
    found = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names = [entry.name for entry in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level or not node.module:
                raise ContractValidationError('RELATIVE_DEPENDENCY_NOT_APPROVED')
            names = [node.module]
        else:
            continue
        for name in names:
            if name in FRAMEWORK_IMPORTS:
                continue
            root = name.split('.')[0]
            if root not in APPROVED_STDLIB:
                raise ContractValidationError('DEPENDENCY_NOT_APPROVED:'+name)
            found.add(root)
    return sorted(found)

def review_changes(baseline, candidate, manifests):
    before, after = dependencies(baseline), dependencies(candidate)
    changes = sorted('+'+name for name in set(after)-set(before)) + sorted('-'+name for name in set(before)-set(after))
    old, new = manifests
    if old['name'] != new['name']:
        raise ContractValidationError('CAPABILITY_ID_MIGRATION_NOT_PERMITTED')
    diff = {key: {'before': old.get(key), 'after': new.get(key)}
            for key in sorted(set(old)|set(new))
            if key != 'is_statically_proven_safe' and old.get(key) != new.get(key)}
    return {'baseline_dependencies':before, 'candidate_dependencies':after,
            'dependency_changes':sorted(changes), 'manifest_changes':diff,
            'candidate_manifest':new, 'installation_required':False}

def validate_criteria(criteria):
    allowed = {'max_latency_ratio', 'max_peak_memory_bytes', 'max_cpu_seconds'}
    values = dict(criteria.comparison_baseline)
    if set(values)-allowed:
        raise ContractValidationError('UNKNOWN_RESOURCE_COMPARISON')
    for value in values.values():
        if isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(value) or value<=0:
            raise ContractValidationError('INVALID_RESOURCE_COMPARISON')
    if set(criteria.rollback_conditions)-{'ANY_ERROR','ASSERTION_FAILURE','RESOURCE_REGRESSION','DEADLINE_EXPIRED','AUTHORITY_REVOKED'}:
        raise ContractValidationError('UNKNOWN_ROLLBACK_CONDITION')
    return values

def resource_regression(criteria, measurement, benchmark):
    limits = validate_criteria(criteria)
    if measurement.get('peak_memory_bytes',0)<=0:
        return 'TRUSTED_RESOURCE_TELEMETRY_REQUIRED'
    if 'max_latency_ratio' in limits and measurement['duration_seconds']*1000 > benchmark['baseline_avg_ms']*limits['max_latency_ratio']:
        return 'LATENCY_REGRESSION'
    if measurement['peak_memory_bytes'] > limits.get('max_peak_memory_bytes',float('inf')):
        return 'MEMORY_REGRESSION'
    if measurement['cpu_seconds'] > limits.get('max_cpu_seconds',float('inf')):
        return 'CPU_REGRESSION'
    return None
