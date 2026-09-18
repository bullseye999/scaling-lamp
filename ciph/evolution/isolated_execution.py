"""Execute raw candidate behavior under the actual Phase 7 kernel boundary.

No expected answers, verifier nonces or signing keys enter the child. All output
is untrusted data and is compared against the trusted oracle in the parent.
"""
import hashlib
import math
import shutil
import importlib.util
import json
import re
import sys
import tempfile
import zipfile
from pathlib import Path
from ciph.kernel.sandbox.runner import OfflineSandboxRunner, RootlessContainerRunner
from ciph.kernel.sandbox.base import SandboxPolicy, SandboxTerminationReason


class CandidateExecutionError(RuntimeError):
    def __init__(self,result):
        self.result=result
        super().__init__(result.termination_reason.value+': '+result.stderr[:1000])


CHILD = """import sys,json
sys.path[:0]=json.loads(sys.argv[1])
data=json.load(sys.stdin)
namespace={"__name__":"candidate"}
exec(compile(data["source"],"<candidate>","exec"),namespace)
instance=namespace[data["class_name"]]()
result=instance.run(data["params"],context={})
print(json.dumps({"results":result},allow_nan=False))
"""


def execute_candidate(source, class_name, params, tier, budget, *, measurements=None):
    if tier not in ("DISPOSABLE_PROCESS", "ROOTLESS_CONTAINER"):
        raise ValueError("SANDBOX_UNAVAILABLE: unknown isolation tier")
    if not isinstance(class_name, str) or not re.fullmatch(r"[A-Za-z_]\w*", class_name):
        raise ValueError("INVALID_CANDIDATE_CLASS")
    if not isinstance(source, str) or len(source.encode()) > 262144:
        raise ValueError("CANDIDATE_SIZE_LIMIT")
    allowed = {"timeout", "max_memory_bytes", "max_output_bytes", "max_cpu_seconds", "max_processes", "max_runs"}
    if set(budget) - allowed:
        raise ValueError("UNSUPPORTED_EVALUATION_BUDGET")
    for key,value in budget.items():
        if isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(value) or value<=0:
            raise ValueError('INVALID_EVALUATION_BUDGET:'+key)
        if key!='timeout' and int(value)!=value:raise ValueError('INTEGER_RESOURCE_LIMIT_REQUIRED')
    with tempfile.TemporaryDirectory(prefix="ciph_evolution_input_") as scratch:
        package = Path(scratch)/"runtime.zip"
        root = Path(__file__).resolve().parents[1]
        with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_STORED) as z:
            for path in sorted(root.rglob('*.py')):
                z.writestr(str(Path('ciph')/path.relative_to(root)), path.read_bytes())
        reads = [str(package)]
        imports = [str(package)]
        # Only the installed cryptographic runtime files, never the project root,
        # database, environment, or entire site-packages tree, are exposed.
        dependencies=Path(scratch)/'dependencies';dependencies.mkdir()
        for name in ('cryptography','_cffi_backend','cffi'):
            spec=importlib.util.find_spec(name)
            if spec and spec.origin:
                path=Path(spec.origin).resolve()
                if spec.submodule_search_locations:
                    shutil.copytree(path.parent,dependencies/name,ignore=shutil.ignore_patterns('__pycache__'))
                else:shutil.copy2(path,dependencies/path.name)
        reads.append(str(dependencies));imports.append(str(dependencies))
        policy = SandboxPolicy(allowed_read_paths=tuple(reads),
            max_wall_time_seconds=min(10.0, float(budget.get('timeout', 5))),
            max_memory_bytes=min(536870912, int(budget.get('max_memory_bytes',536870912))),
            max_output_bytes=min(65536, int(budget.get('max_output_bytes',65536))),
            max_cpu_seconds=min(10, int(budget.get('max_cpu_seconds',5))),
            max_processes=min(32, int(budget.get('max_processes',16))))
        runner = RootlessContainerRunner() if tier == 'ROOTLESS_CONTAINER' else OfflineSandboxRunner()
        result = runner.execute_isolated([sys.executable, '-I', '-S', '-c', CHILD, json.dumps(imports)],
            payload={'source':source,'class_name':class_name,'params':params},policy=policy)
        if result.termination_reason != SandboxTerminationReason.SUCCESS or not result.cleaned_up or not result.execution_confirmed:
            raise CandidateExecutionError(result)
        data = json.loads(result.stdout, parse_constant=lambda value: (_ for _ in ()).throw(ValueError('NONFINITE_OUTPUT')))
        if not isinstance(data, dict) or set(data) != {'results'} or not isinstance(data['results'], dict):
            raise ValueError('INVALID_CANDIDATE_OUTPUT')
        if measurements is not None:
            if result.peak_memory_bytes<=0:raise ValueError('TRUSTED_RESOURCE_TELEMETRY_REQUIRED')
            measurements.update(peak_memory_bytes=result.peak_memory_bytes,cpu_seconds=result.cpu_seconds,duration_seconds=result.duration_seconds)
        return data['results'], result.duration_seconds
