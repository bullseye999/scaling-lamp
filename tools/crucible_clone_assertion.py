"""
crucible_clone_assertion - a fresh vault must expose ZERO prior Crucible state.

Run this inside a sanitized clone. It proves two things a suite run alone cannot:

  1. a brand-new vault starts with an empty candidate registry, no active pointer, no trials and no
     promotion history - the Crucible does not bootstrap itself from anything ambient;
  2. the Crucible never imports production evolutionary state: `ciph.evolution` (the earlier Program-1
     lifecycle) is not reachable from any Crucible module.

Exit code 0 means both hold. Usage: python3 tools/crucible_clone_assertion.py
"""

import ast
import os
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ciph.kernel.crucible_candidates import candidate_history            # noqa: E402
from ciph.kernel.crucible_monitoring import assessment_history             # noqa: E402
from ciph.kernel.crucible_promotion import active_candidate, promotion_history    # noqa: E402
from ciph.kernel.crucible_promotion import rollback_history                # noqa: E402
from ciph.kernel.crucible_trials import trials_for                          # noqa: E402
from ciph.kernel.improvement_opportunities import opportunity_history         # noqa: E402
from ciph.kernel.improvement_hypotheses import hypothesis_history            # noqa: E402
from ciph.kernel.candidate_construction import construction_history           # noqa: E402
from ciph.kernel.improvement_learning import attempts                         # noqa: E402
from ciph.kernel.meta_evolution import meta_request_history                   # noqa: E402
from ciph.kernel.meta_opportunities import meta_opportunity_history           # noqa: E402
from ciph.kernel.meta_hypotheses import meta_hypothesis_history               # noqa: E402
from ciph.kernel.meta_shadow import shadow_records                            # noqa: E402
from ciph.kernel.meta_promotion import meta_promotion_history                 # noqa: E402
from ciph.kernel.meta_learning import meta_attempts                           # noqa: E402
from ciph.kernel.evolution_epochs import epoch_history, rollback_history      # noqa: E402
from ciph.kernel.meta_targets import classification_history                   # noqa: E402

CRUCIBLE_MODULES = sorted(path.name for path in (ROOT / 'ciph' / 'kernel').glob('crucible_*.py'))
FORBIDDEN_IMPORTS = ('ciph.evolution', 'evolution_bridge', 'ciph_evolution', 'ciph.crucible')


def fresh_vault_state_is_empty() -> bool:
    with tempfile.TemporaryDirectory(prefix='ciph-clone-crucible-') as directory:
        db = os.path.join(directory, 'vault.db')
        state = {
            'candidates': candidate_history(db),
            'active_pointer': active_candidate(db, 'planner'),
            'trials': trials_for(db),
            'promotions': promotion_history(db),
            'rollbacks': rollback_history(db),
            'assessments': assessment_history(db),
            'opportunities': opportunity_history(db),
            'hypotheses': hypothesis_history(db),
            'constructions': construction_history(db),
            'learning_attempts': attempts(db),
            'meta_requests': meta_request_history(db),
            'meta_classifications': classification_history(db),
            'meta_opportunities': meta_opportunity_history(db),
            'meta_hypotheses': meta_hypothesis_history(db),
            'meta_shadow_records': shadow_records(db),
            'meta_promotions': meta_promotion_history(db),
            'meta_learning_attempts': meta_attempts(db),
            'meta_epochs': epoch_history(db),
            'meta_rollbacks': rollback_history(db),
        }
    empty = all(
        (value is None or len(value) == 0)
        for key, value in state.items() if key != 'active_pointer')
    empty = empty and state['active_pointer'] is None
    print('fresh vault Crucible state:', {key: (len(value) if isinstance(value, list) else value)
                                          for key, value in state.items()})
    return empty


def crucible_does_not_import_evolution() -> bool:
    offenders = []
    for name in CRUCIBLE_MODULES:
        tree = ast.parse((ROOT / 'ciph' / 'kernel' / name).read_text(encoding='utf-8'))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [entry.name for entry in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or '']
            else:
                continue
            for imported in names:
                if any(imported.startswith(forbidden) for forbidden in FORBIDDEN_IMPORTS):
                    offenders.append(f'{name} -> {imported}')
    print('crucible modules scanned:', len(CRUCIBLE_MODULES))
    print('forbidden imports:', offenders or 'none')
    return not offenders


if __name__ == '__main__':
    empty = fresh_vault_state_is_empty()
    isolated = crucible_does_not_import_evolution()
    print('fresh vault starts empty   :', empty)
    print('no production-evolution import:', isolated)
    sys.exit(0 if (empty and isolated) else 1)
