from phase5_test_support import offline_fixture
"""Phase 4 boundary, production-adapter, and command parity regressions.

No real external scans, model calls, or code promotion are performed.
"""
import ast
import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from cipher_vault import CipherVault
from ciph_core import CiphCore
from ciph.runtime import CiphRuntime
from ciph.capabilities.commands import CommandRegistry, CommandDefinition
from ciph.capabilities.registry import (
    MemoryRetrieveCapability, MemoryStoreCapability, CodePromoteUpgradeCapability,
    CodeListStagedCapability, BountyScanCapability, TorStatusCapability,
    DeadmanStatusCapability, SportsPredictCapability,
)
from ciph.contracts.grants import ScopeGrant, AuthorizationGrant
from ciph.contracts.enums import ScopeType
from ciph.workers.receipts import ExecutionReceipt
from tor_proxy import TorProxy
from dead_mans_switch import DeadMansSwitch


class TestPhase4Boundaries(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-p4-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.vault_args = dict(db_path=str(self.root/'vault.db'),
                               key_file=str(self.root/'vault.key'), salt_file=str(self.root/'vault.salt'))
        self.vault = CipherVault(**self.vault_args)
        self.runtime = CiphRuntime(vault=self.vault, db_path=self.vault.db_path)
        self.addCleanup(self.runtime.shutdown)
        self.core = CiphCore.__new__(CiphCore)
        self.core.runtime = self.runtime

    def grant(self, challenge, **overrides):
        fields = dict(grant_id='grant_'+challenge['plan_hash'], plan_hash=challenge['plan_hash'],
                      step_id=challenge['step_id'], capability=challenge['capability'],
                      params_hash=challenge['params_hash'], scope_grant_id='', expires_at=time.time()+120)
        fields.update(overrides)
        return AuthorizationGrant(**fields).sign(self.runtime.auth_secret_key)

    def scope(self, **overrides):
        fields = dict(scope_id='test_scope', scope_type=ScopeType.TARGET_DOMAIN,
                      allowed_targets=['allowed.example'], valid_until=time.time()+120)
        fields.update(overrides)
        return ScopeGrant(**fields).sign(self.runtime.auth_secret_key)

    def staging(self):
        backend = mock.Mock(spec=['apply'])
        backend.apply.return_value = (True, 'Applied test fixture')
        self.runtime.register_capability(CodePromoteUpgradeCapability(backend))
        return backend

    def test_missing_runtime_blocks_all_commands(self):
        del self.core.runtime
        self.core.code_staging = mock.Mock()
        for command in ['/apply UP-1', '/rollback file.py', '/port-scan allowed.example', '/help']:
            self.assertIn('RUNTIME_UNAVAILABLE', self.core.handle_command(command))
        self.core.code_staging.assert_not_called()
        self.assertEqual(self.core.code_staging.mock_calls, [])

    def test_complete_legacy_inventory_has_no_fallback(self):
        inventory = json.loads((Path(__file__).parent.parent/'ciph/capabilities/legacy_command_inventory.json').read_text())
        self.assertGreater(len(inventory), 150)
        with mock.patch.object(self.runtime, 'execute_reference_loop', side_effect=AssertionError('raw route')):
            for command in inventory:
                if self.runtime.command_registry.find_command(command) is None:
                    with self.subTest(command=command):
                        result = self.runtime.dispatch_slash_command(command+' fixture')
                        self.assertEqual(result['status'], 'COMMAND_UNAVAILABLE')
                        self.assertIn('unavailable', self.core.handle_command(command+' fixture'))
        tree = ast.parse((Path(__file__).parent.parent/'ciph_core.py').read_text())
        handler = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'handle_command')
        calls = [n.func.attr for n in ast.walk(handler) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)]
        self.assertFalse(set(calls) & {'apply', 'rollback', 'port_scan', 'web_vulnerability_scan', 'run', 'execute'})

    def test_dispatch_failure_never_falls_back(self):
        self.core.code_staging = mock.Mock()
        with mock.patch.object(self.runtime, 'dispatch_slash_command', side_effect=RuntimeError('offline')):
            self.assertIn('COMMAND_DISPATCH_FAILED', self.core.handle_command('/apply UP-1'))
        self.assertEqual(self.core.code_staging.mock_calls, [])

    def test_generate_response_has_no_raw_post_command_effects(self):
        self.core.formatter = mock.Mock()
        self.core.vault = mock.Mock()
        self.core.smart_memory = mock.Mock()
        self.core.conversation = mock.Mock()
        self.core.sync_system_state = mock.Mock(side_effect=AssertionError('raw scan'))
        self.assertIn('unavailable', self.core.generate_response('  /rollback fixture.py'))
        self.assertEqual(self.core.vault.mock_calls, [])
        self.assertEqual(self.core.smart_memory.mock_calls, [])
        self.assertEqual(self.core.conversation.mock_calls, [])

    def test_encrypted_memory_survives_runtime_and_vault_restart(self):
        stored = self.runtime.dispatch_slash_command('/memory set token "test secret value"')
        self.assertEqual(stored['status'], 'SUCCESS')
        with sqlite3.connect(self.vault.db_path) as conn:
            encrypted = conn.execute('SELECT encrypted_value FROM command_memory WHERE key=?', ('token',)).fetchone()[0]
        self.assertNotIn('test secret value', encrypted)
        self.runtime.shutdown()
        reopened_vault = CipherVault(**self.vault_args)
        reopened = CiphRuntime(vault=reopened_vault, db_path=reopened_vault.db_path)
        self.addCleanup(reopened.shutdown)
        result = reopened.dispatch_slash_command('/memory get token')
        self.assertEqual(result['receipt'].results['value'], 'test secret value')
        self.assertEqual(result['status'], 'SUCCESS')

    def test_repeated_commands_observe_and_write_fresh_state(self):
        first = self.runtime.dispatch_slash_command('/memory set value one')
        read1 = self.runtime.dispatch_slash_command('/memory get value')
        self.runtime.dispatch_slash_command('/memory set value two')
        read2 = self.runtime.dispatch_slash_command('/memory get value')
        again = self.runtime.dispatch_slash_command('/memory set value one')
        self.assertEqual(read1['receipt'].results['value'], 'one')
        self.assertEqual(read2['receipt'].results['value'], 'two')
        self.assertNotEqual(read1['receipt'].receipt_id, read2['receipt'].receipt_id)
        self.assertNotEqual(first['job_id'], again['job_id'])
        self.assertEqual(self.vault.get_memory('value'), 'one')

    def test_learn_persists_actual_operator_text(self):
        result = self.runtime.dispatch_slash_command('/learn unverified operator assertion')
        self.assertEqual(result['status'], 'SUCCESS')
        key = result['receipt'].results['key']
        self.assertEqual(CipherVault(**self.vault_args).get_memory(key), 'unverified operator assertion')

    def test_missing_and_corrupt_memory_are_not_fabricated(self):
        missing = self.runtime.dispatch_slash_command('/memory get missing')
        self.assertFalse(missing['receipt'].results['found'])
        self.runtime.dispatch_slash_command('/memory set corrupt original')
        with sqlite3.connect(self.vault.db_path) as conn:
            conn.execute("UPDATE command_memory SET encrypted_value='corrupt' WHERE key='corrupt'")
        result = self.runtime.dispatch_slash_command('/memory get corrupt')
        self.assertNotEqual(result['status'], 'SUCCESS')
        self.assertIsNone(result.get('claim'))

    def test_unsupported_memory_backend_cannot_claim_success(self):
        self.runtime.register_capability(MemoryStoreCapability(object()))
        self.runtime.register_capability(MemoryRetrieveCapability(object()))
        for command in ['/memory set key value', '/memory get key']:
            with self.subTest(command=command):
                result = self.runtime.dispatch_slash_command(command)
                self.assertNotEqual(result['status'], 'SUCCESS')
                if result['status'] == 'RECONCILIATION_REQUIRED':
                    evidence = self.runtime.queue.get_job(result['job_id'])['pending_receipt']
                    self.assertEqual(evidence['results']['status'], 'BACKEND_UNAVAILABLE')
                    self.assertTrue(ExecutionReceipt.from_dict(evidence).verify_signature(trust_registry=self.runtime.trust_registry))
                else:
                    self.assertEqual(result['receipt'].results['status'], 'BACKEND_UNAVAILABLE')
                self.assertIsNone(result.get('claim'))

    def test_strict_parser_blocks_ambiguous_and_missing_arguments(self):
        commands = ['/sports home=A home=B away=C', '/sports A B extra', '/sports "A B',
                    '/apply UP-1 extra', '/apply proposal_id=UP-1 proposal_id=UP-2',
                    '/bounty allowed.example unexpected=x', '/help surprise', '/memory set key',
                    '/cvss N L N', '/cvss', '/deadman checkin']
        with mock.patch.object(self.runtime.queue, 'enqueue_job', side_effect=AssertionError('execution')):
            for command in commands:
                with self.subTest(command=command):
                    result = self.runtime.dispatch_slash_command(command)
                    self.assertIn(result['status'], ('INVALID_ARGUMENTS', 'INCOMPLETE_INTENT'))

    def test_positional_keyword_and_alias_parity(self):
        reg = CommandRegistry()
        pairs = [('/sports "Real Madrid" Chelsea', '/predict home="Real Madrid" away=Chelsea'),
                 ('/sports Chelsea home="Real Madrid"', '/sports "Real Madrid" Chelsea'),
                 ('/memory set key "hello world"', '/mem store key=key value="hello world"'),
                 ('/apply UP-1', '/approve proposal_id=UP-1'),
                 ('/cvss AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', '/calc-cvss vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')]
        for lhs, rhs in pairs:
            with self.subTest(lhs=lhs):
                one, params1 = reg.parse(lhs)
                two, params2 = reg.parse(rhs)
                self.assertEqual(one.command, two.command)
                self.assertEqual(params1, params2)

    def test_registry_rejects_alias_hijacking(self):
        reg = CommandRegistry()
        for definition in [CommandDefinition('/evil', 'bad', '', aliases=['/approve']),
                           CommandDefinition('/sports', 'bad', '')]:
            with self.assertRaises(ValueError):
                reg.register(definition)
        self.assertEqual(reg.find_command('/approve').capability_name, 'code.promote_upgrade')

    def test_scope_absence_forgery_expiry_and_type_fail_before_execution(self):
        backend = mock.Mock(spec=['deep_scan'])
        self.runtime.register_capability(offline_fixture(BountyScanCapability(backend)))
        unsigned = ScopeGrant(scope_id='unsigned', scope_type=ScopeType.TARGET_DOMAIN, allowed_targets=['*'])
        for scope in [None, unsigned, object(), self.scope(valid_until=time.time()-1),
                      self.scope(created_at=time.time()+60), self.scope(scope_type=ScopeType.LOCAL_SYSTEM)]:
            with self.subTest(scope=type(scope).__name__):
                result = self.runtime.dispatch_slash_command('/bounty allowed.example', scope_grant=scope)
                self.assertIn(result['status'], ('SCOPE_REQUIRED', 'INVALID_SCOPE_GRANT', 'SCOPE_EXPIRED'))
        backend.deep_scan.assert_not_called()

    def test_out_of_scope_denial_is_authentic_and_durable(self):
        result = self.runtime.dispatch_slash_command('/bounty outside.example', scope_grant=self.scope())
        self.assertEqual(result['status'], 'POLICY_BLOCKED')
        receipt = result['receipt']
        self.assertEqual(receipt.output_hash, ExecutionReceipt.hash_payload(receipt.results))
        self.assertTrue(receipt.verify_signature(trust_registry=self.runtime.trust_registry))
        events = self.runtime.event_store.get_events(aggregate_id=receipt.receipt_id)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['event_id'], result['event_id'])
        self.assertEqual(events[0]['payload'], receipt.to_dict())
        self.assertTrue(self.runtime.event_store.verify_integrity()[0])

    def test_denial_storage_failure_is_explicit(self):
        with mock.patch.object(self.runtime.event_store, 'append_event', side_effect=sqlite3.OperationalError('full')):
            result = self.runtime.dispatch_slash_command('/bounty outside.example', scope_grant=self.scope())
        self.assertEqual(result['status'], 'STORAGE_FAILURE')
        self.assertIsNone(result['receipt'])

    def test_scope_expiry_bounds_worker_token(self):
        scope = self.scope(valid_until=time.time()+10)
        token = self.runtime.mint_execution_token('cybersecurity.bounty_scan', {'target':'allowed.example'}, scope_grant=scope)
        self.assertLessEqual(token.expires_at, scope.valid_until)

    def test_authorization_alias_roundtrip_and_same_grant_replay(self):
        staging = self.staging()
        challenge = self.runtime.dispatch_slash_command('/apply UP-1')
        grant = self.grant(challenge)
        first = self.runtime.dispatch_slash_command('/approve proposal_id=UP-1', auth_grant=grant)
        replay = self.runtime.dispatch_slash_command('/apply UP-1', auth_grant=grant)
        self.assertEqual(first['status'], 'SUCCESS')
        self.assertEqual(replay['status'], 'SUCCESS')
        self.assertEqual(first['job_id'], replay['job_id'])
        staging.apply.assert_called_once_with('UP-1')

    def test_invalid_authorization_never_reaches_backend(self):
        staging = self.staging()
        challenge = self.runtime.dispatch_slash_command('/apply UP-1')
        good = self.grant(challenge)
        bad_sig = AuthorizationGrant(**{**good.to_dict(), 'signature':'forged'})
        for command, grant in [('/apply UP-1', object()), ('/apply UP-1', bad_sig),
                               ('/apply UP-2', good), ('/apply UP-1', self.grant(challenge, expires_at=time.time()-1))]:
            result = self.runtime.dispatch_slash_command(command, auth_grant=grant)
            self.assertIn(result['status'], ('AUTHORIZATION_MISMATCH', 'INVALID_AUTHORIZATION_SIGNATURE'))
        staging.apply.assert_not_called()

    def test_independent_authorization_challenges_do_not_share_execution(self):
        staging = self.staging()
        first = self.runtime.dispatch_slash_command('/apply UP-1')
        second = self.runtime.dispatch_slash_command('/apply UP-1')
        self.assertNotEqual(first['plan_hash'], second['plan_hash'])
        for challenge in [first, second]:
            result = self.runtime.dispatch_slash_command('/apply UP-1', auth_grant=self.grant(challenge))
            self.assertEqual(result['status'], 'SUCCESS')
        self.assertEqual(staging.apply.call_count, 2)

    def test_core_forwards_grants_and_retains_structured_challenge(self):
        self.staging()
        self.core.handle_command('/apply UP-1')
        grant = self.grant(self.core.last_command_result)
        self.core.handle_command('/approve UP-1', auth_grant=grant)
        self.assertEqual(self.core.last_command_result['status'], 'SUCCESS')

    def test_missing_staging_backend_cannot_claim_inspection_or_promotion(self):
        self.runtime.register_capability(CodeListStagedCapability(None))
        self.runtime.register_capability(CodePromoteUpgradeCapability(None))
        listing = self.runtime.dispatch_slash_command('/upgrades')
        self.assertNotEqual(listing['status'], 'SUCCESS')
        challenge = self.runtime.dispatch_slash_command('/apply UP-1')
        result = self.runtime.dispatch_slash_command('/apply UP-1', auth_grant=self.grant(challenge))
        self.assertNotEqual(result['status'], 'SUCCESS')
        self.assertIsNone(result.get('claim'))

    def test_real_tor_interface_parity(self):
        tor = mock.create_autospec(TorProxy, instance=True)
        tor.get_tor_ip.return_value = '192.0.2.1'
        self.core.tor_proxy = tor
        self.core._bind_command_backends()
        self.runtime.register_capability(offline_fixture(self.runtime.registry.get('tor.check_status')))
        result = self.runtime.dispatch_slash_command('/tor')
        self.assertEqual(result['status'], 'SUCCESS')
        self.assertEqual(result['receipt'].results['exit_ip'], '192.0.2.1')
        tor.get_tor_ip.assert_called_once_with()

    def test_real_deadman_status_does_not_reset_or_invent_activity(self):
        backend = DeadMansSwitch(self.vault)
        original = backend.alive_signal
        self.runtime.register_capability(DeadmanStatusCapability(backend))
        result = self.runtime.dispatch_slash_command('/deadman')
        self.assertEqual(result['status'], 'SUCCESS')
        self.assertFalse(result['receipt'].results['active'])
        self.assertEqual(backend.alive_signal, original)

    def test_production_sports_text_is_preserved_in_dialogue(self):
        backend = mock.Mock(spec=['predict_match'])
        backend.predict_match.return_value = 'Model forecast: uncertain outcome, probability 0.55'
        self.runtime.register_capability(offline_fixture(SportsPredictCapability(backend)))
        result = self.runtime.dispatch_slash_command('/sports A B')
        self.assertEqual(result['status'], 'SUCCESS')
        self.assertIn(backend.predict_match.return_value, result['dialogue'])


if __name__ == '__main__':
    unittest.main()
