import copy
import subprocess
import unittest
from unittest.mock import Mock, patch

from tests.test_web_deployment import FirewallMemory
from web.network_guard import GuardError, NetworkGuard, restore_command


class AtomicFirewall(FirewallMemory):
    def __init__(self):
        super().__init__()
        self.transactions = []
        self.reject_line = None
        self.before_restore = None
        self.after_commit = None

    def restore(self, args, payload):
        version = 6 if 'ip6tables' in args[0] else 4
        self.transactions.append((args, payload))
        if self.before_restore:
            self.before_restore(version)
        candidate = copy.deepcopy(self.rules[version])
        lines = payload.splitlines()
        if lines[0] != '*filter' or lines[-1] != 'COMMIT' or lines.count('COMMIT') != 1:
            raise GuardError('invalid transaction')
        for index, line in enumerate(lines):
            if self.reject_line == (version, index):
                raise GuardError('transaction rejected')
            if line in ('*filter', 'COMMIT'):
                continue
            if line.startswith(':'):
                chain = line.split()[0][1:]
                candidate = [rule for rule in candidate if rule[:2] != ['-A', chain]]
                if ['-N', chain] not in candidate:
                    candidate.append(['-N', chain])
                continue
            rule = line.split()
            if rule[0] == '-A':
                candidate.append(rule)
            elif rule[0] == '-D':
                target = ['-A'] + rule[1:]
                if target not in candidate:
                    raise GuardError('exact rule disappeared')
                candidate.remove(target)
            elif rule[0] == '-I':
                chain, position = rule[1], int(rule[2])
                positions = [i for i, current in enumerate(candidate) if current[:2] == ['-A', chain]]
                target = positions[position - 1] if position <= len(positions) else len(candidate)
                candidate.insert(target, ['-A', chain] + rule[3:])
            else:
                raise GuardError('unsupported transaction command')
        self.rules[version] = candidate
        if self.after_commit:
            self.after_commit(version)
        return ''


class LiveFirewallRepairTests(unittest.TestCase):
    def setUp(self):
        self.firewall = AtomicFirewall()
        self.guard = NetworkGuard('10.10.10.37', ['10.10.10.0/24'], ['10.10.10.1'], 18443,
                                  run=self.firewall, restore=self.firewall.restore)
        self.guard.install()
        self.baseline = copy.deepcopy(self.firewall.rules)
        self.firewall.calls.clear()

    def reorder(self):
        self.firewall.rules[4].insert(0, ['-A', 'INPUT_FIREWALL', '-p', 'tcp', '--dport', '22', '-j', 'ACCEPT'])

    def test_repair_publishes_only_complete_per_family_transactions(self):
        self.reorder()
        self.assertFalse(self.guard.valid())
        self.firewall.after_commit = lambda version: self.assertTrue(self.guard.valid_snapshot(version, self.firewall.rules[version]))
        self.assertTrue(self.guard.repair_live())
        self.assertTrue(self.guard.valid())
        self.assertIsNone(self.guard.last_diagnostic)
        self.assertEqual(len(self.firewall.transactions), 2)
        for args, payload in self.firewall.transactions:
            self.assertEqual(args[1:], ['--noflush', '--wait', '5'])
            self.assertEqual(payload.splitlines()[0], '*filter')
            self.assertEqual(payload.splitlines()[-1], 'COMMIT')
            self.assertEqual(payload.count('COMMIT'), 1)
            self.assertEqual(len([line for line in payload.splitlines() if line.startswith(':')]), 1)
            self.assertNotIn('-F ', payload)
            self.assertNotIn(':INPUT ', payload)
            self.assertNotIn(':INPUT_FIREWALL ', payload)
        self.assertTrue(all(args[3:] == ['-S'] for args in self.firewall.calls))

    def test_repair_preserves_unrelated_rules_and_chains(self):
        unrelated = [['-N', 'OTHER'], ['-A', 'OTHER', '-s', '192.0.2.11/32', '-j', 'DROP'],
                     ['-A', 'FORWARD', '-j', 'OTHER'], ['-A', 'INPUT_FIREWALL', '-p', 'udp', '--dport', '53', '-j', 'ACCEPT']]
        self.firewall.rules[4].extend(copy.deepcopy(unrelated))
        self.reorder()
        self.assertTrue(self.guard.repair_live())
        self.assertEqual([rule for rule in self.firewall.rules[4] if rule in unrelated], unrelated)
        self.assertEqual([rule for rule in self.firewall.rules[4] if rule[:2] == ['-P', 'INPUT']], [['-P', 'INPUT', 'ACCEPT']])

    def test_missing_chains_and_jumps_are_created_in_single_commit(self):
        for version in (4, 6):
            chain = 'CERTWEB_INPUT' if version == 4 else 'CERTWEB6_INPUT'
            self.firewall.rules[version] = [rule for rule in self.firewall.rules[version]
                                           if rule[:2] not in (['-N', chain], ['-A', chain]) and rule[-1] != chain]
        self.assertTrue(self.guard.repair_live())
        self.assertTrue(self.guard.valid())

    def test_duplicate_and_exact_legacy_jumps_are_replaced(self):
        _, jump, _ = self.guard.desired(4, 'INPUT_FIREWALL')
        self.firewall.rules[4].append(list(jump))
        self.firewall.rules[4].extend([['-N', 'DEFAULT_INPUT'], self.guard.desired(4, 'DEFAULT_INPUT')[1]])
        self.assertTrue(self.guard.repair_live())
        references = [r for r in self.firewall.rules[4] if r[-2:] == ['-j', 'CERTWEB_INPUT']]
        self.assertEqual(references, [jump])
        self.assertIn(['-N', 'DEFAULT_INPUT'], self.firewall.rules[4])

    def test_mode_changes_replace_complete_chain_without_intermediate_flush(self):
        for mode in ('public', 'lan'):
            with self.subTest(mode=mode):
                self.guard.access_mode = mode
                self.assertTrue(self.guard.repair_live())
                self.assertTrue(self.guard.valid())
                expected = self.guard.desired(4, 'INPUT_FIREWALL')[2]
                self.assertEqual([r for r in self.firewall.rules[4] if r[:2] == ['-A', 'CERTWEB_INPUT']], expected)
                self.assertEqual([r for r in self.firewall.rules[6] if r[:2] == ['-A', 'CERTWEB6_INPUT']],
                                 [['-A', 'CERTWEB6_INPUT', '-j', 'DROP']])

    def test_each_transaction_line_failure_preserves_entire_live_table(self):
        self.guard.access_mode = 'public'
        _, payload = self.guard.repair_plan(4)
        baseline = copy.deepcopy(self.firewall.rules)
        for index in range(len(payload.splitlines())):
            with self.subTest(line=index):
                self.firewall.rules = copy.deepcopy(baseline)
                self.firewall.reject_line = (4, index)
                with self.assertRaises(GuardError):
                    self.guard.repair_live()
                self.assertEqual(self.firewall.rules, baseline)

    def test_second_family_failure_keeps_first_complete_and_can_resume(self):
        self.guard.access_mode = 'public'
        self.firewall.reject_line = (6, 2)
        previous6 = copy.deepcopy(self.firewall.rules[6])
        with self.assertRaises(GuardError):
            self.guard.repair_live()
        self.assertTrue(self.guard.valid_snapshot(4, self.firewall.rules[4]))
        self.assertEqual(self.firewall.rules[6], previous6)
        self.firewall.reject_line = None
        self.assertTrue(self.guard.repair_live())
        self.assertTrue(self.guard.valid())
        self.assertFalse(any(rule[0] == '-N' and ('HOLD' in rule[1] or 'SWAP' in rule[1])
                             for rules in self.firewall.rules.values() for rule in rules))

    def test_unknown_ipv6_entry_prevents_both_writes(self):
        self.reorder()
        self.firewall.rules[6].extend([['-N', 'INPUT_FIREWALL'], ['-A', 'INPUT', '-j', 'INPUT_FIREWALL']])
        with self.assertRaises(GuardError):
            self.guard.repair_live()
        self.assertEqual(self.firewall.transactions, [])
        self.assertEqual(self.guard.last_diagnostic['reason'], 'entry_order_unknown')

    def test_incomplete_snapshot_is_not_used_as_an_empty_firewall(self):
        self.firewall.rules[4] = []
        with self.assertRaises(GuardError):
            self.guard.repair_live()
        self.assertEqual(self.firewall.transactions, [])

    def test_dsm_reload_is_never_bypassed_by_live_or_cold_repair(self):
        for has_hook in (False, True):
            with self.subTest(has_hook=has_hook):
                self.firewall.rules = copy.deepcopy(self.baseline)
                if not has_hook:
                    self.firewall.rules[4] = [rule for rule in self.firewall.rules[4]
                                             if rule != ['-N', 'INPUT_FIREWALL']]
                self.firewall.rules[4].insert(0, ['-A', 'INPUT', '-j', 'FIREWALL_RELOADING'])
                self.firewall.calls.clear()
                self.assertFalse(self.guard.valid())
                self.assertEqual(self.guard.last_diagnostic['reason'], 'entry_order_unknown')
                with self.assertRaises(GuardError):
                    self.guard.repair_live()
                with self.assertRaises(GuardError):
                    self.guard.install()
                self.assertEqual(self.firewall.transactions, [])
                self.assertTrue(all(args[3:] == ['-S'] for args in self.firewall.calls))

    def test_idle_reload_chain_does_not_block_known_dsm_entry(self):
        self.firewall.rules[4].append(['-N', 'FIREWALL_RELOADING'])
        self.assertTrue(self.guard.valid())
        self.assertTrue(self.guard.repair_live())

    def test_dsm_default_input_without_first_hook_is_not_plain_linux(self):
        self.firewall.rules[4] = [rule for rule in self.firewall.rules[4]
                                 if rule != ['-N', 'INPUT_FIREWALL']]
        self.firewall.rules[4].append(['-N', 'DEFAULT_INPUT'])
        self.firewall.calls.clear()
        self.assertFalse(self.guard.valid())
        with self.assertRaises(GuardError):
            self.guard.repair_live()
        with self.assertRaises(GuardError):
            self.guard.install()
        self.assertEqual(self.firewall.transactions, [])
        self.assertTrue(all(args[3:] == ['-S'] for args in self.firewall.calls))

    def test_foreign_references_and_gotos_refuse_live_mutation(self):
        variants = [['-A', 'OTHER', '-j', 'CERTWEB_INPUT'],
                    ['-A', 'INPUT_FIREWALL', '-g', 'CERTWEB_INPUT'],
                    ['-A', 'OTHER', '--goto', 'CERTWEB_INPUT'],
                    ['-A', 'OTHER', '--jump', 'CERTWEB_INPUT'],
                    ['-A', 'INPUT_FIREWALL', '-p', 'tcp', '--dport', '22', '-j', 'CERTWEB_INPUT']]
        for rule in variants:
            with self.subTest(rule=rule):
                self.firewall.rules = copy.deepcopy(self.baseline)
                self.firewall.rules[4].append(rule)
                before = copy.deepcopy(self.firewall.rules)
                with self.assertRaises(GuardError):
                    self.guard.repair_live()
                self.assertEqual(self.firewall.rules, before)
                self.assertEqual(self.firewall.transactions, [])
                self.assertEqual(self.guard.last_diagnostic['reason'], 'reference_mismatch')

    def test_extra_goto_and_long_jump_references_fail_normal_validation(self):
        for target in ('-g', '--goto', '--jump'):
            with self.subTest(target=target):
                self.firewall.rules = copy.deepcopy(self.baseline)
                self.firewall.rules[4].append(['-A', 'OTHER', target, 'CERTWEB_INPUT'])
                self.assertFalse(self.guard.valid())
                diagnostic = self.guard.last_diagnostic
                self.assertEqual(diagnostic['reason'], 'reference_mismatch')
                self.assertEqual(diagnostic['reference_count'], 2)

    def test_reference_added_between_preflight_and_commit_is_detected_before_next_family(self):
        def add_reference(version):
            if version == 4:
                self.firewall.rules[4].append(['-A', 'OTHER', '-g', 'CERTWEB_INPUT'])
        self.firewall.before_restore = add_reference
        with self.assertRaises(GuardError):
            self.guard.repair_live()
        self.assertEqual(len(self.firewall.transactions), 1)
        self.assertEqual(self.guard.last_diagnostic['reason'], 'reference_mismatch')

    def test_hot_rejection_cannot_fall_back_to_destructive_cold_repair(self):
        variants = [['-A', 'OTHER', '-j', 'CERTWEB_INPUT'],
                    ['-A', 'INPUT_FIREWALL', '-g', 'CERTWEB_INPUT'],
                    ['-A', 'OTHER', '--goto', 'CERTWEB_INPUT'],
                    ['-A', 'INPUT_FIREWALL', '-p', 'tcp', '--dport', '22', '-j', 'CERTWEB_INPUT'],
                    ['-A', 'DEFAULT_INPUT', '-p', 'tcp', '-j', 'CERTWEB_INPUT']]
        for rule in variants:
            with self.subTest(rule=rule):
                self.firewall.rules = copy.deepcopy(self.baseline)
                self.firewall.rules[4].append(rule)
                self.firewall.calls.clear()
                before = copy.deepcopy(self.firewall.rules)
                with self.assertRaises(GuardError):
                    self.guard.repair_live()
                with self.assertRaises(GuardError):
                    self.guard.install()
                self.assertEqual(self.firewall.rules, before)
                self.assertEqual(self.firewall.transactions, [])
                self.assertTrue(all(args[3:] == ['-S'] for args in self.firewall.calls))

    def test_second_family_foreign_reference_prevents_all_cold_mutation(self):
        self.reorder()
        self.firewall.rules[6].append(['-A', 'OTHER', '-g', 'CERTWEB6_INPUT'])
        before = copy.deepcopy(self.firewall.rules)
        self.firewall.calls.clear()
        with self.assertRaises(GuardError):
            self.guard.install()
        self.assertEqual(self.firewall.rules, before)
        self.assertTrue(all(args[3:] == ['-S'] for args in self.firewall.calls))
        self.assertEqual(self.guard.last_diagnostic['family'], 6)

    def test_second_family_query_failure_prevents_all_cold_mutation(self):
        self.reorder()
        before = copy.deepcopy(self.firewall.rules)
        def query(args):
            if 'ip6tables' in args[0]:
                raise OSError('unavailable')
            return self.firewall(args)
        self.guard.run = query
        self.firewall.calls.clear()
        with self.assertRaises(OSError):
            self.guard.install()
        self.assertEqual(self.firewall.rules, before)
        self.assertTrue(all(args[3:] == ['-S'] for args in self.firewall.calls))

    def test_cold_repair_recovers_dsm_deleted_jumps_without_touching_other_rules(self):
        unrelated = ['-A', 'INPUT_FIREWALL', '-i', 'lo', '-j', 'ACCEPT']
        self.firewall.rules[4].append(unrelated)
        for version in (4, 6):
            chain = 'CERTWEB_INPUT' if version == 4 else 'CERTWEB6_INPUT'
            self.firewall.rules[version] = [rule for rule in self.firewall.rules[version]
                                           if rule[-2:] != ['-j', chain]]
        self.guard.install()
        self.assertTrue(self.guard.valid())
        self.assertIn(unrelated, self.firewall.rules[4])

    def test_chain_name_in_comment_is_not_a_reference(self):
        rule = ['-A', 'INPUT_FIREWALL', '-m', 'comment', '--comment', 'CERTWEB_INPUT', '-j', 'ACCEPT']
        self.firewall.rules[4].append(rule)
        self.assertTrue(self.guard.repair_live())
        self.assertIn(rule, self.firewall.rules[4])

    def test_preflight_query_failure_never_writes_or_masks_error(self):
        failure = OSError('read unavailable')
        def query(args):
            if 'ip6tables' in args[0]:
                raise failure
            return self.firewall(args)
        self.guard.run = query
        with self.assertRaises(OSError) as raised:
            self.guard.repair_live()
        self.assertIs(raised.exception, failure)
        self.assertEqual(self.firewall.transactions, [])
        self.assertEqual(self.guard.last_diagnostic['reason'], 'query_failed')

    def test_postcommit_read_failure_requires_stop_and_skips_next_family(self):
        self.reorder()
        def query(args):
            if self.firewall.transactions:
                raise OSError('read unavailable')
            return self.firewall(args)
        self.guard.run = query
        with self.assertRaises(OSError):
            self.guard.repair_live()
        self.assertEqual(len(self.firewall.transactions), 1)

    def test_postcommit_rule_mismatch_requires_stop(self):
        def corrupt(version):
            self.firewall.rules[version].append(['-A', 'CERTWEB_INPUT', '-j', 'ACCEPT'])
        self.firewall.after_commit = corrupt
        with self.assertRaises(GuardError):
            self.guard.repair_live()
        self.assertEqual(len(self.firewall.transactions), 1)
        self.assertEqual(self.guard.last_diagnostic['reason'], 'chain_mismatch')

    def test_final_cross_family_readback_detects_concurrent_reorder(self):
        def change(version):
            if version == 6:
                self.reorder()
        self.firewall.after_commit = change
        with self.assertRaises(GuardError):
            self.guard.repair_live()
        self.assertEqual(len(self.firewall.transactions), 2)
        self.assertEqual(self.guard.last_diagnostic['reason'], 'jump_reordered')

    def test_snapshot_rule_disappearing_before_restore_cannot_partially_commit(self):
        self.guard.access_mode = 'public'
        changed = []
        def remove(version):
            if version == 4:
                jump = self.guard.desired(4, 'INPUT_FIREWALL')[1]
                self.firewall.rules[4].remove(jump)
                changed.append(copy.deepcopy(self.firewall.rules))
        self.firewall.before_restore = remove
        with self.assertRaises(GuardError):
            self.guard.repair_live()
        self.assertEqual(self.firewall.rules, changed[0])

    def test_lost_commit_response_is_not_reported_as_success(self):
        self.guard.access_mode = 'public'
        def lost(_):
            raise subprocess.TimeoutExpired('restore', 15)
        self.firewall.after_commit = lost
        with self.assertRaises(subprocess.TimeoutExpired):
            self.guard.repair_live()
        self.assertTrue(self.guard.valid_snapshot(4, self.firewall.rules[4]))
        self.assertEqual(len(self.firewall.transactions), 1)

    def test_invalid_access_mode_never_writes(self):
        self.guard.access_mode = 'invalid'
        with self.assertRaises(GuardError):
            self.guard.repair_live()
        self.assertEqual(self.firewall.transactions, [])


class RestoreCommandTests(unittest.TestCase):
    def test_restore_uses_stdin_and_bounded_wait_without_shell(self):
        args = ['/usr/bin/iptables-restore', '--noflush', '--wait', '5']
        with patch('web.network_guard.subprocess.run', return_value=Mock(returncode=0, stdout='ok')) as run:
            self.assertEqual(restore_command(args, '*filter\nCOMMIT\n'), 'ok')
        self.assertEqual(run.call_args.args, (args,))
        self.assertEqual(run.call_args.kwargs['input'], '*filter\nCOMMIT\n')
        self.assertEqual(run.call_args.kwargs['timeout'], 15)
        self.assertNotIn('shell', run.call_args.kwargs)

    def test_command_error_does_not_expose_stderr(self):
        with patch('web.network_guard.subprocess.run', return_value=Mock(returncode=1, stderr='PRIVATE ERROR')):
            with self.assertRaises(GuardError) as raised:
                restore_command(['/usr/bin/iptables-restore'], 'invalid')
        self.assertNotIn('PRIVATE', str(raised.exception))


if __name__ == '__main__':
    unittest.main()
