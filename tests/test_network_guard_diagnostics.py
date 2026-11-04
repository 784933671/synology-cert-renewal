import copy
import hashlib
import json
import unittest

from tests.test_web_deployment import FirewallMemory
from web.network_guard import GuardError, NetworkGuard


class NetworkGuardDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.firewall = FirewallMemory()
        self.guard = NetworkGuard('10.10.10.37', ['10.10.10.0/24'], ['10.10.10.1'],
                                  18443, run=self.firewall)
        self.guard.install()
        self.baseline = copy.deepcopy(self.firewall.rules)
        self.firewall.calls.clear()

    def assert_diagnostic(self, reason, family=4, hook='INPUT_FIREWALL'):
        result = self.guard.last_diagnostic
        self.assertEqual(set(result), {'version', 'reason', 'family', 'hook', 'jump_position',
                                       'reference_count', 'chain_exists', 'fingerprints'})
        self.assertEqual((result['version'], result['reason'], result['family'], result['hook']),
                         (1, reason, family, hook))
        self.assertIs(type(result['jump_position']), int)
        self.assertIs(type(result['reference_count']), int)
        self.assertIs(type(result['chain_exists']), bool)
        self.assertEqual(set(result['fingerprints']),
                         {'entry', 'hook', 'owned_chain', 'references', 'expected'})
        for value in result['fingerprints'].values():
            self.assertRegex(value, r'^[a-f0-9]{64}$')
        return result

    def test_success_has_no_diagnostic(self):
        self.assertIsNone(self.guard.last_diagnostic)
        self.assertTrue(self.guard.valid())
        self.assertIsNone(self.guard.last_diagnostic)

    def test_missing_jump_is_classified_and_stops_at_first_family(self):
        self.firewall.rules[4] = [r for r in self.firewall.rules[4]
                                  if r[-2:] != ['-j', 'CERTWEB_INPUT']]
        self.assertFalse(self.guard.valid())
        result = self.assert_diagnostic('jump_missing')
        self.assertEqual((result['jump_position'], result['reference_count']), (-1, 0))
        self.assertTrue(result['chain_exists'])
        self.assertEqual(len(self.firewall.calls), 1)

    def test_missing_chain_is_distinguished_from_present_empty_chain(self):
        self.firewall.rules[4] = [r for r in self.firewall.rules[4]
                                  if r[:2] not in (['-A', 'CERTWEB_INPUT'], ['-N', 'CERTWEB_INPUT'])]
        self.assertFalse(self.guard.valid())
        result = self.assert_diagnostic('chain_mismatch')
        self.assertFalse(result['chain_exists'])
        self.assertEqual(result['jump_position'], 0)
        self.firewall.rules[4].append(['-N', 'CERTWEB_INPUT'])
        self.assertFalse(self.guard.valid())
        self.assertTrue(self.assert_diagnostic('chain_mismatch')['chain_exists'])

    def test_reordered_jump_keeps_exact_validation(self):
        self.firewall.rules[4].insert(0, ['-A', 'INPUT_FIREWALL', '-p', 'tcp', '--dport', '22', '-j', 'ACCEPT'])
        self.assertFalse(self.guard.valid())
        result = self.assert_diagnostic('jump_reordered')
        self.assertEqual((result['jump_position'], result['reference_count']), (1, 1))

    def test_duplicate_reference_is_classified(self):
        jump = next(r for r in self.firewall.rules[4] if r[-2:] == ['-j', 'CERTWEB_INPUT'])
        self.firewall.rules[4].append(list(jump))
        self.assertFalse(self.guard.valid())
        result = self.assert_diagnostic('reference_mismatch')
        self.assertEqual((result['jump_position'], result['reference_count']), (0, 2))

    def test_jump_with_wrong_destination_is_not_treated_as_expected_jump(self):
        jump = next(r for r in self.firewall.rules[4] if r[-2:] == ['-j', 'CERTWEB_INPUT'])
        jump[jump.index('-d') + 1] = '192.0.2.1/32'
        self.assertFalse(self.guard.valid())
        result = self.assert_diagnostic('jump_missing')
        self.assertEqual((result['jump_position'], result['reference_count']), (-1, 1))

    def test_chain_change_only_changes_owned_fingerprint(self):
        self.firewall.rules[4].append(['-A', 'CERTWEB_INPUT', '-s', '192.0.2.1/32', '-j', 'DROP'])
        self.assertFalse(self.guard.valid())
        previous = self.assert_diagnostic('chain_mismatch')['fingerprints']
        self.firewall.rules[4][-1][3] = '192.0.2.2/32'
        self.assertFalse(self.guard.valid())
        current = self.assert_diagnostic('chain_mismatch')['fingerprints']
        self.assertNotEqual(previous['owned_chain'], current['owned_chain'])
        for name in ('entry', 'hook', 'references', 'expected'):
            self.assertEqual(previous[name], current[name])

    def test_unknown_entry_order_has_no_arbitrary_hook_name(self):
        self.firewall.rules[4].insert(0, ['-A', 'INPUT', '-j', 'private-chain-name'])
        self.assertFalse(self.guard.valid())
        result = self.assert_diagnostic('entry_order_unknown', hook='unknown')
        self.assertEqual((result['jump_position'], result['reference_count']), (-1, 1))
        self.assertNotIn('private-chain-name', json.dumps(result))

    def test_ipv6_failure_identifies_family_without_losing_ipv4_checks(self):
        self.firewall.rules[6] = [['-P', 'INPUT', 'ACCEPT']]
        self.assertFalse(self.guard.valid())
        result = self.assert_diagnostic('jump_missing', family=6, hook='INPUT')
        self.assertFalse(result['chain_exists'])
        self.assertEqual(len(self.firewall.calls), 2)

    def test_query_error_has_fixed_defaults_and_is_reraised(self):
        failure = GuardError('stderr contains private values')
        def broken(_):
            raise failure
        self.guard.run = broken
        with self.assertRaises(GuardError) as raised:
            self.guard.valid()
        self.assertIs(raised.exception, failure)
        result = self.assert_diagnostic('query_failed', hook='unknown')
        self.assertEqual((result['jump_position'], result['reference_count'], result['chain_exists']), (-1, 0, False))
        empty_digest = hashlib.sha256(b'[]').hexdigest()
        self.assertEqual(set(result['fingerprints'].values()), {empty_digest})
        self.assertNotIn('private', json.dumps(result))

    def test_ipv6_query_error_uses_current_family(self):
        def query(args):
            if 'ip6tables' in args[0]:
                raise OSError('unavailable')
            return self.firewall(args)
        self.guard.run = query
        with self.assertRaises(OSError):
            self.guard.valid()
        self.assert_diagnostic('query_failed', family=6, hook='unknown')

    def test_malformed_query_output_is_not_a_success(self):
        self.guard.run = lambda _: '-A INPUT -m comment --comment "unterminated'
        with self.assertRaises(ValueError):
            self.guard.valid()
        self.assert_diagnostic('query_failed', hook='unknown')

    def test_successful_recheck_clears_previous_diagnostic(self):
        self.firewall.rules[4].append(['-A', 'CERTWEB_INPUT', '-j', 'ACCEPT'])
        self.assertFalse(self.guard.valid())
        self.firewall.rules = copy.deepcopy(self.baseline)
        self.assertTrue(self.guard.valid())
        self.assertIsNone(self.guard.last_diagnostic)

    def test_failed_query_does_not_reuse_previous_rule_evidence(self):
        self.firewall.rules[4].append(['-A', 'CERTWEB_INPUT', '-j', 'ACCEPT'])
        self.assertFalse(self.guard.valid())
        previous = self.guard.last_diagnostic
        def broken(_):
            raise OSError('unavailable')
        self.guard.run = broken
        with self.assertRaises(OSError):
            self.guard.valid()
        result = self.assert_diagnostic('query_failed', hook='unknown')
        self.assertEqual(result['reference_count'], 0)
        self.assertNotEqual(previous['fingerprints']['owned_chain'], result['fingerprints']['owned_chain'])

    def test_invalid_configuration_is_not_mislabeled_as_query_failure(self):
        self.firewall.rules[4].append(['-A', 'CERTWEB_INPUT', '-j', 'ACCEPT'])
        self.assertFalse(self.guard.valid())
        self.guard.access_mode = 'invalid'
        with self.assertRaises(GuardError):
            self.guard.valid()
        self.assertIsNone(self.guard.last_diagnostic)

    def test_diagnostic_contains_no_rule_addresses_or_comments(self):
        self.firewall.rules[4].append(['-A', 'CERTWEB_INPUT', '-s', '192.0.2.123/32',
                                      '-m', 'comment', '--comment', 'SecretKey-do-not-log', '-j', 'DROP'])
        self.assertFalse(self.guard.valid())
        encoded = json.dumps(self.assert_diagnostic('chain_mismatch'))
        for value in ('192.0.2.123', '10.10.10.37', '10.10.10.1', 'SecretKey-do-not-log', 'CERTWEB_INPUT'):
            self.assertNotIn(value, encoded)

    def test_equivalent_whitespace_does_not_change_validation(self):
        def query(args):
            return '\n'.join('  ' + line.replace(' ', '  ') + '  ' for line in self.firewall(args).splitlines())
        self.guard.run = query
        self.assertTrue(self.guard.valid())
        self.assertIsNone(self.guard.last_diagnostic)

    def test_install_repair_clears_previous_diagnostic(self):
        self.firewall.rules[4].append(['-A', 'CERTWEB_INPUT', '-j', 'ACCEPT'])
        self.assertFalse(self.guard.valid())
        self.guard.install()
        self.assertIsNone(self.guard.last_diagnostic)
        self.assertTrue(self.guard.valid())


if __name__ == '__main__':
    unittest.main()
