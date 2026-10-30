import base64
import datetime
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
from urllib.parse import quote

SPEC = importlib.util.spec_from_file_location('failure_diagnostics_tests', Path(__file__).resolve().parents[1] / 'failure_diagnostics.py')
diag = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diag)


class ClassificationTests(unittest.TestCase):
    def test_fixed_acme_phase_markers_identify_each_stage(self):
        cases = {
            'dns_create': "Adding TXT value: secret-token for domain: _acme-challenge.example.com\nError adding TXT record to domain: _acme-challenge.example.com\nRemoving DNS records.\n",
            'dns_propagation': "Let's check each DNS record now. Sleeping for 20 seconds first.\nNot valid yet, let's wait for 10 seconds then check the next one.\nTimed out waiting for DNS.\nRemoving DNS records.\n",
            'acme_challenge': 'Verifying: example.com\nexample.com: Invalid status. Verification error details: DNS problem\nRemoving DNS records.\n',
            'ca_request': 'Error creating new order.\nRemoving DNS records.\n',
            'ca_finalize': "Verification finished, beginning signing.\nLet's finalize the order.\nSigning failed. Finalize code was not 200.\n",
            'ca_download': 'Downloading cert.\nSigning failed. Could not download cert: https://ca.example/cert/secret\n',
        }
        for expected, text in cases.items():
            with self.subTest(stage=expected):
                report = diag.classify('acme', '签发失败', text)
                self.assertEqual(report['stage'], expected)
                self.assertEqual(report['evidence'], 'acme_log')
                self.assertTrue(report['stage_label'])
                self.assertNotIn('secret-token', json.dumps(report))

    def test_timestamp_and_ansi_wrapped_upstream_messages_are_supported(self):
        report = diag.classify('acme', '', '[Fri Oct 30 10:00:00 CST 2026] \x1b[31mVerifying: example.com\x1b[0m\n')
        self.assertEqual(report['stage'], 'acme_challenge')

    def test_known_cloud_error_wins_over_acme_cleanup_messages(self):
        events = [
            {'stage': 'dns_query', 'status': 'success', 'code': ''},
            {'stage': 'dns_create', 'action': 'CreateRecord', 'code': 'UnauthorizedOperation', 'message': 'DO NOT COPY TOKEN'},
            {'stage': 'dns_cleanup', 'action': 'DeleteRecord', 'code': 'NetworkError'},
        ]
        report = diag.classify('acme', '', 'Error adding TXT record to domain: example.com\nRemoving DNS records.', events)
        self.assertEqual(report['stage'], 'dns_create')
        self.assertEqual(report['code'], 'UnauthorizedOperation')
        self.assertEqual(report['category'], 'permission')
        self.assertNotIn('DO NOT COPY', json.dumps(report))

    def test_cleanup_error_does_not_hide_primary_ca_or_challenge_failure(self):
        events = [{'stage': 'dns_cleanup', 'code': 'UnauthorizedOperation'}]
        report = diag.classify('acme', '', 'Verifying: example.com\nexample.com: Invalid status. Verification error details: problem\nRemoving DNS records.', events)
        self.assertEqual(report['stage'], 'acme_challenge')
        self.assertNotEqual(report['code'], 'UnauthorizedOperation')
        cleanup = diag.classify('dns_cleanup', '', '', events)
        self.assertEqual(cleanup['stage'], 'dns_cleanup')
        self.assertEqual(cleanup['code'], 'UnauthorizedOperation')

    def test_dns_success_alone_does_not_assert_acme_validation_started(self):
        events = [{'stage': 'dns_create', 'status': 'success', 'code': 'OK'}]
        report = diag.classify('acme', '签发失败', '', events)
        self.assertEqual(report['stage'], 'acme_unknown')
        self.assertIn('不足', report['summary'])
        report = diag.classify('acme', '', 'All checks succeeded\n')
        self.assertEqual(report['stage'], 'acme_unknown')

    def test_known_acme_error_code_and_transport_are_classified_without_remote_details(self):
        text = 'Error creating new order.\n{"type":"urn:ietf:params:acme:error:rateLimited","detail":"DO NOT COPY secret=abc"}'
        report = diag.classify('acme', '', text)
        self.assertEqual(report['code'], 'urn:ietf:params:acme:error:rateLimited')
        self.assertEqual(report['category'], 'rate_limit')
        self.assertNotIn('DO NOT COPY', json.dumps(report))
        report = diag.classify('acme', '', 'Downloading cert.\ncurl: (28) Connection timed out\n')
        self.assertEqual(report['stage'], 'ca_download')
        self.assertEqual(report['code'], 'CURL_28')

    def test_unknown_error_codes_and_remote_messages_are_not_reflected(self):
        malicious = 'UnauthorizedOperation.STOLEN_SECRET_EXFILTRATION'
        report = diag.classify('acme', '', '', [{'stage': 'dns_query', 'code': malicious, 'message': 'MY SECRET'}])
        self.assertEqual(report['stage'], 'dns_query')
        self.assertEqual(report['code'], 'UNKNOWN_PROVIDER_ERROR')
        self.assertNotIn('STOLEN', json.dumps(report))
        self.assertNotIn('MY SECRET', json.dumps(report))

    def test_unknown_latest_acme_error_does_not_reuse_earlier_known_error(self):
        log = ('Verifying: example.com\nurn:ietf:params:acme:error:badNonce\n'
               'urn:ietf:params:acme:error:unknownNewError\n')
        report = diag.classify('acme', '', log)
        self.assertEqual(report['stage'], 'acme_challenge')
        self.assertEqual(report['code'], 'ACME_CHALLENGE_FAILED')
        self.assertNotEqual(report['category'], 'protocol')

    def test_controller_stage_is_not_overridden_by_unrelated_logs_or_events(self):
        for stage in ('preflight', 'backup', 'certificate_validation', 'dsm_deploy', 'tls_verify', 'success_notification', 'result_recording', 'recovery'):
            with self.subTest(stage=stage):
                report = diag.classify(stage, '本机失败', 'Error adding TXT record to domain: example.com',
                                       [{'stage': 'dns_create', 'code': 'UnauthorizedOperation'}])
                self.assertEqual(report['stage'], stage)
                self.assertEqual(report['evidence'], 'controller')
        timeout = diag.classify('acme', 'ACME 操作超时或被中断', '')
        self.assertEqual(timeout['stage'], 'acme_unknown')
        self.assertEqual(timeout['category'], 'timeout_or_interrupted')

    def test_local_dns_diagnostic_codes_have_fixed_safe_summaries(self):
        for code in ('MissingCredentials', 'StateError', 'RecordStillPresent', 'IndexNotReady',
                     'ResourceNotFound.NoDataOfDomain', 'UnauthorizedOperation.CamNoPermission'):
            with self.subTest(code=code):
                result = diag.classify('dns_cleanup', '', '', [{'stage': 'dns_cleanup', 'code': code}])
                self.assertEqual(result['code'], code)
                self.assertNotEqual(result['category'], 'unclassified')
                self.assertTrue(result['summary'])

    def test_malformed_diagnostic_values_fail_closed(self):
        result = diag.classify('acme', '', '', [{'stage': 'dns_query', 'code': {'secret': 'unsafe'}}])
        self.assertEqual(result['code'], 'UNKNOWN_PROVIDER_ERROR')
        self.assertNotIn('unsafe', json.dumps(result))
        self.assertEqual(diag.classify({})['stage'], 'unknown')


class SanitizationTests(unittest.TestCase):
    def test_exact_secrets_and_encoded_variants_are_removed_before_truncation(self):
        secret = 'special + secret/with=punctuation'
        variants = [secret, quote(secret, safe=''), quote(secret, safe='').lower(),
                    base64.b64encode(secret.encode()).decode(),
                    base64.urlsafe_b64encode(secret.encode()).decode().rstrip('=')]
        output = diag.sanitize('\n'.join(variants), [secret])
        for value in variants:
            self.assertNotIn(value, output)
        short = diag.sanitize('first ' + secret + ' tail', [secret], limit=25)
        self.assertNotIn('special', short)
        self.assertLessEqual(len(short.encode()), 25)

    def test_auth_headers_sessions_json_queries_and_dns_values_are_redacted(self):
        samples = [
            ('Authorization: Bearer short-token\n continuation-secret\nError: failed', ['short-token', 'continuation-secret']),
            ('{"Authorization":"Bearer hidden-value","Cookie":"sid=hidden-session"}', ['hidden-value', 'hidden-session']),
            ('TC3-HMAC-SHA256 Credential=AKID1234567890123456/date/dnspod/tc3_request, Signature=secret-signature', ['AKID1234567890123456', 'secret-signature']),
            ('https://user:password@api.example/path?token=query-token&sid=session-value', ['user:password', 'query-token', 'session-value']),
            ('Tencent_SecretId=short-id\nTencent_SecretKey="short-secret"', ['short-id', 'short-secret']),
            ('Adding TXT value: dns-challenge-secret for domain: _acme-challenge.example.com', ['dns-challenge-secret']),
            ("\x1b[31mTXT value: 'manual-challenge-value'\x1b[0m", ['manual-challenge-value']),
            ('Removing TXT value: another-challenge\n{"RecordValue":"short-txt"}', ['another-challenge', 'short-txt']),
            ('{\\"SecretKey\\":\\"json-escaped-secret\\"}', ['json-escaped-secret']),
            ('token%3Dencoded-short-value%26other%3Dsafe', ['encoded-short-value']),
        ]
        for text, hidden in samples:
            with self.subTest(text=text):
                result = diag.sanitize(text)
                for value in hidden:
                    self.assertNotIn(value, result)

    def test_private_keys_closed_or_truncated_never_survive(self):
        for suffix in ('\n-----END PRIVATE KEY-----\nother', '\ntruncated'):
            raw = 'before\n-----BEGIN PRIVATE KEY-----\nPRIVATEKEYMATERIAL' + suffix
            self.assertNotIn('PRIVATEKEYMATERIAL', diag.sanitize(raw))
            self.assertNotIn('BEGIN PRIVATE KEY', diag.sanitize(raw))

    def test_known_machine_codes_survive_but_opaque_tokens_do_not(self):
        code = 'OPERATION_TIMEOUT_OR_INTERRUPTED'
        opaque = 'Abc01234_-Abc01234_-Abc01234_-Abc01234_-'
        self.assertEqual(diag.sanitize(code), code)
        self.assertNotIn(opaque, diag.sanitize(opaque))
        self.assertNotIn(code, diag.sanitize(code, secrets=[code]))
        for error in diag.ACME_CODES:
            urn = 'urn:ietf:params:acme:error:' + error
            self.assertEqual(diag.sanitize(urn), urn)

    def test_only_explicit_safe_archive_paths_bypass_opaque_token_filter(self):
        path = '/volume1/synology-cert-renewal/state/failures/failure-20261030T123456Z-' + 'a' * 32
        text = '失败记录：' + path
        self.assertEqual(diag.sanitize(text, public_paths=[path]), text)
        self.assertNotIn(path, diag.sanitize(text))
        self.assertNotIn(path, diag.sanitize(text, secrets=['synology-cert-renewal'], public_paths=[path]))
        unsafe = '/volume1/../secrets/' + 'b' * 32
        self.assertNotIn(unsafe, diag.sanitize(unsafe, public_paths=[unsafe]))

    def test_byte_limits_preserve_valid_utf8_and_strip_control_characters(self):
        for limit in (0, 5, 64, 256):
            result = diag.sanitize('\x1b[31m错误\x00\x7f' * 500, limit=limit)
            self.assertLessEqual(len(result.encode()), limit)
            self.assertNotIn('\x1b', result)
            self.assertNotIn('\x00', result)


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.state = Path(self.temporary.name) / 'state'
        self.state.mkdir(mode=0o700)
        self.clock = 1800000000

    def archive(self, message='first', **kwargs):
        return diag.archive_failure(self.state, {'message': message, 'stage': 'acme_unknown'},
                                    {'acme.log': 'Authorization: Bearer hidden-token\n' + message},
                                    now=self.clock, **kwargs)

    def test_failures_are_unique_private_complete_and_do_not_overwrite(self):
        first, second = self.archive(), self.archive('second')
        self.assertNotEqual(first['archive_path'], second['archive_path'])
        for item in (first, second):
            self.assertIsNone(item['archive_error'])
            path = Path(item['archive_path'])
            self.assertTrue((path / 'complete.json').is_file())
            self.assertNotIn('hidden-token', (path / 'acme.log').read_text())
            for candidate in [path] + list(path.iterdir()):
                self.assertEqual(stat.S_IMODE(candidate.stat().st_mode), 0o700 if candidate.is_dir() else 0o600)
        self.assertEqual(json.loads((Path(first['archive_path']) / 'report.json').read_text())['message'], 'first')

    def test_count_and_age_retention_keep_the_newest_complete_archive(self):
        for index in range(4):
            result = self.archive(str(index), max_failures=2)
            self.assertTrue(Path(result['archive_path']).exists())
        folders = list((self.state / 'failures').glob('failure-*'))
        self.assertEqual(len(folders), 2)
        self.clock += 31 * 86400
        latest = self.archive('after retention', max_failures=2)
        self.assertEqual(list((self.state / 'failures').glob('failure-*')), [Path(latest['archive_path'])])

    def test_archive_redacts_report_secrets_and_preserves_public_error_code(self):
        result = diag.archive_failure(self.state, {'message': 'secret=unsafe', 'code': 'OPERATION_TIMEOUT_OR_INTERRUPTED'},
                                       {'acme.log': 'Key value known-credential'}, secrets=['known-credential'], now=self.clock)
        report = json.loads((Path(result['archive_path']) / 'report.json').read_text())
        self.assertNotIn('unsafe', report['message'])
        self.assertEqual(report['code'], 'OPERATION_TIMEOUT_OR_INTERRUPTED')
        self.assertNotIn('known-credential', (Path(result['archive_path']) / 'acme.log').read_text())

    def test_clock_rollback_cannot_prune_the_archive_returned_to_the_email(self):
        self.archive('before clock adjustment', max_failures=1)
        self.clock -= 86400
        latest = self.archive('after clock adjustment', max_failures=1)
        self.assertEqual(list((self.state / 'failures').glob('failure-*')), [Path(latest['archive_path'])])

    def test_large_logs_are_redacted_before_capping_and_oversized_files_are_not_read(self):
        text = 'x\n' * 1000 + '-----BEGIN PRIVATE KEY-----\nsecret-boundary\n-----END PRIVATE KEY-----'
        result = diag.archive_failure(self.state, {}, {'acme.log': text}, now=self.clock, max_log_bytes=128)
        saved = (Path(result['archive_path']) / 'acme.log').read_bytes()
        self.assertLessEqual(len(saved), 128)
        self.assertNotIn(b'secret-boundary', saved)
        large = self.state / 'large.log'
        large.write_bytes(b'a' * (diag.MAX_READ_BYTES + 1))
        large.chmod(0o600)
        result = diag.archive_failure(self.state, {}, {'large.log': large}, now=self.clock)
        self.assertIn('超过安全读取上限', (Path(result['archive_path']) / 'large.log').read_text())

    def test_symlink_archive_root_fails_safely_without_writing_external_directory(self):
        elsewhere = Path(self.temporary.name) / 'elsewhere'
        elsewhere.mkdir(mode=0o700)
        (self.state / 'failures').symlink_to(elsewhere, target_is_directory=True)
        result = self.archive()
        self.assertIsNone(result['archive_path'])
        self.assertIsNotNone(result['archive_error'])
        self.assertEqual(list(elsewhere.iterdir()), [])

    def test_symlink_log_and_traversal_name_are_not_followed(self):
        secret = Path(self.temporary.name) / 'secret'
        secret.write_text('UNRELATED_PRIVATE_DATA')
        secret.chmod(0o600)
        link = self.state / 'link.log'
        link.symlink_to(secret)
        result = diag.archive_failure(self.state, {'message': 'primary error'},
                                       {'safe.log': link, '../escape.log': 'unsafe'}, now=self.clock)
        self.assertIsNotNone(result['archive_path'])
        self.assertIsNotNone(result['archive_error'])
        root = Path(result['archive_path'])
        self.assertNotIn('UNRELATED_PRIVATE_DATA', (root / 'safe.log').read_text())
        self.assertFalse((root.parent / 'escape.log').exists())
        self.assertEqual(json.loads((root / 'report.json').read_text())['message'], 'primary error')

    def test_disk_failure_returns_safe_error_and_does_not_remove_previous_archive(self):
        previous = Path(self.archive()['archive_path'])
        with mock.patch.object(diag, '_write', side_effect=OSError('SECRET DISK DETAIL')):
            result = self.archive('second')
        self.assertIsNone(result['archive_path'])
        self.assertNotIn('SECRET', result['archive_error'])
        self.assertTrue(previous.exists())
        self.assertFalse(list((self.state / 'failures').glob('.partial-*')))

    def test_insecure_state_directory_is_rejected(self):
        self.state.chmod(0o755)
        self.assertIsNone(self.archive()['archive_path'])
        self.assertFalse((self.state / 'failures').exists())

    def test_state_path_with_traversal_is_rejected(self):
        path = self.state / '..' / 'state'
        result = diag.archive_failure(path, {}, {}, now=self.clock)
        self.assertIsNone(result['archive_path'])
        self.assertFalse((self.state / 'failures').exists())


if __name__ == '__main__':
    unittest.main()
