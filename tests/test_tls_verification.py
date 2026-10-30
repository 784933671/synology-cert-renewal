import contextlib
import importlib.util
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location('tls_certctl', Path(__file__).resolve().parents[1] / 'certctl.py')
certctl = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(certctl)


def openssl(*arguments):
    subprocess.run(['openssl'] + [str(argument) for argument in arguments], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


@contextlib.contextmanager
def tls_server(cert, key):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen()
    listener.settimeout(0.2)
    stopping = threading.Event()

    def serve():
        while not stopping.is_set():
            try:
                raw, _ = listener.accept()
            except socket.timeout:
                continue
            try:
                raw.settimeout(5)
                with raw, context.wrap_socket(raw, server_side=True):
                    pass
            except (OSError, ssl.SSLError):
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield {'host': '127.0.0.1', 'port': listener.getsockname()[1],
               'server_name': 'audit.example.test'}
    finally:
        stopping.set()
        thread.join(timeout=6)
        listener.close()
        if thread.is_alive():
            raise AssertionError('TLS test server did not stop')


class TLSVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.certificates = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.certificates.cleanup)
        cls.files = Path(cls.certificates.name)
        files = cls.files
        (files / 'root.cnf').write_text(
            '[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n'
            '[dn]\nCN=TLS Test Root\n[ext]\nbasicConstraints=critical,CA:TRUE\n'
            'keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n')
        openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '365',
                '-config', files / 'root.cnf', '-keyout', files / 'root.key', '-out', files / 'root.pem')
        (files / 'intermediate.ext').write_text(
            'basicConstraints=critical,CA:TRUE,pathlen:0\n'
            'keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n'
            'authorityKeyIdentifier=keyid,issuer\n')
        openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=TLS Test Intermediate',
                '-keyout', files / 'intermediate.key', '-out', files / 'intermediate.csr')
        openssl('x509', '-req', '-in', files / 'intermediate.csr', '-CA', files / 'root.pem',
                '-CAkey', files / 'root.key', '-CAcreateserial', '-days', '180',
                '-extfile', files / 'intermediate.ext', '-out', files / 'intermediate.pem')
        (files / 'leaf.ext').write_text(
            'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'
            'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:audit.example.test\n'
            'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n')
        openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=audit.example.test',
                '-keyout', files / 'leaf.key', '-out', files / 'leaf.csr')
        for name, days in (('leaf', 90), ('expired', 0)):
            openssl('x509', '-req', '-in', files / 'leaf.csr', '-CA', files / 'intermediate.pem',
                    '-CAkey', files / 'intermediate.key', '-CAcreateserial', '-days', days,
                    '-extfile', files / 'leaf.ext', '-out', files / (name + '.pem'))
            (files / (name + '-chain.pem')).write_bytes((files / (name + '.pem')).read_bytes()
                                                        + (files / 'intermediate.pem').read_bytes())

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.controller = certctl.Controller(root / 'home', root / 'archive')
        self.controller.config = {'certificate_id': 'ABC', 'certificate_description': 'TLS test',
                                  'domains': ['audit.example.test'], 'deployment_method': 'local_api'}
        self.controller.state.mkdir(parents=True, mode=0o700)
        self.controller.candidate_dir().mkdir(parents=True, mode=0o700)
        (self.controller.archive / 'ABC').mkdir(parents=True, mode=0o700)
        self.info = {'ABC': {'desc': 'TLS test', 'services': []}}
        certctl.save_json(self.controller.archive / 'INFO', self.info)
        (self.controller.archive / 'DEFAULT').write_text('ABC')
        destinations = {'leaf.pem': self.controller.candidate(),
                        'leaf.key': self.controller.candidate_dir() / 'audit.example.test.key',
                        'intermediate.pem': self.controller.candidate_dir() / 'ca.cer',
                        'leaf-chain.pem': self.controller.candidate_dir() / 'fullchain.cer'}
        for source, destination in destinations.items():
            shutil.copyfile(self.files / source, destination)
        shutil.copyfile(self.files / 'expired.pem', self.controller.archive / 'ABC' / 'cert.pem')
        self.expected = certctl.fingerprint(self.controller.candidate())
        self.controller.log = mock.Mock()
        self.controller.system_check = mock.Mock()
        self.controller.local_api_target = mock.Mock()
        self.controller.deploy_local_api = mock.Mock(side_effect=lambda before:
            shutil.copyfile(self.controller.candidate(), self.controller.current_cert()))
        # 只模拟系统已信任根证书，绝不预加载中间证书。
        original_context = ssl.create_default_context
        patcher = mock.patch.object(certctl.ssl, 'create_default_context',
                                    side_effect=lambda: original_context(cafile=str(self.files / 'root.pem')))
        self.context_factory = patcher.start()
        self.addCleanup(patcher.stop)

    def test_complete_served_chain_is_verified_against_root_and_fingerprint(self):
        with tls_server(self.files / 'leaf-chain.pem', self.files / 'leaf.key') as probe:
            self.controller.config['probes'] = [probe]
            self.controller.verify_probes(self.expected)
        self.context_factory.assert_called_once_with()

    def test_valid_local_candidate_does_not_hide_missing_served_intermediate(self):
        self.controller.candidate_valid()
        with tls_server(self.files / 'leaf.pem', self.files / 'leaf.key') as probe:
            self.controller.config['probes'] = [probe]
            self.assertEqual(self.controller.probe_fingerprint(probe, verify_chain=False), self.expected)
            with self.assertRaisesRegex(certctl.Failure, '证书链、域名或有效期'):
                self.controller.verify_probes(self.expected)

    def test_complete_chain_with_wrong_expected_fingerprint_is_rejected(self):
        with tls_server(self.files / 'leaf-chain.pem', self.files / 'leaf.key') as probe:
            self.controller.config['probes'] = [probe]
            with self.assertRaisesRegex(certctl.Failure, '仍呈现其他证书'):
                self.controller.verify_probes('0' * 64)

    def test_matching_leaf_with_wrong_server_name_is_rejected(self):
        with tls_server(self.files / 'leaf-chain.pem', self.files / 'leaf.key') as probe:
            probe['server_name'] = 'wrong.example.test'
            self.controller.config['probes'] = [probe]
            with self.assertRaisesRegex(certctl.Failure, '证书链、域名或有效期'):
                self.controller.verify_probes(self.expected)

    def test_bootstrap_observes_expired_incomplete_chain_but_health_check_rejects_it(self):
        with tls_server(self.files / 'expired.pem', self.files / 'leaf.key') as probe:
            self.controller.config['probes'] = [probe]
            self.controller.preflight()
            self.context_factory.assert_not_called()
            with self.assertRaisesRegex(certctl.Failure, '证书链、域名或有效期'):
                self.controller.verify_probes(certctl.fingerprint(self.controller.current_cert()))

    def test_expired_complete_chain_is_rejected(self):
        with tls_server(self.files / 'expired-chain.pem', self.files / 'leaf.key') as probe:
            self.controller.config['probes'] = [probe]
            with self.assertRaisesRegex(certctl.Failure, '证书链、域名或有效期'):
                self.controller.verify_probes(certctl.fingerprint(self.files / 'expired.pem'))

    def test_missing_chain_keeps_deployment_pending_until_service_is_fixed(self):
        before = self.controller.binding_state(self.info)
        pending = self.controller.state / 'pending.json'
        with tls_server(self.files / 'leaf.pem', self.files / 'leaf.key') as probe, \
                mock.patch.object(certctl.time, 'sleep'):
            self.controller.config['probes'] = [probe]
            with self.assertRaisesRegex(certctl.Failure, '证书链、域名或有效期'):
                self.controller.deploy_and_verify(before)
        self.assertTrue(pending.is_file())
        self.assertEqual(certctl.read_json(pending)['fingerprint'], self.expected)
        with tls_server(self.files / 'leaf-chain.pem', self.files / 'leaf.key') as probe:
            self.controller.config['probes'] = [probe]
            self.controller.deploy_and_verify(before)
        self.assertFalse(pending.exists())
        self.assertEqual(self.controller.deploy_local_api.call_count, 2)


if __name__ == '__main__':
    unittest.main()
