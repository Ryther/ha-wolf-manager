"""Disposable scanner credentials are revoked and safe diagnostics are bounded."""
import secrets
import json
import base64
import os
from pathlib import Path
import argparse
import subprocess
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
from unittest.mock import patch
import unittest
from scripts.ci import verify_candidate as v


class CommunityTests(unittest.TestCase):
    def test_scanner_has_resource_bounds_and_never_puts_credentials_in_arguments(self):
        from scripts.ci import sonar_community as c
        with tempfile.TemporaryDirectory() as temporary:
            previous = Path.cwd()
            self.addCleanup(os.chdir, previous)
            os.chdir(temporary)
            Path('_tmp').mkdir(mode=0o700)
            for name in ('rust.lcov', 'javascript.lcov', 'python.xml'):
                (Path('_tmp') / name).write_bytes(b'disposable report input')
            args = argparse.Namespace(project='example', sha='1' * 40,
                rust_lcov=Path('_tmp/rust.lcov'), javascript_lcov=Path('_tmp/javascript.lcov'),
                python_xml=Path('_tmp/python.xml'), work=Path('_tmp/work'))
            secret = secrets.token_urlsafe(32)
            command = []
            def docker(argv, **options):
                command.extend(argv)
                self.assertEqual(options['env'], {'PATH': os.defpath, 'SONAR_TOKEN': secret})
                return subprocess.CompletedProcess(argv, 0)
            with patch.object(c.subprocess, 'run', side_effect=docker):
                receipt = c.scanner(args, secret)
            self.assertEqual(receipt, Path('_tmp/work/analysis/report-task.txt'))
            self.assertIn('--memory', command)
            self.assertEqual(command[command.index('--memory') + 1], '2g')
            self.assertEqual(command[command.index('--cpus') + 1], '2')
            self.assertNotIn(secret, ' '.join(command))
            self.assertIn('type=bind,source=' + str(Path.cwd()) + ',target=' + str(Path.cwd()) + ',readonly', command)
            settings = Path('_tmp/work/sonar-project.properties').read_text()
            self.assertIn('sonar.rust.clippy.enabled=false', settings)

    def test_native_http_token_lifecycle_and_diagnostics_never_follow_redirects(self):
        from scripts.ci import sonar_community as c, sonar_gate as s
        password = secrets.token_urlsafe(32)
        token = secrets.token_urlsafe(32)
        issued = set()
        leaked = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_POST(self):
                from urllib.parse import parse_qs
                expected = 'Basic ' + base64.b64encode(('admin:' + password).encode()).decode()
                if self.headers.get('Authorization') != expected:
                    self.send_response(403)
                    self.end_headers()
                    return
                values = parse_qs(self.rfile.read(int(self.headers['Content-Length'])).decode())
                if self.path == '/api/user_tokens/generate':
                    issued.add(values['name'][0])
                    body = {'token': token}
                else:
                    issued.remove(values['name'][0])
                    body = {}
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(body).encode())
            def do_GET(self):
                if self.path == '/api/redirect':
                    self.send_response(302)
                    self.send_header('Location', '/api/sink')
                    self.end_headers()
                    return
                if self.path == '/api/sink':
                    leaked.append(self.headers.get('Authorization'))
                if self.headers.get('Authorization') != 'Bearer ' + token:
                    self.send_response(403)
                    self.end_headers()
                    return
                field = 'hotspots' if self.path.startswith('/api/hotspots/') else 'issues'
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps({'paging': {'pageIndex': 1, 'pageSize': 500, 'total': 0}, field: []}).encode())
        with ThreadingHTTPServer(('127.0.0.1', 0), Handler) as http:
            worker = threading.Thread(target=http.serve_forever, daemon=True)
            worker.start()
            self.addCleanup(http.shutdown)
            url = 'http://127.0.0.1:' + str(http.server_port)
            with patch.object(s, 'COMMUNITY', url), patch.dict(os.environ, {'SONAR_LOCAL_ADMIN_PASSWORD': password}):
                admin = c.LocalAdmin()
                with c.temporary_token(admin) as credential, s.server(url, credential):
                    self.assertEqual(c.diagnostics(c.token_fetch, 'example'), {'issues': [], 'hotspots': []})
                    with self.assertRaisesRegex(v.VerificationError, 'api_redirect_refused'):
                        s.get('/api/redirect')
                self.assertEqual(issued, set())
                self.assertEqual(leaked, [])
            http.shutdown()
            worker.join(timeout=2)

    def test_generation_response_loss_still_revokes_possibly_created_token(self):
        from scripts.ci import sonar_community as c
        issued = set()
        def api(path, params=None, post=False):
            if path == '/api/user_tokens/generate':
                issued.add(params['name'])
                raise OSError('synthetic response loss')
            issued.remove(params['name'])
            return {}
        with self.assertRaises(OSError):
            with c.temporary_token(api):
                self.fail('lost generation response cannot authorize scan')
        self.assertEqual(issued, set())

    def test_fresh_local_scanner_token_is_revoked_after_scanner_failure(self):
        from scripts.ci import sonar_community as c
        issued = set()
        generated = secrets.token_urlsafe(32)
        def api(path, params=None, post=False):
            if path == '/api/user_tokens/generate':
                issued.add(params['name'])
                return {'token': generated}
            if path == '/api/user_tokens/revoke':
                issued.remove(params['name'])
                return {}
            self.fail('unexpected token API')
        with self.assertRaisesRegex(v.VerificationError, 'scanner_failed'):
            with c.temporary_token(api) as token:
                self.assertEqual(token, generated)
                raise v.VerificationError('scanner_failed')
        self.assertEqual(issued, set())

    def test_export_retains_rule_location_but_never_remote_messages_or_payloads(self):
        from scripts.ci import sonar_community as c
        secret = secrets.token_urlsafe(32)
        def fetch(path, params):
            field = 'hotspots' if 'hotspots' in path else 'issues'
            return {'paging': {'pageIndex': 1, 'pageSize': 500, 'total': 1}, field: [
                {'rule': 'python:S1', 'ruleKey': 'python:S1', 'component': 'example:scripts/ci/example.py',
                 'line': 5, 'severity': 'MAJOR', 'message': secret, 'flows': [{'credential': secret}]}]}
        report = c.diagnostics(fetch, 'example')
        self.assertEqual(report['issues'][0]['path'], 'scripts/ci/example.py')
        self.assertEqual(report['issues'][0]['rule'], 'python:S1')
        self.assertNotIn(secret, str(report))

    def test_incomplete_or_changed_findings_pagination_is_refused(self):
        from scripts.ci import sonar_community as c
        for response in [{'paging': {'pageIndex': 1, 'pageSize': 500, 'total': 501}, 'issues': []},
                         {'paging': {'pageIndex': 2, 'pageSize': 500, 'total': 0}, 'issues': []},
                         {'paging': {'pageIndex': 1, 'pageSize': 500, 'total': 50001}, 'issues': []}]:
            with self.subTest(response=response), self.assertRaises(v.VerificationError):
                c.pages(lambda *_: response, '/api/issues/search', {}, 'issues')


if __name__ == '__main__':
    unittest.main()
