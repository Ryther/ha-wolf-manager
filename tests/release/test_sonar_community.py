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
            for name in ('rust.lcov', 'javascript.lcov', 'python.xml', 'clippy.json'):
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
            self.assertIn('-Dsonar.rust.clippyReport.reportPaths=' + str(Path.cwd() / '_tmp/clippy.json'), command)

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

    def test_scan_retains_sanitized_diagnostics_and_revokes_token_on_gate_failure(self):
        from scripts.ci import sonar_community as c
        from contextlib import nullcontext
        previous = Path.cwd()
        self.addCleanup(os.chdir, previous)
        with tempfile.TemporaryDirectory() as directory:
            os.chdir(directory)
            Path('_tmp').mkdir(mode=0o700)
            args = argparse.Namespace(project='example', sha='1' * 40,
                output=Path('_tmp/result.json'), diagnostics=Path('_tmp/diagnostics.json'),
                rust_lcov=Path('_tmp/rust'), javascript_lcov=Path('_tmp/js'), python_xml=Path('_tmp/python'))
            issued = set()
            credential = secrets.token_urlsafe(32)
            def api(path, params=None, post=False):
                if path == '/api/projects/create': return {}
                if path == '/api/user_tokens/generate':
                    issued.add(params['name']); return {'token': credential}
                issued.remove(params['name']); return {}
            safe = {'issues': [{'rule': 'python:S1', 'path': '', 'line': 1, 'severity': 'MAJOR'}], 'hotspots': []}
            with patch.object(c, 'LocalAdmin', return_value=api), patch.object(c, 'ready'), \
                 patch.object(c.s, 'server', return_value=nullcontext()), \
                 patch.object(c, 'scanner', return_value=Path('_tmp/task')), \
                 patch.object(c.s, 'verify', side_effect=v.VerificationError('synthetic_gate')), \
                 patch.object(c, 'diagnostics', return_value=safe):
                with self.assertRaisesRegex(v.VerificationError, 'synthetic_gate'):
                    c.scan(args)
            self.assertEqual(issued, set())
            self.assertEqual(json.loads(args.diagnostics.read_bytes()), safe)
            self.assertFalse(args.output.exists())
            self.assertNotIn(credential, args.diagnostics.read_text())

    def test_scan_success_writes_verified_receipt_and_diagnostics_before_revocation(self):
        from scripts.ci import sonar_community as c
        from contextlib import nullcontext
        previous = Path.cwd()
        self.addCleanup(os.chdir, previous)
        with tempfile.TemporaryDirectory() as directory:
            os.chdir(directory); Path('_tmp').mkdir(mode=0o700)
            token = secrets.token_urlsafe(32)
            events = []
            def api(path, params=None, post=False):
                events.append(path)
                return {'token': token} if path.endswith('/generate') else {}
            argv = ['sonar_community', 'scan', '--project', 'example', '--sha', '1' * 40]
            for name, value in [('rust-lcov', '_tmp/rust'), ('javascript-lcov', '_tmp/js'),
                                ('python-xml', '_tmp/python'), ('work', '_tmp/work'),
                                ('output', '_tmp/result.json'), ('diagnostics', '_tmp/diagnostics.json')]:
                argv += ['--' + name, value]
            verified = {'candidate_sha': '1' * 40, 'coverage': 95}
            with patch('sys.argv', argv), patch.object(c, 'LocalAdmin', return_value=api), \
                 patch.object(c, 'ready'), patch.object(c.s, 'server', return_value=nullcontext()), \
                 patch.object(c, 'scanner', return_value=Path('_tmp/task')), \
                 patch.object(c.s, 'verify', return_value=verified), \
                 patch.object(c, 'diagnostics', return_value={'issues': [], 'hotspots': []}):
                c.main()
            self.assertEqual(json.loads(Path('_tmp/result.json').read_bytes()), verified)
            self.assertEqual(json.loads(Path('_tmp/diagnostics.json').read_bytes()), {'issues': [], 'hotspots': []})
            self.assertEqual(events[-1], '/api/user_tokens/revoke')
            self.assertNotIn(token, Path('_tmp/result.json').read_text())

    def test_readiness_retries_transient_response_loss_and_has_bounded_timeout(self):
        from scripts.ci import sonar_community as c
        with patch.object(c.time, 'sleep') as sleep:
            responses = iter([OSError('response lost'), {'status': 'STARTING'}, {'status': 'UP'}])
            def api(_):
                response = next(responses)
                if isinstance(response, Exception): raise response
                return response
            c.ready(api)
            self.assertEqual(sleep.call_count, 2)
            sleep.reset_mock()
            with self.assertRaisesRegex(v.VerificationError, 'sonar_local_not_ready'):
                c.ready(lambda _: {'status': 'STARTING'})
            self.assertEqual(sleep.call_count, 120)

    def test_diagnostics_cli_writes_safe_report_and_refuses_remote_secret_error(self):
        from scripts.ci import sonar_community as c
        from contextlib import nullcontext
        import sys
        previous = Path.cwd()
        self.addCleanup(os.chdir, previous)
        with tempfile.TemporaryDirectory() as directory:
            os.chdir(directory); Path('_tmp').mkdir(mode=0o700)
            secret = secrets.token_urlsafe(32)
            argv = ['sonar_community', 'diagnostics', '--project', 'example', '--output', '_tmp/result.json']
            with patch.object(sys, 'argv', argv), patch.dict(os.environ, {'SONAR_TOKEN': secret}), \
                 patch.object(c.s, 'server', return_value=nullcontext()) as server, \
                 patch.object(c, 'diagnostics', return_value={'issues': [], 'hotspots': []}):
                c.main()
                server.assert_called_once_with(c.s.CLOUD, secret)
            self.assertEqual(json.loads(Path('_tmp/result.json').read_bytes()), {'issues': [], 'hotspots': []})
            with patch.object(sys, 'argv', argv[:-1] + ['_tmp/refused.json']), \
                 patch.dict(os.environ, {'SONAR_TOKEN': secret}), \
                 patch.object(c.s, 'server', side_effect=OSError(secret)):
                with self.assertRaises(SystemExit) as refused:
                    c.main()
            self.assertNotIn(secret, str(refused.exception))
            self.assertFalse(Path('_tmp/refused.json').exists())


if __name__ == '__main__':
    unittest.main()
