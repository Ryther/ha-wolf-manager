"""Original OCI byte and credential boundaries for the standard transfer adapter."""
import contextlib
import importlib
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from scripts.ci import verify_candidate as v
from test_candidate import fixture


class OciTransferTests(unittest.TestCase):
    def adapter(self):
        return importlib.import_module('scripts.ci.oci_transfer')

    def test_copy_uses_original_layout_and_only_digest_destination(self):
        transfer = self.adapter()
        files, _, _, _, receipt = fixture()
        original = dict(files); image = receipt['image']
        token = secrets.token_urlsafe(32); actor = 'fixture'
        calls = []; private_paths = []
        @contextlib.contextmanager
        def binary():
            yield 123
        def run(fd, arguments, *, config, stdin=None, timeout, phase):
            self.assertEqual(fd, 123)
            self.assertNotIn(token, repr(arguments))
            self.assertEqual(Path(config).parent.stat().st_mode & 0o777, 0o700)
            private_paths.append(Path(config).parent)
            calls.append((arguments, stdin, timeout, phase))
            if phase == 'login':
                self.assertEqual(stdin, token.encode())
                self.assertIn('--registry-config', arguments)
                self.assertIn('--password-stdin', arguments)
                self.assertIn('--username', arguments)
                self.assertIn(actor, arguments)
                self.assertEqual(arguments[-1], 'ghcr.io')
            else:
                self.assertEqual(phase, 'copy')
                self.assertIsNone(stdin)
                self.assertIn('--from-oci-layout', arguments)
                self.assertIn('--to-registry-config', arguments)
                self.assertNotIn('--registry-config', arguments)
                self.assertEqual(arguments[-1], image['repository'] + '@' + image['index_digest'])
                source = arguments[-2]
                layout, digest = source.rsplit('@', 1)
                self.assertEqual(digest, image['index_digest'])
                observed = {p.relative_to(layout).as_posix(): p.read_bytes()
                            for p in Path(layout).rglob('*') if p.is_file()}
                expected = {name.removeprefix('oci/'): data for name, data in files.items()
                            if name.startswith('oci/')}
                self.assertEqual(observed, expected)
        with patch.object(transfer, 'verified_binary', binary), patch.object(transfer, '_run', side_effect=run):
            transfer.transfer(files, image, actor, token)
        self.assertEqual([call[3] for call in calls], ['login', 'copy'])
        self.assertEqual(files, original)
        self.assertTrue(all(not path.exists() for path in private_paths))

    def test_subprocess_credentials_are_stdin_only_and_output_is_discarded(self):
        transfer = self.adapter(); token = secrets.token_urlsafe(32)
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'config.json'
            with patch.object(transfer.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as run:
                transfer._run(123, ['login', '--password-stdin', 'ghcr.io'], config=config,
                              stdin=token.encode(), timeout=60, phase='login')
            args, kwargs = run.call_args
            self.assertEqual(args[0][0], '/proc/self/fd/123')
            self.assertNotIn(token, repr(args))
            self.assertNotIn(token, repr(kwargs['env']))
            self.assertEqual(kwargs['input'], token.encode())
            self.assertEqual(kwargs['stdout'], subprocess.DEVNULL)
            self.assertEqual(kwargs['stderr'], subprocess.DEVNULL)
            self.assertEqual(kwargs['pass_fds'], (123,))
            self.assertFalse(kwargs.get('shell', False))

    def test_native_failures_expose_only_closed_codes(self):
        transfer = self.adapter(); private = secrets.token_urlsafe(24)
        cases = [(subprocess.TimeoutExpired(private, 1, output=private), 'oci_timeout'),
                 (OSError(private), 'oci_unavailable')]
        with tempfile.TemporaryDirectory() as directory:
            for error, code in cases:
                with self.subTest(code=code), patch.object(transfer.subprocess, 'run', side_effect=error):
                    with self.assertRaisesRegex(v.VerificationError, '^' + code + '$') as caught:
                        transfer._run(123, ['cp'], config=Path(directory) / 'config.json',
                                      timeout=1, phase='copy')
                    self.assertNotIn(private, repr(caught.exception))
            for phase in ('login', 'copy'):
                with patch.object(transfer.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)):
                    with self.assertRaisesRegex(v.VerificationError, '^oci_' + phase + '_failed$'):
                        transfer._run(123, [], config=Path(directory) / 'config.json', timeout=1, phase=phase)

    def test_unverified_binary_is_refused(self):
        transfer = self.adapter()
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'oras'
            binary.write_bytes(b'not-the-verified-tool'); binary.chmod(0o755)
            with patch.object(transfer, 'BINARY', binary):
                with self.assertRaisesRegex(v.VerificationError, '^oci_tool_identity$'):
                    with transfer.verified_binary():
                        self.fail('unverified executable accepted')

    def test_verified_binary_rejects_aliases_and_unsafe_modes_and_closes_fd(self):
        transfer = self.adapter()
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'oras'
            raw = b'synthetic-pinned-executable'
            binary.write_bytes(raw); binary.chmod(0o755)
            with patch.object(transfer, 'BINARY', binary), patch.object(transfer, 'BINARY_SHA256', v.sha256(raw)):
                with transfer.verified_binary() as fd:
                    self.assertEqual(os.pread(fd, len(raw), 0), raw)
                with self.assertRaises(OSError):
                    os.fstat(fd)
                hardlink = Path(directory) / 'alias'
                os.link(binary, hardlink)
                with self.assertRaisesRegex(v.VerificationError, '^oci_tool_identity$'):
                    with transfer.verified_binary():
                        self.fail('hard linked executable accepted')
                hardlink.unlink()
                for mode in (0o777, 0o644):
                    binary.chmod(mode)
                    with self.subTest(mode=mode), self.assertRaisesRegex(v.VerificationError, '^oci_tool_identity$'):
                        with transfer.verified_binary():
                            self.fail('unsafe executable mode accepted')
                binary.chmod(0o755)
                symbolic = Path(directory) / 'symbolic'
                symbolic.symlink_to(binary)
                with patch.object(transfer, 'BINARY', symbolic):
                    with self.assertRaisesRegex(v.VerificationError, '^oci_tool_identity$'):
                        with transfer.verified_binary():
                            self.fail('symbolic executable accepted')

    def test_failed_login_cleans_private_credentials_and_never_copies(self):
        transfer = self.adapter()
        files, _, _, _, receipt = fixture()
        paths = []
        @contextlib.contextmanager
        def binary():
            yield 123
        def fail_login(fd, arguments, *, config, **kwargs):
            paths.append(Path(config).parent)
            self.assertEqual(kwargs['phase'], 'login')
            self.assertEqual(Path(config).stat().st_mode & 0o777, 0o600)
            raise v.VerificationError('oci_login_failed')
        with patch.object(transfer, 'verified_binary', binary), patch.object(transfer, '_run', side_effect=fail_login) as run:
            with self.assertRaisesRegex(v.VerificationError, '^oci_login_failed$'):
                transfer.transfer(files, receipt['image'], 'fixture', secrets.token_urlsafe(32))
        self.assertEqual(run.call_count, 1)
        self.assertTrue(all(not path.exists() for path in paths))

    def test_actual_github_bot_actor_is_passed_as_one_login_argument(self):
        transfer = self.adapter()
        files, _, _, _, receipt = fixture()
        @contextlib.contextmanager
        def binary():
            yield 123
        for actor in ('github-actions[bot]', 'dependabot[bot]'):
            with self.subTest(actor=actor), patch.object(transfer, 'verified_binary', binary), \
                    patch.object(transfer, '_run') as run:
                transfer.transfer(files, receipt['image'], actor, secrets.token_urlsafe(32))
                login = run.call_args_list[0].args[1]
                self.assertEqual(login[login.index('--username') + 1], actor)
                self.assertEqual(run.call_count, 2)

    def test_actor_extensions_do_not_admit_flags_or_shell_text(self):
        transfer = self.adapter()
        files, _, _, _, receipt = fixture()
        for actor in ('--password-stdin', 'fixture bot', 'fixture\n--password-stdin',
                      'fixture[other]', 'fixture[bot]suffix', 'fixture;echo'):
            with self.subTest(actor=actor), patch.object(transfer, '_run') as run:
                with self.assertRaisesRegex(v.VerificationError, '^oci_credentials$'):
                    transfer.transfer(files, receipt['image'], actor, secrets.token_urlsafe(32))
                run.assert_not_called()
