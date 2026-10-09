"""Real release CLI output authority refuses aliases and preserves victim bytes."""
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch
from scripts.ci import producer as p, verify_candidate as v


class EvidenceOutputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.previous = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, self.previous)
        (self.root / '_tmp').mkdir(mode=0o700)
        self.victim = self.root / 'victim.json'
        self.victim.write_bytes(b'preserve victim')

    def report(self, output):
        arguments = ['producer', 'report', '--name', 'rust', '--sha', '1' * 40,
                     '--scope', 'Disposable output test', '--output', str(output)]
        with patch('sys.argv', arguments):
            p.main()

    def refuse(self, output):
        with self.assertRaises(v.VerificationError):
            self.report(output)
        self.assertEqual(self.victim.read_bytes(), b'preserve victim')

    def test_report_refuses_absolute_and_parent_traversal_output(self):
        for output in [self.victim, '_tmp/../victim.json', '_tmp/nested/../../victim.json', 'victim.json']:
            with self.subTest(output=str(output)):
                self.refuse(output)

    def test_report_refuses_symlink_parent_and_final(self):
        (self.root / '_tmp' / 'alias').symlink_to(self.root, target_is_directory=True)
        (self.root / '_tmp' / 'final.json').symlink_to(self.victim)
        for output in ['_tmp/alias/victim.json', '_tmp/final.json']:
            with self.subTest(output=output):
                self.refuse(output)

    def test_report_refuses_hardlinked_final(self):
        os.link(self.victim, self.root / '_tmp' / 'linked.json')
        self.refuse('_tmp/linked.json')

    def test_report_refuses_writable_parent_and_final(self):
        unsafe = self.root / '_tmp' / 'unsafe'
        unsafe.mkdir(mode=0o777)
        unsafe.chmod(0o777)
        self.refuse('_tmp/unsafe/report.json')
        target = self.root / '_tmp' / 'unsafe.json'
        target.write_bytes(b'preserve final')
        target.chmod(0o666)
        self.refuse('_tmp/unsafe.json')
        self.assertEqual(target.read_bytes(), b'preserve final')

    def test_report_refuses_special_socket_file(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as special:
            special.bind('_tmp/special')
            self.refuse('_tmp/special')

    def test_report_writes_legitimate_private_output(self):
        self.report('_tmp/nested/report.json')
        raw = (self.root / '_tmp/nested/report.json').read_bytes()
        self.assertEqual(v.json_bytes(raw), {'candidate_sha': '1' * 40,
            'result': 'success', 'scope': 'Disposable output test'})

    def test_all_producer_mutating_commands_refuse_outside_output_before_work(self):
        commands = [
            ['merge', '--amd64', 'missing', '--arm64', 'missing', '--version', '0.1.0'],
            ['assemble', '--amd64', 'missing', '--arm64', 'missing'],
            ['finalize', '--bundle', 'missing', '--artifact', 'missing', '--sha', '1' * 40,
             '--run-id', '1', '--workflow-id', '1'],
        ]
        for command in commands:
            with self.subTest(command=command[0]), patch('sys.argv',
                    ['producer', *command, '--output', str(self.victim)]):
                with self.assertRaisesRegex(v.VerificationError, 'archive_path|evidence_output_path'):
                    p.main()
                self.assertEqual(self.victim.read_bytes(), b'preserve victim')

    def test_sonar_cli_refuses_outside_output_before_network_verification(self):
        from scripts.ci import sonar_gate as s
        arguments = ['sonar', '--task', 'missing', '--sha', '1' * 40, '--project', 'example',
                     '--rust-lcov', 'missing', '--javascript-lcov', 'missing',
                     '--python-xml', 'missing', '--output', str(self.victim)]
        with patch('sys.argv', arguments), patch.object(s, 'verify') as verify:
            with self.assertRaises(SystemExit):
                s.main()
            verify.assert_not_called()
        self.assertEqual(self.victim.read_bytes(), b'preserve victim')

    def test_tree_writes_nested_bytes_with_closed_paths_and_existing_root_refusal(self):
        from scripts.ci import evidence_output as e
        e.Output('_tmp/bundle').write_tree({'nested/report.json': b'{}', 'blob': b'bytes'})
        self.assertEqual((self.root / '_tmp/bundle/blob').read_bytes(), b'bytes')
        self.assertEqual((self.root / '_tmp/bundle/nested/report.json').read_bytes(), b'{}')
        with self.assertRaises(v.VerificationError):
            e.Output('_tmp/bundle').write_tree({'blob': b'overwrite'})
        self.assertEqual((self.root / '_tmp/bundle/blob').read_bytes(), b'bytes')
        with self.assertRaises(v.VerificationError):
            e.Output('_tmp/new').write_tree({'../victim.json': b'overwrite'})
        self.assertFalse((self.root / '_tmp/new').exists())
        self.assertEqual(self.victim.read_bytes(), b'preserve victim')

    def test_oversized_report_refuses_before_any_output_write(self):
        from scripts.ci import evidence_output as e
        with patch.object(e, 'MAX_REPORT', 3):
            with self.assertRaises(v.VerificationError):
                e.Output('_tmp/report.json').write_file(b'four')
        self.assertFalse((self.root / '_tmp/report.json').exists())

    def test_regular_report_replacement_is_complete_private_and_no_temporary_leak(self):
        from scripts.ci import evidence_output as e
        output = e.Output('_tmp/report.json')
        output.write_file(b'previous')
        output.write_file(b'replacement')
        path = self.root / '_tmp/report.json'
        self.assertEqual(path.read_bytes(), b'replacement')
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(path.parent.glob('.evidence-*')), [])

    def test_failed_atomic_replacement_preserves_previous_and_removes_staging(self):
        from scripts.ci import evidence_output as e
        output = e.Output('_tmp/report.json')
        output.write_file(b'previous')
        with patch.object(e.os, 'replace', side_effect=OSError('synthetic rename failure')):
            with self.assertRaises(v.VerificationError):
                output.write_file(b'replacement')
        path = self.root / '_tmp/report.json'
        self.assertEqual(path.read_bytes(), b'previous')
        self.assertEqual(list(path.parent.glob('.evidence-*')), [])

    def test_fifo_file_refuses_without_blocking_and_preserves_victim(self):
        os.mkfifo('_tmp/fifo', 0o600)
        self.refuse('_tmp/fifo')

    @unittest.skipIf(os.geteuid() == 0, 'root-owned files are an accepted authority')
    def test_directory_owned_by_another_unprivileged_user_is_refused(self):
        from scripts.ci import evidence_output as e
        # Existing temporary files remain owned by the actual uid; simulate the
        # independently executing CI uid so native stat metadata cannot match it.
        actual_uid = os.geteuid()
        with patch.object(e.os, 'geteuid', return_value=actual_uid + 1):
            self.refuse('_tmp/report.json')
        self.assertFalse((self.root / '_tmp/report.json').exists())

    def test_symbolic_tmp_root_refuses_output(self):
        (self.root / '_tmp').rmdir()
        (self.root / '_tmp').symlink_to(self.root, target_is_directory=True)
        self.refuse('_tmp/victim.json')

    def test_final_alias_swap_during_staging_refuses_without_touching_victim(self):
        from scripts.ci import evidence_output as e
        output = e.Output('_tmp/report.json')
        output.write_file(b'previous')
        target = self.root / '_tmp/report.json'
        original_sync = e.os.fsync
        swapped = False
        def sync_and_swap(descriptor):
            nonlocal swapped
            original_sync(descriptor)
            if not swapped:
                swapped = True
                target.unlink()
                os.link(self.victim, target)
        with patch.object(e.os, 'fsync', side_effect=sync_and_swap):
            with self.assertRaises(v.VerificationError):
                output.write_file(b'replacement')
        self.assertEqual(self.victim.read_bytes(), b'preserve victim')
        self.assertEqual(target.read_bytes(), b'preserve victim')
        self.assertEqual(list(target.parent.glob('.evidence-*')), [])

    def test_sonar_cli_writes_only_after_successful_verification(self):
        from scripts.ci import sonar_gate as s
        arguments = ['sonar', '--task', 'missing', '--sha', '1' * 40, '--project', 'example',
                     '--rust-lcov', 'missing', '--javascript-lcov', 'missing',
                     '--python-xml', 'missing', '--output', '_tmp/sonar.json']
        result = {'candidate_sha': '1' * 40, 'result': 'success'}
        with patch('sys.argv', arguments), patch.object(s, 'verify', return_value=result):
            s.main()
        self.assertEqual(v.json_bytes((self.root / '_tmp/sonar.json').read_bytes()), result)
        with patch('sys.argv', arguments), patch.object(s, 'verify', side_effect=v.VerificationError('test')):
            with self.assertRaises(SystemExit):
                s.main()
        self.assertEqual(v.json_bytes((self.root / '_tmp/sonar.json').read_bytes()), result)

    def test_tree_refuses_symlink_root_without_touching_target(self):
        from scripts.ci import evidence_output as e
        (self.root / '_tmp/alias').symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(v.VerificationError):
            e.Output('_tmp/alias/bundle').write_tree({'victim.json': b'overwrite'})
        self.assertEqual(self.victim.read_bytes(), b'preserve victim')
        self.assertFalse((self.root / 'bundle').exists())
