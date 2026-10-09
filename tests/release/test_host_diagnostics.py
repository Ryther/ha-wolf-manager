"""Disposable child-process evidence is bounded and survives fixture failure."""
import importlib.util
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2] / 'tests/host-platform/run.py'
spec = importlib.util.spec_from_file_location('host_platform_diagnostics', SOURCE)
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
LIMIT = 1024 * 1024


def setup_archive(data, kind=tarfile.REGTYPE, name='wolf-platform-setup.log'):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as archive:
        entry = tarfile.TarInfo(name)
        entry.type = kind
        entry.size = len(data) if kind == tarfile.REGTYPE else 0
        if kind == tarfile.SYMTYPE:
            entry.linkname = '/reserved-victim'
        archive.addfile(entry, io.BytesIO(data) if entry.isfile() else None)
    return output.getvalue()


class HostDiagnosticsTests(unittest.TestCase):
    def test_failed_family_stdout_and_setup_capture_never_exceed_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            archive = output / 'input.tar'
            archive.write_bytes(setup_archive(b'y' * (LIMIT + 51)))
            real_capture = h.capture
            def fixture(command, **kwargs):
                if command[1] == 'run':
                    return real_capture([sys.executable, '-c',
                        'import os;os.write(1,b"x"*1048613);os.write(2,b"stderr");raise SystemExit(1)'])
                if command[1] == 'cp':
                    return real_capture([sys.executable, '-c',
                        'import sys;sys.stdout.buffer.write(open(sys.argv[1],"rb").read())',
                        str(archive)], **kwargs)
                return h.Capture(b'', 0, False, 0)
            with patch.object(h, 'capture', side_effect=fixture):
                status = h.check({'family': 'debian', 'image': 'reserved-fixture'}, output)
            self.assertEqual(status['returncode'], 1)
            self.assertEqual((output / 'debian.log').stat().st_size, LIMIT)
            self.assertEqual((output / 'debian-setup.log').stat().st_size, LIMIT)
            self.assertTrue(status['log_truncated'])
            self.assertTrue(status['setup_log_truncated'])
            self.assertEqual(status['setup_log_discarded_bytes'], 51)

    def test_timeout_preserves_partial_output_and_uses_safe_error_code(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            def fixture(command, **kwargs):
                if command[1] == 'run':
                    return h.Capture(b'partial fixture output', -9, True, 0)
                return h.Capture(b'', 1, False, 0)
            with patch.object(h, 'capture', side_effect=fixture):
                status = h.check({'family': 'debian', 'image': 'reserved-fixture'}, output)
            self.assertEqual(status.get('error'), 'container_timeout')
            self.assertEqual((output / 'debian.log').read_bytes(), b'partial fixture output')
            self.assertFalse(status['setup_log_saved'])
            self.assertFalse(status['cleanup_success'])

    def test_actual_noisy_child_is_drained_with_fixed_retained_memory(self):
        result = h.capture([sys.executable, '-c',
            'import os;os.write(1,b"a"*2000000);os.write(2,b"z"*2000000)'], limit=19)
        self.assertEqual(result.returncode, 0)
        self.assertFalse(result.timed_out)
        self.assertEqual(result.data, b'a' * 19)
        self.assertEqual(result.discarded, 4000000 - 19)

    def test_actual_timeout_kills_child_group_and_keeps_prior_output(self):
        started = time.monotonic()
        result = h.capture([sys.executable, '-c',
            'import time;print("before timeout",flush=True);time.sleep(20)'], timeout=0.2)
        self.assertTrue(result.timed_out)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.data, b'before timeout\n')
        self.assertLess(time.monotonic() - started, 3)

    def test_closed_stdout_does_not_bypass_process_deadline(self):
        result = h.capture([sys.executable, '-c',
            'import os,time;os.close(1);os.close(2);time.sleep(20)'], timeout=0.2)
        self.assertTrue(result.timed_out)
        self.assertEqual(result.data, b'')

    def test_invalid_setup_tar_or_alias_never_writes_a_log(self):
        for raw in (b'not tar', setup_archive(b'', tarfile.SYMTYPE),
                    setup_archive(b'private', name='../outside')):
            with self.subTest(size=len(raw)), tempfile.TemporaryDirectory() as directory:
                output = Path(directory)
                with patch.object(h, 'capture', return_value=h.Capture(raw, 0, False, 0)):
                    status = h.setup_capture('reserved-container', output, 'debian')
                self.assertFalse(status['setup_log_saved'])
                self.assertEqual(list(output.iterdir()), [])

    def test_invalid_or_truncated_success_evidence_refuses_clean_success(self):
        for result in (h.Capture(b'not json', 0, False, 0),
                       h.Capture(b'{"family":"debian"}', 0, False, 1)):
            with self.subTest(result=result), tempfile.TemporaryDirectory() as directory:
                def fixture(command, **kwargs):
                    return result if command[1] == 'run' else h.Capture(b'', 0, False, 0)
                with patch.object(h, 'capture', side_effect=fixture):
                    status = h.check({'family': 'debian', 'image': 'reserved-fixture'}, Path(directory))
                self.assertEqual(status['returncode'], 1)
                self.assertIn(status['error'], ('evidence_invalid', 'evidence_output_limit'))

    def test_valid_family_evidence_and_cleanup_remain_successful(self):
        with tempfile.TemporaryDirectory() as directory:
            def fixture(command, **kwargs):
                data = b'{"family":"debian","ssh":true}\n' if command[1] == 'run' else b''
                return h.Capture(data, 0, False, 0)
            with patch.object(h, 'capture', side_effect=fixture):
                status = h.check({'family': 'debian', 'image': 'reserved-fixture'}, Path(directory))
            self.assertEqual(status['returncode'], 0)
            self.assertTrue(status['cleanup_success'])
            self.assertEqual(status['evidence'], {'family': 'debian', 'ssh': True})

    def test_spawn_error_never_exposes_external_command_or_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(h, 'capture', side_effect=OSError('PRIVATE_PAYLOAD')):
                status = h.check({'family': 'debian', 'image': 'reserved-fixture'}, Path(directory))
            self.assertEqual(status['returncode'], 1)
            self.assertEqual(status['error'], 'fixture_io_failed')
            self.assertNotIn('PRIVATE_PAYLOAD', str(status))

    def test_failed_container_cleanup_refuses_an_otherwise_passing_family(self):
        with tempfile.TemporaryDirectory() as directory:
            def fixture(command, **kwargs):
                if command[1] == 'run':
                    return h.Capture(b'{"family":"debian"}\n', 0, False, 0)
                return h.Capture(b'', 1, False, 0)
            with patch.object(h, 'capture', side_effect=fixture):
                status = h.check({'family': 'debian', 'image': 'reserved-fixture'}, Path(directory))
            self.assertEqual(status['returncode'], 1)
            self.assertEqual(status['error'], 'container_cleanup_failed')

    def test_selector_error_and_cancellation_terminate_child_without_descriptor_leak(self):
        import os
        import signal
        for exception in (OSError('synthetic selector error'), KeyboardInterrupt()):
            with self.subTest(exception=type(exception).__name__):
                children = []
                original_spawn = h.subprocess.Popen
                def spawn(*args, **kwargs):
                    child = original_spawn(*args, **kwargs)
                    children.append(child)
                    return child
                descriptors = len(list(Path('/proc/self/fd').iterdir()))
                started = time.monotonic()
                try:
                    with patch.object(h.subprocess, 'Popen', side_effect=spawn), \
                            patch.object(h.selectors.DefaultSelector, 'select', side_effect=exception):
                        with self.assertRaises(type(exception)):
                            h.capture([sys.executable, '-c', 'import time;time.sleep(0.6)'], timeout=0.05)
                    self.assertLess(time.monotonic() - started, 0.5)
                    self.assertEqual(len(children), 1)
                    self.assertIsNotNone(children[0].poll())
                    self.assertTrue(children[0].stdout.closed)
                    with self.assertRaises(ProcessLookupError):
                        os.killpg(children[0].pid, 0)
                    self.assertEqual(len(list(Path('/proc/self/fd').iterdir())), descriptors)
                finally:
                    for child in children:
                        if child.poll() is None:
                            os.killpg(child.pid, signal.SIGKILL)
                            child.wait(timeout=3)

    def test_worker_cancellation_event_kills_actual_child_group_promptly(self):
        import concurrent.futures
        import os
        import threading
        cancellation = threading.Event()
        spawned = threading.Event()
        children = []
        original_spawn = h.subprocess.Popen
        def spawn(*args, **kwargs):
            child = original_spawn(*args, **kwargs)
            children.append(child)
            spawned.set()
            return child
        with patch.object(h.subprocess, 'Popen', side_effect=spawn), \
                concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(h.capture, [sys.executable, '-c',
                'import time;time.sleep(20)'], timeout=0.6, cancellation=cancellation)
            self.assertTrue(spawned.wait(1))
            started = time.monotonic()
            cancellation.set()
            result = future.result(timeout=2)
            self.assertTrue(result.cancelled)
            self.assertFalse(result.timed_out)
            self.assertLess(time.monotonic() - started, 0.5)
        self.assertTrue(children[0].stdout.closed)
        with self.assertRaises(ProcessLookupError):
            os.killpg(children[0].pid, 0)

    def test_main_exception_cancels_running_worker_before_pool_shutdown(self):
        import threading
        started = threading.Event()
        worker_results = []
        def worker(entry, output, cancellation=None):
            if entry['family'] == 'debian':
                self.assertTrue(started.wait(1))
                raise KeyboardInterrupt()
            started.set()
            result = h.capture([sys.executable, '-c', 'import time;time.sleep(20)'],
                               timeout=0.6, cancellation=cancellation)
            worker_results.append(result)
            return {'family': entry['family'], 'returncode': 1}
        with tempfile.TemporaryDirectory() as directory, patch.object(h, 'check', side_effect=worker), \
                patch('sys.argv', ['run', '--family', 'debian', '--family', 'ubuntu',
                                   '--jobs', '2', '--output', directory]):
            begin = time.monotonic()
            with self.assertRaises(KeyboardInterrupt):
                h.main()
            self.assertLess(time.monotonic() - begin, 0.5)
        self.assertEqual(len(worker_results), 1)
        self.assertTrue(worker_results[0].cancelled)

    def test_cancelled_family_never_reports_success_and_cleanup_ignores_event(self):
        import threading
        cancellation = threading.Event()
        cancellation.set()
        calls = []
        def fixture(command, **kwargs):
            calls.append((command[1], kwargs.get('cancellation')))
            if command[1] == 'run':
                return h.Capture(b'partial', 0, False, 0, True)
            return h.Capture(b'', 0, False, 0)
        with tempfile.TemporaryDirectory() as directory, patch.object(h, 'capture', side_effect=fixture):
            status = h.check({'family': 'debian', 'image': 'reserved-fixture'}, Path(directory), cancellation)
        self.assertEqual(status['error'], 'container_cancelled')
        self.assertEqual(status['returncode'], 1)
        self.assertTrue(status['cleanup_success'])
        self.assertEqual(calls, [('run', cancellation), ('rm', None)])

    def test_stream_read_error_reaps_actual_child_and_closes_pipe(self):
        import os
        children = []
        original_spawn = h.subprocess.Popen
        original_read = h.os.read
        def spawn(*args, **kwargs):
            child = original_spawn(*args, **kwargs)
            children.append(child)
            return child
        def read(descriptor, size):
            if children and descriptor == children[0].stdout.fileno():
                raise OSError('synthetic read error')
            return original_read(descriptor, size)
        with patch.object(h.subprocess, 'Popen', side_effect=spawn), patch.object(h.os, 'read', side_effect=read):
            with self.assertRaises(OSError):
                h.capture([sys.executable, '-c', 'import time;print("ready",flush=True);time.sleep(20)'])
        self.assertIsNotNone(children[0].poll())
        self.assertTrue(children[0].stdout.closed)
        with self.assertRaises(ProcessLookupError):
            os.killpg(children[0].pid, 0)

    def test_main_submission_cancellation_also_drains_started_workers(self):
        import threading
        started = threading.Event()
        results = []
        original_submit = h.concurrent.futures.ThreadPoolExecutor.submit
        submitted = 0
        def submit(pool, *args, **kwargs):
            nonlocal submitted
            submitted += 1
            if submitted == 2:
                self.assertTrue(started.wait(1))
                raise KeyboardInterrupt()
            return original_submit(pool, *args, **kwargs)
        def worker(entry, output, cancellation):
            started.set()
            result = h.capture([sys.executable, '-c', 'import time;time.sleep(20)'], cancellation=cancellation)
            results.append(result)
            return {'family': entry['family'], 'returncode': 1}
        with tempfile.TemporaryDirectory() as directory, patch.object(h, 'check', side_effect=worker), \
                patch.object(h.concurrent.futures.ThreadPoolExecutor, 'submit', side_effect=submit, autospec=True), \
                patch('sys.argv', ['run', '--family', 'debian', '--family', 'ubuntu',
                                   '--jobs', '2', '--output', directory]):
            with self.assertRaises(KeyboardInterrupt):
                h.main()
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].cancelled)

    def test_setup_capture_receives_shared_cancellation_and_saves_no_partial_tar(self):
        import threading
        cancellation = threading.Event()
        cancellation.set()
        def fixture(command, **kwargs):
            self.assertIs(kwargs.get('cancellation'), cancellation)
            return h.Capture(b'partial tar', -9, False, 0, True)
        with tempfile.TemporaryDirectory() as directory, patch.object(h, 'capture', side_effect=fixture):
            result = h.setup_capture('reserved-container', Path(directory), 'debian', cancellation)
            self.assertEqual(result['setup_error'], 'setup_capture_cancelled')
            self.assertFalse(result['setup_log_saved'])
            self.assertEqual(list(Path(directory).iterdir()), [])
