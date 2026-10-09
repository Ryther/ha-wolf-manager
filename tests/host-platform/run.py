#!/usr/bin/env python3
"""Run isolated distribution checks without exposing Docker or host state inside them."""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import io
import os
import selectors
import signal
import tarfile
import time
import threading
from typing import NamedTuple
from pathlib import Path
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[2]
MATRIX = json.loads((ROOT / "tests/host-platform/images.json").read_text())


MAX_LOG = 1024 * 1024
SETUP_FILE = 'wolf-platform-setup.log'


class Capture(NamedTuple):
    data: bytes
    returncode: int
    timed_out: bool
    discarded: int
    cancelled: bool = False


def terminate(process):
    if process.returncode is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)


def stop_child(process, deadline, cancellation):
    cancelled = cancellation is not None and cancellation.is_set()
    timed_out = time.monotonic() >= deadline
    if cancelled or timed_out:
        terminate(process)
    return cancelled, timed_out


def capture(command, timeout=900, limit=MAX_LOG, cancellation=None):
    """Drain noisy children with bounded memory, cancellation and a deadline."""
    retained = bytearray()
    discarded = 0
    timed_out = False
    cancelled = False
    deadline = time.monotonic() + timeout
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               start_new_session=True)
    try:
        with selectors.DefaultSelector() as ready:
            ready.register(process.stdout, selectors.EVENT_READ)
            while ready.get_map():
                cancelled, timed_out = stop_child(process, deadline, cancellation)
                if cancelled or timed_out:
                    break
                for key, _ in ready.select(min(max(0, deadline - time.monotonic()), 0.25)):
                    chunk = os.read(key.fd, 64 * 1024)
                    if not chunk:
                        ready.unregister(key.fileobj)
                        continue
                    available = max(0, limit - len(retained))
                    retained.extend(chunk[:available])
                    discarded += max(0, len(chunk) - available)
        while not (cancelled or timed_out) and process.poll() is None:
            cancelled, timed_out = stop_child(process, deadline, cancellation)
            if not (cancelled or timed_out):
                try:
                    process.wait(timeout=min(max(0.001, deadline - time.monotonic()), 0.25))
                except subprocess.TimeoutExpired:
                    pass
    except BaseException:
        terminate(process)
        raise
    finally:
        process.stdout.close()
    return Capture(bytes(retained), process.returncode, timed_out, discarded, cancelled)


def setup_capture(name, output, family, cancellation=None):
    # cp works for failed/stopped containers. Parse one bounded regular member
    # in memory; never extract candidate-selected paths to the host filesystem.
    result = capture(['docker', 'cp', name + ':/tmp/' + SETUP_FILE, '-'],
                     timeout=30, limit=MAX_LOG + 4096, cancellation=cancellation)
    if result.cancelled:
        return {'setup_log_saved': False, 'setup_error': 'setup_capture_cancelled'}
    if result.returncode or result.timed_out:
        return {'setup_log_saved': False, 'setup_error': 'setup_capture_failed'}
    try:
        with tarfile.open(fileobj=io.BytesIO(result.data), mode='r:') as archive:
            item = archive.next()
            if item is None or not item.isfile() or item.name != SETUP_FILE:
                return {'setup_log_saved': False, 'setup_error': 'setup_capture_invalid'}
            stream = archive.extractfile(item)
            if stream is None:
                return {'setup_log_saved': False, 'setup_error': 'setup_capture_invalid'}
            data = stream.read(min(item.size, MAX_LOG))
            (output / (family + '-setup.log')).write_bytes(data)
            return {'setup_log_saved': True, 'setup_log_truncated': item.size > MAX_LOG,
                    'setup_log_discarded_bytes': max(0, item.size - MAX_LOG)}
    except (tarfile.TarError, OSError, ValueError):
        return {'setup_log_saved': False, 'setup_error': 'setup_capture_invalid'}


def check(entry: dict[str, str], output: Path, cancellation=None) -> dict[str, object]:
    name = f"wolf-platform-{entry['family']}-{uuid.uuid4().hex[:8]}"
    command = [
        "docker", "run", "--name", name, "--cap-drop=ALL",
        "--cap-add=CHOWN", "--cap-add=DAC_OVERRIDE", "--cap-add=FOWNER",
        "--cap-add=SETUID", "--cap-add=SETGID", "--cap-add=SYS_CHROOT",
        "--cap-add=AUDIT_WRITE", "--security-opt=no-new-privileges:false",
        "--pids-limit=256", "--memory=2g", "--tmpfs=/run",
        "--mount", f"type=bind,source={ROOT / 'installer/templates'},target=/templates,readonly",
        "--mount", f"type=bind,source={ROOT / 'tests/host-platform'},target=/fixture,readonly",
        entry["image"], "/bin/sh", "/fixture/setup.sh", entry["family"],
    ]
    status: dict[str, object] = {'family': entry['family'], 'image': entry['image'],
                                'returncode': 1, 'stage': 'container'}
    try:
        result = capture(command, cancellation=cancellation)
        (output / f"{entry['family']}.log").write_bytes(result.data)
        status.update(returncode=result.returncode, log_truncated=result.discarded > 0,
                      log_discarded_bytes=result.discarded)
        if result.cancelled:
            status.update(returncode=1, error='container_cancelled')
        elif result.timed_out:
            status.update(returncode=1, error='container_timeout')
        elif result.returncode == 0:
            status['stage'] = 'evidence'
            if result.discarded:
                status.update(returncode=1, error='evidence_output_limit')
            else:
                status['evidence'] = json.loads(result.data.strip().splitlines()[-1])
        if status['returncode'] and not result.cancelled:
            status.update(setup_capture(name, output, entry['family'], cancellation))
            if cancellation is not None and cancellation.is_set():
                status['error'] = 'container_cancelled'
    except (ValueError, IndexError):
        status.update(returncode=1, error='evidence_invalid')
    except OSError:
        status.update(returncode=1, error='fixture_io_failed')
    finally:
        try:
            cleanup = capture(['docker', 'rm', '-f', name], timeout=30)
            status['cleanup_success'] = cleanup.returncode == 0 and not cleanup.timed_out
        except OSError:
            status['cleanup_success'] = False
        if not status['cleanup_success']:
            status['returncode'] = 1
            status.setdefault('error', 'container_cleanup_failed')
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--family", choices=[entry["family"] for entry in MATRIX["images"]], action="append")
    parser.add_argument("--jobs", type=int, default=3)
    parser.add_argument("--output", type=Path, default=ROOT / "_tmp/host-platform")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    selected = [entry for entry in MATRIX["images"] if not args.family or entry["family"] in args.family]
    cancellation = threading.Event()
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(args.jobs, 7)))
    futures = []
    try:
        for entry in selected:
            futures.append(executor.submit(check, entry, args.output, cancellation))
        results = [future.result() for future in futures]
    except BaseException:
        cancellation.set()
        for future in futures:
            future.cancel()
        raise
    finally:
        executor.shutdown(wait=True, cancel_futures=True)
    (args.output / "results.json").write_text(json.dumps({"scope": MATRIX["scope"], "verified_at": MATRIX["verified_at"], "results": results}, indent=2) + "\n")
    for result in results:
        print(f"{result['family']}: {'PASS' if result['returncode'] == 0 else 'FAIL'}")
    return 1 if any(result["returncode"] for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
