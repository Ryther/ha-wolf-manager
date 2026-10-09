"""Pinned CI-only ORAS transfer of original OCI bytes to one digest destination."""
from contextlib import contextmanager
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from scripts.ci import fetch_tool, verify_candidate as v

BINARY = Path('_tmp/tools/oras')
BINARY_SHA256 = '246c47e91bf2749a555ffe00a9824844c6df3a26d61974e3ce08f2077d79c556'
REPOSITORY = 'ghcr.io/ryther/ha-wolf-manager'
MAX_BINARY_BYTES = 64 * 1024 * 1024
TOOL_IDENTITY = 'oci_tool_identity'
OCI_PATH = re.compile(r'oci/(?:index\.json|oci-layout|blobs/sha256/[0-9a-f]{64})')


def open_binary():
    try:
        try:
            fd = os.open(BINARY, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            fetch_tool.install('oras', BINARY)
            fd = os.open(BINARY, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise v.VerificationError(TOOL_IDENTITY) from None
    try:
        info = os.fstat(fd)
        v.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                  and info.st_uid == os.geteuid() and not info.st_mode & 0o022
                  and info.st_mode & 0o111 and 0 < info.st_size <= MAX_BINARY_BYTES,
                  TOOL_IDENTITY)
        with os.fdopen(fd, 'rb', closefd=False) as file:
            raw = file.read(MAX_BINARY_BYTES + 1)
        v.require(len(raw) == info.st_size and v.sha256(raw) == BINARY_SHA256, TOOL_IDENTITY)
        return fd
    except BaseException:
        os.close(fd)
        raise


@contextmanager
def verified_binary():
    fd = open_binary()
    try:
        yield fd
    finally:
        os.close(fd)


def _run(binary_fd, arguments, *, config, stdin=None, timeout, phase):
    failures = {'login': 'oci_login_failed', 'copy': 'oci_copy_failed'}
    v.require(phase in failures, 'oci_phase')
    try:
        result = subprocess.run(['/proc/self/fd/' + str(binary_fd), *arguments],
            input=stdin, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={'HOME': str(config.parent), 'PATH': '/usr/bin:/bin'},
            pass_fds=(binary_fd,), timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise v.VerificationError('oci_timeout') from None
    except OSError:
        raise v.VerificationError('oci_unavailable') from None
    v.require(result.returncode == 0, failures[phase])


def write_layout(files, layout):
    for name, data in files.items():
        if not name.startswith('oci/'):
            continue
        v.require(OCI_PATH.fullmatch(name) is not None, 'oci_layout_path')
        destination = layout / name.removeprefix('oci/')
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with destination.open('xb') as file:
            file.write(data)
        destination.chmod(0o600)


def transfer(files, image, actor, token):
    v.require(image['repository'] == REPOSITORY and v.SEMVER.fullmatch(image['tag']), 'oci_subject')
    v.verify_oci(files, image)
    v.require(isinstance(actor, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}(?:\[bot\])?', actor)
              and isinstance(token, str) and 0 < len(token) <= 65536, 'oci_credentials')
    with tempfile.TemporaryDirectory(prefix='wolf-oci-') as directory, verified_binary() as fd:
        private = Path(directory)
        private.chmod(0o700)
        config = private / 'config.json'
        config.write_bytes(b'{"auths":{}}')
        config.chmod(0o600)
        layout = private / 'layout'
        write_layout(files, layout)
        _run(fd, ['login', '--registry-config', str(config), '--username', actor,
                  '--password-stdin', 'ghcr.io'], config=config, stdin=token.encode(),
             timeout=60, phase='login')
        v.require(config.is_file() and not config.is_symlink()
                  and config.stat().st_mode & 0o777 == 0o600, 'oci_credentials')
        _run(fd, ['cp', '--from-oci-layout', '--to-registry-config', str(config),
                  str(layout) + '@' + image['index_digest'], REPOSITORY + '@' + image['index_digest']],
             config=config, timeout=600, phase='copy')
    return image['index_digest']
