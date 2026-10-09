"""Private CI outputs: descriptor-relative paths beneath the checkout's _tmp."""
import os
import secrets
import stat
from scripts.ci import verify_candidate as v

MAX_REPORT = 16 * 1024 * 1024
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def checked(info, directory=False):
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    v.require(kind(info.st_mode) and info.st_uid in (0, os.geteuid())
              and not info.st_mode & 0o022 and (directory or info.st_nlink == 1),
              'evidence_output_metadata')


def child_directory(parent, name, exclusive=False):
    try:
        os.mkdir(name, mode=0o700, dir_fd=parent)
    except FileExistsError:
        v.require(not exclusive, 'evidence_output_exists')
    descriptor = os.open(name, DIRECTORY_FLAGS, dir_fd=parent)
    try:
        checked(os.fstat(descriptor), directory=True)
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def descend(parts, exclusive=False):
    descriptor = os.open('.', DIRECTORY_FLAGS)
    try:
        checked(os.fstat(descriptor), directory=True)
        for index, name in enumerate(parts):
            child = child_directory(descriptor, name, exclusive and index == len(parts) - 1)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def existing_file(parent, name):
    try:
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return None
    checked(info)
    return info.st_dev, info.st_ino


def atomic_file(parent, name, data):
    identity = existing_file(parent, name)
    temporary = '.evidence-' + secrets.token_hex(16)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                         | os.O_CLOEXEC, 0o600, dir_fd=parent)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        v.require(existing_file(parent, name) == identity, 'evidence_output_changed')
        os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass


class Output:
    """Closed authority shared by producer and exact Sonar gate CLI outputs."""
    def __init__(self, path):
        name = v.safe_path(str(path))
        self.parts = name.split('/')
        v.require(len(self.parts) >= 2 and self.parts[0] == '_tmp', 'evidence_output_path')

    def write_file(self, data):
        v.require(isinstance(data, bytes) and len(data) <= MAX_REPORT, 'evidence_output_size')
        try:
            parent = descend(self.parts[:-1])
            try:
                atomic_file(parent, self.parts[-1], data)
            finally:
                os.close(parent)
        except OSError:
            raise v.VerificationError('evidence_output_io') from None

    def write_tree(self, files):
        v.require(isinstance(files, dict) and 0 < len(files) <= 10000, 'evidence_output_count')
        for name, data in files.items():
            v.safe_path(name)
            v.require(isinstance(data, bytes) and len(data) <= v.MAX_FILE, 'evidence_output_size')
        v.require(sum(map(len, files.values())) <= v.MAX_BUNDLE, 'evidence_output_size')
        try:
            root = descend(self.parts, exclusive=True)
            try:
                for name, data in files.items():
                    parts = name.split('/')
                    parent = os.dup(root)
                    try:
                        for part in parts[:-1]:
                            child = child_directory(parent, part)
                            os.close(parent)
                            parent = child
                        atomic_file(parent, parts[-1], data)
                    finally:
                        os.close(parent)
            finally:
                os.close(root)
        except OSError:
            raise v.VerificationError('evidence_output_io') from None
