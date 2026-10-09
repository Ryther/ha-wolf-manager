"""Fetch an allowlisted CI tool release and verify its pinned upstream checksum."""
import io
import argparse
from pathlib import Path
import tarfile
import urllib.request
from scripts.ci import verify_candidate as v

TOOLS = {
    'oras': ('https://github.com/oras-project/oras/releases/download/v1.3.4/oras_1.3.4_linux_amd64.tar.gz',
             'f27adb935022d94df8dc77719c322dda592c78a0d57a6f7dcdd8d900b248c454'),
    'gitleaks': ('https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz',
                 '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb'),
    'actionlint': ('https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz',
                   '8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8'),
}


def install(name, output):
    url, sha = TOOLS[name]
    # No credential is supplied; GitHub's public release CDN redirect is allowed.
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(32 * 1024 * 1024)
    v.require(v.sha256(data) == sha, 'scanner_checksum')
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        members = archive.getmembers()
        binaries = [m for m in members if m.name == name]
        v.require(len(binaries) == 1 and binaries[0].isfile() and binaries[0].size < 64*1024*1024,
                  'scanner_archive')
        binary = archive.extractfile(binaries[0]).read()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('xb') as file: file.write(binary)
    output.chmod(0o755)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('name', nargs='?', choices=sorted(TOOLS), default='gitleaks')
    args = parser.parse_args()
    install(args.name, Path('_tmp/tools') / args.name)
