"""Bind each quality job to the same frozen candidate subject bytes."""
import argparse
from pathlib import Path
import subprocess
from scripts.ci import producer as p
from scripts.ci import verify_candidate as v


def verify(path, sha, checkout=True):
    v.require(v.HEX40.fullmatch(sha), 'subject_sha')
    if checkout:
        actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
        v.require(actual == sha, 'subject_checkout')
    files = p.read_tree(path)
    subject = v.json_bytes(files['subject.json'])
    v.require(subject.get('candidate_sha') == sha and v.SEMVER.fullmatch(subject.get('version', '')),
              'subject_identity')
    expected = subject.get('files')
    v.require(isinstance(expected, dict) and set(expected) == set(files) - {'subject.json'}, 'subject_files')
    for name, digest in expected.items():
        v.safe_path(name); v.require(v.sha256(files[name]) == digest, 'subject_digest')
    image = v.json_bytes(files['image.json']); v.verify_oci(files, image)
    version = subject['version']
    archives = {}
    for triple, machine in v.TRIPLES.items():
        name = 'wolf-manager-host-v' + version + '-' + triple + '.tar.gz'
        v.inspect_tar(files[name], machine); archives[name] = files[name]
    name = 'ha-wolf-manager-installer-v' + version + '.tar.gz'
    v.inspect_tar(files[name], None); archives[name] = files[name]
    sums = ''.join(v.sha256(data) + '  ' + name + '\n' for name, data in sorted(archives.items())).encode()
    v.require(files['SHA256SUMS'] == sums, 'subject_checksums')
    return {'candidate_sha': sha, 'version': version, 'image_index_digest': image['index_digest'],
            'subject_manifest_sha256': v.sha256(files['subject.json']),
            'checksums_sha256': v.sha256(sums)}


def seal(path, sha):
    v.require(v.HEX40.fullmatch(sha), 'subject_sha')
    files = p.read_tree(path)
    v.require('subject.json' not in files, 'subject_already_sealed')
    (path / 'subject.json').write_bytes(p.encoded({'candidate_sha': sha,
        'version': p.metadata(Path.cwd()), 'files': {name: v.sha256(data) for name, data in sorted(files.items())}}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True); parser.add_argument('--sha', required=True)
    parser.add_argument('--seal', action='store_true'); args = parser.parse_args()
    if args.seal: seal(args.bundle, args.sha)
    else: print(p.encoded(verify(args.bundle, args.sha)).decode())
