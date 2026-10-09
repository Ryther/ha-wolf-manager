"""Deterministic candidate packaging and closed publication identity policy.

Receipt claims are not independent authority. The protected verifier must still
verify the successful producer run, every required job and original artifact ZIP.
"""
from __future__ import annotations
import argparse
import gzip
import io
import json
import os
import re
import tomllib
from pathlib import Path
import tarfile
from scripts.ci import evidence_output as e, verify_candidate as v

REPOSITORY = 'Ryther/ha-wolf-manager'
IMAGE = 'ghcr.io/ryther/ha-wolf-manager'


OCI_BLOB_PREFIX = 'oci/blobs/sha256/'
ARCHIVE_SUFFIX = '.tar.gz'
IMAGE_FILE = 'image.json'


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def archive(entries):
    """Reproducible regular-file tar; source ownership/timestamps never leak."""
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode='wb', mtime=0, filename='') as compressed:
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as tar:
            for name, (data, mode) in sorted(entries.items()):
                v.safe_path(name)
                v.require(isinstance(data, bytes) and len(data) <= v.MAX_FILE
                          and type(mode) is int and (mode in (0o644, 0o755) or
                          (mode == 0o444 and name in v.HOST_LICENSES)), 'producer_entry')
                item = tarfile.TarInfo(name)
                item.size = len(data); item.mode = mode; item.mtime = 0
                item.uid = item.gid = 0; item.uname = item.gname = ''
                tar.addfile(item, io.BytesIO(data))
    return output.getvalue()


def merge_oci(inputs, version):
    """Author one deterministic index; preserve all platform graph bytes."""
    v.require(v.SEMVER.fullmatch(version) and len(inputs) == 2, 'producer_platform_count')
    files = {'oci/oci-layout': encoded({'imageLayoutVersion': '1.0.0'})}
    platforms = {}
    for layout in inputs:
        v.require(layout.get('oci-layout') is not None and
                  v.json_bytes(layout['oci-layout']) == {'imageLayoutVersion': '1.0.0'}, 'producer_layout')
        for name, data in layout.items():
            v.safe_path(name)
            if name.startswith('blobs/sha256/'):
                digest = name[len('blobs/sha256/'):]
                v.require(v.HEX64.fullmatch(digest) and v.sha256(data) == digest, 'producer_blob')
                target = 'oci/' + name
                v.require(target not in files or files[target] == data, 'producer_collision')
                files[target] = data
        root = v.json_bytes(layout['index.json'])
        descriptors = root.get('manifests', [])
        v.require(root.get('schemaVersion') == 2 and len(descriptors) == 1, 'producer_root')
        descriptor = descriptors[0]
        # Buildx exports either a direct manifest or a single-platform index.
        if descriptor.get('mediaType') == v.INDEX_TYPE:
            child = v.json_bytes(files[OCI_BLOB_PREFIX + v.parse_digest(descriptor.get('digest'))])
            v.require(len(child.get('manifests', [])) == 1, 'producer_attestation_or_extra_platform')
            descriptor = child['manifests'][0]
        v.require(descriptor.get('mediaType') == v.MANIFEST_TYPE, 'producer_manifest_type')
        raw = files.get(OCI_BLOB_PREFIX + v.parse_digest(descriptor.get('digest')))
        v.require(raw is not None and len(raw) == descriptor.get('size'), 'producer_manifest_digest')
        manifest = v.json_bytes(raw)
        config_descriptor = manifest.get('config', {})
        config = v.json_bytes(files[OCI_BLOB_PREFIX + v.parse_digest(config_descriptor.get('digest'))])
        architecture = config.get('architecture')
        v.require(config.get('os') == 'linux' and architecture in ('amd64', 'arm64')
                  and architecture not in platforms, 'producer_platform')
        descriptor = {key: descriptor[key] for key in ('mediaType', 'digest', 'size')}
        descriptor['platform'] = {'os': 'linux', 'architecture': architecture}
        platforms[architecture] = descriptor
    index = encoded({'schemaVersion': 2, 'mediaType': v.INDEX_TYPE,
                     'manifests': [platforms[a] for a in sorted(platforms)]})
    digest = v.sha256(index)
    files[OCI_BLOB_PREFIX + digest] = index
    files['oci/index.json'] = encoded({'schemaVersion': 2, 'manifests': [
        {'mediaType': v.INDEX_TYPE, 'digest': 'sha256:' + digest, 'size': len(index)}]})
    image = {'repository': IMAGE, 'tag': version, 'index_digest': 'sha256:' + digest,
             'platforms': [{'os': 'linux', 'architecture': a, 'digest': platforms[a]['digest']}
                           for a in sorted(platforms)]}
    v.verify_oci(files, image)
    return files, image


def receipt(files, reports, image, expected, artifact):
    expected.validate()
    v.require(set(reports) == v.REQUIRED_CHECKS, 'producer_required_checks')
    v.require(v.positive_int(artifact.get('id')) and
              artifact.get('name') == 'release-candidate-' + expected.candidate_sha and
              isinstance(artifact.get('digest'), str), 'producer_artifact')
    digest = v.parse_digest(artifact['digest'])
    asset_names = ['wolf-manager-host-v' + expected.version + '-' + triple + ARCHIVE_SUFFIX
                   for triple in sorted(v.TRIPLES)]
    asset_names += ['ha-wolf-manager-installer-v' + expected.version + ARCHIVE_SUFFIX, 'SHA256SUMS']
    checks = []
    for name, report in sorted(reports.items()):
        v.require(report.get('candidate_sha') == expected.candidate_sha and
                  report.get('result') == 'success' and isinstance(report.get('scope'), str)
                  and bool(report['scope']), 'producer_check')
        evidence = 'evidence/' + name + '.json'
        v.require(evidence in files and len(files[evidence]) > 0, 'producer_evidence')
        checks.append({'name': name, 'result': 'success', 'candidate_sha': expected.candidate_sha,
                       'scope': report['scope'], 'evidence_location':
                       'artifact:' + str(artifact['id']) + '/' + evidence})
    assets = []
    for name in sorted(asset_names):
        data = files[name]
        assets.append({'name': name, 'download_url': 'https://api.github.com/repos/' + REPOSITORY +
                       '/actions/artifacts/' + str(artifact['id']) + '/zip', 'sha256': v.sha256(data),
                       'size_bytes': len(data), 'workflow_artifact_id': artifact['id'],
                       'workflow_artifact_sha256': digest})
    result = {'schema_version': 1, 'candidate_sha': expected.candidate_sha,
              'version': expected.version, 'workflow_run_id': expected.run_id,
              'source_repository': REPOSITORY, 'target_triples': sorted(v.TRIPLES),
              'checks': checks, 'assets': assets, 'image': image,
              'addon': {'slug': 'ha_wolf_manager', 'version': expected.version,
                        'image_reference': IMAGE + ':' + expected.version}, 'publication_state': 'draft'}
    v.receipt_identity(result, expected)
    return result


def publisher_identity(run, workflow_id, workflow_path):
    v.require(isinstance(run, dict) and run.get('event') in ('push', 'workflow_dispatch')
              and run.get('head_branch') == 'main' and run.get('status') == 'completed'
              and run.get('conclusion') == 'success' and run.get('workflow_id') == workflow_id
              and run.get('path') in (workflow_path, workflow_path + '@main')
              and run.get('pull_requests') == [] and v.HEX40.fullmatch(run.get('head_sha', '')),
              'publisher_run')
    for field in ('repository', 'head_repository'):
        repo = run.get(field, {})
        v.require(repo.get('full_name') == REPOSITORY and repo.get('fork') is False
                  and v.positive_int(repo.get('id')), 'publisher_repository')
    v.require(run['repository']['id'] == run['head_repository']['id'], 'publisher_fork')
    return run['head_sha']


def release_identity(release, version, candidate_sha, tag_sha):
    v.require(v.SEMVER.fullmatch(version) and v.HEX40.fullmatch(candidate_sha)
              and tag_sha == candidate_sha and release.get('draft') is True
              and release.get('prerelease') is False and release.get('tag_name') == 'v' + version
              and v.positive_int(release.get('id')), 'publisher_release')
    canonical = 'https://uploads.github.com/repos/' + REPOSITORY + '/releases/' + str(release['id']) + '/assets{?name,label}'
    v.require(release.get('upload_url') == canonical, 'publisher_upload_origin')
    return release['id']


def sonar_identity(analysis, gate, candidate_sha):
    v.require(isinstance(analysis.get('key'), str) and bool(analysis['key'])
              and analysis.get('revision') == candidate_sha
              and gate.get('projectStatus', {}).get('status') == 'OK', 'sonar_candidate_gate')
    return True


def read_tree(path):
    result = {}
    for item in sorted(path.rglob('*')):
        v.require(not item.is_symlink(), 'producer_symlink')
        if item.is_file():
            name = item.relative_to(path).as_posix(); v.safe_path(name)
            v.require(item.stat().st_size <= v.MAX_FILE, 'producer_size')
            result[name] = item.read_bytes()
    return result


def write_tree(path, files):
    if isinstance(path, e.Output):
        path.write_tree(files)
        return
    path.mkdir(parents=True, exist_ok=False)
    for name, data in files.items():
        v.safe_path(name)
        target = path / name; target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def metadata(root):
    version = (root / 'version.txt').read_text().strip()
    v.require(v.SEMVER.fullmatch(version), 'coordinated_version')
    cargo = tomllib.loads((root / 'Cargo.toml').read_text())
    package = v.json_bytes((root / 'package.json').read_bytes())
    v.require(cargo['workspace']['package']['version'] == version and package['version'] == version,
              'coordinated_version')
    lock = tomllib.loads((root / 'Cargo.lock').read_text())
    own = {'wolf-core', 'ha-wolf-manager', 'wolf-manager-host'}
    packages = [entry for entry in lock['package'] if entry['name'] in own and 'source' not in entry]
    v.require({entry['name'] for entry in packages} == own and
              all(entry['version'] == version for entry in packages), 'coordinated_lock')
    # Closed scalar checks complement the native Supervisor schema release gate.
    addon = (root / 'wolf_manager/config.yaml').read_text()
    for key, value in [('version', version), ('slug', 'ha_wolf_manager'), ('image', IMAGE)]:
        matches = re.findall(r'^' + key + r':\s*([^\n]+)$', addon, re.MULTILINE)
        v.require(matches == [value], 'coordinated_addon')
    v.require(re.search(r'^ingress_port: 8099$', addon, re.MULTILINE) and
              re.search(r'^init: false$', addon, re.MULTILINE), 'addon_runtime')
    return version


def assemble(root, amd64, arm64, output):
    version = metadata(root)
    platforms = [read_tree(amd64 / 'oci'), read_tree(arm64 / 'oci')]
    files, image = merge_oci(platforms, version)
    licenses = {'licenses/HA-Wolf-Manager.txt': ((root / 'LICENSE').read_bytes(), 0o444),
                'licenses/rumqttc.txt': ((root / 'vendor/rumqttc/LICENSE').read_bytes(), 0o444)}
    for path, triple in [(amd64, 'x86_64-unknown-linux-musl'), (arm64, 'aarch64-unknown-linux-musl')]:
        data = (path / 'wolf-manager-host').read_bytes()
        # Validate static binary and archive before it becomes a release subject.
        content = archive({'bin/wolf-manager-host': (data, 0o755), **licenses})
        v.inspect_tar(content, v.TRIPLES[triple])
        files['wolf-manager-host-v' + version + '-' + triple + ARCHIVE_SUFFIX] = content
    entries = {'install.sh': ((root / 'installer/install.sh').read_bytes(), 0o755)}
    for name, data in read_tree(root / 'installer/templates').items():
        entries['installer/templates/' + name] = (data, 0o644)
    content = archive(entries); v.inspect_tar(content, None)
    files['ha-wolf-manager-installer-v' + version + ARCHIVE_SUFFIX] = content
    files['SHA256SUMS'] = ''.join(v.sha256(data) + '  ' + name + '\n'
                                for name, data in sorted(files.items()) if name.endswith(ARCHIVE_SUFFIX)).encode()
    files[IMAGE_FILE] = encoded(image)
    write_tree(output, files)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    merge = commands.add_parser('merge')
    merge.add_argument('--amd64', type=Path, required=True); merge.add_argument('--arm64', type=Path, required=True)
    merge.add_argument('--version', required=True); merge.add_argument('--output', type=Path, required=True)
    report = commands.add_parser('report')
    report.add_argument('--name', choices=sorted(v.REQUIRED_CHECKS), required=True)
    report.add_argument('--sha', required=True); report.add_argument('--scope', required=True)
    report.add_argument('--output', type=Path, required=True)
    commands.add_parser('metadata')
    bundle = commands.add_parser('assemble')
    bundle.add_argument('--amd64', type=Path, required=True); bundle.add_argument('--arm64', type=Path, required=True)
    bundle.add_argument('--output', type=Path, required=True)
    finalize = commands.add_parser('finalize')
    finalize.add_argument('--bundle', type=Path, required=True); finalize.add_argument('--artifact', type=Path, required=True)
    finalize.add_argument('--sha', required=True); finalize.add_argument('--run-id', type=int, required=True)
    finalize.add_argument('--workflow-id', type=int); finalize.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'metadata':
        print(metadata(Path.cwd()))
        return
    output = e.Output(args.output)
    if args.command == 'merge':
        files, image = merge_oci([read_tree(args.amd64), read_tree(args.arm64)], args.version)
        files[IMAGE_FILE] = encoded(image)
        output.write_tree(files)
    elif args.command == 'report':
        v.require(v.HEX40.fullmatch(args.sha), 'producer_sha')
        output.write_file(encoded({'candidate_sha': args.sha, 'result': 'success', 'scope': args.scope}))
    elif args.command == 'assemble':
        assemble(Path.cwd(), args.amd64, args.arm64, output)
    else:
        files = read_tree(args.bundle)
        reports = {name: v.json_bytes(files['evidence/' + name + '.json']) for name in v.REQUIRED_CHECKS}
        workflow_id = args.workflow_id
        if workflow_id is None:
            authority = v.GitHubAuthority(REPOSITORY, os.environ['GITHUB_TOKEN'])
            run = authority.get_json('/repos/' + REPOSITORY + '/actions/runs/' + str(args.run_id))
            v.require(run.get('id') == args.run_id and run.get('head_sha') == args.sha
                      and run.get('head_branch') == 'main' and run.get('event') in ('push', 'workflow_dispatch')
                      and run.get('path') in ('.github/workflows/candidate.yaml', '.github/workflows/candidate.yaml@main'),
                      'producer_run_identity')
            workflow_id = run['workflow_id']
        expected = v.Expectations(REPOSITORY, args.sha, metadata(Path.cwd()), args.run_id,
                                  workflow_id, '.github/workflows/candidate.yaml')
        result = receipt(files, reports, v.json_bytes(files[IMAGE_FILE]), expected,
                         v.json_bytes(args.artifact.read_bytes()))
        output.write_file(encoded(result))


if __name__ == '__main__':
    main()
