"""Trusted candidate gate. No extraction, execution, rebuilding or publication.

Call only from a protected publisher revision with independently supplied
Expectations. Receipt claims and candidate scripts are never authority.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import tarfile
import urllib.error
import urllib.request
import zipfile
import zlib

REQUIRED_CHECKS = frozenset((
    'rust', 'auth-ingress', 'ssh-policy', 'persistence', 'mqtt', 'lifecycle',
    'ui', 'distro-containers', 'static-amd64', 'static-arm64', 'addon-schema',
    'codeql', 'secrets', 'cargo-audit', 'image-scan-amd64', 'image-scan-arm64', 'sonar', 'docs', 'workflow-lint', 'commits',
))
CI_WORKFLOW = '.github/workflows/ci.yaml'
AUTHORITATIVE_JOBS = {name: 'tests / ' + name for name in REQUIRED_CHECKS}
AUTHORITATIVE_JOBS.update(codeql='codeql / codeql', sonar='sonar / Sonar Cloud',
                          commits='commits / Conventional Commits')
TRIPLES = {'x86_64-unknown-linux-musl': 62, 'aarch64-unknown-linux-musl': 183}
HOST_LICENSES = frozenset({'licenses/HA-Wolf-Manager.txt', 'licenses/rumqttc.txt'})
HEX64 = re.compile(r'[\da-f]{64}\Z', re.ASCII)
HEX40 = re.compile(r'[\da-f]{40}\Z', re.ASCII)
SEMVER = re.compile(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)\Z', re.ASCII)
MAX_FILE = 256 * 1024 * 1024
MAX_BUNDLE = 1024 * 1024 * 1024
INDEX_TYPE = 'application/vnd.oci.image.index.v1+json'
MANIFEST_TYPE = 'application/vnd.oci.image.manifest.v1+json'


class VerificationError(ValueError):
    """Safe, stable refusal code; never forward a token or raw API error."""


ARCHIVE_SUFFIX = '.tar.gz'
def require(condition, code):
    if not condition:
        raise VerificationError(code)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def positive_int(value):
    return type(value) is int and value > 0


def json_bytes(data):
    require(isinstance(data, bytes) and len(data) <= 8 * 1024 * 1024, 'json_size')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate_json_key')
            result[key] = value
        return result
    def constant(_):
        raise VerificationError('non_finite_json')
    try:
        return json.loads(data, object_pairs_hook=unique, parse_constant=constant)
    except ValueError as error:
        if isinstance(error, VerificationError):
            raise
        raise VerificationError('malformed_json') from None


def shape(value, keys, code):
    require(isinstance(value, dict) and set(value) == set(keys.split()), code)


def safe_path(name):
    require(isinstance(name, str) and bool(name) and len(name) <= 1024
            and '\\' not in name and not any(ord(c)<32 or ord(c)==127 for c in name), 'archive_path')
    parts = name.rstrip('/').split('/')
    require(all(part not in ('', '.', '..') for part in parts)
            and not PurePosixPath(name).is_absolute()
            and ':' not in parts[0], 'archive_path')
    return '/'.join(parts)


@dataclass(frozen=True)
class Expectations:
    repository: str
    candidate_sha: str
    version: str
    run_id: int
    workflow_id: int
    workflow_path: str
    branch: str = 'main'
    event: str = 'push'

    def validate(self):
        require(self.repository == 'Ryther/ha-wolf-manager', 'trusted_repository')
        require(isinstance(self.candidate_sha, str) and HEX40.fullmatch(self.candidate_sha), 'trusted_sha')
        require(isinstance(self.version, str) and SEMVER.fullmatch(self.version), 'trusted_version')
        require(positive_int(self.run_id) and positive_int(self.workflow_id), 'trusted_run')
        require(self.workflow_path == CI_WORKFLOW, 'trusted_workflow')
        require(self.event in ('push', 'workflow_dispatch') and self.branch == 'main', 'trusted_event')


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        # Do not forward API credentials to an artifact CDN or another origin.
        raise VerificationError('api_redirect_refused')


class GitHubAuthority:
    """Read-only primary API authority, bound to a protected repository."""
    def __init__(self, repository, token):
        require(repository == 'Ryther/ha-wolf-manager' and isinstance(token, str)
                and token and '\r' not in token and '\n' not in token, 'authority_configuration')
        self.prefix = '/repos/' + repository + '/'
        self.token = token
        self.opener = urllib.request.build_opener(_NoRedirect)

    def get_json(self, path):
        require(isinstance(path, str) and path.startswith(self.prefix)
                and not any(c in path for c in ('\r', '\n', '\\', '#'))
                and '..' not in path, 'authority_path')
        request = urllib.request.Request('https://api.github.com' + path, headers={
            'Accept': 'application/vnd.github+json',
            'Authorization': 'Bearer ' + self.token,
            'X-GitHub-Api-Version': '2026-03-10',
            'User-Agent': 'ha-wolf-manager-trusted-verifier',
        })
        try:
            with self.opener.open(request, timeout=30) as response:
                require(response.status == 200, 'authority_http_status')
                data = response.read(8 * 1024 * 1024 + 1)
            return json_bytes(data)
        except OSError:
            raise VerificationError('authority_unavailable') from None


def verify_jobs(jobs, expected, attempt):
    names = {}
    ids = set()
    for job in jobs:
        require(isinstance(job, dict) and isinstance(job.get('name'), str)
                and positive_int(job.get('id')) and job['id'] not in ids
                and job['name'] not in names, 'duplicate_jobs')
        names[job['name']] = job
        ids.add(job['id'])
    required_names = set(AUTHORITATIVE_JOBS.values())
    semantic_aliases = REQUIRED_CHECKS | {name.rsplit(' / ', 1)[-1] for name in required_names}
    for name in names:
        require(name in required_names or name.rsplit(' / ', 1)[-1] not in semantic_aliases,
                'ambiguous_authoritative_check')
    require(required_names <= names.keys(), 'missing_authoritative_check')
    for name in required_names:
        job = names[name]
        require(job.get('run_id') == expected.run_id and job.get('head_sha') == expected.candidate_sha
                and positive_int(job.get('run_attempt')) and job['run_attempt'] == attempt
                and job.get('status') == 'completed' and job.get('conclusion') == 'success', 'failed_authoritative_check')


def authority_evidence(authority, expected):
    prefix = '/repos/' + expected.repository
    run = authority.get_json(prefix + '/actions/runs/' + str(expected.run_id))
    require(isinstance(run, dict), 'authority_run')
    require(run.get('id') == expected.run_id and run.get('workflow_id') == expected.workflow_id
            and run.get('head_sha') == expected.candidate_sha
            and run.get('head_branch') == expected.branch and run.get('event') == expected.event
            and run.get('status') == 'completed' and run.get('conclusion') == 'success'
            and run.get('path') in (expected.workflow_path, expected.workflow_path + '@' + expected.branch)
            and run.get('pull_requests') == [], 'untrusted_run')
    for field in ('repository', 'head_repository'):
        repo = run.get(field)
        require(isinstance(repo, dict) and repo.get('full_name') == expected.repository
                and repo.get('fork') is False and positive_int(repo.get('id')), 'fork_or_repository')
    require(run['repository']['id'] == run['head_repository']['id'], 'fork_or_repository')
    attempt = run.get('run_attempt')
    require(positive_int(attempt), 'run_attempt')
    workflow = authority.get_json(prefix + '/actions/workflows/' + str(expected.workflow_id))
    require(isinstance(workflow, dict) and workflow.get('id') == expected.workflow_id
            and workflow.get('path') == expected.workflow_path and workflow.get('state') == 'active', 'workflow_authority')
    jobs = []
    total = None
    for page in range(1, 21):
        data = authority.get_json(prefix + f'/actions/runs/{expected.run_id}/attempts/{attempt}/jobs?per_page=100&page={page}')
        require(isinstance(data, dict) and type(data.get('total_count')) is int
                and 0 <= data['total_count'] <= 2000 and isinstance(data.get('jobs'), list), 'jobs_authority')
        if total is None:
            total = data['total_count']
        require(total == data['total_count'], 'changing_job_evidence')
        jobs.extend(data['jobs'])
        require(len(jobs) <= total, 'duplicate_job_page')
        if len(jobs) == total:
            break
        require(bool(data['jobs']), 'incomplete_job_evidence')
    require(len(jobs) == total, 'incomplete_job_evidence')
    verify_jobs(jobs, expected, attempt)
    latest = authority.get_json(prefix + '/actions/runs/' + str(expected.run_id))
    require(isinstance(latest, dict) and latest == run, 'changing_run_evidence')
    return run, workflow, jobs


def receipt_identity(receipt, expected):
    shape(receipt, 'schema_version candidate_sha version workflow_run_id source_repository target_triples checks assets image addon publication_state', 'receipt_shape')
    require(type(receipt['schema_version']) is int and receipt['schema_version'] == 1
            and receipt['candidate_sha'] == expected.candidate_sha and receipt['version'] == expected.version
            and type(receipt['workflow_run_id']) is int and receipt['workflow_run_id'] == expected.run_id
            and receipt['source_repository'] == expected.repository, 'receipt_identity')
    triples = receipt['target_triples']
    require(isinstance(triples, list) and len(triples) == 2 and all(isinstance(v, str) for v in triples)
            and set(triples) == set(TRIPLES), 'target_triples')
    checks = receipt['checks']
    require(isinstance(checks, list) and len(checks) == len(REQUIRED_CHECKS), 'receipt_checks')
    names = set()
    for check in checks:
        shape(check, 'name result candidate_sha scope evidence_location', 'check_shape')
        name = check['name']
        require(isinstance(name, str) and name in REQUIRED_CHECKS and name not in names
                and check['result'] == 'success' and check['candidate_sha'] == expected.candidate_sha, 'receipt_checks')
        for key, limit in (('scope', 256), ('evidence_location', 2048)):
            require(isinstance(check[key], str) and 0 < len(check[key]) <= limit
                    and not any(c in check[key] for c in ('\x00', '\r', '\n')), 'check_evidence')
        names.add(name)
    require(receipt['publication_state'] in ('draft', 'published'), 'publication_state')
    shape(receipt['addon'], 'slug version image_reference', 'addon_shape')
    require(receipt['addon'] == {'slug': 'ha_wolf_manager', 'version': expected.version,
            'image_reference': 'ghcr.io/ryther/ha-wolf-manager:' + expected.version}, 'addon_identity')
    shape(receipt['image'], 'repository tag index_digest platforms', 'image_shape')
    image = receipt['image']
    require(image['repository'] == 'ghcr.io/ryther/ha-wolf-manager' and image['tag'] == expected.version, 'image_identity')
    parse_digest(image['index_digest'])
    require(isinstance(image['platforms'], list) and len(image['platforms']) == 2, 'image_platforms')
    architectures = set()
    for platform in image['platforms']:
        shape(platform, 'os architecture digest', 'platform_shape')
        require(platform['os'] == 'linux' and platform['architecture'] in ('amd64', 'arm64')
                and platform['architecture'] not in architectures, 'image_platforms')
        architectures.add(platform['architecture'])
        parse_digest(platform['digest'])


def parse_digest(value):
    require(isinstance(value, str) and value.startswith('sha256:') and HEX64.fullmatch(value[7:]), 'digest_format')
    return value[7:]


def bundle_files(path):
    require(isinstance(path, (str, Path)), 'artifact_path')
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_BUNDLE, 'artifact_file')
    raw = path.read_bytes()
    files = {}
    total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as bundle:
            entries = bundle.infolist()
            require(len(entries) <= 10000, 'bundle_entry_limit')
            names = set()
            for entry in entries:
                name = safe_path(entry.filename)
                require(name not in names, 'duplicate_archive_entry')
                names.add(name)
                kind = stat.S_IFMT(entry.external_attr >> 16)
                require(kind in (0, stat.S_IFREG, stat.S_IFDIR) and not entry.flag_bits & 1, 'zip_special_entry')
                require(entry.file_size <= MAX_FILE, 'archive_size')
                total += entry.file_size
                require(total <= MAX_BUNDLE, 'archive_size')
                if entry.is_dir():
                    require(kind in (0, stat.S_IFDIR) and entry.file_size == 0, 'zip_directory')
                else:
                    require(kind in (0, stat.S_IFREG), 'zip_special_entry')
                    data = bundle.read(entry)
                    require(len(data) == entry.file_size, 'zip_size')
                    files[name] = data
    except (zipfile.BadZipFile, RuntimeError, OSError, zlib.error, lzma.LZMAError):
        raise VerificationError('malformed_bundle') from None
    return raw, files


def verify_dynamic_table(data, start, size):
    require(size % 16 == 0, 'elf_dynamic_table')
    terminated = False
    for cursor in range(start, start + size, 16):
        tag, _ = struct.unpack('<QQ', data[cursor:cursor+16])
        require(tag != 1, 'elf_dynamic_dependency')
        if tag == 0:
            terminated = True
            break
    require(terminated, 'elf_dynamic_table')


def static_elf(data, machine):
    require(len(data) >= 64 and data[:7] == b'\x7fELF\x02\x01\x01', 'elf_format')
    values = struct.unpack('<16sHHIQQQIHHHHHH', data[:64])
    require(values[1] in (2, 3) and values[2] == machine and values[3] == 1
            and values[8] == 64 and values[9] == 56 and 0 < values[10] <= 4096, 'elf_architecture')
    offset, count = values[5], values[10]
    require(offset >= 64 and offset + count * 56 <= len(data), 'elf_header_bounds')
    executable = False
    for i in range(count):
        kind, flags, start, _, _, size, memory, _ = struct.unpack('<IIQQQQQQ', data[offset+i*56:offset+(i+1)*56])
        require(kind != 3 and start + size <= len(data) and memory >= size, 'dynamic_or_malformed_elf')
        if kind == 2:
            verify_dynamic_table(data, start, size)
        if kind == 1 and flags & 1 and size:
            executable = True
    require(executable, 'elf_executable_segment')


def inspect_tar_file(archive, entry, name, binary_machine):
    executable = False
    template = False
    stream = archive.extractfile(entry)
    require(stream is not None, 'tar_file')
    content = stream.read(MAX_FILE + 1)
    require(len(content) == entry.size, 'tar_size')
    if binary_machine and name == 'bin/wolf-manager-host':
        require(entry.mode & 0o111, 'target_executable')
        static_elf(content, binary_machine)
        executable = True
    elif not binary_machine and name == 'install.sh':
        require(entry.mode & 0o111 and content.startswith(b'#!/bin/sh\n'), 'installer_executable')
        executable = True
    if name.startswith('installer/templates/'):
        template = True
    return executable, template


def validate_tar_target(entry, name, binary_machine):
    if binary_machine:
        require((name in ('bin', 'licenses') and entry.isdir()) or
                (name == 'bin/wolf-manager-host' and entry.isfile()) or
                (name in HOST_LICENSES and entry.isfile() and entry.mode == 0o444),
                'unsupported_host_entry')
    else:
        require(name in ('installer', 'installer/templates', 'install.sh') or name.startswith('installer/templates/') or name == 'installer/metadata.json', 'unsupported_installer_entry')


def inspect_tar(data, binary_machine=None):
    names = set()
    total = 0
    executable = False
    template = False
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r|gz') as archive:
            for entry in archive:
                name = safe_path(entry.name)
                require(name not in names and len(names) < 10000, 'duplicate_archive_entry')
                names.add(name)
                require(entry.isfile() or entry.isdir(), 'tar_special_entry')
                validate_tar_target(entry, name, binary_machine)
                require(entry.size <= MAX_FILE and entry.size >= 0 and not entry.mode & 0o6000, 'archive_size_or_mode')
                total += entry.size
                require(total <= MAX_BUNDLE, 'archive_size')
                if entry.isfile():
                    file_executable, file_template = inspect_tar_file(archive, entry, name, binary_machine)
                    executable |= file_executable
                    template |= file_template
    except (tarfile.TarError, OSError, EOFError):
        raise VerificationError('malformed_archive') from None
    require(executable and (binary_machine or template), 'archive_required_target')
    if binary_machine:
        require(HOST_LICENSES <= names, 'archive_required_licenses')


def verify_oci(files, image):
    require('oci/oci-layout' in files and 'oci/index.json' in files, 'missing_oci_layout')
    require(json_bytes(files['oci/oci-layout']) == {'imageLayoutVersion': '1.0.0'}, 'oci_layout_version')
    def blob(descriptor, media_type=None):
        require(isinstance(descriptor, dict) and 'urls' not in descriptor
                and positive_int(descriptor.get('size')), 'oci_descriptor')
        if media_type:
            require(descriptor.get('mediaType') == media_type, 'oci_media_type')
        digest = parse_digest(descriptor.get('digest'))
        data = files.get('oci/blobs/sha256/' + digest)
        require(data is not None and len(data) == descriptor['size'] and sha256(data) == digest, 'oci_blob_digest')
        return data
    layout_index = json_bytes(files['oci/index.json'])
    require(isinstance(layout_index, dict) and layout_index.get('schemaVersion') == 2
            and isinstance(layout_index.get('manifests'), list) and len(layout_index['manifests']) == 1, 'oci_root_index')
    root = layout_index['manifests'][0]
    require(root.get('digest') == image['index_digest'], 'oci_root_digest')
    index = json_bytes(blob(root, INDEX_TYPE))
    require(isinstance(index, dict) and index.get('schemaVersion') == 2 and index.get('mediaType') == INDEX_TYPE
            and isinstance(index.get('manifests'), list) and len(index['manifests']) == 2, 'oci_platform_index')
    expected = {p['architecture']: p['digest'] for p in image['platforms']}
    seen = set()
    for descriptor in index['manifests']:
        platform = descriptor.get('platform', {})
        require(platform.get('os') == 'linux' and platform.get('architecture') in expected, 'oci_platform')
        architecture = platform['architecture']
        require(architecture not in seen and descriptor.get('digest') == expected[architecture], 'oci_platform_digest')
        seen.add(architecture)
        manifest = json_bytes(blob(descriptor, MANIFEST_TYPE))
        require(isinstance(manifest, dict) and manifest.get('schemaVersion') == 2
                and manifest.get('mediaType') == MANIFEST_TYPE and isinstance(manifest.get('layers'), list), 'oci_manifest')
        config = json_bytes(blob(manifest.get('config'), 'application/vnd.oci.image.config.v1+json'))
        require(isinstance(config, dict) and config.get('os') == 'linux'
                and config.get('architecture') == architecture, 'oci_config_platform')
        for layer in manifest['layers']:
            require(layer.get('mediaType') in ('application/vnd.oci.image.layer.v1.tar',
                    'application/vnd.oci.image.layer.v1.tar+gzip', 'application/vnd.oci.image.layer.v1.tar+zstd'), 'oci_layer_type')
            blob(layer)


def select_candidate_artifact(authority, expected):
    selected = []
    total = None
    listed = []
    for page in range(1, 21):
        response = authority.get_json(f'/repos/{expected.repository}/actions/runs/{expected.run_id}/artifacts?per_page=100&page={page}')
        require(isinstance(response, dict) and type(response.get('total_count')) is int and 0 <= response['total_count'] <= 2000 and isinstance(response.get('artifacts'), list), 'artifact_list')
        if total is None: total = response['total_count']
        require(total == response['total_count'], 'changing_artifact_list')
        listed.extend(response['artifacts'])
        require(len(listed) <= total, 'duplicate_artifact_page')
        if len(listed) == total: break
        require(bool(response['artifacts']), 'incomplete_artifact_list')
    require(len(listed) == total, 'incomplete_artifact_list')
    for artifact in listed:
        require(isinstance(artifact, dict), 'artifact_list')
        if artifact.get('name') == 'release-candidate-' + expected.candidate_sha:
            selected.append(artifact)
    require(len(selected) == 1 and positive_int(selected[0].get('id')), 'candidate_artifact_authority')
    return selected[0]


def authenticate_bundle(artifact_id, path, authority, expected, selected, run):
    raw, files = bundle_files(path)
    info = authority.get_json(f'/repos/{expected.repository}/actions/artifacts/{artifact_id}')
    require(isinstance(info, dict) and info.get('id') == artifact_id and info.get('expired') is False
            and info.get('name') == 'release-candidate-'+expected.candidate_sha
            and info.get('digest') == selected.get('digest') == 'sha256:'+sha256(raw)
            and info.get('size_in_bytes') == len(raw), 'artifact_authority_digest')
    binding = info.get('workflow_run', {})
    require(binding.get('id') == expected.run_id and binding.get('head_sha') == expected.candidate_sha
            and binding.get('head_branch') == expected.branch
            and binding.get('repository_id') == run['repository']['id']
            and binding.get('head_repository_id') == run['head_repository']['id'], 'artifact_authority_identity')
    return sha256(raw), files, info


def merge_bundle_members(merged, files):
    for member, content in files.items():
        require(member not in merged, 'duplicate_bundle_member')
        merged[member] = content


def verify_release_assets(receipt, artifacts, authority, expected, selected, run):
    selected_id = selected['id']
    expected_names = {'wolf-manager-host-v'+expected.version+'-'+triple+ARCHIVE_SUFFIX for triple in TRIPLES}
    installer = 'ha-wolf-manager-installer-v'+expected.version+ARCHIVE_SUFFIX
    expected_names |= {installer, 'SHA256SUMS'}
    assets = receipt['assets']
    require(isinstance(assets, list) and len(assets) == 4, 'asset_set')
    seen = set()
    bundles = {}
    metadata = {}
    verified_assets = {}
    merged = {}
    for asset in assets:
        shape(asset, 'name download_url sha256 size_bytes workflow_artifact_id workflow_artifact_sha256', 'asset_shape')
        name, artifact_id = asset['name'], asset['workflow_artifact_id']
        require(isinstance(name, str) and name in expected_names and name not in seen, 'asset_identity')
        seen.add(name)
        require(artifact_id == selected_id and positive_int(artifact_id) and positive_int(asset['size_bytes']) and asset['size_bytes'] <= MAX_FILE
                and isinstance(asset['sha256'], str) and HEX64.fullmatch(asset['sha256'])
                and isinstance(asset['workflow_artifact_sha256'], str) and HEX64.fullmatch(asset['workflow_artifact_sha256']), 'asset_values')
        canonical_url = f'https://api.github.com/repos/{expected.repository}/actions/artifacts/{artifact_id}/zip'
        require(asset['download_url'] == canonical_url, 'artifact_url')
        if artifact_id not in bundles:
            require(artifact_id in artifacts, 'missing_artifact')
            digest, files, info = authenticate_bundle(artifact_id, artifacts[artifact_id], authority, expected, selected, run)
            bundles[artifact_id] = (digest, files)
            metadata[artifact_id] = info
            merge_bundle_members(merged, files)
        artifact_sha, files = bundles[artifact_id]
        require(artifact_sha == asset['workflow_artifact_sha256'], 'artifact_receipt_digest')
        data = files.get(name)
        require(data is not None and len(data) == asset['size_bytes'] and sha256(data) == asset['sha256'], 'asset_digest')
        verified_assets[name] = data
        if name != 'SHA256SUMS':
            triple = next((t for t in TRIPLES if name.endswith('-'+t+ARCHIVE_SUFFIX)), None)
            inspect_tar(data, TRIPLES[triple] if triple else None)
    require(seen == expected_names and set(artifacts) == set(bundles), 'asset_set')
    sums = verified_assets['SHA256SUMS']
    expected_sums = ''.join(sha256(verified_assets[name])+'  '+name+'\n' for name in sorted(expected_names-{'SHA256SUMS'})).encode()
    require(sums == expected_sums, 'checksum_manifest')
    return bundles, metadata, merged


def _verify_candidate(receipt_bytes, artifacts, authority, expected):
    """Verify exact downloaded GitHub ZIP bytes. Return immutable evidence hashes.

    artifacts maps artifact ID to the preserved ZIP path, never extracted content.
    Do not construct Expectations from the untrusted receipt.
    """
    expected.validate()
    receipt = json_bytes(receipt_bytes)
    receipt_identity(receipt, expected)
    run, workflow, jobs = authority_evidence(authority, expected)
    # Select the producer artifact independently; a receipt cannot nominate a
    # different artifact from the same otherwise-successful workflow run.
    selected = select_candidate_artifact(authority, expected)
    selected_id = selected['id']
    require(isinstance(artifacts, dict) and set(artifacts) == {selected_id}, 'artifact_mapping')
    bundles, metadata, merged = verify_release_assets(receipt, artifacts, authority, expected, selected, run)
    verify_oci(merged, receipt['image'])
    evidence_hashes = {}
    for check in receipt['checks']:
        prefix = f'artifact:{selected_id}/'
        require(check['evidence_location'].startswith(prefix), 'check_evidence_location')
        location = safe_path(check['evidence_location'][len(prefix):])
        content = merged.get(location)
        require(content is not None and 0 < len(content) <= 8*1024*1024, 'missing_check_evidence')
        evidence_hashes[check['name']] = sha256(content)
    evidence = {'run': run, 'workflow': workflow, 'jobs': jobs, 'artifacts': metadata}
    evidence_bytes = json.dumps(evidence, sort_keys=True, separators=(',', ':')).encode()
    return {'schema_version': 1, 'candidate_sha': expected.candidate_sha, 'version': expected.version,
            'workflow_run_id': expected.run_id, 'receipt_sha256': sha256(receipt_bytes),
            'authority_evidence_sha256': sha256(evidence_bytes), 'authority_evidence': evidence,
            'artifact_sha256': {str(k): value[0] for k, value in bundles.items()},
            'check_evidence_sha256': evidence_hashes,
            'index_digest': receipt['image']['index_digest'], 'platforms': receipt['image']['platforms']}


def verify_candidate(receipt_bytes, artifacts, authority, expected):
    try:
        return _verify_candidate(receipt_bytes, artifacts, authority, expected)
    except VerificationError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, OSError, struct.error):
        raise VerificationError('malformed_candidate_or_authority') from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True, help='preserved <artifact-id>.zip files')
    parser.add_argument('--repository', required=True)
    parser.add_argument('--sha', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--run-id', type=int, required=True)
    parser.add_argument('--workflow-id', type=int, required=True)
    parser.add_argument('--workflow-path', required=True)
    parser.add_argument('--event', choices=('push', 'workflow_dispatch'), default='push')
    args = parser.parse_args()
    try:
        expected = Expectations(args.repository, args.sha, args.version, args.run_id,
                                args.workflow_id, args.workflow_path, event=args.event)
        expected.validate()
        files = {}
        for path in args.artifacts.iterdir():
            require(path.suffix == '.zip' and path.stem.isdecimal() and positive_int(int(path.stem)), 'artifact_directory')
            artifact_id = int(path.stem)
            require(artifact_id not in files, 'duplicate_artifact_id')
            files[artifact_id] = path
        require(args.receipt.is_file() and not args.receipt.is_symlink() and args.receipt.stat().st_size <= 8*1024*1024, 'receipt_file')
        result = verify_candidate(args.receipt.read_bytes(), files,
                                 GitHubAuthority(args.repository, os.environ.get('GITHUB_TOKEN')), expected)
        print(json.dumps(result, sort_keys=True))
    except (VerificationError, OSError, TypeError, KeyError, AttributeError, struct.error):
        parser.exit(1, 'Candidate verification refused. No content was extracted or published.\n')


if __name__ == '__main__':
    main()
