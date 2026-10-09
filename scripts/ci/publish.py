"""Protected release receiver and publisher; never execute candidate content.

Run from the default-branch publisher revision. Expected producer identity and
release metadata are independently retrieved from GitHub. Publication is off
unless protected repository settings explicitly enable it.
"""
from __future__ import annotations
import argparse
import base64
import os
from pathlib import Path
import urllib.parse
import urllib.request
from scripts.ci import artifacts as a, producer as p, registry as r, verify_candidate as v


class GitHub(v.GitHubAuthority):
    def write(self, method, path, value=None, raw=None):
        prefix = REPOSITORY_API_PREFIX + p.REPOSITORY + '/'
        v.require(path.startswith(prefix) and not any(c in path for c in ('\r', '\n', '\\', '..')),
                  'publisher_api_path')
        url = ('https://uploads.github.com' if raw is not None else 'https://api.github.com') + path
        request = urllib.request.Request(url, method=method, data=raw if raw is not None else p.encoded(value),
            headers={'Authorization': 'Bearer ' + self.token, 'X-GitHub-Api-Version': '2026-03-10',
                     'Accept': 'application/vnd.github+json',
                     'Content-Type': 'application/octet-stream' if raw is not None else 'application/json'})
        with self.opener.open(request, timeout=120) as response:
            v.require(response.status in (200, 201), 'publisher_api_status')
            return v.json_bytes(response.read(8 * 1024 * 1024 + 1))


REPOSITORY_API_PREFIX = '/repos/'

CANDIDATE_WORKFLOW = v.CI_WORKFLOW

RECEIPT_FILE = 'release-receipt.json'


def tag_commit(authority, version):
    prefix = REPOSITORY_API_PREFIX + p.REPOSITORY
    ref = authority.get_json(prefix + '/git/ref/tags/v' + version)['object']
    for _ in range(5):
        v.require(v.HEX40.fullmatch(ref.get('sha', '')), 'release_tag_sha')
        if ref.get('type') == 'commit': return ref['sha']
        v.require(ref.get('type') == 'tag', 'release_tag_object')
        ref = authority.get_json(prefix + '/git/tags/' + ref['sha'])['object']
    raise v.VerificationError('release_tag_depth')


def prepare(authority, run_id, workflow_id, output):
    prefix = REPOSITORY_API_PREFIX + p.REPOSITORY
    run = authority.get_json(prefix + '/actions/runs/' + str(run_id))
    sha = p.publisher_identity(run, workflow_id, CANDIDATE_WORKFLOW)
    workflow = authority.get_json(prefix + '/actions/workflows/' + str(workflow_id))
    v.require(workflow.get('id') == workflow_id and workflow.get('path') == CANDIDATE_WORKFLOW
              and workflow.get('state') == 'active', 'publisher_workflow_allowlist')
    contents = authority.get_json(prefix + '/contents/version.txt?ref=' + sha)
    v.require(contents.get('encoding') == 'base64' and contents.get('type') == 'file'
              and contents.get('size', 999) <= 100, 'publisher_version_file')
    version = base64.b64decode(contents['content']).decode().strip()
    v.require(v.SEMVER.fullmatch(version), 'publisher_version')
    releases = authority.get_json(prefix + '/releases?per_page=100')
    matches = [release for release in releases if release.get('tag_name') == 'v' + version]
    # Main changes without a coordinated release draft are not publication requests.
    if not matches: return None
    v.require(len(matches) == 1, 'publisher_release_ambiguity')
    release = matches[0]
    if release.get('draft') is False:
        # Automatic replays must never mutate an already published release.
        return None
    release_id = p.release_identity(release, version, sha, tag_commit(authority, version))
    expected = v.Expectations(p.REPOSITORY, sha, version, run_id, workflow_id,
                              CANDIDATE_WORKFLOW, event=run['event'])
    candidate = a.find(authority, run_id, 'release-candidate-' + sha)
    receipt = a.find(authority, run_id, 'release-receipt-' + sha)
    output.mkdir(parents=True, exist_ok=False)
    candidate_path = output / (str(candidate['id']) + '.zip')
    a.download(authority, candidate, candidate_path)
    receipt_path = output / 'receipt.zip'; a.download(authority, receipt, receipt_path)
    _, receipt_files = v.bundle_files(receipt_path)
    v.require(set(receipt_files) == {RECEIPT_FILE}, 'publisher_receipt_artifact')
    receipt_raw = receipt_files[RECEIPT_FILE]
    result = v.verify_candidate(receipt_raw, {candidate['id']: candidate_path}, authority, expected)
    (output / RECEIPT_FILE).write_bytes(receipt_raw)
    (output / 'verification.json').write_bytes(p.encoded(result))
    return expected, release_id, candidate_path, result


def confirm_published_release(release, expected, release_id):
    v.require(isinstance(release, dict) and v.positive_int(release.get('id'))
              and release['id'] == release_id and release.get('tag_name') == 'v' + expected.version
              and release.get('target_commitish') == expected.candidate_sha
              and release.get('draft') is False and release.get('prerelease') is False,
              'publisher_public_release_identity')


def publish(authority, prepared, output):
    expected, release_id, candidate_path, evidence = prepared
    _, files = v.bundle_files(candidate_path)
    receipt_raw = (output / RECEIPT_FILE).read_bytes(); receipt = v.json_bytes(receipt_raw)
    registry = r.Registry(os.environ['GITHUB_ACTOR'], authority.token)
    digest = r.publish(files, receipt['image'], registry.request)
    assets = {entry['name']: files[entry['name']] for entry in receipt['assets']}
    assets[RECEIPT_FILE] = receipt_raw
    assets['release-verification.json'] = (output / 'verification.json').read_bytes()
    publication = {'schema_version': 1, 'candidate_sha': expected.candidate_sha,
                   'version': expected.version, 'workflow_run_id': expected.run_id,
                   'receipt_sha256': evidence['receipt_sha256'], 'image_index_digest': digest,
                   'platforms': receipt['image']['platforms'],
                   'assets': {name: {'sha256': v.sha256(data), 'size_bytes': len(data)}
                              for name, data in sorted(assets.items())}}
    assets['publication.json'] = p.encoded(publication)
    prefix = REPOSITORY_API_PREFIX + p.REPOSITORY + '/releases/' + str(release_id)
    existing = authority.get_json(prefix + '/assets?per_page=100')
    names = [asset.get('name') for asset in existing]
    v.require(len(names) == len(set(names)), 'publisher_duplicate_asset')
    v.require(set(names) <= set(assets), 'publisher_unexpected_asset')
    for name, data in assets.items():
        matches = [asset for asset in existing if asset.get('name') == name]
        if matches:
            info = matches[0]
        else:
            info = authority.write('POST', prefix + '/assets?name=' + urllib.parse.quote(name, safe=''), raw=data)
        v.require(info.get('name') == name and info.get('size') == len(data)
                  and info.get('digest') == 'sha256:' + v.sha256(data), 'publisher_remote_asset_identity')
    # Public release consumers must be able to pull the exact verified image.
    try:
        public_registry = r.Registry.anonymous()
        r.verify_public(files, receipt['image'], public_registry.request)
    except v.VerificationError:
        raise v.VerificationError('publisher_image_not_public') from None
    # Re-check tag just before making the existing draft public; no ref changes.
    v.require(tag_commit(authority, expected.version) == expected.candidate_sha, 'publisher_final_tag')
    release = authority.write('PATCH', prefix, {'tag_name': 'v' + expected.version,
        'target_commitish': expected.candidate_sha, 'draft': False, 'prerelease': False})
    confirm_published_release(release, expected, release_id)
    v.require(tag_commit(authority, expected.version) == expected.candidate_sha, 'publisher_published_tag')
    return publication


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', type=int, required=True)
    parser.add_argument('--workflow-id', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--publish', action='store_true'); args = parser.parse_args()
    v.require(v.positive_int(args.run_id) and v.positive_int(args.workflow_id), 'publisher_expected_run')
    if args.publish: v.require(os.environ.get('RELEASE_PUBLISH_ENABLED') == 'true', 'publisher_disabled')
    authority = GitHub(p.REPOSITORY, os.environ['GITHUB_TOKEN'])
    prepared = prepare(authority, args.run_id, args.workflow_id, args.output)
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as file:
            file.write('eligible=' + ('true' if prepared else 'false') + '\n')
    if prepared and args.publish:
        publish(authority, prepared, args.output)
    print('Verified eligible candidate' if prepared else 'No coordinated draft release is eligible')


GENERIC_REFUSAL = 'Trusted publisher refused; credentials and raw API errors are not logged.'
REGISTRY_REFUSALS = frozenset({
    'registry_upload_origin', 'registry_credentials', 'registry_token',
    'registry_authentication_failed', 'registry_public_token_status', 'registry_public_token_size',
    'registry_public_token', 'registry_public_access_unavailable', 'registry_path',
    'registry_http_failure', 'registry_unavailable', 'registry_required_header',
    'registry_start_upload', 'registry_blob_upload', 'registry_blob_identity',
    'registry_manifest_identity', 'registry_manifest_status', 'registry_manifest_upload',
    'registry_subject', 'registry_tag_rebind', 'registry_tag_status',
    'registry_public_manifest_identity', 'registry_public_subject', 'registry_public_blob_identity'})


def refusal_message(error):
    """Expose only exact known codes and closed transport fields, never remote text."""
    if not isinstance(error, v.VerificationError):
        return GENERIC_REFUSAL
    code = str(error)
    if code == 'publisher_image_not_public':
        return 'Verified image is not anonymously readable. Configure GHCR package visibility as Public, then retry the same candidate; the release remains a draft.'
    if code not in REGISTRY_REFUSALS:
        return GENERIC_REFUSAL
    if isinstance(error, r.RegistryFailure):
        if not isinstance(error.phase, str) or error.phase not in r.DIAGNOSTIC_PHASES or not valid_http_status(error.status):
            return GENERIC_REFUSAL
        status = 'unavailable' if error.status is None else str(error.status)
        return 'Trusted publisher refused: registry phase=' + error.phase + ' HTTP=' + status + '.'
    return 'Trusted publisher refused: ' + code + '.'


def valid_http_status(status):
    return status is None or (type(status) is int and 100 <= status <= 599)


def cli():
    try:
        main()
    except Exception as error:
        raise SystemExit(refusal_message(error)) from None


if __name__ == '__main__':
    cli()
