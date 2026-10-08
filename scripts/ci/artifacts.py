"""Read-only GitHub artifact receiver; preserve original ZIP bytes.

The authenticated API redirect is captured without following it. Download the
short-lived Azure signed URL separately, with no Authorization header, and
bind the downloaded bytes to the independently retrieved artifact digest.
"""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request
from scripts.ci import producer as p
from scripts.ci import verify_candidate as v


class _ArtifactRedirect(urllib.request.HTTPRedirectHandler):
    """Expose the API response for inspection without following its redirect."""
    def redirect_request(self, request, response, code, message, headers, url):
        return None


def presigned_url(url):
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or ''
    v.require(parsed.scheme == 'https' and parsed.port in (None, 443)
              and not parsed.username and not parsed.password and not parsed.fragment
              and host.endswith(('.blob.core.windows.net', '.actions.githubusercontent.com')),
              'artifact_redirect_origin')
    return url


def download(authority, info, output):
    v.require(v.positive_int(info.get('id')) and info.get('expired') is False
              and v.positive_int(info.get('size_in_bytes')) and info['size_in_bytes'] <= v.MAX_BUNDLE,
              'artifact_metadata')
    digest = v.parse_digest(info.get('digest'))
    request = urllib.request.Request('https://api.github.com/repos/' + p.REPOSITORY +
        '/actions/artifacts/' + str(info['id']) + '/zip', headers={
        'Authorization': 'Bearer ' + authority.token, 'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2026-03-10', 'User-Agent': 'ha-wolf-manager-artifact-receiver'})
    try:
        urllib.request.build_opener(_ArtifactRedirect).open(request, timeout=30)
        raise v.VerificationError('artifact_missing_redirect')
    except urllib.error.HTTPError as error:
        with error:
            v.require(error.code == 302, 'artifact_http_status')
            url = presigned_url(error.headers.get('Location', ''))
    try:
        # Even a second signed-URL redirect is refused. Never forward API credentials.
        with urllib.request.build_opener(v._NoRedirect).open(url, timeout=60) as response:
            v.require(response.status == 200, 'artifact_download_status')
            data = response.read(v.MAX_BUNDLE + 1)
    except OSError:
        raise v.VerificationError('artifact_download_unavailable') from None
    v.require(len(data) == info['size_in_bytes'] and v.sha256(data) == digest, 'artifact_download_digest')
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('xb') as file: file.write(data)
    return data


def find(authority, run_id, name):
    v.require(v.positive_int(run_id) and isinstance(name, str) and len(name) <= 200, 'artifact_request')
    found = []; listed = []; total = None
    for page in range(1, 21):
        result = authority.get_json('/repos/' + p.REPOSITORY + '/actions/runs/' + str(run_id) +
                                    '/artifacts?per_page=100&page=' + str(page))
        v.require(type(result.get('total_count')) is int and 0 <= result['total_count'] <= 2000
                  and isinstance(result.get('artifacts'), list), 'artifact_list')
        if total is None: total = result['total_count']
        v.require(result['total_count'] == total, 'changing_artifact_list')
        listed.extend(result['artifacts']); v.require(len(listed) <= total, 'artifact_pagination')
        if len(listed) == total: break
        v.require(bool(result['artifacts']), 'artifact_pagination')
    v.require(len(listed) == total, 'artifact_pagination')
    found = [item for item in listed if item.get('name') == name]
    v.require(len(found) == 1 and found[0].get('workflow_run', {}).get('id') == run_id,
              'artifact_unique_identity')
    return found[0]


def extract(source, output):
    _, files = v.bundle_files(source)
    # Fully validate all paths/types before creating any filesystem entry.
    p.write_tree(output, files)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', type=int, required=True); parser.add_argument('--name', required=True)
    parser.add_argument('--output', type=Path, required=True); parser.add_argument('--extract', action='store_true')
    args = parser.parse_args()
    authority = v.GitHubAuthority(p.REPOSITORY, os.environ['GITHUB_TOKEN'])
    info = find(authority, args.run_id, args.name)
    zip_path = args.output.with_suffix('.zip')
    download(authority, info, zip_path)
    if args.extract: extract(zip_path, args.output)
    args.output.with_suffix('.metadata.json').write_bytes(p.encoded(info))


if __name__ == '__main__':
    try: main()
    except (v.VerificationError, OSError, KeyError, ValueError):
        raise SystemExit('Artifact receiver refused the request; credentials and raw errors are not logged.')
