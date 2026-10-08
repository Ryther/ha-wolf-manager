"""Exact OCI Distribution byte transfer; no builds or manifest serialization.

Only ghcr.io/ryther/ha-wolf-manager is writable. No remote delete or tag rebind.
The caller first passes the independent candidate verifier, then supplies the
verified original bundle files. Native HTTP errors/credentials are never logged.
"""
from __future__ import annotations
import base64
import os
import urllib.error
import urllib.parse
import urllib.request
from scripts.ci import verify_candidate as v

PREFIX = '/v2/ryther/ha-wolf-manager/'


MANIFEST_PATH = 'manifests/'

OCI_BLOB_PREFIX = 'oci/blobs/sha256/'


def upload_path(url):
    parsed = urllib.parse.urlsplit(url)
    v.require(not parsed.fragment and not parsed.username and not parsed.password
              and (not parsed.netloc and not parsed.scheme or
                   parsed.scheme == 'https' and parsed.netloc == 'ghcr.io')
              and parsed.path.startswith(PREFIX + 'blobs/uploads/')
              and '..' not in parsed.path and '\\' not in parsed.path
              and '\r' not in url and '\n' not in url, 'registry_upload_origin')
    return parsed.path + ('?' + parsed.query if parsed.query else '')


class Registry:
    def __init__(self, actor, token):
        v.require(actor and token, 'registry_credentials')
        self.opener = urllib.request.build_opener(v._NoRedirect)
        basic = base64.b64encode((actor + ':' + token).encode()).decode()
        url = 'https://ghcr.io/token?service=ghcr.io&scope=repository%3aryther%2fha-wolf-manager%3Apull%2Cpush'
        request = urllib.request.Request(url, headers={'Authorization': 'Basic ' + basic})
        try:
            with self.opener.open(request, timeout=30) as response:
                result = v.json_bytes(response.read(1024*1024))
            self.token = result.get('token')
            v.require(isinstance(self.token, str) and bool(self.token), 'registry_token')
        except OSError:
            raise v.VerificationError('registry_authentication_failed') from None

    def request(self, method, path, data=None, media=None):
        v.require(path.startswith(PREFIX) and not any(x in path for x in ('\r', '\n', '\\', '..')),
                  'registry_path')
        headers = {'Authorization': 'Bearer ' + self.token,
                   'Accept': v.INDEX_TYPE + ',' + v.MANIFEST_TYPE}
        if media: headers['Content-Type'] = media
        request = urllib.request.Request('https://ghcr.io' + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=120) as response:
                return response.status, dict(response.headers), response.read(8*1024*1024+1)
        except urllib.error.HTTPError as error:
            if error.code == 404: return 404, {}, b''
            raise v.VerificationError('registry_http_failure') from None
        except OSError:
            raise v.VerificationError('registry_unavailable') from None


def header(headers, key):
    matches = [value for name, value in headers.items() if name.lower() == key.lower()]
    v.require(len(matches) == 1, 'registry_required_header')
    return matches[0]


def transfer_blob(files, descriptor, request, done):
    digest = descriptor['digest']
    if digest in done: return
    data = files[OCI_BLOB_PREFIX + v.parse_digest(digest)]
    status, headers, _ = request('HEAD', PREFIX + 'blobs/' + digest)
    if status == 404:
        status, headers, _ = request('POST', PREFIX + 'blobs/uploads/', b'', 'application/octet-stream')
        v.require(status == 202, 'registry_start_upload')
        location = upload_path(header(headers, 'Location'))
        location += ('&' if '?' in location else '?') + 'digest=' + urllib.parse.quote(digest, safe='')
        status, headers, _ = request('PUT', location, data, 'application/octet-stream')
        v.require(status == 201 and header(headers, 'Docker-Content-Digest') == digest, 'registry_blob_upload')
        status, headers, _ = request('HEAD', PREFIX + 'blobs/' + digest)
    v.require(status == 200 and header(headers, 'Docker-Content-Digest') == digest
              and header(headers, 'Content-Length') == str(len(data)), 'registry_blob_identity')
    done.add(digest)

def transfer_manifest(files, descriptor, reference, request):
    data = files[OCI_BLOB_PREFIX + v.parse_digest(descriptor['digest'])]
    status, headers, downloaded = request('GET', PREFIX + MANIFEST_PATH + reference)
    if status == 200:
        v.require(downloaded == data and header(headers, 'Docker-Content-Digest') == descriptor['digest'],
                  'registry_manifest_identity')
        return
    v.require(status == 404, 'registry_manifest_status')
    status, headers, _ = request('PUT', PREFIX + MANIFEST_PATH + reference, data, descriptor['mediaType'])
    v.require(status == 201 and header(headers, 'Docker-Content-Digest') == descriptor['digest'],
              'registry_manifest_upload')
    status, headers, downloaded = request('GET', PREFIX + MANIFEST_PATH + reference)
    v.require(status == 200 and downloaded == data
              and header(headers, 'Docker-Content-Digest') == descriptor['digest'], 'registry_manifest_identity')

def publish(files, image, request):
    v.verify_oci(files, image)
    v.require(image['repository'] == 'ghcr.io/ryther/ha-wolf-manager'
              and v.SEMVER.fullmatch(image['tag']), 'registry_subject')
    status, headers, existing = request('GET', PREFIX + MANIFEST_PATH + image['tag'])
    if status == 200:
        v.require(v.sha256(existing) == v.parse_digest(image['index_digest'])
                  and header(headers, 'Docker-Content-Digest') == image['index_digest'], 'registry_tag_rebind')
    v.require(status in (200, 404), 'registry_tag_status')
    done = set()
    root = v.json_bytes(files['oci/index.json'])['manifests'][0]
    index = v.json_bytes(files[OCI_BLOB_PREFIX + v.parse_digest(root['digest'])])
    for descriptor in index['manifests']:
        content = v.json_bytes(files[OCI_BLOB_PREFIX + v.parse_digest(descriptor['digest'])])
        transfer_blob(files, content['config'], request, done)
        for layer in content['layers']:
            transfer_blob(files, layer, request, done)
        transfer_manifest(files, descriptor, descriptor['digest'], request)
    transfer_manifest(files, root, image['tag'], request)
    return root['digest']
