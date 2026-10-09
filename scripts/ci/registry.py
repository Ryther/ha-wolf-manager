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
BLOB_PATH = 'blobs/'
BLOB_UPLOAD_PATH = 'blobs/uploads/'

OCI_BLOB_PREFIX = 'oci/blobs/sha256/'
OCI_INDEX_FILE = 'oci/index.json'


AUTHENTICATION_PHASE = 'authentication'
PUBLIC_AUTHENTICATION_PHASE = 'public-authentication'
DIAGNOSTIC_PHASES = frozenset({AUTHENTICATION_PHASE, PUBLIC_AUTHENTICATION_PHASE, 'tag-read',
    'manifest-read', 'manifest-upload', 'blob-read', 'blob-start', 'blob-upload', 'request'})


class RegistryFailure(v.VerificationError):
    """Keep the existing refusal code with controlled transport diagnostics."""
    def __init__(self, code, phase, status=None):
        super().__init__(code)
        self.phase = phase
        self.status = status


def request_phase(method, path):
    relative = path[len(PREFIX):]
    if method == 'GET' and relative.startswith(MANIFEST_PATH):
        return 'manifest-read' if relative.startswith(MANIFEST_PATH + 'sha256:') else 'tag-read'
    for verb, prefix, phase in (('HEAD', BLOB_PATH, 'blob-read'),
                               ('POST', BLOB_UPLOAD_PATH, 'blob-start'),
                               ('PUT', BLOB_UPLOAD_PATH, 'blob-upload'),
                               ('PUT', MANIFEST_PATH, 'manifest-upload')):
        if method == verb and relative.startswith(prefix):
            return phase
    return 'request'



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
        except urllib.error.HTTPError as error:
            raise RegistryFailure('registry_authentication_failed', AUTHENTICATION_PHASE, error.code) from None
        except OSError:
            raise RegistryFailure('registry_authentication_failed', AUTHENTICATION_PHASE) from None

    @classmethod
    def anonymous(cls):
        """Obtain only public pull access; never supply a publication credential."""
        registry = cls.__new__(cls)
        registry.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), v._NoRedirect)
        url = 'https://ghcr.io/token?' + urllib.parse.urlencode({
            'service': 'ghcr.io', 'scope': 'repository:ryther/ha-wolf-manager:pull'})
        try:
            with registry.opener.open(urllib.request.Request(url), timeout=30) as response:
                v.require(response.status == 200, 'registry_public_token_status')
                raw = response.read(1024 * 1024 + 1)
                v.require(len(raw) <= 1024 * 1024, 'registry_public_token_size')
                result = v.json_bytes(raw)
            registry.token = result.get('token')
            v.require(isinstance(registry.token, str) and bool(registry.token), 'registry_public_token')
        except urllib.error.HTTPError as error:
            raise RegistryFailure('registry_public_access_unavailable', PUBLIC_AUTHENTICATION_PHASE, error.code) from None
        except OSError:
            raise RegistryFailure('registry_public_access_unavailable', PUBLIC_AUTHENTICATION_PHASE) from None
        return registry

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
            raise RegistryFailure('registry_http_failure', request_phase(method, path), error.code) from None
        except OSError:
            raise RegistryFailure('registry_unavailable', request_phase(method, path)) from None


def header(headers, key):
    matches = [value for name, value in headers.items() if name.lower() == key.lower()]
    v.require(len(matches) == 1, 'registry_required_header')
    return matches[0]


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

def check_tag(image, request):
    status, headers, existing = request('GET', PREFIX + MANIFEST_PATH + image['tag'])
    if status == 200:
        v.require(v.sha256(existing) == v.parse_digest(image['index_digest'])
                  and header(headers, 'Docker-Content-Digest') == image['index_digest'], 'registry_tag_rebind')
    v.require(status in (200, 404), 'registry_tag_status')


def publish(files, image, request, *, transfer):
    v.verify_oci(files, image)
    v.require(image['repository'] == 'ghcr.io/ryther/ha-wolf-manager'
              and v.SEMVER.fullmatch(image['tag']), 'registry_subject')
    check_tag(image, request)
    transfer(files, image)
    # Bulk copy is digest-only: it cannot authorize a changed version tag.
    check_tag(image, request)
    verify_graph(files, image, request)
    root = v.json_bytes(files[OCI_INDEX_FILE])['manifests'][0]
    # transfer_manifest independently checks the tag immediately before binding.
    transfer_manifest(files, root, image['tag'], request)
    return root['digest']


def verify_public_manifest(files, descriptor, reference, request):
    digest = descriptor['digest']
    expected = files[OCI_BLOB_PREFIX + v.parse_digest(digest)]
    status, headers, data = request('GET', PREFIX + MANIFEST_PATH + reference)
    v.require(status == 200 and data == expected
              and header(headers, 'Docker-Content-Digest') == digest, 'registry_public_manifest_identity')


def verify_graph(files, image, request):
    """Read every original index, platform manifest and blob identity."""
    v.verify_oci(files, image)
    v.require(image['repository'] == 'ghcr.io/ryther/ha-wolf-manager'
              and v.SEMVER.fullmatch(image['tag']), 'registry_public_subject')
    root = v.json_bytes(files[OCI_INDEX_FILE])['manifests'][0]
    verify_public_manifest(files, root, root['digest'], request)
    index = v.json_bytes(files[OCI_BLOB_PREFIX + v.parse_digest(root['digest'])])
    blobs = {}
    for descriptor in index['manifests']:
        verify_public_manifest(files, descriptor, descriptor['digest'], request)
        manifest = v.json_bytes(files[OCI_BLOB_PREFIX + v.parse_digest(descriptor['digest'])])
        for blob in [manifest['config'], *manifest['layers']]:
            blobs[blob['digest']] = blob
    for digest, descriptor in blobs.items():
        status, headers, _ = request('HEAD', PREFIX + BLOB_PATH + digest)
        v.require(status == 200 and header(headers, 'Docker-Content-Digest') == digest
                  and header(headers, 'Content-Length') == str(descriptor['size']), 'registry_public_blob_identity')
    return root['digest']


def verify_public(files, image, request):
    """Verify anonymous graph access and the exact final version tag."""
    digest = verify_graph(files, image, request)
    root = v.json_bytes(files[OCI_INDEX_FILE])['manifests'][0]
    verify_public_manifest(files, root, image['tag'], request)
    return digest
