"""Simulated distribution API proves byte-preserving publisher behavior."""
import unittest
from unittest.mock import patch, MagicMock
import urllib.parse
from scripts.ci import registry as r, verify_candidate as v
from test_candidate import fixture, encoded


class RegistryTests(unittest.TestCase):
    def test_bearer_scope_matches_exact_lowercase_oci_repository(self):
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b'{"token":"synthetic-bearer"}'
        opener = MagicMock(); opener.open.return_value = response
        with patch.object(r.urllib.request, 'build_opener', return_value=opener):
            registry = r.Registry('Ryther', 'synthetic-test-only')
        request = opener.open.call_args.args[0]
        url = urllib.parse.urlsplit(request.full_url)
        self.assertEqual(url.scheme, 'https')
        self.assertEqual(url.netloc, 'ghcr.io')
        self.assertEqual(url.path, '/token')
        query = urllib.parse.parse_qs(url.query)
        self.assertEqual(query['scope'], ['repository:ryther/ha-wolf-manager:pull,push'])
        self.assertEqual(query['service'], ['ghcr.io'])
        self.assertEqual(registry.token, 'synthetic-bearer')

    def test_transfer_preserves_raw_manifest_and_layer_bytes_and_refuses_tag_rebind(self):
        files, _, _, _, receipt = fixture()
        image = receipt['image']; calls = []; stored = {}; manifests = {}
        def request(method, path, data=None, media=None):
            calls.append((method, path, data, media))
            if method == 'HEAD':
                digest = path.rsplit('/', 1)[1]
                if digest not in stored: return 404, {}, b''
                return 200, {'Docker-Content-Digest': digest, 'Content-Length': str(len(stored[digest]))}, b''
            if method == 'POST': return 202, {'Location': '/v2/ryther/ha-wolf-manager/blobs/uploads/id'}, b''
            if method == 'PUT' and '/blobs/uploads/' in path:
                digest = path.split('digest=')[1].replace('%3A', ':')
                stored[digest] = data
                return 201, {'Docker-Content-Digest': digest}, b''
            reference = path.rsplit('/', 1)[1]
            if method == 'PUT':
                manifests[reference] = data
                return 201, {'Docker-Content-Digest': 'sha256:' + v.sha256(data)}, b''
            if method == 'GET':
                if reference not in manifests: return 404, {}, b''
                data = manifests[reference]
                return 200, {'Docker-Content-Digest': 'sha256:' + v.sha256(data)}, data
            raise AssertionError((method, path))
        result = r.publish(files, image, request)
        self.assertEqual(result, image['index_digest'])
        for method, _, data, _ in calls:
            if method == 'PUT': self.assertIn(data, files.values())
        original_calls = len(calls)
        r.publish(files, image, request)
        self.assertFalse(any(method in ('PUT', 'POST') for method, *_ in calls[original_calls:]))
        manifests['0.1.0'] = b'other-image'
        with self.assertRaises(v.VerificationError): r.publish(files, image, request)

    def test_upload_location_never_forwards_registry_credentials(self):
        self.assertEqual(r.upload_path('https://ghcr.io/v2/ryther/ha-wolf-manager/blobs/uploads/id?state=a'),
                         '/v2/ryther/ha-wolf-manager/blobs/uploads/id?state=a')
        for url in ['https://attacker.invalid/upload', 'http://ghcr.io/v2/ryther/ha-wolf-manager/blobs/uploads/id',
                    '/v2/other/blobs/uploads/id', '//attacker.invalid/upload',
                    'https://user:pass@ghcr.io/v2/ryther/ha-wolf-manager/blobs/uploads/id']:
            with self.subTest(url=url), self.assertRaises(v.VerificationError): r.upload_path(url)

    def test_native_http_refusals_retain_only_closed_phase_and_status(self):
        import secrets
        import urllib.error
        private = secrets.token_urlsafe(24)
        cases = [('GET', r.PREFIX + 'manifests/0.1.2', 'tag-read'),
                 ('GET', r.PREFIX + 'manifests/sha256:' + 'a' * 64, 'manifest-read'),
                 ('HEAD', r.PREFIX + 'blobs/sha256:' + 'a' * 64, 'blob-read'),
                 ('POST', r.PREFIX + 'blobs/uploads/', 'blob-start'),
                 ('PUT', r.PREFIX + 'blobs/uploads/id?token=' + private, 'blob-upload'),
                 ('PUT', r.PREFIX + 'manifests/0.1.2', 'manifest-upload')]
        registry = r.Registry.__new__(r.Registry)
        registry.token = private
        registry.opener = MagicMock()
        for method, path, phase in cases:
            for status in (401, 403, 429, 503):
                http_error = urllib.error.HTTPError(
                    'https://example.invalid/?token=' + private, status, private, {}, None)
                self.addCleanup(http_error.close)
                registry.opener.open.side_effect = http_error
                with self.subTest(phase=phase, status=status), self.assertRaises(r.RegistryFailure) as caught:
                    registry.request(method, path)
                self.assertEqual(str(caught.exception), 'registry_http_failure')
                self.assertEqual(caught.exception.phase, phase)
                self.assertEqual(caught.exception.status, status)
                self.assertNotIn(private, repr(caught.exception))
        http_error = urllib.error.HTTPError('https://example.invalid', 404, private, {}, None)
        self.addCleanup(http_error.close)
        registry.opener.open.side_effect = http_error
        self.assertEqual(registry.request('GET', cases[0][1]), (404, {}, b''))

    def test_native_auth_http_error_is_distinct_from_network_failure(self):
        import secrets
        import urllib.error
        private = secrets.token_urlsafe(24)
        opener = MagicMock()
        for error, status in [(urllib.error.HTTPError('https://example.invalid', 403, private, {}, None), 403),
                              (OSError(private), None)]:
            if isinstance(error, urllib.error.HTTPError):
                self.addCleanup(error.close)
            opener.open.side_effect = error
            with patch.object(r.urllib.request, 'build_opener', return_value=opener):
                with self.assertRaises(r.RegistryFailure) as caught:
                    r.Registry('fixture', private)
            self.assertEqual(str(caught.exception), 'registry_authentication_failed')
            self.assertEqual(caught.exception.phase, 'authentication')
            self.assertEqual(caught.exception.status, status)

    def test_native_request_network_error_retains_phase_without_private_text(self):
        import secrets
        registry = r.Registry.__new__(r.Registry)
        private = secrets.token_urlsafe(24)
        registry.token = private
        registry.opener = MagicMock()
        registry.opener.open.side_effect = OSError(private)
        with self.assertRaises(r.RegistryFailure) as caught:
            registry.request('PUT', r.PREFIX + 'blobs/uploads/id?secret=' + private)
        self.assertEqual(str(caught.exception), 'registry_unavailable')
        self.assertEqual(caught.exception.phase, 'blob-upload')
        self.assertIsNone(caught.exception.status)
        self.assertNotIn(private, repr(caught.exception))

    def test_anonymous_http_failure_uses_public_auth_phase_and_preserves_refusal(self):
        import urllib.error
        opener = MagicMock()
        error = urllib.error.HTTPError('https://example.invalid/private', 503, 'private-response', {}, None)
        self.addCleanup(error.close)
        opener.open.side_effect = error
        with patch.object(r.urllib.request, 'build_opener', return_value=opener):
            with self.assertRaises(r.RegistryFailure) as caught:
                r.Registry.anonymous()
        self.assertEqual(str(caught.exception), 'registry_public_access_unavailable')
        self.assertEqual(caught.exception.phase, 'public-authentication')
        self.assertEqual(caught.exception.status, 503)
