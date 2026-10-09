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
            reference = path.rsplit('/', 1)[1]
            if method == 'PUT':
                manifests[reference] = data
                return 201, {'Docker-Content-Digest': 'sha256:' + v.sha256(data)}, b''
            if method == 'GET':
                if reference not in manifests: return 404, {}, b''
                data = manifests[reference]
                return 200, {'Docker-Content-Digest': 'sha256:' + v.sha256(data)}, data
            raise AssertionError((method, path))
        def transfer(source, subject):
            self.assertIs(source, files)
            self.assertIs(subject, image)
            root = v.json_bytes(files['oci/index.json'])['manifests'][0]
            index = v.json_bytes(files[r.OCI_BLOB_PREFIX + v.parse_digest(root['digest'])])
            for descriptor in [root, *index['manifests']]:
                manifests[descriptor['digest']] = files[r.OCI_BLOB_PREFIX + v.parse_digest(descriptor['digest'])]
            for descriptor in index['manifests']:
                manifest = v.json_bytes(manifests[descriptor['digest']])
                for blob in [manifest['config'], *manifest['layers']]:
                    stored[blob['digest']] = files[r.OCI_BLOB_PREFIX + v.parse_digest(blob['digest'])]
        result = r.publish(files, image, request, transfer=transfer)
        self.assertEqual(result, image['index_digest'])
        for method, _, data, _ in calls:
            if method == 'PUT': self.assertIn(data, files.values())
        self.assertFalse(any(method == 'POST' or '/blobs/uploads/' in path for method, path, *_ in calls))
        original_calls = len(calls)
        r.publish(files, image, request, transfer=transfer)
        self.assertFalse(any(method in ('PUT', 'POST') for method, *_ in calls[original_calls:]))
        manifests['0.1.0'] = b'other-image'
        with self.assertRaises(v.VerificationError): r.publish(files, image, request, transfer=transfer)

    def test_bulk_copy_tag_conflict_is_refused_before_any_tag_write(self):
        files, _, _, _, receipt = fixture()
        image = receipt['image']; calls = []; copied = []
        def request(method, path, data=None, media=None):
            calls.append((method, path))
            self.assertEqual(method, 'GET')
            self.assertEqual(path, r.PREFIX + 'manifests/' + image['tag'])
            if not copied:
                return 404, {}, b''
            return 200, {'Docker-Content-Digest': 'sha256:' + v.sha256(b'conflicting-image')}, b'conflicting-image'
        def transfer(source, subject):
            self.assertIs(source, files)
            self.assertIs(subject, image)
            copied.append(True)
        with self.assertRaisesRegex(v.VerificationError, '^registry_tag_rebind$'):
            r.publish(files, image, request, transfer=transfer)
        self.assertEqual(copied, [True])
        self.assertEqual(len(calls), 2)

    def test_existing_conflict_refuses_before_bulk_transfer(self):
        files, _, _, _, receipt = fixture()
        transfer = MagicMock()
        request = MagicMock(return_value=(200, {'Docker-Content-Digest': 'sha256:' + v.sha256(b'other')}, b'other'))
        with self.assertRaisesRegex(v.VerificationError, '^registry_tag_rebind$'):
            r.publish(files, receipt['image'], request, transfer=transfer)
        transfer.assert_not_called()

    def test_failed_bulk_transfer_cannot_write_version_tag(self):
        files, _, _, _, receipt = fixture()
        request = MagicMock(return_value=(404, {}, b''))
        transfer = MagicMock(side_effect=v.VerificationError('oci_copy_failed'))
        with self.assertRaisesRegex(v.VerificationError, '^oci_copy_failed$'):
            r.publish(files, receipt['image'], request, transfer=transfer)
        self.assertEqual(request.call_count, 1)

    def test_bulk_success_cannot_certify_missing_remote_graph(self):
        files, _, _, _, receipt = fixture()
        image = receipt['image']; writes = []
        root = v.json_bytes(files['oci/index.json'])['manifests'][0]
        expected = files[r.OCI_BLOB_PREFIX + v.parse_digest(root['digest'])]
        def request(method, path, data=None, media=None):
            if method == 'PUT':
                writes.append(path)
                self.fail('incomplete copy must not bind a release tag')
            if path.endswith('/' + image['tag']):
                return 404, {}, b''
            if path.endswith('/' + root['digest']):
                return 200, {'Docker-Content-Digest': root['digest']}, expected
            return 404, {}, b''
        transfer = MagicMock()
        with self.assertRaises(v.VerificationError):
            r.publish(files, image, request, transfer=transfer)
        transfer.assert_called_once_with(files, image)
        self.assertEqual(writes, [])

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
