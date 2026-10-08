"""Simulated distribution API proves byte-preserving publisher behavior."""
import unittest
from scripts.ci import registry as r, verify_candidate as v
from test_candidate import fixture, encoded


class RegistryTests(unittest.TestCase):
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
