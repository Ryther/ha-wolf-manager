"""Artifact redirect safety, ZIP preservation and metadata coherence."""
import io
import email.message
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import urllib.error
import urllib.request
import zipfile
from scripts.ci import artifacts as a
from scripts.ci import verify_candidate as v


class ArtifactTests(unittest.TestCase):
    def test_api_redirect_downloads_exact_zip_without_forwarding_credentials(self):
        data = b'original archive bytes'
        signed_url = 'https://productionresultssa.blob.core.windows.net/archive?sig=private'
        requests = []
        cdn_redirect = False

        class FixtureTransport(urllib.request.HTTPSHandler):
            def https_open(self, request):
                requests.append(request)
                headers = email.message.Message()
                if request.host == 'api.github.com':
                    headers['Location'] = signed_url
                    return urllib.error.HTTPError(request.full_url, 302, 'Found', headers, io.BytesIO())
                if cdn_redirect:
                    headers['Location'] = 'https://attacker.invalid/archive'
                    return urllib.error.HTTPError(request.full_url, 302, 'Found', headers, io.BytesIO())
                return urllib.error.HTTPError(request.full_url, 200, 'OK', headers, io.BytesIO(data))

        original_builder = urllib.request.build_opener
        def fixture_builder(*handlers):
            return original_builder(FixtureTransport(), *handlers)

        authority = v.GitHubAuthority('Ryther/ha-wolf-manager', 'fixture-token')
        authority.opener = fixture_builder(v._NoRedirect)
        info = {'id': 42, 'expired': False, 'size_in_bytes': len(data),
                'digest': 'sha256:' + v.sha256(data)}
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
                urllib.request, 'build_opener', side_effect=fixture_builder):
            output = Path(directory) / 'archive.zip'
            self.assertEqual(a.download(authority, info, output), data)
            self.assertEqual(output.read_bytes(), data)
            self.assertEqual(len(requests), 2)
            self.assertEqual(requests[0].get_header('Authorization'), 'Bearer fixture-token')
            self.assertEqual(requests[1].full_url, signed_url)
            self.assertIsNone(requests[1].get_header('Authorization'))
            for changed in ({'digest': 'sha256:' + '0' * 64}, {'size_in_bytes': len(data) + 1}):
                rejected = Path(directory) / 'rejected.zip'
                with self.subTest(changed=changed), self.assertRaisesRegex(
                        v.VerificationError, 'artifact_download_digest'):
                    a.download(authority, info | changed, rejected)
                self.assertFalse(rejected.exists())
            cdn_redirect = True
            requests.clear()
            with self.assertRaisesRegex(v.VerificationError, 'api_redirect_refused'):
                a.download(authority, info, Path(directory) / 'redirect.zip')
            self.assertEqual(len(requests), 2)
            self.assertFalse((Path(directory) / 'redirect.zip').exists())

    def test_presigned_download_refuses_other_origins_credentials_and_insecure_urls(self):
        self.assertEqual(a.presigned_url('https://productionresultssa.blob.core.windows.net/file?sig=abc'),
                         'https://productionresultssa.blob.core.windows.net/file?sig=abc')
        for url in ['http://x.blob.core.windows.net/a', 'https://attacker.invalid/a',
                    'https://api.github.com/a', 'https://user:pass@x.blob.core.windows.net/a',
                    'https://x.blob.core.windows.net.attacker.invalid/a',
                    'https://x.blob.core.windows.net/a#fragment']:
            with self.subTest(url=url), self.assertRaises(v.VerificationError):
                a.presigned_url(url)

    def test_extract_refuses_links_and_traversal_before_any_write(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / '42.zip'; out = Path(directory) / 'out'
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, 'w') as z:
                z.writestr('valid', b'valid')
                z.writestr('../escape', b'invalid')
            source.write_bytes(buffer.getvalue())
            with self.assertRaises(v.VerificationError): a.extract(source, out)
            self.assertFalse(out.exists())

    def test_original_zip_is_preserved_when_safely_extracting(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / '42.zip'; out = Path(directory) / 'out'
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, 'w') as z: z.writestr('a/b', b'bytes')
            original = buffer.getvalue(); source.write_bytes(original)
            a.extract(source, out)
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual((out / 'a/b').read_bytes(), b'bytes')
