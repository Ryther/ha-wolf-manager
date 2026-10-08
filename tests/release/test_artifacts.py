"""Artifact redirect safety, ZIP preservation and metadata coherence."""
import io
import runpy
import sys
import secrets
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


class ArtifactCliTests(unittest.TestCase):
    def test_cli_metadata_refusal_reports_only_controlled_stage_and_code(self):
        token = secrets.token_urlsafe(32)
        authority = mock.Mock()
        authority.get_json.side_effect = v.VerificationError('authority_unavailable')
        arguments = ['artifacts', '--run-id', '42', '--name', 'fixture', '--output', '_tmp/fixture']
        with mock.patch.object(sys, 'argv', arguments), mock.patch.dict(
                'os.environ', {'GITHUB_TOKEN': token}), mock.patch.object(
                v, 'GitHubAuthority', return_value=authority), self.assertRaises(SystemExit) as exit:
            runpy.run_module('scripts.ci.artifacts', run_name='__main__')
        self.assertIn('stage=metadata', str(exit.exception))
        self.assertIn('code=authority_unavailable', str(exit.exception))
        self.assertNotIn(token, str(exit.exception))

    def test_cli_raw_transport_failure_does_not_print_signed_url_or_credentials(self):
        token = secrets.token_urlsafe(32)
        authority = mock.Mock()
        authority.get_json.side_effect = OSError('Bearer ' + token + ' https://example.invalid/?sig=' + token)
        arguments = ['artifacts', '--run-id', '42', '--name', 'fixture', '--output', '_tmp/fixture']
        with mock.patch.object(sys, 'argv', arguments), mock.patch.dict(
                'os.environ', {'GITHUB_TOKEN': token}), mock.patch.object(
                v, 'GitHubAuthority', return_value=authority), self.assertRaises(SystemExit) as exit:
            runpy.run_module('scripts.ci.artifacts', run_name='__main__')
        message = str(exit.exception)
        for private in ('Bearer', token, 'https://', 'sig=' + token):
            self.assertNotIn(private, message)
        self.assertIn('stage=metadata', message)
        self.assertIn('type=OSError', message)

    def test_cli_preserves_original_zip_extraction_and_metadata(self):
        token = secrets.token_urlsafe(32)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            archive.writestr('a/b', b'fixture bytes')
        data = buffer.getvalue()
        info = {'id': 42, 'expired': False, 'size_in_bytes': len(data),
                'digest': 'sha256:' + v.sha256(data)}
        def download(_authority, metadata, output):
            self.assertEqual(metadata, info)
            output.write_bytes(data)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'subject'
            arguments = ['artifacts', '--run-id', '42', '--name', 'fixture',
                         '--output', str(output), '--extract']
            with mock.patch.object(sys, 'argv', arguments), mock.patch.dict(
                    'os.environ', {'GITHUB_TOKEN': token}), mock.patch.object(
                    a, 'find', return_value=info), mock.patch.object(a, 'download', side_effect=download):
                a.main()
            self.assertEqual(output.with_suffix('.zip').read_bytes(), data)
            self.assertEqual((output / 'a/b').read_bytes(), b'fixture bytes')
            self.assertEqual(v.json_bytes(output.with_suffix('.metadata.json').read_bytes()), info)

    def test_cli_reports_exact_failed_stage_without_exposing_exception_payload(self):
        token = secrets.token_urlsafe(32)
        private = 'Bearer ' + token + ' https://example.invalid/?sig=' + token
        for stage, target, error, expected in (
                ('metadata', 'find', KeyError(private), 'type=KeyError'),
                ('download', 'download', ValueError(private), 'type=ValueError'),
                ('download', 'download', v.VerificationError('artifact_download_digest'), 'code=artifact_download_digest'),
                ('extract', 'extract', v.VerificationError('archive_path'), 'code=archive_path'),
                ('metadata-write', 'write_bytes', OSError(private), 'type=OSError'),
                ('metadata', 'find', v.VerificationError(private), 'code=verification_refused')):
            with self.subTest(stage=stage, target=target, expected=expected), tempfile.TemporaryDirectory() as directory:
                arguments = ['artifacts', '--run-id', '42', '--name', 'fixture',
                             '--output', str(Path(directory) / 'subject'), '--extract']
                with mock.patch.object(sys, 'argv', arguments), mock.patch.dict(
                        'os.environ', {'GITHUB_TOKEN': token}), mock.patch.object(
                        a, 'find', return_value={}) as find, mock.patch.object(a, 'download') as download, mock.patch.object(
                        a, 'extract') as extract, mock.patch.object(Path, 'write_bytes') as write:
                    {'find': find, 'download': download, 'extract': extract,
                     'write_bytes': write}[target].side_effect = error
                    with self.assertRaises(SystemExit) as exit:
                        a.main()
                message = str(exit.exception)
                self.assertIn('stage=' + stage, message)
                self.assertIn(expected, message)
                for value in ('Bearer', token, 'https://', 'sig=' + token):
                    self.assertNotIn(value, message)
