"""Credential isolation and refusal behavior at native publication boundaries."""
import io
from pathlib import Path
import tempfile
import runpy
import contextlib
import os
import urllib.parse
import unittest
import zipfile
from unittest.mock import MagicMock, patch
import urllib.error
from scripts.ci import artifacts as a, fetch_tool as f, registry as r, verify_candidate as v
from scripts.ci import producer as p, publish as publisher
import test_publisher


def response(data=b'', status=200):
    result = MagicMock()
    result.__enter__.return_value = result
    result.read.return_value = data
    result.status = status
    return result


class NetworkContracts(unittest.TestCase):
    def http_error(self, code, headers):
        error = urllib.error.HTTPError('https://example.invalid', code, '', headers, io.BytesIO())
        self.addCleanup(error.close)
        return error

    def test_actual_addon_schema_and_invalid_metadata(self):
        with contextlib.redirect_stdout(io.StringIO()):
            runpy.run_module('scripts.ci.addon_schema', run_name='__main__')
        with patch('yaml.safe_load', return_value={'name': 42}):
            with self.assertRaisesRegex(SystemExit, 'fails the pinned'):
                runpy.run_module('scripts.ci.addon_schema', run_name='__main__')

    def test_artifact_redirect_download_keeps_credentials_on_api_only(self):
        data = b'original zip bytes'
        authority = MagicMock(token='synthetic-only')
        authority.opener.open.side_effect = self.http_error(302, {'Location': 'https://fixture.blob.core.windows.net/zip?sig=test'})
        cdn = MagicMock()
        cdn.open.return_value = response(data)
        info = {'id': 42, 'expired': False, 'size_in_bytes': len(data), 'digest': 'sha256:' + v.sha256(data)}
        with tempfile.TemporaryDirectory() as directory, patch.object(a.urllib.request, 'build_opener', return_value=cdn):
            output = Path(directory) / 'artifact.zip'
            self.assertEqual(a.download(authority, info, output), data)
            self.assertEqual(output.read_bytes(), data)
            self.assertEqual(authority.opener.open.call_args.args[0].get_header('Authorization'), 'Bearer synthetic-only')
            self.assertIsInstance(cdn.open.call_args.args[0], str)
            info['digest'] = 'sha256:' + '0' * 64
            refused = Path(directory) / 'refused.zip'
            with self.assertRaisesRegex(v.VerificationError, 'artifact_download_digest'):
                a.download(authority, info, refused)
            self.assertFalse(refused.exists())

    def test_artifact_missing_redirect_and_network_failure_never_write(self):
        info = {'id': 42, 'expired': False, 'size_in_bytes': 1, 'digest': 'sha256:' + '0' * 64}
        authority = MagicMock(token='synthetic-only')
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'never.zip'
            with self.assertRaisesRegex(v.VerificationError, 'artifact_missing_redirect'):
                a.download(authority, info, out)
            authority.opener.open.side_effect = self.http_error(302, {'Location': 'https://fixture.actions.githubusercontent.com/zip'})
            cdn = MagicMock(); cdn.open.side_effect = OSError('private endpoint')
            with patch.object(a.urllib.request, 'build_opener', return_value=cdn):
                with self.assertRaisesRegex(v.VerificationError, '^artifact_download_unavailable$'):
                    a.download(authority, info, out)
            self.assertFalse(out.exists())

    def test_artifact_pagination_refuses_changed_or_ambiguous_metadata(self):
        authority = MagicMock()
        authority.get_json.side_effect = [
            {'total_count': 2, 'artifacts': [{'name': 'other'}]},
            {'total_count': 2, 'artifacts': [{'id': 42, 'name': 'candidate', 'workflow_run': {'id': 7}}]}]
        self.assertEqual(a.find(authority, 7, 'candidate')['id'], 42)
        authority.get_json.side_effect = [
            {'total_count': 2, 'artifacts': [{'name': 'other'}]},
            {'total_count': 1, 'artifacts': []}]
        with self.assertRaisesRegex(v.VerificationError, 'changing_artifact_list'):
            a.find(authority, 7, 'candidate')

    def test_registry_native_http_uses_scoped_credentials_and_safe_failures(self):
        opener = MagicMock(); opener.open.return_value = response(b'{"token":"synthetic-bearer"}')
        with patch.object(r.urllib.request, 'build_opener', return_value=opener):
            registry = r.Registry('fixture', 'synthetic-only')
        opener.open.return_value = response(b'manifest')
        self.assertEqual(registry.request('GET', r.PREFIX + 'manifests/0.1.0')[2], b'manifest')
        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_header('Authorization'), 'Bearer synthetic-bearer')
        with self.assertRaisesRegex(v.VerificationError, 'registry_path'):
            registry.request('GET', '/v2/another/image')
        for code in (404, 403):
            opener.open.side_effect = self.http_error(code, {})
            if code == 404:
                self.assertEqual(registry.request('HEAD', r.PREFIX + 'blobs/missing'), (404, {}, b''))
            else:
                with self.assertRaisesRegex(v.VerificationError, '^registry_http_failure$'):
                    registry.request('GET', r.PREFIX + 'manifests/0.1.0')
        opener.open.side_effect = OSError('secret raw error')
        with self.assertRaisesRegex(v.VerificationError, '^registry_unavailable$'):
            registry.request('GET', r.PREFIX + 'manifests/0.1.0')
        with patch.object(r.urllib.request, 'build_opener', return_value=opener):
            with self.assertRaisesRegex(v.VerificationError, '^registry_authentication_failed$'):
                r.Registry('fixture', 'synthetic-only')

    def test_scanner_checksum_and_archive_are_verified_before_installing(self):
        data = p.archive({'actionlint': (b'synthetic binary', 0o755)})
        with tempfile.TemporaryDirectory() as directory, patch.dict(f.TOOLS,
            {'actionlint': ('https://example.invalid/tool', v.sha256(data))}), patch.object(f.urllib.request,
            'urlopen', return_value=response(data)):
            output = Path(directory) / 'actionlint'
            f.install('actionlint', output)
            self.assertEqual(output.read_bytes(), b'synthetic binary')
            self.assertEqual(output.stat().st_mode & 0o777, 0o755)
            with self.assertRaises(FileExistsError): f.install('actionlint', output)
            f.TOOLS['actionlint'] = ('https://example.invalid/tool', '0' * 64)
            with self.assertRaisesRegex(v.VerificationError, 'scanner_checksum'):
                f.install('actionlint', Path(directory) / 'never')
            self.assertFalse((Path(directory) / 'never').exists())

    def test_publisher_transfers_exact_assets_and_refuses_altered_remote_bytes(self):
        fixture = test_publisher.PublisherTests(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        prepared = fixture.prepare()
        original_get = fixture.authority.get_json
        remote = []; writes = []
        def get(path):
            if path.endswith('/assets?per_page=100'): return remote
            return original_get(path)
        def write(method, path, value=None, raw=None):
            writes.append((method, path, value, raw))
            if method == 'PATCH': return {'draft': False}
            name = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)['name'][0]
            item = {'name': name, 'size': len(raw), 'digest': 'sha256:' + v.sha256(raw)}
            remote.append(item)
            return item
        fixture.authority.get_json = get
        fixture.authority.write = write
        with patch.dict(os.environ, {'GITHUB_ACTOR': 'fixture'}), patch.object(publisher.r, 'Registry'), patch.object(
            publisher.r, 'publish', return_value=fixture.fixture.receipt['image']['index_digest']):
            publication = publisher.publish(fixture.authority, prepared, fixture.output)
            self.assertEqual(publication['candidate_sha'], prepared[0].candidate_sha)
            self.assertEqual(writes[-1][0], 'PATCH')
            original = v.bundle_files(prepared[2])[1]
            for method, path, _, raw in writes:
                if method != 'POST': continue
                name = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)['name'][0]
                if name in original: self.assertEqual(raw, original[name])
            writes.clear()
            publisher.publish(fixture.authority, prepared, fixture.output)
            self.assertEqual([item[0] for item in writes], ['PATCH'])
            remote[0]['digest'] = 'sha256:' + '0' * 64
            writes.clear()
            with self.assertRaisesRegex(v.VerificationError, 'publisher_remote_asset_identity'):
                publisher.publish(fixture.authority, prepared, fixture.output)
            self.assertEqual(writes, [])
            remote[0]['digest'] = 'sha256:' + v.sha256(original[remote[0]['name']])
            fixture.tag_sha = 'b' * 40
            with self.assertRaisesRegex(v.VerificationError, 'publisher_final_tag'):
                publisher.publish(fixture.authority, prepared, fixture.output)
            self.assertEqual(writes, [])

    def test_corrupt_lzma_zip_is_a_safe_refusal(self):
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w', compression=zipfile.ZIP_LZMA) as archive:
            archive.writestr('file', b'payload' * 100)
        raw = bytearray(data.getvalue())
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entry = archive.infolist()[0]
            offset = entry.header_offset + 30 + len(entry.filename.encode()) + len(entry.extra)
        raw[offset + 12] ^= 0xff
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bad.zip'; path.write_bytes(raw)
            with self.assertRaisesRegex(v.VerificationError, '^malformed_bundle$'):
                v.bundle_files(path)

    def test_ascii_release_identifiers_refuse_unicode_digits(self):
        self.assertIsNone(v.SEMVER.fullmatch('1.٢.0'))
        self.assertIsNone(v.HEX40.fullmatch('١' * 40))
        self.assertIsNone(v.HEX64.fullmatch('١' * 64))
