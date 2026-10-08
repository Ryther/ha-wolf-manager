"""End-to-end protected receiver refusal tests with independent API fixtures."""
import base64
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile
from scripts.ci import publish as p, verify_candidate as v
import test_candidate as candidate_fixture
from test_candidate import SHA, REPO, encoded, digest


class PublisherTests(unittest.TestCase):
    def setUp(self):
        self.fixture = candidate_fixture.CandidateTests(); self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        mapping = self.fixture.package()
        self.candidate = mapping[42].read_bytes()
        raw = encoded(self.fixture.receipt)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive: archive.writestr('release-receipt.json', raw)
        self.receipt = buffer.getvalue()
        self.receipt_info = {'id': 43, 'name': 'release-receipt-' + SHA,
            'digest': 'sha256:' + digest(self.receipt), 'size_in_bytes': len(self.receipt), 'expired': False,
            'workflow_run': {'id': 99, 'head_sha': SHA}}
        owner = self
        class Authority:
            token = 'simulated-credential'
            def get_json(self, path):
                prefix = '/repos/' + REPO
                if path.startswith(prefix + '/contents/version.txt?'):
                    return {'encoding': 'base64', 'type': 'file', 'size': 6,
                            'content': base64.b64encode(b'0.1.0\n').decode()}
                if path == prefix + '/releases?per_page=100': return owner.releases
                if path == prefix + '/git/ref/tags/v0.1.0': return {'object': {'type': 'commit', 'sha': owner.tag_sha}}
                if path.startswith(prefix + '/actions/runs/99/artifacts?'):
                    return {'total_count': 2, 'artifacts': [owner.fixture.authority.artifact, owner.receipt_info]}
                return owner.fixture.authority.get_json(path)
        self.authority = Authority(); self.tag_sha = SHA
        self.releases = [{'id': 1, 'draft': True, 'prerelease': False, 'tag_name': 'v0.1.0',
                          'upload_url': 'https://uploads.github.com/repos/' + REPO + '/releases/1/assets{?name,label}'}]
        self.directory = tempfile.TemporaryDirectory(); self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name) / 'verified'

    def download(self, authority, info, output):
        data = self.candidate if info['id'] == 42 else self.receipt
        output.write_bytes(data)
        return data

    def prepare(self):
        with patch('scripts.ci.artifacts.download', self.download):
            return p.prepare(self.authority, 99, 77, self.output)

    def test_receiver_checks_full_original_zip_and_all_independent_jobs(self):
        result = self.prepare()
        self.assertEqual(result[0].candidate_sha, SHA)
        self.assertEqual((self.output / '42.zip').read_bytes(), self.candidate)
        self.assertEqual(v.json_bytes((self.output / 'verification.json').read_bytes())['candidate_sha'], SHA)

    def test_no_release_draft_means_no_download_or_publication(self):
        self.releases = []
        with patch('scripts.ci.artifacts.download') as download:
            self.assertIsNone(p.prepare(self.authority, 99, 77, self.output))
            download.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_foreign_tag_failed_check_and_tampered_zip_never_reach_registry(self):
        for mutation in ('tag', 'job', 'zip'):
            with self.subTest(mutation=mutation):
                self.setUp()
                if mutation == 'tag': self.tag_sha = 'b' * 40
                elif mutation == 'job': self.fixture.authority.jobs[0]['conclusion'] = 'failure'
                else: self.candidate += b'tampered'
                with patch('scripts.ci.registry.Registry') as registry:
                    with self.assertRaises(v.VerificationError): self.prepare()
                    registry.assert_not_called()
