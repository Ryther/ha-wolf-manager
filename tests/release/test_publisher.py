"""End-to-end protected receiver refusal tests with independent API fixtures."""
import base64
import io
import os
import urllib.parse
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

    def publishing_fixture(self, mutate=None, native_omission=False):
        prepared = self.prepare()
        original_get = self.authority.get_json
        self.authority.get_json = lambda path: [] if path.endswith('/assets?per_page=100') else original_get(path)
        writes = []
        def write(method, path, value=None, raw=None):
            writes.append((method, path, value))
            if method == 'POST':
                name = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)['name'][0]
                return {'name': name, 'size': len(raw), 'digest': 'sha256:' + v.sha256(raw)}
            self.assertEqual(method, 'PATCH')
            response = {'id': 1, 'tag_name': 'v0.1.0', 'target_commitish': SHA,
                        'draft': False, 'prerelease': False}
            if native_omission:
                # Native API observed omission: a draft update without tag_name loses its association.
                response['tag_name'] = value.get('tag_name', 'untagged-native-omission')
                response['target_commitish'] = value.get('target_commitish', SHA)
            return mutate(response) if mutate else response
        self.authority.write = write
        return prepared, writes

    def run_publish(self, prepared):
        with patch.dict(os.environ, {'GITHUB_ACTOR': 'fixture'}), patch.object(p.r, 'Registry'), \
                patch.object(p.r, 'publish', return_value=self.fixture.receipt['image']['index_digest']), \
                patch.object(p.r, 'verify_public'):
            return p.publish(self.authority, prepared, self.output)

    def test_final_transition_preserves_explicit_tag_and_exact_commit_despite_native_omission(self):
        prepared, writes = self.publishing_fixture(native_omission=True)
        publication = self.run_publish(prepared)
        method, path, value = writes[-1]
        self.assertEqual(method, 'PATCH')
        self.assertEqual(path, '/repos/' + REPO + '/releases/1')
        self.assertEqual(value.get('tag_name'), 'v0.1.0')
        self.assertEqual(value.get('target_commitish'), SHA)
        self.assertIs(value['draft'], False)
        self.assertIs(value['prerelease'], False)
        self.assertEqual(publication['candidate_sha'], SHA)

    def test_final_transition_refuses_git_tag_change_even_with_valid_api_metadata(self):
        def move_tag(response):
            self.tag_sha = 'b' * 40
            return response
        prepared, writes = self.publishing_fixture(move_tag)
        self.assertEqual(self.tag_sha, SHA)
        with self.assertRaisesRegex(v.VerificationError, '^publisher_published_tag$'):
            self.run_publish(prepared)
        self.assertEqual(writes[-1][0], 'PATCH')
        self.assertEqual(writes[-1][2]['target_commitish'], SHA)
        self.assertEqual(self.tag_sha, 'b' * 40)

    def test_final_transition_refuses_unconfirmed_or_changed_api_release_identity(self):
        mutations = {
            'id': lambda response: {**response, 'id': 2},
            'bool-id': lambda response: {**response, 'id': True},
            'float-id': lambda response: {**response, 'id': 1.0},
            'tag': lambda response: {**response, 'tag_name': 'untagged-native-omission'},
            'target': lambda response: {**response, 'target_commitish': 'b' * 40},
            'draft': lambda response: {**response, 'draft': True},
            'prerelease': lambda response: {**response, 'prerelease': True},
            'numeric-draft': lambda response: {**response, 'draft': 0},
            'numeric-prerelease': lambda response: {**response, 'prerelease': 0},
            'missing': lambda response: {},
            'null': lambda response: None,
        }
        for name, mutate in mutations.items():
            with self.subTest(mutation=name):
                self.setUp()
                prepared, writes = self.publishing_fixture(mutate)
                with self.assertRaises(v.VerificationError): self.run_publish(prepared)
                self.assertEqual(writes[-1][0], 'PATCH')

    def test_receiver_checks_full_original_zip_and_all_independent_jobs(self):
        result = self.prepare()
        self.assertEqual(result[0].candidate_sha, SHA)
        self.assertEqual((self.output / '42.zip').read_bytes(), self.candidate)
        self.assertEqual(v.json_bytes((self.output / 'verification.json').read_bytes())['candidate_sha'], SHA)

    def test_receiver_refuses_old_workflow_and_unfinished_attempt_before_download(self):
        for changes in [
            {'path': '.github/workflows/candidate.yaml@main'},
            {'status': 'in_progress', 'conclusion': None},
            {'run_attempt': 0},
            {'run_attempt': True},
        ]:
            with self.subTest(changes=changes), patch.dict(self.fixture.authority.run, changes), \
                    patch('scripts.ci.artifacts.download') as download:
                with self.assertRaises(v.VerificationError):
                    p.prepare(self.authority, 99, 77, self.output)
                download.assert_not_called()
                self.assertFalse(self.output.exists())

    def test_receiver_refuses_missing_required_reusable_check_before_publication(self):
        for name in ('docs', 'workflow-lint', 'commits'):
            with self.subTest(name=name):
                self.setUp()
                required_name = candidate_fixture.JOB_NAMES[name]
                self.fixture.authority.jobs[:] = [j for j in self.fixture.authority.jobs
                                                  if j['name'] != required_name]
                with patch('scripts.ci.registry.Registry') as registry:
                    with self.assertRaisesRegex(v.VerificationError, 'missing_authoritative_check'):
                        self.prepare()
                    registry.assert_not_called()

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
