"""Producer and protected publisher boundary tests; all authority is simulated."""
import copy
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

from scripts.ci import producer as p
from scripts.ci import verify_candidate as v
from test_candidate import fixture, encoded, SHA


class ProducerTests(unittest.TestCase):
    def test_assembled_host_archives_preserve_both_license_texts(self):
        files, _, _, _, receipt = fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'root'
            licenses = {'licenses/HA-Wolf-Manager.txt': b'Synthetic MIT license\n',
                        'licenses/rumqttc.txt': b'Synthetic Apache-2.0 license\n'}
            p.write_tree(root, {'LICENSE': licenses['licenses/HA-Wolf-Manager.txt'],
                               'vendor/rumqttc/LICENSE': licenses['licenses/rumqttc.txt'],
                               'installer/install.sh': b'#!/bin/sh\nexit 0\n',
                               'installer/templates/policy.json': b'{}'})
            platforms = []
            for platform in receipt['image']['platforms']:
                architecture = platform['architecture']
                path = root / architecture
                layout = {name[4:]: data for name, data in files.items() if name.startswith('oci/')}
                layout['index.json'] = encoded({'schemaVersion': 2, 'manifests': [{
                    'mediaType': v.MANIFEST_TYPE, 'digest': platform['digest'],
                    'size': len(files['oci/blobs/sha256/' + platform['digest'][7:]]),
                    'platform': {'os': 'linux', 'architecture': architecture}}]})
                p.write_tree(path / 'oci', layout)
                triple = 'x86_64-unknown-linux-musl' if architecture == 'amd64' else 'aarch64-unknown-linux-musl'
                with tarfile.open(fileobj=io.BytesIO(files['wolf-manager-host-v0.1.0-' + triple + '.tar.gz'])) as tar:
                    (path / 'wolf-manager-host').write_bytes(tar.extractfile('bin/wolf-manager-host').read())
                platforms.append(path)
            output = root / 'output'
            with mock.patch.object(p, 'metadata', return_value='0.1.0'):
                p.assemble(root, *platforms, output)
            for triple in v.TRIPLES:
                with tarfile.open(output / ('wolf-manager-host-v0.1.0-' + triple + '.tar.gz')) as tar:
                    self.assertEqual(set(tar.getnames()), {'bin/wolf-manager-host', *licenses})
                    for name, content in licenses.items():
                        self.assertEqual(tar.extractfile(name).read(), content)
                        self.assertEqual(tar.getmember(name).mode, 0o444)

    def test_archives_are_reproducible_and_ignore_source_metadata(self):
        entries = {'bin/wolf-manager-host': (b'binary', 0o755)}
        self.assertEqual(p.archive(entries), p.archive(entries))
        with tarfile.open(fileobj=io.BytesIO(p.archive(entries))) as tar:
            member = tar.getmembers()[0]
            self.assertEqual((member.uid, member.gid, member.mtime), (0, 0, 0))
            self.assertEqual(member.mode, 0o755)

    def test_archive_rejects_escaping_paths_and_unsafe_modes(self):
        for path, mode in [('../bad', 0o644), ('/bad', 0o644), ('ok', 0o4755)]:
            with self.subTest(path=path, mode=mode):
                with self.assertRaises(v.VerificationError):
                    p.archive({path: (b'bytes', mode)})

    def test_merge_preserves_exact_platform_manifest_and_layer_bytes(self):
        files, _, _, _, receipt = fixture()
        inputs = []
        for platform in receipt['image']['platforms']:
            descriptor = {'mediaType': v.MANIFEST_TYPE, 'digest': platform['digest'],
                          'size': len(files['oci/blobs/sha256/' + platform['digest'][7:]]),
                          'platform': {'os': 'linux', 'architecture': platform['architecture']}}
            layout = {k[4:]: value for k, value in files.items() if k.startswith('oci/')}
            layout['index.json'] = encoded({'schemaVersion': 2, 'manifests': [descriptor]})
            inputs.append(layout)
        output, image = p.merge_oci(inputs, '0.1.0')
        for name, data in files.items():
            if name.startswith('oci/blobs/'):
                self.assertEqual(output[name], data)
        v.verify_oci(output, image)
        self.assertEqual(image['platforms'], receipt['image']['platforms'])
        self.assertEqual(p.merge_oci(list(reversed(inputs)), '0.1.0'), (output, image))

    def test_merge_rejects_duplicate_foreign_platform_and_corrupt_blob(self):
        files, _, _, _, receipt = fixture()
        descriptor = {'mediaType': v.MANIFEST_TYPE, 'digest': receipt['image']['platforms'][0]['digest'],
                      'size': 1, 'platform': {'os': 'linux', 'architecture': 'amd64'}}
        layout = {k[4:]: value for k, value in files.items() if k.startswith('oci/')}
        layout['index.json'] = encoded({'schemaVersion': 2, 'manifests': [descriptor]})
        with self.assertRaises(v.VerificationError):
            p.merge_oci([layout, layout], '0.1.0')

    def test_receipt_cannot_claim_missing_checks_or_artifact_digest(self):
        files, expected, _, _, receipt = fixture()
        reports = {name: {'candidate_sha': SHA, 'result': 'success', 'scope': name}
                   for name in v.REQUIRED_CHECKS}
        artifact = {'id': 42, 'name': 'release-candidate-' + SHA,
                    'digest': 'sha256:' + 'b' * 64, 'size_in_bytes': 99}
        result = p.receipt(files, reports, receipt['image'], expected, artifact)
        self.assertEqual({x['name'] for x in result['checks']}, v.REQUIRED_CHECKS)
        for mutation in ('missing', 'failed', 'wrong_sha', 'missing_digest', 'wrong_name'):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(reports); metadata = dict(artifact)
                if mutation == 'missing': changed.pop('rust')
                elif mutation == 'failed': changed['rust']['result'] = 'failure'
                elif mutation == 'wrong_sha': changed['rust']['candidate_sha'] = 'c' * 40
                elif mutation == 'missing_digest': metadata.pop('digest')
                else: metadata['name'] = 'attacker-selected'
                with self.assertRaises(v.VerificationError):
                    p.receipt(files, changed, receipt['image'], expected, metadata)


class PublisherPolicyTests(unittest.TestCase):
    def test_only_successful_main_owned_allowlisted_run_is_eligible(self):
        _, _, run, _, _ = fixture()
        self.assertEqual(p.publisher_identity(run, 77, '.github/workflows/ci.yaml'), SHA)
        for key, value in [('event', 'pull_request'), ('head_branch', 'feature'),
                           ('conclusion', 'failure'), ('status', 'in_progress'), ('run_attempt', 0),
                           ('run_attempt', True), ('workflow_id', 88),
                           ('path', '.github/workflows/other.yaml@main'),
                           ('pull_requests', [{}])]:
            changed = copy.deepcopy(run); changed[key] = value
            with self.subTest(key=key), self.assertRaises(v.VerificationError):
                p.publisher_identity(changed, 77, '.github/workflows/ci.yaml')
        run['head_repository']['fork'] = True
        with self.assertRaises(v.VerificationError):
            p.publisher_identity(run, 77, '.github/workflows/ci.yaml')

    def test_release_metadata_must_bind_tag_version_commit_and_owned_draft(self):
        release = {'id': 1, 'draft': True, 'prerelease': False, 'tag_name': 'v0.1.0',
                   'target_commitish': SHA, 'upload_url':
                   'https://uploads.github.com/repos/Ryther/ha-wolf-manager/releases/1/assets{?name,label}'}
        self.assertEqual(p.release_identity(release, '0.1.0', SHA, SHA), 1)
        for change in ({'draft': False}, {'prerelease': True}, {'tag_name': 'v0.2.0'},
                       {'upload_url': 'https://attacker.invalid/upload'}):
            with self.subTest(change=change), self.assertRaises(v.VerificationError):
                p.release_identity(dict(release, **change), '0.1.0', SHA, SHA)
        with self.assertRaises(v.VerificationError):
            p.release_identity(release, '0.1.0', SHA, 'b' * 40)

    def test_sonar_gate_must_bind_exact_revision_and_project(self):
        analysis = {'key': 'analysis1', 'revision': SHA}
        gate = {'projectStatus': {'status': 'OK'}}
        self.assertTrue(p.sonar_identity(analysis, gate, SHA))
        for analysis, gate in [({'key': 'x', 'revision': 'b' * 40}, gate),
                               (analysis, {'projectStatus': {'status': 'ERROR'}}),
                               ({'revision': SHA}, gate)]:
            with self.assertRaises(v.VerificationError):
                p.sonar_identity(analysis, gate, SHA)
