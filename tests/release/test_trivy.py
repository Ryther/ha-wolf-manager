"""Image scanner identity, unchanged OCI bytes and bounded private IO."""
import copy
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from scripts.ci import verify_candidate as v
from scripts.ci import trivy_gate as t
from test_candidate import fixture, encoded


class TrivyTests(unittest.TestCase):
    def setUp(self):
        self.files, _, _, _, self.receipt = fixture()
        self.image = self.receipt['image']

    def report(self, architecture):
        _, config_digest = t.selected(self.files, self.image, architecture)
        return {'SchemaVersion': 2, 'ArtifactType': 'container_image',
                'Metadata': {'ImageID': config_digest,
                             'ImageConfig': {'architecture': architecture, 'os': 'linux'}}}

    def test_select_preserves_exact_selected_graph_and_original_layout(self):
        original = copy.deepcopy(self.files)
        for architecture in ('amd64', 'arm64'):
            files = t.selector(self.files, self.image, architecture)
            index = v.json_bytes(files['index.json'])
            self.assertEqual(len(index['manifests']), 1)
            descriptor = index['manifests'][0]
            self.assertEqual(descriptor['platform'], {'os': 'linux', 'architecture': architecture})
            manifest = v.json_bytes(files['blobs/sha256/' + descriptor['digest'][7:]])
            for item in [descriptor, manifest['config'], *manifest['layers']]:
                name = 'blobs/sha256/' + item['digest'][7:]
                self.assertEqual(files[name], original['oci/' + name])
            self.assertEqual(self.files, original)
        with self.assertRaises(v.VerificationError): t.selector(self.files, self.image, 'ppc64le')

    def test_exact_identity_and_authentic_empty_results_accepted(self):
        for arch in ('amd64', 'arm64'):
            report = self.report(arch)
            t.verify_report(self.files, self.image, arch, encoded(report))
            report['Results'] = []
            t.verify_report(self.files, self.image, arch, encoded(report))

    def test_missing_malformed_or_foreign_identity_refused(self):
        for mutation in ('amd-in-arm', 'digest', 'os', 'metadata', 'imageconfig', 'version', 'type', 'results', 'entry', 'vulnerabilities', 'severity', 'duplicate-json'):
            with self.subTest(mutation=mutation):
                report = self.report('arm64')
                if mutation == 'amd-in-arm': report = self.report('amd64')
                elif mutation == 'digest': report['Metadata']['ImageID'] = 'sha256:' + '0' * 64
                elif mutation == 'os': report['Metadata']['ImageConfig']['os'] = 'windows'
                elif mutation == 'metadata': del report['Metadata']
                elif mutation == 'imageconfig': report['Metadata']['ImageConfig'] = None
                elif mutation == 'version': report['SchemaVersion'] = True
                elif mutation == 'type': report['ArtifactType'] = 'filesystem'
                elif mutation == 'results': report['Results'] = {}
                elif mutation == 'entry': report['Results'] = [None]
                elif mutation == 'vulnerabilities': report['Results'] = [{'Vulnerabilities': None}]
                elif mutation == 'severity': report['Results'] = [{'Vulnerabilities': [{'Severity': 'unknown'}]}]
                raw = encoded(report)
                if mutation == 'duplicate-json': raw = b'{"Metadata":{},"Metadata":{}}'
                with self.assertRaises(v.VerificationError): t.verify_report(self.files, self.image, 'arm64', raw)

    def test_high_and_critical_refused_lower_severities_preserved(self):
        for severity in ('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
            report = self.report('amd64')
            report['Results'] = [{'Vulnerabilities': [{'Severity': severity}]}]
            if severity in ('HIGH', 'CRITICAL'):
                with self.assertRaises(v.VerificationError): t.verify_report(self.files, self.image, 'amd64', encoded(report))
            else: t.verify_report(self.files, self.image, 'amd64', encoded(report))

    def test_corrupt_graph_and_oversized_report_refused(self):
        selected, _ = t.selected(self.files, self.image, 'arm64')
        self.files['oci/blobs/sha256/' + selected['digest'][7:]] += b'corruption'
        with self.assertRaises(v.VerificationError): t.selector(self.files, self.image, 'arm64')
        with self.assertRaises(v.VerificationError): t.verify_report({}, {}, 'arm64', b' ' * (t.MAX_REPORT + 1))

    def test_actual_cli_select_and_verify_preserve_candidate_and_refuse_unsafe_output(self):
        with tempfile.TemporaryDirectory(dir='_tmp') as directory:
            root = Path(directory).relative_to(Path.cwd())
            candidate = root / 'candidate'
            for name, data in self.files.items():
                path = candidate / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
            original = {str(p.relative_to(candidate)): p.read_bytes() for p in candidate.rglob('*') if p.is_file()}
            def run(*args):
                return subprocess.run([sys.executable, '-m', 'scripts.ci.trivy_gate', *args],
                                      capture_output=True, timeout=10)
            selector = root / 'selector'
            selected = run('select', '--candidate', str(candidate), '--architecture', 'arm64', '--output', str(selector))
            self.assertEqual(selected.returncode, 0, selected.stderr)
            self.assertEqual(v.json_bytes((selector / 'index.json').read_bytes())['manifests'][0]['platform']['architecture'], 'arm64')
            self.assertEqual({str(p.relative_to(candidate)): p.read_bytes() for p in candidate.rglob('*') if p.is_file()}, original)
            report = root / 'report.json'; report.write_bytes(encoded(self.report('arm64')))
            accepted = run('verify', '--candidate', str(candidate), '--architecture', 'arm64', '--report', str(report))
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            report.write_bytes(encoded(self.report('amd64')))
            refused = run('verify', '--candidate', str(candidate), '--architecture', 'arm64', '--report', str(report))
            self.assertNotEqual(refused.returncode, 0)
            victim = root / 'victim'; victim.mkdir(); (victim / 'sentinel').write_bytes(b'unchanged')
            (root / 'alias').symlink_to('victim', target_is_directory=True)
            for output in (root / 'alias' / 'child', root / '..' / 'escaped', root.resolve() / 'absolute', selector):
                refused = run('select', '--candidate', str(candidate), '--architecture', 'arm64', '--output', str(output))
                self.assertNotEqual(refused.returncode, 0)
            self.assertEqual((victim / 'sentinel').read_bytes(), b'unchanged')
            self.assertEqual(set(victim.iterdir()), {victim / 'sentinel'})

    def test_descriptor_reader_refuses_aliases_unsafe_metadata_and_special_files(self):
        with tempfile.TemporaryDirectory(dir='_tmp') as directory:
            root = Path(directory).relative_to(Path.cwd())
            for name, data in self.files.items():
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
            self.assertEqual(t.read_candidate(root)['image.json'], encoded(self.image))
            victim = root / 'image.json'
            for mutation in ('symlink', 'hardlink', 'mode', 'fifo', 'parent-link'):
                with self.subTest(mutation=mutation):
                    old = victim.read_bytes()
                    if mutation == 'mode': victim.chmod(0o666)
                    else:
                        victim.unlink()
                        if mutation == 'symlink': victim.symlink_to('SHA256SUMS')
                        elif mutation == 'hardlink': os.link(root / 'SHA256SUMS', victim)
                        elif mutation == 'fifo': os.mkfifo(victim)
                        else:
                            victim.write_bytes(old)
                            (root / 'oci').rename(root / 'real-oci'); (root / 'oci').symlink_to('real-oci')
                    with self.assertRaises(v.VerificationError): t.read_candidate(root)
                    if mutation == 'parent-link':
                        (root / 'oci').unlink(); (root / 'real-oci').rename(root / 'oci')
                    else: victim.unlink(); victim.write_bytes(old)

    def test_actual_cli_select_then_verify_both_platforms_and_refuse_cross_scan(self):
        import io
        import json
        from unittest.mock import patch
        previous = Path.cwd()
        self.addCleanup(os.chdir, previous)
        with tempfile.TemporaryDirectory() as directory:
            os.chdir(directory)
            Path('_tmp').mkdir(mode=0o700)
            source = Path('_tmp/candidate'); source.mkdir(mode=0o700)
            for name, data in self.files.items():
                if name.startswith('oci/') or name == 'image.json':
                    target = source / name; target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(data)
            original = {path: path.read_bytes() for path in source.rglob('*') if path.is_file()}
            for architecture in ('amd64', 'arm64'):
                output = Path('_tmp/' + architecture)
                with patch.object(sys, 'argv', ['trivy_gate', 'select', '--candidate', str(source),
                    '--architecture', architecture, '--output', str(output)]):
                    t.main()
                self.assertEqual(json.loads((output / 'index.json').read_bytes())['manifests'][0]['platform']['architecture'], architecture)
                Path('_tmp/reports').mkdir(mode=0o700, exist_ok=True)
                report = Path('_tmp/reports/report-' + architecture + '.json')
                report.write_bytes(encoded(self.report(architecture)))
                argv = ['trivy_gate', 'verify', '--candidate', str(source), '--architecture', architecture, '--report', str(report)]
                with patch.object(sys, 'argv', argv), patch('sys.stdout', new_callable=io.StringIO) as stdout:
                    t.main()
                self.assertEqual(json.loads(stdout.getvalue())['architecture'], architecture)
                report.write_bytes(encoded(self.report('arm64' if architecture == 'amd64' else 'amd64')))
                with patch.object(sys, 'argv', argv), patch('sys.stderr', new_callable=io.StringIO) as stderr:
                    with self.assertRaises(SystemExit) as refused: t.main()
                self.assertEqual(refused.exception.code, 1)
                self.assertIn('No candidate bytes were changed', stderr.getvalue())
            self.assertEqual({path: path.read_bytes() for path in original}, original)
