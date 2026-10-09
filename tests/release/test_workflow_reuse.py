"""Contract checks for reusable candidate validation and trusted report upload."""
from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
CHECKOUT = 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1'
DOWNLOAD = 'actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333'
UPLOAD = 'actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9'


def workflow(name):
    return yaml.safe_load((ROOT / '.github/workflows' / name).read_text())


class WorkflowReuseTests(unittest.TestCase):
    def test_reusable_tests_preserve_exact_ref_native_checks_and_no_secrets(self):
        data = workflow('tests.yaml')
        event = data.get('on', data.get(True))
        self.assertEqual(set(event), {'workflow_call'})
        self.assertTrue(event['workflow_call']['inputs']['ref']['required'])
        self.assertEqual(data['env']['CANDIDATE_SHA'], '${{ inputs.ref }}')
        expected = {'static-amd64', 'static-arm64', 'assemble', 'rust', 'auth-ingress',
                    'ssh-policy', 'persistence', 'mqtt', 'lifecycle', 'ui',
                    'distro-containers', 'addon-schema', 'cargo-audit', 'secrets',
                    'image-scan-amd64', 'image-scan-arm64', 'workflow-lint', 'docs'}
        self.assertEqual(set(data['jobs']), expected)
        self.assertEqual(data['jobs']['static-arm64']['runs-on'], 'ubuntu-24.04-arm')
        self.assertEqual(data['jobs']['static-amd64']['runs-on'], 'ubuntu-24.04')
        for job in data['jobs'].values():
            self.assertNotIn('if', job)
            steps = job['steps']
            checkout = next(step for step in steps if step.get('uses') == CHECKOUT)
            self.assertEqual(checkout['with']['ref'], '${{ github.sha }}')
            self.assertFalse(checkout['with']['persist-credentials'])
            self.assertTrue(any("['git', 'rev-parse', 'HEAD']" in step.get('run', '') for step in steps))
            self.assertNotIn('${{ secrets.', yaml.safe_dump(job))
            self.assertNotIn('packages: write', yaml.safe_dump(job))
        for arch in ('amd64', 'arm64'):
            commands = yaml.safe_dump(data['jobs']['static-' + arch]['steps'])
            self.assertIn('native-build.sh ' + arch, commands)
        same_run = yaml.safe_dump(data['jobs']['assemble']['steps'])
        self.assertIn(DOWNLOAD, same_run)
        for arch in ('amd64', 'arm64'):
            scan = data['jobs']['image-scan-' + arch]
            commands = '\n'.join(step.get('run', '') for step in scan['steps'])
            self.assertIn('--exit-code 0 --format sarif', commands)
            self.assertIn('--exit-code 1 --format json', commands)
            select = 'scripts.ci.trivy_gate select --candidate _tmp/subject --architecture ' + arch
            verify = 'scripts.ci.trivy_gate verify --candidate _tmp/subject --architecture ' + arch
            receipt = 'scripts.ci.producer report --name image-scan-' + arch
            self.assertIn(select, commands)
            self.assertIn('$PWD/_tmp/scan-' + arch + ',target=/candidate,readonly', commands)
            self.assertNotIn('$PWD/_tmp/subject/oci,target=/candidate', commands)
            self.assertLess(commands.index(select), commands.index('docker run'))
            self.assertLess(commands.index(verify), commands.index(receipt))
        self.assertNotIn('scripts.ci.artifacts', yaml.safe_dump(data))

    def test_failure_logs_and_source_checks_are_always_preserved(self):
        jobs = workflow('tests.yaml')['jobs']
        distro = jobs['distro-containers']['steps']
        captures = [step for step in distro if step.get('uses') == UPLOAD]
        self.assertTrue(any(step.get('if') == 'always()' and
                            '_tmp/host-platform' in step['with']['path'] for step in captures))
        self.assertIn('mkdocs build --strict', yaml.safe_dump(jobs['docs']))
        self.assertIn('actionlint@sha256:', yaml.safe_dump(jobs['workflow-lint']))
        self.assertIn('gitleaks dir', yaml.safe_dump(jobs['secrets']))

    def test_codeql_candidate_is_readonly_and_only_trusted_job_uploads(self):
        data = workflow('codeql.yaml')
        self.assertEqual(data['permissions'].get('contents'), 'read')
        self.assertNotIn('security-events', data['permissions'])
        gate = data['jobs']['codeql']
        self.assertNotIn('security-events', gate.get('permissions', {}))
        analyze = next(step for step in gate['steps'] if step.get('uses', '').endswith('/analyze@2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2'))
        self.assertFalse(analyze['with']['upload'])
        self.assertIn('scripts.ci.security_gate', yaml.safe_dump(gate))
        self.assertTrue(any(step.get('if') == 'always()' and step.get('uses') == UPLOAD for step in gate['steps']))
        upload = data['jobs']['upload']
        self.assertIn("github.event_name != 'pull_request'", upload['if'])
        self.assertIn("github.ref == 'refs/heads/main'", upload['if'])
        self.assertEqual(upload['permissions']['security-events'], 'write')
        self.assertFalse(any('run' in step for step in upload['steps']))

    def test_scheduled_security_covers_lockfile_and_both_immutable_platforms(self):
        data = workflow('security.yaml')
        event = data.get('on', data.get(True))
        self.assertIn('schedule', event)
        job = data['jobs']['published-image']
        commands = '\n'.join(step.get('run', '') + step.get('uses', '') for step in job['steps'])
        self.assertIn('scripts.ci.published_subject', commands)
        self.assertIn('amd64 arm64', commands)
        self.assertIn('Cargo.lock', commands)
        self.assertIn('--pkg-types library', commands)
        self.assertIn('--exit-code 1', commands)
        self.assertNotIn('--ignore-unfixed', commands)
        self.assertIn('/upload-sarif@', commands)
        self.assertTrue(any(step.get('if') == 'always()' and step.get('uses') == UPLOAD for step in job['steps']))


if __name__ == '__main__':
    unittest.main()
