"""Regression checks for baseline Sonar authority and protected publication."""
import copy
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
BASELINE_REF = '${{ github.event.pull_request.base.sha || github.sha }}'


def workflow(name):
    return yaml.safe_load((ROOT / '.github/workflows' / name).read_text())


class WorkflowTrustTests(unittest.TestCase):
    def assert_baseline_helpers(self, data):
        for name, modules in {
            'cloud': ('sonar_gate', 'sonar_community'),
            'community': ('sonar_community',),
            'required': ('sonar_aggregate',),
        }.items():
            steps = data['jobs'][name]['steps']
            checkouts = [step for step in steps if step.get('uses', '').startswith('actions/checkout@')]
            self.assertTrue(any(step['with'].get('path') == '_tmp/trusted' and
                                step['with'].get('ref') == BASELINE_REF and
                                step['with'].get('persist-credentials') is False for step in checkouts))
            for module in modules:
                calls = [step['run'] for step in steps if 'run' in step and
                         'scripts.ci.' + module in step['run']]
                self.assertTrue(calls, module)
                for call in calls:
                    argv = shlex.split(call)
                    self.assertEqual(argv[:3], ['python', '-I', '-c'])
                    self.assertIn("sys.path.insert(0, '_tmp/trusted')", argv[3])
                    self.assertIn("runpy.run_module('scripts.ci." + module + "'", argv[3])

    def test_reusable_candidate_checkout_uses_event_subject_not_requested_input(self):
        for name in ('tests.yaml', 'codeql.yaml', 'sonar.yaml'):
            for job in workflow(name)['jobs'].values():
                for step in job['steps']:
                    if step.get('uses', '').startswith('actions/checkout@') and step.get('with', {}).get('path') != '_tmp/trusted':
                        with self.subTest(workflow=name, job=job.get('name')):
                            self.assertEqual(step['with']['ref'], '${{ github.sha }}')
                            self.assertFalse(step['with']['persist-credentials'])

    def test_actual_checkout_guards_reject_foreign_event_before_next_command(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '-q', str(root)], check=True, capture_output=True)
            subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false',
                            '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                            'commit', '--allow-empty', '-qm', 'test: disposable guard subject'],
                           cwd=root, check=True, capture_output=True)
            sha = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
            for name in ('tests.yaml', 'codeql.yaml', 'sonar.yaml'):
                for key, job in workflow(name)['jobs'].items():
                    guards = [step['run'] for step in job['steps']
                              if step.get('name') in ('Verify exact checkout identity', 'Verify exact source')]
                    if not guards:
                        continue
                    with self.subTest(workflow=name, job=key):
                        marker = root / 'candidate-command-ran'
                        script = guards[0] + '\nprintf checked > candidate-command-ran\n'
                        environment = {**os.environ, 'CANDIDATE_SHA': sha, 'GITHUB_SHA': sha}
                        legitimate = subprocess.run(['sh', '-eu', '-c', script], cwd=root,
                            env=environment, capture_output=True, check=False)
                        self.assertEqual(legitimate.returncode, 0)
                        self.assertEqual(marker.read_bytes(), b'checked')
                        marker.unlink()
                        environment['GITHUB_SHA'] = '0' * 40
                        mismatch = subprocess.run(['sh', '-eu', '-c', script], cwd=root,
                            env=environment, capture_output=True, check=False)
                        self.assertNotEqual(mismatch.returncode, 0)
                        self.assertFalse(marker.exists())

    def test_sonar_helpers_are_baseline_owned_in_both_scanners_and_gate(self):
        self.assert_baseline_helpers(workflow('sonar.yaml'))

    def test_historical_candidate_helpers_fail_the_baseline_policy(self):
        historical = copy.deepcopy(workflow('sonar.yaml'))
        for job in historical['jobs'].values():
            job['steps'] = [step for step in job['steps']
                            if step.get('with', {}).get('path') != '_tmp/trusted']
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'historical-sonar.yaml'
            path.write_text(yaml.safe_dump(historical))
            with self.assertRaises(AssertionError):
                self.assert_baseline_helpers(yaml.safe_load(path.read_text()))

    def test_isolated_gate_refuses_failed_scan_despite_candidate_module_shadowing(self):
        step = next(step for step in workflow('sonar.yaml')['jobs']['required']['steps'] if 'run' in step)
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory)
            trusted = candidate / '_tmp/trusted/scripts/ci'
            malicious = candidate / 'scripts/ci'
            for package in (trusted, malicious):
                package.mkdir(parents=True)
                (package / '__init__.py').write_text('')
                (package.parent / '__init__.py').write_text('')
            (trusted / 'sonar_aggregate.py').write_bytes((ROOT / 'scripts/ci/sonar_aggregate.py').read_bytes())
            (malicious / 'sonar_aggregate.py').write_text("raise SystemExit(0)\n")
            environment = {**os.environ, 'PYTHONPATH': str(candidate),
                           'SONAR_EVENT_NAME': 'pull_request', 'SONAR_TRUSTED_PR': 'false',
                           'SONAR_COVERAGE_RESULT': 'success', 'SONAR_CLOUD_RESULT': 'skipped',
                           'SONAR_COMMUNITY_RESULT': 'failure', 'SONAR_REPORT_PRESENT': 'true'}
            command = shlex.split(step['run'])
            command[0] = sys.executable
            result = subprocess.run(command, cwd=candidate, env=environment, capture_output=True, text=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Required Sonar scan or report is missing or unsuccessful', result.stderr)
            historical = subprocess.run([sys.executable, '-m', 'scripts.ci.sonar_aggregate'],
                                        cwd=candidate, env=environment, capture_output=True, check=False)
            self.assertEqual(historical.returncode, 0)

    def test_community_bootstrap_cannot_import_candidate_python_modules(self):
        bootstrap = next(step for step in workflow('sonar.yaml')['jobs']['community']['steps']
                         if step.get('name') == 'Wait and establish local administrative credentials')
        self.assertTrue(bootstrap['run'].startswith("python -I - <<'PYCODE'"))

    def test_pull_requests_cannot_route_to_cloud_or_receive_cloud_token(self):
        sonar = workflow('sonar.yaml')
        self.assertIn("github.event_name != 'pull_request'", sonar['jobs']['cloud']['if'])
        self.assertIn("github.ref == 'refs/heads/main'", sonar['jobs']['cloud']['if'])
        self.assertEqual(sonar['jobs']['community']['if'], "github.event_name == 'pull_request'")
        self.assertEqual(sonar['jobs']['required']['steps'][-1]['env']['SONAR_TRUSTED_PR'], 'false')
        token = workflow('ci.yaml')['jobs']['sonar']['secrets']['SONAR_TOKEN']
        self.assertEqual(token, "${{ github.event_name != 'pull_request' && secrets.SONAR_TOKEN || '' }}")
        diagnostics = next(step for step in sonar['jobs']['community']['steps']
                           if step.get('name') == 'Retain controlled diagnostics')
        self.assertIn('_tmp/community-work/analysis/report-task.txt', diagnostics['with']['path'].splitlines())

    def test_release_receivers_use_protected_revision_without_candidate_execution(self):
        release = workflow('release.yaml')
        event = release.get('on', release.get(True))
        self.assertEqual(event['workflow_run'], {'workflows': ['CI'], 'types': ['completed'], 'branches': ['main']})
        verify = release['jobs']['verify']
        self.assertEqual(verify['permissions'], {'contents': 'write', 'actions': 'read'})
        self.assertEqual(verify['environment'], 'release')
        self.assertIn("github.ref == 'refs/heads/main'", verify['if'])
        self.assertIn("github.event.workflow_run.conclusion == 'success'", verify['if'])
        for name in ('verify', 'publish'):
            job = release['jobs'][name]
            checkout = next(step for step in job['steps'] if step.get('uses', '').startswith('actions/checkout@'))
            self.assertEqual(checkout['with'], {'ref': '${{ github.workflow_sha }}', 'persist-credentials': False})
            runs = [step for step in job['steps'] if 'run' in step]
            self.assertEqual(len(runs), 1)
            self.assertTrue(runs[0]['run'].startswith('python -m scripts.ci.publish --run-id'))
            self.assertEqual(runs[0]['env']['PRODUCER_RUN_ID'], '${{ github.event.workflow_run.id || inputs.run_id }}')
            self.assertEqual(runs[0]['env']['CI_WORKFLOW_ID'], '${{ vars.CI_WORKFLOW_ID }}')
            self.assertFalse(any('download-artifact@' in step.get('uses', '') for step in job['steps']))
        self.assertIn('--publish', release['jobs']['publish']['steps'][-1]['run'])
        self.assertNotIn('--publish', verify['steps'][-1]['run'])


if __name__ == '__main__':
    unittest.main()
