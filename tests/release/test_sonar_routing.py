"""Required Sonar routing and token destinations refuse ambiguous authority."""
import os
from pathlib import Path
import runpy
import secrets
import tempfile
import unittest
from unittest.mock import patch
from scripts.ci import sonar_gate as s, verify_candidate as v


class SonarRoutingTests(unittest.TestCase):
    def aggregate(self, **changes):
        environment = {'SONAR_EVENT_NAME': 'workflow_dispatch', 'SONAR_TRUSTED_PR': 'false',
                       'SONAR_COVERAGE_RESULT': 'success', 'SONAR_CLOUD_RESULT': 'success',
                       'SONAR_COMMUNITY_RESULT': 'skipped', 'SONAR_REPORT_PRESENT': 'true'}
        environment.update(changes)
        with patch.dict(os.environ, environment):
            runpy.run_module('scripts.ci.sonar_aggregate', run_name='__main__')

    def test_dispatch_cloud_and_untrusted_pr_community_have_one_required_scanner(self):
        self.aggregate()
        self.aggregate(SONAR_EVENT_NAME='pull_request', SONAR_CLOUD_RESULT='skipped',
                       SONAR_COMMUNITY_RESULT='success')
        self.aggregate(SONAR_EVENT_NAME='pull_request', SONAR_TRUSTED_PR='true')

    def test_wrong_missing_or_duplicate_scanner_never_satisfies_required_gate(self):
        for changes in [{'SONAR_EVENT_NAME': 'unknown'}, {'SONAR_COVERAGE_RESULT': 'skipped'},
                        {'SONAR_REPORT_PRESENT': 'false'}, {'SONAR_REPORT_PRESENT': 'True'},
                        {'SONAR_TRUSTED_PR': '1'}, {'SONAR_CLOUD_RESULT': 'failure'},
                        {'SONAR_COMMUNITY_RESULT': 'success'},
                        {'SONAR_EVENT_NAME': 'pull_request'},
                        {'SONAR_EVENT_NAME': 'pull_request', 'SONAR_TRUSTED_PR': 'true',
                         'SONAR_CLOUD_RESULT': 'skipped', 'SONAR_COMMUNITY_RESULT': 'success'}]:
            with self.subTest(changes=changes), self.assertRaises(SystemExit):
                self.aggregate(**changes)

    def test_community_task_binds_server_analysis_and_revision(self):
        with tempfile.TemporaryDirectory() as temporary:
            task = Path(temporary) / 'task'
            task.write_text('serverUrl=http://127.0.0.1:9000\nprojectKey=example\nceTaskId=task\n')
            def api(path):
                if path.startswith('/api/ce/'):
                    return {'task': {'status': 'SUCCESS', 'componentKey': 'example', 'analysisId': 'analysis'}}
                if path.startswith('/api/project_analyses/'):
                    return {'analyses': [{'key': 'analysis', 'revision': '1' * 40}]}
                return {'projectStatus': {'status': 'OK'}}
            with s.server('http://127.0.0.1:9000', secrets.token_urlsafe(32)), patch.object(s, 'get', api):
                self.assertEqual(s.completed_analysis(task, 'example', '1' * 40), 'analysis')
            with patch.object(s, 'get', api), self.assertRaises(v.VerificationError):
                s.completed_analysis(task, 'example', '1' * 40)

    def test_unsupported_server_origin_refuses_before_credentials_are_sent(self):
        for url in ['http://localhost:9000', 'http://127.0.0.1:9001',
                    'https://sonarcloud.io.attacker.invalid', 'http://127.0.0.1:9000@attacker.invalid',
                    'https://sonarcloud.io/redirect']:
            with self.subTest(url=url), self.assertRaises(v.VerificationError):
                with s.server(url, secrets.token_urlsafe(32)):
                    self.fail('unsupported origin was accepted')


if __name__ == '__main__':
    unittest.main()
