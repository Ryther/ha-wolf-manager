import copy
import io
import runpy
import sys
import tempfile
from pathlib import Path
import unittest
from unittest import mock
import yaml
from scripts.ci import check_subject as c, security_gate as s
from scripts.ci import producer as p, verify_candidate as v
from test_candidate import fixture, encoded, SHA


class SubjectTests(unittest.TestCase):
    def test_codeql_failure_retains_sarif_without_success_receipt_or_failure_bypass(self):
        root = Path(__file__).resolve().parents[2]
        for name in ('codeql.yaml',):
            with self.subTest(workflow=name):
                workflow = yaml.safe_load((root / '.github/workflows' / name).read_text())
                job = workflow['jobs']['codeql']
                steps = job['steps']
                gate = next(index for index, step in enumerate(steps)
                            if 'scripts.ci.security_gate' in step.get('run', ''))
                receipt = next(index for index, step in enumerate(steps)
                               if 'report --name codeql' in step.get('run', ''))
                upload = steps[-1]
                self.assertIn('actions/upload-artifact@', upload['uses'])
                self.assertEqual(upload.get('if'), 'always()')
                self.assertIn('evidence-codeql-', upload['with']['name'])
                self.assertEqual(upload['with']['path'], '_tmp/evidence')
                self.assertLess(gate, receipt)
                self.assertLess(receipt, len(steps) - 1)
                self.assertEqual(steps[receipt].get('if'), "inputs.subject_artifact != ''")
                self.assertNotIn('continue-on-error', job)
                self.assertTrue(all(not step.get('continue-on-error') for step in steps))

    def extension_report(self, severity='9.8'):
        return {'version': '2.1.0', 'runs': [{'tool': {
            'driver': {'name': 'CodeQL', 'rules': []},
            'extensions': [{'name': 'queries', 'guid': 'fixture-component', 'rules': [
                {'id': 'security', 'properties': {'tags': ['security'], 'security-severity': severity}}]}]},
            'results': [{'ruleId': 'security', 'rule': {'id': 'security', 'index': 0,
                'toolComponent': {'index': 0}}, 'level': 'warning'}]}]}

    def test_codeql_extension_critical_findings_cannot_pass_as_severity_zero(self):
        with self.assertRaisesRegex(v.VerificationError, 'codeql_high_finding'):
            s.sarif_gate([encoded(self.extension_report())])

    def test_codeql_medium_extension_and_guid_lookup_preserve_rule_identity(self):
        report = self.extension_report('6.5')
        self.assertEqual(s.sarif_gate([encoded(report)]), 1)
        reference = report['runs'][0]['results'][0]['rule']
        reference['toolComponent'] = {'guid': 'fixture-component', 'name': 'queries'}
        self.assertEqual(s.sarif_gate([encoded(report)]), 1)
        reference.pop('index')
        self.assertEqual(s.sarif_gate([encoded(report)]), 1)

    def test_codeql_missing_ambiguous_and_invalid_security_authority_refuses(self):
        for mutation in ('missing_severity', 'nan', 'infinity', 'negative', 'boolean', 'text', 'null',
                         'missing_rule', 'duplicate_rule', 'wrong_rule_id', 'bad_rule_index',
                         'bad_component_index', 'wrong_component_name', 'duplicate_component_guid',
                         'default_error'):
            with self.subTest(mutation=mutation):
                report = self.extension_report('6.5')
                run = report['runs'][0]
                extension = run['tool']['extensions'][0]
                rule = extension['rules'][0]
                result = run['results'][0]
                if mutation == 'missing_severity': rule['properties'].pop('security-severity')
                elif mutation in ('nan', 'infinity', 'negative', 'boolean', 'text', 'null'):
                    rule['properties']['security-severity'] = {'nan': 'NaN', 'infinity': 'Infinity', 'negative': '-1', 'boolean': True, 'text': 'invalid', 'null': None}[mutation]
                elif mutation == 'missing_rule': extension['rules'] = []
                elif mutation == 'duplicate_rule': extension['rules'].append(copy.deepcopy(rule))
                elif mutation == 'wrong_rule_id': result['rule']['id'] = 'different'
                elif mutation == 'bad_rule_index': result['rule']['index'] = -1
                elif mutation == 'bad_component_index': result['rule']['toolComponent']['index'] = True
                elif mutation == 'wrong_component_name': result['rule']['toolComponent']['name'] = 'different'
                elif mutation == 'duplicate_component_guid':
                    run['tool']['extensions'].append(copy.deepcopy(extension))
                    result['rule']['toolComponent'] = {'guid': 'fixture-component'}
                else:
                    result.pop('level')
                    rule['defaultConfiguration'] = {'level': 'error'}
                with self.assertRaises(v.VerificationError): s.sarif_gate([encoded(report)])

    def test_codeql_nonsecurity_rule_and_cli_validate_actual_report_files(self):
        report = self.extension_report('6.5')
        rule = report['runs'][0]['tool']['extensions'][0]['rules'][0]
        rule['properties'] = {'tags': ['maintainability']}
        self.assertEqual(s.sarif_gate([encoded(report)]), 1)
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / 'report.sarif').write_bytes(encoded(report))
            with mock.patch.object(sys, 'argv', ['security_gate', directory]), mock.patch('sys.stdout', new_callable=io.StringIO) as output:
                runpy.run_module('scripts.ci.security_gate', run_name='__main__')
            self.assertIn('Verified CodeQL SARIF runs: 1', output.getvalue())
        rule['properties']['security-severity'] = None
        with self.assertRaises(v.VerificationError): s.sarif_gate([encoded(report)])

    def test_same_subject_bytes_are_required_before_each_check(self):
        files, _, _, _, receipt = fixture()
        files = {name: data for name, data in files.items() if not name.startswith('evidence/')}
        files['image.json'] = encoded(receipt['image'])
        files['subject.json'] = encoded({'candidate_sha': SHA, 'version': '0.1.0',
            'files': {name: v.sha256(data) for name, data in files.items()}})
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / 'bundle'; p.write_tree(bundle, files)
            self.assertEqual(c.verify(bundle, SHA, checkout=False)['candidate_sha'], SHA)
            (bundle / 'SHA256SUMS').write_bytes(b'tampered')
            with self.assertRaises(v.VerificationError): c.verify(bundle, SHA, checkout=False)

    def test_codeql_gate_rejects_high_findings_and_absent_reports(self):
        report = {'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'CodeQL', 'rules': [
            {'id': 'security', 'properties': {'security-severity': '9.8'}}]}},
            'results': []}]}
        self.assertEqual(s.sarif_gate([encoded(report)]), 1)
        report['runs'][0]['results'] = [{'ruleId': 'security', 'level': 'warning'}]
        with self.assertRaises(v.VerificationError): s.sarif_gate([encoded(report)])
        with self.assertRaises(v.VerificationError): s.sarif_gate([])

    def test_codeql_empty_results_cannot_certify_failed_or_malformed_execution(self):
        for invocation in ([{'executionSuccessful': False}], {}, [None],
                           [{'executionSuccessful': 'true'}], [{}]):
            with self.subTest(invocation=invocation):
                report = self.extension_report()
                run = report['runs'][0]
                run['results'] = []
                run['invocations'] = invocation
                with self.assertRaises(v.VerificationError): s.sarif_gate([encoded(report)])
        report['runs'][0]['invocations'] = [{'executionSuccessful': True}]
        self.assertEqual(s.sarif_gate([encoded(report)]), 1)

    def test_codeql_driver_identity_is_required_even_with_empty_results(self):
        for driver in ({}, {'name': ''}, {'name': 42}, {'name': '   '}):
            with self.subTest(driver=driver):
                report = self.extension_report()
                report['runs'][0]['results'] = []
                report['runs'][0]['tool']['driver'] = driver
                with self.assertRaises(v.VerificationError): s.sarif_gate([encoded(report)])

    def test_codeql_extension_identity_is_required_even_without_findings(self):
        report = self.extension_report()
        report['runs'][0]['results'] = []
        report['runs'][0]['tool']['extensions'][0].pop('name')
        with self.assertRaises(v.VerificationError): s.sarif_gate([encoded(report)])

    def test_codeql_incomplete_analysis_notifications_cannot_certify_empty_results(self):
        for field in ('toolExecutionNotifications', 'toolConfigurationNotifications'):
            for notifications in ([{'level': 'error'}], {}, [None], [{'level': 'invalid'}]):
                with self.subTest(field=field, notifications=notifications):
                    report = self.extension_report()
                    run = report['runs'][0]
                    run['results'] = []
                    run['invocations'] = [{'executionSuccessful': True, field: notifications}]
                    with self.assertRaises(v.VerificationError): s.sarif_gate([encoded(report)])
            report['runs'][0]['invocations'] = [{'executionSuccessful': True,
                field: [{'level': 'warning'}, {'level': 'note'}]}]
            self.assertEqual(s.sarif_gate([encoded(report)]), 1)
