import copy
import tempfile
from pathlib import Path
import unittest
from scripts.ci import check_subject as c, security_gate as s
from scripts.ci import producer as p, verify_candidate as v
from test_candidate import fixture, encoded, SHA


class SubjectTests(unittest.TestCase):
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
        report = {'version': '2.1.0', 'runs': [{'tool': {'driver': {'rules': [
            {'id': 'security', 'properties': {'security-severity': '9.8'}}]}},
            'results': []}]}
        self.assertEqual(s.sarif_gate([encoded(report)]), 1)
        report['runs'][0]['results'] = [{'ruleId': 'security', 'level': 'warning'}]
        with self.assertRaises(v.VerificationError): s.sarif_gate([encoded(report)])
        with self.assertRaises(v.VerificationError): s.sarif_gate([])
