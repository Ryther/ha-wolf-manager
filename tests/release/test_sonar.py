"""Synthetic Web API responses: prove Rust ingestion, not mixed-language totals."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from scripts.ci import sonar_gate as s, verify_candidate as v

SHA = '1' * 40

class SonarCoverageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.task = self.root / 'task.txt'
        self.task.write_text('serverUrl=https://sonarcloud.io\nprojectKey=example\nceTaskId=task\n')
        self.lcov = self.root / 'rust.lcov'
        self.lcov.write_text('SF:crates/wolf-core/src/lib.rs\nDA:1,4\nDA:2,0\nend_of_record\n')
        self.rust = {'path':'crates/wolf-core/src/lib.rs','language':'rust', 'qualifier':'FIL',
            'measures':[{'metric':'lines_to_cover','value':'2'}, {'metric':'uncovered_lines','value':'1'}]}
        self.components = []
        self.latest = 'analysis'
    def api(self, path):
        if path.startswith('/api/ce/task'): return {'task':{'status':'SUCCESS','componentKey':'example','analysisId':'analysis'}}
        if path.startswith('/api/qualitygates/'): return {'projectStatus':{'status':'OK'}}
        if path.startswith('/api/project_analyses/'):
            return {'analyses':[{'key': self.latest if path.endswith('&ps=1') else 'analysis','revision':SHA}]}
        if path.startswith('/api/measures/component_tree'):
            return {'paging':{'pageIndex':1,'pageSize':500,'total':len(self.components)},'components':self.components}
        return {'component':{'measures':[{'metric':'coverage','value':'95'}, {'metric':'lines_to_cover','value':'1000'}]}}
    def verify(self):
        with patch.object(s,'get',self.api):
            return s.verify(self.task,'example',SHA, self.lcov)
    def test_mixed_project_coverage_cannot_substitute_for_missing_rust_import(self):
        with self.assertRaises(v.VerificationError):self.verify()
    def test_exact_rust_file_counts_accept_matching_lcov(self):
        self.components=[self.rust]
        result=self.verify()
        self.assertEqual(result['rust_covered_lines'],1)
        self.assertEqual(result['rust_files'],1)
        self.assertEqual(result['rust_lcov_sha256'],v.sha256(self.lcov.read_bytes()))
    def test_unimported_report_with_zero_rust_coverage_is_rejected(self):
        self.components=[dict(self.rust,measures=[{'metric':'lines_to_cover','value':'2'},{'metric':'uncovered_lines','value':'2'}])]
        with self.assertRaises(v.VerificationError):self.verify()
    def test_different_rust_line_counts_are_rejected(self):
        self.components=[dict(self.rust,measures=[{'metric':'lines_to_cover','value':'3'},{'metric':'uncovered_lines','value':'1'}])]
        with self.assertRaises(v.VerificationError):self.verify()
    def test_latest_analysis_change_refuses_borrowed_measures(self):
        self.components=[self.rust];self.latest='other'
        with self.assertRaises(v.VerificationError):self.verify()
    def test_duplicate_files_are_rejected(self):
        self.components=[self.rust,self.rust]
        with self.assertRaises(v.VerificationError):self.verify()
    def test_absolute_foreign_lcov_source_is_rejected(self):
        self.lcov.write_text('SF:/untrusted/crates/wolf-core/src/lib.rs\nDA:1,1\nend_of_record\n')
        with self.assertRaises(v.VerificationError):self.verify()
    def test_duplicate_lcov_record_is_rejected(self):
        self.lcov.write_text(self.lcov.read_text()*2)
        with self.assertRaises(v.VerificationError):self.verify()
    def test_malformed_lcov_hits_are_rejected(self):
        self.lcov.write_text('SF:crates/wolf-core/src/lib.rs\nDA:1,-1\nend_of_record\n')
        with self.assertRaises(v.VerificationError):self.verify()
    def test_zero_total_import_never_becomes_positive_evidence(self):
        self.components=[dict(self.rust,measures=[{'metric':'lines_to_cover','value':'0'}])]
        with self.assertRaises(v.VerificationError):self.verify()
    def test_pagination_checks_rust_after_non_rust_page(self):
        original=self.api
        def paged(path):
            if path.startswith('/api/measures/component_tree'):
                page=2 if path.endswith('&p=2') else 1
                items=[{'language':'js'}]*500 if page==1 else [self.rust]
                return {'paging':{'pageIndex':page,'pageSize':500,'total':501},'components':items}
            return original(path)
        with patch.object(s,'get',paged):
            self.assertEqual(s.verify(self.task,'example',SHA,self.lcov)['rust_covered_lines'],1)
    def test_all_zero_lcov_is_rejected(self):
        self.lcov.write_text('SF:crates/wolf-core/src/lib.rs\nDA:1,0\nend_of_record\n')
        with self.assertRaises(v.VerificationError):self.verify()

if __name__ == '__main__':unittest.main()
