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
    def test_missing_report_returns_explicit_controlled_error(self):
        with self.assertRaisesRegex(v.VerificationError, '^required_report$'):
            s.report_bytes(None, 'required_report')

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
    def test_overall_project_below_ninety_is_refused_even_with_imported_rust(self):
        self.components = [self.rust]
        original = self.api
        def low(path):
            if path.startswith('/api/measures/component?'):
                return {'component': {'measures': [
                    {'metric': 'coverage', 'value': '89.99'},
                    {'metric': 'lines_to_cover', 'value': '1000'}]}}
            return original(path)
        with patch.object(s, 'get', low), self.assertRaises(v.VerificationError):
            s.verify(self.task, 'example', SHA, self.lcov)

    def test_each_mixed_language_report_must_be_imported_exactly(self):
        paths = ['crates/wolf-core/src/lib.rs', 'crates/wolf-host/src/lib.rs',
                 'crates/wolf-manager/src/lib.rs']
        self.lcov.write_text(''.join('SF:' + path + '\nDA:1,3\nend_of_record\n' for path in paths))
        javascript = self.root / 'javascript.lcov'
        javascript.write_text('SF:web/app.js\nDA:1,3\nend_of_record\n')
        python = self.root / 'python.xml'
        python.write_text('<coverage><class filename="sonar_gate.py"><lines>'
                          '<line number="1" hits="1"/></lines></class></coverage>')
        measures = [{'metric': 'lines_to_cover', 'value': '1'},
                    {'metric': 'uncovered_lines', 'value': '0'}]
        self.components = [dict(self.rust, path=path, measures=measures) for path in paths]
        self.components += [dict(self.rust, path='web/app.js', language='js', measures=measures),
                            dict(self.rust, path='scripts/ci/sonar_gate.py', language='py', measures=measures)]
        with patch.object(s, 'get', self.api):
            result = s.verify(self.task, 'example', SHA, self.lcov, javascript, python)
        self.assertEqual(result['javascript_covered_lines'], 1)
        self.assertEqual(result['python_covered_lines'], 1)
        self.components.pop()
        with patch.object(s, 'get', self.api), self.assertRaises(v.VerificationError):
            s.verify(self.task, 'example', SHA, self.lcov, javascript, python)

    def test_full_verifier_refuses_low_manager_despite_exact_imports_and_high_projection(self):
        paths = ['crates/wolf-core/src/lib.rs', 'crates/wolf-host/src/lib.rs',
                 'crates/wolf-manager/src/lib.rs', 'web/app.js', 'scripts/ci/sonar_gate.py']
        def record(path, covered):
            return 'SF:' + path + '\n' + ''.join(
                'DA:' + str(line) + ',' + str(int(line <= covered)) + '\n'
                for line in range(1, 101)) + 'end_of_record\n'
        self.lcov.write_text(''.join(record(path, 84 if index == 2 else 100)
                                   for index, path in enumerate(paths[:3])))
        javascript = self.root / 'javascript.lcov'
        javascript.write_text(record(paths[3], 100))
        python = self.root / 'python.xml'
        python.write_text('<coverage><class filename="sonar_gate.py"><lines>' + ''.join(
            '<line number="' + str(line) + '" hits="1"/>' for line in range(1, 101))
            + '</lines></class></coverage>')
        self.components = [dict(self.rust, path=path, language=language, measures=[
            {'metric': 'lines_to_cover', 'value': '100'},
            {'metric': 'uncovered_lines', 'value': '16' if index == 2 else '0'}])
            for index, (path, language) in enumerate(zip(paths, ['rust'] * 3 + ['js', 'py']))]
        with patch.object(s, 'get', self.api), self.assertRaisesRegex(
                v.VerificationError, 'sonar_component_coverage_below_85'):
            s.verify(self.task, 'example', SHA, self.lcov, javascript, python)

    def coverage_groups(self, counts=None):
        counts = counts or [(100, 90)] * 5
        paths = ['crates/wolf-core/src/lib.rs', 'crates/wolf-host/src/lib.rs',
                 'crates/wolf-manager/src/lib.rs', 'web/app.js', 'scripts/ci/sonar_gate.py']
        groups = [{path: (value[0], value[0] - value[1])} for path, value in zip(paths, counts)]
        return {**groups[0], **groups[1], **groups[2]}, groups[3], groups[4]

    def test_component_floor_refuses_manager_hidden_by_high_aggregate(self):
        groups = self.coverage_groups([(10000, 10000), (10000, 10000),
                                      (10000, 8499), (10000, 10000), (10000, 10000)])
        with self.assertRaises(v.VerificationError):
            s.component_coverage(*groups)

    def test_component_coverage_requires_every_crate_and_both_languages(self):
        rust_paths = ['crates/wolf-core/src/lib.rs', 'crates/wolf-host/src/lib.rs',
                      'crates/wolf-manager/src/lib.rs']
        for missing in range(5):
            groups = self.coverage_groups()
            if missing < 3:
                groups[0].pop(rust_paths[missing])
            else:
                groups[missing - 2].clear()
            with self.subTest(missing=missing), self.assertRaises(v.VerificationError):
                s.component_coverage(*groups)

    def test_component_counts_refuse_zero_boolean_negative_and_foreign_inputs(self):
        for invalid in [(0, 0), (True, 0), (100, True), (100, -1), (100, 101)]:
            groups = self.coverage_groups()
            groups[0]['crates/wolf-manager/src/lib.rs'] = invalid
            with self.subTest(invalid=invalid), self.assertRaises(v.VerificationError):
                s.component_coverage(*groups)
        groups = self.coverage_groups()
        groups[0]['crates/foreign/src/lib.rs'] = (100, 0)
        with self.assertRaises(v.VerificationError):
            s.component_coverage(*groups)

    def test_exact_component_and_combined_boundaries_accept_integer_counts(self):
        groups = self.coverage_groups([(100, 85), (100, 90), (100, 90), (100, 90), (100, 95)])
        result = s.component_coverage(*groups)
        self.assertEqual(set(result), {'wolf-core', 'wolf-host', 'wolf-manager', 'javascript', 'python'})
        self.assertEqual(result['wolf-core'], {'covered_lines': 85, 'executable_lines': 100})
        self.assertEqual(sum(row['covered_lines'] for row in result.values()), 450)

    def test_unrounded_combined_below_ninety_never_borrows_rounded_metric(self):
        groups = self.coverage_groups([(10000, 9000)] * 4 + [(10000, 8999)])
        with self.assertRaises(v.VerificationError):
            s.component_coverage(*groups)

    def test_python_report_duplicate_or_traversal_lines_are_refused(self):
        python = self.root / 'python.xml'
        for filename, lines in [('other/../sonar_gate.py', '<line number="1" hits="1"/>'),
                               ('sonar_gate.py', '<line number="1" hits="1"/>' * 2),
                               ('sonar_gate.py', '<line number="1" hits="-1"/>')]:
            with self.subTest(filename=filename, lines=lines):
                python.write_text('<coverage><class filename="' + filename + '"><lines>' + lines
                                  + '</lines></class></coverage>')
                with self.assertRaises(v.VerificationError): s.python_xml(python)

    def test_nonfinite_or_invalid_project_measurements_are_refused(self):
        for coverage, lines in [('nan', '2'), ('inf', '2'), ('100', '0'), ('101', '2')]:
            response = {'component': {'measures': [
                {'metric': 'coverage', 'value': coverage},
                {'metric': 'lines_to_cover', 'value': lines}]}}
            with self.subTest(coverage=coverage, lines=lines), patch.object(s, 'get', return_value=response):
                with self.assertRaises(v.VerificationError): s.project_coverage('example')

    def test_invalid_or_changed_component_paging_is_refused(self):
        for paging in [{'pageIndex': 2, 'pageSize': 500, 'total': 1},
                       {'pageIndex': 1, 'pageSize': 100, 'total': 1},
                       {'pageIndex': 1, 'pageSize': 500, 'total': -1},
                       {'pageIndex': 1, 'pageSize': 500, 'total': 2}]:
            with self.subTest(paging=paging), self.assertRaises(v.VerificationError):
                s.measure_page({'paging': paging, 'components': []}, 1, 1, 0)

    def test_duplicate_missing_negative_and_unknown_file_measures_are_refused(self):
        invalid = [dict(self.rust, qualifier='DIR'), dict(self.rust, path='crates/other/src/lib.rs'),
                   dict(self.rust, measures=self.rust['measures'] * 2),
                   dict(self.rust, measures=[{'metric': 'lines_to_cover', 'value': '2'}]),
                   dict(self.rust, measures=[{'metric': 'lines_to_cover', 'value': '2'},
                                            {'metric': 'uncovered_lines', 'value': '-1'}])]
        for component in invalid:
            with self.subTest(component=component), self.assertRaises(v.VerificationError):
                s.component_counts(component, {'crates/wolf-core/src/lib.rs': (2, 1)}, {}, 'rust')

    def test_all_zero_lcov_is_rejected(self):
        self.lcov.write_text('SF:crates/wolf-core/src/lib.rs\nDA:1,0\nend_of_record\n')
        with self.assertRaises(v.VerificationError):self.verify()

if __name__ == '__main__':unittest.main()
