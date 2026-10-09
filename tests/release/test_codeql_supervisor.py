"""The reviewed Supervisor protocol finding has exact, fail-closed authority."""
import copy
from contextlib import contextmanager
import hashlib
import json
import os
import stat
from pathlib import Path
import tempfile
import unittest
from scripts.ci import security_gate as s, verify_candidate as v


SOURCE_PATH = Path('crates/wolf-manager/src/ha_bootstrap.rs')
SOURCE_BYTES = (Path(__file__).resolve().parents[2] / SOURCE_PATH).read_bytes()
SOURCE_SHA256 = 'e55b67da5034db6307a4e280b0fbd00548ae7639ab8e203e7d4a50c0b713c0c3'


def reviewed_report():
    return {'version': '2.1.0', 'runs': [{
        'tool': {'driver': {'name': 'CodeQL', 'rules': []}, 'extensions': [{
            'name': 'codeql/rust-queries', 'rules': [{
                'id': 'rust/non-https-url', 'defaultConfiguration': {'level': 'warning'},
                'properties': {'tags': ['security'], 'security-severity': '8.1'}}]}]},
        'invocations': [{'executionSuccessful': True}],
        'results': [{'ruleId': 'rust/non-https-url', 'rule': {
            'id': 'rust/non-https-url', 'index': 0, 'toolComponent': {'index': 0}},
            'level': 'warning', 'locations': [{'physicalLocation': {
                'artifactLocation': {'uri': SOURCE_PATH.as_posix(), 'uriBaseId': '%SRCROOT%'},
                'region': {'startLine': 144, 'startColumn': 18, 'endColumn': 51}}}]}]}]}


@contextmanager
def source_fixture():
    previous = Path.cwd()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source = root / SOURCE_PATH
        source.parent.mkdir(parents=True)
        source.write_bytes(SOURCE_BYTES)
        os.chdir(root)
        try:
            yield source
        finally:
            os.chdir(previous)


def check(report):
    return s.sarif_gate([json.dumps(report).encode()])


class SupervisorCodeqlTests(unittest.TestCase):
    def test_exact_reviewed_supervisor_protocol_preserves_source(self):
        self.assertEqual(hashlib.sha256(SOURCE_BYTES).hexdigest(), SOURCE_SHA256)
        with source_fixture() as source:
            self.assertEqual(check(reviewed_report()), 1)
            self.assertEqual(source.read_bytes(), SOURCE_BYTES)

    def test_other_finding_locations_and_authority_refuse_without_writes(self):
        mutations = ('other_file', 'traversal', 'absolute_path', 'wrong_base', 'missing_base',
                     'wrong_line', 'wrong_start_column', 'wrong_end_column', 'multiple_locations',
                     'missing_locations', 'other_rule', 'higher_severity', 'lower_high_severity',
                     'error_level', 'default_error', 'failed_execution', 'error_notification',
                     'wrong_driver', 'wrong_component', 'locations_object', 'location_string',
                     'physical_location_list', 'artifact_location_list', 'region_string',
                     'unknown_region_field', 'wrong_end_line')
        for mutation in mutations:
            with self.subTest(mutation=mutation), source_fixture() as source:
                report = reviewed_report()
                run = report['runs'][0]
                result = run['results'][0]
                physical = result['locations'][0]['physicalLocation']
                location = physical['artifactLocation']
                region = physical['region']
                rule = run['tool']['extensions'][0]['rules'][0]
                if mutation == 'other_file': location['uri'] = 'crates/wolf-manager/src/other.rs'
                elif mutation == 'traversal': location['uri'] = 'crates/wolf-manager/src/../src/ha_bootstrap.rs'
                elif mutation == 'absolute_path': location['uri'] = str(source)
                elif mutation == 'wrong_base': location['uriBaseId'] = '%OTHER%'
                elif mutation == 'missing_base': location.pop('uriBaseId')
                elif mutation == 'wrong_line': region['startLine'] += 1
                elif mutation == 'wrong_start_column': region['startColumn'] += 1
                elif mutation == 'wrong_end_column': region['endColumn'] += 1
                elif mutation == 'multiple_locations': result['locations'].append(copy.deepcopy(result['locations'][0]))
                elif mutation == 'missing_locations': result.pop('locations')
                elif mutation == 'other_rule':
                    rule['id'] = result['ruleId'] = result['rule']['id'] = 'rust/cleartext-logging'
                elif mutation == 'higher_severity': rule['properties']['security-severity'] = '8.2'
                elif mutation == 'lower_high_severity': rule['properties']['security-severity'] = '7.9'
                elif mutation == 'error_level': result['level'] = 'error'
                elif mutation == 'default_error':
                    result.pop('level')
                    rule['defaultConfiguration']['level'] = 'error'
                elif mutation == 'failed_execution': run['invocations'][0]['executionSuccessful'] = False
                elif mutation == 'error_notification': run['invocations'][0]['toolExecutionNotifications'] = [{'level': 'error'}]
                elif mutation == 'wrong_driver': run['tool']['driver']['name'] = 'Other scanner'
                elif mutation == 'wrong_component': run['tool']['extensions'][0]['name'] = 'other/queries'
                elif mutation == 'locations_object': result['locations'] = {'physicalLocation': physical}
                elif mutation == 'location_string': result['locations'] = ['invalid']
                elif mutation == 'physical_location_list': result['locations'][0]['physicalLocation'] = []
                elif mutation == 'artifact_location_list': physical['artifactLocation'] = []
                elif mutation == 'region_string': physical['region'] = 'invalid'
                elif mutation == 'unknown_region_field': region['unreviewed'] = 1
                else: region['endLine'] = 145
                before = source.read_bytes()
                with self.assertRaises(v.VerificationError): check(report)
                self.assertEqual(source.read_bytes(), before)

    def test_changed_missing_and_symlink_source_refuse_without_writes(self):
        for mutation in ('changed', 'missing', 'symlink'):
            with self.subTest(mutation=mutation), source_fixture() as source:
                retained = source.parent / 'retained.rs'
                retained.write_bytes(SOURCE_BYTES)
                if mutation == 'changed': source.write_bytes(SOURCE_BYTES + b'\n// fixture change\n')
                elif mutation == 'missing': source.unlink()
                else:
                    source.unlink()
                    source.symlink_to(retained)
                before = source.read_bytes() if source.exists() else None
                with self.assertRaises(v.VerificationError): check(reviewed_report())
                self.assertEqual(source.read_bytes() if source.exists() else None, before)
                self.assertEqual(retained.read_bytes(), SOURCE_BYTES)
                if mutation == 'symlink': self.assertTrue(source.is_symlink())

    def test_exact_default_warning_is_accepted_without_result_level(self):
        with source_fixture() as source:
            report = reviewed_report()
            report['runs'][0]['results'][0].pop('level')
            self.assertEqual(check(report), 1)
            self.assertEqual(source.read_bytes(), SOURCE_BYTES)

    def test_nearby_decimal_severity_is_not_the_reviewed_value(self):
        for severity in ('8.1000000000000001', '8.0999999999999999'):
            with self.subTest(severity=severity), source_fixture() as source:
                report = reviewed_report()
                rule = report['runs'][0]['tool']['extensions'][0]['rules'][0]
                rule['properties']['security-severity'] = severity
                with self.assertRaises(v.VerificationError): check(report)
                self.assertEqual(source.read_bytes(), SOURCE_BYTES)

    def test_duplicate_approved_and_unrelated_high_results_refuse(self):
        for mutation in ('same_run', 'separate_reports', 'unrelated_high'):
            with self.subTest(mutation=mutation), source_fixture() as source:
                report = reviewed_report()
                if mutation == 'separate_reports':
                    reports = [json.dumps(report).encode(), json.dumps(report).encode()]
                else:
                    result = copy.deepcopy(report['runs'][0]['results'][0])
                    if mutation == 'unrelated_high':
                        result['locations'][0]['physicalLocation']['artifactLocation']['uri'] = 'crates/wolf-manager/src/other.rs'
                    report['runs'][0]['results'].append(result)
                    reports = [json.dumps(report).encode()]
                with self.assertRaises(v.VerificationError): s.sarif_gate(reports)
                self.assertEqual(source.read_bytes(), SOURCE_BYTES)

    def test_source_descriptor_authority_refuses_aliases_unsafe_mode_and_size(self):
        for mutation in ('hardlink', 'parent_symlink', 'world_writable', 'unsafe_parent', 'fifo', 'oversize'):
            with self.subTest(mutation=mutation), source_fixture() as source:
                if mutation == 'hardlink':
                    alias = source.parent / 'alias.rs'
                    os.link(source, alias)
                elif mutation == 'parent_symlink':
                    real_parent = source.parent.with_name('retained-src')
                    source.parent.rename(real_parent)
                    source.parent.symlink_to(real_parent, target_is_directory=True)
                elif mutation == 'world_writable': source.chmod(0o666)
                elif mutation == 'unsafe_parent': source.parent.chmod(0o777)
                elif mutation == 'fifo':
                    source.unlink()
                    os.mkfifo(source)
                else: source.write_bytes(SOURCE_BYTES + b'x' * (16 * 1024))
                parent_metadata = source.parent.lstat()
                metadata = source.lstat()
                before = None if mutation == 'fifo' else source.read_bytes()
                with self.assertRaises(v.VerificationError): check(reviewed_report())
                parent_after = source.parent.lstat()
                self.assertEqual((parent_after.st_ino, parent_after.st_mode, parent_after.st_nlink),
                                 (parent_metadata.st_ino, parent_metadata.st_mode, parent_metadata.st_nlink))
                after = source.lstat()
                self.assertEqual((after.st_ino, after.st_mode, after.st_nlink),
                                 (metadata.st_ino, metadata.st_mode, metadata.st_nlink))
                if mutation == 'fifo': self.assertTrue(stat.S_ISFIFO(after.st_mode))
                else: self.assertEqual(source.read_bytes(), before)
                if mutation == 'hardlink': self.assertEqual(alias.read_bytes(), SOURCE_BYTES)
                if mutation == 'parent_symlink':
                    self.assertTrue(source.parent.is_symlink())
                    self.assertEqual((real_parent / source.name).read_bytes(), SOURCE_BYTES)
