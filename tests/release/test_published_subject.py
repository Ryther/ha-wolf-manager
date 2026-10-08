import json
import unittest
from scripts.ci.published_subject import image_reference


class PublishedSubjectTests(unittest.TestCase):
    def record(self):
        return {'schema_version': 1, 'version': '0.1.0', 'candidate_sha': 'a' * 40,
                'workflow_run_id': 1, 'image_index_digest': 'sha256:' + 'b' * 64,
                'platforms': [{'os': 'linux', 'architecture': architecture,
                              'digest': 'sha256:' + 'c' * 64}
                             for architecture in ('amd64', 'arm64')]}

    def test_immutable_digest_is_used_and_tag_mismatch_refuses(self):
        raw = json.dumps(self.record()).encode()
        self.assertEqual(image_reference(raw, 'v0.1.0'), 'ghcr.io/ryther/ha-wolf-manager@sha256:' + 'b' * 64)
        with self.assertRaises(ValueError):
            image_reference(raw, 'v0.2.0')

    def test_foreign_digest_or_missing_platform_cannot_choose_scan_target(self):
        for invalid in ('https://foreign.example/image', 'sha256:' + 'x' * 64):
            record = self.record(); record['image_index_digest'] = invalid
            with self.assertRaises(ValueError):
                image_reference(json.dumps(record).encode(), 'v0.1.0')
        record = self.record(); record['platforms'].pop()
        with self.assertRaises(ValueError):
            image_reference(json.dumps(record).encode(), 'v0.1.0')
