"""Execute the scheduled scanner shell with disposable command fixtures."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[2]


class SecurityCommandTests(unittest.TestCase):
    def test_failed_platform_still_scans_other_platform_and_lock_and_refuses(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/security.yaml').read_text())
        command = next(step['run'] for step in workflow['jobs']['published-image']['steps']
                       if step.get('name') == 'Scan both published platforms and the current Cargo lockfile')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wrapper = root / 'docker'
            wrapper.write_text('#!' + sys.executable + '\n' +
                'import json,os,sys\n' +
                "with open(os.environ['CAPTURE'], 'a') as output: output.write(json.dumps(sys.argv[1:]) + '\\n')\n" +
                "sys.exit(42 if 'linux/amd64' in sys.argv else 0)\n")
            wrapper.chmod(0o700)
            capture = root / 'commands.jsonl'
            result = subprocess.run(['/bin/sh', '-eu', '-c', command], cwd=root,
                env={'PATH': str(root) + os.pathsep + os.defpath, 'CAPTURE': str(capture),
                     'TRIVY_IMAGE': 'scanner-fixture', 'IMAGE_REFERENCE': 'image-fixture'},
                capture_output=True, text=True, timeout=10, check=False)
            self.assertEqual(result.returncode, 1, result.stderr)
            calls = [json.loads(line) for line in capture.read_text().splitlines()]
            self.assertEqual(len(calls), 3)
            self.assertIn('linux/amd64', calls[0])
            self.assertIn('linux/arm64', calls[1])
            self.assertIn('fs', calls[2])
            self.assertIn('/repo', calls[2])
            self.assertTrue(any('Cargo.lock' in argument for argument in calls[2]))
            self.assertTrue(all('--exit-code' in call and call[call.index('--exit-code') + 1] == '1' for call in calls))
