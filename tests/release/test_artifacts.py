"""Artifact redirect safety, ZIP preservation and metadata coherence."""
import io
from pathlib import Path
import tempfile
import unittest
import zipfile
from scripts.ci import artifacts as a
from scripts.ci import verify_candidate as v


class ArtifactTests(unittest.TestCase):
    def test_presigned_download_refuses_other_origins_credentials_and_insecure_urls(self):
        self.assertEqual(a.presigned_url('https://productionresultssa.blob.core.windows.net/file?sig=abc'),
                         'https://productionresultssa.blob.core.windows.net/file?sig=abc')
        for url in ['http://x.blob.core.windows.net/a', 'https://attacker.invalid/a',
                    'https://api.github.com/a', 'https://user:pass@x.blob.core.windows.net/a',
                    'https://x.blob.core.windows.net.attacker.invalid/a',
                    'https://x.blob.core.windows.net/a#fragment']:
            with self.subTest(url=url), self.assertRaises(v.VerificationError):
                a.presigned_url(url)

    def test_extract_refuses_links_and_traversal_before_any_write(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / '42.zip'; out = Path(directory) / 'out'
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, 'w') as z:
                z.writestr('valid', b'valid')
                z.writestr('../escape', b'invalid')
            source.write_bytes(buffer.getvalue())
            with self.assertRaises(v.VerificationError): a.extract(source, out)
            self.assertFalse(out.exists())

    def test_original_zip_is_preserved_when_safely_extracting(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / '42.zip'; out = Path(directory) / 'out'
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, 'w') as z: z.writestr('a/b', b'bytes')
            original = buffer.getvalue(); source.write_bytes(original)
            a.extract(source, out)
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual((out / 'a/b').read_bytes(), b'bytes')
