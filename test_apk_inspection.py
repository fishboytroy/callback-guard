import io
import struct
import unittest
import zipfile
from unittest.mock import patch
import apk_inspection as apk


class ApkTests(unittest.TestCase):
    def bundle(self, entries):
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as archive:
            for name, data in entries:
                archive.writestr(name, data)
        return output.getvalue()

    def test_traversal_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Unsafe'):
            apk.inspect_apk(self.bundle([('../escape', b'x')]))

    def test_symlink_rejected(self):
        entry = zipfile.ZipInfo('link')
        entry.external_attr = 0o120777 << 16
        with self.assertRaisesRegex(ValueError, 'Unsafe'):
            apk.inspect_apk(self.bundle([(entry, b'target')]))

    def test_archive_limit(self):
        with patch.object(apk, 'MAX_EXPANDED', 2), self.assertRaisesRegex(ValueError, 'expanded'):
            apk.inspect_apk(self.bundle([('large', b'abc')]))

    def test_member_limit(self):
        with patch.object(apk, 'MAX_MEMBER', 2), self.assertRaisesRegex(ValueError, 'member'):
            apk.inspect_apk(self.bundle([('large', b'abc')]))

    def test_missing_manifest(self):
        with self.assertRaisesRegex(ValueError, 'no AndroidManifest'):
            apk.inspect_apk(self.bundle([('resource', b'x')]))

    def test_invalid_manifest_bounds(self):
        for data in (b'', struct.pack('<HHI', 3, 8, 16), struct.pack('<HHIHHI', 3, 8, 16, 1, 8, 0)):
            with self.subTest(data=data), self.assertRaises(ValueError):
                apk.manifest_elements(data)

    def test_case_sensitive_resources_and_incomplete_status(self):
        data = self.bundle([('AndroidManifest.xml', b'fixture'), ('res/a', b'a'), ('res/A', b'b')])
        with patch.object(apk, 'manifest_elements', return_value=[{'tag': 'manifest', 'attributes': {'package': 'test.app'}}]):
            result = apk.inspect_apk(data)
        self.assertEqual(result['entry_count'], 3)
        self.assertEqual(result['status'], 'review-required')
        self.assertEqual(result['signature']['status'], 'not-verified')
        self.assertTrue(result['findings'])


if __name__ == '__main__':
    unittest.main()
