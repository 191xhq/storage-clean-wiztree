import csv
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import scan


class ScannerTests(unittest.TestCase):
    def test_fallback_permission_failure_is_recorded(self):
        issues = []
        with patch('os.scandir', side_effect=PermissionError('denied')):
            self.assertEqual(scan.dir_size_bytes('C:\\blocked', issues), 0)
        self.assertEqual(issues[0]['path'], 'C:\\blocked')
        self.assertTrue(issues[0]['denied'])

    def test_csv_adapter_exists(self):
        import wiztree
        self.assertTrue(callable(wiztree.parse_csv))

    def test_python_small_files_keep_byte_precision(self):
        root = Path(tempfile.mkdtemp(prefix='storage-byte-precision-'))
        (root / 'small.bin').write_bytes(b'x' * 123)
        rows = scan.scandir_children(str(root), min_kb=0)
        self.assertEqual(rows[0]['size_kb'] * 1024, 123)


class CSVTests(unittest.TestCase):
    def parse(self, rows, encoding='utf-8-sig'):
        import wiztree
        with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as f:
            path = Path(f.name)
        # Leave fixtures for audit, never delete user files in acceptance tests.
        with path.open('w', encoding=encoding, newline='') as f:
            csv.writer(f).writerows(rows)
        return wiztree.parse_csv(path, 'C:\\测试 & space')

    def test_reordered_headers_allocated_and_no_double_count(self):
        data = self.parse([
            ['Allocated', 'File Name', 'Folders', 'Size', 'Files', 'Attributes'],
            ['8192', 'C:\\测试 & space\\', '1', '100000', '2', '16'],
            ['4096', 'C:\\测试 & space\\子目录\\', '0', '50000', '1', '16'],
            ['4096', 'C:\\测试 & space\\文件,一.bin', '', '50000', '', '32'],
        ])
        self.assertEqual(data['root']['allocated_bytes'], 8192)
        self.assertEqual(data['children'][0]['size_kb'], 4)
        self.assertEqual(len(data['children']), 2)

    def test_hardlink_allocated_not_counted_twice(self):
        data = self.parse([
            ['File Name', 'Size', 'Allocated'],
            ['C:\\测试 & space\\', '100', '4096'],
            ['C:\\测试 & space\\hard.bin', '100', '04096'],
        ])
        self.assertEqual(data['children'][0]['allocated_bytes'], 0)

    def test_missing_root_and_malformed_numbers_fail(self):
        import wiztree
        with self.assertRaises(wiztree.ScanError):
            self.parse([['File Name', 'Size', 'Allocated'], ['C:\\测试 & space\\child\\', '1', '1']])
        with self.assertRaises(wiztree.ScanError):
            self.parse([['File Name', 'Size', 'Allocated'], ['C:\\测试 & space\\', 'oops', '1']])

    def test_empty_export_fails(self):
        import wiztree
        with self.assertRaises(wiztree.ScanError):
            self.parse([])

    def test_no_allocated_records_logical_fallback(self):
        data = self.parse([['File Name', 'Size'], ['C:\\测试 & space\\', '1024']])
        self.assertTrue(data['warnings'])

    def test_utf16_and_metadata_preamble(self):
        data = self.parse([['WizTree export'], ['文件名', '大小', '已分配空间'], ['C:\\测试 & space\\', '1024', '4096']], 'utf-16')
        self.assertEqual(data['root']['allocated_bytes'], 4096)

    def test_real_wiztree_simplified_chinese_allocated_header(self):
        data = self.parse([['生成由 WizTree 4.33'], ['文件名称','大小','分配','修改时间','属性','文件','文件夹'],
                           ['C:\\测试 & space\\','8833','16384','2026/10/31 18:37:26','0','2','1']])
        self.assertEqual(data['root']['allocated_bytes'], 16384)
        self.assertEqual(data['warnings'], [])

    def test_blank_allocated_reports_logical_fallback(self):
        data = self.parse([['File Name', 'Size', 'Allocated'], ['C:\\测试 & space\\', '1024', '']])
        self.assertTrue(data['warnings'])

    def test_ansi_chinese_path(self):
        data = self.parse([['File Name', 'Size', 'Allocated'], ['C:\\测试 & space\\', '1024', '4096']], 'gb18030')
        self.assertEqual(data['root']['allocated_bytes'], 4096)

    def test_truncated_csv_rejected(self):
        import wiztree
        with self.assertRaises(wiztree.ScanError):
            self.parse([['File Name', 'Size', 'Allocated'], ['C:\\测试 & space\\', '1024']])


if __name__ == '__main__':
    unittest.main()
