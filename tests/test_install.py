import io
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import Mock
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))


class InstallTests(unittest.TestCase):
    def test_official_portable_link_only(self):
        import install_wiztree
        self.assertEqual(install_wiztree.portable_url('<a href="files/wiztree_4_33_portable.zip">Download</a>'),
                         'https://diskanalyzer.com/files/wiztree_4_33_portable.zip')
        with self.assertRaises(ValueError):
            install_wiztree.portable_url('<a href="https://fake.example/wiztree_portable.zip">Download</a>')

    def test_archive_cannot_escape_install_folder(self):
        import install_wiztree
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, 'w') as z:
            z.writestr('../escape.exe', b'harmless')
        payload.seek(0)
        with zipfile.ZipFile(payload) as z:
            with self.assertRaises(ValueError):
                install_wiztree.check_archive(z)

    def test_archive_rejects_windows_path_and_symlink(self):
        import install_wiztree
        for name in ['C:/escape.exe', '..\\escape.exe']:
            payload = io.BytesIO()
            with zipfile.ZipFile(payload, 'w') as z:
                z.writestr(name, b'harmless')
            payload.seek(0)
            with zipfile.ZipFile(payload) as z:
                with self.assertRaises(ValueError):
                    install_wiztree.check_archive(z)

    def test_transient_official_connection_retried_without_disabling_tls(self):
        import install_wiztree
        opener = Mock()
        response = object()
        opener.open.side_effect = [urllib.error.URLError('TLS EOF'), response]
        self.assertIs(install_wiztree.open_official(opener, 'https://diskanalyzer.com/download'), response)
        self.assertEqual(opener.open.call_count, 2)

    def test_official_cdn_redirect_allowed_but_arbitrary_cdn_rejected(self):
        import install_wiztree
        self.assertTrue(install_wiztree.official('https://antibodysoftware-17031.kxcdn.com/files/wiztree_4_33_portable.zip'))
        self.assertFalse(install_wiztree.official('https://other.kxcdn.com/files/wiztree_4_33_portable.zip'))

    def test_native_transport_follows_only_verified_official_redirect(self):
        import install_wiztree
        from unittest.mock import patch
        import subprocess
        first = subprocess.CompletedProcess([],0,stdout=b'301 html\n301\nhttps://antibodysoftware-17031.kxcdn.com/files/wiztree_4_33_portable.zip',stderr=b'')
        second = subprocess.CompletedProcess([],0,stdout=b'PK binary\n200\n',stderr=b'')
        with patch.object(install_wiztree.subprocess,'run',side_effect=[first,second]) as run:
            with install_wiztree.open_official(Mock(), 'https://diskanalyzer.com/files/wiztree_4_33_portable.zip', 'windows-curl') as response:
                self.assertEqual(response.read(), b'PK binary')
            self.assertEqual(run.call_count,2)


if __name__ == '__main__':
    unittest.main()
