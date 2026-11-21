import http.client
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from http.server import ThreadingHTTPServer

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import server
import wiztree


class SafetyTests(unittest.TestCase):
    def test_windows_elevated_server_refuses_start(self):
        with patch.object(server, 'is_elevated_windows', return_value=True), patch.object(sys, 'argv', ['server.py', 'not-needed.json']):
            with self.assertRaises(SystemExit):
                server.main()

    def test_http_guards_without_real_deletion(self):
        root = Path(tempfile.mkdtemp(prefix='storage-safety-'))
        green, yellow, red = [root / x for x in ['green', 'yellow', 'red']]
        for p in (green, yellow, red):
            p.mkdir()
        analysis = root / 'analysis.json'
        analysis.write_text(json.dumps({'system': {}, 'green': [{'trash_paths':[str(green)]}],
                                       'yellow': [{'trash_paths':[str(yellow)]}],
                                       'red':[{'app_paths':[str(red)]}]}), encoding='utf-8')
        data, tpl, rm, trash, op = server.load(analysis)
        self.assertIn(server.expand(green), rm)
        self.assertNotIn(server.expand(yellow), rm)
        self.assertIn(server.expand(yellow), trash)
        self.assertNotIn(server.expand(red), trash)
        with patch.multiple(server, HOME=str(root), DATA=data, TPL=tpl, RM_ALLOW=rm, TRASH_ALLOW=trash, OPEN_ALLOW=op), \
                patch.object(server, 'is_elevated_windows', return_value=False), \
                patch.object(server, 'hard_delete') as delete, patch.object(server, 'move_to_trash') as recycle:
            srv = ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
            worker = threading.Thread(target=srv.serve_forever, daemon=True)
            worker.start()
            def request(payload, host='127.0.0.1'):
                c = http.client.HTTPConnection('127.0.0.1', srv.server_port)
                c.request('POST', '/action', json.dumps(payload), {'Host':host, 'Content-Type':'application/json'})
                response = c.getresponse()
                status, body = response.status, response.read()
                c.close()
                return status
            try:
                base = {'token': server.TOKEN, 'mode':'rm', 'paths':[str(green)]}
                self.assertEqual(request(dict(base, token='wrong')), 403)
                self.assertEqual(request(base, 'evil.example'), 403)
                self.assertEqual(request(dict(base, paths=[str(yellow)])), 403)
                self.assertEqual(request(dict(base, paths=[str(red)])), 403)
                self.assertEqual(request(dict(base, paths=[str(root / '..' / 'outside')])), 403)
                # Even an accidentally allowlisted outside path must fail the HOME boundary.
                outside = str(root.parent / 'outside')
                server.RM_ALLOW.add(server.expand(outside))
                self.assertEqual(request(dict(base, paths=[outside])), 403)
                with patch.object(server, 'is_elevated_windows', return_value=True):
                    self.assertEqual(request(base), 403)
                delete.assert_not_called()
                recycle.assert_not_called()
            finally:
                srv.shutdown()
                srv.server_close()
                worker.join()

    def test_wsl_is_not_linux_or_windows_admin(self):
        with patch.object(sys, 'platform', 'linux'), patch('platform.release', return_value='6.6.87-microsoft-standard-WSL2'):
            self.assertEqual(wiztree.environment(), 'wsl')
        with patch.object(sys, 'platform', 'linux'), patch('platform.release', return_value='6.8.0-generic'), patch.dict(os.environ, {}, clear=True):
            self.assertEqual(wiztree.environment(), 'linux')


if __name__ == '__main__':
    unittest.main()
