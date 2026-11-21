import argparse
import csv
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import scan
import wiztree


class AdapterIntegrationTests(unittest.TestCase):
    def test_csv_to_legacy_json_and_uac_not_repeated_across_scopes(self):
        work = tempfile.mkdtemp(prefix='wiztree-adapter-')
        probe = {'ok':True, 'admin':False, 'wiztree':[{'path':'C:\\WizTree64.exe','version':'4.33'}],
                 'warnings':[], 'system_drive':'C:\\', 'home':'C:\\Users\\tester',
                 'local':'C:\\Users\\tester\\AppData\\Local', 'roaming':'C:\\Users\\tester\\AppData\\Roaming',
                 'temp':'C:\\Temp', 'program_files':'C:\\Program Files', 'program_files_x86':'C:\\Program Files (x86)',
                 'os':'Windows test fixture', 'arch':'x64','build':'test','user':'tester',
                 'disks':[{'name':'C:\\','total_bytes':1024**4,'free_bytes':1024**3,'filesystem':'NTFS'}]}
        calls = []
        def host(request):
            if request['action'] == 'probe':
                return probe
            calls.append(request)
            target = request['target'].rstrip('\\')
            with open(request['output'], 'w', encoding='utf-8-sig', newline='') as f:
                csv.writer(f).writerows([
                    ['File Name','Size','Allocated'],
                    [target+'\\',1000000000,900000000],
                    [target+'\\Users\\',800000000,700000000],
                    [target+'\\Users\\tester\\',700000000,600000000],
                    [target+'\\Users\\tester\\Downloads\\',300000000,200000000],
                    [target+'\\Users\\tester\\.npm\\',150000000,150000000],
                    [target+'\\Users\\tester\\project\\Cache\\',150000000,150000000],
                ])
            return {'ok':True,'admin':False,'admin_evidence':'normal_mode',
                    'uac':'cancelled_or_failed' if len(calls)==1 else 'not_required',
                    'warnings':['simulated UAC warning'], 'version':'4.33'}
        args = argparse.Namespace(target=['C:\\','D:\\'], all_fixed=False, engine='auto',
                                  export_dir=work, files=False, max_depth=8, admin_mode='auto', timeout=5)
        with patch.object(wiztree, 'host_call', side_effect=host):
            system, groups = scan.scan_windows(args)
        self.assertEqual([x['admin_mode'] for x in calls], ['auto','normal'])
        self.assertEqual(system['scan_engine'], 'wiztree')
        self.assertFalse(system['wiztree_admin'])
        self.assertEqual(len(system['scan_scope']), 2)
        self.assertEqual(groups['scan_root_1'][0]['allocated_bytes'], 700000000)
        self.assertEqual(groups['user_profile'][0]['allocated_bytes'], 200000000)
        self.assertEqual([x['path'] for x in groups['dev_caches']], ['C:\\Users\\tester\\.npm'])
        self.assertIn('simulated UAC warning', system['scan_warnings'])
        self.assertTrue(any('Non-administrator' in x for x in system['scan_warnings']))
        # Original report JSON can still encode the complete output.
        json.dumps({'system':system,'groups':groups})

    def test_wsl_paths_use_wslpath_without_shell(self):
        import subprocess
        result = subprocess.CompletedProcess([],0,stdout='C:\\Users\\tester\\中文 folder\n')
        with patch.object(wiztree, 'environment', return_value='wsl'), patch.object(wiztree.subprocess, 'run', return_value=result) as run:
            self.assertEqual(wiztree.windows_path('/mnt/c/Users/tester/中文 folder'), 'C:\\Users\\tester\\中文 folder')
            self.assertEqual(run.call_args.args[0], ['wslpath','-w','/mnt/c/Users/tester/中文 folder'])
            self.assertNotIn('shell', run.call_args.kwargs)


if __name__ == '__main__':
    unittest.main()
