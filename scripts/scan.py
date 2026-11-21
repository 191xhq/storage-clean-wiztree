#!/usr/bin/env python3
"""Read-only storage scanner (macOS + Windows).

Collects disk usage, system info, and per-directory size breakdowns for the
hot spots that typically eat disk, and emits one JSON blob to stdout for Claude
to interpret and classify. Auto-detects the OS and scans the right locations.

READ-ONLY SOURCE SCAN: never changes scanned user data. CSV/JSON exports are
written only to separate output paths. No cleanup operations are performed.

Output shape (same on both OSes):
{
  "generated_at", "scan_seconds",
  "system": {os, build, arch, user, home, filesystem,
             disk_total, disk_used, disk_free, purgeable,
             disks: [{name, total, used, free}]},   # all volumes/drives
  "groups": { "<group>": [{name, path, size_kb, size_h}], ... }
}
"""
import json
import os
import shutil
import sys
import time
import argparse
import ntpath
from pathlib import Path
import wiztree

HOME = os.path.expanduser("~")


def human(kb):
    """KB number -> human string like '12.3 GB'."""
    n = float(kb) * 1024
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit not in ("B", "KB") else f"{int(n)} {unit}"
        n /= 1024


# ======================================================================
# macOS
# ======================================================================
import re
import subprocess


def run(cmd, timeout=180):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


def du_children(path, min_kb=51200, limit=40):
    """Size every immediate child of `path` via du, sorted desc. macOS."""
    if not os.path.isdir(path):
        return []
    results = []
    try:
        entries = sorted(os.listdir(path))
    except PermissionError:
        return [{"name": "(permission denied)", "path": path,
                 "size_kb": 0, "size_h": "?", "denied": True}]
    for name in entries:
        if name in (".", ".."):
            continue
        child = os.path.join(path, name)
        if os.path.islink(child):
            continue
        out = run(["du", "-sk", child], timeout=120)
        m = re.match(r"\s*(\d+)", out)
        if not m:
            continue
        kb = int(m.group(1))
        if kb < min_kb:
            continue
        results.append({"name": name, "path": child, "size_kb": kb, "size_h": human(kb)})
    results.sort(key=lambda r: r["size_kb"], reverse=True)
    return results[:limit]


MAC_TARGETS = [
    ("home", HOME, 102400),
    ("library", os.path.join(HOME, "Library"), 51200),
    ("caches", os.path.join(HOME, "Library/Caches"), 51200),
    ("containers", os.path.join(HOME, "Library/Containers"), 51200),
    ("group_containers", os.path.join(HOME, "Library/Group Containers"), 51200),
    ("app_support", os.path.join(HOME, "Library/Application Support"), 51200),
    ("applications", "/Applications", 102400),
    ("downloads", os.path.join(HOME, "Downloads"), 51200),
    ("dev_caches", None, 51200),
]

MAC_DEV_CACHE_PATHS = [
    "~/Library/Caches/pip", "~/Library/Caches/uv", "~/.cache", "~/.cargo",
    "~/.npm", "~/.pnpm-store", "~/.gradle", "~/.m2",
    "~/Library/Developer/Xcode/DerivedData", "~/Library/Developer/CoreSimulator",
    "~/Library/Developer/Xcode/iOS DeviceSupport", "~/Library/pnpm",
    "~/go/pkg", "~/.docker",
]


def dev_caches_macos():
    results = []
    for p in MAC_DEV_CACHE_PATHS:
        path = os.path.expanduser(p)
        if not os.path.isdir(path):
            continue
        out = run(["du", "-sk", path], timeout=180)
        m = re.match(r"\s*(\d+)", out)
        if not m:
            continue
        kb = int(m.group(1))
        if kb < 51200:
            continue
        results.append({"name": os.path.basename(path.rstrip("/")) or path,
                        "path": path, "size_kb": kb, "size_h": human(kb)})
    results.sort(key=lambda r: r["size_kb"], reverse=True)
    return results


def system_info_macos():
    info = {}
    info["os"] = "macOS " + run(["sw_vers", "-productVersion"]).strip()
    info["build"] = run(["sw_vers", "-buildVersion"]).strip()
    arch = run(["uname", "-m"]).strip()
    brand = run(["sysctl", "-n", "machdep.cpu.brand_string"]).strip()
    info["arch"] = (f"Apple Silicon (arm64){' / ' + brand if brand else ''}"
                    if arch == "arm64" else f"{arch}{' / ' + brand if brand else ''}")
    info["user"] = os.environ.get("USER", "") or run(["whoami"]).strip()
    info["home"] = HOME
    total, used, free = "?", "?", "?"
    try:
        t, u, f = shutil.disk_usage("/")
        total, used, free = human(t // 1024), human(u // 1024), human(f // 1024)
    except Exception:
        pass
    info["disk_total"], info["disk_used"], info["disk_free"] = total, used, free
    dinfo = run(["diskutil", "info", "/"])
    fs = re.search(r"File System Personality:\s*(.+)", dinfo)
    info["filesystem"] = fs.group(1).strip() if fs else "APFS"
    pm = re.search(r"Purgeable Space:\s*([\d.,]+ \w+)", dinfo)
    info["purgeable"] = pm.group(1).strip() if pm else ""
    info["disk_name"] = "Macintosh HD"
    info["disks"] = [{"name": "Macintosh HD", "total": total, "used": used, "free": free}]
    return info


def scan_macos():
    system = system_info_macos()
    groups = {}
    for key, path, floor in MAC_TARGETS:
        groups[key] = dev_caches_macos() if key == "dev_caches" else du_children(path, min_kb=floor)
    return system, groups


# ======================================================================
# Windows  (UNTESTED on this build — stdlib only: os, shutil, ctypes)
# ======================================================================
def dir_size_bytes(path, issues=None):
    """Iterative logical-byte fallback; preserve errors, skip symlinks/junctions."""
    if issues is None:
        issues = FALLBACK_ISSUES
    total = 0
    pending = [path]
    while pending:
        current = pending.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    try:
                        st = entry.stat(follow_symlinks=False)
                        if entry.is_symlink() or getattr(st, 'st_file_attributes', 0) & 0x400:
                            record_issue(issues, entry.path, 'reparse point skipped', denied=False)
                        elif entry.is_file(follow_symlinks=False):
                            total += st.st_size
                        elif entry.is_dir(follow_symlinks=False):
                            pending.append(entry.path)
                    except OSError as exc:
                        record_issue(issues, entry.path, exc)
        except OSError as exc:
            record_issue(issues, current, exc)
    return total


FALLBACK_ISSUES = []


def record_issue(issues, path, error, denied=True):
    issues.append({'path': str(path), 'error': str(error), 'denied': denied})


def scandir_children(path, min_kb=51200, limit=40, issues=None):
    """Size every immediate child of `path` via os.scandir. Windows."""
    if issues is None:
        issues = FALLBACK_ISSUES
    if not path:
        return []
    results = []
    try:
        entries = sorted(os.listdir(path))
    except OSError as exc:
        if isinstance(exc, FileNotFoundError):
            return []
        record_issue(issues, path, exc)
        return [{"name": "(permission denied)", "path": path,
                 "size_kb": 0, "size_h": "?", "denied": True}]
    for name in entries:
        child = os.path.join(path, name)
        before = len(issues)
        try:
            st = os.stat(child, follow_symlinks=False)
            if os.path.islink(child) or getattr(st, 'st_file_attributes', 0) & 0x400:
                record_issue(issues, child, 'reparse point skipped', denied=False)
                continue
            kb = (os.path.getsize(child) if os.path.isfile(child)
                  else dir_size_bytes(child, issues)) / 1024
        except OSError as exc:
            record_issue(issues, child, exc)
            results.append({'name': name, 'path': child, 'size_kb': 0, 'size_h': '?', 'denied': True})
            continue
        partial = any(x['denied'] for x in issues[before:])
        if kb < min_kb and not partial:
            continue
        results.append({"name": name, "path": child, "size_kb": kb, "size_h": human(kb), 'partial': partial})
    results.sort(key=lambda r: r["size_kb"], reverse=True)
    return results[:limit]


def list_drives_windows():
    drives = []
    import string
    for letter in string.ascii_uppercase:
        root = f"{letter}:\\"
        import ctypes
        if ctypes.windll.kernel32.GetDriveTypeW(root) != 3:
            continue
        if os.path.exists(root):
            try:
                t, u, f = shutil.disk_usage(root)
                drives.append({"name": root, "total": human(t // 1024),
                               "used": human(u // 1024), "free": human(f // 1024)})
            except Exception:
                continue
    return drives


def system_info_windows():
    import platform
    info = {}
    info["os"] = platform.system() + " " + platform.release()
    info["build"] = platform.version()
    info["arch"] = os.environ.get("PROCESSOR_ARCHITECTURE", platform.machine())
    info["user"] = os.environ.get("USERNAME", "")
    info["home"] = os.environ.get("USERPROFILE", HOME)
    sysdrive = os.environ.get("SystemDrive", "C:") + "\\"
    total, used, free = "?", "?", "?"
    try:
        t, u, f = shutil.disk_usage(sysdrive)
        total, used, free = human(t // 1024), human(u // 1024), human(f // 1024)
    except Exception:
        pass
    info["disk_total"], info["disk_used"], info["disk_free"] = total, used, free
    info["filesystem"] = "NTFS"
    info["purgeable"] = ""
    info["disk_name"] = sysdrive
    info["disks"] = list_drives_windows()
    return info


def scan_windows_python():
    profile = os.environ.get("USERPROFILE", HOME)
    local = os.environ.get("LOCALAPPDATA", os.path.join(profile, "AppData", "Local"))
    roaming = os.environ.get("APPDATA", os.path.join(profile, "AppData", "Roaming"))
    targets = [
        ("user_profile", profile, 102400),
        ("appdata_local", local, 51200),
        ("appdata_roaming", roaming, 51200),
        ("temp", os.environ.get("TEMP", os.path.join(local, "Temp")), 51200),
        ("downloads", os.path.join(profile, "Downloads"), 51200),
        ("program_files", os.environ.get("ProgramFiles", r"C:\Program Files"), 102400),
        ("program_files_x86", os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), 102400),
    ]
    groups = {}
    for key, path, floor in targets:
        groups[key] = scandir_children(path, min_kb=floor)

    dev_paths = [
        os.path.join(profile, ".cache"), os.path.join(profile, ".npm"),
        os.path.join(profile, ".gradle"), os.path.join(profile, ".m2"),
        os.path.join(profile, ".nuget", "packages"), os.path.join(profile, ".cargo"),
        os.path.join(local, "pip", "Cache"), os.path.join(local, "Yarn"),
        os.path.join(local, "uv"), os.path.join(local, "ms-playwright"),
        os.path.join(local, "go-build"),
    ]
    dev = []
    for path in dev_paths:
        if not os.path.isdir(path):
            continue
        try:
            kb = dir_size_bytes(path) // 1024
        except (PermissionError, OSError):
            continue
        if kb < 51200:
            continue
        dev.append({"name": os.path.basename(path.rstrip("\\/")) or path,
                    "path": path, "size_kb": kb, "size_h": human(kb)})
    dev.sort(key=lambda r: r["size_kb"], reverse=True)
    groups["dev_caches"] = dev
    return system_info_windows(), groups


def host_system(probe):
    disks = [{'name': d['name'], 'total': human(d['total_bytes'] / 1024),
              'used': human((d['total_bytes'] - d['free_bytes']) / 1024),
              'free': human(d['free_bytes'] / 1024), 'filesystem': d['filesystem'],
              'drive_type': 'fixed'} for d in probe['disks']]
    main_disk = next((d for d in disks if d['name'].lower() == probe['system_drive'].lower()), {})
    return {'os': probe['os'], 'build': probe['build'], 'arch': probe['arch'],
            'user': probe['user'], 'home': probe['home'], 'filesystem': main_disk.get('filesystem', '?'),
            'disk_name': probe['system_drive'], 'disk_total': main_disk.get('total', '?'),
            'disk_used': main_disk.get('used', '?'), 'disk_free': main_disk.get('free', '?'),
            'purgeable': '', 'disks': disks}


def legacy_targets(probe):
    p, local = probe['home'], probe['local']
    return [('user_profile', p, 102400), ('appdata_local', local, 51200),
            ('appdata_roaming', probe['roaming'], 51200), ('temp', probe['temp'], 51200),
            ('downloads', ntpath.join(p, 'Downloads'), 51200),
            ('program_files', probe['program_files'], 102400),
            ('program_files_x86', probe['program_files_x86'], 102400)]


def dev_cache_paths(probe):
    p, local = probe['home'], probe['local']
    return ([ntpath.join(p, x) for x in ('.cache', '.npm', '.gradle', '.m2', '.nuget\\packages', '.cargo')] +
            [ntpath.join(local, x) for x in ('pip\\Cache', 'Yarn', 'uv', 'ms-playwright', 'go-build')])


def scan_windows(args):
    env = wiztree.environment()
    FALLBACK_ISSUES.clear()
    warnings, scope, groups, results = [], [], {}, []
    try:
        probe = wiztree.host_call({'action': 'probe'})
        system = host_system(probe)
        warnings.extend(probe.get('warnings', []))
    except wiztree.ScanError as exc:
        probe = None
        warnings.append(str(exc))
        system = system_info_windows() if env == 'windows' else {
            'os': 'Windows host (WSL bridge unavailable)', 'build': '?', 'arch': '',
            'user': os.environ.get('USER', ''), 'home': HOME, 'filesystem': '?',
            'disk_name': '/mnt/c', 'disk_total': '?', 'disk_used': '?', 'disk_free': '?', 'purgeable': '', 'disks': []}
    targets = args.target or ([d['name'] for d in probe['disks']] if args.all_fixed and probe else
                              [probe['system_drive']] if probe else [os.environ.get('SystemDrive', 'C:') + '\\' if env == 'windows' else '/mnt/c'])
    mode = args.admin_mode
    for index, target in enumerate(targets):
        result = None
        if args.engine != 'python' and probe:
            try:
                result = wiztree.scan(target, probe, args.export_dir, args.files, args.max_depth, mode, args.timeout)
                results.append(result)
                warnings.extend(result['warnings'])
                if result['uac'] == 'cancelled_or_failed':
                    mode = 'normal'  # Never reprompt for additional drives in this run.
                children = result['children']
                scope.append({'path': target, 'engine': 'wiztree', 'admin': result['admin'],
                              'admin_evidence': result['admin_evidence'], 'uac': result['uac'], 'csv_path': result['csv_path'],
                              'rows': result['rows'], 'allocated_bytes': result['root']['allocated_bytes'],
                              'max_export_depth': args.max_depth, 'files_exported': args.files, 'status': 'complete'})
                for key, path, floor in legacy_targets(probe):
                    if not path:
                        continue
                    data = result['by_parent'].get(ntpath.normcase(ntpath.normpath(path)), [])
                    if data:
                        groups[key] = [x for x in data if x['size_kb'] >= floor][:40]
                allowed_caches = {ntpath.normcase(ntpath.normpath(p)) for p in dev_cache_paths(probe)}
                dev = [v for k, v in result['totals'].items() if k in allowed_caches and v['size_kb'] >= 51200]
                merged = {v['path']: v for v in groups.get('dev_caches', []) + dev}
                groups['dev_caches'] = sorted(merged.values(), key=lambda x: x['size_kb'], reverse=True)[:40]
            except (wiztree.ScanError, OSError, subprocess.SubprocessError) as exc:
                warnings.append(f'WizTree failed for {target}: {exc}; falling back to Python logical-size scan')
                mode = 'normal'  # One elevation attempt maximum after a failure.
        if result is None:
            actual = wiztree.local_path(target) if probe else target
            if os.path.isdir(actual) or os.path.exists(actual):
                children = scandir_children(actual, min_kb=0)
                scope.append({'path': target, 'engine': 'python-scandir', 'admin': False,
                              'process_admin': probe['admin'] if probe else None,
                              'status': 'partial' if any(x['denied'] for x in FALLBACK_ISSUES) else 'complete',
                              'size_basis': 'logical_bytes'})
            else:
                children = []
                record_issue(FALLBACK_ISSUES, actual, 'Scan target unavailable')
                scope.append({'path': target, 'engine': 'python-scandir', 'admin': False, 'status': 'failed'})
            warnings.append(f'{target}: Python fallback uses logical file size; permissions, hardlinks, sparse/compressed files and filesystem metadata can differ from allocated space')
            if not args.target and probe:
                for key, path, floor in legacy_targets(probe):
                    if path:
                        groups[key] = scandir_children(wiztree.local_path(path), min_kb=floor)
                dev = []
                for path in dev_cache_paths(probe):
                    actual_dev = wiztree.local_path(path)
                    if not os.path.isdir(actual_dev):
                        continue
                    before = len(FALLBACK_ISSUES)
                    kb = dir_size_bytes(actual_dev) / 1024
                    if kb >= 51200 or len(FALLBACK_ISSUES) > before:
                        dev.append({'name': ntpath.basename(path), 'path': path, 'size_kb': kb,
                                    'size_h': human(kb), 'partial': len(FALLBACK_ISSUES) > before})
                groups['dev_caches'] = sorted(dev, key=lambda x: x['size_kb'], reverse=True)
        groups['scan_root_' + str(index + 1)] = children
    engines = sorted({s['engine'] for s in scope})
    system.update({'scan_engine': engines[0] if len(engines) == 1 else 'mixed',
                   'runtime_environment': env, 'windows_host_admin': probe['admin'] if probe else None,
                   'wiztree_version': probe['wiztree'][0]['version'] if probe and probe['wiztree'] else None,
                   'wiztree_admin': bool(results) and all(s['engine'] == 'wiztree' and s['admin'] for s in scope),
                   'scan_scope': scope, 'scan_warnings': list(dict.fromkeys(warnings)),
                   'scan_issues': list(FALLBACK_ISSUES),
                   'denied_paths': list(dict.fromkeys(x['path'] for x in FALLBACK_ISSUES if x['denied']))})
    return system, groups


# ======================================================================
def main():
    parser = argparse.ArgumentParser(description='Read-only storage scan; Windows prefers signed WizTree, UAC elevates only WizTree.')
    parser.add_argument('--probe', action='store_true', help='Detect environment/admin/WizTree only, without scanning')
    parser.add_argument('--target', action='append', help='Explicit small folder or fixed drive; repeat for multiple scopes')
    parser.add_argument('--all-fixed', action='store_true', help='Scan all local fixed disks, system disk by default')
    parser.add_argument('--engine', choices=['auto', 'python'], default='auto')
    parser.add_argument('--admin-mode', choices=['auto', 'normal'], default='auto')
    parser.add_argument('--files', action='store_true', help='Also export file rows; requires explicit focused --target')
    parser.add_argument('--max-depth', type=int, default=8)
    parser.add_argument('--timeout', type=int, default=900)
    parser.add_argument('--export-dir')
    parser.add_argument('--output', help='Write UTF-8 JSON directly, avoids shell redirection encodings')
    args = parser.parse_args()
    if args.files and not args.target:
        parser.error('--files requires an explicit focused --target')
    if args.max_depth < 1 or args.timeout < 1:
        parser.error('max-depth and timeout must be positive')
    started = time.time()
    if args.probe:
        env = wiztree.environment()
        data = {'runtime_environment': env}
        if env in ('windows', 'wsl'):
            try:
                data.update(wiztree.host_call({'action': 'probe'}))
            except wiztree.ScanError as exc:
                data.update({'ok': False, 'error': str(exc)})
        emit(data, args.output)
        return
    if sys.platform == "darwin":
        system, groups = scan_macos()
    elif wiztree.environment() in ('windows', 'wsl'):
        system, groups = scan_windows(args)
    else:
        print(json.dumps({"error": "unsupported_platform", "platform": sys.platform,
                          "message": "scan.py supports macOS and Windows only."},
                         ensure_ascii=False))
        return
    data = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "system": system,
        "groups": groups,
        "scan_seconds": round(time.time() - started, 1),
    }
    emit(data, args.output)


def emit(data, output=None):
    blob = json.dumps(data, ensure_ascii=False, indent=2)
    if output:
        Path(output).write_text(blob, encoding='utf-8')
    else:
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8')
        print(blob)


if __name__ == "__main__":
    main()
