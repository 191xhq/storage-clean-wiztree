"""Read-only WizTree adapter. Standard library; only WizTree can request UAC."""
import base64
import csv
import codecs
import io
import json
import locale
import ntpath
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import uuid


class ScanError(RuntimeError):
    pass


def environment():
    if sys.platform.startswith('win'):
        return 'windows'
    if sys.platform == 'darwin':
        return 'macos'
    if sys.platform.startswith('linux'):
        release = platform.release().lower()
        if 'microsoft' in release or os.environ.get('WSL_DISTRO_NAME'):
            return 'wsl'
        return 'linux'
    return sys.platform


def powershell():
    if environment() == 'wsl':
        exe = shutil.which('powershell.exe')
        if not exe:
            candidate = '/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
            if os.path.isfile(candidate):
                exe = candidate
        if not exe:
            raise ScanError('WSL Windows interop unavailable: powershell.exe not found; sudo is not Windows administrator access')
        return exe
    if environment() != 'windows':
        raise ScanError('Windows host bridge requires native Windows or WSL')
    return str(Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe')


def host_call(request):
    payload = base64.b64encode(json.dumps(request, ensure_ascii=False).encode('utf-8')).decode('ascii')
    script = Path(__file__).with_name('wiztree_host.ps1').read_text(encoding='utf-8-sig')
    command = '& {\n' + script + "\n} -Request '" + payload + "'"
    encoded = base64.b64encode(command.encode('utf-16le')).decode('ascii')
    try:
        proc = subprocess.run([powershell(), '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
                              capture_output=True, timeout=request.get('timeout', 40) + 30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ScanError('Windows bridge failed/timeout: ' + str(exc)) from exc
    try:
        data = json.loads(proc.stdout.decode('utf-8-sig').strip())
    except (UnicodeError, ValueError) as exc:
        raise ScanError('Invalid Windows bridge response: ' + proc.stderr.decode('utf-8', errors='replace')[-1000:]) from exc
    if not data.get('ok'):
        raise ScanError(data.get('error', 'Windows bridge failed'))
    return data


def windows_path(path):
    value = os.fspath(path)
    if ntpath.isabs(value) and ntpath.splitdrive(value)[0]:
        return ntpath.normpath(value)
    if environment() == 'wsl':
        r = subprocess.run(['wslpath', '-w', value], capture_output=True, text=True, timeout=10, check=True)
        return r.stdout.strip()
    return os.path.abspath(value)


def local_path(path):
    if environment() == 'wsl':
        r = subprocess.run(['wslpath', '-u', path], capture_output=True, text=True, timeout=10, check=True)
        return r.stdout.strip()
    return path


def scan(target, probe, output_dir=None, files=False, depth=8, admin_mode='auto', timeout=900):
    candidates = probe.get('wiztree', [])
    if not candidates:
        raise ScanError('WizTree not installed or no trusted executable found. Official download: https://diskanalyzer.com/download')
    if output_dir is None:
        # Host TEMP is visible through /mnt/<drive> in WSL; never export into a Linux-only /tmp.
        output_dir = local_path(ntpath.join(probe['temp'], 'storage-clean-WizTree-' + uuid.uuid4().hex))
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    export = Path(output_dir) / ('wiztree-' + uuid.uuid4().hex + '.csv')
    target = windows_path(target)
    result = host_call({'action': 'scan', 'exe': candidates[0]['path'], 'target': target,
                        'output': windows_path(export), 'files': files, 'depth': depth,
                        'admin_mode': admin_mode, 'timeout': timeout})
    parsed = parse_csv(export, target)
    bridge_warnings = result.get('warnings', [])
    result.update(parsed)
    result['csv_path'] = str(export)
    result['warnings'] = list(bridge_warnings) + parsed['warnings']
    if not result['admin']:
        result['warnings'].append('Non-administrator scan; protected directories may be missing')
    result['warnings'].append('WizTree CSV cannot prove every protected directory was readable; NTFS metadata, snapshots and reparse points can differ from volume used space')
    return result


def _key(value):
    return ''.join(c.lower() for c in value if c.isalnum())


ALIASES = {
    'path': {'filename', 'filepath', 'fullpath', 'path', '文件名', '文件名称', '路径'},
    'size': {'size', 'filesize', 'sizebytes', '大小', '文件大小'},
    'allocated': {'allocated', 'allocatedsize', 'allocatedbytes', 'sizeondisk', '分配', '已分配', '已分配空间', '已分配大小', '占用空间'},
    'attributes': {'attributes', '属性'},
}


def _number(value):
    value = value.strip().replace(',', '').replace('\u00a0', '').replace(' ', '')
    if not value.isdigit():
        raise ScanError('Invalid byte count in CSV: ' + repr(value))
    return int(value)


def _human_bytes(value):
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if value < 1024 or unit == 'TB':
            return f'{value:.1f} {unit}'
        value /= 1024


def parse_csv(path, target, limit=40):
    """Stream rows; keep only the top 40 children per parent, never sum folder totals."""
    path = Path(path)
    if not path.is_file() or not path.stat().st_size:
        raise ScanError('Empty or missing WizTree export')
    with path.open('rb') as raw:
        sample = raw.read(65536)
    if sample.startswith((b'\xff\xfe', b'\xfe\xff')):
        encoding = 'utf-16'
    else:
        try:
            codecs.getincrementaldecoder('utf-8-sig')().decode(sample, final=False)
            encoding = 'utf-8-sig'
        except UnicodeError:
            # getencoding() ignores Python UTF-8 mode and returns the real Windows ACP.
            encoding = locale.getencoding() if os.name == 'nt' else 'gb18030'
            if encoding.lower().replace('-', '') in ('utf8', 'cp65001'):
                encoding = 'gb18030'
    root_path = ntpath.normpath(target)
    root_key = ntpath.normcase(root_path)
    warnings, headers, root, count = [], None, None, 0
    by_parent, totals = {}, {}
    try:
        with path.open(encoding=encoding, newline='') as f:
            preview = f.read(65536)
            f.seek(0)
            # WizTree exports CSV with a metadata preamble on some versions.
            lines = preview.splitlines()
            header_line = next((x for x in lines if any(alias in _key(x) for alias in ALIASES['path']) and any(alias in _key(x) for alias in ALIASES['size'])), '')
            delimiter = ';' if header_line.count(';') > header_line.count(',') else ','
            reader = csv.reader(f, delimiter=delimiter, strict=True)
            for row in reader:
                if headers is None:
                    keys = [_key(x.lstrip('\ufeff')) for x in row]
                    mapping = {kind: next((i for i, x in enumerate(keys) if x in names), None) for kind, names in ALIASES.items()}
                    if mapping['path'] is not None and mapping['size'] is not None:
                        headers = mapping
                        if headers['allocated'] is None:
                            warnings.append('CSV has no Allocated field; using logical size, not actual disk allocation')
                    continue
                if not row or not any(row):
                    continue
                required = [x for x in headers.values() if x is not None]
                if len(row) <= max(required):
                    raise ScanError('Truncated CSV row at line ' + str(reader.line_num))
                full = row[headers['path']]
                path_key = ntpath.normcase(ntpath.normpath(full))
                if not (path_key == root_key or path_key.startswith(root_key.rstrip('\\') + '\\')):
                    warnings.append('Ignored CSV row outside requested scope: ' + full)
                    continue
                size = _number(row[headers['size']])
                raw_alloc = row[headers['allocated']].strip() if headers['allocated'] is not None else ''
                if headers['allocated'] is not None and not raw_alloc and 'CSV contains blank Allocated cells; those rows use logical size' not in warnings:
                    warnings.append('CSV contains blank Allocated cells; those rows use logical size')
                # Official CSV hardlink convention: leading 0 means no extra allocation.
                hardlink = len(raw_alloc) > 1 and raw_alloc.startswith('0')
                allocated = (0 if hardlink else _number(raw_alloc)) if raw_alloc else size
                is_dir = full.endswith(('\\', '/'))
                if headers['attributes'] is not None:
                    attrs = row[headers['attributes']]
                    is_dir = is_dir or (attrs.isdigit() and bool(int(attrs) & 16))
                record = {'name': ntpath.basename(full.rstrip('\\/')) or root_path,
                          'path': ntpath.normpath(full), 'size_kb': allocated / 1024,
                          'size_h': _human_bytes(allocated), 'logical_bytes': size,
                          'allocated_bytes': allocated, 'is_dir': bool(is_dir), 'hardlink': hardlink}
                count += 1
                if path_key == root_key:
                    root = record
                parent = ntpath.normcase(ntpath.dirname(full.rstrip('\\/')))
                if parent not in by_parent and len(by_parent) >= 10000:
                    if 'CSV child index capped at 10000 parent directories; use an explicit focused scan for omitted detail' not in warnings:
                        warnings.append('CSV child index capped at 10000 parent directories; use an explicit focused scan for omitted detail')
                    continue
                siblings = by_parent.setdefault(parent, [])
                siblings.append(record)
                siblings.sort(key=lambda x: x['allocated_bytes'], reverse=True)
                if len(siblings) > limit:
                    siblings.pop()
                # Retain only relevant aggregate directory nodes for legacy group lookup.
                if is_dir and (ntpath.basename(full.rstrip('\\/')).lower() in {'.cache','.npm','.gradle','.m2','.cargo','packages','cache','yarn','uv','ms-playwright','go-build'}):
                    totals[path_key] = record
    except (csv.Error, UnicodeError, OSError) as exc:
        raise ScanError('CSV parse failed: ' + str(exc)) from exc
    if headers is None or root is None:
        raise ScanError('CSV export missing header or requested root; incomplete export')
    return {'root': root, 'children': by_parent.get(root_key, []), 'by_parent': by_parent,
            'totals': totals, 'rows': count, 'warnings': warnings, 'encoding': encoding}
