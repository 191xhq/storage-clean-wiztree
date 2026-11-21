"""Install the official portable WizTree into the current Windows user's Programs.

Run only after explicit user authorization. No registry/PATH/UAC policy changes,
no installer execution, no overwrites or deletions. Standard library only.
"""
import argparse
import hashlib
import io
from html.parser import HTMLParser
import json
import ntpath
import os
from pathlib import Path, PurePosixPath
import re
import ssl
import sys
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile

import wiztree

PAGE = 'https://diskanalyzer.com/download'


def official(url):
    parsed = urllib.parse.urlparse(url)
    # This exact vendor CDN was verified from the official download HTTP redirect.
    return parsed.scheme == 'https' and parsed.hostname in ('diskanalyzer.com', 'www.diskanalyzer.com', 'antibodysoftware-17031.kxcdn.com') and not parsed.username and not parsed.password


class OfficialRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not official(newurl):
            raise ValueError('Refusing download redirect outside WizTree official HTTPS site: ' + newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def open_official(opener, url, transport='urllib', proxy=None):
    if not official(url):
        raise ValueError('Downloads must use the official HTTPS site')
    if transport == 'windows-curl':
        curl = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/curl.exe'
        cmd = [str(curl), '--fail', '--silent', '--show-error', '--proto', '=https',
               '--max-redirs', '0', '--connect-timeout', '10', '--max-time', '55',
               '--max-filesize', str(64 * 1024**2), '--ssl-revoke-best-effort']
        # Keep certificate-chain/hostname checks. Schannel may soft-fail only
        # unavailable CRL endpoints; revoked certificates are still rejected.
        if proxy:
            cmd += ['--proxy', proxy]
        current = url
        for hop in range(4):
            if not official(current):
                raise ValueError('Refusing redirect outside verified official download hosts: ' + current)
            result = subprocess.run(cmd + ['--write-out', '\n%{http_code}\n%{redirect_url}', current], capture_output=True, timeout=60)
            if result.returncode:
                raise ValueError('Official download failed: ' + result.stderr.decode('utf-8', errors='replace'))
            body, status, redirect = result.stdout.rsplit(b'\n', 2)
            if status.startswith(b'3') and redirect:
                current = redirect.decode('utf-8')
                continue
            if status != b'200':
                raise ValueError('Official download returned HTTP ' + status.decode('ascii',errors='replace'))
            return io.BytesIO(body)
        raise ValueError('Official download exceeded redirect limit')
    for attempt in range(3):
        try:
            return opener.open(url, timeout=40)
        except urllib.error.HTTPError:
            raise
        except urllib.error.URLError:
            if attempt == 2:
                raise
            time.sleep(attempt + 1)


def portable_url(html):
    class Links(HTMLParser):
        def __init__(self):
            super().__init__()
            self.links = []
        def handle_starttag(self, tag, attrs):
            if tag == 'a':
                self.links.extend(v for k, v in attrs if k == 'href' and v)
    parser = Links()
    parser.feed(html)
    matches = []
    for href in parser.links:
        url = urllib.parse.urljoin(PAGE, href)
        if official(url) and re.fullmatch(r'/files/wiztree_[0-9_]+_portable\.zip', urllib.parse.urlparse(url).path):
            matches.append(url)
    if not matches:
        raise ValueError('Official download page has no verified portable ZIP link')
    return matches[0]


def check_archive(archive):
    total = 0
    for info in archive.infolist():
        name = info.filename.replace('\\', '/')
        parts = PurePosixPath(name)
        if parts.is_absolute() or '..' in parts.parts or ntpath.splitdrive(name)[0] or ':' in name:
            raise ValueError('Unsafe ZIP path: ' + info.filename)
        if ((info.external_attr >> 16) & 0o170000) == 0o120000:
            raise ValueError('ZIP symlinks are not accepted')
        total += info.file_size
        if total > 256 * 1024**2:
            raise ValueError('Portable archive exceeds expected extracted size')


def install(download_dir, transport='urllib', proxy=None, tls12=False):
    if wiztree.environment() != 'windows':
        raise ValueError('Run this installer with native Windows Python; WSL root is not Windows administrator authorization')
    existing = wiztree.host_call({'action': 'probe'})
    if existing['wiztree']:
        return {'status': 'already_installed', 'wiztree': existing['wiztree']}
    handlers = [OfficialRedirect()]
    if tls12:
        context = ssl.create_default_context()
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        handlers.append(urllib.request.HTTPSHandler(context=context))
    if proxy:
        if not re.fullmatch(r'http://(?:127\.0\.0\.1|localhost):[0-9]+', proxy):
            raise ValueError('Only an existing loopback HTTP proxy is accepted')
        handlers.append(urllib.request.ProxyHandler({'https': proxy}))
    opener = urllib.request.build_opener(*handlers)
    with open_official(opener, PAGE, transport, proxy) as response:
        url = portable_url(response.read(3 * 1024**2).decode('utf-8'))
    download_dir = Path(download_dir).resolve()
    download_dir.mkdir(parents=True, exist_ok=True)
    archive_path = download_dir / ('wiztree-portable-' + uuid.uuid4().hex + '.zip')
    with open_official(opener, url, transport, proxy) as response, archive_path.open('xb') as out:
        count = 0
        while chunk := response.read(1024 * 1024):
            count += len(chunk)
            if count > 64 * 1024**2:
                raise ValueError('Download exceeds expected portable archive size')
            out.write(chunk)
    return deploy_archive(archive_path, url)


def deploy_archive(archive_path, url):
    """Deploy a retained official download, including a completed network retry."""
    if not official(url) or not re.fullmatch(r'/files/wiztree_[0-9_]+_portable\.zip', urllib.parse.urlparse(url).path):
        raise ValueError('Portable archive source must be the official download URL')
    archive_path = Path(archive_path).resolve()
    programs = (Path(os.environ['LOCALAPPDATA']) / 'Programs').resolve()
    programs.mkdir(parents=True, exist_ok=True)
    stage = programs / ('WizTree.pending-' + uuid.uuid4().hex)
    stage.mkdir()
    with zipfile.ZipFile(archive_path) as archive:
        check_archive(archive)
        archive.extractall(stage)
    exe = stage / 'WizTree64.exe'
    if not exe.is_file():
        raise ValueError('Official package does not contain WizTree64.exe at its root; files retained for inspection')
    # Discovery verifies file/version/product/company and Authenticode publisher;
    # stage is inside the same bounded Programs/WizTree* discovery location.
    probe = wiztree.host_call({'action': 'probe'})
    trusted = next((x for x in probe['wiztree'] if Path(x['path']).resolve() == exe.resolve()), None)
    if trusted is None:
        raise ValueError('Downloaded WizTree64.exe failed signature/version validation; nothing executed. ' + '; '.join(probe.get('warnings', [])))
    target = programs / 'WizTree'
    if target.exists():
        target = programs / ('WizTree-' + trusted['version'] + '-' + uuid.uuid4().hex[:8])
    if target.parent.resolve() != programs or target.exists():
        raise ValueError('Installation destination is not a new directory inside user Programs')
    stage.rename(target)
    final_probe = wiztree.host_call({'action': 'probe'})
    installed_exe = target / 'WizTree64.exe'
    if not any(Path(x['path']).resolve() == installed_exe.resolve() for x in final_probe['wiztree']):
        raise ValueError('Installation files are present but final Skill discovery failed')
    return {'status': 'installed', 'source': url, 'archive': str(archive_path),
            'archive_sha256': hashlib.sha256(archive_path.read_bytes()).hexdigest(),
            'path': str(installed_exe), 'version': trusted['version'],
            'signature': trusted['signature'], 'publisher': trusted['publisher'],
            'mode': 'official_portable_per_user_no_system_settings', 'probe': final_probe}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--accept-install', action='store_true', help='Use only after the user explicitly authorizes installing WizTree')
    parser.add_argument('--download-dir', required=True)
    parser.add_argument('--output')
    parser.add_argument('--transport', choices=['urllib', 'windows-curl'], default='urllib')
    parser.add_argument('--proxy', help='Existing loopback HTTP proxy for this request only; never modifies system settings')
    parser.add_argument('--tls12', action='store_true', help='TLS 1.2 compatibility mode with certificate and hostname checks retained')
    args = parser.parse_args()
    if not args.accept_install:
        parser.error('Explicit user authorization is required; pass --accept-install only after authorization')
    result = install(args.download_dir, args.transport, args.proxy, args.tls12)
    blob = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(blob, encoding='utf-8')
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    print(blob)


if __name__ == '__main__':
    main()
