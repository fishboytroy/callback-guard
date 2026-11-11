"""Callback Inspector intake gate. Does not install a system-wide interception hook."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import time
import unicodedata
import urllib.request
import urllib.parse
import uuid
import zipfile
import tarfile
import gzip
import bz2
import lzma

ROOT = Path(__file__).resolve().parent
LIMIT = 25 * 1024 * 1024
INPUT_LIMIT = 80 * 1024 * 1024
TEXT_LIMIT = 2 * 1024 * 1024
TEXT = {'.md', '.markdown', '.txt', '.json', '.yaml', '.yml', '.toml', '.ini',
        '.cfg', '.py', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.ps1',
        '.sh', '.bat', '.cmd', '.html', '.htm', '.css', '.xml', '.csv', '.rst'}
RULES = [
    ('instruction-override', r'ignore\s+(?:all\s+)?(?:previous|prior|system)\s+instructions|bypass.{0,40}(?:approval|permission|consent)'),
    ('concealment', r'secretly|silently|do not (?:tell|inform|disclose)|without (?:the )?user'),
    ('dynamic-code', r'\beval\s*\(|\bexec\s*\(|Invoke-Expression|\biex\b|EncodedCommand|b64decode|\batob\s*\('),
    ('remote-execution', r'(?:curl|wget|Invoke-WebRequest).{0,200}(?:\||exec|bash|powershell)|\bnpx\b'),
    ('installation-or-persistence', r'\b(?:preinstall|postinstall|pip install|npm install|schtasks|crontab)\b'),
    ('sensitive-access', r'os\.environ|process\.env|\.ssh\b|\.aws\b|\.env\b|clipboard|chat history'),
    ('outbound-or-callback', r'https?://|wss?://|webhook|sendBeacon|\bfetch\s*\(|requests\.(?:get|post)|\btelemetry\b|phone.home'),
    ('hidden-html', r'<!--|display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0'),
    ('encoded-content', r'(?:[A-Za-z0-9+/]{100,}={0,2})|(?:\\x[0-9a-f]{2}){4,}'),
    ('external-git-content', r'version https://git-lfs.github.com/spec/v1|\[submodule\s'),
]


def inspect(data, name):
    """Strict heuristic policy: every finding requires review, never auto-override."""
    if len(data) > TEXT_LIMIT:
        return [{'rule': 'incomplete', 'file': name, 'reason': 'Text exceeds 2 MiB'}]
    suffix = Path(name).suffix.lower()
    if suffix not in TEXT and Path(name).name.lower() not in {'license', 'readme', 'dockerfile', '.gitignore'}:
        return [{'rule': 'unsupported', 'file': name, 'reason': 'Unsupported format; held for review'}]
    try:
        encoding = 'utf-16' if data.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig'
        text = data.decode(encoding, errors='strict')
        if '\x00' in text:
            raise ValueError('NUL character')
    except (UnicodeError, ValueError):
        return [{'rule': 'unsupported', 'file': name, 'reason': 'Not supported plain text'}]
    findings = []
    for line_no, line in enumerate(text.splitlines(), 1):
        if any(unicodedata.category(c) == 'Cf' or (ord(c) < 32 and c != '\t') for c in line):
            findings.append({'rule': 'invisible-control', 'file': name, 'line': line_no})
        normalized = unicodedata.normalize('NFKC', line)
        for rule, pattern in RULES:
            if re.search(pattern, normalized, re.I):
                findings.append({'rule': rule, 'file': name, 'line': line_no})
        if len(findings) >= 1000:
            findings.append({'rule': 'incomplete', 'file': name, 'reason': 'Finding limit reached'})
            break
    return findings


def inspect_payload(data, name):
    if name.lower().endswith(('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tar.xz', '.txz')):
        return inspect_tar(data)
    if not zipfile.is_zipfile(io.BytesIO(data)):
        return inspect(data, name)
    findings = []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        if len(entries) > 500 or sum(x.file_size for x in entries) > LIMIT:
            raise ValueError('Archive exceeds 500 entries or 25 MiB expanded size')
        names = set()
        for entry in entries:
            path = PurePosixPath(entry.filename)
            key = entry.filename.casefold()
            if (path.is_absolute() or '..' in path.parts or '\\' in entry.filename
                    or ':' in entry.filename or key in names
                    or (entry.external_attr >> 16) & 0o170000 == 0o120000):
                raise ValueError('Unsafe or duplicate archive path')
            names.add(key)
            if entry.is_dir():
                continue
            if entry.flag_bits & 1 or entry.file_size > TEXT_LIMIT:
                raise ValueError('Encrypted or oversized archive member')
            with archive.open(entry) as member:
                content = member.read(TEXT_LIMIT + 1)
            # Nested archives and binaries are held, never silently skipped.
            findings.extend(inspect(content, entry.filename))
            if len(findings) > 1000:
                raise ValueError('Archive finding limit reached')
    return findings


def inspect_tar(data):
    # Bound decompression BEFORE tarfile parses headers (including PAX headers).
    for signature, module in [(b'\x1f\x8b', gzip), (b'BZh', bz2), (b'\xfd7zXZ\x00', lzma)]:
        if data.startswith(signature):
            with module.open(io.BytesIO(data), 'rb') as stream:
                data = stream.read(LIMIT + 1)
            break
    if len(data) > LIMIT:
        raise ValueError('Expanded TAR exceeds 25 MiB')
    findings, names = [], set()
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
        for count, entry in enumerate(archive, 1):
            if count > 500:
                raise ValueError('TAR exceeds 500 entries')
            path = PurePosixPath(entry.name)
            key = entry.name.casefold()
            if (path.is_absolute() or '..' in path.parts or '\\' in entry.name
                    or ':' in entry.name or key in names):
                raise ValueError('Unsafe or duplicate archive path')
            names.add(key)
            if entry.isdir():
                continue
            if not entry.isfile() or entry.issparse() or entry.size > TEXT_LIMIT:
                raise ValueError('Unsupported TAR member: link, special, sparse, or oversized file')
            with archive.extractfile(entry) as member:
                findings.extend(inspect(member.read(TEXT_LIMIT + 1), entry.name))
            if len(findings) > 1000:
                raise ValueError('Archive finding limit reached')
    return findings


def resolve_download(url, name=None):
    """Resolve known hosting pages to bytes, never execute git or package managers."""
    parsed = urllib.parse.urlsplit(url.strip())
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Use an HTTPS URL without embedded credentials')
    host = parsed.hostname.lower()
    parts = parsed.path.strip('/').split('/')
    direct = urllib.parse.urlunsplit(parsed._replace(fragment=''))
    inferred = urllib.parse.unquote(parts[-1]) if parts else ''
    if host == 'github.com':
        if len(parts) == 2 and all(parts):
            owner, repo = parts
            repo = repo.removesuffix('.git')
            direct = f'https://api.github.com/repos/{owner}/{repo}/zipball'
            inferred = repo + '.zip'
        elif len(parts) >= 5 and parts[2] == 'blob':
            direct = 'https://raw.githubusercontent.com/' + '/'.join(parts[:2] + parts[3:])
        elif len(parts) >= 4 and parts[2] == 'archive':
            pass
        elif len(parts) >= 6 and parts[2:4] == ['releases', 'download']:
            pass
        elif len(parts) >= 6 and parts[2:5] == ['releases', 'latest', 'download']:
            pass
        else:
            raise ValueError('Use a GitHub repository root, file/blob, archive, or direct release asset URL')
    elif host == 'gitlab.com':
        if '/-/blob/' in parsed.path:
            direct = urllib.parse.urlunsplit(parsed._replace(path=parsed.path.replace('/-/blob/', '/-/raw/', 1), fragment=''))
        elif '/-/' not in parsed.path and len(parts) >= 2 and not parsed.path.startswith('/api/'):
            project = '/'.join(parts).removesuffix('.git')
            direct = 'https://gitlab.com/api/v4/projects/' + urllib.parse.quote(project, safe='') + '/repository/archive.zip'
            inferred = parts[-1].removesuffix('.git') + '.zip'
    elif host == 'bitbucket.org' and (len(parts) < 4 or parts[2] not in {'get', 'downloads', 'raw'}):
        raise ValueError('Use Bitbucket Download ZIP, raw file, or direct download URL with the branch specified')
    if not (name or inferred):
        raise ValueError('Provide a download filename')
    return direct, name or inferred


def antivirus(path):
    platform = Path(os.environ.get('ProgramData', 'C:/ProgramData')) / 'Microsoft/Windows Defender/Platform'
    candidates = sorted(platform.glob('*/MpCmdRun.exe'), reverse=True)
    candidates.append(Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'Windows Defender/MpCmdRun.exe')
    executable = next((p for p in candidates if p.is_file()), None)
    if executable is None:
        return {'status': 'unavailable'}
    try:
        result = subprocess.run([str(executable), '-Scan', '-ScanType', '3', '-File', str(path),
                                 '-DisableRemediation'], capture_output=True, timeout=120,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        # DisableRemediation avoids treating a remediated detection as a clean input.
        return {'status': 'completed-no-detection' if result.returncode == 0 else 'blocked-or-failed',
                'exit_code': result.returncode, 'engine': str(executable),
                'output': (result.stdout + result.stderr).decode(errors='replace')[-8000:]}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'status': 'failed', 'reason': str(exc)}


class HTTPSOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != 'https':
            raise ValueError('Non-HTTPS redirect refused')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def run(source=None, url=None, name=None, storage=ROOT / 'intake'):
    job = storage / uuid.uuid4().hex
    job.mkdir(parents=True, exist_ok=False)
    report = {'version': 1, 'created': time.time(), 'status': 'held', 'findings': [],
              'coverage': 'Only this intake operation. Heuristics and Defender; no dependency advisory lookup.',
              'input_limit_bytes': INPUT_LIMIT}
    try:
        if url:
            direct, name = resolve_download(url, name)
            # Omit query strings, which may contain temporary signed credentials.
            report['source_host'] = urllib.parse.urlsplit(url).hostname
            opener = urllib.request.build_opener(HTTPSOnly())
            request = urllib.request.Request(direct, headers={'User-Agent': 'Callback-Guard/1.1'})
            with opener.open(request, timeout=30) as response:
                data = response.read(INPUT_LIMIT + 1)
                final = urllib.parse.urlsplit(response.geturl())
                report['download_host'] = final.hostname
                if response.headers.get_content_type() == 'text/html' and Path(name).suffix.lower() not in {'.html', '.htm'}:
                    raise ValueError('Server returned an HTML page instead of the requested file; use a direct download link')
        else:
            origin = Path(source)
            if origin.is_symlink() or not origin.is_file():
                raise ValueError('Source must be a regular file')
            name = origin.name
            with origin.open('rb') as stream:
                data = stream.read(INPUT_LIMIT + 1)
        if len(data) > INPUT_LIMIT:
            raise ValueError(f'Input exceeds {INPUT_LIMIT // (1024 * 1024)} MiB')
        if not name or re.search(r'[<>:"/\\|?*\x00-\x1f]', name) or name.endswith((' ', '.')) or name in {'.', '..'}:
            raise ValueError('Invalid filename')
        report['name'] = name
        report['sha256'] = hashlib.sha256(data).hexdigest()
        # No untrusted filename is used for staging or release filesystem operations.
        staged = job / 'payload.pending'
        staged.write_bytes(data)
        report['antivirus'] = antivirus(staged)
        if name.lower().endswith('.apk'):
            from apk_inspection import inspect_apk
            report['apk'] = inspect_apk(data)
            report['findings'] = report['apk']['findings']
            report['coverage'] = 'Defender plus bounded APK archive/CRC checks, manifest parsing, member hashes and compiled-code string triage. See apk.limitations.'
            if report['antivirus']['status'] == 'completed-no-detection':
                report['status'] = 'review-required'
        else:
            report['findings'] = inspect_payload(data, name)
        if report['antivirus']['status'] == 'completed-no-detection' and not report['findings']:
            if not staged.exists() or hashlib.sha256(staged.read_bytes()).hexdigest() != report['sha256']:
                raise ValueError('Staged content changed during scan')
            # Release as inert bytes; no installation, execution or automatic agent loading.
            approved = job / 'payload.checked'
            staged.rename(approved)
            report['status'] = 'checks-passed'
            report['checked_file'] = str(approved)
    except Exception as exc:
        report['error'] = str(exc)
    report_path = job / 'report.json'
    report_path.write_text(json.dumps(report, indent=2), encoding='utf-8')
    return report, report_path


def gui():
    from guard_ui import main
    main()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--source', type=Path)
    group.add_argument('--url')
    parser.add_argument('--name')
    parser.add_argument('--gui', action='store_true')
    args = parser.parse_args()
    if args.gui:
        gui()
    elif args.source or args.url:
        result, report_file = run(source=args.source, url=args.url, name=args.name)
        print(json.dumps({'status': result['status'], 'report': str(report_file),
                          'checked_file': result.get('checked_file')}))
        sys.exit(0 if result['status'] == 'checks-passed' else 2)
    else:
        parser.error('Choose --gui, --source FILE, or --url HTTPS_URL --name NAME')
