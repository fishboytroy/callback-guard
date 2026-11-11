"""Automatic after-download scanning; not an execution-blocking security boundary."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid
import sqlite3
from contextlib import closing
import tempfile
import shutil

import guard

RUNTIME = guard.ROOT / 'automatic-state'
PARTIAL = {'.crdownload', '.part', '.partial', '.tmp', '.download'}
DOWNLOAD_CACHE = {}


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    temp.write_text(json.dumps(value, indent=2), encoding='utf-8')
    os.replace(temp, path)


def load(path, default):
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError:
        return default


def download_folders():
    """Read only download settings, not browsing history or credentials."""
    import winreg
    folders = {Path.home() / 'Downloads'}
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r'Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders') as key:
            value, _ = winreg.QueryValueEx(key, '{374DE290-123F-4565-9164-39C4925E467B}')
            folders.add(Path(os.path.expandvars(value)))
    except OSError:
        pass
    local = Path(os.environ['LOCALAPPDATA'])
    for browser in ['Google/Chrome', 'Microsoft/Edge', 'BraveSoftware/Brave-Browser']:
        root = local / browser / 'User Data'
        for prefs in root.glob('*/Preferences'):
            try:
                directory = json.loads(prefs.read_text(encoding='utf-8')).get('download', {}).get('default_directory')
                if directory:
                    folders.add(Path(os.path.expandvars(directory)))
            except (OSError, ValueError):
                continue
    config = load(RUNTIME / 'config.json', {})
    folders.update(Path(p) for p in config.get('extra_download_folders', []))
    # Avoid recursive self-monitoring if someone chooses the guard's directory.
    return sorted({p.resolve() for p in folders if p.is_dir()}, key=str)


def inventory(folders):
    result, errors = {}, []
    for root in folders:
        def onerror(exc):
            errors.append(str(exc))
        for current, dirs, files in os.walk(root, followlinks=False, onerror=onerror):
            dirs[:] = [d for d in dirs if not (Path(current) / d).is_symlink()
                       and not (Path(current) / d).is_junction()
                       and (Path(current) / d).resolve() != guard.ROOT]
            for name in files:
                path = Path(current) / name
                if path.suffix.lower() in PARTIAL or path.is_symlink():
                    continue
                try:
                    stat = path.stat()
                    result[str(path)] = [stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns]
                except OSError as exc:
                    errors.append(str(exc))
                if len(result) >= 20000:
                    errors.append('Inventory incomplete: 20,000 file limit reached')
                    return result, errors
    return result, errors


def browser_targets():
    """Only completed-download paths; also covers Save As outside Downloads."""
    targets, errors = {}, []
    local = Path(os.environ['LOCALAPPDATA'])
    for browser in ['Google/Chrome', 'Microsoft/Edge', 'BraveSoftware/Brave-Browser']:
        for history in (local / browser / 'User Data').glob('*/History'):
            try:
                cached_at, rows = DOWNLOAD_CACHE.get(str(history), (0, []))
                if time.monotonic() - cached_at >= 30:
                    rows = download_rows(history)
                    DOWNLOAD_CACHE[str(history)] = (time.monotonic(), rows)
                for (filename,) in rows:
                    path = Path(filename)
                    if not path.is_file() or path.is_symlink():
                        continue
                    stat = path.stat()
                    targets[str(path)] = [stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns]
            except (OSError, sqlite3.Error, ValueError) as exc:
                errors.append('Download metadata unavailable for ' + str(history.parent) + ': ' + str(exc))
    return targets, errors


def download_rows(history):
    query = 'SELECT target_path FROM downloads WHERE state=1 ORDER BY start_time DESC LIMIT 200'
    try:
        with closing(sqlite3.connect(history.as_uri() + '?mode=ro', uri=True, timeout=0.1)) as db:
            return db.execute(query).fetchall()
    except sqlite3.OperationalError as exc:
        if 'locked' not in str(exc):
            raise
    # Chrome/Edge may hold an exclusive SQLite lock. Query a short-lived local
    # snapshot instead. Only download paths are queried; copies are deleted.
    snapshots = RUNTIME / 'browser-snapshots'
    snapshots.mkdir(parents=True, exist_ok=True)
    sources = [history] + ([Path(str(history) + '-wal')] if Path(str(history) + '-wal').exists() else [])
    before = [(p.stat().st_size, p.stat().st_mtime_ns) for p in sources]
    if sum(size for size, _ in before) > 128 * 1024 * 1024:
        raise ValueError('Browser metadata snapshot exceeds 128 MiB; folder monitoring remains active')
    with tempfile.TemporaryDirectory(dir=snapshots) as tmp:
        copied = Path(tmp) / 'History'
        for source in sources:
            shutil.copyfile(source, Path(tmp) / source.name)
        after = [(p.stat().st_size, p.stat().st_mtime_ns) for p in sources]
        if before != after:
            raise ValueError('Browser metadata changed during snapshot; retry on next cycle')
        with closing(sqlite3.connect(copied, timeout=0.1)) as db:
            db.execute('PRAGMA query_only=ON')
            return db.execute(query).fetchall()


def snapshot(folders):
    current, errors = inventory(folders)
    targets, browser_errors = browser_targets()
    current.update(targets)
    return current, errors + browser_errors


def notify():
    """Fixed message only: never interpolate file contents into shell commands."""
    try:
        subprocess.Popen(['powershell.exe', '-NoProfile', '-WindowStyle', 'Hidden',
                          '-File', str(guard.ROOT / 'notify.ps1')],
                         creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        pass  # Reports/status remain authoritative if Windows suppresses notifications.


def eligible(current, previous, checked):
    return [p for p, stamp in current.items()
            if previous.get(p) == stamp and checked.get(p) != stamp]


def monitor():
    RUNTIME.mkdir(exist_ok=True)
    # Lock lifetime equals process lifetime; an abandoned process cannot leave a stale lock.
    import msvcrt
    with (RUNTIME / 'monitor.lock').open('a+b') as lock:
        lock.seek(0); lock.write(b'0'); lock.flush(); lock.seek(0)
        try:
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            return
        state_path = RUNTIME / 'watch-state.json'
        folders = download_folders()
        previous, errors = snapshot(folders)
        state = load(state_path, None)
        if state is None:
            # Do not flood the user with alerts for all historical Downloads.
            state = {'checked': previous.copy(), 'baseline_created': time.time(),
                     'baseline_note': 'Pre-existing files were inventoried, not scanned.'}
            save(state_path, state)
        last_discovery = time.monotonic()
        stop = RUNTIME / 'stop.request'
        while not stop.exists():
            time.sleep(3)
            if time.monotonic() - last_discovery >= 60:
                folders = download_folders(); last_discovery = time.monotonic()
            current, errors = snapshot(folders)
            needs_review = False
            for filename in eligible(current, previous, state['checked']):
                if stop.exists():
                    break
                try:
                    report, report_path = guard.run(source=Path(filename))
                    report['automatic_source'] = filename
                    report['original_remains_in_place'] = True
                    report['trigger'] = 'browser-download-monitor'
                    save(report_path, report)
                    save(RUNTIME / 'latest-download.json', {'source': filename, 'status': report['status'],
                         'report': str(report_path), 'at': time.time()})
                    state['checked'][filename] = current[filename]
                    needs_review |= report['status'] != 'checks-passed'
                except Exception as exc:
                    errors.append(str(exc)); needs_review = True
            state['checked'] = {p: stamp for p, stamp in state['checked'].items() if p in current}
            save(state_path, state)
            save(RUNTIME / 'monitor-status.json', {'pid': os.getpid(), 'heartbeat': time.time(),
                 'folders': list(map(str, folders)), 'errors': errors,
                 'mode': 'After-download observation. Originals are not blocked or quarantined.'})
            if needs_review:
                notify()
            previous = current
        save(RUNTIME / 'monitor-status.json', {'status': 'stopped', 'at': time.time()})
        stop.unlink(missing_ok=True)


def scan_repository(root):
    root = Path(root).resolve()
    report = {'status': 'review-required', 'trigger': 'git-post-checkout', 'root': str(root),
              'created': time.time(), 'findings': [], 'files': [],
              'scope': 'Checked-out files only; history, external dependencies and submodules are not certified.'}
    path = RUNTIME / 'git-reports' / (uuid.uuid4().hex + '.json')
    try:
        total = 0
        def onerror(exc):
            raise exc
        for current, dirs, files in os.walk(root, followlinks=False, onerror=onerror):
            for name in list(dirs):
                item = Path(current) / name
                if name == '.git':
                    dirs.remove(name)
                elif item.is_symlink() or item.is_junction():
                    raise ValueError('Linked directory requires review: ' + str(item))
            for name in files:
                if name == '.git':
                    continue
                item = Path(current) / name
                if item.is_symlink():
                    raise ValueError('Linked file requires review: ' + str(item))
                if len(report['files']) >= 500:
                    raise ValueError('Incomplete scan: repository exceeds 500 files')
                with item.open('rb') as stream:
                    data = stream.read(guard.TEXT_LIMIT + 1)
                total += len(data)
                if total > guard.LIMIT:
                    raise ValueError('Incomplete scan: repository exceeds 25 MiB text budget')
                relative = item.relative_to(root).as_posix()
                report['files'].append({'path': relative, 'sha256': hashlib.sha256(data).hexdigest()})
                report['findings'].extend(guard.inspect_payload(data, relative))
                if len(report['findings']) > 1000:
                    raise ValueError('Incomplete scan: finding limit exceeded')
        report['antivirus'] = guard.antivirus(root)
        if not report['findings'] and report['antivirus']['status'] == 'completed-no-detection':
            # Detect content changes while Defender was running.
            for item in report['files']:
                file = root / item['path']
                with file.open('rb') as stream:
                    data = stream.read(guard.TEXT_LIMIT + 1)
                if hashlib.sha256(data).hexdigest() != item['sha256']:
                    raise ValueError('Repository changed during scan')
            report['status'] = 'checks-passed'
    except Exception as exc:
        report['error'] = str(exc)
    save(path, report)
    save(RUNTIME / 'latest-git.json', {'root': str(root), 'status': report['status'], 'report': str(path)})
    print('Callback Guard: ' + report['status'] + '\nReport: ' + str(path), file=sys.stderr)
    if report['status'] != 'checks-passed':
        print('Files already exist. Review before opening, installing or running them.', file=sys.stderr)
        notify()
    return 0 if report['status'] == 'checks-passed' else 2


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--monitor', action='store_true')
    parser.add_argument('--repo', type=Path)
    parser.add_argument('--folders', action='store_true')
    args = parser.parse_args()
    if args.monitor:
        try:
            monitor()
        except Exception as exc:
            save(RUNTIME / 'monitor-status.json', {'status': 'failed', 'error': str(exc), 'at': time.time()})
            notify()
            raise
    elif args.repo:
        sys.exit(scan_repository(args.repo))
    elif args.folders:
        print(json.dumps(list(map(str, download_folders())), indent=2))
    else:
        parser.error('Choose --monitor, --repo PATH, or --folders')
