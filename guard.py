"""Callback Inspector intake gate. Does not install a system-wide interception hook."""
# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 fishboytroy. Licensed under the Business Source License 1.1; see LICENSE.
import argparse
import ast
import copy
import hashlib
try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    tomllib = None
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
# Content is classified by magic bytes, not by extension. Media and fonts are
# inert (no embedded instructions the scanner must read); executables and other
# unreadable binaries are held. Text of any language is decoded and rule-checked.
MEDIA_MAGIC = (
    b'\x89PNG\r\n\x1a\n',          # PNG
    b'\xff\xd8\xff',               # JPEG
    b'GIF87a', b'GIF89a',          # GIF
    b'\x00\x00\x01\x00',           # ICO
    b'\x00\x00\x02\x00',           # CUR
    b'BM',                         # BMP
    b'wOFF', b'wOF2',              # WOFF / WOFF2 fonts
    b'OTTO', b'ttcf',              # OpenType / TrueType collection
    b'\x00\x01\x00\x00',           # TrueType font
)
EXECUTABLE_MAGIC = (
    b'MZ',                         # DOS/PE (Windows .exe/.dll)
    b'\x7fELF',                    # ELF
    b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',  # Mach-O
    b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe',  # Mach-O (reversed)
    b'\xca\xfe\xba\xbe',           # Java class / Mach-O fat
    b'dex\n',                      # Android DEX
)


def classify(data):
    """Return (kind, text). kind is 'media', 'executable', 'unknown-binary' or
    'text'; text is the decoded string only when kind == 'text'."""
    if data.startswith(MEDIA_MAGIC):
        return 'media', None
    if data[:4] == b'RIFF' and data[8:12] in {b'WEBP', b'WAVE', b'AVI '}:
        return 'media', None
    if data.startswith(EXECUTABLE_MAGIC):
        return 'executable', None
    try:
        encoding = 'utf-16' if data[:2] in (b'\xff\xfe', b'\xfe\xff') else 'utf-8-sig'
        text = data.decode(encoding, errors='strict')
    except (UnicodeError, ValueError):
        return 'unknown-binary', None
    if '\x00' in text:
        return 'unknown-binary', None
    return 'text', text


# Severity decides what blocks. Only `high` and `critical` hold a scan; `info`
# and `low` are reported but allow `checks-passed`. Ordinary projects contain
# URLs and `pip install` lines, so those are informational, not blocking.
SEVERITY_ORDER = {'info': 0, 'low': 1, 'high': 2, 'critical': 3}
BLOCKING = {'high', 'critical'}

# (rule, pattern, severity). Rules were split so a benign signal (a bare URL, a
# `pip install` mention, reading one env var) no longer carries the same weight
# as an override instruction or a credential read.
RULES = [
    ('instruction-override', r'ignore\s+(?:all\s+)?(?:previous|prior|system)\s+instructions|bypass.{0,40}(?:approval|permission|consent)', 'high'),
    ('concealment', r'secretly|silently|do not (?:tell|inform|disclose)|without (?:the )?user', 'high'),
    ('dynamic-code', r'\beval\s*\(|\bexec\s*\(|Invoke-Expression|\biex\b|EncodedCommand|b64decode|\batob\s*\(', 'high'),
    ('remote-execution', r'(?:curl|wget|Invoke-WebRequest).{0,200}(?:\||exec|bash|powershell)|\bnpx\b', 'high'),
    ('persistence', r'\b(?:preinstall|postinstall|schtasks|crontab)\b', 'high'),
    ('credential-access', r'\.ssh\b|\.aws\b|id_rsa|\bsecrets?\b.{0,20}(?:token|key|password)|private[_-]?key', 'critical'),
    ('network-call', r'webhook|sendBeacon|\bfetch\s*\(|requests\.(?:get|post)|\btelemetry\b|phone.home', 'low'),
    ('hidden-html', r'<!--|display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0', 'high'),
    ('encoded-content', r'(?:[A-Za-z0-9+/]{100,}={0,2})|(?:\\x[0-9a-f]{2}){4,}', 'high'),
    ('external-git-content', r'version https://git-lfs.github.com/spec/v1|\[submodule\s', 'high'),
    # Common, usually benign signals: reported, not blocking.
    ('env-access', r'os\.environ|process\.env|\.env\b|clipboard|chat history', 'low'),
    ('package-install', r'\b(?:pip install|npm install|yarn add)\b', 'info'),
    ('url-reference', r'https?://|wss?://', 'info'),
]


def blocking(findings):
    """A scan is held when any finding is high or critical severity."""
    return any(f.get('severity') in BLOCKING for f in findings)


def escape_excerpt(line, limit=200):
    """A single line rendered safe to display: control and format (zero-width)
    characters become visible \\uXXXX escapes, trimmed to `limit` characters.
    The result is untrusted data, never instructions."""
    out = []
    for ch in line.strip():
        if unicodedata.category(ch) == 'Cf' or (ord(ch) < 32 and ch != '\t'):
            out.append('\\u%04x' % ord(ch))
        else:
            out.append(ch)
    text = ''.join(out)
    return text[:limit] + '…' if len(text) > limit else text


def summarize_risk(findings):
    """One plain-language line: counts by severity, then the top blocking items."""
    if not findings:
        return 'No findings.'
    counts = {}
    for f in findings:
        counts[f.get('severity', 'info')] = counts.get(f.get('severity', 'info'), 0) + 1
    order = ['critical', 'high', 'low', 'info']
    tally = ', '.join('%d %s' % (counts[s], s) for s in order if counts.get(s))
    top = [f for s in ('critical', 'high') for f in findings if f.get('severity') == s][:3]

    def where(f):
        loc = f.get('file', '')
        if f.get('line'):
            loc += ':' + str(f['line'])
        return f['rule'] + ((' (' + loc + ')') if loc else '')

    detail = '; '.join(where(f) for f in top)
    return tally + (('. ' + detail) if detail else '') + ('.' if detail and not detail.endswith('.') else '')


def load_allowlist(root=ROOT):
    """Optional user allowlist. Suppressions downgrade a finding to info and mark
    it `suppressed`; findings are never silently dropped.

    allowlist.json: {"domains": ["docs.python.org"], "suppress_rules": ["env-access"]}
    """
    try:
        raw = json.loads((root / 'allowlist.json').read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {'domains': [], 'suppress_rules': []}
    return {'domains': [str(d).lower() for d in raw.get('domains', [])],
            'suppress_rules': [str(r) for r in raw.get('suppress_rules', [])]}


def apply_allowlist(finding, line, allowlist):
    """Downgrade a finding the user has allowlisted. Returns the finding (marked
    suppressed) so it still appears in the report."""
    rule = finding['rule']
    if rule in allowlist['suppress_rules']:
        finding['severity'] = 'info'
        finding['suppressed'] = 'rule in allowlist suppress_rules'
        return finding
    if rule in ('url-reference', 'network-call') and line:
        low = line.lower()
        if any(domain in low for domain in allowlist['domains']):
            finding['severity'] = 'info'
            finding['suppressed'] = 'domain in allowlist'
    return finding


# ---- Structure-aware analyzers (Phase 3) ------------------------------------
# Keyword rules miss split strings and indirection. These read code structure so
# `'sub'+'process'`, importlib indirection and comment-hidden payloads are caught.

CRED_MARKERS = ('.ssh', '.aws', 'id_rsa', '.claude', '.codex',
                'private_key', 'private-key', 'credentials')
# (dotted prefix, rule, severity). Matched after import aliases are resolved.
PY_CAPS = [
    ('subprocess', 'process-execution', 'high'),
    ('os.system', 'process-execution', 'high'),
    ('os.popen', 'process-execution', 'high'),
    ('os.exec', 'process-execution', 'high'),
    ('os.spawn', 'process-execution', 'high'),
    ('pty.spawn', 'process-execution', 'high'),
    ('socket', 'network-access', 'high'),
    ('requests', 'network-access', 'high'),
    ('httpx', 'network-access', 'high'),
    ('urllib.request.urlopen', 'network-access', 'high'),
    ('http.client', 'network-access', 'high'),
    ('ftplib', 'network-access', 'high'),
    ('smtplib', 'network-access', 'high'),
    ('eval', 'dynamic-code', 'high'),
    ('exec', 'dynamic-code', 'high'),
    ('compile', 'dynamic-code', 'high'),
    ('pickle.loads', 'dynamic-code', 'high'),
    ('marshal.loads', 'dynamic-code', 'high'),
    ('__import__', 'dynamic-code', 'high'),
    ('importlib.import_module', 'dynamic-code', 'high'),
    ('ctypes', 'native-code', 'high'),
    ('cffi', 'native-code', 'high'),
]
PROCESS_NET = {'process-execution', 'network-access'}


def _py_fold(node):
    """Evaluate a constant string built from literal +, * and ''.join([...]), so
    a split or assembled name resolves. Returns the value or None."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _py_fold(node.left), _py_fold(node.right)
        if isinstance(left, str) and isinstance(right, str):
            return left + right
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        left, right = _py_fold(node.left), _py_fold(node.right)
        if isinstance(left, str) and isinstance(right, int):
            return left * right
        if isinstance(left, int) and isinstance(right, str):
            return left * right
    if isinstance(node, ast.Call):
        func = node.func
        if (isinstance(func, ast.Attribute) and func.attr == 'join'
                and isinstance(func.value, ast.Constant) and isinstance(func.value.value, str)
                and len(node.args) == 1 and isinstance(node.args[0], (ast.List, ast.Tuple))):
            items = [_py_fold(e) for e in node.args[0].elts]
            if all(isinstance(i, str) for i in items):
                return func.value.value.join(items)
    return None


def _py_dotted(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return '.'.join(reversed(parts))
    return None


def _py_imports(tree):
    """Map each bound name to the module/attribute it refers to."""
    imports = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    imports[a.asname] = a.name
                else:
                    top = a.name.split('.')[0]
                    imports[top] = top
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ''
            for a in node.names:
                imports[a.asname or a.name] = (module + '.' + a.name) if module else a.name
    return imports


def _py_canonical(name, imports):
    root, _, rest = name.partition('.')
    base = imports.get(root, root)
    return base + ('.' + rest if rest else '')


def _py_capability(cname):
    for prefix, rule, severity in PY_CAPS:
        if cname == prefix or cname.startswith(prefix + '.'):
            return rule, severity
    return None


def analyze_python(text, name):
    """AST analysis: resolve imports and folded strings, flag dangerous calls,
    and escalate a credential read combined with process/network to critical."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return [{'rule': 'python-unparseable', 'file': name, 'severity': 'low',
                 'reason': 'Could not parse; keyword rules still applied'}]
    imports = _py_imports(tree)
    findings, caps, cred_line = [], set(), None
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            low = node.value.lower()
            if any(marker in low for marker in CRED_MARKERS):
                line = getattr(node, 'lineno', 0)
                cred_line = cred_line or line
                findings.append({'rule': 'credential-access', 'file': name, 'line': line,
                                 'severity': 'critical', 'detail': 'credential path in string'})
        if isinstance(node, ast.Call):
            dotted = _py_dotted(node.func)
            if dotted and (dotted == 'getattr' or dotted.endswith('.getattr')):
                if len(node.args) >= 2 and not isinstance(node.args[1], ast.Constant):
                    findings.append({'rule': 'dynamic-code', 'file': name, 'line': node.lineno,
                                     'severity': 'high', 'detail': 'getattr with computed attribute name'})
                    caps.add('dynamic-code')
            if dotted:
                cname = _py_canonical(dotted, imports)
                cap = _py_capability(cname)
                if cap:
                    rule, severity = cap
                    findings.append({'rule': rule, 'file': name, 'line': node.lineno,
                                     'severity': severity, 'detail': cname})
                    caps.add(rule)
                if cname in ('importlib.import_module', '__import__') and node.args:
                    module = _py_fold(node.args[0])
                    if isinstance(module, str):
                        nested = _py_capability(module)
                        if nested:
                            rule, severity = nested
                            findings.append({'rule': rule, 'file': name, 'line': node.lineno,
                                             'severity': severity, 'detail': 'dynamic import of ' + module})
                            caps.add(rule)
    if cred_line is not None and (caps & PROCESS_NET):
        findings.append({'rule': 'exfiltration', 'file': name, 'line': cred_line, 'severity': 'critical',
                         'detail': 'credential read combined with process/network capability'})
    return findings


def _normalize_line(line):
    # Merge adjacent string literals split to dodge matching: 'a'+'b' -> 'ab'.
    return re.sub(r'''(['"])\s*\+\s*(['"])''', '', line)


NORMALIZED_CAPS = {
    'powershell': [
        ('dynamic-code', r'scriptblock\]::create|invoke-expression|\biex\b|frombase64string|-encodedcommand\b', 'high'),
        ('remote-execution', r'net\.webclient|downloadstring|downloadfile|invoke-webrequest|invoke-restmethod', 'high'),
        ('persistence', r'register-scheduledtask|schtasks|add-mppreference|set-mppreference', 'high'),
    ],
    'javascript': [
        ('process-execution', r'child_process|execsync|spawnsync|execfilesync', 'high'),
        ('dynamic-code', r'\beval\s*\(|new\s+function\s*\(', 'high'),
        ('dynamic-require', r'require\s*\(\s*[^\'")\s]', 'high'),
    ],
    'shell': [
        ('remote-execution', r'(curl|wget)\b[^\n|]*\|\s*(sh|bash|zsh)|/dev/tcp/|\bnc\s+-e|bash\s+-c', 'high'),
    ],
}
LANG_BY_SUFFIX = {
    '.ps1': 'powershell', '.psm1': 'powershell', '.psd1': 'powershell',
    '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
    '.ts': 'javascript', '.jsx': 'javascript', '.tsx': 'javascript',
    '.sh': 'shell', '.bash': 'shell',
}


def analyze_normalized(text, name, lang):
    findings = []
    for line_no, line in enumerate(text.splitlines(), 1):
        normalized = _normalize_line(line)
        for rule, pattern, severity in NORMALIZED_CAPS[lang]:
            if re.search(pattern, normalized, re.I):
                findings.append({'rule': rule, 'file': name, 'line': line_no, 'severity': severity})
    return findings


def analyze_package_json(text, name):
    try:
        data = json.loads(text)
    except ValueError:
        return []
    scripts = data.get('scripts', {}) if isinstance(data, dict) else {}
    if not isinstance(scripts, dict):
        return []
    findings = []
    for hook in ('preinstall', 'install', 'postinstall', 'prepare', 'preuninstall', 'postuninstall'):
        if hook in scripts:
            findings.append({'rule': 'persistence', 'file': name, 'severity': 'high',
                             'detail': 'npm ' + hook + ' lifecycle script'})
    return findings


# ---- Prompt-injection detection (Phase 4) -----------------------------------
# Instructions aimed at the assistant are rarely a single matchable phrase. They
# combine an address to the model, a concealment ask, a sensitive target and an
# exfiltration or override action, often spread across lines. Score categories
# over a sliding multi-line window and flag dangerous combinations, so a single
# benign signal (an ordinary skill saying "you are a ...") does not fire.
INJECTION_SIGNALS = [
    ('imperative', r'\byou are\b|\byou must\b|\byou should\b|when you (?:call|use|respond|answer|finish|have finished)|before you (?:respond|answer|reply)|when the user (?:asks|says|sends|next)|for the assistant|assistant[:,]|from now on,? you|do the following|your (?:reply|response|answer|output|summary|real instructions)'),
    ('conceal', r"do not (?:mention|tell|inform|disclose|surface)|don't (?:mention|tell)|no need to (?:mention|tell|say)|without (?:telling|informing|the user)|keep (?:this|it)(?: process)? (?:to yourself|between us|secret|private)|\bquietly\b|\bsecretly\b|\bsilently\b|stays clean|report only that"),
    ('sensitive', r'\bcredential|\bpassword|api[ -]?key|\bsecret|\.ssh\b|id_rsa|config(?:uration)? file|settings? file|settings\.json|environment variable|conversation history|chat history|shell (?:startup|profile)|startup file|~/\.|\.env\b'),
    ('exfil', r'paste the contents|include (?:its|the|your)[^.\n]{0,30}contents|include (?:it|them) in your (?:reply|response|answer|summary)|attach what you find|append[^.\n]{0,30}to[^.\n]{0,30}(?:request|reply|summary)|send[^.\n]{0,40}(?:to |https?://)|exfiltrate|post[^.\n]{0,30}https?://|next outbound'),
    ('authority', r'platform security|security team|pre-?approved|\bauthorized\b|authorization|comes from anthropic|system owner|this is required|overrides? your'),
    ('override', r'skip[^.\n]{0,20}confirmation|without confirmation|proceed directly|do not pause|do not ask|\boverride\b|ignore your[^.\n]{0,20}(?:rules|guidance|caution|instructions)|no restrictions|\bbypass\b|disregard[^.\n]{0,25}(?:system|previous|earlier|instruction|message|guidance|safety)|take priority'),
]
INJECTION_SUFFIXES = {'.md', '.markdown', '.txt', '.rst'}


def analyze_injection(text, name):
    """Flag prompt injection by scoring category combinations over a sliding
    multi-line window. Zero-width characters are stripped first so split text
    still matches."""
    stripped = ''.join(ch for ch in text if unicodedata.category(ch) != 'Cf')
    lines = stripped.splitlines()
    findings, i, window = [], 0, 6
    while i < len(lines):
        norm = unicodedata.normalize('NFKC', ' '.join(lines[i:i + window]))
        cats = {cat for cat, pattern in INJECTION_SIGNALS if re.search(pattern, norm, re.I)}
        severity = None
        if 'conceal' in cats and ('sensitive' in cats or 'exfil' in cats):
            severity = 'critical'
        elif (('imperative' in cats and ('sensitive' in cats or 'exfil' in cats))
              or ('exfil' in cats and 'sensitive' in cats)
              or (('authority' in cats or 'imperative' in cats) and 'override' in cats)
              or ('conceal' in cats and 'imperative' in cats)):
            severity = 'high'
        if severity:
            findings.append({'rule': 'prompt-injection', 'file': name, 'line': i + 1,
                             'severity': severity, 'detail': 'signals: ' + ','.join(sorted(cats))})
            i += window  # step past this window to avoid duplicate overlapping hits
        else:
            i += 1
        if len(findings) >= 20:
            break
    return findings


# ---- Dependency reporting (Phase 6) -----------------------------------------
# Dependencies are listed, not resolved or fetched. Each is reported as not
# covered by this scan. A tiny offline typosquat check runs by default; a
# known-vulnerability lookup against OSV.dev is opt-in because it uses network.
TOP_PACKAGES = {
    'pypi': {'requests', 'urllib3', 'numpy', 'pandas', 'flask', 'django', 'boto3',
             'setuptools', 'pip', 'wheel', 'pytest', 'pyyaml', 'click', 'jinja2',
             'cryptography', 'certifi', 'idna', 'six', 'colorama', 'scipy'},
    'npm': {'lodash', 'react', 'express', 'chalk', 'axios', 'debug', 'commander',
            'request', 'async', 'moment', 'webpack', 'typescript', 'vue', 'jest',
            'eslint', 'dotenv', 'uuid', 'glob', 'yargs', 'next'},
}
DEPENDENCY_MANIFESTS = {'requirements.txt', 'pyproject.toml', 'package.json'}


def _edit_distance_one(a, b):
    if a == b:
        return False
    if abs(len(a) - len(b)) > 1:
        return False
    # True when one substitution, one adjacent transposition, or one insertion
    # or deletion apart (Damerau-style; transpositions are a common typosquat).
    if len(a) == len(b):
        diffs = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
        if len(diffs) == 1:
            return True
        if len(diffs) == 2 and diffs[1] == diffs[0] + 1:
            i, j = diffs
            return a[i] == b[j] and a[j] == b[i]
        return False
    short, long = (a, b) if len(a) < len(b) else (b, a)
    i = j = 0
    skipped = False
    while i < len(short) and j < len(long):
        if short[i] != long[j]:
            if skipped:
                return False
            skipped = True
            j += 1
        else:
            i += 1
            j += 1
    return True


def _typosquat(name, ecosystem):
    name = name.lower()
    top = TOP_PACKAGES.get(ecosystem, set())
    if name in top:
        return None
    for known in top:
        if _edit_distance_one(name, known):
            return known
    return None


def _parse_requirements(text):
    deps = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(('#', '-')):
            continue
        line = line.split(';')[0].split('#')[0].strip()
        match = re.match(r'^([A-Za-z0-9][A-Za-z0-9._-]*)', line)
        if match:
            name = match.group(1)
            version = line[len(name):].strip() or None
            deps.append((name, version))
    return deps


def _parse_pyproject(text):
    if tomllib is None:
        return []
    try:
        data = tomllib.loads(text)
    except (ValueError, TypeError):
        return []
    deps = []
    project = data.get('project', {}) if isinstance(data, dict) else {}
    for spec in project.get('dependencies', []) or []:
        match = re.match(r'^([A-Za-z0-9][A-Za-z0-9._-]*)', str(spec))
        if match:
            deps.append((match.group(1), None))
    for group in (project.get('optional-dependencies', {}) or {}).values():
        for spec in group or []:
            match = re.match(r'^([A-Za-z0-9][A-Za-z0-9._-]*)', str(spec))
            if match:
                deps.append((match.group(1), None))
    poetry = data.get('tool', {}).get('poetry', {}) if isinstance(data, dict) else {}
    for key in (poetry.get('dependencies', {}) or {}):
        if key.lower() != 'python':
            deps.append((key, None))
    return deps


def _parse_package_json_deps(text):
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if not isinstance(data, dict):
        return []
    deps = []
    for section in ('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'):
        block = data.get(section)
        if isinstance(block, dict):
            for name, version in block.items():
                deps.append((name, version if isinstance(version, str) else None))
    return deps


def analyze_dependencies(text, name):
    """List declared dependencies (not resolved or fetched) and flag typosquats."""
    base = Path(name).name.lower()
    if base == 'requirements.txt':
        ecosystem, deps = 'pypi', _parse_requirements(text)
    elif base == 'pyproject.toml':
        ecosystem, deps = 'pypi', _parse_pyproject(text)
    elif base == 'package.json':
        ecosystem, deps = 'npm', _parse_package_json_deps(text)
    else:
        return []
    findings = []
    for dep_name, version in deps:
        findings.append({'rule': 'dependency', 'file': name, 'severity': 'info',
                         'ecosystem': ecosystem, 'package': dep_name, 'version': version,
                         'detail': 'declared dependency; not covered by this scan'})
        near = _typosquat(dep_name, ecosystem)
        if near:
            findings.append({'rule': 'typosquat-suspect', 'file': name, 'severity': 'low',
                             'ecosystem': ecosystem, 'package': dep_name,
                             'detail': 'name is one edit from "%s"' % near})
    return findings


def osv_lookup(ecosystem, name, version):
    """Query OSV.dev for known vulnerabilities. Network; caller opts in. Returns
    a list of advisory ids, or None if the lookup could not be completed."""
    osv_ecosystem = {'pypi': 'PyPI', 'npm': 'npm'}.get(ecosystem)
    if not osv_ecosystem:
        return None
    query = {'package': {'name': name, 'ecosystem': osv_ecosystem}}
    if version:
        cleaned = re.sub(r'^[^0-9]*', '', version)
        if cleaned:
            query['version'] = cleaned
    body = json.dumps(query).encode()
    request = urllib.request.Request('https://api.osv.dev/v1/query', data=body,
                                     headers={'Content-Type': 'application/json',
                                              'User-Agent': 'Callback-Guard/1.1'})
    try:
        opener = urllib.request.build_opener(HTTPSOnly())
        with opener.open(request, timeout=15) as response:
            data = json.loads(response.read(1024 * 1024))
        return [v.get('id') for v in data.get('vulns', []) if v.get('id')]
    except Exception:
        return None


def enrich_with_osv(findings):
    """Append known-vulnerability findings for each listed dependency. Mutates and
    returns the findings list. Only called when the user passes --osv."""
    extra = []
    for finding in findings:
        if finding.get('rule') != 'dependency':
            continue
        ids = osv_lookup(finding.get('ecosystem'), finding.get('package'), finding.get('version'))
        if ids is None:
            extra.append({'rule': 'osv-unavailable', 'file': finding.get('file'), 'severity': 'info',
                          'package': finding.get('package'), 'detail': 'OSV lookup could not be completed'})
        elif ids:
            extra.append({'rule': 'known-vulnerability', 'file': finding.get('file'), 'severity': 'high',
                          'package': finding.get('package'), 'detail': 'OSV: ' + ', '.join(ids[:5])})
    findings.extend(extra)
    return findings


def apply_pro_extensions(report, data, name):
    """Optional paid-tier enrichment hook.

    The free engine never ships Pro code. A separately licensed, privately
    distributed `callback_guard_pro` module may be installed alongside it; if
    present, its `enrich(report_snapshot, data, name)` is called and may RETURN
    extra finding dicts to append. The extension receives a deep copy of the
    report, so it cannot mutate or remove the engine's own findings, and the
    caller recomputes the blocking and release decision from the combined
    findings afterwards. An extension that is absent, raises, or returns
    anything unexpected never affects the free scan's result. See ARCHITECTURE.md.
    """
    try:
        import callback_guard_pro  # Optional; resolved at runtime, not shipped here.
    except Exception:
        return  # Free tier: no Pro module installed.
    try:
        added = callback_guard_pro.enrich(copy.deepcopy(report), data, name)
        extra = [f for f in (added or []) if isinstance(f, dict)]
        report['findings'].extend(extra)
        report['pro'] = {'status': 'applied', 'added': len(extra),
                         'version': getattr(callback_guard_pro, '__version__', 'unknown')}
    except Exception as exc:
        # A broken extension must not break or clear the free scan.
        report['pro'] = {'status': 'error', 'error': str(exc)}


def analyze_structural(text, name, allowlist):
    """Dispatch structure-aware analysis by file type. Returns severity-tagged
    findings, with allowlisted rules downgraded."""
    suffix = Path(name).suffix.lower()
    base = Path(name).name.lower()
    findings = []
    if suffix == '.py':
        findings = analyze_python(text, name)
    elif suffix in LANG_BY_SUFFIX:
        findings = analyze_normalized(text, name, LANG_BY_SUFFIX[suffix])
    if base == 'package.json':
        findings += analyze_package_json(text, name)
    if base in DEPENDENCY_MANIFESTS:
        findings += analyze_dependencies(text, name)
    if suffix in INJECTION_SUFFIXES:
        findings += analyze_injection(text, name)
    return [apply_allowlist(f, None, allowlist) for f in findings]


def inspect(data, name):
    """Strict heuristic policy: every finding requires review, never auto-override.

    Classify by content first. Inert media carries no finding unless it hides
    under a text/code extension; executables and unreadable binaries are held;
    text of any language (not only the known extensions) is rule-checked."""
    suffix = Path(name).suffix.lower()
    base = Path(name).name.lower()
    text_extension = suffix in TEXT or base in {'license', 'readme', 'dockerfile', '.gitignore'}
    kind, text = classify(data)
    if kind == 'media':
        if text_extension:
            # Media/binary bytes under a text or code extension is a disguise.
            return [{'rule': 'content-mismatch', 'file': name, 'severity': 'high',
                     'reason': 'Media or binary content under a text/code extension'}]
        return []
    if kind == 'executable':
        return [{'rule': 'binary-executable', 'file': name, 'severity': 'high',
                 'reason': 'Executable or compiled binary; held for review'}]
    if kind == 'unknown-binary':
        return [{'rule': 'unsupported', 'file': name, 'severity': 'high',
                 'reason': 'Unsupported or binary format; held for review'}]
    if len(data) > TEXT_LIMIT:
        return [{'rule': 'incomplete', 'file': name, 'severity': 'high', 'reason': 'Text exceeds 2 MiB'}]
    allowlist = load_allowlist()
    findings = []
    for line_no, line in enumerate(text.splitlines(), 1):
        if any(unicodedata.category(c) == 'Cf' or (ord(c) < 32 and c != '\t') for c in line):
            findings.append({'rule': 'invisible-control', 'file': name, 'line': line_no, 'severity': 'high'})
        normalized = unicodedata.normalize('NFKC', line)
        for rule, pattern, severity in RULES:
            if re.search(pattern, normalized, re.I):
                findings.append(apply_allowlist(
                    {'rule': rule, 'file': name, 'line': line_no, 'severity': severity},
                    line, allowlist))
        if len(findings) >= 1000:
            findings.append({'rule': 'incomplete', 'file': name, 'severity': 'high', 'reason': 'Finding limit reached'})
            break
    findings.extend(analyze_structural(text, name, allowlist))
    source_lines = text.splitlines()
    for finding in findings:
        line_no = finding.get('line')
        if line_no and 1 <= line_no <= len(source_lines) and 'untrusted_excerpt' not in finding:
            finding['untrusted_excerpt'] = escape_excerpt(source_lines[line_no - 1])
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


def run(source=None, url=None, name=None, storage=ROOT / 'intake', osv=False):
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
        if osv:
            # Opt-in network lookup; may add known-vulnerability findings.
            enrich_with_osv(report['findings'])
            report['osv_checked'] = True
        # Optional paid-tier enrichment. May only ADD findings; the blocking and
        # release decision below is recomputed from the combined findings, so a
        # Pro finding can hold a result but never clear one. Absent in the free tier.
        apply_pro_extensions(report, data, name)
        report['blocking'] = blocking(report['findings'])
        report['max_severity'] = max((f.get('severity', 'info') for f in report['findings']),
                                     key=lambda s: SEVERITY_ORDER.get(s, 0), default=None)
        report['risk_summary'] = summarize_risk(report['findings'])
        injection = [f for f in report['findings'] if f.get('rule') == 'prompt-injection']
        if injection:
            # Packet for an optional agent review. A review may ADD findings; it
            # must never clear a held result (see SKILL.md).
            report['injection_review'] = {
                'status': 'not-run',
                'note': 'Heuristic flags only. An agent may classify these passages and add findings; it must never override a held result.',
                'passages': [{'file': f.get('file'), 'line': f.get('line'),
                              'severity': f['severity'], 'signals': f.get('detail')} for f in injection]}
        if (report['antivirus']['status'] == 'completed-no-detection'
                and not report['blocking'] and report['status'] != 'review-required'):
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
    parser.add_argument('--osv', action='store_true',
                        help='Look up declared dependencies against OSV.dev (uses network).')
    args = parser.parse_args()
    if args.gui:
        gui()
    elif args.source or args.url:
        result, report_file = run(source=args.source, url=args.url, name=args.name, osv=args.osv)
        print(json.dumps({'status': result['status'], 'report': str(report_file),
                          'checked_file': result.get('checked_file')}))
        sys.exit(0 if result['status'] == 'checks-passed' else 2)
    else:
        parser.error('Choose --gui, --source FILE, or --url HTTPS_URL --name NAME')
