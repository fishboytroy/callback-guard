"""Bounded, non-executing APK triage. Not a malware or signature verifier."""
import hashlib
import io
from pathlib import PurePosixPath
import re
import struct
import zipfile

MAX_EXPANDED = 256 * 1024 * 1024
MAX_MEMBER = 64 * 1024 * 1024
MAX_ENTRIES = 10000


def manifest_elements(data):
    """Read Android binary XML start elements; reject malformed bounds."""
    def unpack(fmt, offset, end):
        if offset < 0 or offset + struct.calcsize(fmt) > end:
            raise ValueError('Truncated Android binary XML')
        return struct.unpack_from(fmt, data, offset)

    kind, header, size = unpack('<HHI', 0, len(data))
    if kind != 3 or header != 8 or size != len(data):
        raise ValueError('Invalid Android binary XML header')
    strings, elements = [], []
    offset = header
    while offset < size:
        kind, head, length = unpack('<HHI', offset, size)
        end = offset + length
        if head < 8 or length < head or end > size:
            raise ValueError('Invalid Android XML chunk')
        if kind == 1:
            count, styles, flags, start, _ = unpack('<IIIII', offset + 8, end)
            if head < 28 or count > 100000 or head + 4 * (count + styles) > length:
                raise ValueError('Invalid Android string pool')
            strings = []
            for index in range(count):
                relative, = unpack('<I', offset + head + 4 * index, end)
                pos = offset + start + relative
                def read_length(pos, utf8):
                    fmt, step, mask = ('<B', 1, 128) if utf8 else ('<H', 2, 32768)
                    value, = unpack(fmt, pos, end)
                    pos += step
                    if value & mask:
                        extra, = unpack(fmt, pos, end)
                        value = ((value & (mask - 1)) << (8 if utf8 else 16)) | extra
                        pos += step
                    return value, pos
                utf8 = bool(flags & 256)
                amount, pos = read_length(pos, utf8)
                if utf8:
                    amount, pos = read_length(pos, True)
                byte_count = amount if utf8 else amount * 2
                terminator = 1 if utf8 else 2
                if pos + byte_count + terminator > end or any(data[pos + byte_count:pos + byte_count + terminator]):
                    raise ValueError('Invalid Android string bounds')
                strings.append(data[pos:pos + byte_count].decode('utf-8' if utf8 else 'utf-16le'))
        elif kind == 0x102:
            if head < 16:
                raise ValueError('Invalid Android element')
            base = offset + head
            _, name, attr_start, attr_size, count = unpack('<IIHHH', base, end)
            if attr_size < 20 or count > 4096 or base + attr_start + attr_size * count > end:
                raise ValueError('Invalid Android attributes')
            def string(index):
                if index >= len(strings):
                    raise ValueError('Invalid Android string reference')
                return strings[index]
            attrs = {}
            for index in range(count):
                pos = base + attr_start + index * attr_size
                ns, key, raw, value_size, zero, typ, value = unpack('<IIIHBBI', pos, end)
                if value_size != 8 or zero:
                    raise ValueError('Invalid Android typed value')
                val = string(raw) if raw != 0xffffffff else string(value) if typ == 3 else bool(value) if typ == 18 else value
                key = (string(ns) + ':' if ns != 0xffffffff else '') + string(key)
                attrs[key] = val
            elements.append({'tag': string(name), 'attributes': attrs})
        offset = end
    if not elements or elements[0]['tag'] != 'manifest':
        raise ValueError('Missing manifest root')
    return elements


def inspect_apk(data):
    result = {'mode': 'apk', 'members': [], 'findings': [],
              'signature': {'status': 'not-verified'},
              'limitations': ['APK signing identity and cryptographic signatures are not verified.',
                              'Compiled code receives inventory and string-indicator triage, not decompilation or behavioral analysis.',
                              'No dependency vulnerability lookup, runtime analysis, or publisher identity verification.']}
    names, manifest = set(), None
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        total = sum(entry.file_size for entry in entries)
        if len(entries) > MAX_ENTRIES or total > MAX_EXPANDED:
            raise ValueError('APK exceeds 10000 entries or 256 MiB expanded size')
        result.update(entry_count=len(entries), expanded_bytes=total)
        for entry in entries:
            path = PurePosixPath(entry.filename)
            mode = (entry.external_attr >> 16) & 0o170000
            if (path.is_absolute() or '..' in path.parts or '\\' in entry.filename
                    or ':' in entry.filename or '\x00' in entry.filename
                    or entry.filename in names or mode not in (0, 0o100000, 0o040000)):
                raise ValueError('Unsafe or duplicate APK member')
            # Android ZIP names are case-sensitive; nothing is extracted to Windows.
            names.add(entry.filename)
            if entry.flag_bits & 1 or entry.file_size > MAX_MEMBER:
                raise ValueError('Encrypted APK member or member exceeds 64 MiB')
            if entry.is_dir():
                continue
            with archive.open(entry) as stream:
                content = stream.read(MAX_MEMBER + 1)
            if len(content) != entry.file_size:
                raise ValueError('APK member size mismatch')
            category = 'dex' if content.startswith(b'dex\n') else 'native-library' if content.startswith(b'\x7fELF') else 'resource-or-metadata'
            member = {'name': entry.filename, 'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest(), 'category': category}
            if category in ('dex', 'native-library'):
                indicators = [term.decode() for term in (b'DexClassLoader', b'Runtime;->exec', b'ProcessBuilder', b'android/webkit/WebView') if term in content]
                member['string_indicators'] = indicators
                member['url_samples'] = sorted(set(x.decode('ascii', errors='replace') for x in re.findall(rb'https?://[\x21-\x7e]{1,256}', content)))[:50]
            if content.startswith((b'PK\x03\x04', b'MZ', b'#!')):
                result['findings'].append({'rule': 'embedded-executable-or-archive', 'file': entry.filename})
            result['members'].append(member)
            if entry.filename == 'AndroidManifest.xml':
                if len(content) > 4 * 1024 * 1024:
                    raise ValueError('APK manifest exceeds 4 MiB')
                manifest = manifest_elements(content)
    if manifest is None:
        raise ValueError('APK has no AndroidManifest.xml')
    result['manifest'] = manifest
    android = 'http://schemas.android.com/apk/res/android:'
    result['package'] = manifest[0]['attributes'].get('package')
    result['permissions'] = [e['attributes'].get(android + 'name') for e in manifest if e['tag'].startswith('uses-permission')]
    for element in manifest:
        attrs = element['attributes']
        for flag in ('debuggable', 'testOnly', 'usesCleartextTraffic'):
            if attrs.get(android + flag) is True:
                result['findings'].append({'rule': 'manifest-review', 'flag': flag, 'tag': element['tag']})
    result['findings'].append({'rule': 'incomplete-apk-analysis', 'reason': '; '.join(result['limitations'])})
    result['status'] = 'review-required'
    return result
