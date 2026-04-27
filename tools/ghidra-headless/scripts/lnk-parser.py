#!/usr/bin/env python3
"""lnk-parser: Windows LNK file structure parser.

Why this exists: pylnk3 0.4.3 has a bug where TrackerDataBlock parsing fails
with `LookupError: unknown encoding: ansi`. LECmd requires .NET. This tool
parses LNK files using only Python stdlib, with special focus on malware
forensics: padding obfuscation detection, embedded PE/PDF extraction, and
TrackerDataBlock MachineID extraction (operator pivot point).

Usage:
  lnk-parser.py <file.lnk>                         # pretty-print all fields
  lnk-parser.py <file.lnk> --json                  # JSON output
  lnk-parser.py <file.lnk> --extract-embedded OUT  # write embedded PDF/PE to OUT dir
"""
import argparse
import json
import struct
import sys
from pathlib import Path

CLSID_LNK = b'\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46'

LINK_FLAGS = [
    'HasLinkTargetIDList', 'HasLinkInfo', 'HasName', 'HasRelativePath',
    'HasWorkingDir', 'HasArguments', 'HasIconLocation', 'IsUnicode',
    'ForceNoLinkInfo', 'HasExpString', 'RunInSeparateProcess', 'Unused1',
    'HasDarwinID', 'RunAsUser', 'HasExpIcon', 'NoPidlAlias',
    'Unused2', 'RunWithShimLayer', 'ForceNoLinkTrack', 'EnableTargetMetadata',
    'DisableLinkPathTracking', 'DisableKnownFolderTracking', 'DisableKnownFolderAlias',
    'AllowLinkToLink', 'UnaliasOnSave', 'PreferEnvironmentPath',
    'KeepLocalIDListForUNCTarget',
]

EXTRA_BLOCK_SIGS = {
    0xA0000001: 'EnvironmentVariableDataBlock',
    0xA0000002: 'ConsoleDataBlock',
    0xA0000003: 'TrackerDataBlock',
    0xA0000004: 'ConsoleFEDataBlock',
    0xA0000005: 'SpecialFolderDataBlock',
    0xA0000006: 'DarwinDataBlock',
    0xA0000007: 'IconEnvironmentDataBlock',
    0xA0000008: 'ShimDataBlock',
    0xA0000009: 'PropertyStoreDataBlock',
    0xA000000B: 'KnownFolderDataBlock',
    0xA000000C: 'VistaAndAboveIDListDataBlock',
}


def parse_header(data):
    header_size = struct.unpack('<I', data[0:4])[0]
    if header_size != 0x4C:
        raise ValueError(f'Invalid LNK header size: {header_size:#x}')
    if data[4:20] != CLSID_LNK:
        raise ValueError('Not a valid LNK file (CLSID mismatch)')
    flags_val = struct.unpack('<I', data[20:24])[0]
    return {
        'header_size': header_size,
        'link_flags': flags_val,
        'flags_set': [n for i, n in enumerate(LINK_FLAGS) if flags_val & (1 << i)],
        'file_attributes': struct.unpack('<I', data[24:28])[0],
        'target_file_size': struct.unpack('<I', data[52:56])[0],
    }


def parse_string_data(data, offset, is_unicode, keys):
    strings = {}
    for key in keys:
        char_count = struct.unpack('<H', data[offset:offset+2])[0]
        offset += 2
        byte_len = char_count * 2 if is_unicode else char_count
        if is_unicode:
            s = data[offset:offset+byte_len].decode('utf-16-le', errors='replace')
        else:
            s = data[offset:offset+byte_len].decode('cp1252', errors='replace')
        offset += byte_len
        stripped = s.strip()
        padding_before = len(s) - len(s.lstrip())
        padding_after = len(s) - len(s.rstrip())
        # Detect the longest run of consecutive whitespace anywhere inside the string.
        # This catches the classic LNK padding obfuscation trick: `cmd.exe /c ` + <huge
        # whitespace run> + <real command>, which leading/trailing strip() misses.
        import re as _re
        longest_run = 0
        for m in _re.finditer(r'\s{2,}', s):
            longest_run = max(longest_run, m.end() - m.start())
        strings[key] = {
            'raw': s,
            'stripped': stripped,
            'char_count': char_count,
            'padding_before': padding_before,
            'padding_after': padding_after,
            'longest_internal_whitespace': longest_run,
            'obfuscated': padding_before > 20 or padding_after > 20 or longest_run > 50,
        }
    return strings, offset


def parse_extra_data(data, offset, total):
    blocks = []
    while offset + 8 < total:
        block_size = struct.unpack('<I', data[offset:offset+4])[0]
        if block_size < 8 or offset + block_size > total:
            break
        sig = struct.unpack('<I', data[offset+4:offset+8])[0]
        sig_name = EXTRA_BLOCK_SIGS.get(sig, f'Unknown_{sig:#x}')
        block = {'sig': f'{sig:#010x}', 'name': sig_name, 'offset': offset, 'size': block_size}
        try:
            if sig == 0xA0000001:  # EnvironmentVariableDataBlock
                ansi = data[offset+8:offset+8+260].split(b'\x00')[0].decode('cp1252', 'replace')
                uni = data[offset+8+260:offset+8+260+520].decode('utf-16-le', 'replace').split('\x00')[0]
                block['env_ansi'] = ansi
                block['env_unicode'] = uni
            elif sig == 0xA0000007:  # IconEnvironmentDataBlock
                ansi = data[offset+8:offset+8+260].split(b'\x00')[0].decode('cp1252', 'replace')
                uni = data[offset+8+260:offset+8+260+520].decode('utf-16-le', 'replace').split('\x00')[0]
                block['icon_ansi'] = ansi
                block['icon_unicode'] = uni
            elif sig == 0xA0000003:  # TrackerDataBlock
                machine_id = data[offset+16:offset+16+16].split(b'\x00')[0].decode('cp1252', 'replace')
                block['machine_id'] = machine_id
        except Exception as e:
            block['parse_error'] = str(e)
        blocks.append(block)
        offset += block_size
    return blocks, offset


def detect_embedded(data, total):
    finds = []
    pdf_off = data.find(b'%PDF-')
    if pdf_off >= 0:
        pdf_end = data.rfind(b'%%EOF')
        size = (pdf_end + 5 - pdf_off) if pdf_end > pdf_off else (total - pdf_off)
        finds.append({'type': 'PDF', 'offset': pdf_off, 'size': size})
    mz_off = data.find(b'MZ')
    while mz_off >= 0:
        if mz_off + 64 < total:
            e_lfanew = struct.unpack('<I', data[mz_off+0x3c:mz_off+0x40])[0]
            if mz_off + e_lfanew + 4 < total and data[mz_off+e_lfanew:mz_off+e_lfanew+4] == b'PE\x00\x00':
                finds.append({'type': 'PE', 'offset': mz_off, 'e_lfanew': e_lfanew})
        nxt = data.find(b'MZ', mz_off + 1)
        if nxt == mz_off or nxt < 0:
            break
        mz_off = nxt
    return finds


def parse_lnk(path):
    data = Path(path).read_bytes()
    total = len(data)
    result = {'file': str(path), 'size': total}
    result['header'] = parse_header(data)

    offset = 76
    flags = set(result['header']['flags_set'])

    if 'HasLinkTargetIDList' in flags:
        idlist_size = struct.unpack('<H', data[offset:offset+2])[0]
        result['target_id_list_size'] = idlist_size
        offset += 2 + idlist_size

    if 'HasLinkInfo' in flags and 'ForceNoLinkInfo' not in flags:
        li_size = struct.unpack('<I', data[offset:offset+4])[0]
        li_flags = struct.unpack('<I', data[offset+8:offset+12])[0]
        result['link_info'] = {'size': li_size, 'flags': f'{li_flags:#x}'}
        if li_flags & 1:  # VolumeIDAndLocalBasePath
            lbp_off = struct.unpack('<I', data[offset+16:offset+20])[0]
            s_start = offset + lbp_off
            s_end = data.index(b'\x00', s_start)
            result['link_info']['local_base_path'] = data[s_start:s_end].decode('cp1252', 'replace')
        offset += li_size

    str_keys = []
    if 'HasName' in flags: str_keys.append('NAME_STRING')
    if 'HasRelativePath' in flags: str_keys.append('RELATIVE_PATH')
    if 'HasWorkingDir' in flags: str_keys.append('WORKING_DIR')
    if 'HasArguments' in flags: str_keys.append('COMMAND_LINE_ARGUMENTS')
    if 'HasIconLocation' in flags: str_keys.append('ICON_LOCATION')

    is_unicode = 'IsUnicode' in flags
    result['string_data'], offset = parse_string_data(data, offset, is_unicode, str_keys)
    result['extra_data_offset'] = offset
    result['extra_blocks'], end = parse_extra_data(data, offset, total)
    result['tail_bytes'] = total - end
    result['embedded_content'] = detect_embedded(data, total)

    return result, data


def pretty_print(result):
    print(f"[+] File: {result['file']} ({result['size']} bytes)")
    print(f"[+] LinkFlags: {result['header']['link_flags']:#010x}")
    for f in result['header']['flags_set']:
        print(f"    - {f}")
    print(f"[+] TargetFileSize: {result['header']['target_file_size']}")
    if 'link_info' in result and 'local_base_path' in result['link_info']:
        print(f"[+] LocalBasePath: {result['link_info']['local_base_path']}")
    for key, sd in result.get('string_data', {}).items():
        marker = ' ** OBFUSCATED ** ' if sd['obfuscated'] else ''
        print(f"\n[+] {key}{marker} (chars={sd['char_count']}, pad_b={sd['padding_before']}, pad_a={sd['padding_after']}, longest_ws_run={sd.get('longest_internal_whitespace', 0)})")
        if sd.get('longest_internal_whitespace', 0) > 50:
            # Collapse padding for readability
            import re as _re2
            collapsed = _re2.sub(r'\s{20,}', '<...PADDING...>', sd['raw'])
            print(f"    --- COLLAPSED (padding masked) ---")
            print(f"    {collapsed[:2000]}")
        else:
            print(f"    --- STRIPPED ---")
            print(f"    {sd['stripped'][:2000]}")
    print(f"\n[+] ExtraData blocks:")
    for b in result.get('extra_blocks', []):
        print(f"    - {b['name']} ({b['sig']}) @ {b['offset']:#x}, size={b['size']}")
        for k in ('machine_id', 'env_ansi', 'env_unicode', 'icon_ansi', 'icon_unicode'):
            if k in b:
                print(f"      {k}: {b[k]}")
    if result.get('embedded_content'):
        print(f"\n[!] Embedded content detected:")
        for e in result['embedded_content']:
            print(f"    - {e['type']} @ offset={e['offset']:#x}, size={e.get('size', '?')}")


def extract_embedded(result, data, outdir):
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    stem = Path(result['file']).stem
    extracted = []
    for i, e in enumerate(result['embedded_content']):
        if e['type'] == 'PDF' and 'size' in e:
            out = outdir / f'{stem}_embedded_{i}.pdf'
            out.write_bytes(data[e['offset']:e['offset']+e['size']])
            extracted.append(str(out))
            print(f'[+] Extracted PDF: {out} ({e["size"]} bytes)')
        elif e['type'] == 'PE':
            out = outdir / f'{stem}_embedded_{i}.exe'
            out.write_bytes(data[e['offset']:])  # best effort — rest of file
            extracted.append(str(out))
            print(f'[+] Extracted PE: {out} ({len(data)-e["offset"]} bytes, tail-dump)')
    return extracted


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('lnk_file', help='Path to .lnk file')
    ap.add_argument('--json', action='store_true', help='Output as JSON')
    ap.add_argument('--extract-embedded', metavar='OUTDIR', help='Extract embedded PDF/PE to OUTDIR')
    args = ap.parse_args()

    if not Path(args.lnk_file).exists():
        print(f'File not found: {args.lnk_file}', file=sys.stderr)
        sys.exit(2)

    try:
        result, data = parse_lnk(args.lnk_file)
    except Exception as e:
        print(f'Parse error: {e}', file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    else:
        pretty_print(result)

    if args.extract_embedded:
        extract_embedded(result, data, args.extract_embedded)


if __name__ == '__main__':
    main()
