#!/usr/bin/env python3
"""chunk-extract: Extract embedded payload chunks from PE .rdata by RVA+size.

Why this exists: Rust/Go malware loaders commonly embed next-stage payloads
directly in .rdata as DAT_xxx blobs. Ghidra's decompile reveals the RVA and
size, but there's no standard tool to dump those bytes to disk. This tool
takes a PE file + a list of (RVA, size) pairs and writes each chunk as a
separate file, with entropy + magic byte analysis for downstream triage.

Usage:
  # Single chunk
  chunk-extract.py <pe> --rva 0x140041e2d --size 0x57964 --out chunk1.bin

  # Multiple chunks from a config file (one VA size name per line)
  chunk-extract.py <pe> --batch chunks.txt --outdir ./chunks/

  # chunks.txt format (comments start with #):
  #   # name       VA            size
  #   chunk1       0x140041e2d   0x57964
  #   chunk2       0x140099791   0x118423

Output: each chunk as separate file + a manifest.json with entropy/magic info.
"""
import argparse
import hashlib
import json
import math
import sys
from collections import Counter
from pathlib import Path

try:
    import pefile
except ImportError:
    print('ERROR: pefile required. pip install pefile', file=sys.stderr)
    sys.exit(2)

KNOWN_MAGIC = [
    (b'MZ', 'PE'),
    (b'PK\x03\x04', 'ZIP'),
    (b'\x1f\x8b\x08', 'GZ'),
    (b'\x7fELF', 'ELF'),
    (b'%PDF-', 'PDF'),
    (b'\x89PNG', 'PNG'),
    (b'BM', 'BMP'),
    (b'GIF8', 'GIF'),
    (b'Rar!', 'RAR'),
    (b'7z\xbc\xaf\x27\x1c', '7Z'),
    (b'\x1f\x9d', 'LZW'),
    (b'MSCF', 'CAB'),
    (b'\xfd7zXZ\x00', 'XZ'),
    (b'(\xb5/\xfd', 'ZSTD'),
    (b'LZIP', 'LZIP'),
    (b'\x04\x22\x4d\x18', 'LZ4'),
    (b'BZh', 'BZIP2'),
]


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    total = len(data)
    return -sum((n/total) * math.log2(n/total) for n in c.values())


def detect_magic(data: bytes) -> str:
    for magic, name in KNOWN_MAGIC:
        if data.startswith(magic):
            return name
    return 'unknown'


def rva_to_file_offset(pe: 'pefile.PE', rva: int) -> int:
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return s.PointerToRawData + (rva - s.VirtualAddress)
    raise ValueError(f'RVA {rva:#x} not in any section')


def va_to_rva(pe: 'pefile.PE', va: int) -> int:
    return va - pe.OPTIONAL_HEADER.ImageBase


def extract_chunk(data: bytes, pe: 'pefile.PE', va: int, size: int) -> dict:
    rva = va_to_rva(pe, va)
    foff = rva_to_file_offset(pe, rva)
    chunk = data[foff:foff+size]
    return {
        'va': f'{va:#x}',
        'rva': f'{rva:#x}',
        'file_offset': f'{foff:#x}',
        'size': size,
        'actual_size': len(chunk),
        'entropy': round(entropy(chunk), 3),
        'magic': detect_magic(chunk),
        'sha256': hashlib.sha256(chunk).hexdigest(),
        'head_hex': chunk[:32].hex(),
        'tail_hex': chunk[-16:].hex(),
        '_bytes': chunk,
    }


def parse_batch(path: Path):
    chunks = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        name, va_str, size_str = parts[0], parts[1], parts[2]
        va = int(va_str, 0)
        size = int(size_str, 0)
        chunks.append({'name': name, 'va': va, 'size': size})
    return chunks


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('pe_file', type=Path, help='PE file to extract from')
    ap.add_argument('--rva', help='RVA (single chunk mode) — can be hex (0x...) or decimal')
    ap.add_argument('--va', help='VA (alternative to --rva)')
    ap.add_argument('--size', help='Chunk size')
    ap.add_argument('--out', type=Path, help='Output file (single chunk mode)')
    ap.add_argument('--batch', type=Path, help='Batch config file (name VA size per line)')
    ap.add_argument('--outdir', type=Path, default=Path('./chunks'), help='Output directory (batch mode)')
    args = ap.parse_args()

    if not args.pe_file.exists():
        print(f'PE not found: {args.pe_file}', file=sys.stderr)
        sys.exit(1)

    data = args.pe_file.read_bytes()
    pe = pefile.PE(data=data)

    chunks_to_extract = []
    if args.batch:
        if not args.batch.exists():
            print(f'Batch file not found: {args.batch}', file=sys.stderr)
            sys.exit(1)
        chunks_to_extract = parse_batch(args.batch)
    elif args.size:
        if args.va:
            va = int(args.va, 0)
        elif args.rva:
            va = int(args.rva, 0) + pe.OPTIONAL_HEADER.ImageBase
        else:
            print('ERROR: --rva or --va required (or --batch)', file=sys.stderr)
            sys.exit(1)
        size = int(args.size, 0)
        chunks_to_extract = [{'name': 'chunk', 'va': va, 'size': size}]
    else:
        print('ERROR: specify --batch or --rva/--va + --size', file=sys.stderr)
        sys.exit(1)

    outdir = args.outdir
    outdir.mkdir(parents=True, exist_ok=True)

    manifest = {'pe_file': str(args.pe_file), 'pe_size': len(data), 'chunks': []}
    for c in chunks_to_extract:
        try:
            info = extract_chunk(data, pe, c['va'], c['size'])
        except ValueError as e:
            print(f"[ERR] {c['name']}: {e}", file=sys.stderr)
            continue

        if args.batch:
            out_path = outdir / f"{c['name']}.bin"
        else:
            out_path = args.out or (outdir / 'chunk.bin')

        chunk_bytes = info.pop('_bytes')
        out_path.write_bytes(chunk_bytes)
        info['name'] = c['name']
        info['output'] = str(out_path)
        manifest['chunks'].append(info)
        print(f"[+] {c['name']}: VA={info['va']} size={info['actual_size']} entropy={info['entropy']} magic={info['magic']} -> {out_path}")

    manifest_path = outdir / 'manifest.json'
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False))
    print(f'[+] Manifest: {manifest_path}')


if __name__ == '__main__':
    main()
