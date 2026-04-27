#!/usr/bin/env python3
"""pe-encrypt: Encrypt a file to quarantine .enc.gz format (proxy-web compatible).

Why this exists: The project rule is "never decrypt malware on the host OS".
This tool encrypts any file (typically malware extracted inside a container)
to AES-256-CBC + gzip format, so it can be safely transferred via host
filesystem to vmware-sandbox VMs for dynamic analysis. The output format
matches decrypt_quarantine.py / vm_quarantine_decrypt.ps1.

Format: gzip(IV[16B] || AES-256-CBC(PKCS7(data))), key = SHA256(password).

Usage:
  pe-encrypt.py <input> <output.enc.gz>              # use QUARANTINE_PASSWORD env
  pe-encrypt.py <input> <output.enc.gz> -p <pass>    # explicit password

Safety: This script refuses to run on the host OS unless --host-ok is given.
Intended use: inside ghidra-headless docker container.
"""
import argparse
import gzip
import hashlib
import os
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
except ImportError:
    print('ERROR: cryptography package required. pip install cryptography', file=sys.stderr)
    sys.exit(2)


def encrypt(in_path: Path, out_path: Path, password: str) -> None:
    data = in_path.read_bytes()
    key = hashlib.sha256(password.encode()).digest()
    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    ciphertext = enc.update(padded) + enc.finalize()

    blob = iv + ciphertext
    compressed = gzip.compress(blob)
    out_path.write_bytes(compressed)

    print(f'[OK] Encrypted: {in_path} ({len(data)} bytes)')
    print(f'     -> {out_path} ({len(compressed)} bytes)')
    print(f'     IV (first 4 bytes): {iv[:4].hex()}')


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('input', type=Path, help='Input file (typically inside container)')
    ap.add_argument('output', type=Path, help='Output .enc.gz file')
    ap.add_argument('-p', '--password', help='Password (falls back to QUARANTINE_PASSWORD env)')
    ap.add_argument('--host-ok', action='store_true', help='Allow running on host OS (dangerous — use only for non-malware files)')
    args = ap.parse_args()

    in_docker = os.path.exists('/.dockerenv') or os.environ.get('CONTAINER_ENV')
    if not in_docker and not args.host_ok:
        print('ERROR: Refusing to run on host OS. Use inside a container.', file=sys.stderr)
        print('       Rationale: encrypting malware on host may trigger Defender.', file=sys.stderr)
        print('       If the input is non-malware, pass --host-ok.', file=sys.stderr)
        sys.exit(3)

    password = args.password or os.environ.get('QUARANTINE_PASSWORD')
    if not password:
        print('ERROR: Password required (use -p or QUARANTINE_PASSWORD env).', file=sys.stderr)
        sys.exit(4)

    if not args.input.exists():
        print(f'ERROR: Input not found: {args.input}', file=sys.stderr)
        sys.exit(5)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    encrypt(args.input, args.output, password)


if __name__ == '__main__':
    main()
