#!/usr/bin/env python3
"""
Decrypt and decompress files from Quarantine folder
"""

import sys
import os
import gzip
import hashlib
import argparse
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from dotenv import load_dotenv


def decrypt_and_decompress(encrypted_path: Path, output_path: Path, password: str):
    """Decrypt and decompress file."""
    # Read encrypted file
    with open(encrypted_path, 'rb') as f:
        compressed_data = f.read()

    # Decompress
    data = gzip.decompress(compressed_data)

    # Extract IV and ciphertext
    iv = data[:16]
    ciphertext = data[16:]

    # Derive key from password
    key = hashlib.sha256(password.encode()).digest()

    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # Write to output
    with open(output_path, 'wb') as f:
        f.write(plaintext)

    print(f"[OK] Decrypted: {encrypted_path} -> {output_path}")


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(description='Decrypt Quarantine files')
    parser.add_argument('encrypted_file', type=str, help='Path to encrypted file (.enc.gz)')
    parser.add_argument('-o', '--output', type=str, help='Output file path', default=None)
    parser.add_argument('-p', '--password', type=str, help='Decryption password (or use QUARANTINE_PASSWORD env)', default=None)

    args = parser.parse_args()

    # Safety guard: refuse to run on host OS (must be inside Docker container)
    in_docker = os.path.exists("/.dockerenv") or os.environ.get("CONTAINER_ENV")
    if not in_docker:
        print("ERROR: This script must run inside a Docker container, not on the host OS.")
        print("       Decrypting malware on the host is dangerous.")
        print("       Use: docker exec ghidra-headless python3 /opt/ghidra-scripts/decrypt_quarantine.py ...")
        sys.exit(1)

    # Get password
    password = args.password
    if not password:
        load_dotenv()
        password = os.environ.get('QUARANTINE_PASSWORD')

    if not password:
        print("Error: Password required (use -p or QUARANTINE_PASSWORD env)")
        sys.exit(1)

    encrypted_path = Path(args.encrypted_file)
    if not encrypted_path.exists():
        print(f"Error: File not found: {encrypted_path}")
        sys.exit(1)

    # Determine output path
    if args.output:
        output_path = Path(args.output)
    else:
        # Remove .enc.gz extension
        output_path = encrypted_path.parent / encrypted_path.name.replace('.enc.gz', '')

    try:
        decrypt_and_decompress(encrypted_path, output_path, password)
        print(f"[OK] Output: {output_path}")
    except Exception as e:
        print(f"Error: Decryption failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
