#!/usr/bin/env python3
"""
Decrypt and decompress quarantine files inside Ghidra container.
Simplified version - reads QUARANTINE_PASSWORD from env directly (no .env file needed).
"""

import sys
import os
import gzip
import hashlib
import argparse
import logging
import time
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

logger = logging.getLogger(__name__)


def setup_logging(level=logging.INFO):
    """Configure logging format and level."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def decrypt_and_decompress(encrypted_path: Path, output_path: Path, password: str):
    logger.info("decrypt_and_decompress: entry - encrypted_path='%s', output_path='%s'", encrypted_path, output_path)
    start_time = time.time()

    logger.debug("Reading encrypted file: %s", encrypted_path)
    read_start = time.time()
    with open(encrypted_path, 'rb') as f:
        compressed_data = f.read()
    read_elapsed = time.time() - read_start
    logger.debug("Read %d bytes in %.3f seconds", len(compressed_data), read_elapsed)

    logger.debug("Decompressing gzip data")
    decompress_start = time.time()
    data = gzip.decompress(compressed_data)
    decompress_elapsed = time.time() - decompress_start
    logger.debug("Decompressed to %d bytes in %.3f seconds", len(data), decompress_elapsed)

    iv = data[:16]
    ciphertext = data[16:]
    logger.debug("IV length=%d, ciphertext length=%d", len(iv), len(ciphertext))

    logger.debug("Deriving AES key from password via SHA-256")
    key = hashlib.sha256(password.encode()).digest()

    logger.debug("Decrypting with AES-CBC")
    decrypt_start = time.time()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    decrypt_elapsed = time.time() - decrypt_start
    logger.debug("AES decryption completed in %.3f seconds", decrypt_elapsed)

    logger.debug("Removing PKCS7 padding")
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    logger.debug("Plaintext size after unpadding: %d bytes", len(plaintext))

    logger.debug("Writing decrypted output to: %s", output_path)
    write_start = time.time()
    with open(output_path, 'wb') as f:
        f.write(plaintext)
    write_elapsed = time.time() - write_start
    logger.debug("Wrote %d bytes in %.3f seconds", len(plaintext), write_elapsed)

    # Calculate and display hash
    sha256 = hashlib.sha256(plaintext).hexdigest()
    total_elapsed = time.time() - start_time
    print(f"[OK] Decrypted: {encrypted_path.name} -> {output_path}")
    print(f"[OK] SHA256: {sha256}")
    print(f"[OK] Size: {len(plaintext)} bytes")

    logger.info("decrypt_and_decompress: exit - sha256=%s, size=%d bytes, total_time=%.3f seconds", sha256, len(plaintext), total_elapsed)
    return output_path


def main():
    logger.info("main: entry")
    setup_logging()

    parser = argparse.ArgumentParser(description='Decrypt quarantine files (container version)')
    parser.add_argument('encrypted_file', type=str, help='Path to encrypted file (.enc.gz)')
    parser.add_argument('-o', '--output', type=str, help='Output file path', default=None)
    parser.add_argument('-p', '--password', type=str, help='Decryption password', default=None)

    args = parser.parse_args()
    logger.debug("main: parsed arguments - encrypted_file='%s', output='%s', password=%s", args.encrypted_file, args.output, "provided" if args.password else "not provided")

    password = args.password or os.environ.get('QUARANTINE_PASSWORD')
    if not password:
        logger.error("main: No password provided via -p flag or QUARANTINE_PASSWORD environment variable")
        print("Error: Password required (use -p or QUARANTINE_PASSWORD env)")
        sys.exit(1)
    logger.debug("main: Password source: %s", "command-line argument" if args.password else "QUARANTINE_PASSWORD env")

    encrypted_path = Path(args.encrypted_file)
    if not encrypted_path.exists():
        logger.error("main: Encrypted file not found: %s", encrypted_path)
        print(f"Error: File not found: {encrypted_path}")
        sys.exit(1)
    logger.info("main: Input file exists, size=%d bytes", encrypted_path.stat().st_size)

    if args.output:
        output_path = Path(args.output)
        logger.debug("main: Using explicit output path: %s", output_path)
    else:
        output_path = encrypted_path.parent / encrypted_path.name.replace('.enc.gz', '')
        logger.debug("main: Auto-generated output path: %s", output_path)

    try:
        decrypt_and_decompress(encrypted_path, output_path, password)
        logger.info("main: Decryption completed successfully")
    except Exception as e:
        logger.error("main: Decryption failed: %s", e, exc_info=True)
        print(f"Error: Decryption failed: {e}")
        sys.exit(1)

    logger.info("main: exit")


if __name__ == '__main__':
    main()
