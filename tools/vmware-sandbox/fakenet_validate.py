#!/usr/bin/env python3
"""FakeNet-NG Configuration Validator

Validates CA certificates, custom_responses.ini, and raw HTTP response files.
Catches common errors: expired certs, missing InstanceName, broken CRLF, etc.

Usage:
    python fakenet_validate.py check-ca <cert_file>
    python fakenet_validate.py check-config <ini_file>
    python fakenet_validate.py check-response <response_file>
    python fakenet_validate.py check-all <fakenet_dir>
"""

import argparse
import configparser
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path


# ANSI colors
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
NC = "\033[0m"


def ok(msg):
    print(f"{GREEN}[PASS]{NC} {msg}")


def fail(msg):
    print(f"{RED}[FAIL]{NC} {msg}")


def warn(msg):
    print(f"{YELLOW}[WARN]{NC} {msg}")


# ============================================================
# check-ca: CA certificate expiry check
# ============================================================
def check_ca(cert_path: str) -> bool:
    """Check CA certificate validity. Returns True if PASS."""
    if not os.path.isfile(cert_path):
        fail(f"Certificate file not found: {cert_path}")
        return False

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        # Fallback: openssl CLI
        warn("cryptography module not installed. Trying openssl CLI...")
        return _check_ca_openssl(cert_path)

    with open(cert_path, "rb") as f:
        data = f.read()

    try:
        if b"-----BEGIN CERTIFICATE-----" in data:
            cert = x509.load_pem_x509_certificate(data)
        else:
            cert = x509.load_der_x509_certificate(data)
    except Exception as e:
        fail(f"Cannot parse certificate: {e}")
        return False

    now = datetime.utcnow()
    not_before = cert.not_valid_before_utc.replace(tzinfo=None)
    not_after = cert.not_valid_after_utc.replace(tzinfo=None)

    print(f"  Subject:    {cert.subject}")
    print(f"  Not Before: {not_before}")
    print(f"  Not After:  {not_after}")

    if now < not_before:
        fail(f"Certificate is not yet valid (starts {not_before})")
        return False

    if now > not_after:
        fail(f"Certificate EXPIRED on {not_after}")
        print(f"  Re-generate with:")
        print(f'    openssl req -x509 -newkey rsa:2048 -keyout fakenet_ca.key -out fakenet_ca.crt \\')
        print(f'      -days 3650 -nodes -subj "/CN=FakeNet CA"')
        print(f'    openssl x509 -in fakenet_ca.crt -outform DER -out fakenet_ca.der')
        return False

    remaining = not_after - now
    if remaining < timedelta(days=30):
        warn(f"Certificate expires in {remaining.days} days ({not_after})")
        print(f"  Consider re-generating soon.")
        return False  # Treat <30 days as FAIL for safety

    ok(f"Certificate valid. Expires in {remaining.days} days ({not_after})")
    return True


def _check_ca_openssl(cert_path: str) -> bool:
    """Fallback CA check using openssl CLI."""
    import subprocess
    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-noout", "-enddate"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            fail(f"openssl failed: {result.stderr.strip()}")
            return False
        # Parse: notAfter=Mar 01 00:00:00 2027 GMT
        line = result.stdout.strip()
        date_str = line.split("=", 1)[1].strip()
        expiry = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
        remaining = expiry - datetime.utcnow()
        if remaining.total_seconds() < 0:
            fail(f"Certificate EXPIRED on {expiry}")
            return False
        if remaining.days < 30:
            warn(f"Certificate expires in {remaining.days} days")
            return False
        ok(f"Certificate valid. Expires in {remaining.days} days")
        return True
    except FileNotFoundError:
        fail("Neither 'cryptography' module nor 'openssl' CLI available")
        return False


# ============================================================
# check-config: custom_responses.ini validation
# ============================================================
VALID_INSTANCE_NAMES = {"HTTPListener80", "HTTPListener443"}
VALID_RESPONSE_KEYS = {"HttpStaticString", "HttpRawFile", "HttpStaticFile"}


def check_config(ini_path: str) -> bool:
    """Validate custom_responses.ini. Returns True if all PASS."""
    if not os.path.isfile(ini_path):
        fail(f"INI file not found: {ini_path}")
        return False

    ini_dir = os.path.dirname(os.path.abspath(ini_path))
    config = configparser.ConfigParser(interpolation=None)
    # Preserve key casing
    config.optionxform = str

    try:
        config.read(ini_path, encoding="utf-8")
    except configparser.Error as e:
        fail(f"INI parse error: {e}")
        return False

    if not config.sections():
        warn("No sections found in INI file")
        return True  # Empty is technically valid

    all_pass = True

    for section in config.sections():
        print(f"\n  [{section}]")

        # InstanceName check
        instance_name = config.get(section, "InstanceName", fallback=None)
        if not instance_name:
            fail(f"  InstanceName missing (required)")
            all_pass = False
        elif instance_name.strip() not in VALID_INSTANCE_NAMES:
            warn(f"  InstanceName '{instance_name.strip()}' not in {VALID_INSTANCE_NAMES}")
            # Not fatal, could be custom listener

        # HttpURIs check
        uris = config.get(section, "HttpURIs", fallback=None)
        if not uris:
            warn(f"  HttpURIs missing")
        elif not uris.strip().startswith("/"):
            fail(f"  HttpURIs should start with '/': got '{uris.strip()}'")
            all_pass = False
        else:
            ok(f"  HttpURIs: {uris.strip()}")

        # Response type check
        response_keys = [k for k in config[section] if k in VALID_RESPONSE_KEYS]
        if not response_keys:
            fail(f"  No response specified (need HttpStaticString, HttpRawFile, or HttpStaticFile)")
            all_pass = False
        elif len(response_keys) > 1:
            warn(f"  Multiple response types: {response_keys} (only first is used)")

        # HttpRawFile existence check
        raw_file = config.get(section, "HttpRawFile", fallback=None)
        if raw_file:
            raw_path = os.path.join(ini_dir, raw_file.strip())
            if os.path.isfile(raw_path):
                ok(f"  HttpRawFile exists: {raw_file.strip()}")
            else:
                fail(f"  HttpRawFile NOT FOUND: {raw_file.strip()} (looked in {ini_dir})")
                all_pass = False

    if all_pass:
        ok(f"Config validation passed: {ini_path}")
    else:
        fail(f"Config validation has errors: {ini_path}")

    return all_pass


# ============================================================
# check-response: Raw HTTP response CRLF validation
# ============================================================
def check_response(file_path: str) -> bool:
    """Validate raw HTTP response file for CRLF compliance. Returns True if PASS."""
    if not os.path.isfile(file_path):
        fail(f"Response file not found: {file_path}")
        return False

    with open(file_path, "rb") as f:
        data = f.read()

    if len(data) == 0:
        fail("Response file is empty")
        return False

    all_pass = True

    # Check for bare LF (LF without preceding CR)
    i = 0
    bare_lf_lines = []
    line_num = 1
    while i < len(data):
        if data[i] == 0x0A:  # LF
            if i == 0 or data[i - 1] != 0x0D:  # No preceding CR
                bare_lf_lines.append(line_num)
            line_num += 1
        i += 1

    if bare_lf_lines:
        fail(f"Bare LF (not CRLF) found on lines: {bare_lf_lines[:10]}")
        all_pass = False
    else:
        ok("All line endings are CRLF")

    # Check header/body separator (CRLFCRLF = \r\n\r\n)
    sep_pos = data.find(b"\r\n\r\n")
    if sep_pos == -1:
        fail("No header/body separator (\\r\\n\\r\\n) found")
        all_pass = False
    else:
        ok(f"Header/body separator found at byte {sep_pos}")

        # Check first line looks like HTTP status
        first_line = data[:data.find(b"\r\n")].decode("utf-8", errors="replace")
        if first_line.startswith("HTTP/"):
            ok(f"Status line: {first_line}")
        else:
            fail(f"First line doesn't look like HTTP status: '{first_line}'")
            all_pass = False

        # Check Content-Type header
        header_block = data[:sep_pos].decode("utf-8", errors="replace")
        if "Content-Type" in header_block or "content-type" in header_block.lower():
            ok("Content-Type header present")
        else:
            warn("Content-Type header missing (recommended)")

    if all_pass:
        ok(f"Response validation passed: {file_path}")
    else:
        fail(f"Response validation has errors: {file_path}")

    return all_pass


# ============================================================
# check-all: run all checks on a FakeNet directory
# ============================================================
def check_all(fakenet_dir: str) -> bool:
    """Run all checks on a FakeNet directory tree. Returns True if all PASS."""
    if not os.path.isdir(fakenet_dir):
        fail(f"Directory not found: {fakenet_dir}")
        return False

    all_pass = True

    # Find and check CA certificates
    print("=" * 60)
    print("CA Certificate Check")
    print("=" * 60)

    cert_patterns = ["*.crt", "*.pem", "*.cer"]
    certs_found = []
    for pattern in cert_patterns:
        certs_found.extend(Path(fakenet_dir).rglob(pattern))

    if certs_found:
        for cert in certs_found:
            print(f"\n  Checking: {cert}")
            if not check_ca(str(cert)):
                all_pass = False
    else:
        warn("No certificate files found (.crt/.pem/.cer)")

    # Find and check custom_responses.ini
    print("\n" + "=" * 60)
    print("Custom Response Config Check")
    print("=" * 60)

    ini_files = list(Path(fakenet_dir).rglob("custom_responses*.ini"))
    if ini_files:
        for ini in ini_files:
            print(f"\n  Checking: {ini}")
            if not check_config(str(ini)):
                all_pass = False
    else:
        warn("No custom_responses*.ini found")

    # Find and check raw HTTP response files referenced in INI
    print("\n" + "=" * 60)
    print("Raw HTTP Response Check")
    print("=" * 60)

    response_files_checked = set()
    for ini in ini_files:
        config = configparser.ConfigParser(interpolation=None)
        config.optionxform = str
        try:
            config.read(str(ini), encoding="utf-8")
        except configparser.Error:
            continue

        ini_dir = os.path.dirname(str(ini))
        for section in config.sections():
            raw_file = config.get(section, "HttpRawFile", fallback=None)
            if raw_file:
                raw_path = os.path.join(ini_dir, raw_file.strip())
                if raw_path not in response_files_checked and os.path.isfile(raw_path):
                    response_files_checked.add(raw_path)
                    print(f"\n  Checking: {raw_path}")
                    if not check_response(raw_path):
                        all_pass = False

    if not response_files_checked:
        warn("No HttpRawFile references found to check")

    # Summary
    print("\n" + "=" * 60)
    if all_pass:
        ok("ALL CHECKS PASSED")
    else:
        fail("SOME CHECKS FAILED - review errors above")
    print("=" * 60)

    return all_pass


# ============================================================
# CLI
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="FakeNet-NG Configuration Validator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s check-ca input/fakenet_ca.crt
  %(prog)s check-config input/custom_responses.ini
  %(prog)s check-response input/vidar_config_response.txt
  %(prog)s check-all input/
        """
    )
    sub = parser.add_subparsers(dest="command")

    p_ca = sub.add_parser("check-ca", help="Check CA certificate expiry")
    p_ca.add_argument("cert", help="Path to certificate file (.crt/.pem/.der)")

    p_config = sub.add_parser("check-config", help="Validate custom_responses.ini")
    p_config.add_argument("ini", help="Path to custom_responses.ini")

    p_resp = sub.add_parser("check-response", help="Validate raw HTTP response file")
    p_resp.add_argument("file", help="Path to raw HTTP response file")

    p_all = sub.add_parser("check-all", help="Run all checks on FakeNet directory")
    p_all.add_argument("dir", help="Path to FakeNet/input directory")

    args = parser.parse_args()

    if args.command == "check-ca":
        sys.exit(0 if check_ca(args.cert) else 1)
    elif args.command == "check-config":
        sys.exit(0 if check_config(args.ini) else 1)
    elif args.command == "check-response":
        sys.exit(0 if check_response(args.file) else 1)
    elif args.command == "check-all":
        sys.exit(0 if check_all(args.dir) else 1)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
