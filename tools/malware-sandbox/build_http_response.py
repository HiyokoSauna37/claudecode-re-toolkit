#!/usr/bin/env python3
"""HTTP Response Builder for FakeNet-NG

Generates raw HTTP response files with guaranteed CRLF line endings.
Supports templates for common malware C2 responses.

Usage:
    python build_http_response.py --status 200 --content-type text/plain --body "ok" --output resp.txt
    python build_http_response.py --from-body body.txt --content-type text/plain --output resp.txt
    python build_http_response.py --template vidar-config --output resp.txt
    python build_http_response.py --template vidar-client --output resp.txt
    python build_http_response.py --list-templates
    python build_http_response.py --template vidar-config --output resp.txt --validate
"""

import argparse
import os
import subprocess
import sys
from datetime import datetime


CRLF = b"\r\n"

# ============================================================
# Templates
# ============================================================
TEMPLATES = {
    "vidar-config": {
        "description": "Vidar Stealer /api/config response (semicolon-separated fields)",
        "status": 200,
        "content_type": "text/plain",
        "body": (
            "1,1,1,1,1,"                                    # flags (browser, crypto, etc.)
            "FAKENETID000000000000000000000000,"              # bot ID placeholder
            "1,1,1,1,250,"                                   # more flags + timeout
            "Default;"                                        # profile name
            "%DOCUMENTS%\\;"                                  # search path
            "*.txt:*.dat:*wallet*.*:*2fa*.*:*backup*.*:"     # file patterns
            "*code*.*:*password*.*:*auth*.*:*google*.*:"
            "*utc*.*:*UTC*.*:*crypt*.*:*key*.*;"
            "50;"                                             # max file size MB
            "true;"                                           # recursive
            "movies:music:mp3:exe;"                           # exclude extensions
        ),
    },
    "vidar-client": {
        "description": "Vidar Stealer /api/client response (simple 'ok')",
        "status": 200,
        "content_type": "text/plain",
        "body": "ok",
    },
    "generic-json": {
        "description": "Generic JSON 200 OK response",
        "status": 200,
        "content_type": "application/json",
        "body": '{"status":"ok"}',
    },
    "generic-html": {
        "description": "Generic HTML 200 OK response",
        "status": 200,
        "content_type": "text/html",
        "body": "<html><body>OK</body></html>",
    },
    "empty-200": {
        "description": "Empty 200 OK response (no body)",
        "status": 200,
        "content_type": "text/plain",
        "body": "",
    },
}

STATUS_TEXTS = {
    200: "OK",
    201: "Created",
    204: "No Content",
    301: "Moved Permanently",
    302: "Found",
    400: "Bad Request",
    403: "Forbidden",
    404: "Not Found",
    500: "Internal Server Error",
}


def build_response(status: int, content_type: str, body: str) -> bytes:
    """Build a raw HTTP response with CRLF line endings."""
    status_text = STATUS_TEXTS.get(status, "OK")
    body_bytes = body.encode("utf-8") if body else b""

    lines = [
        f"HTTP/1.1 {status} {status_text}".encode("utf-8"),
        f"Content-Type: {content_type}".encode("utf-8"),
        f"Content-Length: {len(body_bytes)}".encode("utf-8"),
        b"Connection: close",
    ]

    result = CRLF.join(lines) + CRLF + CRLF + body_bytes
    return result


def write_response(data: bytes, output_path: str):
    """Write response bytes to file in binary mode (preserving CRLF)."""
    with open(output_path, "wb") as f:
        f.write(data)
    print(f"[*] Written {len(data)} bytes to {output_path}")


def validate_output(output_path: str) -> bool:
    """Run fakenet_validate.py check-response on the output."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    validator = os.path.join(script_dir, "fakenet_validate.py")

    if not os.path.isfile(validator):
        print("[!] fakenet_validate.py not found, skipping validation")
        return True

    result = subprocess.run(
        [sys.executable, validator, "check-response", output_path],
        capture_output=False
    )
    return result.returncode == 0


def list_templates():
    """Print available templates."""
    print("Available templates:")
    print()
    for name, tmpl in TEMPLATES.items():
        print(f"  {name}")
        print(f"    {tmpl['description']}")
        print(f"    Content-Type: {tmpl['content_type']}")
        body_preview = tmpl['body'][:80] + ("..." if len(tmpl['body']) > 80 else "")
        print(f"    Body preview: {body_preview}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="HTTP Response Builder for FakeNet-NG Custom Responses",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --template vidar-config --output vidar_config_response.txt
  %(prog)s --template vidar-client --output vidar_client_response.txt
  %(prog)s --status 200 --content-type text/plain --body "hello" --output resp.txt
  %(prog)s --from-body body.txt --content-type application/json --output resp.txt
  %(prog)s --list-templates
        """
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument("--template", choices=list(TEMPLATES.keys()),
                       help="Use a predefined template")
    group.add_argument("--from-body", metavar="FILE",
                       help="Read body from file")
    group.add_argument("--list-templates", action="store_true",
                       help="List available templates")

    parser.add_argument("--status", type=int, default=200,
                        help="HTTP status code (default: 200)")
    parser.add_argument("--content-type", default="text/plain",
                        help="Content-Type header (default: text/plain)")
    parser.add_argument("--body", default="",
                        help="Response body string")
    parser.add_argument("--output", "-o", metavar="FILE",
                        help="Output file path")
    parser.add_argument("--validate", action="store_true",
                        help="Run check-response after generation")

    args = parser.parse_args()

    if args.list_templates:
        list_templates()
        return

    # Determine response parameters
    if args.template:
        tmpl = TEMPLATES[args.template]
        status = tmpl["status"]
        content_type = tmpl["content_type"]
        body = tmpl["body"]
    elif args.from_body:
        if not os.path.isfile(args.from_body):
            print(f"[!] Body file not found: {args.from_body}")
            sys.exit(1)
        with open(args.from_body, "r", encoding="utf-8") as f:
            body = f.read()
        status = args.status
        content_type = args.content_type
    else:
        status = args.status
        content_type = args.content_type
        body = args.body

    if not args.output:
        print("[!] --output is required (except with --list-templates)")
        sys.exit(1)

    # Build and write
    data = build_response(status, content_type, body)
    write_response(data, args.output)

    # Optional validation
    if args.validate:
        print()
        if not validate_output(args.output):
            sys.exit(1)


if __name__ == "__main__":
    main()
