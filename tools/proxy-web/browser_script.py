#!/usr/bin/env python3
"""
Browser automation script for Docker container
Runs in isolated environment with Playwright
Downloads stay inside container; only encrypted archives reach /output
"""

import sys
import os
import json
import time
import gzip
import hashlib
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


DOWNLOAD_DIR = Path('/tmp/downloads')
OUTPUT_DIR = Path('/output')


def calculate_hashes(file_path: Path) -> dict:
    """Calculate MD5, SHA1, SHA256 hashes of a file."""
    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()

    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        'md5': md5.hexdigest(),
        'sha1': sha1.hexdigest(),
        'sha256': sha256.hexdigest()
    }


def encrypt_and_compress(input_path: Path, output_path: Path, password: str):
    """Encrypt with AES-256-CBC and gzip compress. Output to /output."""
    with open(input_path, 'rb') as f:
        plaintext = f.read()

    key = hashlib.sha256(password.encode()).digest()
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    compressed = gzip.compress(iv + ciphertext)

    with open(output_path, 'wb') as f:
        f.write(compressed)


def process_downloaded_file(file_path: Path, password: str) -> dict:
    """Hash, encrypt, and delete a downloaded file. Return metadata."""
    hashes = calculate_hashes(file_path)
    enc_name = f"{file_path.name}.enc.gz"
    enc_path = OUTPUT_DIR / enc_name
    encrypt_and_compress(file_path, enc_path, password)
    size = file_path.stat().st_size
    file_path.unlink()
    return {
        'filename': file_path.name,
        'size': size,
        'hashes': hashes,
        'encrypted_file': enc_name
    }


def download_from_network(url: str, password: str) -> dict | None:
    """Download a URL detected in network log inside container."""
    import urllib.request
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    filename = urlparse(url).path.split('/')[-1] or 'download.bin'
    dest = DOWNLOAD_DIR / filename

    try:
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            with open(dest, 'wb') as f:
                f.write(resp.read())
        info = process_downloaded_file(dest, password)
        info['url'] = url
        return info
    except Exception as e:
        print(f"Secondary download failed ({url}): {e}", file=sys.stderr)
        return None


def analyze_url(url: str, password: str) -> dict:
    """Analyze URL with Playwright in headless Chrome."""
    result = {
        'success': False,
        'final_url': url,
        'screenshot': '',
        'html_file': '',
        'downloads': [],
        'network_log': [],
        'error': ''
    }

    network_requests = []
    downloads_info = []

    try:
        with sync_playwright() as p:
            chromium_args = [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-gpu'
            ]
            # When USE_TOR=1, route Chromium traffic through Tor SOCKS5 proxy
            if os.environ.get('USE_TOR') == '1':
                chromium_args.extend([
                    '--proxy-server=socks5://127.0.0.1:9050',
                    '--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1',
                ])
                print("Tor mode: routing Chromium through SOCKS5 proxy", file=sys.stderr)

            browser = p.chromium.launch(
                headless=True,
                args=chromium_args
            )

            context = browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                accept_downloads=True,
                ignore_https_errors=True
            )

            page = context.new_page()

            # Network logging
            request_id = 0

            def log_request(request):
                nonlocal request_id
                request_id += 1

                network_requests.append({
                    'RequestID': str(request_id),
                    'Timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                    'Method': request.method,
                    'URL': request.url,
                    'Domain': urlparse(request.url).netloc,
                    'DestinationIP': '',
                    'StatusCode': '',
                    'ContentType': '',
                    'ContentLength': '',
                    'Referer': request.headers.get('referer', ''),
                    'UserAgent': request.headers.get('user-agent', ''),
                    'SetCookie': '',
                    'Duration': '',
                    'RedirectTo': '',
                    'Description': f"{request.method} request"
                })

            def log_response(response):
                for req in network_requests:
                    if req['URL'] == response.url and req['StatusCode'] == '':
                        req['StatusCode'] = str(response.status)
                        req['ContentType'] = response.headers.get('content-type', '')
                        req['ContentLength'] = response.headers.get('content-length', '')
                        req['SetCookie'] = response.headers.get('set-cookie', '')

                        if 300 <= response.status < 400:
                            req['RedirectTo'] = response.headers.get('location', '')
                            req['Description'] = f"Redirect to {req['RedirectTo']}"
                        break

            # Download handling - save to /tmp/downloads (not /output)
            def handle_download(download):
                try:
                    download_path = DOWNLOAD_DIR / download.suggested_filename
                    download.save_as(download_path)

                    info = process_downloaded_file(download_path, password)
                    info['url'] = download.url
                    downloads_info.append(info)
                except Exception as e:
                    print(f"Download error: {e}", file=sys.stderr)

            page.on('request', log_request)
            page.on('response', log_response)
            context.on('download', handle_download)

            # Navigate to URL
            try:
                response = page.goto(url, wait_until='networkidle', timeout=30000)
                result['final_url'] = page.url

                time.sleep(2)

                # Screenshot and HTML go directly to /output (safe files)
                screenshot_path = OUTPUT_DIR / 'screenshot.png'
                page.screenshot(path=str(screenshot_path), full_page=True)
                result['screenshot'] = 'screenshot.png'

                html_content = page.content()
                html_path = OUTPUT_DIR / 'page.html'
                with open(html_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                result['html_file'] = 'page.html'

                result['success'] = True

            except PlaywrightTimeout:
                result['error'] = 'Page load timeout (30s)'
            except Exception as e:
                if 'Download is starting' in str(e):
                    time.sleep(10)
                    result['success'] = True
                    result['final_url'] = url
                else:
                    result['error'] = str(e)

            context.close()
            browser.close()

    except Exception as e:
        result['error'] = f"Browser automation failed: {str(e)}"

    # Secondary downloads from network log
    downloadable_types = [
        'application/zip', 'application/x-zip-compressed',
        'application/x-msdownload', 'application/exe',
        'application/x-exe', 'application/x-msdos-program',
        'application/octet-stream', 'application/x-dosexec'
    ]
    already_downloaded = {d['url'] for d in downloads_info}

    for req in network_requests:
        content_type = req.get('ContentType', '').lower()
        req_url = req['URL']
        parsed_url = urlparse(req_url)
        # Only download from http/https schemes (block file://, javascript://, etc.)
        if parsed_url.scheme not in ('http', 'https'):
            continue
        if (any(dt in content_type for dt in downloadable_types)
                and req_url not in already_downloaded):
            info = download_from_network(req_url, password)
            if info:
                downloads_info.append(info)
                already_downloaded.add(req_url)

    result['network_log'] = network_requests
    result['downloads'] = downloads_info

    return result


def main():
    """Main entry point for Docker container."""
    if len(sys.argv) < 2:
        print(json.dumps({'error': 'No URL provided'}))
        sys.exit(1)

    url = sys.argv[1]
    password = os.environ.get('QUARANTINE_PASSWORD', '')
    if not password:
        print(json.dumps({'error': 'QUARANTINE_PASSWORD env not set'}))
        sys.exit(1)

    DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)

    result = analyze_url(url, password)

    # Write result to file (primary output — avoids Docker log truncation)
    result_json = json.dumps(result, ensure_ascii=False)
    try:
        with open(OUTPUT_DIR / 'result.json', 'w', encoding='utf-8') as f:
            f.write(result_json)
    except Exception as e:
        print(f"Warning: failed to write result.json: {e}", file=sys.stderr)

    # Also output to stdout (fallback)
    print(result_json)


if __name__ == '__main__':
    main()
