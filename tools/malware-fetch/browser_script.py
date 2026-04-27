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
import re
import base64
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


def decode_base64_payloads(texts: list[str]) -> list[dict]:
    """Scan texts for Base64 strings, decode them, and return results."""
    b64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
    results = []
    seen = set()

    for text in texts:
        for match in b64_pattern.finditer(text):
            b64str = match.group()
            if b64str in seen:
                continue
            seen.add(b64str)
            try:
                decoded_bytes = base64.b64decode(b64str)
                # Check if result is printable text
                try:
                    decoded_text = decoded_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    try:
                        decoded_text = decoded_bytes.decode('ascii')
                    except UnicodeDecodeError:
                        # Binary data - show hex preview
                        decoded_text = None

                if decoded_text and any(c.isprintable() for c in decoded_text[:50]):
                    context_start = max(0, match.start() - 60)
                    context_end = min(len(text), match.end() + 60)
                    results.append({
                        'encoded': b64str[:120] + ('...' if len(b64str) > 120 else ''),
                        'decoded': decoded_text[:2000],
                        'length': len(b64str),
                        'context': text[context_start:context_end]
                    })
            except Exception:
                continue

    return results


def extract_page_assets(page, output_dir: Path) -> dict:
    """Extract JS files, inline scripts, and DOM structure from page.

    Designed for ClickFix analysis: captures external JS sources,
    inline script contents, clipboard hijack attempts, and rendered DOM.
    """
    assets = {
        'external_js': [],
        'inline_scripts': [],
        'clipboard_commands': [],
        'dom_structure': '',
        'iframes': [],
        'forms': [],
        'decoded_payloads': [],
        'event_listeners': []
    }

    all_script_texts = []  # Collect for Base64 scanning

    # 1. Extract external JS URLs and content from network responses
    try:
        js_elements = page.query_selector_all('script[src]')
        for i, el in enumerate(js_elements):
            src = el.get_attribute('src')
            if not src:
                continue
            try:
                js_content = page.evaluate('''(src) => {
                    return fetch(src).then(r => r.text()).catch(() => null);
                }''', src)
            except Exception:
                js_content = None

            js_filename = f'script_{i}.js'
            if js_content:
                js_path = output_dir / js_filename
                with open(js_path, 'w', encoding='utf-8') as f:
                    f.write(js_content)
                assets['external_js'].append({
                    'src': src,
                    'file': js_filename,
                    'size': len(js_content)
                })
                all_script_texts.append(js_content)
    except Exception as e:
        print(f"External JS extraction error: {e}", file=sys.stderr)

    # 2. Extract inline scripts
    try:
        inline_scripts = page.evaluate('''() => {
            const scripts = document.querySelectorAll('script:not([src])');
            return Array.from(scripts).map((s, i) => ({
                index: i,
                content: s.textContent,
                type: s.type || 'text/javascript'
            }));
        }''')
        for script in inline_scripts:
            if not script['content'] or not script['content'].strip():
                continue
            inline_filename = f'inline_{script["index"]}.js'
            inline_path = output_dir / inline_filename
            with open(inline_path, 'w', encoding='utf-8') as f:
                f.write(script['content'])
            assets['inline_scripts'].append({
                'file': inline_filename,
                'type': script['type'],
                'size': len(script['content']),
                'preview': script['content'].strip()[:200]
            })
            all_script_texts.append(script['content'])
    except Exception as e:
        print(f"Inline script extraction error: {e}", file=sys.stderr)

    # 3. Detect clipboard hijack attempts (ClickFix signature)
    try:
        clipboard_info = page.evaluate('''() => {
            const results = [];
            const allScripts = document.querySelectorAll('script');
            const patterns = [
                /navigator\\.clipboard\\.writeText/g,
                /document\\.execCommand\\(['"]copy['"]/g,
                /clipboardData/g,
                /\\.select\\(\\)/g,
                /powershell/gi,
                /mshta/gi,
                /cmd\\.exe/gi,
                /certutil/gi,
                /bitsadmin/gi,
                /Invoke-Expression/gi,
                /IEX/g,
                /FromBase64String/gi,
                /atob\\(/g,
                /\\\\x[0-9a-fA-F]{2}/g
            ];
            allScripts.forEach((script) => {
                const text = script.textContent || '';
                patterns.forEach((pattern) => {
                    const matches = text.match(pattern);
                    if (matches) {
                        results.push({
                            pattern: pattern.source,
                            matches: matches.length,
                            context: text.substring(
                                Math.max(0, text.indexOf(matches[0]) - 100),
                                text.indexOf(matches[0]) + matches[0].length + 100
                            )
                        });
                    }
                });
            });
            const hiddenInputs = document.querySelectorAll(
                'textarea[style*="position: absolute"], textarea[style*="opacity: 0"], ' +
                'textarea[style*="left: -"], input[style*="position: absolute"], ' +
                'textarea.hidden, textarea[style*="display:none"], ' +
                'div[style*="position: absolute"][style*="left: -"]'
            );
            hiddenInputs.forEach((el) => {
                results.push({
                    pattern: 'hidden_element',
                    element: el.tagName,
                    value: (el.value || el.textContent || '').substring(0, 500),
                    style: el.getAttribute('style') || ''
                });
            });
            return results;
        }''')
        assets['clipboard_commands'] = clipboard_info
    except Exception as e:
        print(f"Clipboard detection error: {e}", file=sys.stderr)

    # 3b. Retrieve actual clipboard writes captured by init script hooks
    try:
        captured = page.evaluate('() => window.__clipboardCaptures || []')
        if captured:
            assets['clipboard_captured'] = captured
            captured_path = output_dir / 'clipboard_captured.json'
            with open(captured_path, 'w', encoding='utf-8') as f:
                json.dump(captured, f, ensure_ascii=False, indent=2)
            # Add clipboard text to Base64 scan pool
            for cap in captured:
                if cap.get('text'):
                    all_script_texts.append(cap['text'])
    except Exception as e:
        print(f"Clipboard capture retrieval error: {e}", file=sys.stderr)

    # 4. DOM structure snapshot
    try:
        dom_structure = page.evaluate('''() => {
            function serializeNode(node, depth) {
                if (depth > 6) return '';
                if (node.nodeType !== 1) return '';
                const tag = node.tagName.toLowerCase();
                const attrs = [];
                if (node.id) attrs.push('id="' + node.id + '"');
                if (node.className && typeof node.className === 'string')
                    attrs.push('class="' + node.className.substring(0, 80) + '"');
                if (tag === 'a' && node.href) attrs.push('href="' + node.href.substring(0, 120) + '"');
                if (tag === 'script' && node.src) attrs.push('src="' + node.src + '"');
                if (tag === 'iframe' && node.src) attrs.push('src="' + node.src + '"');
                if (node.getAttribute('style')) {
                    const style = node.getAttribute('style');
                    if (style.includes('display:none') || style.includes('display: none') ||
                        style.includes('visibility:hidden') || style.includes('opacity: 0') ||
                        style.includes('opacity:0') || style.includes('position: absolute'))
                        attrs.push('style="' + style.substring(0, 120) + '"');
                }
                if (node.getAttribute('onclick')) attrs.push('onclick="..."');
                if (node.getAttribute('onmousedown')) attrs.push('onmousedown="..."');
                if (node.getAttribute('onkeydown')) attrs.push('onkeydown="..."');

                const indent = '  '.repeat(depth);
                let line = indent + '<' + tag;
                if (attrs.length > 0) line += ' ' + attrs.join(' ');
                line += '>';

                const children = Array.from(node.children);
                if (children.length === 0) {
                    if (tag === 'script') {
                        const txt = (node.textContent || '').trim();
                        if (txt) line += ' [' + txt.length + ' chars]';
                    }
                    return line + '\\n';
                }

                let result = line + '\\n';
                children.forEach(child => {
                    result += serializeNode(child, depth + 1);
                });
                return result;
            }
            return serializeNode(document.documentElement, 0);
        }''')
        dom_path = output_dir / 'dom_structure.txt'
        with open(dom_path, 'w', encoding='utf-8') as f:
            f.write(dom_structure)
        assets['dom_structure'] = 'dom_structure.txt'
    except Exception as e:
        print(f"DOM structure extraction error: {e}", file=sys.stderr)

    # 5. Base64 payload auto-decode
    try:
        decoded = decode_base64_payloads(all_script_texts)
        if decoded:
            assets['decoded_payloads'] = decoded
            decoded_path = output_dir / 'decoded_payloads.json'
            with open(decoded_path, 'w', encoding='utf-8') as f:
                json.dump(decoded, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"Base64 decode error: {e}", file=sys.stderr)

    # 6. iframe content capture
    try:
        iframe_data = page.evaluate('''() => {
            const iframes = document.querySelectorAll('iframe');
            return Array.from(iframes).map((iframe, i) => {
                let content = null;
                try {
                    const doc = iframe.contentDocument || iframe.contentWindow?.document;
                    if (doc) content = doc.documentElement.outerHTML;
                } catch(e) { /* cross-origin */ }
                return {
                    index: i,
                    src: iframe.src || '',
                    id: iframe.id || '',
                    name: iframe.name || '',
                    style: iframe.getAttribute('style') || '',
                    width: iframe.width || '',
                    height: iframe.height || '',
                    content: content ? content.substring(0, 50000) : null,
                    crossOrigin: content === null && iframe.src ? true : false
                };
            });
        }''')
        for iframe in iframe_data:
            if iframe.get('content'):
                iframe_filename = f'iframe_{iframe["index"]}.html'
                iframe_path = output_dir / iframe_filename
                with open(iframe_path, 'w', encoding='utf-8') as f:
                    f.write(iframe['content'])
                iframe['file'] = iframe_filename
                iframe['content'] = f'[saved to {iframe_filename}]'
                all_script_texts.append(iframe.get('content', ''))
        if iframe_data:
            assets['iframes'] = iframe_data
            iframes_path = output_dir / 'iframes.json'
            with open(iframes_path, 'w', encoding='utf-8') as f:
                json.dump(iframe_data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"iframe extraction error: {e}", file=sys.stderr)

    # 7. Form action / hidden input extraction (phishing analysis)
    try:
        form_data = page.evaluate('''() => {
            const forms = document.querySelectorAll('form');
            return Array.from(forms).map((form, i) => {
                const inputs = Array.from(form.querySelectorAll('input')).map(inp => ({
                    name: inp.name || '',
                    type: inp.type || 'text',
                    value: inp.value ? inp.value.substring(0, 200) : '',
                    id: inp.id || '',
                    placeholder: inp.placeholder || '',
                    hidden: inp.type === 'hidden'
                }));
                const textareas = Array.from(form.querySelectorAll('textarea')).map(ta => ({
                    name: ta.name || '',
                    type: 'textarea',
                    value: ta.value ? ta.value.substring(0, 200) : '',
                    id: ta.id || '',
                    placeholder: ta.placeholder || '',
                    hidden: false
                }));
                return {
                    index: i,
                    action: form.action || '',
                    method: form.method || 'GET',
                    id: form.id || '',
                    className: form.className || '',
                    enctype: form.enctype || '',
                    target: form.target || '',
                    inputs: inputs.concat(textareas),
                    hiddenCount: inputs.filter(inp => inp.hidden).length
                };
            });
        }''')
        if form_data:
            assets['forms'] = form_data
            forms_path = output_dir / 'forms.json'
            with open(forms_path, 'w', encoding='utf-8') as f:
                json.dump(form_data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"Form extraction error: {e}", file=sys.stderr)

    # 8. Event listener enumeration via CDP
    try:
        cdp = page.context.new_cdp_session(page)
        # Get document node
        doc = cdp.send('DOM.getDocument', {'depth': 0})
        root_id = doc['root']['nodeId']
        # Query all elements
        all_nodes = cdp.send('DOM.querySelectorAll', {
            'nodeId': root_id,
            'selector': '*'
        })
        listeners_result = []
        for node_id in all_nodes.get('nodeIds', [])[:200]:  # Cap at 200 elements
            try:
                obj = cdp.send('DOM.resolveNode', {'nodeId': node_id})
                remote_obj_id = obj['object']['objectId']
                listeners = cdp.send('DOMDebugger.getEventListeners', {
                    'objectId': remote_obj_id
                })
                if listeners.get('listeners'):
                    # Get node description
                    try:
                        node_desc = cdp.send('DOM.describeNode', {'nodeId': node_id})
                        tag = node_desc['node'].get('localName', '?')
                        attrs = node_desc['node'].get('attributes', [])
                        attr_str = ''
                        for j in range(0, len(attrs), 2):
                            if attrs[j] in ('id', 'class'):
                                attr_str += f' {attrs[j]}="{attrs[j+1]}"'
                    except Exception:
                        tag = '?'
                        attr_str = ''

                    for listener in listeners['listeners']:
                        listeners_result.append({
                            'element': f'<{tag}{attr_str}>',
                            'type': listener.get('type', ''),
                            'useCapture': listener.get('useCapture', False),
                            'passive': listener.get('passive', False),
                            'once': listener.get('once', False),
                            'scriptId': listener.get('scriptId', ''),
                            'lineNumber': listener.get('lineNumber', 0),
                            'columnNumber': listener.get('columnNumber', 0)
                        })
            except Exception:
                continue
        cdp.detach()

        if listeners_result:
            assets['event_listeners'] = listeners_result
            listeners_path = output_dir / 'event_listeners.json'
            with open(listeners_path, 'w', encoding='utf-8') as f:
                json.dump(listeners_result, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"Event listener enumeration error: {e}", file=sys.stderr)

    return assets


def analyze_url(url: str, password: str) -> dict:
    """Analyze URL with Playwright in headless Chrome."""
    result = {
        'success': False,
        'final_url': url,
        'screenshot': '',
        'html_file': '',
        'downloads': [],
        'network_log': [],
        'page_assets': {},
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

            # Intercept clipboard writes (ClickFix detection)
            page.add_init_script("""
                window.__clipboardCaptures = [];
                // Hook navigator.clipboard.writeText
                if (navigator.clipboard) {
                    const origWriteText = navigator.clipboard.writeText.bind(navigator.clipboard);
                    navigator.clipboard.writeText = function(text) {
                        window.__clipboardCaptures.push({
                            method: 'clipboard.writeText',
                            text: text,
                            timestamp: new Date().toISOString(),
                            stack: new Error().stack
                        });
                        return origWriteText(text);
                    };
                }
                // Hook document.execCommand('copy') - capture selected text
                const origExecCommand = document.execCommand.bind(document);
                document.execCommand = function(cmd) {
                    if (cmd === 'copy') {
                        const selection = document.getSelection();
                        let copiedText = '';
                        if (selection && selection.toString()) {
                            copiedText = selection.toString();
                        }
                        // Also check for focused textarea/input
                        const active = document.activeElement;
                        if (active && (active.tagName === 'TEXTAREA' || active.tagName === 'INPUT')) {
                            copiedText = active.value.substring(active.selectionStart, active.selectionEnd);
                        }
                        window.__clipboardCaptures.push({
                            method: 'execCommand.copy',
                            text: copiedText,
                            timestamp: new Date().toISOString(),
                            stack: new Error().stack
                        });
                    }
                    return origExecCommand.apply(document, arguments);
                };
            """)

            # Network logging
            request_id_counter = 0
            # Map Playwright request object id -> our RequestID for precise matching
            request_id_map = {}

            def log_request(request):
                nonlocal request_id_counter
                request_id_counter += 1
                rid = str(request_id_counter)
                request_id_map[id(request)] = rid

                network_requests.append({
                    'RequestID': rid,
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
                # Match by request object identity, not URL
                rid = request_id_map.get(id(response.request))
                if rid is None:
                    # Fallback: match by URL (for redirected requests)
                    for req in reversed(network_requests):
                        if req['URL'] == response.url and req['StatusCode'] == '':
                            rid = req['RequestID']
                            break
                if rid is None:
                    return

                for req in network_requests:
                    if req['RequestID'] == rid:
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

                # --- Multi-stage screenshots ---
                screenshots = []

                # Stage 1: Initial page load (before any interaction)
                ss1_path = OUTPUT_DIR / 'screenshot.png'
                page.screenshot(path=str(ss1_path), full_page=True)
                result['screenshot'] = 'screenshot.png'
                screenshots.append('screenshot.png')

                html_content = page.content()
                html_path = OUTPUT_DIR / 'page.html'
                with open(html_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                result['html_file'] = 'page.html'

                # Stage 2: After click (triggers ClickFix clipboard hijack + UI changes)
                try:
                    page.click('body', timeout=3000)
                    time.sleep(1)
                    ss2_path = OUTPUT_DIR / 'screenshot_after_click.png'
                    page.screenshot(path=str(ss2_path), full_page=True)
                    screenshots.append('screenshot_after_click.png')
                except Exception:
                    pass

                # Stage 3: After delay (captures progress bars, redirects, etc.)
                try:
                    time.sleep(3)
                    ss3_path = OUTPUT_DIR / 'screenshot_delayed.png'
                    page.screenshot(path=str(ss3_path), full_page=True)
                    screenshots.append('screenshot_delayed.png')
                except Exception:
                    pass

                result['screenshots'] = screenshots

                # Extract page assets (JS, inline scripts, DOM, clipboard, iframes, forms, listeners)
                result['page_assets'] = extract_page_assets(page, OUTPUT_DIR)

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
