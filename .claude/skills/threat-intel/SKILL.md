---
name: threat-intel
description: |
  Smart unified OSINT / threat-intelligence CLI over 18 services (VT, Hybrid Analysis, Triage, MalwareBazaar, ThreatFox, OTX, URLHaus, URLScan.io, Shodan, AbuseIPDB, GreyNoise, IPInfo, BGPView, Whois/RDAP, NIST NVD, VulnCheck, Malpedia, Malshare). Auto-detects input type — give it a hash/IP/URL/CVE/domain/file and it picks the right workflow. IOC extraction (txt/pdf/eml/url with SSRF defense), MITRE ATT&CK mapping, YARA scan, HTML/PDF reports.
  Use when: 脅威インテリ問合せ, OSINT, ハッシュ調査, IP評判, CVE調査, KEV確認, IOC抽出, ATT&CK mapping, hash相関, IP相関, threat-intel, ti
  Do NOT use for: 静的解析（ghidra-headless）、動的解析（malware-sandbox）、危険サイト閲覧（malware-fetch）
instructions: |
  **The single command you need to remember:**
  ```
  python tools/threat-intel/intel-cli.py <input>
  ```
  It auto-detects: hash → correlation, IP → correlation, CVE → NIST+VulnCheck, URL → URLScan+VT, domain → Whois+OTX+URLScan+VT, file → IOC extract.

  **Or for setup / inspection:**
  ```
  python tools/threat-intel/intel-cli.py status   # show which API keys are configured
  python tools/threat-intel/intel-cli.py cache stats
  ```

  ## 入力 → 自動実行

  | ユーザの入力 | 自動的に走るワークフロー |
  |---|---|
  | hash (md5/sha1/sha256) | `correlate-hash` (VT + Bazaar + OTX + URLHaus + HA + Triage 一斉) |
  | IP | `correlate-ip` (BGPView + IPInfo + VT + OTX + Shodan + AbuseIPDB + GreyNoise) |
  | `CVE-YYYY-NNNNN` | NIST NVD lookup + VulnCheck KEV/MITRE/NVD2 search |
  | URL (`http://...`) | URLScan.io submit + VirusTotal URL lookup |
  | domain | Whois + URLScan domain search + VT domain + OTX domain |
  | file (txt/pdf/eml) | IOC抽出 (SSRF防御済) |
  | URL (`http(s)://...` を ioc コマンドで指定) | URL から IOC 抽出 |

  ## キー未設定でも壊れない設計

  各サービスは個別に API キーチェック → 未設定なら **その1つだけ** スキップして続行。
  `status` コマンドで一目で「何が使えるか」確認可能。

  ## 主要コマンド一覧

  ### スマートワークフロー
  ```
  python tools/threat-intel/intel-cli.py 8.8.8.8                    # IP相関
  python tools/threat-intel/intel-cli.py <sha256>                   # Hash相関
  python tools/threat-intel/intel-cli.py CVE-2024-3400              # CVE調査
  python tools/threat-intel/intel-cli.py example.com                # Domain調査
  python tools/threat-intel/intel-cli.py https://example.com        # URL調査
  python tools/threat-intel/intel-cli.py /path/to/report.pdf        # IOC抽出
  ```

  ### エイリアス（auto-detect スキップ）
  ```
  python tools/threat-intel/intel-cli.py hash <h>
  python tools/threat-intel/intel-cli.py ip <ip>
  python tools/threat-intel/intel-cli.py cve <cve>
  python tools/threat-intel/intel-cli.py url <url>
  python tools/threat-intel/intel-cli.py domain <d>
  python tools/threat-intel/intel-cli.py file <path>
  ```

  ### サービス指定
  ```
  python tools/threat-intel/intel-cli.py vt {hash|ip|domain|url|behavior} <value>
  python tools/threat-intel/intel-cli.py ha hash <h>
  python tools/threat-intel/intel-cli.py triage {search|summary|dynamic} <v>
  python tools/threat-intel/intel-cli.py bazaar hash <h>
  python tools/threat-intel/intel-cli.py threatfox {ioc|recent} <v>
  python tools/threat-intel/intel-cli.py otx {hash|ip|domain} <v>
  python tools/threat-intel/intel-cli.py urlhaus {url|hash|tag|recent-urls|recent-payloads} [<v>]
  python tools/threat-intel/intel-cli.py urlscanio {submit|result|search|domain|ip} <v>
  python tools/threat-intel/intel-cli.py shodan {ip|search} <v>
  python tools/threat-intel/intel-cli.py abuseipdb ip <ip>
  python tools/threat-intel/intel-cli.py greynoise ip <ip>
  python tools/threat-intel/intel-cli.py ipinfo ip <ip>
  python tools/threat-intel/intel-cli.py bgpview ip <ip>
  python tools/threat-intel/intel-cli.py whois {domain|ip} <v>
  python tools/threat-intel/intel-cli.py nist {cve|cpe|severity|keyword|cwe} <v>
  python tools/threat-intel/intel-cli.py vulncheck {indexes|kev|kev-cve|mitre|mitre-cve|nvd2|nvd2-cve|backup} [<v>]
  python tools/threat-intel/intel-cli.py malpedia {actors|families|payloads|actor|family|yara|sample} [<v>]
  python tools/threat-intel/intel-cli.py malshare {list|hash} [<v>]
  ```

  ### 補助
  ```
  python tools/threat-intel/intel-cli.py status              # APIキー設定状況
  python tools/threat-intel/intel-cli.py cache stats|clear|prune
  python tools/threat-intel/intel-cli.py ioc extract <file|url>
  python tools/threat-intel/intel-cli.py yara <rules> <target>
  python tools/threat-intel/intel-cli.py attack <tag1> <tag2> ...
  python tools/threat-intel/intel-cli.py report html|pdf <out> [--from <result.json>]
  ```

  ## グローバルフラグ（位置は前/後どちらでもOK）

  ```
  --output-format text|json|csv     # 既定: text (色付き). JSON は jq 等にパイプ可
  --proxy URL                       # HTTP/HTTPS/SOCKS5 (例: socks5://127.0.0.1:9050)
  --no-cache                        # キャッシュ無効
  --cache-ttl SEC                   # TTL (既定 3600)
  --quiet / --verbose
  --background 0|1                  # 0=明背景端末, 1=暗 (既定)
  --report html|pdf --report-file PATH   # コマンド完了後にレポート生成
  ```

  例: `intel-cli.py --output-format json correlate-hash <h> > result.json`

  ## .env (リポジトリルート)

  既存の `VIRUSTOTAL_API_KEY`, `ABUSECH_AUTH_KEY` に加えて、以下追加可能（任意）:
  ```
  ALIENVAULT_API_KEY=
  HYBRID_ANALYSIS_API_KEY=
  TRIAGE_API_KEY=
  URLSCANIO_API_KEY=
  SHODAN_API_KEY=
  ABUSEIPDB_API_KEY=
  GREYNOISE_API_KEY=
  IPINFO_API_KEY=
  VULNCHECK_API_KEY=
  NIST_API_KEY=
  MALSHARE_API_KEY=
  MALPEDIA_API_KEY=
  ```
  詳細は `references/api-keys-guide.md` 参照。

  ## 既存ツールとの使い分け
  - **VT/Bazaar/ThreatFox/OTXの単発問合せ** → `tools/malware-fetch/malware-fetch.exe` (Go) の方が速い場合あり
  - **横断相関 / NIST / VulnCheck / Triage / Shodan / AbuseIPDB / 他10サービス** → 本ツール (これらは malware-fetch にない)
  - **C2クラスタプロファイル** → `tools/malware-fetch/intel/c2cluster.py` (本ツールの代替ではない)

  ## 設計原則
  - **絶対にクラッシュしない** — APIキー未設定 / ネットワーク到達不可 / API異常応答すべて `{'error': '...'}` 辞書で graceful。CLI の exit code で識別可能 (0=成功, 2=入力エラー, 3=APIエラー, 4=想定外)
  - **キャッシュは透明** — 1回問合せた結果は SQLite (`~/.threat_intel_cache.db`) に1時間保存。同じ hash を別フローから問合せても再fetch しない
  - **Claude Code が読める** — `--output-format json` で構造化出力。エラーも JSON で返るのでパイプライン化容易
references:
  - references/api-keys-guide.md
license: GPL-3.0-or-later
