---
name: proxy-web
description: |
  Safely access dangerous websites (malware distribution, phishing, C2 servers) via Docker-isolated browser and perform forensic analysis. Downloads are AES-256 encrypted inside the container - no raw malware touches the host. Includes VirusTotal, MalwareBazaar, ThreatFox lookups and directory listing parsing.
  Use when: "analyze this URL", "download malware safely", "check this suspicious site", "C2 server profiling", "proxy-web", "access malicious URL", "VT check hash", "MalwareBazaar search", "ThreatFox lookup", "directory listing"
instructions: |
  1. Build if needed: cd tools/proxy-web && go build -o proxy-web.exe .
  2. Run: proxy-web.exe "<URL>" (add --tor for Tor routing)
  3. For VT: proxy-web.exe check <sha256>
  4. For MalwareBazaar: proxy-web.exe bazaar hash <sha256>
  5. For ThreatFox: proxy-web.exe threatfox ioc "<ip>"
  6. For directory listing: proxy-web.exe list "<URL>"
  7. For decryption: proxy-web.exe decrypt <file.enc.gz>
  8. If download detected, offer Ghidra headless analysis
---
# Proxy Web

危険なWebサイト（マルウェア配布サイト、フィッシングサイト等）に安全にアクセスし、フォレンジック分析を行うツール。

## 使い方

### Go版（推奨）

```bash
# URL分析（推奨）
proxy-web.exe "http://evil.com/malware.exe"
proxy-web.exe "hxxp://evil[.]com/malware.exe"

# Tor経由
proxy-web.exe --tor "http://evil.com/malware.exe"

# 復号化
proxy-web.exe decrypt <file.enc.gz>
proxy-web.exe decrypt <file.enc.gz> -o output.exe -p password

# VirusTotal連携（組み込み）
proxy-web.exe check <sha256>
proxy-web.exe behavior <sha256>
proxy-web.exe lookup <sha256>

# ディレクトリリスティング解析
proxy-web.exe list "http://c2server.com:5002/"
proxy-web.exe list "hxxp://evil[.]com:8080/"

# MalwareBazaar検索
proxy-web.exe bazaar hash <sha256/md5/sha1>
proxy-web.exe bazaar sig <family_name>
proxy-web.exe bazaar tag <tag>

# ThreatFox検索
proxy-web.exe threatfox ioc "1.2.3.4:5002"
proxy-web.exe threatfox hash <sha256/md5>
proxy-web.exe threatfox tag <tag>
proxy-web.exe threatfox malware <family>
```

ビルド:
```bash
cd tools/proxy-web && go build -o proxy-web.exe .
```

### Python版（フォールバック）

```bash
# CLI引数モード
python tools/proxy-web/proxy_web.py "http://evil.com/malware.exe"

# Tor経由
python tools/proxy-web/proxy_web.py --tor "http://evil.com/malware.exe"

# 復号化
python tools/proxy-web/decrypt_quarantine.py <file.enc.gz>
```

どのディレクトリからでも実行可能（.envパスはスクリプト位置から自動解決）。

## Go版 vs Python版

| 項目 | Go版 | Python版 |
|------|------|----------|
| ホスト側依存 | Goバイナリのみ | Python + requests + docker + dotenv |
| VT連携 | 組み込み（check/behavior/lookup） | 別スクリプト（vt_check.py等） |
| 復号化 | 組み込み（decryptサブコマンド） | 別スクリプト（decrypt_quarantine.py） |
| Docker操作 | Docker SDK (Go) | docker-py |
| ディレクトリリスティング | 組み込み（listサブコマンド） | なし |
| MalwareBazaar | 組み込み（bazaarサブコマンド） | なし |
| ThreatFox | 組み込み（threatfoxサブコマンド） | なし |

**注意**: browser_script.pyはコンテナ内でPython維持（Playwright依存）。Go化対象外。

## 機能

- Dockerコンテナでの完全隔離実行
- defanged URL自動復元（hxxp → http等）
- フルページスクリーンショット
- HTMLソース保存
- ダウンロードファイル検知＆ハッシュ算出（MD5/SHA1/SHA256）
- **コンテナ内でAES-256暗号化** → ホストに生バイナリが一切出現しない
- VirusTotal API連携（ハッシュはコンテナからJSON返却）
- ネットワークログ（CSV形式、Timeline Explorer対応）
- 接続失敗時の自動リトライ（最大3回）
- HTTPディレクトリリスティング解析（Apache/Nginx/Python http.server対応）
- MalwareBazaar検索（ハッシュ/シグネチャ/タグ）
- ThreatFox検索（IOC/ハッシュ/タグ/マルウェアファミリー）

## C2サーバープロファイリングワークフロー

C2サーバーを発見した場合の推奨手順:

1. **ディレクトリリスティング取得**: `proxy-web.exe list "http://<c2>:<port>/"`
2. **スクリーンショット+HTML取得**: `proxy-web.exe "http://<c2>:<port>/"`
3. **個別ファイルダウンロード**: リスティングで見つかった各ファイルに対して `proxy-web.exe "http://<c2>:<port>/<file>"`
4. **ハッシュでVT検索**: `proxy-web.exe check <sha256>`
5. **MalwareBazaar検索**: `proxy-web.exe bazaar hash <sha256>`
6. **ThreatFox IOC検索**: `proxy-web.exe threatfox ioc "<c2_ip>"`
7. **Ghidra静的解析**: ダウンロードされたバイナリをGhidra Headlessで解析
8. **VMware動的解析**: パック済みバイナリはVMware Sandboxで実行

## 出力先

`tools/proxy-web/Quarantine/<domain>/<timestamp>/`

ホストに出現するファイル:
- `screenshot.png` - ページスクリーンショット
- `page.html` - HTMLソース
- `*.enc.gz` - 暗号化済みダウンロードファイル
- `metadata.json` - ハッシュ・VT結果・メタデータ
- `network.csv` - ネットワークログ

**生のEXE/DLL/ZIPは一切ホストに出現しない。**

## 依存関係

- Docker（必須）
- Go 1.21+（Go版ビルド用）
- Python packages: requests, python-dotenv, cryptography, docker（Python版のみ）

## Dockerイメージ再ビルド

```bash
cd tools/proxy-web
docker build -t proxy-web-browser:latest .
```

## 後続解析オプション

ダウンロードファイル（EXE/DLL等）が検出された場合、以下の追加解析を提案する:

- **Ghidra Headless解析**: `/ghidra-headless` スキルでバイナリの静的解析（インポートAPI、文字列、デコンパイル）
  - **ローカルでは絶対に復号化しない** → 暗号化されたままDockerコンテナにコピーし、コンテナ内で復号化・解析する
  - **推奨: ワンコマンド解析**:
    ```bash
    bash tools/ghidra-headless/ghidra.sh quarantine-analyze "tools/proxy-web/Quarantine/<domain>/<timestamp>/<file>.enc.gz"
    ```
  - **quarantine CLIツール** で隔離ファイル管理:
    ```bash
    ./tools/quarantine/quarantine.exe list              # 一覧表示
    ./tools/quarantine/quarantine.exe check             # コンテナ準備状況確認
    ./tools/quarantine/quarantine.exe analyze 1         # 番号指定で解析
    ```
  - 手動手順（フォールバック）:
    ```bash
    # 暗号化のままコンテナの /tmp/ へ転送（!! /analysis/input/ ではなく /tmp/ を使うこと !!）
    docker cp "tools/proxy-web/Quarantine/<domain>/<timestamp>/<encrypted_file>" ghidra-headless:/tmp/
    # コンテナ内で復号化（decrypt_quarantine.pyはDockerイメージに内蔵済み）
    docker exec -e QUARANTINE_PASSWORD="<password>" ghidra-headless \
        python3 /opt/ghidra-scripts/decrypt_quarantine.py /tmp/<encrypted_file>
    bash tools/ghidra-headless/ghidra.sh analyze /tmp/<decrypted_binary>
    ```

## Instructions

- ダウンロードファイルが検出された場合、VirusTotal結果を報告した後に「Ghidra Headlessで静的解析を実行しますか？」とユーザーに確認する
- ユーザーが同意した場合、復号化 → Ghidra解析の流れを自動実行する
- Ghidra静的解析でVMProtect/Themida等のパッカーが検出された場合、またはインポートテーブルが空・文字列がほぼ暗号化されている場合:
  → 「VMware Sandboxで動的解析を実行しますか？」とユーザーに確認する
  → Skillツールで vmware-sandbox を呼び出す
  → アンパック後バイナリをGhidraで再解析する連携フロー

## セキュリティ

- Quarantineフォルダはローカルのみ（Gitignore設定済み）
- ダウンロードファイルはコンテナ内でAES-256-CBC暗号化+gzip圧縮
- 復号化（Go版）: `proxy-web.exe decrypt <file.enc.gz>`
- 復号化（Python版）: `python tools/proxy-web/decrypt_quarantine.py <file>`

## 既知の問題と解決策

### Windows Defender隔離問題
- **問題**: Docker volume mountで生EXEがホストに出現 → Windows Defenderが即座に隔離・削除
- **解決**: ダウンロード・ハッシュ計算・暗号化をすべてコンテナ内で実行。`/tmp/downloads/`に一時保存し、暗号化後に削除。ホストのvolume mountには`.enc.gz`のみ書き出す。

### input() EOFError問題
- **問題**: パイプ入力時に`input()`がEOFErrorで失敗
- **解決**: `argparse`でCLI引数対応 + `sys.stdin.isatty()`で対話/パイプモードを自動判定

### .envパス解決問題
- **問題**: `load_dotenv()`がCWD依存 → 別ディレクトリから実行すると`QUARANTINE_PASSWORD`が未設定
- **解決**: `Path(__file__).resolve().parent.parent.parent / '.env'`でスクリプト位置基準でパス解決

### --torがChromiumにプロキシ未指定
- **問題**: `--tor`オプションでChromium自体にSOCKS5プロキシを指定していない
- **解決**: `USE_TOR=1`環境変数をコンテナに渡し、browser_script.pyで`--proxy-server=socks5://127.0.0.1:9050`をChromiumに追加

### tor-proxy未起動エラー
- **問題**: tor-proxyコンテナ未起動時に`--tor`で即エラー（"No such container"）
- **解決**: `ensureTorProxy()`関数を追加。自動プル・起動・Tor回線確立待機を実行

### Docker JSON出力切り詰め
- **問題**: network_logが巨大な場合、DockerログのマルチプレクシングでJSONが分割されパーサーが失敗
- **解決**: browser_script.pyが`/output/result.json`にファイル出力。docker.goがファイル読み取り優先、フォールバックでstdoutパース

### result.jsonパースエラー
- **問題**: Go短縮変数宣言（`:=`）のスコープでエラーハンドリングが機能していなかった
- **解決**: 変数名を`unmarshalErr`に変更し、if-elseで正しいエラーハンドリングに修正

### Python型不一致
- **問題**: browser_script.pyのRequestID(int)とStatusCode(int)がGoのNetworkEntry struct（string型フィールド）と不一致
- **解決**: `str(request_id)`、`str(response.status)`に変換

### 環境変数

| 変数名 | 用途 | 必須 |
|--------|------|------|
| `QUARANTINE_PASSWORD` | AES-256暗号化パスワード | URL分析時 |
| `VIRUSTOTAL_API_KEY` | VirusTotal API | check/behavior/lookup |
| `ABUSECH_AUTH_KEY` | abuse.ch API (MB/TF) | bazaar/threatfox（なしでも動作） |
