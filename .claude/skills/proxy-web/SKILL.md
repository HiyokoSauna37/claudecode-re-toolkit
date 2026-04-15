---
name: proxy-web
description: |
  Safely access dangerous websites (malware, phishing, ClickFix, C2) via Docker-isolated browser. AES-256 encrypted downloads. Integrated VT/MalwareBazaar/ThreatFox/OTX lookups, C2 auto-profiling, network log classification, batch domain probing.
  Use when: URL分析, C2偵察, ハッシュチェック, マルウェアサイト, フィッシング解析, ClickFix解析, proxy-web, c2-profile, OTX, batch-probe, classify
  Do NOT use for: 単なるURL要約（url-summary）、通常のWebページ閲覧
instructions: |
  **パス規則: `tools/proxy-web/proxy-web.exe` フルパス必須。`./`や`cd`は禁止。**

  ## 入力→コマンド判定（これに従う）

  | ユーザの入力 | 最初に実行するコマンド |
  |---|---|
  | URL | `preflight` → `probe --tor URL` → 結果に応じてURL分析 |
  | IP or IP:port | `c2-profile IP:port` (これ1つで基本完了) |
  | ドメイン名 | `probe` でHTTP確認 → URL分析 or `otx domain` でTI検索 |
  | ファイルハッシュ | `check HASH` → `behavior HASH` → `bazaar hash HASH` |
  | network.csv | `classify CSV --target DOMAIN` |
  | ドメインリスト | `batch-probe FILE --threads 30` |

  ## URL分析フロー
  0. `preflight`
  1. `probe --tor "URL"` → Direct/Tor/Skip判定
  2. `"URL"` (or `--tor "URL"`) → スクリーンショット+DL+暗号化
  3. DLファイルあり → `check`/`behavior`/`bazaar hash` → Ghidra提案
  4. DLファイルなし → `classify network.csv --target DOMAIN` でネットワーク分析
  5. 不審ドメイン/IP → `otx domain`/`threatfox ioc` でTI検索

  ## C2フロー
  1. `c2-profile IP:port` (VT+TF+OTX+PassiveDNS+ポートスキャン自動)
  2. 追加: `recon URL` / `ws probe ws://IP:port/ws` / `list URL`
  3. パネル発見 → URL分析でキャプチャ
  4. OTXパルス発見 → `otx stats PULSE_ID` / `otx hashes PULSE_ID`
  5. 大量IOC → `batch-probe domains.txt` でアクティブなもの特定

  ## ClickFix JSペイロード分析フロー
  1. `probe --batch` で各ペイロードURLの生存確認（200/400/404）
  2. `fetch URL` で生JSファイルを取得（**ブラウザ不使用、`<pre>`タグ問題なし**）
  3. `python3 tools/proxy-web/js_deobfuscate.py <file.js>` でClickFix検出+IOC抽出
  4. HTMLページ（JSが注入される先）は従来通り `proxy-web.exe "URL"` でスクリーンショット取得
  注意: `.js`ファイルを `proxy-web.exe "URL"` に渡すとChromiumが `<pre>` テキスト表示する → 必ず `fetch` を使う

  ## 安全規則
  - DLファイルは**コンテナ内で暗号化済み**。ホストに生バイナリは出ない
  - Ghidra解析: `ghidra.sh quarantine-analyze <file.enc.gz>`
  - probe並列時は `--batch` 必須（exit 2で全キャンセル防止）
  - ClickFix/フィッシング検出はURL分析時に自動実行（clipboard_captured.json等）
---
# Proxy Web

Docker隔離ブラウザでの安全なWeb分析ツール。

## コマンド早見表

```bash
PW="tools/proxy-web/proxy-web.exe"    # 毎回フルパスで実行

# === 基本 ===
$PW preflight                          # Docker/環境変数チェック
$PW probe --tor "URL"                  # DNS+HTTP+FortiGate検出
$PW "URL"                             # URL分析（SS+DL+暗号化）
$PW --tor "URL"                       # Tor経由URL分析
$PW decrypt <file.enc.gz>             # 復号化

# === 脅威インテリジェンス ===
$PW check <sha256>                    # VTハッシュ検出率
$PW behavior <sha256>                 # VT振る舞い
$PW lookup <sha256>                   # VT詳細
$PW vt-ip <IP>                        # VT IPレポート
$PW threatfox ioc "IP:port"           # ThreatFox IOC
$PW threatfox tag/hash/malware <val>  # ThreatFox検索
$PW bazaar hash/sig/tag <val>         # MalwareBazaar検索
$PW bazaar download <sha256>          # サンプルDL (--to-ghidra)
$PW otx domain/ip <val>              # OTXパルス検索
$PW otx pulse/hashes/urls/stats <id> # OTXパルス詳細

# === C2偵察 ===
$PW c2-profile <IP[:port]>           # 自動偵察（VT+TF+OTX+DNS+ポートスキャン）
$PW recon "URL"                       # HTTPメソッド/拡張子/SSL偵察
$PW ws probe "ws://IP:port/ws"       # WebSocket認証チェック
$PW ws capture "ws://IP:port/ws" -d 60 --json
$PW list "URL"                        # ディレクトリリスティング

# === 生ファイル取得 ===
$PW fetch "URL"                       # 生HTTPレスポンス保存（ブラウザ不使用）
$PW fetch "URL" -o output.js          # ファイル名指定
$PW fetch "URL" -d ./mydir            # 出力先ディレクトリ指定

# === JS難読化解析 ===
python3 tools/proxy-web/js_deobfuscate.py <file.js>           # ClickFix検出+IOC抽出
python3 tools/proxy-web/js_deobfuscate.py <file.js> --json    # JSON出力
python3 tools/proxy-web/js_deobfuscate.py <file.js> --ioc-only  # IOCのみ
python3 tools/proxy-web/js_deobfuscate.py page.html           # proxy-web出力のpage.htmlも対応

# === 分析 ===
$PW classify <csv> --target <domain>  # ネットワークログ分類
$PW batch-probe <file> --threads 30   # 大量ドメイン一括プローブ
$PW probe --batch "URL"               # 並列安全probe
```

## C2プロファイリング

```bash
$PW c2-profile <IP[:port]>
```
→ VT IP + ThreatFox + OTX + Passive DNS再帰ピボット + 全IPポートスキャン + SSHバナー + IOCリスト

追加調査が必要な場合のみ: `recon` / `ws probe` / `list` / URL分析

## ネットワークログ分類

URL分析後のnetwork.csvを自動分類:
```bash
$PW classify Quarantine/<domain>/<ts>/network.csv --target <domain>
```
検出カテゴリ: `BLOCKCHAIN_RPC`(C2設定取得) / `C2_API` / `TRACKER` / `TARGET` / `CDN`

## 出力先

`tools/proxy-web/Quarantine/<domain>/<timestamp>/`

主要ファイル: `screenshot.png` / `page.html` / `*.enc.gz` / `metadata.json` / `network.csv`

ClickFix検出時: `clipboard_captured.json` / `decoded_payloads.json` / `inline_N.js` / `script_N.js`

**生のEXE/DLL/ZIPはホストに出現しない。**

## 後続解析

DLファイル検出時 → ユーザに「Ghidra Headlessで静的解析しますか？」と確認:
```bash
bash tools/ghidra-headless/ghidra.sh quarantine-analyze "<file.enc.gz>"
```

パッカー検出時 → 「VMware Sandboxで動的解析しますか？」と確認 → vmware-sandboxスキル

## リファレンス

- 既知の問題と解決策: [references/known-issues.md](references/known-issues.md)
- 調査ナレッジ: [references/knowledge.md](references/knowledge.md)
- ビルド: `cd tools/proxy-web && go build -o proxy-web.exe .`
- Docker再ビルド: `cd tools/proxy-web && docker build -t proxy-web-browser:latest .`
