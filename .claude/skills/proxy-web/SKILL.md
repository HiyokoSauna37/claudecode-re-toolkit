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
  | URL | `preflight` → `probe "URL"` → `[Action]` に従い URL分析（`--tor` 要否も Action 判断）|
  | IP or IP:port | `c2-profile IP:port` (これ1つで基本完了) |
  | ドメイン名 | `probe` でHTTP確認 → URL分析 or `otx domain` でTI検索 |
  | ファイルハッシュ | `check HASH` → `behavior HASH` → `bazaar hash HASH` |
  | network.csv | `classify CSV --target DOMAIN` |
  | ドメインリスト | `batch-probe FILE --threads 30` |

  ## URL分析フロー
  0. `preflight`（自動実行されるが、コマンドライン操作では明示実行を推奨）
  1. `probe "URL"` → `[Action]` 判定:
     - `Direct` → 手順2へ
     - `Use --tor` → `--tor "URL"` で手順2へ（ホスト側 127.0.0.1:9050 必要）
     - `Skip` → **URL分析を中止**（exit code 2 は正常終了）。`otx domain` / `threatfox ioc` でTI検索に切り替える
  2. `"URL"` (or `--tor "URL"`) → スクリーンショット+DL+暗号化
  3. DLファイルあり → `check`/`behavior`/`bazaar hash` → Ghidra提案
  4. DLファイルなし → `classify network.csv --target DOMAIN` でネットワーク分析
  5. 不審ドメイン/IP → `otx domain`/`threatfox ioc` でTI検索

  ## C2フロー
  1. `c2-profile IP:port` (VT+TF+OTX+PassiveDNS+ポートスキャン自動 — passive DNS ピボット展開で数分かかる場合あり、コマンド自然終了まで待機)
  2. **クラスタ全体プロファイル**: `python3 tools/proxy-web/intel/c2cluster.py profile --seed IP:port` or `--tag TAG_NAME`
     - ThreatFoxタグ横展開→並列プローブ→fingerprintグループ化を一撃で実行
     - 全ノードのOPEN/FILTERED/CLOSED判定、HTMLタイトル/Server抽出、パネル候補抽出
  3. 追加（c2-profile の結果を確認してから必要なものだけ実行、不要なら省略）: `recon URL` / `ws probe ws://IP:port/ws` / `list URL`
  4. パネル発見 → URL分析でキャプチャ
  5. OTXパルス発見 → `otx stats PULSE_ID` / `otx hashes PULSE_ID`
  6. 大量IOC → `batch-probe domains.txt` でアクティブなもの特定
  7. **fingerprintハンティング**: `python3 tools/proxy-web/intel/c2cluster.py fp-hunt ips.txt --title "Bot Manager" --server "Microsoft-HTTPAPI"` — 既知パターンでの横断捜索
  8. **threat-intel ツール一式** (`tools/proxy-web/intel/`): `c2cluster` / `c2hunt` / `threatfeed` / `iocminer` / `loghunter` / `intel` (統合ディスパッチャ) / `hunt-report.exe` (Go, 結果集約)

  ## ClickFix JSペイロード分析フロー
  1. （省略可）URLの生存確認: `probe --batch` で複数URL、`probe "URL"` で1件 — 省略して直接 js_deobfuscate.py に進んでも可（URL不達ならスクリプト側でもエラーになる）
  2. **JSファイル取得は `--url` 推奨（ディスク書き込みなし、Defender回避）:**
     ```
     python3 tools/proxy-web/js_deobfuscate.py --url "http://domain/api/css.js"
     ```
  3. `fetch URL` を使う場合: **自動で `.enc.gz` 暗号化保存される** (Defender対策)
     - 解析時: `proxy-web.exe decrypt <file.enc.gz>` してから `js_deobfuscate.py`
     - またはそのまま `js_deobfuscate.py <file.enc.gz>` でも自動復号
  4. ClearFake (Polygonブロックチェーン型C2) の場合:
     ```
     python3 tools/proxy-web/clearfake_decode.py "http://domain/api/css.js"
     ```
  5. HTMLページはブラウザで: `proxy-web.exe "URL"` → スクリーンショット取得
  注意: `.js`ファイルを `proxy-web.exe "URL"` に渡すとChromiumが `<pre>` テキスト表示 → 必ず `--url` か `fetch` を使う

  ## ClearFakeキャンペーン識別パターン
  - Passive DNS: 大量の `.beer` TLDドメインが同一IPに集中 (CDN名typosquat)
  - ThreatFox tags: `ClearFake`, `ClickFix`, `ErrTraffic`, `bulletproof`
  - VT communicating files: `stealer1.txt`, `clickfix.ps1`, `7z.exe` など
  - ASN: Omegatech LTD (AS202412) = bulletproof hosting
  - JS内: `__BW_SCRIPT_INITIALIZED__`, `CONTRACT_CONFIG`, `MODE_FILE_MAP`
  - Polygon RPC呼び出し: `rpc.ankr.com/polygon`, `polygon.drpc.org` 等

  ## Pythonスクリプト実行の注意（Windows Git Bash）
  - **`python3 -c "...多行コード..."` は禁止** → Windowsバッチwrapperが干渉してインデントエラー
  - Writeツールで `.py` ファイルを作成してから実行する
  - ファイル書き込みは `/tmp/` 不可のことが多い → Writeツールでプロジェクト内に作成

  ## 安全規則
  - DLファイルは**コンテナ内で暗号化済み**。ホストに生バイナリは出ない
  - `fetch` コマンドも **`.enc.gz` 暗号化保存** (Defender対策、2026-04-17修正)
  - Ghidra解析: `ghidra.sh quarantine-analyze <file.enc.gz>`
  - probe並列時は `--batch` 必須（exit 2で全キャンセル防止）
  - ClickFix/フィッシング検出はURL分析時に自動実行（clipboard_captured.json等）

  ## 実行前チェック（2026-04-17強化）
  - **`proxy-web "URL"` 実行前に preflight 自動実行**（Docker 未起動なら即終了 → 3回無駄リトライなし）
    - スクリプト等で抑制したい場合: `proxy-web "URL" --skip-preflight`
    - 症状: `Docker daemon ... not running` → Docker Desktop 起動後に再実行
  - **`c2-profile` / `probe` / `threatfox` / `otx` / `vt-ip` / `js_deobfuscate.py` / `clearfake_decode.py` は Docker 不要**（純ネットワーク/API/Python直接実行）→ preflight 不要
  - **`--tor` の要否判断**: `probe "URL"` の `[Action]` 表示（`Direct` / `Use --tor` / `Skip`）に従う。デフォルトは Direct で、必要時のみ `--tor` を付与
  - **`--tor` の挙動（コマンドで違う）**:
    - `proxy-web.exe "URL" --tor`（URL分析）→ Docker tor-proxy を自動起動（追加セットアップ不要）
    - `probe --tor` / `probe --batch --tor`（probe系）→ **ホスト側 127.0.0.1:9050 必要**。未起動なら REFUSED → `--tor` を外して Direct 再試行、それも失敗なら `Skip`
  - **WebFetch は ThreatFox/VTサイトで CAPTCHA に阻まれる** → APIを直接叩くコマンド（`threatfox` / `vt-ip` / `otx`）を使う

  ## ThreatFox `tag` / `malware` は --limit N 対応（2026-04-17強化）
  - デフォルト limit=10。大量取得は `--limit 200` 等を指定（最大 1000）
  - 例: `proxy-web.exe threatfox tag "AS216071" --limit 200`
  - 取りこぼし例: 2026-04-17以前、AS216071タグは実際50+件あるのに10件で打ち切られていた
---
# Proxy Web

Docker隔離ブラウザでの安全なWeb分析ツール。

## コマンド早見表

```bash
PW="tools/proxy-web/proxy-web.exe"    # 毎回フルパスで実行

# === 基本 ===
$PW preflight                          # Docker/環境変数チェック
$PW probe "URL"                        # Direct probe (推奨: [Action] 判断後に --tor 要否決定)
$PW probe --tor "URL"                  # 強制 Tor probe (要ホスト側 127.0.0.1:9050)
$PW "URL"                             # URL分析（SS+DL+暗号化）
$PW --tor "URL"                       # Tor経由URL分析（tor-proxy コンテナ自動起動）
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
$PW fetch "URL"                       # .enc.gz暗号化保存（Defender対策）
$PW fetch "URL" -o output.js          # ファイル名指定（保存は output.js.enc.gz）
$PW fetch "URL" -d ./mydir            # 出力先ディレクトリ指定
$PW decrypt <file.enc.gz>             # 復号してから解析

# === JS難読化解析 ===
python3 tools/proxy-web/js_deobfuscate.py --url "URL"          # ★推奨: URL直接解析（ディスク書込なし）
python3 tools/proxy-web/js_deobfuscate.py <file.js>            # ローカルファイル解析
python3 tools/proxy-web/js_deobfuscate.py <file.enc.gz>        # 暗号化済みファイル自動復号+解析
python3 tools/proxy-web/js_deobfuscate.py <file> --json        # JSON出力
python3 tools/proxy-web/js_deobfuscate.py <file> --ioc-only    # IOCのみ
python3 tools/proxy-web/js_deobfuscate.py page.html            # proxy-web出力のpage.htmlも対応

# === ClearFake専用解析 ===
python3 tools/proxy-web/clearfake_decode.py "URL"              # XOR+B64復号+スマートコントラクト設定+IOC
python3 tools/proxy-web/clearfake_decode.py "URL" --modes cloudflare,browser  # モードスクリプット指定
python3 tools/proxy-web/clearfake_decode.py "URL" --ioc-only   # IOCリストのみ
python3 tools/proxy-web/clearfake_decode.py "URL" --json       # JSON出力

# === 分析 ===
$PW classify <csv> --target <domain>        # ネットワークログ分類
$PW batch-probe <file> --threads 30         # 大量ドメイン一括プローブ (stdout出力のみ、ファイル書込なし)
$PW batch-probe <file> --timeout 5 --dns-only   # DNS解決のみで高速チェック
$PW probe --batch "URL"                     # 並列安全probe (exit 2で全キャンセル回避)
```

## batch-probe の出力仕様

- **ファイル出力なし、stdout のみ**。結果を保存したい場合は `| tee result.txt` でリダイレクト
- 分類: `Alive`（DNS解決+HTTP応答あり）/ `Filtered`（timeout、FW疑い）/ `Dead`（DNS失敗/refused/521）
- Alive 行フォーマット: `  domain.example -> 1.2.3.4 HTTP 200 [nginx]`
- アクティブドメイン抽出 one-liner:
  ```bash
  $PW batch-probe domains.txt --threads 30 \
    | awk '/^Alive domains:/{flag=1;next} /^Filtered/{flag=0} flag && /->/{print $1}' > active.txt
  ```
- 後続は `active.txt` を用いて `probe` → `[Action]` 判断 → URL分析 or `classify` へ

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

主要ファイル: `screenshot.png` / `page.html` / `*.enc.gz` (AES-256-CBC + gzip) / `metadata.json` / `network.csv`

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
