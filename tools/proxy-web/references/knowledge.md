# proxy-web 調査ナレッジ

## ClearFake / ClickFix キャンペーン分析

### 概要
ClearFake は Polygon ブロックチェーンをC2として利用するマルウェア配布インフラ。
被害者の Webサイト（主にWordPress）に悪意あるJSを注入し、ClickFix手法でPowerShellを実行させる。

### 識別シグネチャ

**ドメインパターン:**
- `.beer` TLD + CDN/フレームワーク名のtyposquat
- 例: `bootstrup-cdn-ns.beer`, `fontawesome-js-cdn.beer`, `verification-cdn-cloud.beer`
- 同一IPに10〜30ドメインが集中（Passive DNSで確認）

**ASN:**
- Omegatech LTD (AS202412) = 常連のbulletproof hosting (DE)
- ThreatFox tag: `bulletproof`, `Omegatech`

**ThreatFox IOCタグ:**
- `ClearFake`, `ClickFix`, `ErrTraffic`, `blockchain`, `macOS`
- Port 80/443 両方が `botnet_cc` または `payload_delivery`

**VT communicating files:**
- `stealer1.txt`, `stealer2.txt` → PowerShell stealer
- `clickfix.ps1` → ClickFix配布スクリプト (検出率 0/76 も多い)
- `7z.exe` → 正規ツールを悪用してZIP解凍

### 攻撃チェーン

```
1. 侵害サイト (WordPress等) に script タグ注入
   → <script src="http://<domain>.beer/api/css.js">

2. css.js (XOR key=51〜255, Base64+XOR)
   → Polygon RPC 複数でフォールバック
   → スマートコントラクト呼び出し (function selector: b68d1809)
   → AES-GCM/RC4で暗号化されたC2設定を取得
   → panelBaseUrl, apiBase, psCmd, downloadUrl を取得

3. モードスクリプト取得
   → /api/index.php?a=js&mode=<mode>
   → mode例: cloudflare (v6.js) = 偽Cloudflare DDoS保護画面

4. ClickFix (偽Cloudflare画面)
   → 全画面の偽「DDoS Protection by Cloudflare」
   → チェックボックスクリック → クリップボードにPowerShellコマンドセット
   → 「PowerShellを管理者で開いて貼り付けてEnter」と指示
   → 20言語対応 (EN/DE/FR/ES/IT/PT/NL/TR/KO/HI/ID/VI/TH/ZH/JA/UK/CS/RO/HE/AR)

5. PowerShell ClickFix ペイロード
   → verification-cdn-cloud.beer/api/7z.exe DL (7-Zip)
   → /api/index.php?a=dl&token=<token> から暗号化ZIP DL
   → ZIP password: "2026" (確認済み)
   → 解凍してEXE実行 (infostealer)
```

### スマートコントラクト詳細
- Chain: Polygon (MATIC)
- Contract: `0x994Cb8274721E5d6dAA4fE3FeBf80CF9237A9ae8`
- Function: `b68d1809`
- API Key例: `49f1213251b35c468ae5699c3715b4f16bde9910c9e17b7b33ffd23e02c9fc05`
- RPC hosts: rpc.ankr.com/polygon, polygon.drpc.org, 1rpc.io/matic 等14ホスト (フォールバック)

### JS難読化
- css.js: `var _0xNNNN = XOR_KEY; var _0xNNNN = 'BASE64...';`
  → base64decode(DATA) XOR KEY → 平文JS
  → 各サンプルでXOR keyが異なる (51, 114, 255 等)
- モードスクリプトも同様の方式

### 対処コマンド
```bash
# 1コマンドで全解析
python3 Tools/proxy-web/clearfake_decode.py "http://<domain>/api/css.js"

# または js_deobfuscate.py で
python3 Tools/proxy-web/js_deobfuscate.py --url "http://<domain>/api/css.js"
```

### 関連キャンペーンIOC (2026-04-16〜17調査)
- IP: 178.16.52.101 (Omegatech LTD)
- 関連ドメイン: bigbadwolf.click (logging C2)
- バックアップペイロードホスト: friendlydomain.ru, whtempdomain.com
- 追加C2: 217.69.0.159, 45.32.150.251
- OTXパルス: 69e102b1a49b38887a3da97e (LTNA-Australia, 1993 indicators)

---

## Windows Git Bash での Python スクリプト実行

### 問題
`python3 -c "...多行コード..."` がWindowsで失敗する。

**エラー例:**
```
File "<string>", line 1
    ||  goto :error
IndentationError: unexpected indent
```

**原因:** Windows の `python3` は `.cmd` バッチファイルwrapperで、コマンド失敗時に
`goto :error` が stderr に流れ込んでインデントエラーに見える。

**対策:** Write ツールで `.py` ファイルを作成してから実行する。
```python
# Write ツールで作成
# python3 /path/to/script.py として実行
```

---

## fetch コマンドと Windows Defender

### 問題
`proxy-web.exe fetch URL` で取得した malicious JS/EXE がホストに保存された直後に
Windows Defender によって削除される。

**症状:** `css.js.headers` は残るが `css.js` が消える (Defenderが内容スキャン→削除)

**対策 (2026-04-17修正済み):**
- `fetch` コマンドは自動的に `.enc.gz` 暗号化保存するよう変更
- Defenderは暗号化済みファイルの内容を判定できないため保持される
- 解析時は `proxy-web.exe decrypt` または `js_deobfuscate.py <file.enc.gz>`

**推奨ワークフロー (ディスク書き込み回避):**
```bash
python3 Tools/proxy-web/js_deobfuscate.py --url "http://domain/api/css.js"
```

---

## /tmp/ への書き込み不可 (Git Bash on Windows)

Git Bash から `/tmp/` や多くのパスへの書き込みは Permission denied になることが多い。
→ Write ツールを使ってプロジェクト内のディレクトリに作成する。
→ または Bash の `>` リダイレクトをプロジェクトのカレントディレクトリに対して使う。
