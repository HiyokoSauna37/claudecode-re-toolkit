# Ghidra Headless Knowledge Base

詳細なナレッジ・解析手順・既知の問題をまとめたファイル。
SKILL.mdのKBクイックリファレンスから参照される。

## KB-1: InfoStealer特化解析手順

InfoStealer（情報窃取型マルウェア）と判定された場合、以下の追加手順で「何を盗むか」「どこに送るか」を重点的に調査する。

### Step 1: InfoStealer判定チェック

以下の特徴があればInfoStealerの可能性が高い:
- SQLite3関連文字列（`sqlite_master`, `CREATE TABLE`, `ROWID`等）→ ブラウザDB直接読み取り
- 暗号化API（`ChainingModeCBC`, `BCrypt*`）→ ブラウザ保存パスワードの復号
- 大量のhex-encoded文字列 → C2 URL、窃取対象パス等の難読化
- 30以上のDLL存在チェック（`LoadLibraryA`） → サンドボックス/VM回避
- `KERNEL32` + `MSVCRT` のみインポート → 他APIは全て動的解決で隠蔽
- MinGW/GCCコンパイル → クロスプラットフォーム対応のstealer builder

### Step 2: 窃取対象の特定

**文字列解析で以下を探索:**
```bash
bash tools/ghidra-headless/ghidra.sh strings <binary>
```
- ブラウザパス: `Login Data`, `Web Data`, `Cookies`, `Local State`, `User Data`
- ウォレット: `wallet.dat`, `Electrum`, `Exodus`, `MetaMask`
- メッセンジャー: `Discord`, `Telegram`, `leveldb`, `Local Storage`
- FTP/SSH: `FileZilla`, `.ssh/`, `WinSCP`
- VPN: `NordVPN`, `ProtonVPN`, `OpenVPN`

**インポート解析で暗号化/ファイルアクセスAPIを確認:**
```bash
bash tools/ghidra-headless/ghidra.sh imports <binary>
```
- `CryptUnprotectData` → DPAPI保護データの復号
- `BCryptDecrypt` → ブラウザ暗号鍵の復号
- `ChainingModeCBC` → AES-CBC復号
- `sqlite3_*` → SQLiteデータベース操作

### Step 3: C2通信先の特定

**静的解析:**
- hex-encoded文字列のデコード（`FUN_*`の大規模関数を特定）
- URLパターン（`http://`, `https://`, `ws://`）
- IPアドレスパターン
- ドメイン名文字列

**VT Behavior APIで動的解析を補完:**
```bash
# VT APIでサンドボックス動的解析結果を取得
curl -s "https://www.virustotal.com/api/v3/files/<SHA256>/behaviour" \
  -H "x-apikey: $VIRUSTOTAL_API_KEY" | python -m json.tool
```
- DNS queries → C2ドメイン/IP特定
- HTTP connections → 通信先URL特定
- プロセス生成 → PowerShellコマンド等の確認

### Step 4: データステージング方式の確認

- SQLite CREATE TABLE文 → 窃取データの一時格納テーブル構造
- テンポラリファイル作成パターン → ローカルステージング
- ZIP/圧縮ライブラリ → 窃取データの圧縮送信
- AES/暗号化 → 窃取データの暗号化送信

### Step 5: レポートへの記載項目

InfoStealerの場合、レポートに以下を必ず記載:
1. **窃取対象データ一覧**（ブラウザ/ウォレット/メッセンジャー/FTP等）
2. **C2通信先**（IP/ドメイン/ポート/プロトコル）
3. **データステージング方式**（SQLiteテーブル/一時ファイル）
4. **暗号化方式**（AES-CBC/DPAPI/その他）
5. **環境検出/回避手法**（DLLチェック/TLS Callback/Sleep等）

## KB-2: ランサムウェア特化解析手順

ランサムウェアと判定された場合、「暗号方式」「影響範囲」「復号可能性」を重点的に調査する。

### Step 1: ランサムウェア判定チェック

以下の特徴があればランサムウェアの可能性が高い:
- **暗号化ライブラリ**: `CryptEncrypt`, `BCryptEncrypt`, `AES`, `RSA`, `ChaCha20`
- **ファイル列挙+書込み**: `FindFirstFile` + `FindNextFile` + `CreateFile` + `WriteFile` の組み合わせ
- **拡張子変更**: `.encrypted`, `.locked`, `.crypt` 等の文字列
- **脅迫文テンプレート**: `README`, `DECRYPT`, `RECOVER`, `ransom`, `bitcoin`, `wallet` 等
- **シャドウコピー削除**: `vssadmin`, `wmic shadowcopy`, `bcdedit`
- **プロセス/サービス停止**: `taskkill`, `net stop`, `sc stop`（DB/バックアップソフト停止用）

### Step 2: 暗号方式の特定

```bash
bash tools/ghidra-headless/ghidra.sh imports <binary>
bash tools/ghidra-headless/ghidra.sh decompile <binary>
```
- imports + decompileで暗号関連関数を特定（AES/RSA/ChaCha20等）
- 鍵生成ロジックの解析（ハードコード鍵 vs C2から取得）
- ファイル暗号化の単位（全体 vs 一部 vs インターミッテント暗号化）

### Step 3: 影響範囲の特定

```bash
bash tools/ghidra-headless/ghidra.sh strings <binary>
```
- 暗号化対象の拡張子リスト（strings解析）
- 除外ディレクトリ（Windows, Program Files等を避ける傾向）
- ネットワークドライブ列挙: `WNetOpenEnum`, `WNetEnumResource`
- 横展開メカニズム: SMB, PsExec, WMI

### Step 4: 脅迫文・支払い情報の抽出

strings解析で以下を探索:
- 脅迫文テンプレート（HTML/TXTリソース）
- 暗号通貨ウォレットアドレス（BTC: `[13][a-km-zA-HJ-NP-Z1-9]{25,34}`）
- Torサイト（`.onion`）
- 被害者ID生成ロジック

### Step 5: レポート記載項目

ランサムウェアの場合、レポートに以下を必ず記載:
1. **暗号方式**（アルゴリズム、鍵長、鍵管理方法）
2. **暗号化対象**（拡張子リスト、除外パス）
3. **脅迫文内容**（支払い方法、期限、連絡先）
4. **永続化・横展開メカニズム**
5. **復号可能性の評価**（鍵がハードコードか、既知の脆弱性があるか）

## KB-3: RAT特化解析手順

RAT（Remote Access Trojan）と判定された場合、「実行可能なコマンド」「C2プロトコル」を重点的に調査する。

### Step 1: RAT判定チェック

以下の特徴があればRATの可能性が高い:
- **ネットワーク待受**: `bind`, `listen`, `accept`（リバースシェル型は`connect`）
- **コマンド分岐**: 大きなswitch-case/if-else構造（decompile結果）
- **スクリーンショット**: `BitBlt`, `GetDC`, `CreateCompatibleBitmap`
- **キーロガー**: `SetWindowsHookEx`, `GetAsyncKeyState`, `GetKeyState`
- **ファイル転送**: `CreateFile` + `ReadFile` + ネットワークAPI の組み合わせ
- **シェル実行**: `CreateProcess` + `CreatePipe`（リモートシェル）
- **Webカメラ**: `capCreateCaptureWindow`, DirectShow関連

### Step 2: コマンドテーブルの解析

```bash
bash tools/ghidra-headless/ghidra.sh decompile <binary>
bash tools/ghidra-headless/ghidra.sh xrefs <binary>
```
- メイン処理ループを特定（recv → パース → switch-case）
- コマンドID/文字列の一覧抽出
- 各コマンドの機能マッピング（ファイル操作/プロセス操作/情報収集/横展開）

### Step 3: C2プロトコルの解析

- 通信プロトコル（HTTP/HTTPS/TCP raw/DNS tunneling/WebSocket）
- データフォーマット（JSON/バイナリ/カスタム）
- 暗号化・認証（TLS/カスタム暗号/ハードコードキー）
- ビーコン間隔（Sleep値）

### Step 4: レポート記載項目

RATの場合、レポートに以下を必ず記載:
1. **対応コマンド一覧**（コマンドID + 機能説明）
2. **C2プロトコル**（プロトコル、ポート、暗号化方式）
3. **永続化メカニズム**
4. **権限昇格手法**
5. **横展開能力**

## KB-4: MetaStealer/Teddy Characteristics

### MetaStealer/Tedyの特徴（2026-02-23）
- SQLite3エンジンを静的リンク（.textセクション6.3MB+）
- MinGW/GCCコンパイル（非MSVC）
- KERNEL32 + MSVCRTの2ライブラリのみインポート、他は全て動的解決
- 30以上のDLL存在チェックでサンドボックス/VM検出
- TLS Callbacks 2個でアンチデバッグ
- hex-encoded暗号化文字列をランタイムでデコード（中核関数15KB+）
- AES-CBC（ChainingModeCBC）でブラウザ暗号鍵復号
- Cloudflare DNS (162.159.36.2) をC2通信に利用（DNS tunneling/DoH）
- 9つの難読化テーブル名SQLiteテーブルで窃取データをステージング
- PowerShell `Get-Process` でセキュリティソフト検出
- GitLab等の正規サービスを配布インフラとして悪用（Living off Trusted Sites）
- `ai_data_standard.exe` のようにAIツールを偽装した名前

## KB-5: StealC v2 Characteristics

### StealC v2の特徴（2026-02-24）
- **確定方法**: ビルドパス `C:\builder_v2\stealc\json.h` が.rdataに残存（279箇所参照）
- **コンパイラ**: MSVC (C++)、nlohmann/jsonライブラリ使用
- **文字列難読化**: Standard Base64 + RC4。キーはハードコード（例: `TEh3Vzpre3`）、.rdata内に配置
- **復号関数パターン**: 21KB+の巨大関数が100+個のBase64文字列を`FUN_xxxxx(RC4+B64デコード)` → グローバル変数に格納
- **`aAbBcCdDeFgGhHIjmMnprRStTuUVwWxXyYzZ`**: Base64アルファベットではなく、strtok的bitmap関数で使う文字セット（誤認注意）
- **特異セクション**: `tdb` セクション（RW、非実行）がStealC固有データ格納領域
- **API動的解決**: KERNEL32.dllのみ静的インポート、他12 DLL・69 APIをLoadLibrary/GetProcAddressで解決
- **C2通信**: WinINet API（InternetOpenW等）でHTTP POST + JSON。`Content-Type: application/json`
- **データExfil**: 0x40000 bytes (256KB) チャンク分割マルチパート送信。JSON構造: `total_parts`/`part_index`/`data`
- **C2プロトコル**: `opcode`, `hwid`, `build`, `data`, `filename`, `upload_file`, `success`/`done`/`blocked`/`waiting`/`missing`/`failed`
- **ブラウザ窃取**: Chromium (Chrome/Brave/Edge) + Firefox (nss3.dll直接ロード+PK11SDR_Decrypt)
- **Chrome ABE対応**: `app_bound_encrypted_key` を直接抽出、DPAPI + AES-GCM v10/v20復号
- **Restart Manager悪用**: `RmStartSession`/`RmGetList` でブラウザがロック中のDBファイルを解放
- **窃取対象**: ブラウザ(パスワード/Cookie/履歴/オートフィル)、暗号ウォレット(拡張機能)、Steam(config/ssfn)、Outlook、スクリーンショット(GDI+ JPEG)
- **システムフィンガープリント**: 25+項目（IP/Country/HWID/OS/CPU/RAM/GPU/解像度/プロセス一覧/インストール済みアプリ）→ `system_info.txt`
- **ローダー機能**: PowerShell `iex(New-Object Net.WebClient).DownloadString(`、msiexec.exe /passive
- **APCインジェクション**: `CreateProcessA`(SUSPENDED) → `VirtualAllocEx` → `WriteProcessMemory` → `QueueUserAPC` → `ResumeThread`
- **UAC Bypass**: `runas` + `run_as_admin`
- **自己削除**: `cmd.exe /c timeout /t 5 & del /f /q "<自パス>"` → `ExitProcess(0)`
- **アンチデバッグ**: `IsDebuggerPresent` + `QueryPerformanceCounter` タイミング検出
- **Ghidra解析のコツ**: xrefsで最多呼び出し関数がRC4復号関数。そこからRC4キーを特定し、全文字列を一括復号→C2 URL・設定値・窃取パスが判明

### StealC v2の特徴（2026-02-24）— 詳細解析結果
- **バイナリ**: x86_64 PE、760KB、1672関数
- **文字列難読化**: RC4 + Base64で全文字列を暗号化。`FUN_140002b78`（21KB、93000文字のデコンパイル出力）で一括デコード
- **復号パターン**: `strlen(base64_str) → FUN_140008238(copy) → FUN_140007e7c(RC4+B64 decode) → FUN_14000804c(store to global)`
- **API解決**: `FUN_14003d5d8`で全APIを動的解決。`LoadLibrary`相当の`DAT_1400b7dd8`と`GetProcAddress`相当の`DAT_1400b7de0`を使用
- **解決DLL**: kernel32（`CreateFileA`等）, wininet（`InternetConnectW`, `HttpSendRequestW`等）, crypt32, advapi32, ntdll, user32, ole32等
- **C2通信**: `FUN_14000c4dc` - WinINet API使用、HTTP POST + `Content-Type: application/json`ヘッダ
- **DPAPI**: `FUN_14001c4d0` - `CryptUnprotectData`相当でブラウザパスワード復号。`DPAPI`マジック(5bytes)チェック後に復号
- **データ送信**: `FUN_14000cab8` - チャンク分割送信（`total_parts`, `part_index`）、ステータス管理（`success`, `waiting`, `missing`, `failed`）
- **自己削除**: `FUN_14003cbc8` - `cmd.exe /c timeout /t 5 & del /f /q "<自身のパス>"`
- **メイン窃取ロジック**: `FUN_14000a0a0` - 8127bytes、大量のローカル変数（スタック0x680+使用）、267呼び出し元

## KB-6: VMProtect/Etset Dropper

### VMProtect/Etset Dropper（2026-02-23）
- VMProtect検出: セクション名が難読化（`.uBq`, `.J)t`, `.sYB`等の非標準名）
- インポートテーブル完全隠蔽（0個検出）、文字列もほぼ暗号化（27個のみ等）
- エントリーポイントがVMPセクション内に存在
- VMPセクションがバイナリの90%以上を占める
- Ghidra Headlessでの静的解析は**初期トリアージが限界**（セクション構造、PE metadata、パッカー判定）
- PE metadataで正規ソフトに偽装（例: Intel Bluetooth Service）
- VTサンドボックス結果で動的挙動を補完する必要がある
- 動的解析（x64dbg等）が必須 → VMware Windows VM での解析を推奨

## KB-7: UPXパックされたInstaller/Dropper

### UPXパックされたInstaller/Dropper（2026-02-23）
- UPXパック検出: セクション名 `UPX0`/`UPX1`
- コンテナ内でアンパック: `upx -d <binary>` → 再解析
- .rsrcセクションがバイナリの90%以上 → 埋め込みペイロード
- zlib inflate内蔵 → リソース展開→ファイルドロップ→ShellExecuteExW実行
- GUI付きインストーラーに偽装（SHBrowseForFolderW、InputRequester）

## KB-8: Go Binary Analysis Patterns

### Go製バイナリの解析パターン
- **コンパイラ検出**: info解析で`Compiler: golang`、関数名に`go.`/`runtime.`プレフィクスで判定
- **middle dot問題（修正済み）**: Go内部パッケージパスに`·`(U+00B7)を使用。Jython(Python2)のASCIIデフォルトエンコーディングで`UnicodeEncodeError`。全スクリプトを`codecs.open(file, "w", encoding="utf-8")`に修正済み
- **インポートの特殊性**: Goバイナリは標準ライブラリを静的リンクするため、PEインポートテーブルが最小限（kernel32のみ等）。imports解析の結果が少なくても正常
- **RTTI復元**: `runtime.typestring`等の型情報からGo構造体名・メソッド名を復元可能。strings解析で`type.`プレフィクスの文字列を探す
- **大量の関数**: Goランタイム+標準ライブラリで関数5000+は普通。decompile_allは時間がかかるため、重要関数を特定してから個別デコンパイル推奨
- **strings解析が最も有効**: C2アドレス、設定値、エラーメッセージがリテラルで残りやすい

## KB-9: UPXドロッパー解析パイプライン

### UPXドロッパー → 動的解析 → Ghidra再解析パイプライン
1. **Ghidra初期トリアージ**: info → セクション名`UPX0`/`UPX1`検出 → UPXパック確認
2. **コンテナ内アンパック**: `docker exec ghidra-headless upx -d /tmp/binary` → 再解析
3. **アンパック後に.rsrcが90%+**: 埋め込みペイロード（ドロッパー）の可能性
4. **動的解析へ切替**: vmware-sandbox でドロップされたファイルを回収
5. **ドロップされたバイナリをGhidra再解析**: `bash tools/ghidra-headless/ghidra.sh analyze <dropped_binary>`

## KB-10: decompile_all.py Limitations

### decompile_all.pyの制限事項
- Ghidra 12.0.3のJython DecompInterface APIに互換性問題あり
- 大量関数（1000+）のバイナリでは全関数デコンパイルが失敗する場合がある
- 代替: 個別の重要関数をGhidra GUIで手動デコンパイル

## KB-11: Mergen Devirtualization連携

VMProtectのコード仮想化層をMergenで除去し、Ghidra解析と組み合わせる。

### VMProtect二層構造

| 層 | Ghidra での見え方 | 対処 |
|----|-------------------|------|
| Layer 1: パッキング | インポート0個、文字列なし | memdump-racer でアンパック → Ghidra再解析 |
| Layer 2: コード仮想化 | VMディスパッチャループのみ表示 | Mergen でLLVM IRにリフティング → IR読解 |

### Ghidra + Mergen 併用フロー

```bash
# 1. アンパック後バイナリをGhidra解析
bash tools/ghidra-headless/ghidra.sh analyze <unpacked.exe>
# → デコンパイル結果でVMディスパッチャ関数を特定

# 2. VMP関数アドレスを検出
tools/dump-triage/dump-triage.exe --vmp-addrs <unpacked.exe>

# 3. Mergenでdevirtualize
bash tools/mergen/mergen.sh devirt <unpacked.exe> <address>
# → LLVM IR (.ll) 出力

# 4. LLVM IRとGhidraデコンパイル結果を照合
# - LLVM IRのcall命令 = 外部API呼び出し（C2, ファイル操作等）
# - Ghidraのxrefs結果と合わせてコールチェーンを理解
```

### VMディスパッチャの特徴（Ghidraで識別）

Ghidraのデコンパイル結果で以下のパターンが見えたらVMP仮想化関数:
- 巨大なswitch-case / ジャンプテーブル（VMハンドラディスパッチ）
- レジスタ配列（仮想レジスタ）の大量read/write
- bytecodeポインタのインクリメント + 次ハンドラへのjump
- 関数全体が1つの大きなループ

→ このような関数のアドレスをMergenに渡してdevirtualize

## KB-12: Known Issues

### Windows bind mount読み取りエラー（2026-02-24発見）
- **問題**: `docker cp` でコンテナの `/analysis/input/`（bind mount先）にコピーしたファイルを、Java（Ghidra）が `Invalid argument` で読み取れない
- **原因**: Windows Docker Desktop のbind mountはNTFS↔Linux FSの変換で一部操作に失敗する
- **解決**: bind mount (`/analysis/input/`) ではなく、コンテナネイティブFS (`/tmp/`) にファイルを配置する
- **影響**: `prepare_binary()` 関数（ホスト→input/コピー）は通常ファイルには機能するが、quarantineファイルの復号済みバイナリは `/tmp/` に置くべき
- **対策済み**: `quarantine-analyze` コマンドは `/tmp/` を使用

### コンテナにPython依存関係が不足（2026-02-24発見）
- **問題**: Alpine Linuxベースのコンテナに `python3`, `pip`, `cryptography` が未インストール → `decrypt_quarantine.py` が実行不可
- **原因**: 初期Dockerfileはghidra（Java）のみを想定、Python依存関係を含めていなかった
- **解決**: Dockerfileに `python3`, `py3-pip`, `py3-cryptography` を追加、`decrypt_quarantine.py` をイメージにbake
- **対策済み**: Dockerfile更新済み。リビルド後はコンテナに復号機能が内蔵される

### MSYS/Git Bash パス変換（path munging）
- **問題**: Windows Git Bash環境で `/opt/ghidra/...` が `C:/Program Files/Git/opt/ghidra/...` に自動変換される
- **原因**: MSYS2/Git BashがUnixパスをWindowsパスに変換する仕様
- **解決**: `export MSYS_NO_PATHCONV=1` を設定（ghidra.sh冒頭で設定済み）
- **注意**: `docker exec` で直接コマンドを実行する場合も `bash -c` で囲むこと

### Jython UnicodeEncodeError（Go製バイナリ解析時）
- **問題**: Go製バイナリの関数名/文字列に`·`(U+00B7, middle dot)が含まれ、`open(file, "w")`で書き込み時にJython(Python2)がASCIIエンコードを試みて`UnicodeEncodeError`
- **影響**: list_functions.py, extract_strings.py, decompile_all.py等の全スクリプト
- **解決（2026-02-24）**: 全7スクリプトで`import codecs`追加、`open()`→`codecs.open(file, "w", encoding="utf-8")`に変更
- **対象ファイル**: binary_info.py, list_functions.py, extract_strings.py, decompile_all.py, xrefs_report.py, list_imports.py, list_exports.py

### analyzeHeadlessのスクリプトパス
- **問題**: `-postScript binary_info.py` でスクリプトが見つからない
- **原因**: analyzeHeadlessはデフォルトでカレントディレクトリのみ検索
- **解決**: `-scriptPath /opt/ghidra-scripts` を必ず指定（ghidra.shのrun_headless()で設定済み）

### Alpine Linux gcompat問題 - Decompiler起動不可（2026-02-24発見）
- **問題**: `DecompInterface.openProgram()` が `false` を返し、全関数のデコンパイルが失敗（`decompileCompleted() == false`、エラーメッセージ空）
- **原因**: Alpine Linux（musl libc）上でGhidraのデコンパイラバイナリ（`/opt/ghidra/Ghidra/Features/Decompiler/os/linux_x86_64/decompile`）がglibc依存のため実行不可（`cannot execute: required file not found`）
- **解決**: `apk add --no-cache gcompat` でglibc互換レイヤーをインストール
- **確認方法**: `docker exec ghidra-headless /opt/ghidra/Ghidra/Features/Decompiler/os/linux_x86_64/decompile` が正常終了すること
- **対策**: Dockerfileに `gcompat` を追加しておくべき。未対策の場合はコンテナ起動後に手動インストール
- **注意**: PyGhidraスクリプト（.py）はGhidra 12.x headlessではサポートされない場合がある。Javaスクリプト（.java）を使用すること

### Ghidra Headlessでの特定関数デコンパイル方法（2026-02-24確認）
- **ユースケース**: 大規模バイナリで全関数デコンパイルが非現実的な場合、特定アドレスの関数のみをデコンパイル
- **スクリプト**: Javaスクリプトで `DecompInterface` + `getFunctionAt(toAddr(0xADDRESS))` を使用
- **テンプレート**: `/opt/ghidra-scripts/DecompileSpecific3.java` がコンテナ内に配置済み
- **実行コマンド**:
```bash
export MSYS_NO_PATHCONV=1
docker exec ghidra-headless bash -c "/opt/ghidra/support/analyzeHeadless /analysis/projects tmp_decomp -import '/path/to/binary' -overwrite -deleteProject -analysisTimeoutPerFile 300 -scriptPath /opt/ghidra-scripts -max-cpu 2 -postScript DecompileSpecific3.java 2>&1"
```

## KB-13: .NET Loader + Process Hollowing パターン（MSILZilla系）

### 特徴
- .NETバイナリでインポートテーブル完全空（0 DLL）
- 関数数が異常に多い（65,000+）= ジャンクコードによるアンチ解析
- 多言語関数名（英/独/仏/西語混在）でソースコード読解を妨害
- 139+のWindowsフォームクラス（`above101_Load`, `adobe82_Load`等）
- button1_Clickスタブ（2バイト）= GUIの偽装
- PE metadata偽装（FileDescription/ProductNameが無意味な文字列）

### Ghidra静的解析の限界
- Ghidraは.NET ILコードをネイティブ同様にデコンパイルするが、ジャンクコード量が膨大でノイズが多すぎる
- strings出力はほぼメタデータのみ（24文字列等）
- imports出力は0件
- **静的解析でのIOC抽出は不可能** → VT behavior + 動的解析が必須

### VT behaviorで確認すべきポイント
- `RegAsm.exe` / `MSBuild.exe` / `InstallUtil.exe` 等の正規.NETツール起動 = Process Hollowing
- Dropped files に PE_EXE がある = インジェクションペイロード
- DbgManagedDebugger / DbgJITDebugLaunchSetting レジストリチェック = .NETアンチデバッグ

### CAPA検出パターン
- T1620 Reflective Code Loading（.NETアセンブリ動的ロード）
- T1497.001 VM検知（Parallels/QEMU/VBox/Xen文字列参照）
- T1614 System Location Discovery（ジオフェンシング）
- CreateThread/SuspendThread大量マッチ = スレッドインジェクション

### 推奨フロー
1. Ghidra info/imports → .NET判定、インポート空確認
2. VT behavior → Process Hollowing先の正規ツール名とDropped PEハッシュ取得
3. CAPA → Anti-VM/Anti-Debug/Reflective Loading確認
4. VMware Sandbox動的解析（FakeNet-NG + HollowsHunter）
5. dnSpy（VM内）でILレベルのデコンパイル

## KB-14: Go製Dropper + Dead Drop Resolver パターン

### 特徴
- Go 1.x コンパイル（DWARF情報残存の場合あり）
- 関数数5,000+（Go標準ライブラリ静的リンク）
- mainパッケージの関数が極端に少ない（3-5個）
- net/http + os/exec インポート = URL取得→実行
- Pastebin/GitHub Gist等のDDRサービスURLがハードコード

### 解析手順
1. strings出力から `pastebin.com`, `gist.github.com`, `raw.githubusercontent.com` 等のURL検索
2. DDR URLの中身を `curl` で確認（Stage 2 URL取得）
3. proxy-webでStage 2をダウンロード
4. Stage 2のGhidra解析→ファミリ特定

### CAPA検出パターン（wolfSSL静的リンク型）
- wolfSSL: AES/3DES/RC4/Salsa20/ChaCha + SHA全種 + HMAC
- Base64/XOR多数マッチ（Go標準ライブラリのエンコーディング）
- クレジットカードパース → Stage 1自体にもInfoStealer機能の可能性
- kernel32ベースアドレス解決 + PEエクスポートパース = ランタイムリンキング

### 注意
- Go製バイナリのYARAマッチ率は低い（静的リンクでシグネチャが埋もれる）
- Goランタイム文字列がstrings出力の大部分を占める → mainパッケージ関連のxrefsを優先確認

## KB-15: .enc.gz ファイルの自動処理（2026-03-11修正）

### 問題
yara-scan/capa コマンドが .enc.gz（proxy-web隔離ファイル）を直接処理できず、手動復号が必要だった。

### 解決
ghidra.sh の yara-scan/capa コマンドに .enc.gz 自動検出・復号を追加:
1. 入力ファイルが `.enc.gz` の場合、Ghidraコンテナ内で `decrypt_in_container()` を実行
2. 復号済みバイナリを一時ディレクトリにコピー
3. ホスト側のYARA/CAPAスキャナーで解析
4. 完了後にコンテナ内・ホスト側の一時ファイルを両方クリーンアップ

### 使い方（変更なし）
```bash
bash tools/ghidra-headless/ghidra.sh yara-scan "tools/proxy-web/Quarantine/<domain>/<ts>/<file>.enc.gz"
bash tools/ghidra-headless/ghidra.sh capa "tools/proxy-web/Quarantine/<domain>/<ts>/<file>.enc.gz"
```

## KB-16: .NETバイナリ解析ガイド（2026-04-12追加）

### Ghidraの.NET制限事項

Ghidraのネイティブデコンパイラ（`decompile_all.py`）は.NET CIL（Common Intermediate Language）を処理できない。
.NETバイナリに対してdecompileを実行すると全関数で `Decompilation error` が発生する。

**Ghidraで可能な.NET解析:**
- `info`: アーキテクチャ、セクション情報（CLI Streamエラーが出るが動作はする）
- `functions`: .NETメタデータからの関数名リスト（クラス名・メソッド名が取得可能）
- `strings`: PE文字列（VersionInfo等のメタデータ。.NETの文字列リテラルは取得困難）
- `imports`: 空になる（.NETはP/Invoke以外インポートテーブルを使わない）
- `xrefs`: 全てcaller/callee 0になる（CILはネイティブ呼び出しではない）

**Ghidraでは不可能:**
- `decompile`: 全関数エラー（CIL非対応）
- ネイティブxrefs: CILのメソッド呼び出しはGhidraのxref解析に現れない

### dotnet-decompile ツール（推奨）

ILSpy CLIをDocker化した専用ツール: `tools/dotnet-decompiler/dotnet-decompile.exe`

```bash
# C#ソースへの完全デコンパイル（.enc.gz自動復号対応）
bash tools/ghidra-headless/ghidra.sh dotnet-decompile <binary|file.enc.gz>

# メタデータ（参照アセンブリ等）
bash tools/ghidra-headless/ghidra.sh dotnet-metadata <binary|file.enc.gz>

# 型/クラス一覧
bash tools/ghidra-headless/ghidra.sh dotnet-types <binary|file.enc.gz>
```

### .NET判別条件
1. VTタグに `assembly`, `msil`, `peexe` + `64bits` が同居
2. Ghidra infoで "CLI Stream" エラー出現
3. CAPA出力に `dotnet` バックエンド表記
4. ファイルサイズが小さい（数十KB）のにfunction名が豊富 → .NETメタデータ由来

### .NET推奨フロー
```
Phase 0: PE Triage（pe_triage.py）
  → .NET検出 → Ghidra decompileスキップ、dotnet-decompileへ

Phase 1（並列）:
  Agent A: dotnet-decompile（C#ソース取得、主力）
  Agent B: YARA（ファミリ判定）
  Agent C: CAPA（ATT&CK、dotnetバックエンド）
  Agent D: Ghidra info+functions（メタデータのみ）

Phase 2: C#ソースから手動IOC抽出
  → ioc_extractor.pyはGhidra出力前提のためC#ソースには未対応
  → C#ソースのURL/IP/ドメイン/レジストリキーは手動で抽出

Phase 3: レポート
```

### 実例: MSILHeracles Loader（2026-04-12、furystaff.tech）
- `net_launcher.exe` (27KB) → VT 36/76 trojan.msilheracles
- namespace `pornhub`、メソッド `cum()` — 挑発的な命名
- 攻撃フロー: Mutex確認 → C2からDLL取得 → %TEMP%/*.hrz書き出し → LoadLibraryA → Init() → 自己削除
- TLSハンドラ、スレッド列挙・強制終了、SelfPostRemove（fsutil + del）
- Ghidraでは全37関数デコンパイル失敗 → dotnet-decompileで完全C#ソース取得成功

## KB-17: Ghidraデコンパイラ権限エラー修正（2026-04-12発見、2026-04-13根本修正）

### 問題
Ghidraコンテナ内のデコンパイラバイナリ（`/opt/ghidra/Ghidra/Features/Decompiler/os/linux_x86_64/decompile`）の権限不足により、decompile_all.pyが全関数でエラーを返す。**エラーメッセージは空文字列**で原因特定が困難。

### 根本原因（2026-04-13確定）
初期修正で `chmod +x`（実行権限）のみ付与したが、**読み取り権限(`+r`)が不足**していた。ダイナミックローダー(`ld-linux-x86-64.so.2`)はELFファイルを**読んでメモリにマッピング**する必要があり、`--x`（実行のみ）ではPermission deniedで起動失敗する。

Ghidra Java側はデコンパイラプロセスの起動失敗をJavaのDecompileResultsオブジェクトにラップするが、`getErrorMessage()`は空文字列を返す。`getDecompiledFunction()`がnullになるのみで、根本原因への手がかりを一切提供しない。

### 解決
Dockerfileを `chmod +rx` に修正:
```dockerfile
RUN chmod +rx /opt/ghidra/Ghidra/Features/Decompiler/os/linux_x86_64/decompile || true && \
    chmod +rx /opt/ghidra/Ghidra/Features/Decompiler/os/linux_arm_64/decompile || true
```

### 早期検出機能（2026-04-13追加）
decompile_all.pyに早期失敗検出を追加。最初の10関数が全てエラーの場合:
- `[CRITICAL]` レベルの警告メッセージを出力
- `chmod +rx` の修正コマンドを表示
- 分析は継続するが、ユーザーに即座に問題を通知

### 影響
- 既存コンテナ: `docker exec -u root ghidra-headless chmod +rx /opt/ghidra/Ghidra/Features/Decompiler/os/linux_x86_64/decompile` で即時修正可能
- 新規ビルド: Dockerfile修正済み（`+rx`）
- 修正前: 5068/5068 ERROR（エラーメッセージ空）
- 修正後: 5068/5068 SUCCESS（エラー0）

---

## KB-18: .NETパイプライン改善（2026-04-12）

### 問題
.NETバイナリ解析時に3つのツールが正常動作しなかった:

1. **pe_triage.py**: ホスト側ツールのため.enc.gzファイルを直接処理できない（DOS Header magic not found）
2. **ioc_extractor.py**: Ghidra出力のみスキャン → .NETバイナリではstrings/importsがほぼ空 → IOC 0件
3. **malware_classifier.py**: 同上の理由で分類不能（Unknown 0%）

### 原因
- pe_triage.pyはpefileライブラリに依存しホスト実行前提。.enc.gzの復号はコンテナ内でしかできない
- ioc_extractor.pyとmalware_classifier.pyは `tools/ghidra-headless/output/` のファイルのみ参照
- dotnet-decompiler出力（`tools/dotnet-decompiler/output/<binary>/` 配下の.csファイル）を参照していなかった

### 解決

**1. ghidra.sh pe-triageサブコマンド追加:**
- .enc.gz検出 → コンテナ内で復号 → ホストの一時ディレクトリにコピー → pe_triage.py実行 → 一時ファイル削除
- analyze-fullパイプラインにもPhase 0として統合

**2. ioc_extractor.py dotnet出力スキャン:**
- `find_ghidra_outputs()` に dotnet-decompiler出力ディレクトリのスキャンを追加
- `tools/dotnet-decompiler/output/<binary_name>/` 配下の全.csファイルを再帰走査
- binary_name（拡張子付き）とstem（拡張子なし）の両方でディレクトリを検索
- .NET名前空間の偽陽性（system.io, system.net等）をBENIGN_DOMAINSに追加

**3. malware_classifier.py dotnet出力スキャン:**
- 同様にfind_ghidra_outputs()にdotnet-decompiler出力を追加
- C#ソースをimports_text + strings_textの両方に追加（P/Invoke定義 + 文字列リテラル）
- Loaderルールに `LoadLibraryA`, `GetProcAddress`, `FreeLibrary`, `DownloadFile`, `WebClient` 等を追加

### 結果（net_launcher.exe再テスト）
| ツール | Before | After |
|--------|--------|-------|
| pe-triage | DOS Header error | LOW_IMPORTS_DYNAMIC_API（正常） |
| ioc-extract | 0 IOC | 2 IOC（C2 IP + C2 URL） |
| classify | Unknown 0% | **Loader 98%** |

---

## KB-22: AdaptixC2 beacon 静的解析パターン（2026-04-27 追加）

### 帰属の決め手（誤解しやすい順）

1. **C++ RTTI 文字列**: `13ConnectorHTTP` / `9Connector` / `N10__cxxabiv117__class_type_infoE` / `N10__cxxabiv120__si_class_type_infoE` が `.rdata` に出現 → AdaptixC2 ソースの `extenders/beacon_agent/src_beacon/beacon/Connector{,HTTP}.{h,cpp}` と一致。`ConnectorDNS` / `ConnectorSMB` / `ConnectorTCP` も同階層に存在
2. **MinGW-w64 でビルドされた C++**: `Mingw-w64 runtime failure` / `__C_specific_handler` / `__getmainargs` / pseudo-relocation 系メッセージ
3. **インポート極少**: KERNEL32 + MSVCRT のみ 28 個前後、ネットワーク/Crypt API 不在 → 動的 API 解決の典型
4. **VT family**: `adaptixc2` / `zusy` / `adaptix`

### 動的 API 解決の構造（ApiLoader.cpp）

- ハッシュ関数: **DJB2 variant**, `hash = 0x624 + 33 * hash + tolower(c)`（標準 DJB2 は seed 5381・乗数 33 — 乗数は同じだが seed が違う）
  - 同じハッシュ計算は wide-string 版もあり（PEB walk で DLL 名を照合）
- PEB walk via `gs:[0x60]` → `Ldr->InMemoryOrderModuleList` で目的の DLL ハンドルを取得（`GetModuleAddress`）
- export table を走査し API 名のハッシュ照合（`GetSymbolAddress`）
- `api-ms-win-*` / `ext-ms-*` (Windows API set) は forwarded export を再帰解決
- グローバル `SysModules` / `ApiWin` / `ApiNt`（=Ghidra 上の `DAT_xxxxxxxx` の関数ポインタ table）に解決済みアドレスを保存

### 埋込 profile のレイアウト（AgentConfig.cpp）

```
[ 4 bytes  ] declared_size N        (uint32, NATIVE LE)
[ N bytes  ] RC4-encrypted profile
[ 16 bytes ] RC4 key
```

- profile データは `getProfile()` が返す `.rdata` 内のラベル
- profile サイズは `getProfileSize()` の戻り値（即値 1 行）
- `getProfile()` / `getProfileSize()` はいずれも非常に小さい関数（`return &DAT_*` / `return 0xNNN;`）→ 関数サイズが 11/13 bytes 程度の関数を Ghidra から探すのが近道
- profile 復号後は **AgentConfig::AgentConfig() の Unpack 順** で読む: `agent_type, kill_date, working_time, sleep_delay, jitter_delay, listener_type, use_ssl, servers[], http_method, uris[], parameter, user_agents[], http_headers, ans_pre_size, ans_size, host_headers[], rotation_mode, proxy_type, proxy_host, proxy_port, proxy_username, proxy_password`

### Packer のエンディアン非対称（落とし穴）

- `Pack32` / `Set32` は **明示的に big-endian** で書く（`place[0] = (v >> 24) & 0xFF; ...`）→ agent → server 通信用
- `Unpack32` は **`memcpy(&value, buf+idx, 4)` ベース** = ネイティブ x86-64 の **little-endian 読み**
- つまり server が profile を埋め込む際は LE で書く必要がある（公式 server がそうしている）
- 復号スクリプトを書く時に Pack のソースだけ見て BE で実装すると `declared_size` が巨大値（例 `0x01010000`）になり、RC4 鍵が空でこける

### 静的解析時の検出限界

- **YARA**: ファミリ別の専用ルールが追いついていない or サンプルが少しずつ違う → 0 hits も普通
- **CAPA**: IAT がほぼ空（KERNEL32+MSVCRT 28 件のみ）→ rule マッチ不能で `ERROR capa: 22 / Error: CAPA produced no output`
- → 動的 API 解決ビーコン全般で CAPA は使えない。ハッシュ → API 名マップ後に capa を「rules を当てる」方式は別途必要

### 自動化ツール

```bash
bash tools/ghidra-headless/ghidra.sh adaptix-profile <bin|enc.gz>      # profile 抽出 + RC4 復号 → JSON
bash tools/ghidra-headless/ghidra.sh adaptix-hash-match <bin|enc.gz>   # decompile_all 出力のハッシュ → API 名 → CSV
```

- `adaptix_profile_extract.py` は LE で `declared_size` を読み、layout 整合性 (`4 + N + 16 == profile_size`) をチェック。不整合なら `--profile-rva` / `--profile-size` で上書きできる
- `adaptix_hash_match.py` は `FUN_<api_resolver>(handle, 0x...)` パターンと `FUN_<module_resolver>(0x...)` パターンを抽出。バンドル `adaptix_apidefines.h` は GPL-3.0 snapshot（`gh api` で再取得可能、ヘッダコメント参照）

### 参考になった事例（agent.x64.exe / d3e257a5...921fb）

- VT 52/75 / family `adaptixc2`/`zusy`
- 105KB / .text 96KB / 337 functions / TLS callback 2 個
- profile size = 0x115 (277 bytes), declared_size = 0x101 (257), key 16 bytes
- C2: `20.198.18.136:443` / `POST /api/v1/status, /updates/check.php, /content.html`
- Beacon-ID HTTP header: `X-Beacon-Id`
- 解決された API ハッシュ 125 個すべて `ApiDefines.h` と一致（matched=125, unmatched=0）→ 改変なしの公式ビルド

---

## KB-23: Ghidra プロジェクトロックと pe-triage MSYS パスバグ（2026-04-27 修正）

### Ghidra プロジェクトロック競合（並列実行不可問題）

**症状**: `ghidra.sh` の解析系コマンド（`yara-scan`, `imports`, `strings` など）を 1 メッセージ内で 5 並列起動すると 4/5 が次のエラーで失敗:

```
ERROR Abort due to Headless analyzer error:
ghidra.framework.store.LockException: Unable to lock project!
/analysis/projects/tmp_project
```

**原因**: `analyzeHeadless` は同名プロジェクトを排他ロックする。`PROJECT_NAME="tmp_project"` が固定だったため。

**対策**: `run_headless` 関数内で per-invocation の suffix を付与:

```bash
local proj_name="${PROJECT_NAME}_$$_$(date +%s%N)"
```

`-deleteProject` フラグが付いているので古いプロジェクトは自動掃除される。これにより独立コマンドの並列実行が可能になった。

### pe-triage `.enc.gz` の MSYS パスバグ

**症状**: `bash ghidra.sh pe-triage <file.enc.gz>` で復号後に次のエラーで死ぬ:

```
OSError: [Errno 22] Invalid argument: 'C:\\Users\\<host>\\AppData\\Local\\Temp\\tmp.XXX\\<binary>'
```

**原因**: 旧フローは「コンテナ内で復号 → ホスト一時ディレクトリへ docker cp → ホスト Python (`pe_triage.py`) で開く」だったが、Git Bash の MSYS パス変換が `C:\Users\...\Temp\tmp.XXX\...` 文字列を破壊し、`open()` が `Errno 22` を返す。

**対策**: `.enc.gz` を渡された場合は **完全コンテナ内実行** に自動切替:

```
.enc.gz → resolve_binary でコンテナ内 /tmp に復号
        → pe_triage.py をコンテナにコピー
        → コンテナ内 python3 で実行
        → /tmp/output/. をホストにコピー
        → 復号済みバイナリ削除
```

通常 PE（host path）は今まで通りホスト側 pe_triage.py で速く処理する。`--in-container <path>` 明示指定も継続サポート。

### ioc-extract / classify の `.enc.gz` basename 解決

**症状**: `bash ghidra.sh ioc-extract <file.enc.gz>` で

```
Error: No Ghidra output files found for '<full path>.enc.gz' in .../output
  Looked for: <full path>.enc.gz_strings.txt, <full path>.enc.gz_imports.txt, ...
```

**原因**: 引数のフルパス（`.enc.gz` 込み）をそのまま `ioc_extractor.py` に渡していたため、Ghidra が出力する `<binary basename>_strings.txt` 等と名前が一致しない。

**対策**: ghidra.sh 側で basename + `.enc.gz` strip を行ってから渡す:

```bash
ioc_target=$(basename "${2%.enc.gz}")
python3 ioc_extractor.py "$ioc_target" ...
```

`classify` も同様の処理を追加。これによりユーザはフルパス（`.enc.gz` 込み）でも binary name 単独でも同じように呼べる。
