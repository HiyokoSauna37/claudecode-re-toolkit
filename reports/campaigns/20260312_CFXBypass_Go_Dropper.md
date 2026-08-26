# Ghidra Analysis: CFXBypass.exe (Go Dropper + Dead Drop Resolver)
Date: 2026-03-12

## Target
- File: CFXBypass.exe
- SHA256: 165c77e0cb3fc6551babc2de99e0c5182fb86e20ac3354da7ae980b580721049
- MD5: 423cf5ddbe13df64594385b8fd519cc7
- Size: 8,346,112 bytes (8.0 MB)
- Format: PE x86-64
- Compiler: Go 1.25.4 (`cmd/compile go1.25.4; regabi`)
- Image Base: 0x140000000

## Source
- Download URL: https://raw.githubusercontent.com/... (proxy-web Quarantine)
- Quarantine Path: `tools/proxy-web/Quarantine/raw.githubusercontent.com/20260312_012816/CFXBypass.exe.enc.gz`

## Analysis Performed
- [x] info
- [x] imports
- [x] strings (via container `strings` — Ghidra script UnicodeEncodeError)
- [x] exports (5,977 functions)
- [x] YARA scan (0 matches / 739 rules — expected for Go, KB-14)
- [ ] CAPA (container execution pending)
- [ ] decompile (decompiler binary missing from container)
- [x] DDR URL resolved → Stage 2 confirmed
- [x] **Dynamic Analysis (vmware-sandbox)** — FakeNet-NG付きHost-Only環境で実行

## Key Findings — Research Detail

### マルウェアファミリ特定
- **分類: Go製 Dropper / Loader** (Dead Drop Resolver パターン, KB-14完全一致)
- ビルドパス: `E:/REINSTALL OS 3/Loaders&Droppers/hello.go`
- Goパッケージ: `_/E_/REINSTALL_OS_3/Loaders_Droppers`
- 偽装: FiveM (CFX.re) バイパスツールを装う

### KB-14 一致項目
| 特徴 | 本検体 |
|---|---|
| Go 1.x コンパイル | ✅ Go 1.25.4 |
| 関数数 5,000+ | ✅ 5,977 |
| mainパッケージ関数が極少 | ✅ 6関数（main.a, main.b, main.main + deferwrap x3） |
| net/http + os/exec | ✅ 両方使用 |
| DDRサービスURL ハードコード | ✅ Pastebin |

### 攻撃チェーン
```
[1] CFXBypass.exe (Go Dropper)
    ├── PowerShell: MessageBox "Checking for updates..." (社会的偽装)
    ├── HTTP GET: https://pastebin.com/raw/QKQwYyHd (DDR)
    │   └── 取得内容: https://gitlab.com/khannely/derrxt/-/raw/main/clean4213.exe
    └── os/exec: Stage 2 ダウンロード＆実行

[2] clean4213.exe (MSILZilla .NET Loader, 15.2MB)
    ├── VT: 46/76 (Trojan.MSILZilla)
    ├── SHA256: 2788e0a5aa953234b427955d133786bc99dd0a8e45439d541e7cdf87738e28ed
    ├── 65,746 ジャンク関数 + 多言語難読化
    └── Process Hollowing → RegAsm.exe

[3] Final Payload (未取得 — 動的解析が必要)
    └── RegAsm.exe内で実行される最終ペイロード（InfoStealer推定）
```

### 技術的詳細

#### ソーシャルエンジニアリング
- ファイル名 `CFXBypass.exe` はFiveM (CitizenFX) のバイパスツールを装う
- 実行時に PowerShell で偽ダイアログ表示:
  ```powershell
  Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('Checking for updates...', 'Updater', 'OK', 'Information')
  ```
- ユーザーが「アップデート確認中」と思っている間にバックグラウンドでStage 2をダウンロード

#### Dead Drop Resolver (DDR)
- DDR URL: `https://pastebin.com/raw/QKQwYyHd`
- 取得内容: `https://gitlab.com/khannely/derrxt/-/raw/main/clean4213.exe`
- DDRの利点: C2 URLをPastebinで更新可能（バイナリ再配布不要）

#### Go バイナリ特性
- 静的リンク: 全Go標準ライブラリが同梱 → 8MB
- インポート: `KERNEL32.DLL!TlsAlloc` のみ（Go典型）
- DWARF デバッグ情報残存（ver 5, 179 compUnits）
- 暗号ライブラリ: crypto/rc4, crypto/tls, crypto/aes, crypto/des（TLS通信用、ペイロード暗号化の可能性も）
- mime/multipart 使用 → ファイルアップロード/マルチパートPOSTの可能性

#### Main パッケージ関数
| Address | Size | Name |
|---|---|---|
| 0x14022bba0 | 220B | main.a |
| 0x14022bc80 | 558B | main.b |
| 0x14022bee0 | 67B | main.b.deferwrap2 |
| 0x14022bf40 | 76B | main.b.deferwrap1 |
| 0x14022bfa0 | 1,372B | main.main |
| 0x14022c520 | 67B | main.main.deferwrap1 |

- `main.main` (1,372B): メインロジック（DDR取得→DL→実行の全フロー推定）
- `main.b` (558B): HTTP通信またはペイロード実行処理推定
- `main.a` (220B): ヘルパー関数

### ATT&CK マッピング
| Technique | Description |
|---|---|
| T1204.002 | User Execution: Malicious File (FiveM bypass偽装) |
| T1059.001 | Command and Scripting Interpreter: PowerShell (MessageBox表示) |
| T1102.001 | Web Service: Dead Drop Resolver (Pastebin) |
| T1105 | Ingress Tool Transfer (GitLab → clean4213.exe) |
| T1036.005 | Masquerading: Match Legitimate Name (CFXBypass) |
| T1027.002 | Obfuscated Files: Software Packing (Stage 2: MSILZilla) |
| T1055.012 | Process Injection: Process Hollowing (Stage 2 → RegAsm.exe) |

### IOC一覧
#### Network
- DDR: `https://pastebin.com/raw/QKQwYyHd`
- Stage 2: `https://gitlab.com/khannely/derrxt/-/raw/main/clean4213.exe`
- GitLab Actor: `khannely`

#### File Hashes
| Stage | SHA256 | MD5 |
|---|---|---|
| Stage 1 (CFXBypass.exe) | `165c77e0cb3fc6551babc2de99e0c5182fb86e20ac3354da7ae980b580721049` | `423cf5ddbe13df64594385b8fd519cc7` |
| Stage 2 (clean4213.exe) | `2788e0a5aa953234b427955d133786bc99dd0a8e45439d541e7cdf87738e28ed` | `0a83ae0d2f0004850488c20ec4a14aa1` |

#### Host
- Build Path: `E:/REINSTALL OS 3/Loaders&Droppers/hello.go`
- PowerShell execution via `os/exec`

## Dynamic Analysis Results (vmware-sandbox)

### 環境
- VM: Windows 10 (Host-Only, ネットワーク隔離)
- FakeNet-NG 3.5: DNS/HTTP偽応答でC2通信パターンをキャプチャ
- 解析出力: `tools/vmware-sandbox/output/CFXBypass.exe_20260312_022453/`

### 実行結果サマリ

| 項目 | 結果 |
|---|---|
| プロセス存続 | 短命（実行後に自己終了） |
| 子プロセス | `powershell.exe` (MessageBox表示) |
| Stage 2 DL | 30回リトライ後に失敗（FakeNet応答がvalid PEではない） |
| ドロップ先 | `%AppData%\700f6155ae167f34<N>.exe` (N=0-36, 全て0バイト) |
| レジストリ永続化 | なし（Run key未変更） |
| Process Hollowing | 未発生（Stage 2未取得のため） |
| VM検知 | なし（正常実行） |

### 挙動詳細

#### Phase 1: ソーシャルエンジニアリング
1. `CFXBypass.exe` 起動直後に `powershell.exe` をspawn
2. PowerShellが MessageBox `"Checking for updates..."` を表示
3. ユーザーをアップデート確認画面で待機させている間にバックグラウンドでDDR通信を試行

#### Phase 2: DDR → Stage 2 ダウンロード試行
1. `pastebin.com` にHTTPS接続を試行（DDR取得）
2. FakeNet-NGがDNS応答 + 偽HTTPレスポンスを返却
3. 取得した「URL」に対してStage 2のダウンロードを試行
4. ダウンロード先: `%AppData%\Roaming\700f6155ae167f34<N>.exe`
   - ファイル名 `700f6155ae167f34` はハッシュ/識別子ベースの固定プレフィックス
   - サフィックス番号 `0-36` で順次リトライ（一部欠番: 13, 16, 20, 27, 30, 32）
5. FakeNetの応答がvalid PEではないため全ファイル0バイト
6. 30回のリトライ後に終了

#### Phase 3: 実行試行
- ダウンロード失敗のため Stage 2 実行には至らず
- `OpenWith.exe` ダイアログが表示（FakeNet応答ファイルをWindowsが開こうとした）

### 攻撃チェーン（動的解析で確認）
```
CFXBypass.exe (Go Dropper)
├── [確認済み] powershell.exe → MessageBox "Checking for updates..."
├── [確認済み] HTTPS → pastebin.com (DDR) — FakeNetで応答キャプチャ
├── [確認済み] Stage 2 DL → %AppData%\700f6155ae167f34<N>.exe (30回リトライ)
├── [未到達] Stage 2 (clean4213.exe) 実行
├── [未到達] Process Hollowing → RegAsm.exe
└── [未到達] Final Payload
```

### 動的解析IOC（追加）
#### Host Artifacts
- Drop Path: `%AppData%\700f6155ae167f34<N>.exe` (N=0-36)
- ファイル名プレフィックス: `700f6155ae167f34` （固定識別子）
- PowerShell子プロセス（MessageBox表示用）

### ATT&CK マッピング（動的解析で追加確認）
| Technique | Description | 確認方法 |
|---|---|---|
| T1059.001 | PowerShell: MessageBox表示 | プロセスリストで確認 |
| T1102.001 | DDR: Pastebin HTTPS接続試行 | FakeNet応答 + OpenWithダイアログ |
| T1105 | Stage 2 DL: 30回リトライ機構 | `%AppData%` に0バイトEXE×30 |
| T1547 | Persistence: **未使用**（Dropper単体では永続化なし） | レジストリ Run key 未変更 |

### 評価
- **VM検知なし**: Go DropperはVM環境チェックを実装していない（単純なDDR+DL+Exec）
- **リトライ機構**: 30回以上のダウンロード試行 → 通信不安定な環境でも粘り強く動作する設計
- **Stage 2取得にはNAT or 実インターネット接続が必要**: Host-Only+FakeNetではStage 2のvalid PEを取得できない
- **推奨**: clean4213.exe（Stage 2）をproxy-web等で別途取得し、vmware-sandboxで独立解析するのが効率的

## Ghidra環境の問題（本解析で発生）
1. **デコンパイラ未インストール**: コンテナ内に `/opt/ghidra/Ghidra/Features/Decompiler/os/linux_x86_64/decompile` が存在せず、全関数のデコンパイル失敗
2. **UnicodeEncodeError**: Go記号名のUnicode文字（`[]`, `{}`, `*`等）で `extract_strings.py`, `decompile_all.py`, `xrefs_report.py` が出力ファイル書き込み失敗（0バイト）
3. **docker cp MSYS パス変換**: `SCRIPT_DIR` (MSYS形式) を `docker cp` に渡すと `GetFileAttributesEx C:\c` エラー → `SCRIPT_DIR_WIN` に修正済み

## 関連レポート
- [clean4213.exe (MSILZilla .NET Loader)](20260312_clean4213_MSILZilla_Loader.md) — Stage 2

## 推奨次ステップ
1. ~~**動的解析**: vmware-sandbox で実行~~ → ✅ 完了（本レポート）
2. **clean4213.exe 動的解析**: Stage 2 を vmware-sandbox で実行 → Process Hollowing → RegAsm.exe 内の最終ペイロード取得
   - 既にproxy-webで取得済み or VT/MalwareBazaarからDL可能
   - [関連レポート: clean4213.exe](20260312_clean4213_MSILZilla_Loader.md)
3. **VT検索**: CFXBypass.exe の SHA256 でVT提出・検出率確認
4. **GitLab Actor調査**: `khannely` の他リポジトリ・アクティビティ確認
5. **Pastebin監視**: DDR URL の内容変更追跡（別のStage 2に差し替えられる可能性）
