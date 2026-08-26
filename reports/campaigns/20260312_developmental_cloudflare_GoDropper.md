# Malware Analysis Report: developmental.exe (Cloudflare Phishing Lure)

**Date**: 2026-03-12
**Analyst**: Claude Code (Ghidra Headless)
**Classification**: Obfuscated Go Binary — Possible Ransomware/Loader (Unconfirmed)
**Confidence**: LOW (static analysis only, dynamic analysis required)

---

## Executive Summary

`cloudflare-check.cfd` からダウンロードされたPHPファイル偽装のGo製Windowsバイナリ。Go 1.26.0でコンパイルされ、関数名・型名が英単語で難読化されている。CAPA解析により動的API解決（PEB walking）、多重暗号化（Salsa20/ChaCha, RC4, AES, XOR）、デバッガ検出のcapabilityが確認された。C2アドレス等の直接的IOCは静的解析では抽出不可 — ランタイム復号と推定。VT未登録の新規検体。

---

## Sample Information

| Property | Value |
|---|---|
| Original Filename | developmental.exe |
| Delivered As | index.php |
| SHA256 | `2c4e09f94e5487378f4953e4d0fb1353be50087991ae9d8e93367a41f5898007` |
| MD5 | `80b6971a8ebfd9e9d51d2e81f6e34a2f` |
| SHA1 | `71c37b0068b687f4205d32b28094520c68f15d4f` |
| File Size | 2,322,432 bytes (2.2 MB) |
| File Type | PE32+ (x86-64) Windows executable |
| Compiler | Go 1.26.0 |
| Source Path | optimization/main.go |
| Version | 1.0.0.0 |
| VirusTotal | Not found (未登録) |
| YARA | 0 matches / 739 rules |

## Delivery

| Property | Value |
|---|---|
| Domain | cloudflare-check.cfd |
| URL | `https://cloudflare-check.cfd/api/index.php?a=dl&token=0c1bad9a...&src=cloudflare&mode=cloudflare` |
| Technique | Cloudflare偽装フィッシング — ブラウザ確認を装いバイナリをDL |
| Content-Type | application/octet-stream |
| Response Size | 2,322,432 bytes |

## Technical Analysis

### 1. Binary Structure

- **PE64 Windows executable** disguised as `index.php`
- Go 1.26.0 compiled (latest Go — Ghidra RTTI mapper未対応)
- エントリーポイント: `_rt0_amd64_windows` (0x140077c00)
- 1,560関数検出
- 全コードが `optimization/main.go` 1ファイルに集約（外部パッケージ依存なし）

**セクション構成:**
| Section | Size | Permissions | Notes |
|---|---|---|---|
| .text | 685 KB | R-X | コード |
| .rdata | 1.4 MB | R-- | 読み取り専用データ（Goランタイム文字列含む） |
| .data | 344 KB | RW- | 初期化済みデータ |
| .symtab | 100 KB | R-- | Go symbol table |

### 2. Obfuscation

**関数名難読化** — main packageの関数名がランダムな英単語:
- `main.Commissioners` (func1-3, 各5サブ関数)
- `main.Wholesale` (func1-4)
- `main.Emergency` (func1-10, 各最大5サブ関数)
- `main.Authorization` (func1-6)
- `main.Conversations` (func1-4)
- `main.Newsletter` (func1-2)
- `main.Varieties` (func1-2)

**型名難読化:**
- `Australiaappreciate`, `Hypotheticalselecting`, `Informationalinfluences`
- `Conditionhampshire`, `Transitionstarsmerchant`
- 正規の型名: `RegID`, `IRNode`, `Register`, `Discipline`, `MotionVector`, `BlockID`, `AssetClass`, `Position`

### 3. CAPA Capabilities (15 detected)

**動的API解決 (T1106/T1129):**
- PEB access → ldr_data → kernel32 base address取得
- PE export parsingによる関数解決
- PE header parsing

**暗号化/エンコード:**
- Salsa20/ChaCha encryption
- RC4 PRGA encryption
- AES encryption (x86 AES-NI extensions)
- XOR encoding
- Base64 encoding
- Murmur3 hashing

**Anti-Analysis (T1027):**
- Debugger detection (B0001.019)
- Anti-Sandbox indicators: `Sleep`, `sample` strings
- Anti-VM indicators: `CPUID` string

### 4. Import Analysis

唯一のインポート: `KERNEL32.DLL!TlsAlloc`

Strings内のDLL参照:
- `ntdll.dll` — NT native API
- `winmm.dll` — Multimedia (タイマー?)
- `powrprof.dll` — Power management (evasion?)
- `bcryptprimitives.dll` — 暗号化プリミティブ
- `crypt32.dll` — 証明書/暗号化
- `kernel32.dll` — Base Windows API

→ **動的API解決**: PEB walkingでDLLベースアドレスを取得し、Export tableを解析してAPIを動的に解決。インポートテーブルには最低限のみ記載。

### 5. Embedded IOC

| Type | Value |
|---|---|
| SHA256 | `55b825d6d76842fa06225686af4e70043b16687553e9bcbcd398b6e012f72a75` |
| SHA256 | `25d71935e7be5b3a1b9e7953558bb9b2749229687cf3cd39c7f99d3f42672fae` |

※ 用途不明（整合性チェック/ペイロード検証用の可能性）

### 6. Classification Assessment

| Category | Score | Indicators |
|---|---|---|
| **Ransomware** | 13 | `.locked` extension, `RECOVER` string |
| RAT | 5 | `shell`, `sleep` strings |
| Loader | 5 | `inject` string |
| Dropper | 4 | `.exe`, `.dll` strings |
| InfoStealer | 3 | `opera` string |
| Worm | 0 | — |

**判定: Unknown** — スコアはGoランタイム文字列のノイズを含む。`.locked`/`RECOVER`がランサムウェア固有か、Go runtime由来かは静的解析では判別不可。

## MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|---|---|---|
| Obfuscated Files or Information | T1027 | 関数名/型名の英単語難読化、暗号化多重層 |
| Shared Modules | T1129 | 動的API解決（PEB walking + PE export parsing） |
| Masquerading | T1036 | PHPファイル偽装 (index.php → developmental.exe) |
| Phishing: Spearphishing Link | T1566.002 | Cloudflare偽装ドメイン (cloudflare-check.cfd) |

## Static Analysis Limitations

静的解析は以下の理由で限界に達している:

1. **C2/設定が不可視** — 文字列にURL/IP/ドメインが一切なし。ランタイム復号と推定
2. **デコンパイル不可** — Go 1.26がGhidra RTTI mapper未対応。関数レベルの解析不可
3. **動的API解決** — インポート1件。実際に使用されるAPIはPEB walking経由で隠蔽
4. **多重暗号化** — Salsa20, RC4, AES, XOR。設定/ペイロードの暗号化に使用と推定
5. **YARA/VT未マッチ** — 既知ファミリに非該当。新規またはカスタムツールの可能性

## Recommendation: Dynamic Analysis Escalation

**VMware Sandbox動的解析を強く推奨。** 取得すべき情報:

- [ ] **C2通信先**: FakeNet-NG/Wiresharkで通信先IP/ドメイン/プロトコルをキャプチャ
- [ ] **動的API一覧**: API Monitorで実際に呼び出されるWindows APIを記録
- [ ] **ファイル操作**: `.locked`拡張子によるファイル暗号化挙動の確認（Ransomware判定）
- [ ] **メモリダンプ**: HollowsHunterでメモリ内の復号済み設定/ペイロードを抽出
- [ ] **レジストリ/永続化**: ProcMonで永続化メカニズムを特定
- [ ] **埋め込みSHA256の用途**: 整合性チェック/ペイロード検証の確認
