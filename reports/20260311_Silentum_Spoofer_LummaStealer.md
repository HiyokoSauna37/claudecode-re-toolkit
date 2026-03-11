# Silentum Spoofer → LummaStealer Downloader + MSILZilla Loader
Date: 2026-03-11

## Overview

GitHubで「HWID Spoofer」として配布されている偽ツール。実態はLummaStealer系のマルウェアダウンローダー。

## Attack Chain

```
[GitHub] Silentum_Spoofer.exe (Go 1.25.4, 8.3MB)
    |
    | HTTP GET
    v
[Pastebin] /raw/QKQwYyHd → Stage 2 URL (Dead Drop Resolver)
    |
    | HTTP GET
    v
[GitLab] clean4213.exe (.NET, 15.2MB)
    |
    | Process Hollowing
    v
[RegAsm.exe] Injected payload (InfoStealer)
```

## Stage 1: Silentum_Spoofer.exe

| 項目 | 値 |
|------|-----|
| SHA256 | `165c77e0cb3fc6551babc2de99e0c5182fb86e20ac3354da7ae980b580721049` |
| VT | 52/76 (trojan.lummastealer/misc) |
| コンパイラ | Go 1.25.4 (DWARF残存) |
| サイズ | 8,346,112 bytes |
| 関数数 | 5,976 (main: 3) |
| エントリ | `_rt0_amd64_windows` |

### 機能
- `main.main`: Pastebin URLからStage 2 URLを取得 → ダウンロード → `os/exec.Command`で実行
- `main.a`: `crypto/rand.Read`でランダムデータ生成
- `main.b`: ファイル操作(`os.Open`)
- ハードコードURL: `https://pastebin.com/raw/QKQwYyHd`
- VTタグ: `long-sleeps`, `detect-debug-environment`

## Stage 2: clean4213.exe

| 項目 | 値 |
|------|-----|
| SHA256 | `2788e0a5aa953234b427955d133786bc99dd0a8e45439d541e7cdf87738e28ed` |
| VT | 46/76 (trojan.msil/zilla) |
| コンパイラ | .NET (self-contained) |
| サイズ | 15,973,888 bytes |
| 関数数 | 65,746 |
| インポート | 0 (完全隠蔽) |

### 難読化手法
- 139+のWindowsフォームクラス（`above101_Load`, `adobe82_Load`等）
- 多言語ジャンク関数名（英/独/仏/西語混在）
  - 例: `sincereRBnXw1`, `BenutzerfreundlichkeitbtmOh6`, `KunstlicheIntelligenzRmRhq5`
- button1_Clickスタブ（2バイト）
- PE metadata偽装: FileDescription="outcome", ProductName="dete"

### Process Hollowing
- `RegAsm.exe`（正規.NETユーティリティ）を子プロセスとして起動
- メモリ上でペイロードを復号→RegAsm.exeにインジェクション
- RegAsm.exeとしてInfoStealerが動作

### VT Behavior
- Spawns: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe`
- Drops: PE_EXE (`645a18d7ffd962724134d55541e00e95fc903be3e1701b04a7a536e21423c0f4`)
- Anti-debug: DbgManagedDebugger/DbgJITDebugLaunchSetting レジストリチェック

## YARA Scan

| Stage | マッチ | ルール数 |
|-------|--------|----------|
| Stage 1 | 0 | 739 |
| Stage 2 | 0 | 739 |

既知ファミリのシグネチャに該当なし。.NET難読化+Go静的リンクによるシグネチャ回避。

## CAPA Analysis

### Stage 1 (Go Dropper)
| カテゴリ | 検出内容 |
|----------|---------|
| ATT&CK | T1140 Deobfuscate, T1027 Obfuscation, T1129 Shared Modules |
| 暗号 | AES, 3DES, RC4, Salsa20/ChaCha, SHA全種, HMAC, **wolfSSL静的リンク** |
| エンコード | Base64(x24), XOR(x24), FNV(x21), MurmurHash(x6) |
| アンチ解析 | ソフトウェアブレークポイント検出、解析ツール文字列参照 |
| 収集 | **クレジットカード情報パース（2件）** |
| 通信 | HTTPステータスコードチェック |

**注**: Stage 1はDropperだけでなく、クレジットカードパース機能を含む（wolfSSL経由の暗号通信と組み合わせ）

### Stage 2 (.NET Loader)
| カテゴリ | 検出内容 |
|----------|---------|
| ATT&CK | T1027 Obfuscation, T1620 Reflective Loading, T1497.001 VM検知, **T1614 地理的位置取得** |
| Anti-VM | **Parallels, Qemu, VirtualBox, Xen** 全仮想化環境を検出 |
| 暗号 | .NET AES（ペイロード復号） |
| スレッド | CreateThread(139件), SuspendThread(140件) |
| .NET | アセンブリ動的ロード（Reflective Loading）、リソースアクセス |

**注**: VMware以外にもParallels/QEMU/VirtualBox/Xenを検出。ジオフェンシング（T1614）で特定地域のみ動作。

## Dynamic Analysis (VMware Sandbox)

- Network: Host-Only (isolated)
- 結果: 実行後即終了、プロセス/ファイル変更なし
- CLR_v4.0\ngen.logが更新 = .NETランタイムはロードされた
- 原因推定: C2到達不可（Host-Only）またはVM検知で即終了

## IOCs

### Network
| Type | Value |
|------|-------|
| DDR | `https://pastebin.com/raw/QKQwYyHd` |
| Stage2 URL | `https://gitlab.com/khannely/derrxt/-/raw/main/clean4213.exe` |

### File Hashes
| File | SHA256 |
|------|--------|
| Stage 1 | `165c77e0cb3fc6551babc2de99e0c5182fb86e20ac3354da7ae980b580721049` |
| Stage 2 | `2788e0a5aa953234b427955d133786bc99dd0a8e45439d541e7cdf87738e28ed` |
| Injected PE | `645a18d7ffd962724134d55541e00e95fc903be3e1701b04a7a536e21423c0f4` |

### Infrastructure
| Type | Value |
|------|-------|
| GitHub repo | `CAMUNLOCK/Silentum-Spoofer` |
| GitLab repo | `khannely/derrxt` |
| Pastebin ID | `QKQwYyHd` |

### Abused Legitimate Tool
- `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe` (Process Hollowing target)

## MITRE ATT&CK

| ID | Technique | Detail |
|----|-----------|--------|
| T1204.002 | User Execution: Malicious File | "HWID Spoofer"偽装で実行を誘導 |
| T1102.001 | Dead Drop Resolver | Pastebin経由でStage 2 URLを動的取得 |
| T1105 | Ingress Tool Transfer | GitLabからStage 2ダウンロード |
| T1055.012 | Process Hollowing | RegAsm.exeにペイロードインジェクション |
| T1027.002 | Software Packing | .NET難読化（65k+ジャンク関数） |
| T1036.005 | Masquerading | "Silentum Spoofer"として偽装配布 |
| T1497.001 | System Checks | VM/デバッガ検知（Parallels/QEMU/VBox/Xen全対応） |
| T1140 | Deobfuscate/Decode | Stage 1: wolfSSL+AES+RC4+XOR多層エンコード |
| T1620 | Reflective Code Loading | Stage 2: .NETアセンブリ動的ロード |
| T1614 | System Location Discovery | Stage 2: ジオフェンシング |

## 所見

- GitHubで「ゲーミングツール」として配布される典型的なマルウェア配布パターン
- Pastebin DDRにより、Stage 2 URLを任意に変更可能（テイクダウン回避）
- Stage 1はGo製でDWARF残存だが、wolfSSL静的リンク+クレジットカードパース機能あり = 単純Dropperではなく、Stage 1自体にもInfoStealer機能の可能性
- Stage 2は本格的な.NET難読化 + Process Hollowing + 全仮想化環境検知 = 市販のLoader/Crypterサービス（MaaS）
- Stage 2のAnti-VMはParallels/QEMU/VBox/Xen全対応 → ANY.RUN等のクラウドサンドボックスでも回避される可能性
- ジオフェンシング（T1614）により特定地域でのみ動作 → 標的型の要素
- 最終ペイロードはLummaStealer系InfoStealerと推定（VTラベル+クレジットカードパース機能より）
