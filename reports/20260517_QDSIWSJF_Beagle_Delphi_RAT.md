# Malware Analysis Report: QDSIWSJF.msi — Beagle Campaign Delphi RAT Variant

**Date:** 2026-05-17  
**Analyst:** HiyokoSauna (cc-re-toolkit)  
**Sample:** `260511-xbdenagx4x_pw_infected.zip` (Triage submission)  
**Classification:** RAT/Backdoor — Beagle Campaign Advanced Variant  
**Threat Actor:** Russian-speaking cybercrime group (AdaptixC2/RalfHacker cluster)  
**Confidence:** HIGH (TTP match to Sophos "Donuts and Beagles" report, May 2026)

---

## Executive Summary

MSIインストーラーを用いたDLLサイドローディング攻撃により、Delphi/FMX製フルRAT (`woman.dll`) をプロセスホロウイングで展開するマルウェア。Sophos X-Opsが2026年5月に公開した「Donuts and Beagles」キャンペーン（Beagle Backdoor）の**上位バリアント**と判断。同キャンペーンはClaude AI偽サイトのほか、CrowdStrike/SentinelOne/Trellix偽アップデートサイト経由でも配布されており、ロシア語圏サイバー犯罪グループによるマルチペイロード配布オペレーション。

---

## 1. Sample Identification

| Property | Value |
|----------|-------|
| Filename | `260511-xbdenagx4x_pw_infected.zip` → `QDSIWSJF.msi` |
| ZIP Password | infected |
| MSI SHA256 | `729563f7b39c66b8b4d26734b208b880c089853f7a0cb878aaaf9f6bbb51baa9` |
| MSI MD5 | `5d97b054966256fa3e3d2da129ae3654` |
| MSI Size | 12,419,072 bytes |
| MSI Product | "Mum" by "Benzidine Champignon" |
| ProductCode | `{D32BAEF7-2BED-4E41-A94A-A78D42DCA32B}` |
| UpgradeCode | `{C1AE9B0D-12DC-48FD-B927-9870B898B9A6}` |
| Install Path | `%LOCALAPPDATA%\Quadraphony\` |
| CustomAction | "LaunchFile" (EXE自動実行) |

---

## 2. MSI Contents

| Install Name | Role | SHA256 | Size |
|---|---|---|---|
| `EngineSil64.exe` | 正規署名ローダー (NI/ICS) | `cbb423fb06e3a2963de30237ca387f82fbe85b1a989a3bc3a64ac325ca0809f0` | 169,344 |
| `ucrtbase.dll` | **Trojanized** (FNV-1a API hash) | `d93ce42cd625510b2355de086bcd19e2c11307ccade7bad62b09c7f340a866ba` | 1,133,624 |
| `msvcp_win.dll` | **Trojanized** (FNV-1a API hash) | `08f2fe38501a88a7d3c13976733c2ca08b5597c3328d51fa1f5f5d8474c33ecf` | 637,880 |
| `loader_sync.db` | 暗号化ペイロード (entropy 7.99) | `e3aabd546bdf63153ff4dddfc693515f77ed97d3c07c5eab4b99d1d3d4aee86d` | 9,909,530 |
| `buffer_opt.idx` | 設定ファイル | `3fb9263c63a308d3e2f9aa6d0d101bd1445a73c3ff72ad87d523c53c7f8b8ae3` | 23,939 |
| `libcrypto-3-x64.dll` | OpenSSL (正規) | `02a27eeea96756814ed2939c23d1b2a7fd046bb5a745392e198860c25ffbc51d` | 7,269,248 |
| `vcruntime140.dll` | MS Runtime (正規) | `6a611ee3550f5d27952ddf02fa6e919f4c83a53d54efcde1d880614f0695bef0` | 123,496 |
| `MSSP7FR.DLL` | MS Spelling (正規) | `4eb3506399e086944cb2d64429c747624a4f2c75ca68f8d7b808cd23969f0f67` | 974,208 |

---

## 3. Attack Chain

```
[Stage 1] MSI Installation
  ├── msiexec /i QDSIWSJF.msi /qn
  └── Files deployed to %LOCALAPPDATA%\Quadraphony\

[Stage 2] Loader Execution (EngineSil64.exe)
  ├── PDB: C:\jenkins\workspace\BUILD\GitRepos\dca-infra\build_windows_mainline\task\task.pdb
  ├── Signed: Sectigo Public Code Signing CA R36
  ├── Original: National Instruments / ICS energy_server (DAQ/ESRV infrastructure)
  ├── Imports: libcrypto-3-x64.dll (EVP_sha256, HMAC), VCRUNTIME140.dll
  ├── Persistence copy → C:\ProgramData\indexcli_stable\
  ├── Key derivation: HMAC-SHA256 + EVP_MD5 via OpenSSL
  └── Decrypts loader_sync.db → in-memory DLL payload

[Stage 3] Process Hollowing
  ├── Creates: %LOCALAPPDATA%\AdaptiveSc.exe
  ├── Hollows main image at 0x400000 (malformed header)
  └── Reflective DLL injection: woman.dll at 0x2029ffd0000 (RWX, MEM_PRIVATE)

[Stage 4] Final Payload — woman.dll (Delphi/FMX RAT)
  ├── DoH resolution → C2 domain lookup (bypasses DNS monitoring)
  ├── HTTPS POST → 8 C2 IP failover
  ├── CryptoAPI encrypted communication
  ├── Data exfiltration (SaveToZip)
  ├── Additional process injection (VirtualAllocEx + WriteProcessMemory)
  ├── Service installation (CreateServiceW)
  ├── Privilege escalation (AdjustTokenPrivileges)
  └── Cover deployment: Crisp.exe (legit Squirrel installer)

[Stage 5] Post-Exploitation
  ├── Downloads: DataRescueCommunity_1.msi (35MB, additional cover/payload)
  └── Multiple AdaptiveSc.exe instances (×3, redundancy)
```

---

## 4. Final Payload Analysis: woman.dll

| Property | Value |
|----------|-------|
| SHA256 | `05e68390d992c77dc59661e6e95628d72145c37b3f5011558284e986cc2c5506` |
| Size | 8,941,568 bytes |
| Type | PE32+ DLL, x86-64, 10 sections |
| Compiler | Delphi/FreePascal (FMX FireMonkey framework) |
| HTTP Library | ICS THttpCli V9.4 (François Piette) |
| Export Name | `woman.dll` |
| Exports | `TMethodImplementationIntercept`, `__dbk_fcall_wrapper`, `dbkFCallWrapperAddr`, `s` |
| Internal Namespace | `FMX.Controls.OleJxCA` |
| Imports | 537 APIs from 26 libraries (52 suspicious) |
| YARA Detection | **0 / 1,454 rules** (HTML padding evasion) |

### 4.1 RTTI-Derived Class Structure

| Class | Purpose |
|-------|---------|
| `OleJxCA.CommandRecord` | C2コマンド構造 |
| `OleJxCA.TBotDataRecord` | ボットデータ収集 |
| `OleJxCA.M_OnlineRec` | オンライン接続状態管理 |
| `OleJxCA.PLog` | ログ管理 |
| `OleJxCA.PCritSec` | スレッド同期 |
| `Apiariqtypuhe.SaveToZip` | データ窃取(ZIP圧縮) |
| `FMXTee.Editor.Title5QJG.TBrowser` | ブラウザコンポーネント |

### 4.2 Key Capabilities (Import-Based)

| Category | APIs | Function |
|----------|------|----------|
| Crypto | CryptAcquireContext/Hash/DeriveKey/Encrypt/Decrypt/GenKey | 通信暗号化 + config復号 |
| Injection | VirtualAllocEx + WriteProcessMemory + OpenProcess | 追加プロセス注入 |
| Privilege | AdjustTokenPrivileges + OpenProcessToken + LookupPrivilegeValueW | トークン操作 |
| Persistence | CreateServiceW + StartServiceW + RegSetValueExW | サービス + レジストリ |
| Network | WS2_32 + WSOCK32 (dual stack) + gethostbyname | 直接ソケット通信 |
| Anti-Debug | IsDebuggerPresent | 解析回避 |
| Execution | CreateProcessW + CreateProcessAsUserW + ShellExecuteExW | プロセス生成 |
| Sessions | WTSEnumerateSessionsW + WTSQueryUserToken | 他ユーザーセッション操作 |

### 4.3 Evasion Techniques

1. **HTML Content Padding**: .text セクションの大部分がWebページの平文テキスト → YARA署名を完全回避 (0/1454)
2. **DNS over HTTPS (DoH)**: 5つのDoHプロバイダ → 標準DNS監視を回避
3. **FNV-1a API Hashing**: ローダーDLL (ucrtbase/msvcp_win) で動的API解決
4. **Reflective DLL Loading**: ディスク上に最終ペイロードが出現しない
5. **Process Hollowing**: 正規プロセス名 (AdaptiveSc.exe) に偽装
6. **Legitimate Binary Abuse**: Sectigo署名付きNI/ICSバイナリ

---

## 5. C2 Infrastructure

### 5.1 Active C2 Servers (NAT接続で確認)

| IP | Port | State | Role |
|----|------|-------|------|
| `217.9.12.52` | 443 | ESTABLISHED ×2 | Primary C2 |
| `193.202.84.78` | 443 | ESTABLISHED | Secondary C2 |
| `176.65.132.184` | 443 | ESTABLISHED ×2 | Active C2 |
| `193.202.84.72` | 443 | SYN_SENT ×11 | Backup |
| `121.127.37.125` | 443 | SYN_SENT ×10 | Backup |
| `144.31.167.11` | 443 | SYN_SENT ×18 | Backup (most attempts) |
| `45.155.69.198` | 443 | SYN_SENT ×4 | Backup |
| `79.132.131.86` | 443 | SYN_SENT ×2 | Backup |

### 5.2 DoH Resolvers (C2ドメイン解決用)

- `https://cloudflare-dns.com/dns-query`
- `https://dns.google/dns-query`
- `https://dns.google/resolve`
- `https://dns.quad9.net/dns-query`
- `https://dns.opendns.com/dns-query`
- `https://doh.appliedprivacy.net/query`

### 5.3 Communication Protocol

- Transport: HTTPS (TLS 1.2/1.3, port 443)
- Method: HTTP POST (ICS THttpCli V9.4)
- Encryption: Windows CryptoAPI (CryptDeriveKey → CryptEncrypt)
- Failover: 8 IP round-robin
- DNS: DoH (bypasses system DNS resolver and monitoring)
- Certificate: Let's Encrypt ACME自動生成

### 5.4 Local Proxy

- `127.0.0.1:443` (SYN_SENT ×8) — ローカルプロキシ/リダイレクタコンポーネント

---

## 6. Persistence Mechanisms

| Method | Detail |
|--------|--------|
| File Copy | `C:\ProgramData\indexcli_stable\` (全MSIコンテンツ + Crisp.exe) |
| Process Spawning | `%LOCALAPPDATA%\AdaptiveSc.exe` (×3 instances) |
| Service Registration | `CreateServiceW` + `StartServiceW` (API import確認) |
| Registry | `RegSetValueExW` (Run key suspected) |
| Cover Software | `Crisp.exe` — 正規Squirrel installer (Crisp.im Desktop App) |
| Additional Download | `DataRescueCommunity_1.msi` (35MB, TEMP) |

---

## 7. Secondary Payload: Crisp.exe

| Property | Value |
|----------|-------|
| SHA256 | `c2e62475768c9546efe1da92a55f3bb2a55350eed83241139917aabd1ad25f8a` |
| Size | 342,224 bytes |
| Type | PE32, GUI, i386 |
| Identity | **Legitimate** Squirrel auto-updater (Crisp.im Desktop App) |
| PDB | `C:\Users\paulb\code\Squirrel\squirrel.windows\src\StubExecutable\bin\Release\StubExecutable.pdb` |
| Source | `https://gitlab.com/crisp-im/crisp-app-desktop` |
| Purpose | 永続化カバー（正規ソフトウェアに偽装したプロセス存在理由） |

---

## 8. Configuration File: buffer_opt.idx

| Property | Value |
|----------|-------|
| Size | 23,939 bytes |
| Structure | ASCII section (15,607 bytes) + Binary section (8,332 bytes) |
| ASCII Encoding | 独自暗号（文字頻度は英語に一致、転置+カスタムアルゴリズム） |
| Binary Structure | `0xFCADB1` マーカー × 78回、type bytes (0x83/0x4a/0xcb/0x82/0x92/0x46/0x0e/0x6b) |
| Content | C2設定（ドメイン名、暗号鍵等と推定、未解読） |

---

## 9. Campaign Attribution

### 9.1 Related Campaign: "Donuts and Beagles" (Sophos X-Ops, May 2026)

| Feature | Beagle (Sophos) | This Sample |
|---------|-----------------|-------------|
| Delivery | MSI installer | MSI installer ✓ |
| Technique | DLL sideloading | DLL sideloading ✓ |
| Signed Binary | G DATA updater (NOVupdate.exe) | NI/ICS (EngineSil64.exe) |
| Encrypted Data | .dat file (XOR key) | loader_sync.db (HMAC-SHA256) |
| Intermediate | DonutLoader | Custom FNV-1a DLLs |
| Final Payload | Beagle (8 commands) | woman.dll (full RAT) |
| C2 | license.claude-pro.com TCP443/UDP8080 | 8 IP + DoH + HTTPS |
| Active Since | Feb 2026 | Apr 30, 2026 (file timestamps) |
| Brands | Claude, Trellix, CrowdStrike, SentinelOne | "Mum" (generic) |

### 9.2 Evolution Timeline

```
[Feb 2026] Beagle v1 — Simple backdoor (8 commands, XOR decrypt, DonutLoader)
     │       Distribution: update-crowdstrike.com, update-sentinelone.com, update-trellix.com
     │
[Mar 2026] AdaptixC2 variant — Same XOR key, AdaptixC2 shellcode payload
     │       Distribution: claude-pro.com (+ Defender chain, decoy PDF)
     │
[Apr 2026] ★ THIS SAMPLE ★ — Full Delphi/FMX RAT (woman.dll)
     │       Evolution: HMAC-SHA256 crypto, DoH evasion, HTML YARA bypass, 8-IP failover
     │       Distribution: Unknown vector (MSI "Mum" / "Benzidine Champignon")
     │
[May 2026] Sophos public disclosure → IOCs/TTPs published
```

### 9.3 Threat Actor Profile

| Attribute | Assessment |
|-----------|------------|
| Origin | Russian-speaking cybercrime group |
| Framework | AdaptixC2 (developer: "RalfHacker") |
| Associated Ransomware | Akira (AdaptixC2 user, 250+ breaches) |
| Infrastructure | Cloudflare CDN + Alibaba Cloud C2 |
| Sophistication | HIGH (multi-payload, infrastructure rotation, DoH, YARA evasion) |
| Campaign Duration | Feb 2026 — ongoing |
| Distribution | Malvertising + SEO poisoning + multiple brand impersonation |

---

## 10. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|----------|
| Initial Access | Phishing / Malvertising | T1566.001 | MSI via fake brand sites |
| Execution | Signed Binary Proxy Execution | T1218.007 | msiexec + EngineSil64.exe |
| Execution | User Execution | T1204.002 | MSI installer download |
| Persistence | Create/Modify System Service | T1543.003 | CreateServiceW import |
| Persistence | Boot/Logon Autostart (Registry) | T1547.001 | RegSetValueExW import |
| Persistence | Masquerading | T1036.005 | Crisp.exe (legit cover) |
| Privilege Escalation | Access Token Manipulation | T1134.001 | AdjustTokenPrivileges |
| Defense Evasion | DLL Side-Loading | T1574.002 | ucrtbase.dll / msvcp_win.dll |
| Defense Evasion | Process Hollowing | T1055.012 | AdaptiveSc.exe hollowed |
| Defense Evasion | Reflective Code Loading | T1620 | woman.dll RWX injection |
| Defense Evasion | Obfuscated Files or Information | T1027 | HTML padding (0/1454 YARA) |
| Defense Evasion | Dynamic API Resolution | T1027.007 | FNV-1a hashing |
| Defense Evasion | Indicator Removal | T1070.004 | DeleteFileA/W imports |
| Discovery | Process Discovery | T1057 | Winapi.TlHelp32 |
| Discovery | System Information Discovery | T1082 | GET /json (IP check) |
| Command and Control | Encrypted Channel: Asymmetric | T1573.002 | HTTPS + CryptoAPI |
| Command and Control | Application Layer: DNS | T1071.004 | DoH (5 resolvers) |
| Command and Control | Fallback Channels | T1008 | 8 IP rotation |
| Command and Control | Ingress Tool Transfer | T1105 | DataRescueCommunity_1.msi |
| Collection | Data Staged: Local | T1074.001 | SaveToZip |
| Exfiltration | Over C2 Channel | T1041 | HTTP POST |

---

## 11. Detection Recommendations

### 11.1 Network-Based

```yaml
# DoH to known resolvers (malware bypasses standard DNS)
- alert tls any any -> any 443 (tls.sni; content:"cloudflare-dns.com"; sid:1000001;)
- alert tls any any -> any 443 (tls.sni; content:"dns.google"; sid:1000002;)
- alert tls any any -> any 443 (tls.sni; content:"dns.quad9.net"; sid:1000003;)

# C2 IPs
- 217.9.12.52:443
- 193.202.84.78:443
- 193.202.84.72:443
- 176.65.132.184:443
- 121.127.37.125:443
- 144.31.167.11:443
- 45.155.69.198:443
- 79.132.131.86:443
```

### 11.2 Host-Based

```yaml
# File paths
- C:\ProgramData\indexcli_stable\*
- %LOCALAPPDATA%\Quadraphony\*
- %LOCALAPPDATA%\AdaptiveSc.exe

# Process behavior
- EngineSil64.exe spawning AdaptiveSc.exe
- AdaptiveSc.exe with RWX memory regions > 5MB
- Multiple AdaptiveSc.exe instances

# Registry
- HKCU\Software\Microsoft\Windows\CurrentVersion\Run (monitor for new entries)

# Service creation
- New service with binary path containing "indexcli_stable"
```

### 11.3 YARA Rule (HTML Padding Bypass)

```yara
rule Beagle_Delphi_RAT_WomanDLL {
    meta:
        description = "Beagle Campaign Delphi RAT - woman.dll variant"
        author = "HiyokoSauna"
        date = "2026-05-17"
        hash = "05e68390d992c77dc59661e6e95628d72145c37b3f5011558284e986cc2c5506"
    strings:
        $rtti1 = "FMX.Controls.OleJxCA" ascii
        $rtti2 = "TBotDataRecord" ascii
        $rtti3 = "CommandRecord" ascii
        $rtti4 = "M_OnlineRec" ascii
        $rtti5 = "Apiariqtypuhe" ascii
        $export = "woman.dll" ascii
        $http = "THttpCli" ascii wide
        $doh1 = "cloudflare-dns.com/dns-query" ascii wide
        $doh2 = "dns.google/dns-query" ascii wide
        $delphi = "TMethodImplementationIntercept" ascii
    condition:
        uint16(0) == 0x5A4D and
        filesize > 5MB and
        (3 of ($rtti*)) or
        ($export and $delphi and any of ($doh*))
}
```

---

## 12. IOC Summary

### File Hashes (SHA256)

```
729563f7b39c66b8b4d26734b208b880c089853f7a0cb878aaaf9f6bbb51baa9  QDSIWSJF.msi
cbb423fb06e3a2963de30237ca387f82fbe85b1a989a3bc3a64ac325ca0809f0  EngineSil64.exe
d93ce42cd625510b2355de086bcd19e2c11307ccade7bad62b09c7f340a866ba  ucrtbase.dll (malicious)
08f2fe38501a88a7d3c13976733c2ca08b5597c3328d51fa1f5f5d8474c33ecf  msvcp_win.dll (malicious)
e3aabd546bdf63153ff4dddfc693515f77ed97d3c07c5eab4b99d1d3d4aee86d  loader_sync.db
3fb9263c63a308d3e2f9aa6d0d101bd1445a73c3ff72ad87d523c53c7f8b8ae3  buffer_opt.idx
05e68390d992c77dc59661e6e95628d72145c37b3f5011558284e986cc2c5506  woman.dll (final payload)
c2e62475768c9546efe1da92a55f3bb2a55350eed83241139917aabd1ad25f8a  Crisp.exe (legit cover)
```

### Network IOCs

```
# C2 Servers (port 443)
217.9.12.52
193.202.84.78
193.202.84.72
176.65.132.184
121.127.37.125
144.31.167.11
45.155.69.198
79.132.131.86
```

### Filesystem IOCs

```
%LOCALAPPDATA%\Quadraphony\
C:\ProgramData\indexcli_stable\
%LOCALAPPDATA%\AdaptiveSc.exe
%TEMP%\DataRescueCommunity_1.msi
```

### MSI Metadata

```
ProductName: Mum
Manufacturer: Benzidine Champignon
ProductCode: {D32BAEF7-2BED-4E41-A94A-A78D42DCA32B}
UpgradeCode: {C1AE9B0D-12DC-48FD-B927-9870B898B9A6}
```

---

## 13. Unresolved Items

1. **C2 Domains**: DoH経由で解決されるため未特定（IPは8件確定）
2. **buffer_opt.idx 完全解読**: 独自暗号アルゴリズム（転置+カスタム、XOR非適合）
3. **配布経路**: 本検体の具体的な配布サイト/ルート不明
4. **窃取対象詳細**: ブラウザ/ウォレット/クレデンシャル等の具体ターゲット
5. **Crisp.exe の役割詳細**: auto-updater stub が永続化にどう使われるか

---

## 14. Distribution Analysis — 被害者がマルウェアに到達するまで

### 14.1 攻撃者の集客手法

| 手法 | 詳細 |
|------|------|
| **Google Ads (マルバタイジング)** | "Claude AI download", "Claude Code" 等のクエリに対しスポンサー広告を出稿。検索結果1ページ目の最上位に表示 |
| **SEOポイズニング** | オーガニック検索結果でも上位表示を狙う |
| **ブランド偽装** | claude-pro.com を登録、本物の claude.ai のUIを完全クローン |

### 14.2 偽サイトの特徴

| 項目 | 値 |
|------|-----|
| URL | `claude-pro[.]com` |
| 外観 | claude.ai 完全クローン |
| 提供製品名 | "Claude-Pro Relay"（架空） |
| ダウンロードファイル | `Claude-Pro-windows-x64.zip` (505MB) |
| CDN | Cloudflare（正規サイトと同じCDN → ブロック困難） |
| C2ホスティング | Alibaba Cloud（CDNと分離） |
| サーバー設置 | 2026年3月 |
| 機能しないリンク | ダウンロードボタン以外のすべてのリンクがトップページにリダイレクト |

### 14.3 被害者のユーザージャーニー

```
1. ユーザーが "Claude AI" を検索
2. Google Ads の最上位に claude-pro.com が表示
3. クリック → 本物そっくりのサイトが表示
4. "Download for Windows" をクリック
5. Claude-Pro-windows-x64.zip (505MB) をダウンロード
6. 展開 → Claude.msi を実行
7. 「インストール中...」サイレント完了。アプリは起動しない
8. ユーザーは「失敗したかな？」と思い放置
9. 裏側: DLLサイドローディング → 暗号化ペイロード復号 → RAT活動開始
```

### 14.4 被害者が気づかない理由

1. **505MBのZIP**: 「AIモデル含むから大きいんだろう」と合理化
2. **MSI形式**: Windows標準インストーラー、SmartScreenも通過しやすい
3. **署名付きEXE**: 正規証明書（Sectigo/G DATA）で署名 → AV/EDRも見逃す
4. **Startup/ProgramDataに配置**: エクスプローラーで普通見ない場所
5. **プロセス名**: "AdaptiveSc.exe" — タスクマネージャーで見ても怪しくない
6. **HTTPS通信**: C2通信が通常のWeb閲覧と区別不能

### 14.5 同時期に発生しているAIツール偽装キャンペーン

| キャンペーン | 手法 | 発見 |
|---|---|---|
| Fake Claude Pro (Beagle) | 偽サイト + MSI sideload | Sophos, 2026/05 |
| Fake Claude Code (Windows/macOS) | Google Ads + 偽DLサイト | Bitdefender, 2026/03 |
| Claude.ai Shared Chats悪用 | 正規共有チャットでターミナルコマンド誘導 (macOS) | BleepingComputer, 2026/05 |
| Fake CrowdStrike/SentinelOne/Trellix | 偽アップデートサイト | Sophos, 2026/02-04 |
| Fake Cursor/OpenClaw/DeepSeek/Grok | Google Ads 偽ダウンロード | Pillar Security, 2025-2026 |

> **統計**: 2026年最初10週間で、2025年全体を超えるAIツール偽装マルウェアキャンペーンが発生。少なくとも20の異なるキャンペーンがAI/vibe codingエコシステムを標的に（Pillar Security, 2026/03）

### 14.6 配布経路に関する追加ソース

- [AI Coding Tools Under Fire: Mapping the Malvertising Campaigns (Pillar Security)](https://www.pillar.security/blog/ai-coding-tools-under-fire-mapping-the-malvertising-campaigns-targeting-the-vibe-coding-ecosystem)
- [Windows and macOS Malware Spreads via Fake "Claude Code" Google Ads (Bitdefender)](https://www.bitdefender.com/en-us/blog/labs/fake-claude-code-google-ads-malware)
- [Hackers abuse Google ads, Claude.ai chats to push Mac malware (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hackers-abuse-google-ads-claudeai-chats-to-push-mac-malware/)
- [macOS Malware Leverages Google Ads and Legitimate Claude.ai Shared Chats (CybersecurityNews)](https://cybersecuritynews.com/macos-malware-leverages-google-ads/)

---

## 15. References

- [Donuts and Beagles: Fake Claude site spreads backdoor (Sophos X-Ops, May 2026)](https://www.sophos.com/en-us/blog/donuts-and-beagles-fake-claude-site-spreads-backdoor)
- [Fake Claude AI website delivers new 'Beagle' Windows malware (BleepingComputer)](https://www.bleepingcomputer.com/news/security/fake-claude-ai-website-delivers-new-beagle-windows-malware/)
- [AdaptixC2: A New Open-Source Framework Leveraged in Real-World Attacks (Unit42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [Russian Ransomware Gangs Weaponize Open-Source AdaptixC2 (The Hacker News)](https://thehackernews.com/2025/10/russian-ransomware-gangs-weaponize-open.html)
- [RalfHacker identified as AdaptixC2 developer with ties to Russia (SC Media)](https://www.scworld.com/news/ralfhacker-identified-as-adaptixc2-developer-with-ties-to-russia)
- [Open-source AdaptixC2 hacking tool has fans in Russian cybercrime underground (The Record)](https://therecord.media/open-source-adaptixc2-red-teaming-tool-russian-cybercrime)
- [GHOSTPULSE haunts victims using defense evasion bag o' tricks (Elastic Security Labs)](https://www.elastic.co/security-labs/ghostpulse-haunts-victims-using-defense-evasion-bag-o-tricks)
- [HijackLoader/GhostPulse/IDAT Loader Comprehensive Analysis (Vladyslav Bahlai)](https://medium.com/@baglai.vlad/hijackloader-ghostpulse-idat-loader-comprehensive-analysis-6e15f48eb96d)
- [Fake Claude Campaign Uses PlugX-Style DLL Sideloading Chain (GBHackers)](https://gbhackers.com/plugx-style-dll-sideloading-chain/)
