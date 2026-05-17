# Lazarus CookiePlus Backdoor — ComparePlus.dll

**Date:** 2026-05-17
**Analyst:** Claude Code (ghidra-headless + threat-intel)
**Classification:** Trojan.NukeSped / CookiePlus
**Attribution:** Lazarus Group (DPRK) — Operation DreamJob
**Confidence:** HIGH (Kaspersky IOC exact match)

---

## Executive Summary

Lazarus APT (北朝鮮) の多機能バックドア **CookiePlus** の検体。正規Notepad++プラグイン「ComparePlus」にバックドア機能を注入したトロイの木馬化DLLで、Kasperskyが2024年12月に公開した Operation DreamJob キャンペーンの一部として既に文書化されている。

---

## Sample Identification

| Property | Value |
|----------|-------|
| SHA256 | `6f9b79c20330a7c8ade8285866e5602bb86b50a817205ee3c8a466101193386d` |
| MD5 | `4c4abe85a1c68ba8385d2cb928ac5646` |
| SHA1 | `8edcd1d8d390d61587d334f4527e569a5bdf915c` |
| File Type | PE32+ DLL (x86-64) |
| Size | 670,720 bytes |
| Compile Time | 2024-05-21 08:03:59 UTC |
| Linker | MSVC 14.28 (Visual Studio 2019) |
| VT Detection | 50/68 |
| VT Label | trojan.nukesped/lazarus |
| Source | Triage (260515-z3wresf17x) |

---

## Disguise & Masquerade

### 偽装: ComparePlus (Notepad++ Plugin)

本体はNotepad++用ファイル比較プラグイン「ComparePlus」の正規コードを内包し、以下の正規エクスポートを保持:

| Export | Purpose |
|--------|---------|
| `beNotified` | Notepad++ notification callback |
| `getFuncsArray` | Plugin menu registration |
| `getName` | Plugin name string |
| `isUnicode` | Unicode support flag |
| `messageProc` | Message handler |
| `setInfo` | Plugin initialization |

RTTI情報にも正規プラグインのクラス群 (`ProgressDlg`, `SettingsDialog`, `NavDialog`, `ColorCombo`, `AboutDialog` 等) が残存。

### 内部モジュール名

PE Export Directory の Name フィールド: **`netsvc_loader.dll`** — ネットワークサービスローダーとしての本来の目的を示す。

---

## Persistence Mechanisms

| Mechanism | Detail |
|-----------|--------|
| DLL Sideload | `ComparePlus.dll` として Notepad++ plugins ディレクトリに配置 |
| Windows Service | `ServiceMain` / `ServiceHandler` エクスポートによるサービス登録 |
| Service API | `RegisterServiceCtrlHandlerW`, `SetServiceStatus` をインポート |

---

## Encryption & Obfuscation

| Technique | Evidence |
|-----------|----------|
| PEB Walking (gs:[60h]) | YARA: MalDev_PEB_Walking_x64 (6 string matches) |
| FNV-1a API Hashing | YARA: MalDev_API_Hash_FNV1a (3 string matches) |
| Inline AES (S-box埋込) | YARA: MalDev_AES_Embedded_SBox_or_RCON |
| RC4 PRGA | CAPA: encrypt data using RC4 PRGA |
| XOR Encoding | CAPA: encode data using XOR |
| Stack String Obfuscation | CAPA: contain obfuscated stackstrings |
| Operator Stack (aggregator) | YARA: MalDev_Operator_Stack (high severity) |

---

## C2 Communication

- **ハードコードC2なし** — 静的解析でURL/IPは検出されず
- **外部設定ファイル**: `C:\Program Files\Common Files\microsoft shared\ink\ThirdParty.dat`
  - RC4/AES暗号化されたC2設定を格納
  - Kaspersky報告の別バリアントでは `msado.inc` を使用
- **VNCコンポーネント内蔵**: リモートデスクトップ制御用の TightVNC/UltraVNC 派生コード

---

## Capabilities (CAPA: 48 detections)

### MITRE ATT&CK Mapping

| Tactic | ID | Technique |
|--------|----|-----------|
| Execution | T1129 | Shared Modules |
| Execution | T1059 | Command and Scripting Interpreter |
| Persistence | T1543.003 | Windows Service |
| Persistence | T1574.001 | DLL Search Order Hijacking |
| Defense Evasion | T1027 | Obfuscated Files or Information |
| Defense Evasion | T1027.005 | Indicator Removal from Tools |
| Defense Evasion | T1027.007 | Dynamic API Resolution |
| Defense Evasion | T1222 | File and Directory Permissions Modification |
| Discovery | T1082 | System Information Discovery |
| Discovery | T1083 | File and Directory Discovery |
| Discovery | T1614 | System Location Discovery |
| Collection | T1056.001 | Input Capture: Keylogging |
| Collection | T1115 | Clipboard Data |
| Collection | T1213 | Data from Information Repositories |

### Key Capabilities

- **Keylogging** via `SetWindowsHookExW` (application hook)
- **Clipboard monitoring**
- **Credit card data parsing**
- **Geolocation discovery**
- **Anti-debug** (IsDebuggerPresent, GetTickCount timing)
- **Analysis tool detection** (reference analysis tools strings)
- **Dynamic API resolution** (PEB + FNV-1a hash)
- **PE parsing** (resolve function by parsing PE exports)
- **Process/thread creation** (CreateProcess, CreateThread)
- **SQL statement execution** (data exfiltration)

---

## PE Structure

### Sections

| Name | Virtual Size | Raw Size | Entropy | Flags |
|------|-------------|----------|---------|-------|
| .text | 372,516 | 372,736 | 6.454 | RX |
| .rdata | 133,022 | 133,120 | 5.215 | R |
| .data | 24,396 | 7,680 | 3.532 | RW |
| .pdata | 17,808 | 17,920 | 5.665 | R |
| _RDATA | 148 | 512 | 1.447 | R |
| .rsrc | 133,472 | 133,632 | 2.859 | R |
| .reloc | 3,608 | 4,096 | 5.183 | R |

### Imports (9 DLLs, 234 functions)

- KERNEL32.dll, USER32.dll, ADVAPI32.dll, SHELL32.dll
- SHLWAPI.dll, GDI32.dll, COMCTL32.dll, COMDLG32.dll, MSIMG32.dll

### Suspicious APIs (9)

- `ShellExecuteW` — Command execution
- `OpenProcess` — Process manipulation
- `GetProcAddress` / `LoadLibraryW` — Dynamic loading
- `GetTickCount` / `QueryPerformanceCounter` — Anti-analysis timing
- `IsDebuggerPresent` — Debugger detection
- `TerminateProcess` — Process termination
- `SetWindowsHookExW` — Keylogging hook

### Rich Header

Compiled with multiple VS2019 toolset versions (builds 26715, 29118, 29333), indicating a project built over time or incorporating pre-built libraries.

---

## IOCs

### File Indicators

| Type | Value |
|------|-------|
| SHA256 | `6f9b79c20330a7c8ade8285866e5602bb86b50a817205ee3c8a466101193386d` |
| MD5 | `4c4abe85a1c68ba8385d2cb928ac5646` |
| SHA1 | `8edcd1d8d390d61587d334f4527e569a5bdf915c` |
| Filename (disguise) | `ComparePlus.dll` |
| Internal name | `netsvc_loader.dll` |

### Host Indicators

| Type | Value |
|------|-------|
| Config file path | `C:\Program Files\Common Files\microsoft shared\ink\ThirdParty.dat` |
| Service registration | Via `ServiceMain` / `ServiceHandler` exports |
| Plugin location | Notepad++ `plugins\ComparePlus\` directory |

### Related Samples (Kaspersky IOC list, same campaign)

| MD5 | Description |
|-----|-------------|
| `e6a1977ecce2ced5a471baa52492d9f3` | CookiePlus variant (ComparePlus.dll) |
| `fdc5505d7277e0bf7b299957eadfd931` | CookiePlus variant (ComparePlus.dll) |
| `80ab98c10c23b7281a2bf1489fc98c0d` | CookiePlus variant (ComparePlus.dll) |

---

## Attribution

### Confirmed: Lazarus Group (Operation DreamJob)

| Evidence | Detail |
|----------|--------|
| Kaspersky IOC match | MD5 `4c4abe85a1c68ba8385d2cb928ac5646` listed in securelist report |
| VT consensus | 50/68 vendors label as trojan.nukesped/lazarus |
| TTP alignment | ComparePlus disguise, service persistence, external config, crypto stack |
| Campaign | Operation DreamJob / DeathNote (fake job offer delivery) |
| Malware family | CookiePlus (MISTPEN successor) |

### Public References

1. **Kaspersky securelist** (2024-12): https://securelist.com/lazarus-new-malware/115059/
   - "Lazarus new malware" — CookiePlus, MISTPEN evolution
   - Contains this exact MD5 in IOC appendix
2. **Triage tags**: cookieplus, lazarus, apt, backdoor, discovery, downloader, loader, persistence

---

## Comparison with Notepad++ Hosting Incident (2025)

| | Notepad++ Supply Chain (2025) | This Sample (CookiePlus) |
|---|---|---|
| Actor | Chinese APT (Lotus Blossom) | **North Korean (Lazarus)** |
| Vector | Hosting infra compromise → update hijack | Social engineering → DLL sideload |
| Timeline | June–December 2025 | Compiled May 2024 |
| Scope | All updaters (mass targeting) | Targeted individuals (fake job offers) |
| Relation | **None** | N/A |

---

## Recommendations

1. **Detection**: YARA rule on `netsvc_loader.dll` export name + Notepad++ plugin exports combination
2. **Hunting**: Search for `ThirdParty.dat` in `%ProgramFiles%\Common Files\microsoft shared\ink\`
3. **Prevention**: Notepad++ plugin integrity verification, application allowlisting
4. **Dynamic Analysis**: Recover `ThirdParty.dat` from infected hosts to decrypt C2 configuration

---

## Analysis Artifacts

| File | Content |
|------|---------|
| `tools/ghidra-headless/output/cookieplus_triage.json` | PE Triage results |
| `tools/ghidra-headless/output/cookieplus_capa.json` | CAPA capability analysis (48 detections) |
| `tools/ghidra-headless/output/cookieplus_maldev.json` | MalDev technique scan |

---

*Generated by cc-malware-toolkit (ghidra-headless + threat-intel skills)*
