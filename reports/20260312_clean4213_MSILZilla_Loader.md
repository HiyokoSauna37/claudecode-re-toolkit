# Ghidra Analysis: clean4213.exe (MSILZilla .NET Loader)
Date: 2026-03-12

## Target
- File: clean4213.exe
- SHA256: 2788e0a5aa953234b427955d133786bc99dd0a8e45439d541e7cdf87738e28ed
- MD5: 0a83ae0d2f0004850488c20ec4a14aa1
- Size: 15,973,888 bytes (15.2 MB)
- Format: .NET PE64 (x86-64)
- Image Base: 0x140000000

## Source
- Download URL: https://gitlab.com/khannely/derrxt/-/raw/main/clean4213.exe
- VirusTotal: **46/76** (Trojan.MSILZilla)
- VT Link: https://www.virustotal.com/gui/file/2788e0a5aa953234b427955d133786bc99dd0a8e45439d541e7cdf87738e28ed

## Analysis Performed
- [x] info
- [x] imports
- [x] strings
- [x] functions
- [x] xrefs
- [x] exports
- [x] YARA scan (0 matches / 739 rules)
- [x] CAPA analysis (15 rules matched)
- [x] IOC extraction (0 IOCs — expected for packed .NET loader)
- [x] Malware classification (Unknown — .NET obfuscation defeats heuristic classifier)
- [ ] decompile (skipped: 65,746 junk functions, KB-13 threshold exceeded)

## Key Findings — Research Detail

### マルウェアファミリ特定
- **ファミリ名: MSILZilla** (Trojan.MSILZilla / MSIL/Kryptik)
- 根拠: VT 46/76検出、`popular_threat_label: trojan.msil/zilla`
- 分類: **.NET Loader with Process Hollowing** (KB-13パターン完全一致)

### KB-13一致項目
| 特徴 | 本検体 |
|---|---|
| .NETバイナリ、インポート空 | ✅ 0 imports from 0 DLL |
| 65,000+ジャンク関数 | ✅ 65,746関数 |
| 多言語関数名（英/独/仏/西混在） | ✅ `QualitätssicherungIsnhA8`, `gastronomiqueAkxCB3`, `mêmeJLIRs3`, `recuerdoAGuHC4` |
| PE metadata偽装 | ✅ ProductName: `dete`, FileDescription: `outcome` |
| strings出力がメタデータのみ | ✅ 24文字列（全てPEリソース情報） |
| RegAsm.exe Process Hollowing | ✅ VT behavior: RegAsm.exe dropped |
| .NETアンチデバッグ | ✅ DbgManagedDebugger / DbgJITDebugLaunchSetting レジストリチェック |

### CAPA検出（ATT&CK マッピング）
| Technique | Description |
|---|---|
| T1027 | Obfuscated Files or Information |
| T1620 | Reflective Code Loading (.NETアセンブリ動的ロード) |
| T1497.001 | Virtualization/Sandbox Evasion (Parallels, Qemu, VirtualBox, Xen検出) |
| T1614 | System Location Discovery (ジオフェンシング) |

### MBC (Malware Behavior Catalog)
| MBC | Description |
|---|---|
| B0009 | Virtual Machine Detection |
| E1027.m05 | AES Encryption (.NET標準) |
| C0038 | Create Thread (139 matches) |
| C0055 | Suspend Thread (140 matches) |
| C0018 | Terminate Process |

### VT Behavior分析
- **Process Hollowing先**: `%windir%\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe`
- **Dropped PE**: SHA256 `645a18d7ffd962724134d55541e00e95fc903be3e1701b04a7a536e21423c0f4` (VT未登録)
- **Anti-Debug**: DbgManagedDebugger / DbgJITDebugLaunchSetting レジストリ確認
- **.NET CLR log**: `clean42131.exe.log` (ファイル名に"1"追加)
- **Tags**: `64bits`, `assembly`, `peexe`, `spreader`

### 技術的詳細
- **難読化**: 65,746個のジャンク関数（多言語ランダム名）でコード解析を妨害
- **Anti-VM**: Parallels, QEMU, VirtualBox, Xen の文字列参照による仮想環境検出
- **ペイロード復号**: AES (.NET標準ライブラリ) でランタイム復号
- **実行フロー**: .NET CLR → AESでペイロード復号 → RegAsm.exe起動 → Process Hollowing → ペイロード注入・実行
- **ジオフェンシング**: System Location Discoveryで地域制限の可能性

### 静的解析の限界
- Ghidra decompileは65,746関数のジャンクコードにより実質不可能（タイムアウト）
- imports/strings/xrefsからのIOC抽出は不可（全て.NET動的解決 + ランタイム復号）
- **最終ペイロードの特定には動的解析（VMware Sandbox + HollowsHunter）が必須**

## Dropped PE Payload (未分析)
- SHA256: `645a18d7ffd962724134d55541e00e95fc903be3e1701b04a7a536e21423c0f4`
- VT Status: 未登録（NotFound）
- 注: RegAsm.exeにインジェクトされるペイロード。ファミリ特定には動的解析でメモリダンプが必要

## 推奨次ステップ
1. **VMware Sandbox動的解析**: FakeNet-NG + HollowsHunter でRegAsm.exeからペイロードをダンプ
2. ダンプしたPEをGhidra再解析 → 最終ペイロードのファミリ特定（InfoStealer? RAT?）
3. C2通信先のネットワークIOC取得
