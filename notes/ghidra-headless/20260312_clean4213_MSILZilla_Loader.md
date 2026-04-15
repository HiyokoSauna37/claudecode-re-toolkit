# Ghidra Analysis: clean4213.exe (MSILZilla .NET Loader)
Date: 2026-03-12

## Target
- File: clean4213.exe
- SHA256: `2788e0a5aa953234b427955d133786bc99dd0a8e45439d541e7cdf87738e28ed`
- MD5: `0a83ae0d2f0004850488c20ec4a14aa1`
- SHA1: `e59fd14a995fcf91da5490e97e2fd3636bc10f7e`
- Size: 15,973,888 bytes (15.2 MB)
- Format: .NET PE64 (amd64)

## Source
- Download URL: `https://gitlab.com/khannely/derrxt/-/raw/main/clean4213.exe`
- VirusTotal: **46/76 検出** — `trojan.msil/zilla`
- VT Link: https://www.virustotal.com/gui/file/2788e0a5aa953234b427955d133786bc99dd0a8e45439d541e7cdf87738e28ed

## Analysis Performed
- [x] info
- [x] imports
- [x] strings
- [x] functions
- [x] xrefs
- [x] decompile (失敗 — 65k関数でOOM)
- [x] YARA scan (0マッチ)
- [x] CAPA analysis (14 capabilities)
- [x] IOC extraction
- [x] Classification
- [x] VT behavior lookup

## Key Findings — Research Detail

### マルウェアファミリ特定
- **ファミリ名**: MSILZilla (.NET Loader / Process Hollowing)
- **VT分類**: `trojan.msil/zilla` (26ベンダがtrojan、12がMSIL系と判定)
- **VTタグ**: `64bits`, `assembly`, `peexe`, `spreader`
- **根拠**:
  - .NETバイナリ + 65,746ジャンク関数（8バイトスタブ）
  - 多言語難読化関数名（独/仏/西/英混在: `QualitätssicherungIsnhA8`, `gastronomiqueAkxCB3`, `recuerdoAGuHC4`）
  - PE metadata偽装（InternalName: "dete", ProductName: "outcome", Copyright 2023）
  - KB-13パターン完全一致

### Process Hollowing ターゲット
- **正規プロセス**: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe`
- VT behaviorで`RegAsm.exe`がプロセス生成として確認
- T1055.012 (Process Hollowing) が HIGH severity で検出

### Dropped Files
| SHA256 | 種別 | パス |
|---|---|---|
| `1e9516da2ded24d635f5fab0347d34ceb76e50b2a015ebb1ee3b8ee69de5faae` | RegAsm.exe (正規) | `%windir%\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe` |
| `645a18d7ffd962724134d55541e00e95fc903be3e1701b04a7a536e21423c0f4` | **PE_EXE (ペイロード)** | — |
| `51516adfcc2efa23fb4a53d835c91dc5bc66bea7894fb53909afdbbbded43a28` | CLR usage log (CSV) | `%LOCALAPPDATA%\Microsoft\CLR_v4.0\UsageLogs\clean42131.exe.log` |

### 技術的詳細

#### 難読化
- **関数名**: 多言語ランダム単語 + ランダムサフィックス（ConfuserEx系）
- **関数数**: 65,746（大半が8バイトスタブ = ジャンクコード）
- **インポート**: 0件（全てCLR経由で動的解決）
- **文字列**: 24件のみ（PEリソースセクションのバージョン情報のみ）
- **コールグラフ**: 完全破壊（全関数 0 callers / 0 callees）

#### Anti-Analysis
- Anti-VM: Parallels, QEMU, VirtualBox, Xen 文字列参照
- Anti-Debug: SetUnhandledExceptionFilter, ページガード検出
- Geofencing: T1614 System Location Discovery

#### 暗号化
- AES復号（.NET System.Security.Cryptography経由）
- ペイロードをランタイム復号 → RegAsm.exeにProcess Hollowing

#### ランタイム動作
1. AESで埋め込みペイロードを復号
2. RegAsm.exe をサスペンド状態で起動
3. Process Hollowing（T1055.012）でペイロードを注入
4. RegAsm.exeのコンテキストで悪意あるコードを実行

### ATT&CK マッピング
| Technique | 名称 | Severity |
|---|---|---|
| T1055.012 | Process Hollowing | HIGH |
| T1055 | Process Injection (write + control flow modification) | HIGH |
| T1620 | Reflective Code Loading (.NET assembly) | INFO |
| T1027 | Obfuscated Files or Information (AES暗号化ペイロード) | INFO |
| T1027.002 | Software Packing (RWX page) | INFO |
| T1497.001 | Virtualization/Sandbox Evasion | INFO |
| T1614 | System Location Discovery | INFO |
| T1562.001 | Impair Defenses (native function modification) | MEDIUM |
| T1564.003 | Hidden Window | INFO |
| T1057 | Process Discovery | INFO |
| T1129 | Shared Modules (dynamic function loading) | INFO |

### 静的解析の限界
- Ghidra decompile: 65k関数でJVM OOM → 完了不可
- YARA: 0マッチ（.NET難読化でシグネチャ不適合）
- IOC抽出: 0件（文字列がメタデータのみ）
- 分類器: Unknown（インポート/文字列が空で判定不能）

→ **CAPAとVT behaviorが最も有効な情報源**

## 推奨次ステップ
1. **Dropped PE (ペイロード) の解析**: SHA256 `645a18d7ffd962724134d55541e00e95fc903be3e1701b04a7a536e21423c0f4` をVTで取得・Ghidra解析 → 最終ペイロードのファミリ特定
2. **VMware Sandbox動的解析**: HollowsHunter/PE-sieveでRegAsm.exeからインジェクトされたPEをメモリダンプ → Ghidra再解析
3. **dnSpy (VM内)**: ILレベルでAES復号ルーチンとProcess Hollowingロジックの詳細確認
