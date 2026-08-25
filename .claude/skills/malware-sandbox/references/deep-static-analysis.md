# 深層静的解析ガイド

post-execution-audit.md の F/G を超える高度な静的解析手順。
エンコードされたペイロードの抽出、カーネルドライバ解析、Authenticode検証、threat-intel相関を扱う。

## 前提

- Ghidra コンテナ起動済み (`docker compose up -d`)
- 対象バイナリを永続プロジェクトにインポート済み（post-execution-audit.md の F 節参照）
- `ghidra.sh analyze` の出力 (`_strings.txt`, `_xrefs.txt`, `_functions.txt`, `_imports.txt`) が存在
- `decompile_function.py` / `extract_string.py` は `tools/ghidra-headless/scripts/` にコミット済み。Docker volume mount により `/opt/ghidra-scripts/` にマウントされるため、`docker cp` は不要

## コマンド実行環境の使い分け

| コマンド種別 | 実行環境 | 理由 |
|---|---|---|
| `docker exec ghidra-headless bash -c '...'` | PowerShell | Git Bash がコンテナ内パス (`/opt/...`) を Windows パスに変換してしまうため |
| `bash tools/ghidra-headless/ghidra.sh ...` | Bash (Git Bash) | ghidra.sh 自体が bash スクリプト。引数のホスト側パスは正しく処理される |
| PowerShell スクリプト（デコード等） | PowerShell | .NET ライブラリ使用 |

## 1. デコンパイルターゲットの選定

### 1.1 Suspicious API 逆引き

**1.1 と 1.2 は両方実行し、結果を統合してターゲットを選定する。**

xrefs 出力から、セキュリティ重要APIの呼び出し元を特定:

```bash
grep -E "CreateServiceW|CreateProcessW|ShellExecuteW|RegSetValueExW|ReadProcessMemory|VirtualProtect|WriteProcessMemory|NtQueryInformationProcess" \
  tools/ghidra-headless/output/<name>_xrefs.txt
```

`Called by:` の関数名を記録。

### 1.2 大関数の特定

```bash
# 関数をサイズ降順でソート（上位30件）
grep -E "^\s*0x" tools/ghidra-headless/output/<name>_functions.txt | \
  awk '{print $2, $4, $1}' | sort -rn | head -30
```

2000バイト超の関数はオーケストレータやメインロジックの可能性が高い。

### 1.3 デコンパイル実行

```bash
# PowerShell から実行（Git Bash はコンテナパスを変換してしまう）
docker exec ghidra-headless bash -c '
/opt/ghidra/support/analyzeHeadless /analysis/projects ghidra_project \
  -process <name>.dll -noanalysis \
  -scriptPath /opt/ghidra-scripts \
  -postScript decompile_function.py /analysis/output/<name>_targeted.txt \
    0xOFFSET1 0xOFFSET2 0xOFFSET3'
```

**注意**: decompile_function.py は ASCII のみ対応（Jython制限）。em-dash 等の非ASCII文字を使わないこと。

**オフセットの計算**: decompile_function.py にはImageBase相対オフセットを渡す。
ImageBase は `_info.txt` の先頭、または decompile_function.py の出力ヘッダ `ImageBase: 0x180000000` で確認可能。
`オフセット = 関数の絶対アドレス - ImageBase` (例: `0x180008000 - 0x180000000 = 0x8000`)。

## 2. エンコードされたペイロードの抽出

### 2.1 長大文字列の発見

strings 出力で Base64 や Hex パターンを探す:

```bash
grep -oE '[A-Za-z0-9+/=]{100,}' tools/ghidra-headless/output/<name>_strings.txt | \
  awk '{print length, substr($0,1,60)"..."}' | sort -rn | head -10
```

strings 出力は切り詰められるため、Ghidraスクリプトで全文抽出が必要:

### 2.2 アドレス指定で全文抽出 (extract_string.py)

```powershell
# PowerShell から実行（Git Bash はコンテナパスを変換するため）
docker exec ghidra-headless bash -c '/opt/ghidra/support/analyzeHeadless /analysis/projects ghidra_project -process <name>.dll -noanalysis -scriptPath /opt/ghidra-scripts -postScript extract_string.py /analysis/output/full_string.txt 0x<ADDRESS>'
```

ADDRESS は strings 出力の先頭列にある **絶対仮想アドレス** をそのまま使う。
strings 出力形式: `0x180045000     "QUFBQ..."` — この `0x180045000` 部分がアドレス。

### 2.3 多層デコード

マルウェアは多層エンコードを使う。一般的なパターン:

| パターン | 層1 | 層2 | 層3 | 結果 |
|---|---|---|---|---|
| Triple (本検体) | Base64 | Base64 | Hex→bytes | PE (MZ) |
| Double | Base64 | XOR/RC4 | - | shellcode/PE |
| Single + compression | Base64 | inflate/LZNT1 | - | PE/config |

デコード手順 (PowerShell):

```powershell
# Layer 1: Base64
$layer1 = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($raw))

# Layer 2: Base64 again (if layer1 matches ^[A-Za-z0-9+/=]+$)
$layer2 = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($layer1))

# Layer 3: Hex to bytes (if layer2 matches ^[0-9A-Fa-f]+$ and starts with 4D5A)
$bytes = New-Object byte[] ($layer2.Length / 2)
for ($i = 0; $i -lt $layer2.Length; $i += 2) {
    $bytes[$i/2] = [Convert]::ToByte($layer2.Substring($i, 2), 16)
}

# MZ check
[Text.Encoding]::ASCII.GetString($bytes[0..1])  # should be "MZ"
```

**サイズヒントの活用**: デコンパイル中に `local_xx = 0xNNNN` のような定数が見つかったら、デコード結果のバイト数と照合する。一致すればデコードが正しい証拠。

### 2.4 抽出PEの解析

```bash
# Ghidra input にコピーして pe-triage
cp <extracted>.bin tools/ghidra-headless/input/<name>.dll
bash tools/ghidra-headless/ghidra.sh pe-triage tools/ghidra-headless/input/<name>.dll

# Subsystem: Native なら カーネルドライバ
# full analyze で xrefs/strings/imports を取得
bash tools/ghidra-headless/ghidra.sh analyze tools/ghidra-headless/input/<name>.dll

# 解析後は input から削除
rm tools/ghidra-headless/input/<name>.dll
```

## 3. カーネルドライバ解析

### 3.1 ドライバの特徴

| フィールド | 値 | 意味 |
|---|---|---|
| Subsystem | Native | カーネルモード |
| INIT セクション | あり | ドライバ初期化コード |
| ntoskrnl.exe のみインポート | 典型 | カーネルAPI直接呼び出し |
| IoCreateDevice | あり | ユーザーモード通信チャネル |

### 3.2 重要API分類

```
[プロセス操作]
PsLookupProcessByProcessId, ZwTerminateProcess, ZwOpenProcess

[ドライバ操作]  
ZwUnloadDriver, ZwQuerySystemInformation(SystemModuleInformation=0xB)

[ファイル操作]
ZwCreateFile(DELETE), ZwSetInformationFile(FileDispositionInformation)

[レジストリ操作]
ZwOpenKey, ZwCreateKey, ZwSetValueKey, ZwDeleteKey

[通信]
IoCreateDevice, IoCreateSymbolicLink, IofCompleteRequest
```

### 3.3 AV/EDR Killer の判定基準

以下の3つ以上が揃えば AV/EDR Killer:
1. ZwTerminateProcess + PsLookupProcessByProcessId
2. ZwUnloadDriver
3. セキュリティ製品名の文字列 (MsMpEng, WdFilter, 360, etc.)
4. ZwSetValueKey でサービス Start=4 (DISABLED)
5. IoCreateDevice (user-mode からの kill コマンド受付)

### 3.4 ドライバのデコンパイル

まず Section 1 の手順でターゲットオフセットを特定してから実行する。
entry 関数は pe-triage の `Entrypoint: 0xNNNN` から取得（この値は ImageBase 相対オフセット = decompile_function.py にそのまま渡せる）。worker/killer 等は xrefs + strings から推定。

```powershell
# プロジェクトにインポート
docker exec ghidra-headless bash -c '
/opt/ghidra/support/analyzeHeadless /analysis/projects ghidra_project \
  -import /analysis/input/<driver>.dll -overwrite \
  -scriptPath /opt/ghidra-scripts'

# デコンパイル (entry + worker + killer + unloader)
docker exec ghidra-headless bash -c '
/opt/ghidra/support/analyzeHeadless /analysis/projects ghidra_project \
  -process <driver>.dll -noanalysis \
  -scriptPath /opt/ghidra-scripts \
  -postScript decompile_function.py /analysis/output/<driver>_decompile.txt \
    <entry_offset> <worker_offset> <killer_offset> <unloader_offset>'
```

## 4. Authenticode 署名の検証

### 4.1 オーバーレイデータの確認

pe-triage で `Overlay data: N bytes at offset 0xXXXX` が出たら Authenticode 署名の可能性。
`0xXXXX` はファイル先頭からのバイトオフセット（PE読み込みコードでそのまま配列インデックスとして使える）:

```powershell
$pe = [IO.File]::ReadAllBytes("extracted.bin")
$offset = 0x<overlay_offset>
# PKCS#7 マーカー: 30 82 ... 06 09 2A 86 48 86 F7 0D 01 07 02
$hex = ($pe[$offset..($offset+15)] | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
# "30 82" で始まれば ASN.1 SEQUENCE (証明書)
```

### 4.2 証明書情報の抽出

```powershell
# .sys 拡張子で保存（Get-AuthenticodeSignature が認識するため）
Copy-Item extracted.bin temp_driver.sys
$sig = Get-AuthenticodeSignature -FilePath temp_driver.sys

# 主要フィールド
$sig.Status                          # Valid / HashMismatch / NotSigned
$sig.SignerCertificate.Subject       # 署名者
$sig.SignerCertificate.Issuer        # 発行者
$sig.SignerCertificate.Thumbprint    # フィンガープリント (IOC)
$sig.SignerCertificate.SerialNumber  # シリアル (IOC)
$sig.TimeStamperCertificate.Subject  # タイムスタンプ署名者
```

### 4.3 偽証明書の判定

| チェック項目 | 本物 | 偽物 |
|---|---|---|
| Microsoft WHQL の Country | C=US | C=CN, C=HK 等 |
| Issuer と Subject が同一組織 | No (CA は別組織) | しばしば同一 |
| Status | Valid | HashMismatch / UnknownError |
| 証明書チェーンの深さ | 3以上 | 1-2 |

## 5. PDB パスの抽出

PDB パスは開発者の環境情報を含む重要IOC:

```powershell
$pe = [IO.File]::ReadAllBytes("extracted.bin")
# RSDS シグネチャを検索 (0x52 0x53 0x44 0x53)
for ($i = 0; $i -lt $pe.Length - 4; $i++) {
    if ($pe[$i] -eq 0x52 -and $pe[$i+1] -eq 0x53 -and $pe[$i+2] -eq 0x44 -and $pe[$i+3] -eq 0x53) {
        $pathStart = $i + 24  # RSDS(4) + GUID(16) + Age(4)
        $pathEnd = $pathStart
        while ($pathEnd -lt $pe.Length -and $pe[$pathEnd] -ne 0) { $pathEnd++ }
        $pdb = [Text.Encoding]::ASCII.GetString($pe[$pathStart..($pathEnd-1)])
        Write-Output "PDB: $pdb"
        break
    }
}
```

PDB パスから読み取れる情報:
- プロジェクト名 / ツールセット名
- バージョン番号
- ビルド構成 (Debug/Release)
- 開発者のドライブレター / ディレクトリ構造

## 6. Threat-Intel 相関

### 6.1 ハッシュ相関 (複数サービス横断)

```bash
python3 tools/threat-intel/intel-cli.py correlate-hash <SHA256> --output-format json --quiet
```

### 6.2 個別サービス

```bash
# VirusTotal 詳細
python3 tools/threat-intel/intel-cli.py vt hash <SHA256>

# VT サンドボックス挙動 (verdict_labels が重要)
python3 tools/threat-intel/intel-cli.py vt behavior <SHA256>

# MalwareBazaar
python3 tools/threat-intel/intel-cli.py bazaar hash <SHA256>
```

### 6.3 結果の解釈

| VT verdict_labels | 意味 |
|---|---|
| WinosStager | Winos4.0 フレームワークのステージャー |
| ValleyRAT | Winos 系の RAT コンポーネント |
| Terminator / Poortry | 既知の AV Killer ドライバ |
| BYOVD | Bring Your Own Vulnerable Driver |

## 7. 推奨ワークフロー（深層静的解析）

```
1. ghidra.sh analyze → 基本出力取得 (strings, imports, xrefs, functions)
2. imports/xrefs からターゲット関数選定 → decompile_function.py
3. FLOSS 結果 + strings で長大エンコード文字列を発見
4. extract_string.py で全文抽出 → 多層デコード → PE確認
5. 抽出PEを pe-triage → Subsystem確認 → full analyze
6. カーネルドライバなら: strings でキルリスト、imports でAPI確認
7. Authenticode 署名検証 → 証明書IOC抽出
8. PDB パス抽出 → ツールセット/キャンペーン帰属
9. threat-intel correlate-hash → ファミリー判定
10. VT behavior → sandbox verdict でフレームワーク特定
```

## extract_string.py (Ghidra script) — 参考実装

`tools/ghidra-headless/scripts/extract_string.py` としてコミット済み（volume mount で自動配置）。
以下はソース参考:

```python
# Ghidra script: extract wide string at a given address
# @category Analysis
# @runtime Jython
import codecs
args = getScriptArgs()
output_path = args[0]
addr_hex = args[1]
program = currentProgram
addr_space = program.getAddressFactory().getDefaultAddressSpace()
addr = addr_space.getAddress(int(addr_hex, 16))
mem = program.getMemory()
chars = []
offset = 0
while True:
    try:
        lo = mem.getByte(addr.add(offset)) & 0xFF
        hi = mem.getByte(addr.add(offset + 1)) & 0xFF
        code_point = lo | (hi << 8)
        if code_point == 0:
            break
        chars.append(chr(code_point))
        offset += 2
    except:
        break
result = ''.join(chars)
print("[INFO] Address: 0x%x, Length: %d chars" % (addr.getOffset(), len(result)))
with codecs.open(output_path, 'w', encoding='utf-8') as f:
    f.write(result)
print("[INFO] Saved to %s" % output_path)
```
