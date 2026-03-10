---
name: vmware-sandbox
description: VMware Workstation上のWindows VM をvmrun CLIで操作し、マルウェアの動的解析を行う。VMProtect等のパックバイナリやGhidra静的解析では限界のある検体に対応。
instructions: |
  スキル実行手順：
  1. VM状態を確認: bash tools/vmware-sandbox/sandbox.sh status
  2. 停止中なら起動: bash tools/vmware-sandbox/sandbox.sh start
  3. ユーザーに「解析対象のバイナリパスを教えてください」と質問
  4. ネットワーク隔離: bash tools/vmware-sandbox/sandbox.sh net-isolate
  5. 指示に応じて解析コマンドを構築・実行
     - 基本的な解析フロー: SKILL.md本文の「手動解析手順」（Step 1〜6）を参照
     - パック済みバイナリ: 「VMProtect/パック済みバイナリの解析手順」を参照
     - アンパック: 「3-Level Unpacking System」を参照
     - DBI解析: 「Frida DBI解析」を参照
     - 失敗時: 「VMProtect解析のフォールバック戦略」を参照
     - ユーザの指示が曖昧な場合: 解析目的を確認してから最適な手法を提案
  6. 結果をユーザーに報告し、次の指示を待つ
  7. 「終了」「exit」で解析セッション終了 → スナップショットに復帰

  トリガー条件:
  - VMProtect/Themida等パック済みバイナリの解析
  - 動的解析、ランタイム挙動の観察
  - プロセスインジェクション、アンパック後のメモリダンプ
  - ネットワーク通信のキャプチャ（C2通信確認）
  - ghidra-headless（静的解析）で限界に達した検体の追加調査
  - 不審EXE/DLLの実行時挙動確認

  ============================================================
  環境情報
  ============================================================
  - VMware Workstation（vmrun CLI）
  - vmrun: .envの VMRUN_PATH で指定
  - VMX: .envの VM_VMX_PATH で指定
  - ゲストOS: Windows 10/11（推奨）
  - ゲスト内Python: 3.10.x / Intel PIN: 3.31（Level 2 TinyTracer用）
  - ゲスト認証: .envファイル（VM_GUEST_USER / VM_GUEST_PASS）
  - ゲストプロファイル: .envのVM_GUEST_PROFILEで設定
  - ゲストIP: 動的（sandbox.sh statusで確認）
  - クリーンスナップショット: .envのVM_SNAPSHOT で設定（デフォルト: "clean_with_tools"）

  ============================================================
  ツールパス
  ============================================================
  - sandbox.sh: tools/vmware-sandbox/sandbox.sh
  - vmrun wrapper (Go): tools/vmware-sandbox/vmrun-wrapper（タイムアウト付きvmrunラッパー）
  - network isolator (Python): tools/vmware-sandbox/net_isolate.py（ネットワーク切替）
  - memdump-racer (Go): tools/vmware-sandbox/memdump-racer（ゲスト内メモリダンプレーサー）
  - tiny-unpack (Go): tools/vmware-sandbox/tiny-unpack（TinyTracerベース自動アンパッカー）
  - fakenet_validate.py: tools/vmware-sandbox/fakenet_validate.py（FakeNet設定バリデータ）
  - build_http_response.py: tools/vmware-sandbox/build_http_response.py（HTTPレスポンスビルダー）

  ============================================================
  エラー防止ルール（重要）
  ============================================================

  認証:
  - vmrunの -gu / -gp は必ず.envから取得（VM_GUEST_USER / VM_GUEST_PASS）
  - 手動でvmrunを叩く場合も .envの値を使うこと（PIN 1127エラー等の原因になる）
  - sandbox.sh経由であれば自動的に.envを読み込む

  管理者権限:
  - ゲスト内でStop-Service, Set-Service等のサービス操作はAdmin権限が必要
  - vmrun runProgramInGuest は「ログオンユーザー権限」で実行される
  - Admin操作が必要な場合は事前にGUI上でUAC昇格するか、管理者シェルで実行

  ツール名（正確に）:
  - pe-sieve64.exe（pe-sieve.exeではない）
  - hollows_hunter64.exe
  - memdump-racer.exe

  PE-sieveオプション一覧（よく使うもの）:
  - /pid <PID>       対象PID（必須）
  - /dmode 3         dump mode: PE + unpacked（推奨。/dmode 4は存在しない）
  - /imp 3           import reconstruction: aggressive
  - /shellc 3        shellcode detection: aggressive（値なしの /shellc はエラー）
  - /dir <path>      出力ディレクトリ
  - /minidmp         MiniDump取得
  値が必要なオプションに値を付けずに使うとエラーになる

  PID取得:
  - PowerShell経由でGet-Processすると「PowerShell自身のPID」が返る場合がある
  - 正確なPID取得には CreateProcessW で直接プロセスを起動するのが最善
  - memdump-racer はこの問題を回避するために作成された

  ユーザー名/パス名によるVM検知（既知の制約）:
  - ゲストユーザー名が "malware" 等の部分一致パターンで検知される可能性
  - パス "C:\Users\<user>\Desktop\analysis" が検知される可能性
  - 対策: 解析ディレクトリを C:\work や C:\temp 等に変更する手もあるが、環境次第で許容

  VMware Tools操作の禁止事項:
  - VMware Toolsのサービスを停止・レジストリ改名してはならない
  - VMware Tools停止後はvmrun通信が不可能になり、VM制御を完全に失う
  - 一度失うと「vmrun stop」もハングし、force-stopでvmware-vmx.exeをkillするしかなくなる

  ============================================================
  基本操作
  ============================================================

  VM管理:
  bash tools/vmware-sandbox/sandbox.sh start              # VM起動（nogui）
  bash tools/vmware-sandbox/sandbox.sh stop               # VM停止
  bash tools/vmware-sandbox/sandbox.sh force-stop          # VMXプロセスkill（vmrun stop失敗時）
  bash tools/vmware-sandbox/sandbox.sh status              # 状態確認・IP表示
  bash tools/vmware-sandbox/sandbox.sh revert [snapshot]   # スナップショット復帰（default: .envのVM_SNAPSHOT）
  bash tools/vmware-sandbox/sandbox.sh snapshot [name]     # スナップショット作成

  ネットワーク管理:
  bash tools/vmware-sandbox/sandbox.sh net-isolate         # Host-Only（マルウェア解析時はこれ必須）
  bash tools/vmware-sandbox/sandbox.sh net-nat             # NAT（C2通信キャプチャ時のみ）
  bash tools/vmware-sandbox/sandbox.sh net-disconnect      # 完全切断
  bash tools/vmware-sandbox/sandbox.sh net-status          # 現在のネットワーク設定表示

  ファイル転送:
  bash tools/vmware-sandbox/sandbox.sh copy-to <local_file> [guest_path]   # ホスト→ゲスト
  bash tools/vmware-sandbox/sandbox.sh copy-from <guest_path> [local_path] # ゲスト→ホスト

  ゲスト操作:
  bash tools/vmware-sandbox/sandbox.sh exec <program> [args]        # プログラム実行
  bash tools/vmware-sandbox/sandbox.sh ps <powershell_command>       # PowerShell実行（出力なし）
  bash tools/vmware-sandbox/sandbox.sh guest-cmd [--timeout N] <ps_cmd> [outfile]  # PowerShell実行＋出力回収
  bash tools/vmware-sandbox/sandbox.sh run-script <script.ps1> [timeout=60]  # PS1をVMにコピー→実行→ログ回収
  bash tools/vmware-sandbox/sandbox.sh set-clock <YYYY-MM-DD HH:MM:SS>      # 時刻同期無効化＋時刻設定
  bash tools/vmware-sandbox/sandbox.sh processes                     # プロセス一覧
  bash tools/vmware-sandbox/sandbox.sh screenshot [output_path]      # スクリーンショット
  bash tools/vmware-sandbox/sandbox.sh ip                            # ゲストIP取得

  ツール管理:
  bash tools/vmware-sandbox/sandbox.sh guest-tools         # ゲスト内ツール存在確認
  bash tools/vmware-sandbox/sandbox.sh memdump <target> [delays] [outdir]  # メモリダンプレース実行

  Frida DBI解析:
  bash tools/vmware-sandbox/sandbox.sh frida-analyze <binary> [wait_sec=60]
    Frida spawnerモードでマルウェアを起動し、Sleep無効化・Anti-Debug回避・メモリダンプを自動実行

  アンパック（3-Level Unpacking System）:
  bash tools/vmware-sandbox/sandbox.sh unpack <binary> [level]
    level: 1=memdump-racer, 2=TinyTracer, 3=manual x64dbg, auto=自動エスカレーション（default）

  ============================================================
  vmrunコマンド実行時の注意（重要）
  ============================================================

  vmrunのハング防止ルール:
  1. runProgramInGuest はスナップショット復帰後にハングすることがある
     → runScriptInGuest の方が安定（vmrun_script()ヘルパー使用推奨）
  2. cmd.exe /c でリダイレクト(>)を使わない → ハングする
  3. PowerShell実行時は -NoProfile -NonInteractive を必ず付ける
  4. 長時間かかる可能性があるコマンドはBashのtimeoutを設定（30秒推奨）
  5. getGuestIPAddress では -wait を付けずタイムアウトで制御する

  安全なコマンド実行パターン:
  # OK: vmrun_script()でrunScriptInGuest（最も安定）
  vmrun_script 60 "powershell.exe -NoProfile -NonInteractive -Command '...'"

  # OK: PowerShellでファイル出力 → copyFromGuestでホストに回収
  vmrun runProgramInGuest ... powershell.exe -NoProfile -NonInteractive -Command "..."
  vmrun copyFileFromGuestToHost ...

  # NG: cmd.exeでリダイレクト（ハングする）
  vmrun runProgramInGuest ... cmd.exe /c "dir > file.txt"
---

## ネットワーク安全管理（最重要）

### 原則: マルウェア実行前にネットワークを隔離する

マルウェアがNAT経由でインターネットに接続すると:
- C2サーバーと通信し追加ペイロードをダウンロード
- ホストOSのNATインターフェース経由でLAN内に攻撃が波及する可能性
- マルウェアがVM検知してホストを標的にする可能性（VMエスケープ）

### ネットワークモード一覧

| モード | 用途 | ホストへの影響 | 安全度 |
|--------|------|----------------|--------|
| **Host-Only** | 通常のマルウェア解析（推奨） | なし | 高 |
| **Disconnected** | 完全隔離解析 | なし | 最高 |
| **NAT** | C2通信キャプチャ（要注意） | あり | 低 |

### 解析フロー（ネットワーク安全手順込み）

```bash
# 1. スナップショット復帰
bash tools/vmware-sandbox/sandbox.sh revert

# 2. ネットワーク隔離（必須）
bash tools/vmware-sandbox/sandbox.sh net-isolate

# 3. ネットワーク状態確認
bash tools/vmware-sandbox/sandbox.sh net-status

# 4. マルウェアコピー＆実行
bash tools/vmware-sandbox/sandbox.sh copy-to /path/to/malware.exe
bash tools/vmware-sandbox/sandbox.sh exec "C:\Users\malwa\Desktop\analysis\malware.exe"

# 5. 解析結果収集
bash tools/vmware-sandbox/sandbox.sh processes
bash tools/vmware-sandbox/sandbox.sh screenshot

# 6. クリーンアップ
bash tools/vmware-sandbox/sandbox.sh revert
```

### C2通信キャプチャが必要な場合のみ（ユーザー確認必須）

```bash
# ユーザーに「NATモードで実行しますか？ホストネットワークに影響する可能性があります」と確認
bash tools/vmware-sandbox/sandbox.sh net-nat
```

## 自動解析ワークフロー

### ワンコマンド解析（推奨）
```bash
bash tools/vmware-sandbox/sandbox.sh analyze <binary_path> [wait_seconds=60]
```

自動実行フロー:
1. クリーンスナップショットに復帰
2. **ネットワークをHost-Onlyに切替（自動）**
3. ゲストに解析ディレクトリ作成
4. マルウェアをゲストにコピー
5. 実行前スクリーンショット＋プロセスリスト取得
6. マルウェア実行
7. 指定秒数待機（デフォルト60秒）
8. 実行後スクリーンショット＋プロセスリスト取得
9. HollowsHunter実行（自動）
10. プロセスdiff生成
11. クリーンスナップショットに復帰

結果出力先: `tools/vmware-sandbox/output/<binary名>_<timestamp>/`

## 手動解析手順

### Step 1: 環境準備
```bash
# クリーンスナップショットから開始（毎回必ず）
bash tools/vmware-sandbox/sandbox.sh revert

# ネットワーク隔離（必須）
bash tools/vmware-sandbox/sandbox.sh net-isolate

# マルウェアをゲストにコピー
bash tools/vmware-sandbox/sandbox.sh copy-to /path/to/malware.exe
```

### Step 1.5: 初期トリアージ（ゲスト内）
```bash
# Detect It Easy でパッカー/コンパイラ判定（GUIが起動する）
bash tools/vmware-sandbox/sandbox.sh exec "C:\Users\malwa\Desktop\tools\die\die.exe" "C:\Users\malwa\Desktop\analysis\malware.exe"

# pestudio でPE構造を詳細確認（GUIが起動する）
bash tools/vmware-sandbox/sandbox.sh exec "C:\Users\malwa\Desktop\tools\pestudio\pestudio\pestudio.exe" "C:\Users\malwa\Desktop\analysis\malware.exe"

# .NETマルウェアの場合: dnSpy でデコンパイル
bash tools/vmware-sandbox/sandbox.sh exec "C:\Users\malwa\Desktop\tools\dnSpy\dnSpy.exe" "C:\Users\malwa\Desktop\analysis\malware.exe"
```

### Step 2: 解析ツール起動（ゲスト内）
```bash
# FakeNet-NG でネットワークシミュレーション開始（管理者権限推奨）
# DNS/HTTP/SMTP等の偽応答を返し、C2通信パターンを安全にキャプチャ
bash tools/vmware-sandbox/sandbox.sh exec "C:\Users\malwa\Desktop\tools\fakenet\fakenet3.5\fakenet.exe"

# ProcMonで挙動監視開始
bash tools/vmware-sandbox/sandbox.sh exec "C:\Users\malwa\Desktop\tools\procmon\Procmon.exe" /AcceptEula /Backingfile C:\Users\malwa\Desktop\analysis\procmon.pml

# x64dbg起動（64bitバイナリの場合）
bash tools/vmware-sandbox/sandbox.sh exec "C:\Users\malwa\Desktop\tools\x64dbg\release\x64\x64dbg.exe"
```

### Step 3: マルウェア実行
```bash
bash tools/vmware-sandbox/sandbox.sh exec "C:\Users\malwa\Desktop\analysis\malware.exe"
```

### Step 4: 挙動収集
```bash
# プロセス一覧
bash tools/vmware-sandbox/sandbox.sh processes

# スクリーンショット
bash tools/vmware-sandbox/sandbox.sh screenshot

# PE-sieveでインジェクション検出（64bit）
bash tools/vmware-sandbox/sandbox.sh exec "C:\Users\malwa\Desktop\tools\pe-sieve64.exe" /pid <PID>

# HollowsHunterで全プロセススキャン（64bit）
bash tools/vmware-sandbox/sandbox.sh exec "C:\Users\malwa\Desktop\tools\hollows_hunter64.exe"
```

### Step 4.5: 追加解析ツール
```bash
# HxD でダンプファイルやメモリダンプをバイナリレベルで確認
bash tools/vmware-sandbox/sandbox.sh exec "C:\Users\malwa\Desktop\tools\hxd\app\HxD.exe" "C:\Users\malwa\Desktop\analysis\dump.bin"

# YARA でシグネチャスキャン（ルールファイルをゲストにコピー後）
bash tools/vmware-sandbox/sandbox.sh exec "C:\Users\malwa\Desktop\tools\yara\yara64.exe" "C:\Users\malwa\Desktop\analysis\rules.yar" "C:\Users\malwa\Desktop\analysis\malware.exe"

# CyberChef でエンコードされたペイロードをデコード（ブラウザで開く）
bash tools/vmware-sandbox/sandbox.sh exec "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" "C:\Users\malwa\Desktop\tools\cyberchef\CyberChef_v10.22.1.html"
```

### Step 5: 結果回収
```bash
# ゲストから結果ファイルを回収
bash tools/vmware-sandbox/sandbox.sh copy-from "C:\Users\malwa\Desktop\analysis\procmon.pml"
```

### Step 6: クリーンアップ
```bash
bash tools/vmware-sandbox/sandbox.sh revert
```

## VMProtect/パック済みバイナリの解析手順

Ghidra Headless（静的解析）で以下の特徴が検出された場合、動的解析に切り替え:
- セクション名が非標準（`.uBq`, `.J)t`等）
- インポートテーブルが空（0個）
- VMPセクションがバイナリの90%以上
- エントリーポイントがVMPセクション内

### 推奨アプローチ
1. **Detect It Easy (DiE)**: 高速トリアージ（パッカー/コンパイラ/リンカー即座に判定）
2. **pestudio**: PE構造の詳細確認（インポート/リソース/エントロピー/VirusTotal連携）
3. **Ghidra**: 初期トリアージ（PE metadata、セクション構造、デコンパイル）
4. **VMware Sandbox**: x64dbgでOEPまで実行→メモリダンプ→PE-sieveでアンパック
5. **Ghidra**: アンパック後バイナリを再解析（デコンパイル可能に）

### x64dbgアンパック手順
```bash
# 1. x64dbgにマルウェアをロード（64bitバイナリの場合はx64を使用）
bash tools/vmware-sandbox/sandbox.sh exec "C:\Users\malwa\Desktop\tools\x64dbg\release\x64\x64dbg.exe" "C:\Users\malwa\Desktop\analysis\packed.exe"

# 2. OEP（Original Entry Point）でブレーク後、Scyllaでダンプ
#    → 手動操作が必要な場合はVMwareのGUI表示に切り替え

# 3. ダンプファイルを回収
bash tools/vmware-sandbox/sandbox.sh copy-from "C:\Users\malwa\Desktop\analysis\packed_dump.exe"

# 4. Ghidraで再解析
bash tools/ghidra-headless/ghidra.sh analyze tools/vmware-sandbox/output/packed_dump.exe
```

## ゲスト内解析ツール

ツールパスのベース: `C:\Users\malwa\Desktop\tools\`

| ツール | パス | 用途 |
|--------|------|------|
| x64dbg (32bit) | tools\x64dbg\release\x32\x32dbg.exe | デバッガ（アンパック、APIトレース） |
| x64dbg (64bit) | tools\x64dbg\release\x64\x64dbg.exe | 64bitバイナリ用デバッガ |
| PE-sieve (64bit) | tools\pe-sieve64.exe | プロセスインジェクション検出 |
| HollowsHunter (64bit) | tools\hollows_hunter64.exe | 全プロセスメモリスキャン |
| memdump-racer | tools\memdump-racer.exe | メモリダンプレース（CreateProcessW直接起動） |
| tiny-unpack | tools\tiny-unpack.exe | TinyTracerベース自動アンパッカー（2パスOEP検出） |
| TinyTracer | C:\pin\source\tools\TinyTracer\install\TinyTracer64.dll | Intel PINベーストレーサー（要Intel PIN） |
| API Monitor (32bit) | tools\apimonitor\API Monitor (rohitab.com)\apimonitor-x86.exe | API呼び出しトレース |
| API Monitor (64bit) | tools\apimonitor\API Monitor (rohitab.com)\apimonitor-x64.exe | API呼び出しトレース |
| Process Monitor | tools\procmon\Procmon.exe | ファイル/レジストリ/ネットワーク監視 |
| Frida 17.7.3 | pip install済み（Python 3.10） | DBI（Dynamic Binary Instrumentation）。APIフック・メモリダンプ |
| FakeNet-NG 3.5 | tools\fakenet\fakenet3.5\fakenet.exe | ネットワークシミュレーション（DNS/HTTP/SMTP偽装応答） |
| Detect It Easy 3.10 | tools\die\die.exe | パッカー/コンパイラ/リンカー自動判定 |
| dnSpy 6.5.1 | tools\dnSpy\dnSpy.exe | .NETデコンパイラ（IL/C#/VB.NET） |
| pestudio 9.61 | tools\pestudio\pestudio\pestudio.exe | PE静的解析（インポート/リソース/VirusTotal連携） |
| CyberChef 10.22.1 | tools\cyberchef\CyberChef_v10.22.1.html | エンコード/デコード/暗号化変換（ブラウザで開く） |
| HxD 2.5.0.0 | tools\hxd\app\HxD.exe | ヘックスエディタ（バイナリ手動パッチ/ダンプ確認） |
| YARA 4.5.5 | tools\yara\yara64.exe / yarac64.exe | パターンマッチングルールエンジン |

スナップショット:
- `clean_with_tools`: 全ツールインストール済み（解析開始のベース・唯一のスナップショット）

## 入出力ディレクトリ

| ディレクトリ | 用途 |
|-------------|------|
| tools/vmware-sandbox/input/ | 解析対象バイナリの配置 |
| tools/vmware-sandbox/output/ | 解析結果の出力先 |
| tools/vmware-sandbox/logs/ | 解析ログ |

## コマンドログ（必須）

解析実行時はログを記録:
```
tools/vmware-sandbox/logs/YYYYMMDD_<target_name>.md
```

ログ形式:
```markdown
# Dynamic Analysis: <target_name>
Date: YYYY-MM-DD

## Target
- File: <filename>
- SHA256: <hash>
- Size: <size>
- Packer: <VMProtect/UPX/None/Unknown>

## Environment
- Snapshot: clean_with_tools
- Network: Host-Only / NAT / Disconnected
- Wait time: <seconds>

## Pre-Execution
- Processes: <count>
- Screenshot: pre_execution.png

## Execution & Observations
- New processes: <list>
- File system changes: <notable changes>
- Registry changes: <notable changes>
- Network activity: <connections>

## Post-Execution
- Processes: <count>
- Screenshot: post_execution.png
- PE-sieve findings: <injections detected>
- HollowsHunter findings: <summary>

## Key Findings
- <finding 1>
- <finding 2>

## IOCs
- <IOC 1>
- <IOC 2>
```

## 3-Level Unpacking System

パックされたマルウェアの自動アンパックを3段階で実行するシステム。

### アーキテクチャ
```
sandbox.sh unpack <binary> [level]
  ├── Level 1: memdump-racer (タイミングベース)
  │     CreateProcessW → delay → pe-sieve + MiniDump → quality判定
  ├── Level 2: tiny-unpack (TinyTracerベース)
  │     TinyTracer Pass1(トレース) → OEP検出 → Pass2(停止) → HollowsHunter dump
  ├── Level 3: x64dbg (手動、手順表示のみ)
  └── auto: L1 → 品質チェック → L2 → 品質チェック → L3手順表示
```

### 使い方
```bash
# 自動エスカレーション（推奨）
bash tools/vmware-sandbox/sandbox.sh unpack /path/to/packed.exe

# レベル指定
bash tools/vmware-sandbox/sandbox.sh unpack /path/to/packed.exe 1   # memdump-racer
bash tools/vmware-sandbox/sandbox.sh unpack /path/to/packed.exe 2   # TinyTracer
bash tools/vmware-sandbox/sandbox.sh unpack /path/to/packed.exe 3   # 手動手順表示
```

### 各レベル詳細

**Level 1: memdump-racer**
- 最速（約2分）。VMProtectの300msアンパックウィンドウを狙い撃ち
- pe-sieve64でメモリスキャン＋MiniDump取得
- 品質判定: ダンプPEのインポート数 > 5 で GOOD
- タイムアウト: 120秒

**Level 2: tiny-unpack (TinyTracer)**
- より精度が高い。OEP（Original Entry Point）を自動検出
- Pass 1: TinyTracerでトレース → .tagファイルからセクション遷移パターン検出
- Pass 2: 検出したOEPで停止 → HollowsHunterでダンプ
- 品質判定: 同上（インポート数 > 5）
- タイムアウト: 300秒
- 前提条件: ゲストにIntel PIN 3.31+ / TinyTracer / bcdedit /debug off

**Level 3: x64dbg (手動)**
- L1/L2で失敗した場合のフォールバック
- x64dbg + Scyllaプラグインでの手動ダンプ手順を表示

### auto-escalation
`auto`（デフォルト）では:
1. Level 1 実行 → quality.txt が GOOD なら完了 → Ghidra解析
2. POOR なら Level 2 実行 → quality.txt が GOOD なら完了 → Ghidra解析
3. POOR なら Level 3 の手動手順を表示

### 出力ファイル
各レベルの出力:
- `quality.txt` — GOOD / POOR
- `manifest.txt` — ダンプされた全ファイルのフルパス一覧
- `log.txt` — 全操作ログ
- ダンプされたPEファイル群

### TinyTracerセットアップ前提条件
Level 2を使用するには、ゲストVMに以下のセットアップが必要:
1. Intel PIN 3.31+ を `C:\pin` にインストール
2. TinyTracer をコンパイルし `C:\pin\source\tools\TinyTracer\install\` に配置
3. `bcdedit /debug off` を実行して再起動（カーネルデバッグ無効化）
4. setup_tinytracer.ps1 を実行: `powershell -ExecutionPolicy Bypass -File setup_tinytracer.ps1`
5. hollows_hunter64.exe がtools内に存在すること

## メモリダンプレース手法（VMProtectアンパック）

VMProtectはプロセス起動後のごく短い時間（約300ms以内）にOEPへのジャンプを完了する。
このウィンドウ内でメモリをダンプすれば、アンパック済みコードを取得できる。

### 手法
1. CreateProcessWで対象バイナリを直接起動（PID誤取得を防ぐため）
2. 指定ディレイ後にpe-sieve64.exeでプロセスメモリをスキャン＆ダンプ
3. 同時にMiniDumpWriteDumpでフルメモリダンプも取得
4. 複数ディレイ（0ms, 100ms, 200ms, 300ms, 500ms）で繰り返しベストを選択

### 成功パターン
- ディレイ200-300ms → pe-sieveがアンパック済みPEを検出（/dmode 3 /imp 3 /shellc 3）
- 出力: `<PID>/140000000.<binary_name>` がアンパック済み本体

### 失敗パターン
- ディレイ0ms → まだアンパックが始まっていない（VMPコードのまま）
- ディレイ500ms以上 → プロセスが既にVM検知で終了している場合がある
- PowerShell経由のPID → PowerShell自身のPIDを取得してしまう

### sandbox.shからの実行
```bash
bash tools/vmware-sandbox/sandbox.sh memdump <target_on_guest> ["0,100,200,300,500"] [outdir]
```

## install.exeで確認されたVM検知手法

install.exe（VMProtect 3.x）が使用するVM検知手法の完全リスト:

| カテゴリ | 検知手法 | 詳細 |
|----------|---------|------|
| SMBIOS | DMIテーブル読取 | "VMware"文字列をBIOS情報から検出 |
| CPUID | CPUID命令 | Hypervisor bit (ECX bit 31)、VMwareシグネチャ |
| MACアドレス | NICベンダープレフィクス | 00:0C:29, 00:50:56 (VMware OUI) |
| プロセス | プロセス名チェック | vmtoolsd.exe, vmwaretray.exe, vmwareuser.exe |
| レジストリ | サービスキー | HKLM\SYSTEM\...\VMware Tools, VMware Physical Disk Helper |
| ドライバ | カーネルドライバ | vmci.sys, vsock.sys, vmhgfs.sys, vmmouse.sys |
| デバイス | デバイス名 | \\.\VMwareVMDeviceDrv, VMware SVGA 3D |
| ユーザー名 | パターンマッチ | "malware"部分一致で検知の可能性 |
| パス名 | ディレクトリ名 | "analysis"、"sandbox"等のキーワード |
| HW仕様 | ディスクサイズ/RAM | 小さすぎるディスク(<80GB)やRAM(<4GB)でVM判定 |

## トラブルシューティング

### vmrunコマンドがハングする
- **原因**: runScriptInGuest、cmd.exeリダイレクト、getGuestIPAddress -wait が無限待機
- **対策**: vmrun-wrapperを使用（タイムアウト付き）、またはBashのtimeoutコマンドで制御
- **回避パターン**: PowerShell -NoProfile -NonInteractive でコマンド実行
- **修正済み（2026-02-24）**: sandbox.shの全ゲスト操作コマンド（runProgramInGuest, copyFile*, createDirectory*）をvmrun_t（タイムアウト付き）に統一。cmd_exec()を含む24箇所を修正

### log出力でWindowsパスが破損する
- **原因**: `echo -e`がパス中の`\t`(タブ)、`\a`(ベル)等をエスケープシーケンスとして解釈
- **例**: `C:\Users\malwa\Desktop\analysis\target.exe` → `\t`がタブ、`\a`がベルに変換されログが崩壊
- **修正済み（2026-02-24）**: log()/warn()/err()を`printf '%b %s\n'`に変更。`%b`でANSIカラーのみ解釈し、`%s`でメッセージをリテラル出力

### vmrun stopがハングする
- **原因**: VMware Toolsが停止している（サービス停止、レジストリ改名等でvmrun通信不可）
- **対策**: `bash tools/vmware-sandbox/sandbox.sh force-stop` でvmware-vmx.exeプロセスを直接kill
- **回復**: force-stop後に `sandbox.sh revert` でクリーン状態に復帰

### VMware Tools復旧不可（アンチパターン）
- **やってはいけないこと**: ゲスト内でVMware Toolsサービスの停止やレジストリキー改名
- **結果**: vmrun経由の全操作（stop, exec, copy等）が不可能になる
- **唯一の復旧方法**: force-stop → スナップショット復帰
- **VM検知回避でVMware Toolsを無効化するのは絶対にNG**

### ゲストのユーザーフォルダ名が不明
- **原因**: MSアカウントだとフォルダ名が短縮される
- **対策**: .envの`VM_GUEST_PROFILE`に正しいパスを設定済み
- **確認方法**: VMのGUIでエクスプローラーから C:\Users\ を確認

### PowerShell出力がUTF-16になる
- **対策**: `-Command "... | Out-File -Encoding UTF8 file.txt"` でUTF-8指定

### ネットワーク設定変更後にVMが通信できない
- **原因**: VMを再起動しないとネットワーク設定が反映されない場合がある
- **対策**: net_isolate.py は必要に応じてVMをsuspend/resumeする

### runProgramInGuestがスナップショット復帰後にハングする（2026-02-25発見）
- **問題**: `vmrun revert` → `vmrun start` 後に `runProgramInGuest` がタイムアウト
- **原因**: スナップショット復帰後のVMware Toolsの初期化タイミング問題
- **解決**: `runScriptInGuest` を使用（`vmrun_script()` ヘルパー関数）
- **対策済み**: sandbox.shに `vmrun_script()` 関数を追加。frida-analyzeコマンドはこちらを使用

### Frida Module.findExportByName が未定義（2026-02-25発見）
- **問題**: Frida 17.7.3で `Module.findExportByName(dll, func)` が "TypeError: not a function"
- **原因**: Frida 17.xで`Module`のAPIが変更。`Module`は関数型で、`getGlobalExportByName`のみ持つ
- **解決**: `Process.getModuleByName(dll).getExportByName(func)` を使用
- **影響**: bypass_vmdetect.js, dump_payload.js の全フックが動作しなくなる

### Frida x64でstdcall ABIエラー（2026-02-25発見）
- **問題**: `NativeFunction(addr, 'int', ['pointer'], { abi: 'stdcall' })` → "invalid abi specified"
- **原因**: x64 Windowsではstdcallは存在しない（win64 calling conventionのみ）
- **解決**: `{ abi: 'stdcall' }` を削除（デフォルトのwin64 ABIが使われる）

### Frida Interceptor.replaceでプロセスクラッシュ（2026-02-25発見）
- **問題**: `Interceptor.replace` で Process32FirstW/NextW を差し替えるとプロセスが即座に終了
- **原因**: x64でのreplace実装が不安定。特にPEB/TEB参照する関数で問題が起きやすい
- **解決**: `Interceptor.attach`（監視のみ）に変更。replaceは使わない

### Frida重量フックでプロセスデッドロック（2026-02-25発見）
- **問題**: RegOpenKeyExW, CreateFileW, NtQuerySystemInformationにフック → プロセスがハング
- **原因**: DLL初期化中にこれらのAPIが数千回呼ばれ、Fridaのインターセプタがボトルネック
- **解決**: 重量APIフックを全て削除。Sleep, IsDebuggerPresent, VirtualProtect等の軽量フックのみ使用
- **教訓**: Fridaフックはプロセス初期化パス上の高頻度APIには使えない

### vmrunのゾンビプロセスがVM操作をブロック（2026-02-25発見）
- **問題**: 複数のvmrun.exeプロセスが残留し、後続のvmrunコマンドが全てタイムアウト
- **原因**: タイムアウトでvmrunがkillされた後もプロセスが残り、VMXファイルのロックを保持
- **症状**: `vmrun list` = "0 running VMs" だが `revert`/`start` がハング。`.lck`ファイルが残存
- **解決手順**:
  1. `taskkill //F //IM vmrun.exe` — 全vmrunプロセスをkill
  2. `.lck`ディレクトリを削除 — `rm -rf "<VM_DIR>/"*.lck`
  3. VMware GUI（vmware.exe）が開いている場合は閉じる
  4. 再度 `vmrun revertToSnapshot` → `vmrun start`
- **予防**: vmrunの`timeout`を十分大きく設定（60s推奨）。小さすぎるタイムアウトでプロセスが中途半端に終了すると残留する

### Frida wheelのfor loop コピーが失敗する（2026-02-25発見）
- **問題**: Bash for loopでバックスラッシュWindowsパスを含む変数展開 → "ファイルが見つかりません"
- **原因**: MSYS/Git Bashのパス変換とvmrun引数のエスケープが競合
- **解決**: 各ファイルを個別のコマンドで明示的にコピー（ループ変数を使わない）

## ゲストコマンド出力の取得パターン

### guest-cmdヘルパー（推奨）
```bash
# PowerShellコマンドを実行し、結果をホストに回収してそのまま表示
bash tools/vmware-sandbox/sandbox.sh guest-cmd 'Get-Process | Select Name,Id'

# 結果をファイルに保存
bash tools/vmware-sandbox/sandbox.sh guest-cmd 'Get-NetTCPConnection' output/connections.txt
```

内部処理: PowerShell Out-File → copyFileFromGuestToHost → 表示/保存

### 手動パターン（guest-cmdで対応できない場合）
```bash
# 1. ゲスト内でPowerShellを実行し、結果をファイルに出力
bash tools/vmware-sandbox/sandbox.sh ps "Get-Process | Out-File -Encoding UTF8 C:\Users\malwa\Desktop\analysis\result.txt"

# 2. ファイルをホストに回収
bash tools/vmware-sandbox/sandbox.sh copy-from "C:\Users\malwa\Desktop\analysis\result.txt"
```

## DDoSボットネット解析ナレッジ（run.exe / 2026-02-24）

### 攻撃チェーン
1. **UPXドロッパー** (install.exe) → 展開 → `run.exe` をドロップ＆実行
2. **run.exe**: Go製C2ボット（DDoSボットネットクライアント）
3. C2サーバーから攻撃指令を受信 → SYN Flood / UDP Flood / HTTP Flood 等を実行

### Go製C2ボットの特徴
- **コンパイラ**: Go (GCC-Go or gc)。Ghidraでは`go.`プレフィクスの関数名で識別
- **関数名のmiddle dot**: Go内部パッケージパスに `·` (U+00B7, middle dot) を使用 → Jython/Python2で`UnicodeEncodeError`を起こす
- **インポートの特殊性**: Goバイナリは通常のPEインポートテーブルが最小限。syscall経由で直接呼び出すため、imports解析だけでは不十分
- **RTTI/型情報**: Goランタイムの型情報（`runtime.typestring`等）から構造体名やメソッド名を復元可能
- **大量の関数**: Goランタイム＋標準ライブラリが静的リンクされるため、関数数が5000+になることが多い
- **strings解析が有効**: C2アドレス、攻撃メソッド名、エラーメッセージ等がリテラル文字列として残りやすい

### 解析時の注意点
- Ghidra静的解析ではGoバイナリの関数名復元が不完全 → `list_functions.py`の結果でGoパッケージ構造を推測
- `strings`解析でC2 URL、攻撃メソッド名（syn, udp, http等）、設定値を探す
- 動的解析ではネットワーク通信をキャプチャしてC2プロトコルを特定（Host-Onlyモードではブロックされるため、必要に応じてNAT）

## ネットワークフォレンジック連携ナレッジ

### FakeNet-NG活用ガイド（Host-Onlyモード推奨）

FakeNet-NGはHost-Onlyモードで動作し、マルウェアのネットワーク通信に偽応答を返す:
- **DNS**: 全ドメインをlocalhost（127.0.0.1）に解決 → マルウェアが問い合わせるC2ドメインを特定
- **HTTP/HTTPS**: 偽のHTTPレスポンスを返す → C2のURIパス、User-Agent、POSTデータをキャプチャ
- **SMTP**: メール送信を受け取る → 情報窃取のexfiltrationパターンを確認
- **ログ**: fakenet.log にすべての通信が記録される

```bash
# FakeNet-NG起動（マルウェア実行前に起動しておく）
bash tools/vmware-sandbox/sandbox.sh exec "C:\Users\malwa\Desktop\tools\fakenet\fakenet3.5\fakenet.exe"

# マルウェア実行後、ログを回収
bash tools/vmware-sandbox/sandbox.sh copy-from "C:\Users\malwa\Desktop\tools\fakenet\fakenet3.5\fakenet.log"
```

NATモードを使わずにC2通信パターンを安全に取得できるため、FakeNet-NGの利用を最優先で検討すること。

### FakeNet-NG詳細運用ガイド

#### 事前チェック手順
マルウェア実行前に必ず以下を実行:
```bash
bash tools/vmware-sandbox/sandbox.sh fakenet-validate
# または個別チェック:
python tools/vmware-sandbox/fakenet_validate.py check-ca input/fakenet_ca.crt
python tools/vmware-sandbox/fakenet_validate.py check-config input/custom_responses.ini
```

#### CA証明書管理
- FakeNet-NGのHTTPS応答にはCA証明書が必要
- 証明書が期限切れだとTLSハンドシェイクが失敗し、マルウェアのHTTPS通信がキャプチャできない
- 有効期限確認: `fakenet_validate.py check-ca <cert>`
- 再生成手順:
  ```bash
  openssl req -x509 -newkey rsa:2048 -keyout fakenet_ca.key -out fakenet_ca.crt \
    -days 3650 -nodes -subj "/CN=FakeNet CA"
  openssl x509 -in fakenet_ca.crt -outform DER -out fakenet_ca.der
  ```
- VM時刻を過去に巻き戻した場合、証明書の「Not Before」より前になるとエラーになるので注意
- VM内でCA証明書をインストール: `setup_ca.ps1` で信頼されたルート証明機関に追加

#### custom_responses.ini 設定ルール
1. **InstanceName必須**: `HTTPListener80` (HTTP) または `HTTPListener443` (HTTPS)
2. **HttpRawFile配置先**: custom_responses.iniと同じディレクトリ（FakeNet/fakenet3.5/直下）
3. **マッチ優先順**: INIファイル上で先に書いたルールが優先
4. **レスポンスタイプは排他**: HttpStaticString / HttpRawFile / HttpStaticFile のうち1つだけ
5. **テンプレート参照**: `input/templates/custom_responses_template.ini`

#### Raw HTTPレスポンスファイル作成ルール
- 全行が `\r\n` (CRLF) 終端でなければならない（LFのみだとFakeNetがパースに失敗）
- ヘッダとボディの間に `\r\n\r\n` (空行) が必要
- `build_http_response.py` を使って生成するのが最も安全:
  ```bash
  python tools/vmware-sandbox/build_http_response.py --template vidar-config --output resp.txt --validate
  ```
- 手動作成した場合は必ず検証: `fakenet_validate.py check-response <file>`

#### HTTPS応答が必要な検体の対応フロー
1. CA証明書の有効期限確認
2. VM内にCA証明書をインストール（信頼されたルートCA）
3. custom_responses.iniで `InstanceName: HTTPListener443` を指定
4. FakeNet起動 → マルウェア実行
5. fakenet.log でHTTPS通信のキャプチャを確認

### Lumma Stealer動的解析時の注意点
- HTTP平文C2（`/api/set_agent`）なので、Host-OnlyモードでもFakeNetで応答をキャプチャ可能
- NATモードなら実C2通信をWiresharkでキャプチャ可能だが、C2から追加ペイロードがダウンロードされるリスクあり
- ブラウザフィンガープリント収集型のため、Chrome/Edgeのプロファイルデータが窃取対象

### Cloudflare ECH使用マルウェア
- Encrypted Client Hello（ECH）使用時、TLS SNIが`cloudflare-ech.com`に置換される
- pcapからは実際の接続先ドメインが見えない
- 動的解析で実ドメインを特定するには、DNS over HTTPS（DoH）ではなく平文DNSクエリのキャプチャが必要
- FakeNet-NGやINetSimで強制的にDNS応答を返すことで、マルウェアが問い合わせるドメインを特定可能

### ブラウザフィンガープリント型Stealer
- Chrome/Edge両方からWebGL・Canvas・Fonts・Screen・Audio・Network情報を収集
- VM環境ではGPU情報がVM固有のもの（VMware SVGA 3D等）になるため検知される可能性あり
- 対策: VM内でGPUパススルーを設定するか、検知を許容して挙動パターンの収集に集中

### ネットワークフォレンジックとの連携フロー
1. **pcap分析**（network-forensicsスキル）でC2パターンを特定
2. **動的解析**（vmware-sandbox）でマルウェアを実行し通信を再現
3. **通信パターンの照合**: pcapで観測されたC2通信と動的解析結果を比較
4. **IOC抽出**: 確認されたC2ドメイン/IP/URI/User-Agentをリスト化

## Frida DBI解析（Phase 2）

Frida（Dynamic Binary Instrumentation）を使ったマルウェア動的解析。
Sleep bombing無効化、Anti-Debug回避、VirtualProtect/VirtualAllocのメモリダンプを自動実行。

### ワンコマンド実行
```bash
bash tools/vmware-sandbox/sandbox.sh frida-analyze <binary_path> [wait_seconds=60]
```

自動実行フロー:
1. クリーンスナップショットに復帰
2. Frida wheelのオフラインインストール（ゲスト内）
3. ネットワークをHost-Onlyに切替
4. マルウェア＋Fridaスクリプトをゲストにコピー
5. 実行前のスクリーンショット＋プロセスリスト取得
6. `frida -f <binary> -l bypass_vmdetect.js -l dump_payload.js -q -t <sec> --kill-on-exit`
7. 実行後のスクリーンショット＋プロセスリスト取得
8. メモリダンプ＋Fridaログをホストに回収
9. クリーンスナップショットに復帰

### Fridaスクリプト

| スクリプト | 機能 |
|-----------|------|
| `frida-scripts/bypass_vmdetect.js` | Sleep/SleepEx無効化、IsDebuggerPresent/CheckRemoteDebuggerPresent偽装、NtQueryInformationProcess (ProcessDebugPort/ObjectHandle/Flags) バイパス |
| `frida-scripts/dump_payload.js` | VirtualProtect (RWX/RX→ダンプ)、VirtualAlloc追跡、CreateThreadシェルコード検出、新規モジュール監視(3s間隔×55s) |

### Frida CLI オプション（17.7.3）
```bash
# スポーンモード（推奨）: マルウェアを起動してフック
frida -f <binary> -l script1.js -l script2.js -q -t 60 --kill-on-exit

# -q: quiet mode（インタラクティブプロンプト無効）
# -t 60: 60秒後に自動終了
# --kill-on-exit: Frida終了時にプロセスをkill
```

### Frida 17.7.3 API互換性ノート（重要）

| 廃止されたAPI | 代替API | 備考 |
|--------------|---------|------|
| `Module.findExportByName(dll, func)` | `Process.getModuleByName(dll).getExportByName(func)` | Frida 17.xで`Module`はクラスではなくなった |
| `--no-pause` CLI flag | `-q` (quiet mode) | 自動resume |
| `Script.bindExitHandler(fn)` | `setTimeout(fn, N)` | 終了フック代替 |
| `{ abi: 'stdcall' }` | 省略（デフォルトwin64） | x64ではstdcall無効 |

### Fridaフック安定性ノート

**安定（推奨）:**
- `Sleep`, `SleepEx` — Interceptor.attach（引数書き換え）
- `IsDebuggerPresent`, `CheckRemoteDebuggerPresent` — Interceptor.attach（戻り値書き換え）
- `NtQueryInformationProcess` — Interceptor.attach（デバッグ情報クラスのみ）
- `VirtualProtect`, `VirtualAlloc`, `CreateThread` — Interceptor.attach（監視＋ダンプ）

**不安定（使用禁止）:**
- `Process32FirstW`, `Process32NextW` — Interceptor.replace → プロセスクラッシュ（x64で不安定）
- `RegOpenKeyExW`, `CreateFileW` — 大量呼び出しでDLL初期化デッドロック
- `NtQuerySystemInformation` — 同上、プロセス起動時に数千回呼ばれる

### Fridaオフラインインストール

ゲストVMはHost-Only（ネットワーク隔離）のため、Fridaはオフラインインストール:
```
tools/vmware-sandbox/input/frida_wheels/
├── frida-17.7.3-cp37-abi3-win_amd64.whl
├── frida_tools-14.6.0-py3-none-any.whl
├── colorama-0.4.6-py2.py3-none-any.whl
├── prompt_toolkit-3.0.52-py3-none-any.whl
├── pygments-2.19.2-py3-none-any.whl
├── websockets-13.1-cp310-cp310-win_amd64.whl
├── typing_extensions-4.15.0-py3-none-any.whl
└── wcwidth-0.6.0-py3-none-any.whl
```

ゲスト内で: `pip install --no-index --find-links=<dir> frida-tools`

### 出力ファイル
```
tools/vmware-sandbox/output/<binary>_frida_<timestamp>/
├── frida_log.txt          # Fridaコンソール出力（API呼び出しログ）
├── dumps/                 # メモリダンプ（dump_NNN_<tag>_<addr>_<size>.bin）
├── pre_processes.txt      # 実行前プロセスリスト
├── post_processes.txt     # 実行後プロセスリスト
├── pre_screenshot.png     # 実行前スクリーンショット
└── post_screenshot.png    # 実行後スクリーンショット
```

## DonutLoader解析ナレッジ（2026-02-25）

### 検体情報
- **SHA256**: `e7acc171f303d8c399f7e01f0091fe0e6253b8f81c6e444ec644d57463462f9d`
- **VT Detection**: 39/76 (trojan.tedy/zusy)
- **Packer**: MinGW-w64 + CFG Flattening + Sleep Bombing

### 特徴
- **CFG Flattening**: 20,292関数中98.1%が51-100bytesの均一サイズ（制御フロー平坦化）
- **Sleep Bombing**: 97.7%の関数（19,833/20,292）がSleepを呼び出し。合計115,000+回のSleep呼び出し
- **TLS Callbacks**: 2個のTLSコールバックでアンチデバッグ
- **暗号化ペイロード**: .rdataセクションに2.6MBのhex-encoded暗号化ペイロード
- **偽装情報**: 13個の偽Clangバージョン文字列、偽会社名"Modern Cyber Core Inc"
- **最終ペイロード**: Donutシェルコードフレームワーク（AMSI/WDLTD/ETWバイパス）→ StealC推定

### Frida解析結果
- **Sleep無効化**: 115,000+回のSleep呼び出しを全て0msに書き換え → 高速実行
- **VirtualAlloc**: 3回のアロケーション（512B RWX, 960KB RW×2 = ステージング領域）
- **VirtualProtect**: 32KBをPAGE_EXECUTE_READ(0x20)に変更 → ペイロード展開
- **メモリダンプ**: `dump_001_vp_215ffda1000_32768.bin` (32KB x86-64コード)
- **結果**: ペイロード展開後もVM検知が動作しプロセス終了（CPUID/VMware I/Oポート経由 — Fridaではフック不可）

### 教訓
- Frida DBI はユーザーモードAPI（Sleep, VirtualProtect等）のフックには有効
- CPUIDやVMwareバックドアI/Oポート（IN命令）はカーネルレベルのため、Fridaではバイパス不可
- カーネルレベルVM検知のバイパスにはVMX設定変更（Phase 1: harden-vmx）が必要

## VMProtect二層構造とDevirtualization

VMProtectで保護されたバイナリには2つの保護層がある:

| 層 | 内容 | 除去ツール | 状態 |
|----|------|-----------|------|
| **Layer 1: パッキング** | コード暗号化、IAT隠蔽、アンチダンプ | memdump-racer (Level 1) | 除去可能 |
| **Layer 2: コード仮想化** | x86命令をVMP bytecodeに変換、VMディスパッチャで実行 | Mergen (LLVM lifting) | 対応中 |

### Layer 1: パッキング層（除去済み）
- memdump-racerのタイミングベースダンプで除去
- アンパック後のPEにはインポートテーブルが復元される
- Ghidraで基本的なデコンパイルが可能になる

### Layer 2: コード仮想化層（Mergenで対応）
- アンパック後もVMP仮想化された関数はデコンパイルできない
- Ghidraでは「VMディスパッチャループ」としか見えない
- Mergenで仮想化関数をLLVM IRにリフティング → 元のロジックを復元

### Devirtualizationパイプライン

```bash
# 1. パッキング層の除去（既存）
bash tools/vmware-sandbox/sandbox.sh unpack /path/to/packed.exe

# 2. VMP関数アドレスの検出
tools/dump-triage/dump-triage.exe --vmp-addrs /path/to/unpacked.exe > vmp_addrs.txt

# 3. Devirtualization（LLVM IRへの変換）
bash tools/mergen/mergen.sh devirt /path/to/unpacked.exe 0x140001000
# または一括:
bash tools/mergen/mergen.sh devirt-batch /path/to/unpacked.exe vmp_addrs.txt

# 4. Ghidra再解析（LLVM IR出力と照合）
bash tools/ghidra-headless/ghidra.sh analyze /path/to/unpacked.exe

# ワンコマンド（自動検出＋一括devirt）:
bash tools/vmware-sandbox/sandbox.sh devirt /path/to/unpacked.exe
```

### Mergenの使い方

**コンテナ管理:**
```bash
bash tools/mergen/mergen.sh start    # ビルド＆起動（初回: ~10分）
bash tools/mergen/mergen.sh stop     # 停止
bash tools/mergen/mergen.sh status   # 状態確認
bash tools/mergen/mergen.sh shell    # コンテナ内シェル
```

**Devirtualization:**
```bash
# 単一関数
bash tools/mergen/mergen.sh devirt <binary> <address>
# → tools/mergen/output/<binary>_<address>.ll にLLVM IR出力

# アドレスリストから一括
bash tools/mergen/mergen.sh devirt-batch <binary> <addresses.txt>
# → 各アドレスごとに.llファイル出力

# VMPセクションスキャン
bash tools/mergen/mergen.sh scan <binary>
# → VMP関数候補アドレスを表示
```

**LLVM IR出力の読み方:**
- `define` で始まる関数定義 = devirtualize済みの元のロジック
- `load`/`store` = メモリアクセス（レジスタ相当の操作含む）
- `call` = 外部API呼び出し（C2通信、ファイル操作等の特定に使える）
- 最適化パスにより冗長なVMハンドラコードが除去され、本質的なロジックのみ残る

**制限事項:**
- VMP 3.x の全ハンドラに対応しているとは限らない（新バージョンで追加されたハンドラは未対応の可能性）
- 間接ジャンプが3分岐以上の関数は失敗する場合がある
- devirt失敗時はTriton（動的シンボリック実行）をフォールバックとして検討

### dump-triage VMP アドレス検出

```bash
# VMP関数アドレスをMergen入力形式で出力
tools/dump-triage/dump-triage.exe --vmp-addrs <binary>
```

出力形式:
```
# VMP Address Candidates: install.exe
# ImageBase: 0x140000000
# EntryPoint RVA: 0x00001000 (VA: 0x140001000)
# EntryPoint is INSIDE a VMP section

# Section: .vmp0    VA=0x00001000 Size=0x50000

0x140001000
0x140002340
0x14000A100
...
```

検出ロジック:
- 非標準セクション名 + 実行可能属性 = VMPセクション
- セクション内のCALL/JMPターゲットを列挙
- エントリポイントがVMPセクション内の場合フラグ

### install.exe解析ナレッジ（VMP 3.x）

VMP 3.xの典型的なセクション構造:
- セクション名が難読化（`.uBq`, `.J)t`, `.sYB`等）
- VMPセクションがバイナリの90%以上を占有
- インポートテーブルが空（0個）
- エントリポイントがVMPセクション内

memdump-racer結果:
- Layer 1（パッキング）は200-300msのタイミングダンプで除去成功
- Layer 2（仮想化）はメモリダンプでは除去不可 → Mergenが必要

## VMProtect解析のフォールバック戦略

3-Level Unpacking / Mergen devirt / Frida DBI の各段階で失敗した場合のエスカレーションパス。

### パッキング層除去の失敗時

| 段階 | 失敗パターン | 対処 |
|---|---|---|
| L1 memdump-racer | ディレイが合わない（POOR判定） | ディレイを50ms刻みで0-1000msにスイープ（デフォルトの5点では不足な場合） |
| L2 TinyTracer | OEP検出失敗（.tagにセクション遷移なし） | Intel PINバージョン（3.31必須）とTinyTracerの互換性を確認 |
| L3 x64dbg手動 | Anti-Debugが強力でブレーク不可 | ScyllaHideプラグインでNtQueryInformationProcess等を偽装 |
| **全Level失敗** | パッキング層が特殊（VMP以外の独自パッカー等） | Frida DBIで VirtualProtect/VirtualAlloc をフックし、RWX→RX遷移時にメモリダンプ（dump_payload.jsが対応済み） |

### コード仮想化層（Mergen）の失敗時

| 失敗パターン | 原因 | 対処 |
|---|---|---|
| devirt失敗（間接ジャンプ3分岐以上） | Mergenの制限 | 対象関数を手動で分割し、個別にdevirt |
| 未対応VMPハンドラ | VMP 3.x新バージョン | Triton（動的シンボリック実行）でPythonスクリプトを手動構築。**未ツール化、手動対応が必要** |
| dump-triageのVMPアドレス検出失敗 | セクション構造が想定外 | Ghidraのセクション解析で手動特定 |

### VM検知によりプロセスが即終了する場合

| 検知レベル | 例 | 対処 | 状態 |
|---|---|---|---|
| ユーザーモードAPI | IsDebuggerPresent, CheckRemoteDebuggerPresent | Frida bypass_vmdetect.js | 対処済み |
| レジストリ/プロセス/ドライバ | VMware Tools, vmci.sys | VMware Tools停止は**禁止**（vmrun通信不可になる）。許容する | 許容 |
| カーネルレベル | CPUID Hypervisor bit, VMware I/Oポート (IN 0x5658) | VMX設定で偽装。`hypervisor.cpuid.v0 = "FALSE"` 等 | **未実装（harden-vmx計画中）** |
| SMBIOS/DMI | BIOS文字列に"VMware" | VMX設定で偽装。`smbios.reflectHost = "TRUE"` 等 | **未実装（harden-vmx計画中）** |

### harden-vmx（計画中）で対処予定のVMX設定項目

```
hypervisor.cpuid.v0 = "FALSE"          # CPUID Hypervisor bitを隠蔽
smbios.reflectHost = "TRUE"            # ホストのSMBIOS情報を反映
board-id.reflectHost = "TRUE"          # ボードIDをホストから反映
ethernet0.address = "XX:XX:XX:XX:XX:XX"  # MACアドレスを非VMwareベンダーに変更
monitor_control.restrict_backdoor = "TRUE"  # VMwareバックドアI/Oポートを制限
```

注意: これらの設定はVMware Toolsの通信にも影響する可能性がある。変更後のvmrun動作検証が必須。

### フォールバック全体フロー

```
unpack auto
  → L1 POOR → L2 POOR → L3 手動失敗
    → Frida DBI (VirtualProtect/VirtualAllocフック) でメモリダンプ
      → 成功 → Ghidra再解析
      → 失敗（VM検知で即終了）
        → harden-vmx でVMX設定変更後に再試行
        → Frida bypass + harden-vmx でもVM検知突破不可
          → ユーザに「この検体はカーネルレベルVM検知が強力で現環境では解析困難」と報告

devirt (Mergen)
  → 成功 → LLVM IR出力 → Ghidra照合
  → 失敗 → 関数分割して個別devirt
    → 失敗 → Triton手動スクリプト（未ツール化）
      → 対応不可 → ユーザに「VMP仮想化層の解析は現ツールでは限界」と報告
```

## CYNEX推奨モニタリングツール一覧

ゲスト内解析ツールテーブルの追加（CYNEX ホワイトペーパー セクション6推奨）:

| ツール | パス | 用途 | 備考 |
|--------|------|------|------|
| Autoruns | tools\autoruns\autoruns64.exe | 永続化メカニズム一覧検出 | Sysinternals。Run/Service/Task/COM等を網羅 |
| Regshot | tools\regshot\Regshot-x64-ANSI.exe | レジストリ前後差分比較 | regshot_diff.pyと連携。1st→実行→2nd→Compare |
| Sysmon | サービスとしてインストール | カーネルレベルイベントログ | プロセス生成/ネットワーク/ファイル変更をEventLogに記録 |
| TCPView | tools\tcpview\tcpview64.exe | リアルタイムTCP/UDP接続監視 | Sysinternals。C2接続をリアルタイム確認 |
| Process Hacker | tools\processhacker\ProcessHacker.exe | 高機能プロセスマネージャ | メモリ読み書き/ハンドル操作/DLLインジェクション検出 |
| Wireshark | C:\Program Files\Wireshark\Wireshark.exe | パケットキャプチャ | FakeNet-NG併用でC2プロトコル詳細分析 |

**推奨追加ツール（手動インストール）:**

| 優先度 | ツール | 用途 | 備考 |
|---|---|---|---|
| HIGH | Autoruns | 永続化メカニズム検出 | Sysinternals |
| HIGH | Regshot | レジストリ前後比較 | regshot_diff.pyと連携 |
| MEDIUM | Sysmon | カーネルレベルイベントログ | 要サービスインストール |
| MEDIUM | TCPView | リアルタイム接続監視 | Sysinternals |
| MEDIUM | Process Hacker | 高機能プロセスマネージャ | メモリ/ハンドル操作 |
| LOW | BlobRunner | シェルコード実行補助 | デバッグ用 |
| LOW | Resource Hacker | PEリソース抽出 | アイコン/文字列 |

## 解析安全チェックリスト（CYNEX 4.3準拠）

### 解析前チェック
- [ ] クリーンスナップショットに復帰済み
- [ ] ネットワークがHost-Only（またはDisconnected）に切替済み
- [ ] `sandbox.sh net-status` で確認済み
- [ ] マルウェア検体は暗号化Zipで管理（パスワード付き）
- [ ] ホスト→ゲストのファイル共有は一方向（ゲスト→ホストの自動コピー無効）
- [ ] ホストOSのリアルタイム保護が有効（万一のエスケープ対策）

### 解析中チェック
- [ ] マルウェア実行前にモニタリングツールを起動（ProcMon/FakeNet/Regshot 1st等）
- [ ] 実行後の待機時間を十分確保（デフォルト60秒、Sleep bombing検体は延長）
- [ ] NATモード使用時はユーザー確認を取得済み
- [ ] 解析ログを記録中（`logs/YYYYMMDD_<target>.md`）

### 解析後チェック
- [ ] 解析結果（テキスト/スクリーンショット/ダンプ）をホストに回収済み
- [ ] クリーンスナップショットに復帰済み
- [ ] 解析ログを完成（Key Findings/IOCs記載）
- [ ] 暗号化Zip以外の形式でマルウェアがホスト上に残っていないことを確認

## デバッグ目的ガイド（CYNEX 4.4準拠）

| デバッグ目的 | 想定シーン | 推奨ツール | 手法 |
|---|---|---|---|
| **難読化解析** | CFG平坦化、VMProtect仮想化、文字列暗号化 | x64dbg + ScyllaHide, Frida DBI | ブレークポイントで復号後メモリを確認。Fridaで復号関数フック |
| **挙動詳細** | API呼び出し順序、引数・戻り値の確認 | API Monitor, ProcMon, Frida | API MonitorでAPI呼び出しトレース。ProcMonでファイル/レジストリ監視 |
| **暗号処理** | C2通信の暗号化/復号、データexfil方式 | x64dbg, Frida, Wireshark | 暗号API（BCrypt*/Crypt*）にブレーク。Fridaで引数/戻り値ダンプ |
| **解析回避対応** | Anti-Debug, Anti-VM, Sleep bombing | Frida bypass_vmdetect.js, ScyllaHide | Fridaで自動バイパス。ScyllaHideでNtQueryInformationProcess偽装 |

### 目的別推奨フロー

```
難読化解析:
  Ghidra静的解析 → 暗号化関数特定 → x64dbg/Fridaでランタイム復号 → 復号済みデータ取得

挙動詳細:
  ProcMon起動 → FakeNet起動 → マルウェア実行 → ログ回収 → ファイル/レジストリ/通信の時系列分析

暗号処理:
  imports解析でCrypt API特定 → Fridaフックで引数/戻り値キャプチャ → 暗号鍵/IV/平文を取得

解析回避対応:
  sandbox-evasion-check実行 → 検知項目修正 → Frida bypass有効化 → マルウェア再実行
```

## ツールプロセス名オブファスケーション（CYNEX 6章）

マルウェアはProcess32First/NextWで解析ツールのプロセス名をチェックする。
EXE名を変更することで検知を回避できる。

### リネーム対象と推奨名

| 元のEXE名 | リネーム例 | 備考 |
|---|---|---|
| procmon.exe | svchost2.exe | ProcMon |
| procmon64.exe | conhost2.exe | ProcMon 64bit |
| wireshark.exe | netcfg.exe | Wireshark |
| x64dbg.exe | notepad2.exe | デバッガ |
| x32dbg.exe | calc2.exe | デバッガ 32bit |
| processhacker.exe | dllhost2.exe | Process Hacker |
| fiddler.exe | explorer2.exe | Fiddler |
| die.exe | mspaint2.exe | Detect It Easy |
| pestudio.exe | winlogon2.exe | pestudio |
| fakenet.exe | lsass2.exe | FakeNet-NG |

### 運用手順

1. `sandbox.sh evasion-check` でプロセス名検知を確認
2. 検知されたツールのEXEをリネーム
3. 再度 `sandbox.sh evasion-check` で検知が解消されたことを確認
4. **注意**: リネーム後もショートカットや設定ファイル内のパスは元のままなので、必要に応じて更新

### sandbox-evasion-checkとの連携

```bash
# 1. 診断実行
bash tools/vmware-sandbox/sandbox.sh evasion-check

# 2. レポートで "Analysis tool processes" が FAIL なら
#    検知されたプロセスをリネーム

# 3. 再診断で PASS を確認
bash tools/vmware-sandbox/sandbox.sh evasion-check
```

## 通信エミュレーション拡張ガイド（CYNEX 6章）

マルウェアのC2通信を安全にキャプチャするための3レベル構成。

### Level 1: FakeNet-NG（現行・基本）

```bash
# ゲスト内でFakeNet-NG起動
bash tools/vmware-sandbox/sandbox.sh exec "C:\Users\malwa\Desktop\tools\fakenet\fakenet3.5\fakenet.exe"
```

- **対応プロトコル**: DNS, HTTP, HTTPS, SMTP, FTP, IRC, BITS
- **特徴**: 全ドメインをlocalhost解決、偽HTTP応答
- **制限**: カスタムバイナリプロトコル、WebSocket、DoHには非対応
- **用途**: 基本的なC2ドメイン/URI/User-Agent特定

### Level 2: INetSim（計画）

```
# 将来的にゲストまたは別VMにINetSimをセットアップ
# FakeNet-NGより多くのプロトコルをシミュレート
```

- **対応プロトコル**: DNS, HTTP/HTTPS, FTP, SMTP, POP3, TFTP, NTP, Syslog等 14+
- **特徴**: 実際のファイルダウンロード応答、SSL証明書生成
- **用途**: より高度なC2エミュレーション、ファイルダウンロード追跡

### Level 3: Custom C2 Mock（上級・手動）

マルウェアファミリが特定された後、そのC2プロトコルに合わせたモックサーバーを構築。

- **用途**: StealC, Lumma等のC2 APIエンドポイントを再現
- **手法**: Python Flask/FastAPIで特定のレスポンスを返すサーバー
- **前提**: 静的解析/動的解析でC2プロトコルが判明していること

```python
# 例: StealC v2 C2モック（概念）
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route("/api", methods=["POST"])
def c2_handler():
    data = request.json
    if data.get("opcode") == "init":
        return jsonify({"status": "success", "config": "..."})
    return jsonify({"status": "waiting"})
```

### レベル選択指針

| 状況 | 推奨レベル |
|---|---|
| 初期トリアージ、C2ドメイン特定 | Level 1 (FakeNet-NG) |
| ダウンローダー、多段ペイロード | Level 2 (INetSim) |
| 特定ファミリの深掘り解析 | Level 3 (Custom Mock) |

## 関連スキル連携

- **ghidra-headless**: 静的解析（デコンパイル、インポート分析）。パック検出→動的解析→アンパック→再デコンパイルの連携。Mergen LLVM IR出力との照合
- **kali-pentest**: radare2による高速トリアージ、エントロピー分析でパッカー判定
- **forensic-analysis**: フォレンジックで発見された不審バイナリの動的解析
- **memory-forensics**: メモリダンプからの不審プロセス抽出→動的解析で挙動確認

## Vidar Stealer C2プロトコル仕様

### 通信チェーン全体像
```
1. DNS解決 → Steam/Telegram等のDDRサービス
2. DDR (Dead Drop Resolver) → actual_persona_name から bare domain 抽出
3. DNS解決 → C2ドメイン
4. POST /api/config → セミコロン区切り設定レスポンス取得
5. POST /api/client → "ok" レスポンスで登録確認
6. 情報窃取 (ブラウザ、暗号資産ウォレット、ファイル等)
7. POST /api/ (exfiltration) → zipファイルでデータ送信
```

### Steam DDRフロー
- Vidarはサンプルごとにハードコードされた Steam Profile ID を持つ（例: `/id/XXXXXXXX`）
- Profile IDは Ghidra の strings / xrefs で特定可能
- Steamプロフィールページの `<span class="actual_persona_name">` タグからbare domainを抽出
- `</span>` を終了マーカーとして使用
- FakeNetで応答する場合: `input/templates/fake_steam_profile_template.html` を編集し、
  `REPLACE_DOMAIN` を偽C2ドメイン（FakeNetが解決するもの）に置換

### /api/config レスポンス仕様
- **Content-Type**: text/plain（JSONではない）
- **形式**: カンマ区切りフラグ + セミコロン区切りフィールド
- **フィールドマッピング**:
  ```
  flags(csv),botID,more_flags,timeout,
  ProfileName;SearchPath;FilePatterns;MaxSizeMB;Recursive;ExcludeExtensions;
  ```
- 例: `1,1,1,1,1,BOTID,1,1,1,1,250,Default;%DOCUMENTS%\;*.txt:*.dat;50;true;exe;`
- build_http_response.py の `--template vidar-config` で生成可能

### /api/client レスポンス仕様
- **Content-Type**: text/plain
- **ボディ**: `ok` （2文字のプレーンテキスト）
- このレスポンスがないとVidarは処理を中断する

### User-Agent
- `SystemInfo Client/1.0`（Vidar固有のUA）

### FakeNet Custom Response設定例
```ini
[VidarC2Config]
InstanceName:     HTTPListener443
HttpURIs:         /api/config
HttpRawFile:      vidar_config_response.txt

[VidarC2Client]
InstanceName:     HTTPListener443
HttpURIs:         /api/client
HttpStaticString: ok
```

## Vidar Stealer解析で発見されたエラーと対策（2026-03-01）

### 14. .env CRLF line endings
- **問題**: .envがCRLF改行だと全変数に`\r`が付加され、vmrunの全コマンドが失敗する
- **原因**: Windowsエディタで.envを編集するとCRLF化する
- **対策（修正済み）**: sandbox.shの.env読み込み時に`key="${key%$'\r'}"` `value="${value%$'\r'}"` で`\r`を除去
- **確認方法**: `sed -i 's/$/\r/' .env` でCRLF化 → `sandbox.sh status` が動作すること

### 15. VM clock change causes death
- **問題**: `Set-Date`でVM時刻を変更するとVMware Tools時刻同期と競合し、VMが不安定になる
- **原因**: VMware ToolsがホストOSの時刻に同期し、ゲスト側の変更を上書き
- **対策（実装済み）**: `sandbox.sh set-clock` コマンドで以下を自動実行:
  1. .vmxに`tools.syncTime = "FALSE"`等の設定を追加
  2. P/Invoke `SetSystemTime` で時刻設定（Set-Dateより安定）

### 16. Set-Date UAC silent failure
- **問題**: `Set-Date` はUAC昇格が必要だが、vmrun経由では昇格できず無言で失敗する
- **対策**: `SetSystemTime` Win32 API P/Invokeを使用（safe_set_clock.ps1）

### 17. guest-cmd timeout for Frida
- **問題**: Frida等の長時間実行コマンドがデフォルトタイムアウト(30s)で打ち切られる
- **対策（実装済み）**:
  - `sandbox.sh guest-cmd --timeout 120 'command'` でタイムアウト個別指定
  - `.env` の `VMRUN_TIMEOUT` でデフォルトタイムアウトを変更可能

### 18. Start-Process frida path
- **問題**: Frida CLIをPATHなしで呼ぶとコマンド未検出になる
- **対策**: ゲスト内PythonのScriptsディレクトリのfrida.exeをフルパス指定、またはPATH通過済み環境で`frida`を直接呼ぶ

### 19. Complex PowerShell via vmrun
- **問題**: 複雑なPowerShellコマンドはvmrunの引数経由で壊れる（クォート/エスケープ問題）
- **対策（実装済み）**: `sandbox.sh run-script <local_script.ps1> [timeout=60]`
  - .ps1をVMにコピー→実行→ログ回収を自動化
  - 複雑なスクリプトはファイル経由で渡すのが正解

### 20. 0-byte file in snapshot
- **問題**: スナップショットに含まれないファイル（ビルド未実行等）が0バイトでゲストにコピーされ、後続処理が"unsupported file format"で失敗
- **対策（修正済み）**: `copy-to` でソースファイルの存在確認 + 0バイトチェックを追加

### 21. PS1復号形式不一致
- **問題**: 複数の復号スクリプトが混在し、暗号形式が不一致（Rfc2898DeriveBytes vs SHA256直接ハッシュ）
- **正しい形式**: `SHA256(password)` → AES-256-CBC鍵、`gzip(IV + ciphertext)` のフォーマット
- **対策**: 誤形式のスクリプト4件を削除:
  - `decrypt_and_verify.ps1`（Rfc2898DeriveBytes）
  - `setup_step2.ps1`（同上）
  - `try_decrypt.ps1`（使い捨て試行）
  - `decrypt_with_tool.ps1`（同上）
- **正しいスクリプト**: `decrypt_quarantine.ps1`, `decrypt.ps1`, `decrypt_babi.ps1`, `decrypt-tool/main.go`

### 22. FakeNet CA証明書期限切れ
- **問題**: CA証明書の有効期限が切れるとFakeNetのHTTPS応答がTLSハンドシェイク失敗になる
- **症状**: マルウェアのHTTPS C2通信がキャプチャできない、FakeNetログに"SSL error"
- **対策（ツール化）**: `sandbox.sh fakenet-validate` で事前チェック。`fakenet_validate.py check-ca` で期限確認
- **再生成**: `openssl req -x509 -newkey rsa:2048 -keyout fakenet_ca.key -out fakenet_ca.crt -days 3650 -nodes`

### 23. FakeNet Custom Responseマッチ不全
- **問題**: custom_responses.ini の InstanceName 未設定、HttpRawFile のパスミス、HttpURIs の形式不正
- **症状**: マルウェアのリクエストに対してデフォルトレスポンスが返り、C2フローが進まない
- **対策（ツール化）**: `fakenet_validate.py check-config` で InstanceName必須チェック、ファイル存在確認、URI形式チェック
- **InstanceName**: `HTTPListener80` (HTTP) or `HTTPListener443` (HTTPS) のみ有効

### 24. Vidar /api/config がJSONではなくセミコロン区切り
- **問題**: /api/config のレスポンスをJSON形式で作成するとVidarがパースに失敗する
- **正しい形式**: カンマ区切りフラグ + セミコロン区切りフィールド（プレーンテキスト）
- **対策**: `build_http_response.py --template vidar-config` で正しい形式のレスポンスを生成

### 25. Vidar /api/client に "ok" プレーンテキストが必要
- **問題**: /api/client のレスポンスが "ok" でないとVidarが処理を中断する
- **対策**: custom_responses.ini で `HttpStaticString: ok` を設定

### 26. FakeNet pcap 0 bytes
- **問題**: FakeNetのpcapファイルが0バイトになることがある
- **原因**: FakeNetが正常終了しなかった場合、pcapバッファがフラッシュされない
- **対策**: Wiresharkを併用してpcapを取得する。VM内で `tshark.exe -i Ethernet -w capture.pcap` を並行実行

### 27. Frida 120s timeout不足
- **問題**: Vidar等の多段C2通信マルウェアでは、DDR→config→exfiltrationの全フローに120秒以上かかる
- **対策**: `sandbox.sh frida-analyze` のデフォルトtimeoutを `wait_sec + 60` に延長（従来は+30）
- **推奨**: wait_sec=300 を指定して `sandbox.sh frida-analyze <binary> 300` で実行

## ScarfaceStealer / Vidar系マルウェア識別ナレッジ（2026-03-04）

### ScarfaceStealer概要
- Vidar Stealerの亜種/リブランド（Vidar lineage）
- C2サーバーでHTTPディレクトリリスティングを公開するパターンが多い
- install.exe等の汎用ファイル名でドロップされることが多い
- VMProtect/Themidaでパックされていることが多く、静的解析困難

### C2サーバー特徴（39.106.81.175:5002の事例）
- HTTPディレクトリリスティングが有効（Werkzeug/Python http.server）
- 複数のマルウェアファミリーが同居（PPI = Pay-Per-Install ディストリビューション）
- ファイルが定期的に更新される（ドロッパーのローテーション）

### ANY.RUN活用ガイド（VMProtect anti-VMバイパス用フォールバック）
- VMProtect検体がVMware環境のVM検知で実行を拒否する場合のフォールバック
- ANY.RUNはKVM/QEMUベースのためVMwareバックドアI/Oポート検知を回避可能
- 無料プランでも基本的な動的解析結果（プロセスツリー、ネットワーク通信、ファイルI/O）が確認可能
- 有料プランではpcapダウンロード、メモリダンプ、YARA検索が利用可能

### KVM/QEMU vs VMware のanti-VM検知差異
| 検知手法 | VMware | KVM/QEMU (ANY.RUN) |
|----------|--------|---------------------|
| CPUID hypervisor bit | 検知される | 検知される（ただしCPUIDリーフが異なる） |
| VMwareバックドアI/Oポート | 検知される | 存在しない（回避） |
| レジストリキー (VMware Tools) | 検知される | 存在しない（回避） |
| MAC prefix (00:0C:29等) | 検知される | 異なるprefix（回避） |
| SMBIOS/DMI文字列 | "VMware" | カスタマイズ可能 |

### マルチファミリーC2 / PPIディストリビューションパターン
- 1つのC2サーバーに複数ファミリー（Vidar, ScarfaceStealer, Lumma等）が共存
- PPI（Pay-Per-Install）ネットワークではインストーラーが複数のペイロードを順次ダウンロード
- 各ペイロードは異なるC2を使用することがあるため、1検体の解析で複数のC2が判明する
- proxy-webの `list` サブコマンドでディレクトリ構造を把握してから個別ダウンロードが効率的

## 注意事項

- **解析前に必ずネットワークをHost-Onlyに切り替えること（最重要）**
- 解析前に必ずクリーンスナップショットに復帰すること
- 解析後も必ずクリーンスナップショットに復帰すること（汚染防止）
- NATモードは C2通信キャプチャ時のみ、ユーザー確認を取ってから使用
- ホストOS上でマルウェアを直接実行しないこと
- 解析結果（テキスト/スクリーンショット）のみホストに回収
- vmrunコマンドは必ずタイムアウトを設定して実行すること
