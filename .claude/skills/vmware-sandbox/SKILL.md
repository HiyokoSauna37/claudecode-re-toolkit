---
name: vmware-sandbox
description: VMware Workstation上のWindows VM をvmrun CLIで操作し、マルウェアの動的解析を行う。VMProtect等のパックバイナリやGhidra静的解析では限界のある検体に対応。DispatchLoggerによるスクリプト系マルウェアのCOM監視にも対応。Use when: 動的解析, マルウェア実行, サンドボックス, sandbox, dynamic analysis, unpack, アンパック, 挙動解析, PE-sieve, HollowsHunter, FakeNet, Frida, COM監視, スクリプトマルウェア, VBS解析, JS解析, DispatchLogger
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
     - DBI解析: references/frida-dbi.md を参照
     - 失敗時: references/fallback-strategy.md を参照
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
bash tools/vmware-sandbox/sandbox.sh exec "<GUEST_ANALYSIS_DIR>/malware.exe"
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
bash tools/vmware-sandbox/sandbox.sh revert
bash tools/vmware-sandbox/sandbox.sh net-isolate
bash tools/vmware-sandbox/sandbox.sh copy-to /path/to/malware.exe
```

### Step 1.5: 初期トリアージ（ゲスト内）
```bash
bash tools/vmware-sandbox/sandbox.sh exec "<GUEST_TOOLS>/die/die.exe" "<GUEST_ANALYSIS_DIR>/malware.exe"
bash tools/vmware-sandbox/sandbox.sh exec "<GUEST_TOOLS>/pestudio/pestudio/pestudio.exe" "<GUEST_ANALYSIS_DIR>/malware.exe"
# .NETマルウェアの場合:
bash tools/vmware-sandbox/sandbox.sh exec "<GUEST_TOOLS>/dnSpy/dnSpy.exe" "<GUEST_ANALYSIS_DIR>/malware.exe"
```

### Step 2: 解析ツール起動（ゲスト内）
```bash
bash tools/vmware-sandbox/sandbox.sh exec "<GUEST_TOOLS>/fakenet/fakenet3.5/fakenet.exe"
bash tools/vmware-sandbox/sandbox.sh exec "<GUEST_TOOLS>/procmon/Procmon.exe" /AcceptEula /Backingfile <GUEST_ANALYSIS_DIR>/procmon.pml
bash tools/vmware-sandbox/sandbox.sh exec "<GUEST_TOOLS>/x64dbg/release/x64/x64dbg.exe"
```

### Step 2.5: COM監視（スクリプト系マルウェアの場合）
VBS/JS/HTA/PowerShell/Officeマクロなどスクリプト系検体の場合、DispatchLoggerでCOM呼び出しを可視化:
```bash
# スクリプトファイルを指定（injector経由でDLL注入+cscript実行）
bash tools/vmware-sandbox/sandbox.sh dispatch-logger malware.vbs 120

# PowerShellスクリプトの場合
bash tools/vmware-sandbox/sandbox.sh dispatch-logger powershell.exe '-File C:\analysis\malware.ps1'

# EXEでもCOM利用している場合は有効
bash tools/vmware-sandbox/sandbox.sh dispatch-logger suspicious.exe 60
```
出力: `tools/vmware-sandbox/output/displog_<timestamp>.log` (raw) + `_parsed.txt` (再構成済み)
前提: ゲストにSysinternals DebugView (Dbgview.exe) がインストール済みであること
カバレッジ: WSH/PowerShell/AutoIT=100%, VBAマクロ=95%, VB6=65%, .NET COM=60%, C++=10%(WMIのみ)

### Step 3: マルウェア実行
```bash
bash tools/vmware-sandbox/sandbox.sh exec "<GUEST_ANALYSIS_DIR>/malware.exe"
```

### Step 4: 挙動収集
```bash
bash tools/vmware-sandbox/sandbox.sh processes
bash tools/vmware-sandbox/sandbox.sh screenshot
bash tools/vmware-sandbox/sandbox.sh exec "<GUEST_TOOLS>/pe-sieve64.exe" /pid <PID>
bash tools/vmware-sandbox/sandbox.sh exec "<GUEST_TOOLS>/hollows_hunter64.exe"
```

### Step 4.5: 追加解析ツール
```bash
bash tools/vmware-sandbox/sandbox.sh exec "<GUEST_TOOLS>/hxd/app/HxD.exe" "<GUEST_ANALYSIS_DIR>/dump.bin"
bash tools/vmware-sandbox/sandbox.sh exec "<GUEST_TOOLS>/yara/yara64.exe" "<GUEST_ANALYSIS_DIR>/rules.yar" "<GUEST_ANALYSIS_DIR>/malware.exe"
bash tools/vmware-sandbox/sandbox.sh exec "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" "<GUEST_TOOLS>/cyberchef/CyberChef_v10.22.1.html"
```

### Step 5: 結果回収
```bash
bash tools/vmware-sandbox/sandbox.sh copy-from "<GUEST_ANALYSIS_DIR>/procmon.pml"
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
1. **Detect It Easy (DiE)**: 高速トリアージ
2. **pestudio**: PE構造の詳細確認
3. **Ghidra**: 初期トリアージ
4. **VMware Sandbox**: x64dbgでOEPまで実行→メモリダンプ→PE-sieveでアンパック
5. **Ghidra**: アンパック後バイナリを再解析

## ゲスト内解析ツール

ツールパスのベース: `<GUEST_TOOLS>` （.envのVM_GUEST_PROFILEから導出）

| ツール | パス | 用途 |
|--------|------|------|
| x64dbg (32bit) | tools\x64dbg\release\x32\x32dbg.exe | デバッガ（アンパック、APIトレース） |
| x64dbg (64bit) | tools\x64dbg\release\x64\x64dbg.exe | 64bitバイナリ用デバッガ |
| PE-sieve (64bit) | tools\pe-sieve64.exe | プロセスインジェクション検出 |
| HollowsHunter (64bit) | tools\hollows_hunter64.exe | 全プロセスメモリスキャン |
| memdump-racer | tools\memdump-racer.exe | メモリダンプレース（CreateProcessW直接起動） |
| tiny-unpack | tools\tiny-unpack.exe | TinyTracerベース自動アンパッカー（2パスOEP検出） |
| TinyTracer | C:\pin\source\tools\TinyTracer\install\TinyTracer64.dll | Intel PINベーストレーサー |
| API Monitor (32/64) | tools\apimonitor\API Monitor (rohitab.com)\apimonitor-x86/x64.exe | API呼び出しトレース |
| Process Monitor | tools\procmon\Procmon.exe | ファイル/レジストリ/ネットワーク監視 |
| Frida 17.7.3 | pip install済み（Python 3.10） | DBI。APIフック・メモリダンプ |
| FakeNet-NG 3.5 | tools\fakenet\fakenet3.5\fakenet.exe | ネットワークシミュレーション |
| Detect It Easy 3.10 | tools\die\die.exe | パッカー/コンパイラ/リンカー自動判定 |
| dnSpy 6.5.1 | tools\dnSpy\dnSpy.exe | .NETデコンパイラ |
| pestudio 9.61 | tools\pestudio\pestudio\pestudio.exe | PE静的解析 |
| CyberChef 10.22.1 | tools\cyberchef\CyberChef_v10.22.1.html | エンコード/デコード変換 |
| HxD 2.5.0.0 | tools\hxd\app\HxD.exe | ヘックスエディタ |
| YARA 4.5.5 | tools\yara\yara64.exe / yarac64.exe | パターンマッチング |

スナップショット: .envのVM_SNAPSHOTで設定（全ツールインストール済み・唯一のスナップショット）

## 入出力ディレクトリ

| ディレクトリ | 用途 |
|-------------|------|
| tools/vmware-sandbox/input/ | 解析対象バイナリの配置 |
| tools/vmware-sandbox/output/ | 解析結果の出力先 |
| tools/vmware-sandbox/logs/ | 解析ログ |

## コマンドログ（必須）

解析実行時は `tools/vmware-sandbox/logs/YYYYMMDD_<target_name>.md` にログを記録。
形式: Target情報、Environment、Pre/Post-Execution、Key Findings、IOCs。

## 3-Level Unpacking System

パックされたマルウェアの自動アンパックを3段階で実行するシステム。

```
sandbox.sh unpack <binary> [level]
  ├── Level 1: memdump-racer (タイミングベース) — 最速（約2分）
  ├── Level 2: tiny-unpack (TinyTracerベース) — OEP自動検出
  ├── Level 3: x64dbg (手動、手順表示のみ)
  └── auto: L1 → 品質チェック → L2 → 品質チェック → L3手順表示
```

品質判定: ダンプPEのインポート数 > 5 で GOOD。出力: quality.txt, manifest.txt, log.txt, ダンプPE群。

Level 2前提条件: ゲストにIntel PIN 3.31+ / TinyTracer / `bcdedit /debug off`。

## メモリダンプレース手法（VMProtectアンパック）

VMProtectはプロセス起動後の約300ms以内にOEPジャンプを完了する。複数ディレイ（0-500ms）でpe-sieve64スキャン＋MiniDumpを取得し、ベストを選択。

```bash
bash tools/vmware-sandbox/sandbox.sh memdump <target_on_guest> ["0,100,200,300,500"] [outdir]
```

## ゲストコマンド出力の取得パターン

### guest-cmdヘルパー（推奨）
```bash
bash tools/vmware-sandbox/sandbox.sh guest-cmd 'Get-Process | Select Name,Id'
bash tools/vmware-sandbox/sandbox.sh guest-cmd 'Get-NetTCPConnection' output/connections.txt
```

### 手動パターン（guest-cmdで対応できない場合）
```bash
bash tools/vmware-sandbox/sandbox.sh ps "Get-Process | Out-File -Encoding UTF8 <GUEST_ANALYSIS_DIR>/result.txt"
bash tools/vmware-sandbox/sandbox.sh copy-from "<GUEST_ANALYSIS_DIR>/result.txt"
```

## .enc.gz quarantine ファイルの自動復号

```bash
# .enc.gz ファイルを直接指定可能（自動復号）
bash tools/vmware-sandbox/sandbox.sh analyze "tools/proxy-web/Quarantine/<domain>/<ts>/<file>.enc.gz" 90
```

自動処理: .enc.gz検出 → VMにコピー → vm_quarantine_decrypt.ps1で復号（.NET Crypto API） → 復号済みバイナリ実行。
形式: gzip(IV[16B] + AES-256-CBC(data)), key = SHA256(password)。パスワードは.envの`QUARANTINE_PASSWORD`。

## .NET マルウェアの動的解析ナレッジ

- VT behaviorで `RegAsm.exe` / `MSBuild.exe` / `InstallUtil.exe` の起動確認 → Process Hollowing
- Host-Only環境ではFakeNet-NGによるC2エミュレーションが必要
- .NETバイナリはGhidraよりdnSpyの方が情報量が多い
- 全仮想化環境検出マルウェアはVT behaviorを最大限活用

## ネットワークフォレンジック連携ナレッジ

### FakeNet-NG活用ガイド（Host-Onlyモード推奨）
FakeNet-NGはHost-Onlyで動作し、DNS/HTTP/SMTP等の偽応答を返してC2通信パターンを安全にキャプチャ。NATモード不要。

```bash
bash tools/vmware-sandbox/sandbox.sh exec "<GUEST_TOOLS>/fakenet/fakenet3.5/fakenet.exe"
# マルウェア実行後、ログを回収
bash tools/vmware-sandbox/sandbox.sh copy-from "<GUEST_TOOLS>/fakenet/fakenet3.5/fakenet.log"
```

FakeNet詳細運用（CA証明書、custom_responses.ini設定、HTTPS対応、Lumma/ECH対応等）は [references/vidar-knowledge.md](references/vidar-knowledge.md) および [references/cynex-guide.md](references/cynex-guide.md) を参照。

## 注意事項

- **解析前に必ずネットワークをHost-Onlyに切り替えること（最重要）**
- 解析前に必ずクリーンスナップショットに復帰すること
- 解析後も必ずクリーンスナップショットに復帰すること（汚染防止）
- NATモードは C2通信キャプチャ時のみ、ユーザー確認を取ってから使用
- ホストOS上でマルウェアを直接実行しないこと
- **ホストOS上にマルウェアバイナリを復号・展開しないこと（最重要）**: Dockerコンテナ内の復号済みバイナリを `docker cp` でホストにコピーしてからVMに転送するのは禁止。暗号化ZIP/.enc.gzをそのままVMゲストにコピーし、VM内で展開すること。`tools/vmware-sandbox/input/` にも復号済みマルウェアを置くな
- 解析結果（テキスト/スクリーンショット）のみホストに回収
- vmrunコマンドは必ずタイムアウトを設定して実行すること
- **teeの出力先に実行中スクリプトや重要ファイルを絶対に指定しない**
- **.enc.gz ファイルは analyze コマンドに直接渡せる（自動復号）**
- **vmrun経由のPowerShellはパラメータ3つ以上で壊れる → run-script推奨**

## VM検知手法

install.exeで確認されたVM検知手法（SMBIOS, CPUID, MAC, プロセス, レジストリ, ドライバ, デバイス等）の詳細は [references/vm-detection-methods.md](references/vm-detection-methods.md) を参照。

## トラブルシューティング

vmrunハング、VMware Tools復旧不可、PowerShell UTF-16、ゾンビプロセス等の既知問題と対策は [references/troubleshooting.md](references/troubleshooting.md) を参照。

## Frida DBI解析

Frida DBI（Sleep無効化、Anti-Debug回避、メモリダンプ）の詳細手順・API互換性ノート・安定性ノートは [references/frida-dbi.md](references/frida-dbi.md) を参照。

## VMProtect二層構造とDevirtualization

VMProtectの2層保護（パッキング層 + コード仮想化層）とMergenによるdevirtualizationパイプラインは [references/vmprotect-devirt.md](references/vmprotect-devirt.md) を参照。

## VMProtect解析のフォールバック戦略

3-Level Unpacking / Mergen / Frida DBI の各段階で失敗した場合のエスカレーションパスは [references/fallback-strategy.md](references/fallback-strategy.md) を参照。

## CYNEX推奨ツール・安全チェックリスト・デバッグガイド

CYNEX推奨モニタリングツール、解析安全チェックリスト、デバッグ目的ガイド、ツールプロセス名オブファスケーション、通信エミュレーション拡張ガイドは [references/cynex-guide.md](references/cynex-guide.md) を参照。

## Vidar Stealer ナレッジ

Vidar Stealer C2プロトコル仕様（Steam DDR、/api/config、/api/client）および解析時に発見されたエラーと対策は [references/vidar-knowledge.md](references/vidar-knowledge.md) を参照。

## DDoSボットネット解析ナレッジ

Go製C2ボット（run.exe）の攻撃チェーンと解析注意点は [references/ddos-botnet-knowledge.md](references/ddos-botnet-knowledge.md) を参照。

## DonutLoader解析ナレッジ

CFG Flattening + Sleep Bombing検体のFrida解析結果と教訓は [references/donutloader-knowledge.md](references/donutloader-knowledge.md) を参照。

## ScarfaceStealer / Vidar系マルウェア識別ナレッジ

ScarfaceStealer概要、C2特徴、ANY.RUN活用ガイド、KVM vs VMware検知差異は [references/scarface-vidar-knowledge.md](references/scarface-vidar-knowledge.md) を参照。

## 関連スキル連携

- **ghidra-headless**: 静的解析（デコンパイル、インポート分析）。パック検出→動的解析→アンパック→再デコンパイルの連携。Mergen LLVM IR出力との照合
- **kali-pentest**: radare2による高速トリアージ、エントロピー分析でパッカー判定
- **forensic-analysis**: フォレンジックで発見された不審バイナリの動的解析
- **memory-forensics**: メモリダンプからの不審プロセス抽出→動的解析で挙動確認
