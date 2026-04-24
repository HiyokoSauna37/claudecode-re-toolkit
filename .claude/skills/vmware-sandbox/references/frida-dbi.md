# Frida DBI解析（Phase 2）

Frida（Dynamic Binary Instrumentation）を使ったマルウェア動的解析。
Sleep bombing無効化、Anti-Debug回避、VirtualProtect/VirtualAllocのメモリダンプを自動実行。

## ワンコマンド実行
```bash
bash tools/vmware-sandbox/sandbox.sh frida-analyze <binary_path> [wait_seconds=60]
```

自動実行フロー:
1. clean_with_toolsスナップショットに復帰
2. Frida wheelのオフラインインストール（ゲスト内）
3. ネットワークをHost-Onlyに切替
4. マルウェア＋Fridaスクリプトをゲストにコピー
5. 実行前のスクリーンショット＋プロセスリスト取得
6. `frida -f <binary> -l bypass_vmdetect.js -l dump_payload.js -q -t <sec> --kill-on-exit`
7. 実行後のスクリーンショット＋プロセスリスト取得
8. メモリダンプ＋Fridaログをホストに回収
9. clean_with_toolsスナップショットに復帰

## Fridaスクリプト

| スクリプト | 機能 |
|-----------|------|
| `frida-scripts/bypass_vmdetect.js` | Sleep/SleepEx無効化、IsDebuggerPresent/CheckRemoteDebuggerPresent偽装、NtQueryInformationProcess (ProcessDebugPort/ObjectHandle/Flags) バイパス |
| `frida-scripts/dump_payload.js` | VirtualProtect (RWX/RX→ダンプ)、VirtualAlloc追跡、CreateThreadシェルコード検出、新規モジュール監視(3s間隔×55s) |

## Frida CLI オプション（17.7.3）
```bash
# スポーンモード（推奨）: マルウェアを起動してフック
frida -f <binary> -l script1.js -l script2.js -q -t 60 --kill-on-exit

# -q: quiet mode（インタラクティブプロンプト無効）
# -t 60: 60秒後に自動終了
# --kill-on-exit: Frida終了時にプロセスをkill
```

## Frida 17.7.3 API互換性ノート（重要）

| 廃止されたAPI | 代替API | 備考 |
|--------------|---------|------|
| `Module.findExportByName(dll, func)` | `Process.getModuleByName(dll).getExportByName(func)` | Frida 17.xで`Module`はクラスではなくなった |
| `--no-pause` CLI flag | `-q` (quiet mode) | 自動resume |
| `Script.bindExitHandler(fn)` | `setTimeout(fn, N)` | 終了フック代替 |
| `{ abi: 'stdcall' }` | 省略（デフォルトwin64） | x64ではstdcall無効 |

## Fridaフック安定性ノート

**安定（推奨）:**
- `Sleep`, `SleepEx` — Interceptor.attach（引数書き換え）
- `IsDebuggerPresent`, `CheckRemoteDebuggerPresent` — Interceptor.attach（戻り値書き換え）
- `NtQueryInformationProcess` — Interceptor.attach（デバッグ情報クラスのみ）
- `VirtualProtect`, `VirtualAlloc`, `CreateThread` — Interceptor.attach（監視＋ダンプ）

**不安定（使用禁止）:**
- `Process32FirstW`, `Process32NextW` — Interceptor.replace → プロセスクラッシュ（x64で不安定）
- `RegOpenKeyExW`, `CreateFileW` — 大量呼び出しでDLL初期化デッドロック
- `NtQuerySystemInformation` — 同上、プロセス起動時に数千回呼ばれる

## Fridaオフラインインストール

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

## 出力ファイル
```
tools/vmware-sandbox/output/<binary>_frida_<timestamp>/
├── frida_log.txt          # Fridaコンソール出力（API呼び出しログ）
├── dumps/                 # メモリダンプ（dump_NNN_<tag>_<addr>_<size>.bin）
├── pre_processes.txt      # 実行前プロセスリスト
├── post_processes.txt     # 実行後プロセスリスト
├── pre_screenshot.png     # 実行前スクリーンショット
└── post_screenshot.png    # 実行後スクリーンショット
```

## Fridaトラブルシューティング

### Frida Module.findExportByName が未定義（2026-02-25発見）
- **問題**: Frida 17.7.3で `Module.findExportByName(dll, func)` が "TypeError: not a function"
- **原因**: Frida 17.xで`Module`のAPIが変更。`Module`は関数型で、`getGlobalExportByName`のみ持つ
- **解決**: `Process.getModuleByName(dll).getExportByName(func)` を使用

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
