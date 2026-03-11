# トラブルシューティング

### vmrunコマンドがハングする
- **原因**: runScriptInGuest、cmd.exeリダイレクト、getGuestIPAddress -wait が無限待機
- **対策**: vmrun-wrapperを使用（タイムアウト付き）、またはBashのtimeoutコマンドで制御
- **回避パターン**: PowerShell -NoProfile -NonInteractive でコマンド実行
- **修正済み（2026-02-24）**: sandbox.shの全ゲスト操作コマンド（runProgramInGuest, copyFile*, createDirectory*）をvmrun_t（タイムアウト付き）に統一。cmd_exec()を含む24箇所を修正

### log出力でWindowsパスが破損する
- **原因**: `echo -e`がパス中の`\t`(タブ)、`\a`(ベル)等をエスケープシーケンスとして解釈
- **例**: `C:\Users\user\Desktop\analysis\target.exe` → `\t`がタブ、`\a`がベルに変換されログが崩壊
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

### vmrunのゾンビプロセスがVM操作をブロック（2026-02-25発見）
- **問題**: 複数のvmrun.exeプロセスが残留し、後続のvmrunコマンドが全てタイムアウト
- **原因**: タイムアウトでvmrunがkillされた後もプロセスが残り、VMXファイルのロックを保持
- **症状**: `vmrun list` = "0 running VMs" だが `revert`/`start` がハング。`.lck`ファイルが残存
- **解決手順**:
  1. `taskkill //F //IM vmrun.exe` — 全vmrunプロセスをkill
  2. `.lck`ディレクトリを削除 — `rm -rf "VM_DIR/"*.lck`
  3. VMware GUI（vmware.exe）が開いている場合は閉じる
  4. 再度 `vmrun revertToSnapshot` → `vmrun start`
- **予防**: vmrunの`timeout`を十分大きく設定（60s推奨）。小さすぎるタイムアウトでプロセスが中途半端に終了すると残留する

### Frida wheelのfor loop コピーが失敗する（2026-02-25発見）
- **問題**: Bash for loopでバックスラッシュWindowsパスを含む変数展開 → "ファイルが見つかりません"
- **原因**: MSYS/Git Bashのパス変換とvmrun引数のエスケープが競合
- **解決**: 各ファイルを個別のコマンドで明示的にコピー（ループ変数を使わない）

### .env CRLF line endings（2026-03-01発見）
- **問題**: .envがCRLF改行だと全変数に`\r`が付加され、vmrunの全コマンドが失敗する
- **対策（修正済み）**: sandbox.shの.env読み込み時に`key="${key%$'\r'}"` `value="${value%$'\r'}"` で`\r`を除去

### VM clock change causes death（2026-03-01発見）
- **問題**: `Set-Date`でVM時刻を変更するとVMware Tools時刻同期と競合し、VMが不安定になる
- **対策（実装済み）**: `sandbox.sh set-clock` コマンドで自動実行（.vmxにsyncTime=FALSE + P/Invoke SetSystemTime）

### Set-Date UAC silent failure
- **問題**: `Set-Date` はUAC昇格が必要だが、vmrun経由では昇格できず無言で失敗する
- **対策**: `SetSystemTime` Win32 API P/Invokeを使用（safe_set_clock.ps1）

### guest-cmd timeout for Frida
- **問題**: Frida等の長時間実行コマンドがデフォルトタイムアウト(30s)で打ち切られる
- **対策（実装済み）**: `sandbox.sh guest-cmd --timeout 120 'command'` でタイムアウト個別指定

### Start-Process frida path
- **問題**: Frida CLIをPATHなしで呼ぶとコマンド未検出になる
- **対策**: フルパス指定、またはPATH通過済み環境で`frida`を直接呼ぶ

### Complex PowerShell via vmrun
- **問題**: 複雑なPowerShellコマンドはvmrunの引数経由で壊れる
- **対策（実装済み）**: `sandbox.sh run-script <local_script.ps1> [timeout=60]`

### 0-byte file in snapshot
- **問題**: スナップショットに含まれないファイルが0バイトでゲストにコピーされる
- **対策（修正済み）**: `copy-to` でソースファイルの存在確認 + 0バイトチェックを追加

### PS1復号形式不一致
- **問題**: 複数の復号スクリプトが混在し、暗号形式が不一致
- **正しい形式**: `SHA256(password)` → AES-256-CBC鍵、`gzip(IV + ciphertext)` のフォーマット
- **正しいスクリプト**: `decrypt_quarantine.ps1`, `decrypt.ps1`, `decrypt_babi.ps1`, `decrypt-tool/main.go`

### FakeNet CA証明書期限切れ
- **対策（ツール化）**: `sandbox.sh fakenet-validate` で事前チェック

### FakeNet Custom Responseマッチ不全
- **対策（ツール化）**: `fakenet_validate.py check-config` でチェック

### Vidar /api/config がJSONではなくセミコロン区切り
- **対策**: `build_http_response.py --template vidar-config` で正しい形式のレスポンスを生成

### Vidar /api/client に "ok" プレーンテキストが必要
- **対策**: custom_responses.ini で `HttpStaticString: ok` を設定

### FakeNet pcap 0 bytes
- **対策**: Wiresharkを併用してpcapを取得する

### Frida 120s timeout不足
- **対策**: `sandbox.sh frida-analyze` のデフォルトtimeoutを `wait_sec + 60` に延長。wait_sec=300推奨
