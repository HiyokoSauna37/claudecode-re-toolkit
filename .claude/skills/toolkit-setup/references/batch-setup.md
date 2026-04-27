# 一括セットアップ手順書

Phase 1 で「一括セットアップ」が選択された場合にこの手順に従う。
Phase 0 の診断結果と選択されたセットアップ範囲に基づき、該当するステップのみ実行する。

**対話型との違い**: 最初に全体計画を提示→承認後に一気に実行。ただし環境変更操作の直前には確認を取る。

---

## Step 1: 全体計画の提示

Phase 0 の診断結果をもとに、実行する全アクションを一覧表示:

```
============================================
  セットアップ計画
============================================
  実行環境:
  - OS: Windows 11
  - Docker: [起動中 / 未起動 / 未インストール]
  - VMware: [インストール済み / 未インストール]
  - Go: [X.XX / 未インストール]
  - Python: [X.XX / 未インストール]

  実行予定アクション:
  [1] .env 作成 — QUARANTINE_PASSWORD自動生成、APIキー入力
  [2] Docker: malware-fetch イメージビルド（初回 3-5分）
  [3] Docker: ghidra-headless コンテナ起動（初回 5-10分）
  [4] YARA/CAPA セットアップ
  [5] VMware Sandbox 環境確認
============================================
```

AskUserQuestion で承認:
- 選択肢: 「この計画で実行する（推奨）」「計画を修正する」「キャンセル」
- 「計画を修正する」→ 除外したいステップを multiSelect で確認

---

## Step 2: .env 作成/編集（入力の一括収集）

AskUserQuestion を**最小回数**で済ませるため、必要な入力をまとめて収集する。

### 1回目の質問（最大4問を同時に）

Q1: QUARANTINE_PASSWORD — 「自動生成（推奨）」「自分で入力する」
Q2: VIRUSTOTAL_API_KEY — 「今は設定しない」「入力する」
Q3: ABUSECH_AUTH_KEY — 「スキップ」「入力する」
Q4: VMware設定（範囲に含む場合）— 「自動検出を使用（推奨）」「手動で入力する」

### 2回目の質問（1回目で「入力する」が選ばれた項目のみ）

Other での自由入力を求める。

### VMware 自動検出
```bash
# vmrun.exe 探索
ls "C:/Program Files (x86)/VMware/VMware Workstation/vmrun.exe" 2>/dev/null
ls "C:/Program Files/VMware/VMware Workstation/vmrun.exe" 2>/dev/null

# .vmx ファイル探索（Glob ツール使用）
find "$USERPROFILE/Documents/Virtual Machines" -name "*.vmx" 2>/dev/null
```
検出結果を提示して確認。VM_GUEST_PROFILE は VM_GUEST_USER から `C:\Users\<user>` を自動推定。

### .env 書き込み確認
AskUserQuestion:
```
以下の内容で .env を作成/更新します:
QUARANTINE_PASSWORD=********
VIRUSTOTAL_API_KEY=********
...
実行してよろしいですか？
```
承認後に Write/Edit で書き込み。

---

## Step 3: Docker 環境構築（並列実行）

malware-fetch と ghidra-headless は独立しているため並列実行可能。

### 3-1. 実行前確認

```bash
docker info > /dev/null 2>&1
```
失敗時 → 「Docker Desktop が起動していません」と案内して終了。

既存イメージ/コンテナがある場合、AskUserQuestion:
```
既存の環境が検出されました:
- malware-fetch-browser:latest: 作成日 YYYY-MM-DD
- ghidra-headless: 状態 running
```
選択肢: 「スキップ」「再ビルド（キャッシュ使用）」「再ビルド（キャッシュなし）」

### 3-2. 並列実行

承認後、Bash ツールを2つ並列で実行（両方 `run_in_background: true`）:

**タスク A: malware-fetch ビルド**
```bash
docker build -t malware-fetch-browser:latest tools/malware-fetch/ && docker run --rm malware-fetch-browser:latest echo "OK"
```

**タスク B: ghidra-headless 起動**
```bash
docker compose -f tools/ghidra-headless/docker-compose.yml up -d && sleep 5 && docker exec ghidra-headless echo "OK"
```

### 3-3. 結果報告
両タスク完了後にまとめて報告:
```
Docker 環境構築結果:
[OK] malware-fetch-browser:latest ビルド完了
[OK] ghidra-headless コンテナ起動完了
```
失敗時は `docker logs` でエラー内容を確認して報告。

---

## Step 4: YARA/CAPA セットアップ

### 4-1. 実行前確認
AskUserQuestion:
```
以下をインストールします:
- YARA ルール（signature-base + yara-forge）
- yara-python（pip）
- flare-capa（pip）+ ルール更新
実行してよろしいですか？
```

### 4-2. 実行（逐次 — 依存関係あり）
```bash
bash tools/ghidra-headless/setup_yara_rules.sh
pip install yara-python
pip install flare-capa
capa --update-rules
```

### 4-3. 検証
```bash
python -c "import yara; print('yara-python OK')"
capa --version
```
Expected output: バージョン情報が表示される。

---

## Step 5: VMware Sandbox 環境確認

### 5-1. 実行前確認
AskUserQuestion:
```
VMware Sandbox の環境を確認します（vmrun接続テスト、スナップショット確認、ゲストツール確認）。
ゲスト確認にはVM起動が必要です。実行してよろしいですか？
```

### 5-2. 基本確認（VM 起動不要）
```bash
"$VMRUN_PATH" -T ws list
ls "$VM_VMX_PATH"
"$VMRUN_PATH" -T ws listSnapshots "$VM_VMX_PATH"
```
`clean_with_tools` スナップショットの存在を確認。

### 5-3. ゲスト確認（VM 起動が必要）
```bash
bash tools/malware-sandbox/sandbox.sh start
bash tools/malware-sandbox/sandbox.sh guest-tools
bash tools/malware-sandbox/sandbox.sh net-status
```

### 5-4. 不足ツールの自動インストール
不足検出時 → AskUserQuestion で確認後:
```bash
bash tools/malware-sandbox/sandbox.sh setup-guest
```

---

## Step 6: 最終検証サマリー

すべてのステップ完了後、Phase 0 と同じ診断を並列再実行:

```bash
# 並列で全チェック
docker info > /dev/null 2>&1
docker images malware-fetch-browser:latest --format "{{.ID}}"
docker inspect -f '{{.State.Status}}' ghidra-headless
python -c "import yara"
capa --version
"$VMRUN_PATH" -T ws list  # VMware設定済みの場合のみ
```

結果をサマリー表示:
```
============================================
  Toolkit Setup 完了サマリー
============================================
[OK] .env               設定済み
[OK] Docker Desktop      起動中
[OK] malware-fetch-browser   ビルド済み (abc123def)
[OK] ghidra-headless     コンテナ実行中 (Up 2 minutes)
[OK] YARA rules          ダウンロード済み
[OK] yara-python         v4.x.x
[OK] flare-capa          v7.x.x
[OK] VMware Sandbox      接続確認済み (snapshot: clean_with_tools)

次のステップ:
- malware-fetch: malware-fetch.exe "http://example.com"
- ghidra-headless: bash tools/ghidra-headless/ghidra.sh analyze <binary>
- malware-sandbox: bash tools/malware-sandbox/sandbox.sh analyze <binary>

問題がある場合は /toolkit-setup で再実行できます。
============================================
```
