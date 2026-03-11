# 対話型ウィザード手順書

Phase 1 で「対話型ウィザード」が選択された場合にこの手順に従う。
Phase 0 の診断結果と選択されたセットアップ範囲に基づき、該当するステップのみ実行する。

**CRITICAL: 各ステップの環境変更操作の前に必ず AskUserQuestion でユーザー確認を取ること。**

---

## Step 1: .env 作成/編集

### 新規作成

AskUserQuestion で各項目を**順番に**確認する:

**Q-A: QUARANTINE_PASSWORD**
- 用途説明: マルウェアファイルのAES-256暗号化パスワード。proxy-web / ghidra-headless / vmware-sandbox の全ツールで共通利用
- 選択肢: 「自動生成（推奨）」「自分で入力する」
- 自動生成: `openssl rand -base64 24` で生成 → ユーザーに表示して確認
- 手動入力: Other で自由入力

**Q-B: VIRUSTOTAL_API_KEY**
- 用途説明: proxy-web のハッシュチェック・VT連携に必要。無料アカウントで取得可
- 選択肢: 「今は設定しない（後で追加可能）」「入力する」

**Q-C: ABUSECH_AUTH_KEY**
- 用途説明: MalwareBazaar / ThreatFox 検索に使用。なくても動作するがレート制限あり
- 選択肢: 「スキップ（なしで動作可能）」「入力する」

**Q-D: VMware 関連（VMware が選択範囲に含まれる場合のみ）**

D-1. VMRUN_PATH — 自動検出を試みて結果を提示:
```bash
ls "C:/Program Files (x86)/VMware/VMware Workstation/vmrun.exe" 2>/dev/null
ls "C:/Program Files/VMware/VMware Workstation/vmrun.exe" 2>/dev/null
```
見つかれば推奨として提示、見つからなければ Other で手動入力。

D-2. VM_VMX_PATH — デフォルトVM格納先の .vmx を探索して選択肢に:
```bash
find "$USERPROFILE/Documents/Virtual Machines" -name "*.vmx" 2>/dev/null
```

D-3. VM_GUEST_USER / VM_GUEST_PASS — Other で入力（パスワードはマスク表示）

D-4. VM_GUEST_PROFILE — VM_GUEST_USER から `C:\Users\<user>` を自動推定して確認

D-5. VM_SNAPSHOT / VMRUN_TIMEOUT — デフォルト値（clean_with_tools / 30）を提示:
- 選択肢: 「デフォルトを使用（推奨）」「カスタマイズする」

### 既存 .env の編集

1. 現在の .env を読み取り、設定済み項目を一覧表示（**値はマスク**）
2. AskUserQuestion で「どの項目を変更しますか？」と確認（multiSelect）
3. 選択項目のみ上記の質問フローで再設定
4. 変更前後の差分を表示（値はマスク）し、確認を取ってから書き込む

### .env 書き込み

最終確認を AskUserQuestion で実施:
```
以下の内容で .env を作成/更新します:
QUARANTINE_PASSWORD=********
VIRUSTOTAL_API_KEY=********  (または: 未設定)
ABUSECH_AUTH_KEY=********    (または: 未設定)
VMRUN_PATH=<検出パス>        (または: 未設定)
...
```
- 承認後に Write/Edit ツールで .env を作成/更新

**エラー時**: Write が失敗した場合はパーミッションを確認。管理者権限が必要な場所に .env を作成しようとしていないか確認する。

---

## Step 2: Docker — proxy-web イメージビルド

### 2-1. 前提確認
```bash
docker info > /dev/null 2>&1
```
失敗時 → 「Docker Desktop が起動していません。起動してから再実行してください。」と案内して**このステップを終了**。

### 2-2. 既存イメージ確認
```bash
docker images proxy-web-browser:latest --format "{{.ID}} {{.CreatedAt}}"
```
既存イメージがある場合、AskUserQuestion:
- 選択肢: 「スキップ」「再ビルド（キャッシュ使用）」「再ビルド（キャッシュなし — Dockerfile変更時推奨）」

### 2-3. ビルド実行
AskUserQuestion で確認後:
```bash
docker build -t proxy-web-browser:latest tools/proxy-web/
# --no-cache 選択時:
docker build --no-cache -t proxy-web-browser:latest tools/proxy-web/
```
`run_in_background: true` で実行。完了後に結果を報告。

### 2-4. 検証
```bash
docker run --rm proxy-web-browser:latest echo "OK"
```
Expected output: `OK`。失敗時はビルドログを確認。

---

## Step 3: Docker — ghidra-headless コンテナ起動

### 3-1. 既存コンテナ確認
```bash
docker ps -a --filter "name=ghidra-headless" --format "{{.Status}}"
```
- 実行中 → 「再作成しますか？」
- 停止中 → 「起動しますか？ or 再作成しますか？」
  - 起動のみ: `docker start ghidra-headless`
  - 再作成: `docker compose down && up -d`
- 未作成 → 新規作成フローへ

### 3-2. コンテナ起動
AskUserQuestion で確認後:
```bash
docker compose -f tools/ghidra-headless/docker-compose.yml up -d
```

### 3-3. 検証
```bash
docker exec ghidra-headless echo "OK"
docker exec ghidra-headless ls /opt/ghidra/support/analyzeHeadless
```
Expected output: `OK` + ファイルパス表示。失敗時は `docker logs ghidra-headless` でエラー確認。

---

## Step 4: YARA/CAPA セットアップ

### 4-1. YARA ルールダウンロード
AskUserQuestion で確認後:
```bash
bash tools/ghidra-headless/setup_yara_rules.sh
```
Expected output: ルールファイルが `tools/ghidra-headless/yara-rules/` に展開される。

### 4-2. yara-python
```bash
pip show yara-python 2>/dev/null
```
未インストール → AskUserQuestion で確認後 `pip install yara-python`。
検証: `python -c "import yara; print('OK')"`

### 4-3. flare-capa
```bash
pip show flare-capa 2>/dev/null
```
未インストール → AskUserQuestion で確認後:
```bash
pip install flare-capa
capa --update-rules
```
検証: `capa --version`

---

## Step 5: VMware Sandbox 環境構築ガイド

VMware のセットアップは大部分が手動作業のため、ガイド提示 + 自動化可能な部分のみ実行。

### 5-1. VMware Workstation 確認
```bash
"$VMRUN_PATH" -T ws list 2>/dev/null
```
失敗時 → VMware Workstation のインストールを案内して終了。

### 5-2. VM 存在確認
```bash
ls "$VM_VMX_PATH" 2>/dev/null
```
見つからない場合 → `tools/vmware-sandbox/docs/VM-SETUP.md` の Step 1-2 を要約提示。

### 5-3. スナップショット確認
```bash
"$VMRUN_PATH" -T ws listSnapshots "$VM_VMX_PATH" 2>/dev/null
```
`clean_with_tools` 未検出 → スナップショット作成手順を案内。

### 5-4. ゲストツール確認（ユーザー確認必須）
AskUserQuestion: 「VM を起動してゲスト内ツールの存在を確認しますか？」

承認後:
```bash
bash tools/vmware-sandbox/sandbox.sh start
bash tools/vmware-sandbox/sandbox.sh guest-tools
```
不足ツール検出時 → AskUserQuestion: 「setup-guest で自動インストールしますか？」
承認後: `bash tools/vmware-sandbox/sandbox.sh setup-guest`

### 5-5. ネットワーク・接続確認
```bash
bash tools/vmware-sandbox/sandbox.sh net-status
bash tools/vmware-sandbox/sandbox.sh status
```
Host-Only でない場合は警告表示。

---

## Step 6: 最終検証サマリー

すべてのステップ完了後、環境全体を再診断（Phase 0 と同じチェックを並列実行）して結果を表示:

```
============================================
  Toolkit Setup 完了サマリー
============================================
[OK] .env               設定済み（QUARANTINE_PASSWORD, VT_API_KEY, ...）
[OK] Docker Desktop      起動中
[OK] proxy-web-browser   ビルド済み
[OK] ghidra-headless     コンテナ実行中
[OK] YARA rules          ダウンロード済み
[OK] yara-python         インストール済み
[OK] flare-capa          インストール済み
[--] VMware Sandbox      未設定（任意）

次のステップ:
- proxy-web: proxy-web.exe "http://example.com"
- ghidra-headless: bash tools/ghidra-headless/ghidra.sh analyze <binary>
- vmware-sandbox: bash tools/vmware-sandbox/sandbox.sh analyze <binary>
============================================
```
