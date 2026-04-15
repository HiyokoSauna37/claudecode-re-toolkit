---
name: sync-skills
description: >-
  ~/.claude/skills/ から本リポジトリの .claude/skills/ へスキルを同期し、README更新・commit・pushまで一括実行する。
  Use when: "スキル同期", "sync skills", "スキル更新", "skill sync", "最新化", "/sync-skills"
  Do NOT use for: スキルの新規作成、スキルレビュー（skill-reviewerを使用）
instructions: |
  ## 実行フロー

  1. 差分検出: ソースとターゲットの全スキルを比較
  2. サニタイズ付きコピー: パス修正・個人情報除去しながら更新
  3. README更新: EN/JP両方のスキル説明を更新
  4. commit & push

  ## 重要ルール
  - **個人情報を絶対に含めない**（外部公開リポジトリ）
  - パスケーシング: ソース側の `Tools/` は本リポジトリの `tools/` に変換
  - プレースホルダ化: 具体的ユーザーパス → `<GUEST_TOOLS>`, `<GUEST_ANALYSIS_DIR>` 等
  - ソースのみの変更を取り込む。ターゲット側独自の修正（小文字パス等）は維持
---

# Sync Skills

`~/.claude/skills/` の最新スキル定義を本リポジトリ（`.claude/skills/`）に同期するスキル。

## ソースとターゲット

| | パス |
|---|---|
| **ソース（最新）** | `C:\Users\xxxxx\.claude\skills\` |
| **ターゲット（本リポ）** | `.claude/skills/` |

## 同期対象スキル

本リポジトリに存在する以下のスキルのみ同期する:

| スキル | 説明 |
|---|---|
| ghidra-headless | Ghidra静的解析 |
| proxy-web | Web安全アクセス＆フォレンジック |
| vmware-sandbox | VMware動的解析 |
| toolkit-setup | セットアップウィザード |

**ソースにのみ存在するスキル（bug-bounty, gandalf等）は同期対象外。**

## Step 1: 差分検出

各スキルについて、Agent(subagent_type=Explore) で以下を比較:
- SKILL.md の差分
- kb-entries.md の差分（存在する場合）
- references/ ディレクトリの差分（新規ファイル、変更ファイル）

**出力**: スキルごとの変更サマリ（何が変わったか、新規ファイルは何か）

## Step 2: サニタイズルール

コピー時に以下の変換を適用する:

### パスケーシング
```
Tools/ghidra-headless/ → tools/ghidra-headless/
Tools/proxy-web/       → tools/proxy-web/
Tools/vmware-sandbox/  → tools/vmware-sandbox/
Tools/dotnet-decompiler/ → tools/dotnet-decompiler/
Tools/url-probe/       → tools/url-probe/
Tools/quarantine/      → tools/quarantine/
```

### 個人情報除去
以下のパターンをプレースホルダまたは汎用表現に置換:

| パターン | 置換先 |
|---|---|
| `C:\Users\malwa\...` | `<GUEST_TOOLS>` or 汎用パス |
| `C:\Users\xxxxx\...` | 除去またはプレースホルダ |
| `malware-hunt@outlook.jp` | 除去 |
| `"malwa"→"malware"部分一致` | 汎用的な説明に |
| 具体的なFakeNetパス `C:\Users\malwa\Desktop\tools\fakenet\...` | `<GUEST_TOOLS>/fakenet/...` |
| 具体的なメールアドレス (`*@outlook.*`, `*@gmail.*` 等) | 除去 |

### コンテンツ判定
- **技術的IOC**（C2 IP、マルウェアドメイン、SHA256等）: そのまま残す（公開情報）
- **解析ナレッジ**（マルウェアファミリ特徴、C2プロトコル等）: そのまま残す
- **日付付きのユーザー固有メモ**: 個人情報でなければ残す

## Step 3: ファイル更新

### SKILL.md更新
- ソースが全面リライトの場合: Write で全置換（サニタイズ適用済み）
- ソースが部分変更の場合: Edit で差分のみ適用

### kb-entries.md更新
- 新規KBエントリのみ追記（既存エントリの `tools/` 小文字パスは維持）
- KB内の具体的ユーザーパスはサニタイズ

### references/ 更新
- 新規ファイル: Write で作成（サニタイズ適用）
- 既存ファイル: 意味のある内容変更のみ適用（パスケーシングだけの差分はスキップ）

## Step 4: README更新

`README.md`（EN）と `README_JP.md`（JP）の以下セクションを更新:

1. **機能一覧テーブル**: 各スキルの description 列を最新化
2. **アーキテクチャ図**: 新機能があれば行を追加
3. **ツール詳細セクション**: 各スキルの機能リストを最新化

### 更新の判断基準
- スキルのdescriptionやfrontmatterに新しいキーワードが追加された → テーブル更新
- 新しい大機能が追加された（例: .NETデコンパイル、DispatchLogger） → 詳細セクション更新
- 既存機能の微修正のみ → README変更不要

## Step 5: Commit & Push

```bash
git add .claude/skills/<changed_skills>/ README.md README_JP.md
git commit -m "update: sync skills from ~/.claude/skills to latest version

- <skill1>: <changes summary>
- <skill2>: <changes summary>

Co-Authored-By: Claude <model> <noreply@anthropic.com>"

git push
```

## 個人情報チェック（最終確認）

push前に以下のgrepで個人情報が含まれていないことを確認:

```bash
grep -r "malwa@\|malware-hunt@\|@outlook\.\|@gmail\.\|@yahoo\.\|C:\\\\Users\\\\malwa\|C:\\\\Users\\\\shima" .claude/skills/ --include="*.md" -l
```

ヒットがあれば修正してからpush。`shimakaze-git`（公開GitHubユーザー名）は許容。

## 注意事項

- vmware-sandbox の references/ はパスケーシング差分(`Tools/` vs `tools/`)と具体的ユーザーパス差分が多い。**意味のある内容変更のみ**適用し、パスケーシングだけの差分はターゲット側（`tools/` 小文字）を維持
- ソース側の `clean_with_tools` スナップショット名 vs ターゲット側の `クリーン`: ソースの命名に合わせる（英語化）
- kb-entries.md の既存エントリ内パスは書き換えない（既にlowercaseで正しい）
