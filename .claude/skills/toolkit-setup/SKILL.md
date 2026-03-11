---
name: toolkit-setup
description: |
  マルウェア解析ツールキットの初回セットアップおよび再セットアップを実行する。前提条件チェック、.env作成、Dockerイメージビルド、YARA/CAPAインストール、VMware環境構築ガイドを含む。
  Use when: "セットアップ", "setup", "初期設定", "環境構築", "toolkit-setup", ".envを作りたい", "Dockerビルド", "再セットアップ", "VMware設定", ".env編集"
  Do NOT use for: マルウェア解析の実行（proxy-web / ghidra-headless / vmware-sandbox を使用）、個別ツールのトラブルシューティング
instructions: |
  1. Phase 0 — 環境診断: 以下を並列実行して現状を把握
     .env存在確認, docker info, docker images/ps, vmrun list, go/python version, yara-rules/ 存在, pip show yara-python/flare-capa
  2. Phase 1 — モード選択: AskUserQuestion で2問確認
     Q1: セットアップモード（対話型 or 一括）をメリット・デメリット付きで提示
     Q2: セットアップ範囲（multiSelect）。診断結果に基づきセットアップ済み項目を明記
  3. Phase 2 — 実行: 選択モードの reference を Read して手順に従う
     対話型 → references/interactive-setup.md
     一括型 → references/batch-setup.md
  CRITICAL: 環境を変更する操作の前には必ず AskUserQuestion でユーザー確認を取ること
  CRITICAL: .env のパスワード・APIキーは画面にマスク表示（****）すること
metadata:
  author: shimakaze-git
  version: 1.0.0
  category: setup
---

# Toolkit Setup

## Instructions

### Step 1: 環境診断（Phase 0）

以下を**すべて並列で**実行し、各コンポーネントの状態を判定する:

```bash
# 並列実行（すべて独立）
cat .env 2>/dev/null | head -1                                    # .env 存在
docker info > /dev/null 2>&1                                      # Docker Desktop
docker images proxy-web-browser:latest --format "{{.ID}}"         # proxy-web イメージ
docker ps -a --filter "name=ghidra-headless" --format "{{.Status}}" # ghidra コンテナ
ls "C:/Program Files (x86)/VMware/VMware Workstation/vmrun.exe" 2>/dev/null  # VMware
go version 2>/dev/null                                            # Go
python --version 2>/dev/null                                      # Python
ls tools/ghidra-headless/yara-rules/ 2>/dev/null                  # YARA rules
pip show yara-python 2>/dev/null                                  # yara-python
pip show flare-capa 2>/dev/null                                   # flare-capa
```

診断結果を以下の形式で表示:
```
環境診断結果:
[OK] Docker Desktop      起動中
[!!] .env               未作成
[OK] proxy-web-browser   ビルド済み
[!!] ghidra-headless     未作成
...
```

### Step 2: モード選択（Phase 1）

AskUserQuestion で以下を確認:

**Q1: セットアップモード**（header: "モード"）
| 選択肢 | メリット | デメリット |
|--------|----------|------------|
| 対話型ウィザード | 1ステップずつ確認。安心。途中キャンセル容易 | 確認回数が多く時間がかかる |
| 一括セットアップ | 全体計画を提示→承認後に一気に実行。速い | 個別ステップの細かい調整がしにくい |

**Q2: セットアップ範囲**（header: "範囲", multiSelect: true）
Phase 0 の結果に基づき、未セットアップ項目をデフォルトで含める。
セットアップ済み項目は「(済)」と明記し、再セットアップの選択肢として残す。
- .env 作成/編集
- Docker: proxy-web イメージビルド
- Docker: ghidra-headless コンテナ起動
- YARA/CAPA セットアップ
- VMware Sandbox 環境構築ガイド

### Step 3: 手順実行（Phase 2）

選択されたモードの reference を Read して手順に従う:
- **対話型**: `references/interactive-setup.md`
- **一括型**: `references/batch-setup.md`

## Examples

### 初回セットアップ（典型的な流れ）

```
ユーザー: "セットアップして"
→ Phase 0: 環境診断（.env未作成、Docker起動中、他は未セットアップ）
→ Phase 1: モード選択 → 対話型、全項目選択
→ Phase 2: .env作成 → proxy-webビルド → ghidra起動 → YARA/CAPA → VMware確認
→ 最終サマリー表示
```

### 再セットアップ（Dockerイメージ更新）

```
ユーザー: "Dockerイメージを再ビルドしたい"
→ Phase 0: 環境診断（.env済、Docker済、ghidra済）
→ Phase 1: モード選択 → Docker: proxy-web のみ選択
→ Phase 2: キャッシュ有無を確認 → 再ビルド → 検証
```

### .env の部分編集

```
ユーザー: ".envのVT APIキーを変更したい"
→ Phase 0: .env存在確認
→ Phase 1: .env作成/編集 のみ選択
→ Phase 2: 既存値をマスク表示 → 変更項目を確認 → 差分適用
```

## Troubleshooting

### Docker Desktop が起動していない

```
症状: docker info が失敗
原因: Docker Desktop が未起動またはWSL2バックエンドが未設定
解決: Docker Desktop を起動してから /toolkit-setup を再実行
```

### Docker ビルドが失敗する

```
症状: docker build がエラーで停止
よくある原因:
- ネットワーク接続不良（パッケージダウンロード失敗）
- ディスク容量不足
解決:
1. docker system prune で不要イメージを削除
2. ネットワーク接続を確認して再実行
3. --no-cache オプションで再ビルド
```

### ghidra-headless コンテナが起動しない

```
症状: docker compose up -d 後に docker exec が失敗
よくある原因:
- ポート競合
- メモリ不足（MAXMEM=4G が必要）
解決:
1. docker logs ghidra-headless でエラー確認
2. docker compose -f tools/ghidra-headless/docker-compose.yml down && up -d で再作成
```

### VMware vmrun が応答しない

```
症状: vmrun -T ws list がハングまたはエラー
よくある原因:
- VMware Workstation サービスが未起動
- vmrun.exe のパスが不正
解決:
1. VMRUN_PATH が正しいか確認
2. VMware Workstation を起動してから再実行
3. 詳細は references/troubleshooting.md（vmware-sandbox スキル）を参照
```

### .env の既存値を上書きしてしまった

```
症状: .env の値が意図せず変更された
解決: git checkout .env で復元（.gitignoreに含まれる場合は不可）
予防: このスキルは既存 .env を上書きせず差分提案のみ行う設計
```

## セキュリティルール

- .env 内の機密情報（パスワード、APIキー）は表示時に必ずマスクする
- 既存の .env がある場合は上書きせず、差分のみ提案する
- Docker イメージの再ビルドは --no-cache の要否をユーザーに確認する
- VMware VM の起動・操作は必ずユーザー確認を取る
