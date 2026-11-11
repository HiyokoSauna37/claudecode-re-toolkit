---
name: toolkit-setup
description: |
  マルウェア解析ツールキットの初回セットアップおよび再セットアップを実行する。前提条件チェック、.env作成、Dockerイメージビルド、YARA/CAPA/FLOSS/dumpulatorインストール、VMware環境構築ガイドを含む。
  Use when: "セットアップ", "setup", "初期設定", "環境構築", "toolkit-setup", ".envを作りたい", "Dockerビルド", "再セットアップ", "VMware設定", ".env編集", "FLOSS", "dumpulator"
  Do NOT use for: マルウェア解析の実行（malware-fetch / ghidra-headless / malware-sandbox を使用）、検体固有の解析失敗の調査
  （※ Docker イメージ・コンテナ・依存パッケージなど**環境側の不調**は本スキルの Troubleshooting 節が扱う。
  「特定の検体だけ解析が失敗する」は環境ではなく解析側の問題なので各解析スキルへ回す）
instructions: |
  1. Phase 0 — 環境診断: 以下を並列実行して現状を把握
     .env存在確認, docker info, docker images/ps, vmrun.exe の存在確認, go/python version, yara-rules/ 存在, pip show yara-python/flare-capa/flare-floss/dumpulator
     （実行するコマンドは本文 Step 1 のコードブロックが正）
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
test -f .env && echo present                                      # .env 存在（**中身は絶対に表示しない** — 上の CRITICAL 参照）
docker info > /dev/null 2>&1                                      # Docker Desktop
docker images malware-fetch-browser:latest --format "{{.ID}}"         # malware-fetch イメージ
docker images ghidra-headless-ghidra:latest --format "{{.ID}}"       # ghidra-headless イメージ
docker ps -a --filter "name=ghidra-headless" --format "{{.Status}}" # ghidra コンテナ
docker images dotnet-decompiler-dotnet-decompiler:latest --format "{{.ID}}"  # dotnet-decompiler イメージ
ls "C:/Program Files (x86)/VMware/VMware Workstation/vmrun.exe" 2>/dev/null  # VMware
go version 2>/dev/null                                            # Go
python --version 2>/dev/null                                      # Python
ls tools/ghidra-headless/yara-rules/ 2>/dev/null                  # YARA rules
pip show yara-python 2>/dev/null                                  # yara-python
pip show flare-capa 2>/dev/null                                   # flare-capa（malware-sandbox 用。ghidra-headless はイメージ内に同梱済み）
pip show flare-floss 2>/dev/null                                  # flare-floss（malware-sandbox 用。ghidra-headless はイメージ内に同梱済み）
pip show dumpulator 2>/dev/null                                   # dumpulator (新機能)
```

**OK / NG の判定基準**（これで判定する。exit code ではなく出力の有無で見る）:

| コマンド | `[OK]` とする条件 | `[!!]` とする条件 |
|---|---|---|
| `test -f .env && echo present` | `present` が出る | 出力が空（ファイルなし） |
| `docker info` | exit 0 | exit 非0 |
| `docker images ... --format "{{.ID}}"` | ID が出力される | 出力が空 |
| `docker ps -a --filter ...` | Status が **`Up ...` で始まる** | 出力が空（未作成）**または `Exited` / `Created`（作成済みだが起動していない）** |
| `ls .../vmrun.exe` | パスが出力される | 出力が空 |
| `go version` / `python --version` | バージョン文字列が出て、かつ **Python 3.10+ / Go 1.26+** を満たす | 出力が空、または要求バージョン未満 |
| `ls .../yara-rules/` | 1件以上のエントリ | 出力が空 |
| `pip show <pkg>` | `Name:` 行を含む出力がある | **出力が空**（未インストール。`pip show` は未インストールでも exit 0 を返すので exit code で判定しないこと） |

**`docker info` が NG のときは、image / container の3行を `[!!]`（未ビルド・未作成）と判定してはいけない。**
デーモンが止まっていると `docker images` / `docker ps` はどちらも空を返すので、「未ビルド」と「判定不能」が区別できない。
この場合は `[??] 判定不能（Docker 停止中）` と表示する。
なお Docker Desktop の起動直後はデーモンがまだ応答しないことがあるため、`docker info` が NG なら
**1 度だけ数秒待って再実行**し、それでも NG のときに初めて「停止中」と確定させる。

`.env` の判定は **ファイルが存在するかどうかだけ**で、各キーに値が入っているかは見ていない。
「どの API が実際に使えるか」まで必要なら threat-intel スキルの `status` か
`tools/malware-fetch/malware-fetch.exe preflight` を使う（本 Phase 0 の範囲外）。

診断結果は **まずユーザー向けにそのまま画面表示する**（Phase 1 の質問文に埋め込むのではなく、
Phase 1 に進む前の独立した出力とする）。Phase 1 の Q2 では、この結果を「(済)」表記の根拠として参照する。

**実際のイメージ名／コンテナ名の対応**（`docker images` の出力と突き合わせるときに使う）:

| SKILL.md 上の呼び名 | 実イメージ名 | コンテナ名 |
|---|---|---|
| malware-fetch イメージ | `malware-fetch-browser:latest` | （都度起動・破棄） |
| ghidra-headless | `ghidra-headless-ghidra:latest`（compose のプロジェクト名+サービス名由来） | `ghidra-headless` |
| dotnet-decompiler | `dotnet-decompiler-dotnet-decompiler:latest` | `dotnet-decompiler` |

診断結果を以下の形式で表示:
```
環境診断結果:
[OK] Docker Desktop      起動中
[!!] .env               未作成
[OK] malware-fetch-browser   ビルド済み
[!!] ghidra-headless     未作成
[??] dotnet-decompiler   判定不能（Docker 停止中）
...
```
Phase 0 の画面表示で使う記号は `[OK]` / `[!!]` / `[??]` の3種のみ。
**(済) / (一部未) / (未) は Q2 の選択肢ラベル専用**で、Phase 0 の表示には出さない。

### Step 2: モード選択（Phase 1）

AskUserQuestion で以下を確認:

**Q1: セットアップモード**（header: "モード"）
| 選択肢 | メリット | デメリット |
|--------|----------|------------|
| 対話型ウィザード | 1ステップずつ確認。安心。途中キャンセル容易 | 確認回数が多く時間がかかる |
| 一括セットアップ | 全体計画を提示→承認後に一気に実行。速い | 個別ステップの細かい調整がしにくい |

**Q2: セットアップ範囲**（header: "範囲", multiSelect: true）
デフォルト選択は **ユーザーの依頼内容が具体的かどうか** で決める（Examples 節の各例もこの規則に従っている）:

- **依頼が特定コンポーネントを名指ししている場合**（例:「ghidra-headless を作り直したい」）
  → **その項目だけ**をデフォルト選択にする。他の未セットアップ項目は選択肢として提示はするがデフォルトには含めない
  - **名指しされたコンポーネントが複数行に分かれている場合**（ghidra-headless = イメージビルド行 + コンテナ起動行）:
    **軽い方（コンテナ起動＝再作成）だけをデフォルト選択**にし、イメージビルド行は選択肢として並べる。
    コンテナ再作成は数秒・低リスクで済み、それで直らなければイメージ再ビルドに上げればよいため。
    **デフォルト選択にすることと、実行してよいことは別**。Troubleshooting の「症状を確認してから提案する」は
    Phase 2（実行）に掛かる制約なので、Q2 でデフォルト選択に入れたうえで、実行前に症状を聞けばよい
    ユーザーが「イメージを作り直したい」「Dockerfile を変えた」と明示した場合のみイメージビルド行をデフォルトにする
- **依頼が「セットアップして」「診断して」など範囲を特定していない場合**
  → Phase 0 で `[!!]` だった **未セットアップ項目すべて**をデフォルト選択にする

いずれの場合も、セットアップ済み項目は「(済)」と明記し、再セットアップの選択肢として残す。
**「(済)」の行でもデフォルト選択にしてよい** — 名指し規則が (済)/(未) より優先する
（「動いているのに調子が悪い」類の依頼では、対象は必ず (済) の行になるため）。

**Q1 の既定は「対話型ウィザード」**。環境を壊す操作を含むので、明示的に「一括で」と言われた時だけ一括にする。

**「(済)」の粒度**: Q2 の選択肢は下のリストの**行単位**で扱う（サブ項目に分割しない）。表記は 3 通り:

| 行内の状態 | 表記 |
|---|---|
| 実体がすべて `[OK]` | **(済)** |
| 一部が `[OK]`、一部が `[!!]` | **(一部未)** |
| 実体がすべて `[!!]` | **(未)** |
| 実体に `[??]`（判定不能）が含まれる | **(判定不能)** — Docker を起動して再診断するまで Q2 の選択肢として出さない |

各行がどの診断項目に対応するかは下のリストの「判定対象」を見る。
**`go version` / `python --version` / `docker info` はセットアップ対象ではなく前提条件のチェック**なので、
Q2 のどの行にも対応しない（`[!!]` なら Q2 ではなくユーザーへの前提不足として報告する）。
`docker info` が NG のときは Docker Desktop の起動そのものが先で、Q2 に進む前に解決する。
（Python 3.11+ が要るのは任意コンポーネントの x64dbg-automate だけ。3.10 系でも既定のセットアップは成立するので
`[!!]` にはせず、x64dbg-automate を使う場合のみ前提不足として案内する）
| Q2 の行 | 判定対象（Phase 0 の項目） |
|---|---|
| .env 作成/編集 | `.env` |
| Docker: malware-fetch イメージビルド | `malware-fetch-browser:latest` |
| Docker: ghidra-headless **イメージビルド** | `ghidra-headless-ghidra:latest` の有無（`docker images`） |
| Docker: ghidra-headless **コンテナ起動** | `ghidra-headless` コンテナの Status（`docker ps -a`） |
| Docker: dotnet-decompiler イメージビルド | `dotnet-decompiler-dotnet-decompiler:latest` の有無（`docker images`） |
| YARA ルール/yara-python セットアップ | yara-rules ディレクトリ + `yara-python` |
| capa/FLOSS/dumpulator セットアップ（ホスト側） | `flare-capa` + `flare-floss` + `dumpulator`（すべて malware-sandbox 用のホスト側インストール） |
| VMware Sandbox 環境構築ガイド | `vmrun.exe` の存在のみ。**VM 本体の構築状況は Phase 0 では判定しない**ため、この行は「(済)」でも「ガイドを読み直す」選択肢として常に**提示**する（ただし**デフォルト選択には入れない**）。`vmrun.exe` が [OK] でも VM・スナップショットが整っている保証は無いので、「(済)」を「動的解析が使える」と読ませないこと |

- **イメージとコンテナを別行にしている理由**: Troubleshooting 節のとおり「イメージ再ビルド」と「コンテナ再作成」は別作業。
  ユーザーが「イメージを作り直したい」と言った場合はイメージビルド行、「コンテナが起動しない」ならコンテナ起動行を選ぶ
- FLOSS/dumpulator は `pip install flare-floss dumpulator` — **malware-sandbox 用のホスト側インストール**。
  **references/ の手順は flare-capa しか扱っていないので、この pip 行が正**（references 側の欠落を待たずにこれを使う）。
  導入確認は `pip show flare-floss dumpulator` で `Name:` 行が出ること。
  ghidra-headless の capa/FLOSS は Dockerfile でピン止め済み（flare-capa 9.4.0 / flare-floss 3.1.1 + capa ルール同梱）なのでホストには不要

### Step 3: 手順実行（Phase 2）

選択されたモードの reference を Read して手順に従う:
- **対話型**: `references/interactive-setup.md`
- **一括型**: `references/batch-setup.md`

**任意コンポーネント（既定のセットアップには含めない）**: x64dbg-automate による Level 3 デバッガ自動制御。
ホスト側は Python **3.11+** と `pip install "x64dbg_automate==0.9.2"`（**必ず `==` でピン**）、
ゲスト側はプラグイン `v0.8.1-ghost_fungus` の配置と `x64dbg.ini` への `[XAutomate] Mode=remote` 追記が要る。
`.env` の `VM_X64DBG_HOST` / `VM_X64DBG_REQ_PORT` / `VM_X64DBG_PUB_PORT` を併せて設定する。
手順は `tools/malware-sandbox/docs/VM-SETUP.md` の «Step 3.5»、検証は
`python tools/malware-sandbox/x64dbg_driver.py --selftest`（VM 不要）。

## Examples

### 初回セットアップ（典型的な流れ）

```
ユーザー: "セットアップして"
→ Phase 0: 環境診断（.env未作成、Docker起動中、他は未セットアップ）
→ Phase 1: モード選択 → 対話型、全項目選択
→ Phase 2: .env作成 → malware-fetchビルド → ghidra起動 → YARA/CAPA → VMware確認
→ 最終サマリー表示
```

### 再セットアップ（Dockerイメージ更新）

```
ユーザー: "Dockerイメージを再ビルドしたい"
→ Phase 0: 環境診断（.env済、Docker済、ghidra済）
→ Phase 1: モード選択 → Docker: malware-fetch のみ選択
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

### コンテナは `Up` なのに調子が悪い

`docker ps` が `Up` でも中が壊れていることがある。上の「起動しない」手順は使えないので、この順で切り分ける:

```
1. docker exec ghidra-headless echo ok                      # 疎通確認。失敗 → コンテナ再作成
2. docker logs ghidra-headless                              # 空ならコンテナ側のエラーは出ていない
3. docker inspect -f '{{.Created}}' ghidra-headless         # コンテナ作成時刻
   docker inspect -f '{{.Created}}' ghidra-headless-ghidra:latest   # イメージ作成時刻
   # コンテナの方が古い = イメージ更新が未反映 → イメージ再ビルド + --force-recreate
   # コンテナの方が新しい = 反映済み。ここは正常で、再ビルドの理由にはならない
```
**各手順の解釈**: 手順1 が `ok` を返せば疎通は正常。手順2 の `docker logs` は **空が正常**
（何か出ていればその内容が一次情報なので、それを起点に調べる）。手順3 は **コンテナがイメージより新しければ正常**。

**1〜3 がすべて正常だった場合**、原因はコンテナの外にある。次の順で当たる:
1. **メモリ**: Ghidra は `MAXMEM=4G` を要求する。**判定は Docker Desktop の割当が 4GB を明確に超えているか**:
   ```bash
   docker info --format '{{.MemTotal}}'   # Docker に割り当てられた総メモリ（bytes）
   ```
   **6GB 未満なら要因候補**（4GB のヒープに加えて JVM 以外の使用分が乗るため）。
   実使用を見るなら `docker stats ghidra-headless` を**解析実行中に別ターミナルで**回す。
   待機中は数十 MiB しか出ないので、止まっている状態で測っても意味がない
2. **解析タイムアウト**: `ghidra.sh` 冒頭の `TIMEOUT=300`（秒）に当たると
   `ERROR REPORT: Analysis timed out at 300 seconds` が**コマンドの標準出力**に出る。
   **これは失敗ではなく打ち切りで、出力ファイルは生成される。**
   「途中で落ちる」がこれに該当するかは、その文言が出ているかと、
   `tools/ghidra-headless/output/` に成果物が出来ているかで判別する。
   延ばすなら `tools/ghidra-headless/ghidra.sh` の `TIMEOUT=300` を直接書き換える
   （環境変数での上書きには対応していない）
3. **検体固有**: 特定の検体でだけ失敗するなら環境ではなく解析側の問題。**本スキルの範囲外**なので
   ghidra-headless スキルへ回す

いずれの場合も **どのコマンドがどう失敗するのか（コマンド全文・エラー全文・検体の種別とサイズ）を
ユーザーに確認してから**再作成・再ビルドを提案すること（症状不明のまま 4GB のイメージを作り直させない）。

**「コンテナ再作成」と「イメージ再ビルド」は別物**（ユーザーが「作り直したい」と言ったときはどちらか確認する）:

| やりたいこと | コマンド |
|---|---|
| コンテナだけ作り直す（イメージはそのまま。起動不良の復旧用） | `docker compose -f tools/ghidra-headless/docker-compose.yml down && docker compose -f tools/ghidra-headless/docker-compose.yml up -d` |
| **イメージから再ビルド**（Dockerfile 変更・Ghidra/capa のバージョン更新を反映） | `docker compose -f tools/ghidra-headless/docker-compose.yml build` → `... up -d --force-recreate` |
| キャッシュを捨てて完全再ビルド（`--no-cache` の要否はユーザーに確認） | 上記 `build` に `--no-cache` を付与 |

### VMware vmrun が応答しない

```
症状: vmrun -T ws list がハングまたはエラー
よくある原因:
- VMware Workstation サービスが未起動
- vmrun.exe のパスが不正
解決:
1. VMRUN_PATH が正しいか確認
2. VMware Workstation を起動してから再実行
3. 詳細は references/guides/troubleshooting.md（malware-sandbox スキル）を参照
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
