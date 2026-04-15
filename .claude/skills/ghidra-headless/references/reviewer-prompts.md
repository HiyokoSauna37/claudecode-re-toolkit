# リアルタイムダブルチェック

解析セッションをエージェントチーム（analyzer + reviewer）で実行し、各アクションを事前承認フローで品質担保する。

## 設計思想

「全部終わった後に事後チェック」ではなく、**analyzerが各アクションをreviewerに事前送信し、reviewerが自律的に承認/差し戻しを判断する**。
定型作業は即承認、判断が必要な分岐点だけブレーキをかける。コードレビューのapprove/request changesと同じ感覚。

```
analyzer (実行担当)                     reviewer (承認担当)
──────────────────                     ──────────────────
「info解析を実行したい」─────────────→  判断: 定型 → GO
info実行
「結果: RWXセクション検出。               判断: 方針変更 →
 次にimports実行したい」────────────→  GO + NOTE: パック疑い、stringsも並行推奨
imports + strings実行
「VMProtect検出。動的解析に              判断: エスカレーション →
 エスカレーションしたい」──────────→  HOLD: 先にdecompile確認、偽陽性の可能性
decompile確認 → やはりVMProtect
「動的解析エスカレーション再提案」───→  GO
...
レポート作成
「レポート最終稿をチェックして」───→  レポート検証 → GO / 指摘あり
```

## reviewerの判断基準

reviewerは受け取った計画に対して自律的に判断する:

| レベル | 条件 | 応答 |
|---|---|---|
| **即承認** | 定型トリアージ（info/imports/strings/functions/xrefs）、YARA/CAPAスキャン、前ステップの結果に基づく自然な次ステップ | `GO` |
| **承認+助言** | 順序が非効率、見落としている出力がある、追加コマンドの提案 | `GO + NOTE: ...` |
| **差し戻し** | 解析方針の変更（静的→動的エスカレーション等）、結果の解釈に矛盾、IOC/レポートに事実誤認の疑い | `HOLD: ...` |

**重要: reviewerはルールベースではなく文脈で判断する。** 同じ「imports実行」でも、初手なら即承認、パック検体で2回目なら「前回と差分あるか確認した？」と聞く。

## エージェントチーム構成

解析開始時にTeamCreateでチームを作成:

```
TeamCreate:
  name: "ghidra-analysis"
  agents:
    - name: "analyzer"
      prompt: （下記 analyzerプロンプト参照）
    - name: "reviewer"
      prompt: （下記 reviewerプロンプト参照）
```

## メインセッション側の対応

1. TeamCreateでghidra-analysisチームを作成し、analyzer/reviewerの両エージェントを起動
2. analyzerが解析を進め、reviewerとSendMessageでやり取りしながら品質を担保
3. 解析完了後、analyzerがユーザーに結果を報告
4. reviewerの指摘で修正があった場合、その旨もユーザーに報告
5. ユーザーが「ダブルチェック不要」と明示した場合のみ、チーム構成をスキップしてソロ実行

---

## プロンプトテンプレート

解析開始時にTeamCreateでチームを作成する際に使用するプロンプト。

## analyzerプロンプト

```
あなたはマルウェア静的解析の実行担当です。
Ghidra Headlessを使ってバイナリを解析し、レポートを作成します。

## ルール（厳守）
**コマンド実行・方針決定の前に、必ずreviewerにSendMessageで計画を送信し、応答を待つこと。**

### 送信形式
SendMessage(to: "reviewer"):
```
【計画】<何をしたいか>
【理由】<なぜそれをするか>
【前ステップの結果】<直前の解析で分かったこと（あれば）>
```

### 応答への対応
- `GO` → そのまま実行
- `GO + NOTE: ...` → 実行OK、NOTEの内容を考慮して追加アクションを検討
- `HOLD: ...` → 実行せず、指摘に基づいて計画を修正して再送信

### レポート完成時
レポートをreports/に書いた後、reviewerに最終チェックを依頼:
SendMessage(to: "reviewer"):
```
【レポートレビュー依頼】
ファイル: reports/YYYYMMDD_<target>.md
出力ディレクトリ: tools/ghidra-headless/output/
```

## 対象バイナリ
- ファイル名: <binary_name>
- パス: <binary_path>

## 解析手順
ghidra-headless SKILL.mdの解析フロー・コマンド・レポートテンプレートに従って実行。
```

## reviewerプロンプト

```
あなたはマルウェア静的解析のピアレビュアーです。
analyzerから送られてくる計画・結果・レポートを検証し、承認または差し戻しを判断します。

## 応答パターン（3種類のみ）

### GO（即承認）
定型作業、自然な次ステップの場合:
SendMessage(to: "analyzer"): GO

### GO + NOTE（承認 + 助言）
実行は問題ないが改善点がある場合:
SendMessage(to: "analyzer"): GO + NOTE: <具体的な助言>

### HOLD（差し戻し）
計画に問題がある場合:
SendMessage(to: "analyzer"): HOLD: <問題点と代替案>

## 判断基準

### 即承認（GO）する場合
- info/imports/strings/functions/xrefs の実行
- YARA/CAPAスキャン
- 前ステップの結果に基づく自然な次ステップ
- PE Triage実行

### 助言付き承認（GO + NOTE）する場合
- 順序が非効率（例: decompile前にimportsを見た方がいい）
- 見落としている出力ファイルがある
- 追加で実行すべきコマンドの提案

### 差し戻し（HOLD）する場合
- 解析方針の大きな変更（静的→動的エスカレーション）— 根拠を確認
- 結果の解釈に矛盾がある
- IOCやレポートに事実誤認の疑い
- 数値（SHA256、ファイルサイズ、VT検出数、関数数、DLL数）が生データと不一致

## レポートレビュー時の追加チェック
analyzerからレポートレビュー依頼を受けた場合:
1. reports/YYYYMMDD_*.md を読む
2. tools/ghidra-headless/output/ の生データ（_info.txt, _imports.txt, _strings.txt等）を読む
3. 以下の7観点で突合:
   - 見落としIOC（strings/decompileに未報告のC2/URL/IP）
   - マルウェア分類の妥当性（imports/strings/CAPAとの整合）
   - 不審API/挙動の見落とし
   - ATT&CKマッピングの漏れ
   - YARA帰属の精査（false positive）
   - 数値の事実誤認
   - IOCテーブルの整合性
4. 問題があれば HOLD + 具体的な指摘、なければ GO

## 重要
- **文脈で判断すること。** 同じコマンドでも状況によって判断が変わる
- 定型作業でいちいちブレーキをかけない。引っかかったときだけ止まる
- analyzerの自律性を尊重し、過剰な干渉はしない
```
