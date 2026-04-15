# 解析レポート執筆ガイド

## スタイル: watchTowr Labs風ナラティブ（必須）

**レポート執筆時は必ず `watchtowr-report` スキルを読み込むこと。**
スキルにはスタイルガイド（Voice, Humor Patterns, Section Structure, Anti-Patterns等）が含まれている。

```
Skill tool → skill: "watchtowr-report"
```

## レポート生成のタイミング

analyze-fullパイプライン完了後、またはユーザーが「レポート作成」を指示した時点で:

1. `watchtowr-report` スキルを読み込む
2. `tools/ghidra-headless/output/` の生データ + OSINT結果を収集
3. テンプレートに従いナラティブレポートを執筆
4. `reports/YYYYMMDD_<target_name>.md` に保存

## 必須コンテンツ（見出しはwatchtowr風に自由変更可）

| コンテンツ | 必須 | 内容 |
|-----------|------|------|
| Opening + SHA256/VT引用 | 必須 | シーン設定 + 第一印象の皮肉 + OSINT結果 |
| Static Analysis | 必須 | Ghidra/CAPA/YARAの結果を研究過程として語る |
| Dynamic Analysis | 条件付 | VMware Sandbox実施時。「何が起きなかったか」も語る |
| Deep Dive | 必須 | 設定抽出、コマンドテーブル、暗号化方式 |
| Defense Evasion | 条件付 | AMSI bypass, 難読化等が確認された場合 |
| Disguise & Persistence | 必須 | 偽装・永続化の詳細 |
| Family Attribution | 必須 | 複数ソースからの証拠テーブル |
| What To Do, How To Live | 必須 | 即時対応 + Detection Rules + Hunting |
| IOC Summary | 必須 | Network/File/Host の3分類テーブル |
| MITRE ATT&CK | 必須 | Tactic / Technique / ID / Evidence の4列テーブル |
| Analysis Timeline | 必須 | 実施ステップ一覧 |
| Closing | 必須 | インパクトのある1文で終わる（正式な「結論」セクションは不要） |

## 自動解析結果の埋め込みルール

**「検出あり」「CAPAで判定」等の曖昧な記載は禁止。** 必ず具体的な出力をナラティブに織り込む:

1. **YARA**: マッチしたルール名・ソース・説明をテーブルで記載。0件の場合はルール数を明記し、検体固有のカスタムYARAルール案をDetectionセクションで提示
2. **CAPA**: capability名・namespace・ATT&CK IDをテーブルで列挙。ナラティブ中でも主要capabilityに言及
3. **ioc-extract**: カテゴリ別件数と主要IOCをテーブルで記載。手動抽出IOCはIOC Summaryセクションに記載
4. **classify**: 分類・スコア・根拠をテーブルで記載。手動判定と自動判定が異なる場合は両方記載し理由を説明

## IOC Summary形式（統一）

IOCは必ず以下の3分類テーブルで記載（コードブロック形式は禁止）:
- **Network**: Type / Value / Context
- **File**: Name / SHA256 / Context
- **Host**: Type / Value / Context（Registry, Mutex, Scheduled Task, File Path）

## ATT&CK形式（統一）

必ず4列: **Tactic / Technique / ID / Evidence**（3列は禁止）

## 解析レポートの保存先（厳守）

**重要: レポートは必ず以下のパスに保存すること。他の場所（notes/ 等）には絶対に保存しない。**

```
reports/YYYYMMDD_<target_name>.md
```

- **保存先: `reports/` ディレクトリ直下**（サブディレクトリは作らない）
- notes/ や notes/01_literature/malware/ には保存しない（過去に誤出力あり）
- proxy-web経由の場合、DL元URL・ランディングページ・VT結果など取得時の情報を必ずレポートに含める
- `tools/ghidra-headless/output/` には生の解析出力（テキスト/デコンパイル結果）を保存
- `reports/` にはそれをまとめた人間向けレポートを保存
