---
name: ghidra-headless
description: Ghidra Headless AnalyzerをDockerコンテナで実行し、バイナリの静的解析・デコンパイル・インポート分析を行う。Use when: バイナリ解析, デコンパイル, 静的解析, reverse engineering, マルウェア解析, CTF reversing, 逆アセンブル, EXE解析, DLL解析, 不審バイナリ
instructions: |
  スキル実行手順：
  1. コンテナ状態を確認: docker inspect -f '{{.State.Status}}' ghidra-headless
  2. 停止中なら起動: bash tools/ghidra-headless/ghidra.sh start
  3. ユーザーに「解析対象のバイナリパスを教えてください」と質問
  4. 指示に応じて解析コマンドを構築・実行
     **重要: .enc.gzファイルは全コマンドで直接渡せる。ghidra.shが自動検知してコンテナ内で復号する。**
     **ホスト上で復号化スクリプト(decrypt_quarantine.py等)を実行してはならない。**
     **ホスト上にopenssl/gunzip等で復号してはならない。**
  5. 結果をユーザーに報告し、次の指示を待つ
  6. 「終了」「exit」で解析セッション終了 → ログファイルをgit commit & push

  トリガー条件:
  - バイナリ解析、リバースエンジニアリング、マルウェア解析
  - EXE/DLL/ELF/SO/Mach-Oファイルの構造調査
  - CTFのreversing問題
  - 不審バイナリの静的解析
  - デコンパイル、逆アセンブル
  - forensic-analysisで発見された不審バイナリの深掘り

  ============================================================
  コマンドログ記録（必須）
  ============================================================
  解析実行時は必ずログを記録:
  tools/ghidra-headless/logs/YYYYMMDD_<target_name>.md

  ============================================================
  ツールパス
  ============================================================
  tools/ghidra-headless/ghidra.sh

  ============================================================
  基本操作
  ============================================================

  コンテナ管理:
  bash tools/ghidra-headless/ghidra.sh start    # ビルド＆起動
  bash tools/ghidra-headless/ghidra.sh stop     # 停止
  bash tools/ghidra-headless/ghidra.sh status   # 状態確認

  ============================================================
  YARA/CAPA セットアップ（初回のみ）
  ============================================================
  # YARAルールダウンロード
  bash tools/ghidra-headless/setup_yara_rules.sh

  # YARA Python
  pip install yara-python

  # CAPA
  pip install flare-capa
  capa --update-rules
---

## 解析コマンド

### 解析コマンド

フル解析（推奨: 全スクリプト一括実行）:
```bash
bash tools/ghidra-headless/ghidra.sh analyze <binary_path>
```

個別解析:
```bash
bash tools/ghidra-headless/ghidra.sh info <binary>       # アーキテクチャ、セクション、エントリーポイント
bash tools/ghidra-headless/ghidra.sh decompile <binary>  # 全関数のC疑似コード
bash tools/ghidra-headless/ghidra.sh functions <binary>  # 関数一覧（アドレス/サイズ）
bash tools/ghidra-headless/ghidra.sh strings <binary>    # 文字列＋クロスリファレンス
bash tools/ghidra-headless/ghidra.sh imports <binary>    # インポートテーブル（不審API自動フラグ）
bash tools/ghidra-headless/ghidra.sh exports <binary>    # エクスポートテーブル
bash tools/ghidra-headless/ghidra.sh xrefs <binary>      # クロスリファレンスレポート
```

### ポスト解析（YARA/CAPA/IOC抽出/分類）
```bash
bash tools/ghidra-headless/ghidra.sh yara-scan <binary>          # YARAスキャン（APT帰属・マルウェアファミリ判定）
bash tools/ghidra-headless/ghidra.sh capa <binary>               # CAPA解析（capability + MITRE ATT&CK マッピング）
bash tools/ghidra-headless/ghidra.sh ioc-extract <binary_name>   # IOC自動抽出（IP/Domain/URL/Hash/レジストリ等）
bash tools/ghidra-headless/ghidra.sh classify <binary_name>      # マルウェア種別自動分類（InfoStealer/Ransomware/RAT等）
bash tools/ghidra-headless/ghidra.sh analyze-full <binary>       # フルパイプライン（5段階）
```

- `yara-scan`: 生バイナリをYARAルールでスキャン。signature-base（APT帰属）+ yara-forge（5000+ルール）対応。Docker不要
- `capa`: Mandiant CAPAでマルウェアのcapability検出 + MITRE ATT&CK / MBCマッピング。Vivisectバックエンド、Docker不要
- `ioc-extract`: strings/imports/decompile出力からIOCを正規表現で抽出。Ghidraアーティファクト(FUN_/DAT_)・プライベートIP・Cランタイム文字列は自動除外。JSON + サマリー出力
- `classify`: imports/stringsの重み付きスコアリングでInfoStealer/Ransomware/RAT/Dropper/Loader/Wormを判定。パッカー検出(VMProtect/UPX/Themida)・アンチ解析検出も実行
- `analyze-full`: 5段階パイプライン。初回解析時の推奨コマンド
  **エージェント並列実行で高速化:**
  ```
  Phase 1（並列）: Agent toolで同時起動（全てrun_in_background: true）
    Agent A: YARA Scan（生バイナリ、数秒）→ 既知ファミリ即時判定
      bash tools/ghidra-headless/ghidra.sh yara-scan <binary>
    Agent B: CAPA Analysis（生バイナリ、数十秒）→ ATT&CK自動マッピング
      bash tools/ghidra-headless/ghidra.sh capa <binary>
    Agent C: Ghidra Analysis（逆アセンブル・デコンパイル、数分）
      bash tools/ghidra-headless/ghidra.sh analyze <binary>

  Phase 2（全エージェント完了後、逐次）:
    [4/5] IOC Extraction（Ghidra出力から）
      bash tools/ghidra-headless/ghidra.sh ioc-extract <binary_name>
    [5/5] Malware Classification（Ghidra出力から）
      bash tools/ghidra-headless/ghidra.sh classify <binary_name>
  ```
  - Phase 1のYARA/CAPAはDocker不要・生バイナリ直接処理のためGhidraと完全独立
  - Phase 2はGhidra出力（strings/imports/decompile）に依存するためAgent C完了後に実行
  - YARA/CAPAが先に完了した場合、既知ファミリ判定結果を即座にユーザーに報告可能

### 出力先
- 結果ファイル: `tools/ghidra-headless/output/`
- ファイル名: `<binary名>_<解析種別>.txt` / `.c`
- YARAスキャン結果: `<binary名>_yara.json`
- CAPA解析結果: `<binary名>_capa.json`
- IOC結果: `<binary名>_iocs.json`
- 分類結果: `<binary名>_classification.json`

## 解析起点の選択ガイド

解析の効率はどこから始めるかで大きく変わる。状況に応じて最適な起点を選択する。

| 起点パターン | 状況 | 最初に実行するコマンド | 次のステップ |
|---|---|---|---|
| A. 気になるAPI | VTやサンドボックスで特定APIの使用が判明 | `imports` → 該当APIのxrefsを追跡 | decompileで呼び出し元関数を読む |
| B. 特定の文字列 | C2ドメイン、ファイルパス等の手がかりあり | `strings` → 該当文字列のxrefsを追跡 | decompileで参照元関数を読む |
| C. 動的解析の補完 | vmware-sandboxで挙動は把握済み、詳細ロジックを知りたい | `decompile`（特定関数） | 暗号化/通信/回避の実装詳細を読む |
| D. 手がかりなし | 未知検体、情報なし | `info` → `imports` → `strings`（下記の推奨フロー） | トリアージ結果から判断 |

**「手がかりなし」（パターンD）の場合のみ下記の推奨フローを使用する。A〜Cに該当する場合は、起点に応じたショートカットで解析を開始。**

## フォレンジック観点の推奨分析フロー

### 1. 初期トリアージ
```bash
bash tools/ghidra-headless/ghidra.sh info <binary>
bash tools/ghidra-headless/ghidra.sh imports <binary>
```
- アーキテクチャ確認（x86/x64/ARM）
- **不審API自動フラグ**を確認（VirtualAlloc, CreateRemoteThread, URLDownloadToFile等）
- セクション権限（RWXセクション=パッカー/自己改変の可能性）

### 2. 文字列解析
```bash
bash tools/ghidra-headless/ghidra.sh strings <binary>
```
- C2アドレス、URL、レジストリキー、ファイルパス
- エンコードされた文字列のパターン
- PDB情報、デバッグメッセージ

### 3. 関数・構造解析
```bash
bash tools/ghidra-headless/ghidra.sh functions <binary>
bash tools/ghidra-headless/ghidra.sh xrefs <binary>
```
- エントリーポイントからのコールチェーン
- 最も呼ばれている関数（暗号化/通信ルーチン候補）
- リーフ関数（暗号化/ハッシュ計算の可能性）

### 4. デコンパイル
```bash
bash tools/ghidra-headless/ghidra.sh decompile <binary>
```
- 不審関数のC疑似コード確認
- ロジック理解、IOC抽出

### 5. フル解析（一括）
```bash
bash tools/ghidra-headless/ghidra.sh analyze <binary>
```
- 上記すべてを1回のanalyzeHeadless実行で完了

## コマンドログ（必須）

解析実行時は必ずログを記録:
```
tools/ghidra-headless/logs/YYYYMMDD_<target_name>.md
```

ログ形式:
```markdown
# Ghidra Analysis: <target_name>
Date: YYYY-MM-DD

## Target
- File: <filename>
- SHA256: <hash>
- Size: <size>

## Source (proxy-web経由の場合)
- Download URL: <ダウンロード元URL>
- Landing Page: <アクセスしたURL>
- Quarantine Path: <Quarantineディレクトリパス>
- VirusTotal: <VT検出率・リンク>

## Analysis Performed
- [ ] info
- [ ] imports
- [ ] strings
- [ ] functions
- [ ] xrefs
- [ ] decompile

## Key Findings
<!-- 解析目的に応じてIR SummaryまたはResearch Detailを選択 -->
```

### IR目的（迅速対応型）のKey Findings

インシデント対応時は以下の形式でIOCと推奨対応を即座に提示:
```markdown
## Key Findings — IR Summary
### IOC一覧（コピペ用）
- C2: <IP:Port> (<Protocol>)
- Hash: SHA256:<hash>
- 永続化: <レジストリキー or サービス名>
- ドロップファイル: <パス>

### 推奨対応
- [ ] C2アドレスをFW/Proxyでブロック
- [ ] 該当レジストリキーの削除
- [ ] 関連プロセスの停止
```

### リサーチ目的（情報収集型）のKey Findings

マルウェアリサーチ・脅威分析時は技術詳細を網羅:
```markdown
## Key Findings — Research Detail
### マルウェアファミリ特定
- ファミリ名: <name>
- 根拠: <ビルドパス、PDB、特徴的文字列等>

### 技術的詳細
- 文字列難読化: <方式>
- API解決方式: <静的/動的>
- C2プロトコル: <プロトコル + フォーマット>

### ATT&CK マッピング
- T1059.001: PowerShell
- ...
```

## 解析レポートの保存先（厳守）

**重要: レポートは必ず以下のパスに保存すること。他の場所（notes/ 等）には絶対に保存しない。**

```
reports/YYYYMMDD_<target_name>.md
```

- **保存先: `reports/` ディレクトリ直下**（サブディレクトリは作らない）
- notes/ や notes/ghidra-headless/ には保存しない（過去に誤出力あり）
- proxy-web経由の場合、DL元URL・ランディングページ・VT結果など取得時の情報を必ずレポートに含める
- `tools/ghidra-headless/output/` には生の解析出力（テキスト/デコンパイル結果）を保存
- `reports/` にはそれをまとめた人間向けレポートを保存

## proxy-webで取得したファイルの解析手順

**!! 最重要: ローカル（ホストOS）上で絶対に復号化しないこと !!**

### .enc.gz ファイルの解析方法（全コマンド対応）

**全てのghidra.shコマンドが .enc.gz を直接受け付ける。** ghidra.shが自動で：
1. 暗号化ファイルをコンテナの `/tmp/` にコピー
2. `.env` の `QUARANTINE_PASSWORD` でコンテナ内復号
3. 解析実行
4. 復号済みバイナリを自動削除

```bash
# .enc.gz をそのまま渡すだけ（全コマンドで同じ）
bash tools/ghidra-headless/ghidra.sh analyze "tools/proxy-web/Quarantine/<domain>/<timestamp>/<file>.enc.gz"
bash tools/ghidra-headless/ghidra.sh info "tools/proxy-web/Quarantine/<domain>/<timestamp>/<file>.enc.gz"
bash tools/ghidra-headless/ghidra.sh imports "tools/proxy-web/Quarantine/<domain>/<timestamp>/<file>.enc.gz"
bash tools/ghidra-headless/ghidra.sh strings "tools/proxy-web/Quarantine/<domain>/<timestamp>/<file>.enc.gz"
bash tools/ghidra-headless/ghidra.sh analyze-full "tools/proxy-web/Quarantine/<domain>/<timestamp>/<file>.enc.gz"
bash tools/ghidra-headless/ghidra.sh yara-scan "tools/proxy-web/Quarantine/<domain>/<timestamp>/<file>.enc.gz"
bash tools/ghidra-headless/ghidra.sh capa "tools/proxy-web/Quarantine/<domain>/<timestamp>/<file>.enc.gz"
```

**禁止事項（ユーザーから繰り返し指摘されている。絶対に破らないこと）:**
- `decrypt_quarantine.py` をホストで実行禁止
- `openssl`/`gunzip`/`python3 -c` 等でホスト上で復号禁止
- `docker cp` でコンテナから復号済みバイナリをホストにコピー禁止
- 上記のような手動復号手順は一切不要。ghidra.shに .enc.gz を渡すだけ

### quarantine CLIツール（Go）

```bash
# 隔離エントリ一覧
./tools/quarantine/quarantine.exe list

# エントリ詳細（番号またはドメイン部分一致）
./tools/quarantine/quarantine.exe info 1
./tools/quarantine/quarantine.exe info 39.106

# Ghidraコンテナの準備状況チェック
./tools/quarantine/quarantine.exe check

# 復号化 + Ghidra解析を実行
./tools/quarantine/quarantine.exe analyze 1
```

## Knowledge Base

**KB-1〜KB-12 の詳細は `kb-entries.md` に分離。**
ファイルパス: `.claude/skills/ghidra-headless/kb-entries.md`

**解析時の手順:**
1. 下のクイックリファレンスで関連するKB番号を特定
2. `Read` で `kb-entries.md` の該当KBセクションを読み込む

### KBエントリ一覧（クイックリファレンス）

| KB | カテゴリ | 内容 |
|---|---|---|
| 1 | 解析手順 | InfoStealer特化解析手順（判定/窃取対象/C2/ステージング/レポート） |
| 2 | 解析手順 | ランサムウェア特化解析手順（判定/暗号方式/影響範囲/脅迫文/レポート） |
| 3 | 解析手順 | RAT特化解析手順（判定/コマンドテーブル/C2プロトコル/レポート） |
| 4 | マルウェアファミリ | MetaStealer/Teddy特徴（SQLite静的リンク、MinGW、DNS tunneling） |
| 5 | マルウェアファミリ | StealC v2特徴（RC4+Base64難読化、WinINet C2、Chrome ABE対応） |
| 6 | パッカー/ドロッパー | VMProtect/Etset Dropper（セクション難読化、インポート隠蔽） |
| 7 | パッカー/ドロッパー | UPXパックInstaller/Dropper（.rsrc埋め込みペイロード） |
| 8 | 言語固有 | Go製バイナリ解析パターン（middle dot問題、静的リンク、RTTI復元） |
| 9 | パイプライン | UPXドロッパー→動的解析→Ghidra再解析パイプライン |
| 10 | 制限事項 | decompile_all.py制限事項（Jython互換性、大量関数） |
| 11 | ツール連携 | Mergen Devirtualization連携（VMProtect二層構造、LLVM IR） |
| 12 | 既知の問題 | 全既知問題（bind mount、Python deps、MSYS path、Jython Unicode、gcompat等） |
| 13 | マルウェアパターン | .NET Loader + Process Hollowing（MSILZilla系、65k+ジャンク関数、多言語難読化） |
| 14 | マルウェアパターン | Go製Dropper + Dead Drop Resolver（Pastebin/GitLab DDR、wolfSSL静的リンク） |
| 15 | ツール修正 | .enc.gzファイルのyara-scan/capa自動復号サポート（2026-03-11追加） |

## Radare2との併用

Kaliコンテナにradare2がインストール済み。Ghidraとの使い分け:

| 目的 | ツール | コマンド例 |
|------|--------|-----------|
| 30秒トリアージ | **r2** | `docker exec kali bash -c "r2 -qc 'iI; iS; ii' /path/to/binary"` |
| エントロピー分析（パッカー判定） | **r2** | `docker exec kali bash -c "r2 -qc 'p=e' /path/to/binary"` |
| 暗号定数検出 | **r2** | `docker exec kali bash -c "r2 -qc '/cr' /path/to/binary"` |
| 文字列フィルタ検索 | **r2** | `docker exec kali bash -c "r2 -qc 'iz~http' /path/to/binary"` |
| 2検体のバイナリdiff | **r2** | `docker exec kali bash -c "radiff2 binary1 binary2"` |
| デコンパイル（C疑似コード） | **Ghidra** | `bash tools/ghidra-headless/ghidra.sh decompile <binary>` |
| 関数コールグラフ | **Ghidra** | `bash tools/ghidra-headless/ghidra.sh xrefs <binary>` |
| 不審API自動フラグ | **Ghidra** | `bash tools/ghidra-headless/ghidra.sh imports <binary>` |

推奨フロー: **r2で素早く「怪しい」を見つけて、Ghidraで「読む」**

## 暗号化/難読化ペイロードの動的解析エスカレーション

静的解析で以下の特徴が検出された場合、**自動的にVMware Sandbox動的解析を提案する**:

### エスカレーション条件
- 文字列の90%以上がhex-encoded/暗号化データ
- インポートテーブルが極端に少ない（<10個のDLL、動的API解決の兆候）
- .rdataや.rsrcに大きな暗号化ペイロードが埋め込まれている
- CFG平坦化・VMProtect・Themida等の難読化でデコンパイルが実質不可能
- C2アドレス・設定値がランタイム復号でしか取得できない

### 提案フロー
1. Ghidra静的解析完了
2. 上記条件に該当 → 「静的解析ではペイロード/C2の特定が不可能です。VMware Sandboxで動的解析を実行しますか？」とユーザーに提案
3. ユーザー同意 → vmware-sandbox スキルで動的解析を実行
4. 動的解析結果（メモリダンプ/展開後バイナリ） → Ghidra再解析

### 動的解析で取得すべき情報
- **展開後ペイロード**: HollowsHunter/PE-sieveでメモリダンプ → Ghidra再解析でマルウェアファミリー特定
- **C2通信先**: プロセスモニタ/Wiresharkで通信先IP/ドメイン/URIパターン
- **API呼び出し**: API Monitorで動的に解決されたAPI一覧
- **ファイル/レジストリ変更**: ProcMonで永続化メカニズム特定

## ポスト解析: IOC活用ガイド

Ghidra解析で抽出したIOCを次のアクションに繋げる。OSINT自体はfoensic-analysis/vmware-sandboxが担当するが、**何を抽出し、どう使うか**は静的解析スキルの範囲内。

| 抽出したIOC | 次のアクション | 補足 |
|---|---|---|
| C2 IP/ドメイン | VTで関連検体検索、Shodanでインフラ調査 | `curl -s "https://www.virustotal.com/api/v3/domains/{domain}" -H "x-apikey: $VT_API_KEY"` |
| ハッシュ値 | VTで検出名・サンドボックス結果取得 | `curl -s "https://www.virustotal.com/api/v3/files/{hash}" -H "x-apikey: $VT_API_KEY"` |
| 特徴的文字列 | Google/GitHubでOSSベースのマルウェア特定 | ビルドパス、PDB情報、ユニークなエラーメッセージ等 |
| ファミリ名特定後 | ベンダブログで既知のTTPs/IOC取得 | MITRE ATT&CKマッピング |
| YARA向けパターン | 類似検体のハンティング | strings/imports結果からYARAルール素案を生成 |

**OSSベースのマルウェア判定**: ビルドパスやユニークな文字列をGitHubで検索し、ソースコードが公開されている場合はREADMEで機能一覧を把握できる（解析コスト大幅削減）。StealC v2のビルドパス発見と同じアプローチ。

## 関連スキル連携
- **proxy-web**: 危険サイトからダウンロードされたバイナリの取得・隔離
- **forensic-analysis**: Prefetch/Amcache/MFTで発見された不審EXEの深掘り
- **memory-forensics**: malfindダンプDLLの逆コンパイル
- **kali-pentest**: CTF reversing問題、John/Hashcatとの連携、**radare2によるトリアージ**
- **vmware-sandbox**: VMProtect等パック済みバイナリの動的解析。静的解析で限界→動的解析→アンパック→Ghidra再解析の連携フロー
- **mergen**: VMProtectコード仮想化の除去。Ghidraで「VMディスパッチャ」としか見えない関数をLLVM IRに変換

## 注意事項
- 解析タイムアウト: 5分/ファイル（-analysisTimeoutPerFile 300）
- プロジェクトDBは毎回削除（-deleteProject）でディスク節約
- 大きなバイナリ（>50MB）はdecompile_allに時間がかかる → 個別コマンドで必要な関数のみ調査推奨
- MAXMEM=4G（docker-compose.ymlで変更可能）

### 解析コスト判断の閾値

「これ以上解析しても情報が得られるか」の判断基準:

| 指標 | 閾値 | 推奨アクション |
|---|---|---|
| 関数数 | 5000超 | decompile_allは非推奨。imports/strings/xrefsで重要関数を特定してから個別decompile |
| バイナリサイズ | 50MB超 | 個別コマンドで必要な関数のみ調査（上記注意事項と同じ） |
| decompile時間 | 10分超/関数 | タイムアウト。難読化の可能性 → vmware-sandbox検討 |
| strings結果 | 90%以上がhex/暗号化 | エスカレーション条件に該当 → 動的解析提案 |
| imports結果 | 10 DLL未満 | 動的API解決の可能性。APIフラグ結果が少なくても正常とは限らない |

**解析終了の判断**: 目的（IR: IOC収集 / リサーチ: 技術詳細）を達成したら終了。コスト閾値に達しても目的未達の場合は、vmware-sandboxへの動的解析エスカレーションを検討。
