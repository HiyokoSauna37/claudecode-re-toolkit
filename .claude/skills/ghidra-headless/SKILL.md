---
name: ghidra-headless
description: >-
  Ghidra Headless AnalyzerをDockerコンテナで実行し、バイナリの静的解析・デコンパイル・インポート分析を行う。
  Use when: バイナリ解析, デコンパイル, 静的解析, reverse engineering, マルウェア解析, CTF reversing, EXE解析, DLL解析
  Do NOT use for: 動的解析（vmware-sandbox）, メモリダンプ解析（memory-forensics）
instructions: |
  実行フロー:
  1. コンテナ確認: docker inspect -f '{{.State.Status}}' ghidra-headless → 停止中なら bash tools/ghidra-headless/ghidra.sh start
  2. 解析対象のバイナリパスを確認
  3. .enc.gzは全コマンドで直接渡せる（ghidra.shが自動復号）。ホスト上で復号禁止。
  4. .NET判別（VTタグ assembly/msil、info結果 CLI Stream、CAPAバックエンド dotnet）→ decompileスキップ、dotnet-decompile使用
  5. 解析はエージェントチーム（analyzer+reviewer）で実行 → [references/reviewer-prompts.md](references/reviewer-prompts.md)
  6. 「終了」「exit」→ ログcommit&push
  ツールパス: tools/ghidra-headless/ghidra.sh
  ログ: tools/ghidra-headless/logs/YYYYMMDD_<target>.md（必須）
---

## コマンド早見表

### コンテナ管理
```bash
bash tools/ghidra-headless/ghidra.sh start     # ビルド&起動
bash tools/ghidra-headless/ghidra.sh stop      # 停止
bash tools/ghidra-headless/ghidra.sh status    # 状態確認
```

### PE トリアージ（Phase 0）
```bash
python tools/ghidra-headless/pe_triage.py <binary>                            # ホスト側トリアージ
python tools/ghidra-headless/pe_triage.py <binary> --json                     # JSON出力
bash tools/ghidra-headless/ghidra.sh pe-triage <binary|file.enc.gz>           # .enc.gz対応版
```

| Verdict | 意味 | 次アクション |
|---|---|---|
| PACKER_DETECTED:xxx | パッカー検出 | vmware-sandbox動的解析優先 |
| HIGH_ENTROPY_PACKED | エントロピー>7.0 | 動的解析検討 |
| RWX_SECTION | RWXセクション | 動的解析推奨 |
| LOW_IMPORTS_DYNAMIC_API | インポート極少 | 動的解析推奨 |
| MANY_SUSPICIOUS_APIS | 不審API 5件超 | imports/xrefsで追跡 |
| CLEAN_TRIAGE | 特筆なし | 通常のGhidra解析フロー |

### Ghidra解析
```bash
bash tools/ghidra-headless/ghidra.sh analyze <binary>                         # フル解析（推奨）
bash tools/ghidra-headless/ghidra.sh analyze --processor ARM:LE:32:v8T <bin>  # ARM Thumb強制
bash tools/ghidra-headless/ghidra.sh info <binary>                            # アーキテクチャ/セクション
bash tools/ghidra-headless/ghidra.sh decompile <binary>                       # C疑似コード
bash tools/ghidra-headless/ghidra.sh functions <binary>                       # 関数一覧
bash tools/ghidra-headless/ghidra.sh strings <binary>                         # 文字列+xref
bash tools/ghidra-headless/ghidra.sh imports <binary>                         # インポート（不審APIフラグ）
bash tools/ghidra-headless/ghidra.sh exports <binary>                         # エクスポート
bash tools/ghidra-headless/ghidra.sh xrefs <binary>                           # クロスリファレンス
```

### ポスト解析
```bash
bash tools/ghidra-headless/ghidra.sh yara-scan <binary>       # YARAスキャン（APT帰属/ファミリ判定）
bash tools/ghidra-headless/ghidra.sh capa <binary>            # CAPA（capability+ATT&CKマッピング）
bash tools/ghidra-headless/ghidra.sh ioc-extract <binary>     # IOC自動抽出（IP/Domain/URL/Hash等）
bash tools/ghidra-headless/ghidra.sh classify <binary>        # マルウェア種別自動分類
bash tools/ghidra-headless/ghidra.sh analyze-full <binary>    # フルパイプライン（Phase 0-4）
```

### .NETバイナリ
```bash
bash tools/ghidra-headless/ghidra.sh dotnet-decompile <binary|file.enc.gz>    # C#ソースへデコンパイル
bash tools/ghidra-headless/ghidra.sh dotnet-metadata <binary|file.enc.gz>     # アセンブリメタデータ
bash tools/ghidra-headless/ghidra.sh dotnet-types <binary|file.enc.gz>        # 型/クラス一覧
```

出力先: `tools/dotnet-decompiler/output/<binary_name>/`

### 出力読み取り（MSYS変換回避、必ずこれを使う）
```bash
bash tools/ghidra-headless/ghidra.sh output ls "sample*"
bash tools/ghidra-headless/ghidra.sh output cat sample_info.txt
bash tools/ghidra-headless/ghidra.sh output head sample_decompiled.c 100
bash tools/ghidra-headless/ghidra.sh output grep "connect" sample_strings.txt
```

**重要**: `docker exec ghidra-headless cat ...` 直接実行はMSYSパス変換で失敗する。

## analyze-full パイプライン

```
Phase 0: PE Triage（ホスト、数秒）→ Verdictで戦略調整
Phase 1（並列）: Agent A=YARA, Agent B=CAPA, Agent C=Ghidra analyze
Phase 2（Agent C完了後）: IOC Extraction → Classification
Phase 3: watchtowr-reportスキルでレポート生成
Phase 4: reviewerで見落とし検出
```

YARA/CAPAはDocker不要・Ghidraと独立。先に完了したら即ユーザー報告可。

## 解析起点の選択

| 起点 | 状況 | 最初のコマンド |
|---|---|---|
| A. 気になるAPI | VT/サンドボックスでAPI判明 | `imports` → xrefs追跡 |
| B. 特定の文字列 | C2ドメイン等の手がかり | `strings` → xrefs追跡 |
| C. 動的解析の補完 | 挙動把握済み、詳細知りたい | `decompile`（特定関数） |
| D. 手がかりなし | 未知検体 | `info` → `imports` → `strings` → `functions` → `xrefs` → `decompile` |

A-C該当時はショートカット。Dの場合のみ標準フローを使用。

## .enc.gz ファイルの扱い

**全コマンドが .enc.gz を直接受け付ける。** ghidra.shが自動で復号→解析→復号済み削除。

```bash
bash tools/ghidra-headless/ghidra.sh analyze "tools/proxy-web/Quarantine/<domain>/<ts>/<file>.enc.gz"
```

**禁止（繰り返し指摘済み、絶対厳守）:**
- `decrypt_quarantine.py` をホストで実行禁止
- `openssl`/`gunzip`/`python3 -c` でホスト復号禁止
- `docker cp` で復号済みバイナリをホストにコピー禁止

### quarantine CLIツール
```bash
tools/quarantine/quarantine.exe list              # 隔離エントリ一覧
tools/quarantine/quarantine.exe info 1            # 詳細（番号 or ドメイン部分一致）
tools/quarantine/quarantine.exe check             # Ghidraコンテナ準備状況
tools/quarantine/quarantine.exe analyze 1         # 復号+Ghidra解析
```

## 出力先

| 種別 | パス |
|---|---|
| Ghidra結果 | `tools/ghidra-headless/output/<binary>_<種別>.txt/.c` |
| YARA | `<binary>_yara.json` |
| CAPA | `<binary>_capa.json` |
| IOC | `<binary>_iocs.json` |
| 分類 | `<binary>_classification.json` |
| .NET | `tools/dotnet-decompiler/output/<binary>/` |
| ログ | `tools/ghidra-headless/logs/YYYYMMDD_<target>.md` |

## セットアップ（初回のみ）

```bash
pip install pefile yara-python                    # PE Triage + YARA
choco install die                                 # オプション: DiEパッカー検出
# capa: https://github.com/mandiant/capa/releases からバイナリをPATHに配置
bash tools/ghidra-headless/ghidra.sh start        # Ghidraコンテナ初回ビルド
docker compose -f tools/dotnet-decompiler/docker-compose.yml up -d --build  # .NET用
```

## Knowledge Base

KB-1〜KB-21 → [kb-entries.md](kb-entries.md)

| KB | 内容 |
|---|---|
| 1-3 | 特化解析手順（InfoStealer/Ransomware/RAT） |
| 4-5 | マルウェアファミリ（MetaStealer・Teddy/StealC v2） |
| 6-7 | パッカー/ドロッパー（VMProtect・Etset/UPX） |
| 8 | Go製バイナリ解析パターン |
| 9 | UPXドロッパー→動的→再解析パイプライン |
| 10 | decompile_all.py制限事項 |
| 11 | Mergen Devirtualization連携 |
| 12 | 全既知問題（bind mount/Python deps/MSYS path等） |
| 13-14 | マルウェアパターン（.NET Loader/Go Dropper+DDR） |
| 15 | .enc.gz yara-scan/capa自動復号 |
| 16 | .NETバイナリ解析ガイド |
| 17 | Ghidraデコンパイラ権限エラー修正 |
| 18 | .NETパイプライン改善 |
| 19-20 | ツール改善（dexec/output/auto_detect/binary_info/decompile_all） |
| 21 | Kimwolf: ARM32 Android botnet |

## コスト閾値

| 指標 | 閾値 | 推奨 |
|---|---|---|
| 関数数 | 5000超 | imports/strings/xrefsで特定→個別decompile |
| サイズ | 50MB超 | 個別コマンドで必要関数のみ |
| decompile時間 | 10分超/関数 | 難読化→vmware-sandbox検討 |
| strings | 90%以上暗号化 | 動的解析エスカレーション |
| imports | 10 DLL未満 | 動的API解決の可能性 |

エスカレーション・IOC活用・Radare2併用 → [references/advanced-analysis.md](references/advanced-analysis.md)
レポート執筆ガイド → [references/report-guide.md](references/report-guide.md)

## 関連スキル
proxy-web(バイナリ取得) / forensic-analysis(不審EXE深掘り) / memory-forensics(malfindダンプ) / kali-pentest(CTF/r2トリアージ) / vmware-sandbox(パック検体動的解析) / mergen(VMProtect除去) / watchtowr-report(レポート生成)

## 標準化ツール（bb-toolkit 連携）

| ツール | 用途 |
|---|---|
| `tools/ghidra-headless/scripts/lnk-parser.py` | LNK構造パース（パディング難読化検出、埋込PE/PDF抽出、MachineID 取得）。**pylnk3 は `ansi` encoding バグで使えないので必ずこちらを使う** |
| `tools/ghidra-headless/scripts/pe-encrypt.py` | Ghidra コンテナ内ファイル → quarantine .enc.gz 形式 (AES-256-CBC + gzip)。ホスト経由で VM に渡す時の標準手段 |
| `tools/ghidra-headless/scripts/chunk-extract.py` | PE .rdata から RVA+size 指定で埋込バイナリ抽出 (entropy/magic付き)。Rust/Go マルウェアの DAT_xxx 展開用 |
| `tools/bb-toolkit/go/bb-gcs-enum` (Go) | GCS 公開バケット全列挙 + ダウンロード (LOLCloud 偵察) |

## 落とし穴（2026-04-19 セッションで判明）

- **BusyBox strings は `-e l` 非対応**: Alpine ベースの ghidra-headless コンテナで UTF-16LE 文字列抽出したい場合、`python3 -c "..."` で直接デコードするか `apk add binutils` で GNU strings を入れる
- **`unzip` は AES-256 (PKv5.1) 非対応**: MalwareBazaar 配布 ZIP は AES-256 なので必ず `7z x -pinfected` を使う（コンテナに既存）
- **`docker cp` で MSYS パス変換**: ホスト → コンテナの `/tmp/...` 指定時、`MSYS_NO_PATHCONV=1` プレフィックスを付ける
- **`yara-scan` / `capa` / `analyze` はホスト側ツール**: コンテナ内 `/tmp/` のバイナリには直接渡せない（ファイル不在エラー）。ホストファイルとして渡すか、`scripts/pe-encrypt.py` で `.enc.gz` 化してから `analyze <file.enc.gz>` を使う
- **`Sleep(大きな数値)` は単位要注意**: Rust の `Duration::from_nanos(800_000_000)` は 0.8 秒。静的解析で見た数値を秒単位と誤読しない。ProcMon の Process Start→Exit で実時間確認
- **VMware 単一キー検知の典型**: `HKLM\SOFTWARE\VMware, Inc.\VMware Tools` RegOpenKey → 存在で即 exit する Rust マルウェアが多い。動的解析で 1 秒以内に exit するなら VM 検知を疑う

## 注意
- タイムアウト: 5分/ファイル、MAXMEM=4G
- プロジェクトDBは毎回削除（-deleteProject）
- 大バイナリ(>50MB)はdecompile_all非推奨
