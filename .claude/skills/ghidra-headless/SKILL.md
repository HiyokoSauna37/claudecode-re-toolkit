---
name: ghidra-headless
description: >-
  Ghidra Headless AnalyzerをDockerコンテナで実行し、PE/ELF/.NET/ARM バイナリの静的解析・デコンパイル・インポート分析を行う。quarantine 由来 .enc.gz の自動復号にも対応。
  Use when: バイナリ解析（EXE/DLL/.NET/ARM/Android）, デコンパイル, 静的解析, reverse engineering, マルウェア解析, CTF reversing, quarantine .enc.gz 解析
  Do NOT use for: 動的解析（malware-sandbox）, メモリダンプ解析（memory-forensics）
instructions: |
  実行フロー:
  1. コンテナ確認: docker inspect -f '{{.State.Status}}' ghidra-headless → 停止中なら bash tools/ghidra-headless/ghidra.sh start
  2. 解析対象のバイナリパスを確認（.enc.gz は全コマンドが自動復号するのでそのまま渡す。ホスト上で openssl/gunzip/decrypt_quarantine.py は絶対に使わない）
  3. .NET判別（VTタグ assembly/msil、`info` 出力の CLI Stream、CAPA バックエンド dotnet のいずれか）→ Ghidra の decompile はスキップし dotnet-decompile を使う
  4. 実行モード選択:
     - 単発調査（imports/strings/xrefs 等の特定コマンドだけ欲しい）→ ショートカット（body「解析起点の選択」A-C参照）
     - フル解析（ファミリ判定・レポートまで）→ analyze-full パイプライン（Phase 0-4: triage → YARA/CAPA/Ghidra 並列 → IOC/分類 → watchtowr-report → reviewer）
     - analyzer+reviewer の詳細プロンプトは [references/reviewer-prompts.md](references/reviewer-prompts.md)
  5. **コマンドログは自動記録** — `ghidra.sh` を実行するたびに `tools/ghidra-headless/logs/YYYYMMDD_<target>.md` に自動追記される。手動記述不要。確認は `ghidra.sh log-show <binary>`
  6. 「終了」「exit」宣言時: git add logs/ && commit && push
  ツールパス: tools/ghidra-headless/ghidra.sh
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
python tools/ghidra-headless/pe_triage.py <binary>                            # ホスト側トリアージ（通常PE用、高速）
python tools/ghidra-headless/pe_triage.py <binary> --json                     # JSON出力
bash tools/ghidra-headless/ghidra.sh pe-triage <binary|file.enc.gz>           # .enc.gz対応版（復号が必要な場合のみ）
```

**使い分け:** 通常 PE → `pe_triage.py`（ホスト直接、高速）。`.enc.gz` → `ghidra.sh pe-triage`（自動復号付き）。`analyze-full` を使う場合は Phase 0 が内包されるので事前単独実行は不要（戦略判断を先にしたい場合のみ単独で打つ）。

| Verdict | 意味 | 次アクション |
|---|---|---|
| PACKER_DETECTED:xxx | パッカー検出 | malware-sandbox動的解析優先（静的解析スキップ） |
| HIGH_ENTROPY_PACKED | エントロピー>7.0 | 動的解析検討 |
| RWX_SECTION | RWXセクション | デフォルト: `analyze-full` / パッカー疑い濃厚なら malware-sandbox 併用 |
| LOW_IMPORTS_DYNAMIC_API | インポート極少 | デフォルト: `analyze-full` / 動的 API 解決の疑い濃厚なら malware-sandbox |
| MANY_SUSPICIOUS_APIS | 不審API 5件超 | デフォルト: `analyze-full` / 特定 API を深掘りしたい場合のみ imports/xrefs 個別 |
| CLEAN_TRIAGE | 特筆なし | `analyze-full`（フル解析） or 個別コマンド |

**分岐ルール:** PACKER_DETECTED / HIGH_ENTROPY_PACKED は malware-sandbox へエスカレーション（静的解析の ROI が低い）。それ以外はすべて `analyze-full` がデフォルト。個別深掘り（特定 API の xrefs 等）が目的の場合のみ imports/strings/xrefs に切り替える。

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

### AdaptixC2 ビーコン専用（KB-22 参照）
```bash
bash tools/ghidra-headless/ghidra.sh adaptix-profile <binary|file.enc.gz>     # 埋込 RC4 profile を抽出して JSON 出力（C2 URL/UA/Beacon-ID パラメータ等を取得）
bash tools/ghidra-headless/ghidra.sh adaptix-hash-match <binary|file.enc.gz>  # decompile 内のハッシュ定数 → API 名 にマップ（要 analyze/decompile 先行）
```
出力: `output/<binary>_profile.json` / `output/<binary>_api_hashes.csv`

### .NETバイナリ
```bash
bash tools/ghidra-headless/ghidra.sh dotnet-decompile <binary|file.enc.gz>    # C#ソースへデコンパイル
bash tools/ghidra-headless/ghidra.sh dotnet-metadata <binary|file.enc.gz>     # アセンブリメタデータ
bash tools/ghidra-headless/ghidra.sh dotnet-types <binary|file.enc.gz>        # 型/クラス一覧
```

出力先: `tools/dotnet-decompiler/output/<binary_name>/`
- `Source/` — C# ソース（ILSpy デコンパイル結果、*.cs ファイル群）
- `metadata.json` — アセンブリメタデータ（dotnet-metadata の出力）
- `types.txt` — 型/クラス一覧（dotnet-types の出力）

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

**Phase 0 は analyze-full が内包する** — `analyze-full` を打つなら事前の `pe-triage` 単独実行は不要。

**pe-triage を単独で先打ちすべきケース（analyze-full の前に Verdict 先読み）:**
- 大サイズ (50MB+) or 低インポート数 (10 DLL 未満) でパッカー疑惑濃厚 → 数分の analyze-full を走らせる前に打ち切り判断
- **迷ったら（未知検体・事前情報なしの場合を含む）`analyze-full` 直行で OK**

**analyze-full 中の PACKER_DETECTED 挙動**: パイプラインに自動中断ロジックは無く、PACKER_DETECTED が出ても Phase 1〜5（YARA / CAPA / Ghidra / IOC / 分類）は **すべて完走する**（各ステップは "non-critical, continuing" で続行）。Phase 0 の `<binary>_triage.json` を読んで `verdict == PACKER_DETECTED:*` の場合、**ユーザー側で** Phase 1 以降の出力を見て ROI 低と判断したら malware-sandbox に切り替える。

YARA/CAPA は Docker 不要・Ghidra と独立。先に完了したら即ユーザーへ **中間報告** すること:
- YARA 完了 → ファミリ名・ルール一致数を報告
- CAPA 完了 → 主要 ATT&CK TTP（Top 5-10）を報告
- Ghidra 完了後 → IOC / 分類と統合して最終レポートへ

## .NET 判別（最優先分岐）

Ghidra でデコンパイルする前に .NET バイナリかチェック。3つのシグナルのいずれかで判定:

| シグナル | 取得方法 |
|---|---|
| VT タグ | `assembly` / `msil` / `dotnet` |
| `info` 出力 | セクションに `CLR` / `CLI Stream` |
| CAPA | バックエンド `dotnet`（`ghidra.sh capa` が .NET バイナリを自動判定 — 追加フラグ不要） |

**判別タイミング:** `pe-triage` は PE パッカー検出のみで .NET 判定はしない（CLI Stream シグナルは出ない）。事前情報なしの検体は `ghidra.sh info <binary>` を 1 回打って CLI Stream の有無を確認 → .NET なら dotnet-decompile、通常 PE なら analyze-full に分岐。VT タグで事前に `.NET` と分かっていれば pe-triage すらスキップして直接 dotnet-decompile でよい。

.NET 確定 → `ghidra.sh decompile` はスキップし `ghidra.sh dotnet-decompile <binary>` を使う（Ghidra のデコンパイラは CLR を認識できない）。
初回セットアップ: `docker compose -f tools/dotnet-decompiler/docker-compose.yml up -d --build`
稼働確認（2回目以降）: `docker compose -f tools/dotnet-decompiler/docker-compose.yml ps`（停止中なら `up -d` で再起動）

**.NET でも `pe-triage` / `yara-scan` / `capa` は有効**: .NET バイナリは PE ヘッダを持つので、ConfuserEx / Costura / SmartAssembly 等の .NET パッカー検出は pe-triage で可能。YARA/CAPA も .NET に対応（CAPA は `dotnet` バックエンドを使う）。

**.NET では `analyze-full` を使わない**: analyze-full の Phase 1 には Ghidra analyze が含まれるが CLR は解析できず Ghidra 出力は無意味になる。.NET では個別コマンド（`pe-triage` → `yara-scan` + `capa` + `dotnet-decompile` + `dotnet-metadata` + `dotnet-types` を並列）→ 最後に watchtowr-report スキルで統合、という流れにする。

**並列実行手段:** Claude Code では Agent tool を使って subagent を 1 メッセージ内で複数 dispatch するのが推奨（独立コマンドは並列実行される）。手動の bash 実行なら別ターミナル or `&` でバックグラウンド化。

**Ghidra コマンドの並列実行は OK**（KB-23）: `ghidra.sh` の `run_headless` は per-invocation で project name に PID + nano-second suffix を付与するので、`yara-scan` / `capa` / `imports` / `strings` 等の同時実行で `LockException: Unable to lock project! /analysis/projects/tmp_project` は出ない。古いプロジェクトは `-deleteProject` で自動削除される。

## 解析起点の選択

| 起点 | 状況 | 最初のコマンド |
|---|---|---|
| A. 気になるAPI | VT/サンドボックスでAPI判明 | `imports` → xrefs追跡 |
| B. 特定の文字列 | C2ドメイン等の手がかり | `strings` → xrefs追跡 |
| C. 動的解析の補完 | 挙動把握済み、詳細知りたい | `decompile`（特定関数） |
| D. 手がかりなし | 未知検体 | `info` → `imports` → `strings` → `functions` → `xrefs` → `decompile` |

A-C該当時はショートカット。Dの場合のみ標準フローを使用。

## .enc.gz ファイルの扱い

**全コマンドが .enc.gz を直接受け付ける。** 対象: `pe-triage` / `info` / `analyze` / `analyze-full` / `decompile` / `functions` / `strings` / `imports` / `exports` / `xrefs` / `yara-scan` / `capa` / `ioc-extract` / `classify` / `adaptix-profile` / `adaptix-hash-match` / `dotnet-decompile` / `dotnet-metadata` / `dotnet-types`。ghidra.sh が自動で復号→解析→復号済み削除。

**`pe-triage` の .enc.gz は in-container 経路に自動切替**（KB-22）: 過去にホスト側 Python に渡す経路で `OSError: [Errno 22] Invalid argument: 'C:\\Users\\...\\Temp\\tmp.XXX\\...'` という MSYS パス変換バグがあった。`.enc.gz` を渡すと自動的に「コンテナ内で復号→コンテナ内で pe_triage.py 実行→結果のみ docker cp」のフローに切り替わる。

```bash
bash tools/ghidra-headless/ghidra.sh analyze "tools/malware-fetch/Quarantine/<domain>/<ts>/<file>.enc.gz"
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
`analyze N` が `No encrypted files to analyze.` を返した場合: そのエントリに `.enc.gz` バイナリが存在しない（平文ファイルのみ）。`quarantine.exe info N` でパスを確認し別エントリを選択する。平文 JS/HTML は ghidra-headless のスコープ外 → malware-fetch の `js_deobfuscate.py` 等を使う。

## 出力先

| 種別 | パス |
|---|---|
| Ghidra結果 | `tools/ghidra-headless/output/<binary>_<種別>.txt/.c` |
| PE Triage | `<binary>_triage.json` |
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

KB-1〜KB-23 → [references/kb-entries.md](references/kb-entries.md)

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
| **22** | **AdaptixC2 beacon 解析パターン**（C++ Connector/HTTP RTTI / DJB2 variant hash seed=0x624 / RC4 profile / Pack=BE & Unpack=LE 非対称 / 動的 API 解決ビーコンには CAPA が無効） |
| **23** | **Ghidra プロジェクトロック**（per-invocation suffix 化済 → 並列実行 OK）と **pe-triage `.enc.gz` の MSYS パスバグ → in-container 自動切替** |

## コスト閾値

| 指標 | 閾値 | 推奨 |
|---|---|---|
| 関数数 | 5000超 | imports/strings/xrefsで特定→個別decompile |
| サイズ | 50MB超 | 個別コマンドで必要関数のみ |
| decompile時間 | 10分超/関数 | 難読化→malware-sandbox検討 |
| strings | 90%以上暗号化 | 動的解析エスカレーション |
| imports | 10 DLL未満 | 動的API解決の可能性 |

エスカレーション・IOC活用・Radare2併用 → [references/advanced-analysis.md](references/advanced-analysis.md)
レポート執筆ガイド → [references/report-guide.md](references/report-guide.md)

## 関連スキル
malware-fetch(バイナリ取得) / forensic-analysis(不審EXE深掘り) / memory-forensics(malfindダンプ) / kali-pentest(CTF/r2トリアージ) / malware-sandbox(パック検体動的解析) / mergen(VMProtect除去) / watchtowr-report(レポート生成)

## 標準化ツール（bb-toolkit 連携）

| ツール | 用途 |
|---|---|
| `tools/ghidra-headless/scripts/lnk-parser.py` | LNK構造パース（パディング難読化検出、埋込PE/PDF抽出、MachineID 取得）。**pylnk3 は `ansi` encoding バグで使えないので必ずこちらを使う** |
| `tools/ghidra-headless/scripts/pe-encrypt.py` | Ghidra コンテナ内ファイル → quarantine .enc.gz 形式 (AES-256-CBC + gzip)。ホスト経由で VM に渡す時の標準手段 |
| `tools/ghidra-headless/scripts/chunk-extract.py` | PE .rdata から RVA+size 指定で埋込バイナリ抽出 (entropy/magic付き)。Rust/Go マルウェアの DAT_xxx 展開用 |
| `tools/ghidra-headless/scripts/adaptix_profile_extract.py` (Python) | AdaptixC2 beacon 内蔵 profile を抽出し RC4 復号。`ghidra.sh adaptix-profile` 経由で呼び出される。`--profile-rva` / `--profile-size` で `getProfile()` の指す RVA とサイズを上書き可（KB-22） |
| `tools/ghidra-headless/scripts/adaptix_hash_match.py` (Python) | AdaptixC2 の動的 API 解決ハッシュ → API 名にマップ（`FUN_1400111a1(handle, 0x...)` パターンを抽出）。バンドル済 `adaptix_apidefines.h` (GPL-3.0 snapshot) と照合 |
| `tools/bb-toolkit/go/bb-gcs-enum` (Go) | GCS 公開バケット全列挙 + ダウンロード (LOLCloud 偵察) |

## 落とし穴（2026-04-19 セッションで判明）

- **BusyBox strings は `-e l` 非対応**: Alpine ベースの ghidra-headless コンテナで UTF-16LE 文字列抽出したい場合、`python3 -c "..."` で直接デコードするか `apk add binutils` で GNU strings を入れる
- **`unzip` は AES-256 (PKv5.1) 非対応**: MalwareBazaar 配布 ZIP は AES-256 なので必ず `7z x -pinfected` を使う（コンテナに既存）
- **`docker cp` で MSYS パス変換**: ホスト → コンテナの `/tmp/...` 指定時、`MSYS_NO_PATHCONV=1` プレフィックスを付ける
- **Windows ドライブパス (`C:\...`) の扱い**: `bash tools/ghidra-headless/ghidra.sh <cmd> C:\malware\x.exe` のように `ghidra.sh` 経由で渡す分には内部で変換済みで問題なく通る。`docker exec` / `docker cp` に直接渡す時だけ MSYS 変換で失敗するので、出力参照は必ず `ghidra.sh output <subcmd>` を使う
- **`yara-scan` / `capa` / `analyze` はホスト側ツール**: コンテナ内 `/tmp/` のバイナリには直接渡せない（ファイル不在エラー）。ホストファイルとして渡すか、`scripts/pe-encrypt.py` で `.enc.gz` 化してから `analyze <file.enc.gz>` を使う
- **`Sleep(大きな数値)` は単位要注意**: Rust の `Duration::from_nanos(800_000_000)` は 0.8 秒。静的解析で見た数値を秒単位と誤読しない。ProcMon の Process Start→Exit で実時間確認
- **VMware 単一キー検知の典型**: `HKLM\SOFTWARE\VMware, Inc.\VMware Tools` RegOpenKey → 存在で即 exit する Rust マルウェアが多い。動的解析で 1 秒以内に exit するなら VM 検知を疑う

## 注意
- タイムアウト: 5分/ファイル、MAXMEM=4G
- プロジェクトDBは毎回削除（-deleteProject）
- 大バイナリ(>50MB)はdecompile_all非推奨
