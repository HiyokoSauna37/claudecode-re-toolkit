---
name: threat-intel
description: |
  Smart unified OSINT / threat-intelligence CLI over 18 services (VT, Hybrid Analysis, Triage, MalwareBazaar, ThreatFox, OTX, URLHaus, URLScan.io, Shodan, AbuseIPDB, GreyNoise, IPInfo, BGPView, Whois/RDAP, NIST NVD, VulnCheck, Malpedia, Malshare). Auto-detects input type — give it a hash/IP/URL/CVE/domain/file and it picks the right workflow. IOC extraction (txt/pdf/eml/url), MITRE ATT&CK mapping, YARA scan, HTML/PDF reports. Human-gated public submission of IOCs/samples (ThreatFox / URLhaus / AbuseIPDB / MalwareBazaar / VirusTotal / Triage) from a per-report IOC manifest.
  Use when: 脅威インテリ問合せ, OSINT, ハッシュ調査, IP評判, CVE調査, KEV確認, IOC抽出, ATT&CK mapping, hash相関, IP相関, threat-intel, ti, IOC投稿, IOC共有, ThreatFox投稿, URLhaus投稿, AbuseIPDB報告, MalwareBazaarアップロード, VTアップロード, Triage投稿, submit IOCs
  Do NOT use for: 静的解析（ghidra-headless）、動的解析（malware-sandbox）、危険サイト閲覧（malware-fetch）
---

**機密データはローカルで扱う。** 裸の URL や `url` コマンドは、URLScan のキーが設定済みなら元の URL を外部サービスへ送信する。`unlisted` でも送信される。顧客・社内・トークン付き URL を外部へ送れない場合はローカルの記録だけを調べる。外部照会が許可されているときは、まず既存結果の検索を選ぶ。

**公開可否を検討する回答にも承認条件を示す。** 顧客・業務由来の検体や IOC は公開対象外。公開できる素材でも公開投稿の承認は人間専用とし、エージェントは代行しない。

**The single command you need to remember:**
```
python tools/threat-intel/intel-cli.py <input>
```
It auto-detects: hash → correlation, IP → correlation, CVE → NIST+VulnCheck, URL → URLScan+VT, domain → Whois+OTX+URLScan+VT, file → IOC extract.

**Or for setup / inspection:**
```
python tools/threat-intel/intel-cli.py status   # show which API keys are configured
python tools/threat-intel/intel-cli.py cache stats
```

## 入力 → 自動実行

| ユーザの入力 | 自動的に走るワークフロー |
|---|---|
| hash (md5/sha1/sha256) | `correlate-hash` (VT + Bazaar + OTX + URLHaus + HA + Triage のうち **キー設定済みのものだけ** 一斉。**Malshare / Malpedia / ThreatFox は相関の構成外**なので、必要なら個別に叩く) |
| IP | `correlate-ip` (**BGPView + IPInfo は常時実行**、VT + OTX + Shodan + AbuseIPDB + GreyNoise は **キー設定済みのみ**) |
| `CVE-YYYY-NNNNN` | NIST NVD lookup + VulnCheck KEV/MITRE/NVD2 search |
| URL (`http://...`) | URLScan.io submit（既定 `unlisted`。`URLSCANIO_VISIBILITY=public` で公開）+ VirusTotal URL lookup |
| domain | Whois + URLScan domain search + VT domain + OTX domain |
| file (txt/pdf/eml/md 等のテキスト) | ローカルファイルから IOC を抽出。テキストとして読める拡張子に対応 |
| URL (`http(s)://...` を ioc コマンドで指定) | URL から IOC を抽出。初回 URL のみ接続先を検査するため、不審なコンテンツは隔離環境で取得済みのローカルファイルを使う |

## キー未設定でも壊れない設計

**先に数の話**: description の「18 services」に対し `status` は **16 行**しか出さない。欠けているのは
キー概念を持たない BGPView と Whois-RDAP の 2 つで、**欠落でも不整合でもない**（詳細は後述）。

各サービスは個別に API キーチェック → 未設定なら **その1つだけ** 落として続行（他サービスは通常どおり実行される）。
`status` コマンドで一目で「何が使えるか」確認可能。**相関コマンドを打つ前に `status` を見ておくと、
出力に現れないサービスが「キー未設定」なのか「ヒット0」なのか判別できる。**

### 出力の見え方は 4 通り（いずれも正常）

| 見え方 | 該当サービス | 意味 |
|---|---|---|
| `HTTP 401` の見出し付きエラーブロックが出る | abuse.ch 系（MalwareBazaar / URLHaus / ThreatFox）— **3つとも `ABUSECH_AUTH_KEY` 1つを共有**。1つ設定すれば3つとも通る | リクエストは送られ、サーバが 401 を返した |
| **ブロックごと出力に現れない（無音）** | キー必須サービス全般。hash相関: OTX / HybridAnalysis / Triage ／ IP相関: VirusTotal / OTX / Shodan / **AbuseIPDB** / **GreyNoise** ／ **domain: OTX / URLScan.io** | キー未設定をローカルで検出し、問合せ自体を行わなかった |
| `<サービス名> skipped (no <KEY>)` と1行出る | VulnCheck / URLScan.io（CVE・URL ワークフロー） | ワークフロー側がキー有無を先に見て、明示的に飛ばした |
| **見出しは出るが中身が1行のエラー/`No information available`** | キー不要のサービス（BGPView 等） | 問合せは**実行された**が結果が得られなかった。**キー未設定は原因ではない** |

つまり **「出力に無い＝実行されなかった」であって「ヒット0」ではない**。
逆に **「見出しが出ている＝実行された」** ので、中身が空ならそれは本当にデータが取れなかったということ。
**ただし domain ワークフローだけは見出しが出ない。** Whois が失敗すると専用見出しを出さず、
`DOMAIN WORKFLOW` 見出しの直下にエラー1行（`python-whois required: pip install python-whois`）が出るだけ。
domain では見出しの有無ではなく **文言で** 判定すること。
domain ワークフローで**常時実行される（キー不要の）のは Whois だけ**で、それも下記のとおり
Python パッケージが要る。VT domain はキー必須、OTX / URLScan.io は無音スキップになる。
例: VT のみ設定の環境で `correlate-hash` を打つと、実際に現れるのは
`MalwareBazaar`(401) / `URLHaus`(401) / `VirusTotal` の 3 ブロックだけで、OTX/HA/Triage は一切出ない。
なお **ThreatFox は abuse.ch 系だが `correlate-hash` の構成メンバーではない**ため、相関出力には
401 すら現れない（`threatfox` を直接叩いたときだけ 401 になる）。
**既知: BGPView は API 提供終了。** `api.bgpview.io` が DNS ごと消えている（NXDOMAIN、2026-09 時点で
1.1.1.1 / 8.8.8.8 でも解決不可）ため、どの IP を渡しても
`BGPView unreachable: ... Failed to resolve 'api.bgpview.io'` になる。**ヒット0 ではない。**
ASN / prefix / AS 名が要るときは **IPInfo の `org`**（`AS13335 Cloudflare, Inc.` の形式）を使う。
`VIRUSTOTAL_API_KEY` があれば **VirusTotal ブロックにも `ASN` / `AS Owner` / `RIR` / `Network` が入る**ので、
2 系統で相互検証できる。
他のサービスが空だった場合、**キャッシュ由来かどうかだけ**は `--no-cache` を付けて再実行すれば切り分けられる
（相関全体・サービス単体のどちらに付けても効く。`--no-cache correlate-ip <IP>` でも `--no-cache bgpview ip <IP>` でも可）。

### キー不要で動くサービス（`status` の ✗ に釣られない）

`status` は **16 サービス**を列挙するが、これは「キーを持ちうるサービス」の一覧であって
「動くサービス」の一覧ではない。次の 2 点に注意:

- **`status` に載っていない = キー概念が無い**（BGPView / Whois-RDAP）。ただし
  **`correlate-ip` が常時実行するのは BGPView と IPInfo の 2 つだけ**。Whois-RDAP はキー不要だが
  **相関には組み込まれていない**ので、必要なら `whois ip <IP>` を個別に叩く。
  さらに BGPView は上記のとおり API 停止中なので、**実際にデータを返す常時実行サービスは IPInfo だけ**。
- **「キー不要」＝「動く」ではない。** Whois-RDAP は API キーは要らないが Python パッケージに依存し、
  未導入だと `ipwhois required: pip install ipwhois`（ドメイン側は `python-whois required: ...`）を返す。
  これは 4 パターン表の「見出しは出るが中身が1行のエラー」に該当し、**原因はキーではなくローカル依存の欠如**。
- **`status` が ✗ でもキー無しで動くものがある** — `IPINFO_API_KEY ✗` でも IPInfo は
  org / country / city を普通に返す（無料枠、レート制限のみ）。NIST NVD も同様にキー無しで引ける。

→ **IP 相関は全キー未設定でも BGPView + IPInfo の 2 ブロックが出るのが期待値**。

**hash 相関は逆で、キー無しで実データを返すサービスは 1 つも無い。**
MalwareBazaar / URLHaus は登録だけ無条件に行われるので**ブロック自体は必ず出る**が、
abuse.ch が認証必須化したため `ABUSECH_AUTH_KEY` が無ければ中身は 401 になる
（これが「401 が出る」組と「無音」組の違いの正体 — 前者は問合せに行き、後者は行かない）。
Malshare / Malpedia もキー必須で、かつ相関の構成外。**hash を調べるには最低 1 つキーが要る。**
✗ を見て「このサービスは出ないはず」と決めつけないこと。

なお **同じ「キー未設定」でも、サービス指定コマンドを直接叩いたときは文言が変わる**
（例: `vulncheck kev-cve` を直接実行 → `vulncheck API key not set. Configure VULNCHECK_API_KEY in .env`）。
ワークフロー内の `skipped` 行と原因は同一なので、裏取りのために直接叩き直す必要はない。

### exit code と部分失敗

- **一部サービスだけ失敗しても exit code は 0**（＝「全体としては成功」扱い）。
  上表の 4 パターン（401 エラーブロック / 無音スキップ / 明示スキップ行 / `No information available`）は
  **いずれも exit 0** になる。
  個別サービスの成否は exit code では判定できない。**出力本体を見ること。**
- exit code が非 0 になるのは、コマンド全体が成立しなかったときだけ（入力不正 → 2 など）。

### `--output-format json` の範囲

- JSON は **stdout にクリーンな配列だけ**が出る（text の装飾は混ざらない）。`jq` に直接パイプしてよい。
- ただし **JSON に載るのは成功したサービスのみ**。上の 401 ブロックは JSON 配列には含まれない。
  「どのサービスが失敗したか」まで機械的に取りたい場合は text 出力側を併用する。
- **失敗したサービスは JSON に出ない。これは単体サービスコマンドでも同じ**で、
  `whois ip <IP>` が依存欠如で失敗すると JSON は `[]`（空配列）になる。
  **空配列を「ヒット0」と読まないこと** — どちらなのかは text 出力側でしか分からない。
- **相関コマンド（`correlate-hash` / `correlate-ip`）の JSON 要素には `source` フィールドが入る**
  （`"source": "IPInfo"` / `"VirusTotal"` など）。複数サービスが1つの配列に混ざるので、
  **要素の振り分けはフィールドの形から推測せず `source` で行う**。相関以外のワークフロー（CVE 等）は
  単一サービスなので原則付かない。**例外として VirusTotal 由来の要素は常に `source` を持つ**
  （VT 側が自前で入れているため）。したがって「`source` が無い＝相関ではない」とは言えるが、
  「`source` がある＝相関である」とは言えない。
- **フィールド名はサービスごとに異なる**（本 SKILL.md では列挙しない）。text 出力のラベルに概ね対応する。
  実際のキーを知りたいときは 1 回流して確認するのが速い:
  ```
  python tools/threat-intel/intel-cli.py --output-format json <入力> | python -c "import json,sys;[print(sorted(r)) for r in json.load(sys.stdin)]"
  ```
  例: CVE ワークフローは `cve_id` / `published` / `status` / `cvss_v3_score` / `cvss_v3_severity` /
  `kev_listed` / `kev_added` / `kev_action_due` / `kev_name` / `description`（`description` は切り詰めなしの全文）。
  CVSS のベクタ文字列・CVSS v2・CWE・参照 URL は**入らない**。

### text 出力の色は消せない — 機械処理に使わない

`--no-color` 相当のフラグは**無い**。`--background 0|1` は明/暗背景に合わせた**配色の切替**であって
無効化ではなく、パイプやファイルへリダイレクトしても ANSI エスケープはそのまま残る。
→ **text 出力をパースしようとしないこと。機械処理は `--output-format json` を使う。**
どうしても text を後段処理するなら自前で剥がす: `... | sed -r 's/\x1b\[[0-9;]*m//g'`

### CVSS は NVD 自身の評価を返す

NVD は **同じ CVE に対して複数の CVSS v3 を持つ**（ベンダ＝CNA の自己評価と NVD の評価）。
本ツールは **必ず NVD（`nvd@nist.gov`）の値**を返す。そのため**ベンダのアドバイザリと数字が食い違うことがある**:

| CVE | CNA の評価 | **本ツールが返す NVD 値** |
|---|---|---|
| CVE-2020-1472 (Zerologon) | 5.5 MEDIUM (Microsoft) | **10.0 CRITICAL** |
| CVE-2023-4966 (CitrixBleed) | 9.4 CRITICAL (Citrix) | **7.5 HIGH** |

どちらも誤りではなく評価主体が違うだけ。**食い違いを見つけてもツールのバグと判断しないこと。**
なお上表の CNA 側の数値は**説明のための例示であってツール出力ではない**。
ベンダ値は本ツールでは取得できないので、必要ならベンダのアドバイザリを直接参照する
（報告に載せるなら「ツール由来ではない」と明示すること）。

### KEV 判定は API キー不要

**CVE ワークフローは CISA KEV の掲載有無を必ず出す。** NVD API v2 の応答に KEV 情報が同梱されており、
そこから取得しているので **`VULNCHECK_API_KEY` は不要**。text 出力では CVSS の直下に1行:
```
    CISA KEV:  LISTED  (added 2022-02-10, action due 2022-08-10)
    CISA KEV:  not listed (per NVD)
```
JSON にも `kev_listed`（真偽値）/ `kev_added` / `kev_action_due` / `kev_name` が入るので、
**「悪用実績を機械可読で渡す」依頼はキー無しで完結する**。`not listed (per NVD)` は
**`LISTED` の意味**: CISA が「実際の攻撃での悪用を確認した」として KEV カタログに載せた、ということ。
推測ではなく確定情報として報告してよい。`kev_action_due` は連邦機関向けの是正期限で、
**過ぎていても掲載が取り消されるわけではない**。
逆に `not listed (per NVD)` は「NVD が KEV 掲載を示していない」であって
**「悪用されていない」ではない**。ここを言い換えないこと。

VulnCheck（`kev` / `kev-cve`）は **NVD より詳しい追加情報が要るときだけ**使う任意経路。
キー未設定で `VulnCheck skipped` が出ても、**KEV 判定そのものは NVD 側で済んでいる**ので
「KEV 未確認」と報告しないこと。

## IOC 抽出結果の読み方

抽出は正規表現ベースなので、**ドメイン欄には非ドメインが混ざりうる**。
ファイル名・コード識別子（`ntdll.dll` / `MSBuild.exe` / `System.Drawing.Bitmap`）は自動で除外されるが、
**除外しきれないものが残る**:
- マルウェアファミリ表記（`trojan.msil` / `win.lokipws` — Malpedia 形式）
- 製品名（`Agile.NET` — `.net` が実在 TLD のため区別不能）

→ **抽出結果をそのまま IOC リストとして提出しない。** 目視で選別してから相関に回すこと。
URL は末尾の Markdown 記法（`` ` `` / `*` / `)` 等）を自動で落としてから重複排除する。

## 主要コマンド一覧

### スマートワークフロー
```
python tools/threat-intel/intel-cli.py 8.8.8.8                    # IP相関
python tools/threat-intel/intel-cli.py <sha256>                   # Hash相関
python tools/threat-intel/intel-cli.py CVE-2024-3400              # CVE調査
python tools/threat-intel/intel-cli.py example.com                # Domain調査
python tools/threat-intel/intel-cli.py https://example.com        # URLScan への外部送信を許可された URL のみ
python tools/threat-intel/intel-cli.py /path/to/report.pdf        # IOC抽出
```

### 相関コマンドを明示指定する
上表の `correlate-hash` / `correlate-ip` は **ワークフロー名であると同時にサブコマンド名**でもある。
auto-detect に任せず直接打ってよい:
```
python tools/threat-intel/intel-cli.py correlate-hash <hash>
python tools/threat-intel/intel-cli.py correlate-ip <ip>
```

### エイリアス（auto-detect スキップ）
```
python tools/threat-intel/intel-cli.py hash <h>
python tools/threat-intel/intel-cli.py ip <ip>
python tools/threat-intel/intel-cli.py cve <cve>
python tools/threat-intel/intel-cli.py url <url>
python tools/threat-intel/intel-cli.py domain <d>
python tools/threat-intel/intel-cli.py file <path>
```

### サービス指定
```
python tools/threat-intel/intel-cli.py vt {hash|ip|domain|url|behavior} <value>
python tools/threat-intel/intel-cli.py ha hash <h>
python tools/threat-intel/intel-cli.py triage {search|summary|dynamic} <v>
python tools/threat-intel/intel-cli.py bazaar hash <h>
python tools/threat-intel/intel-cli.py threatfox {ioc|recent} <v>
python tools/threat-intel/intel-cli.py otx {hash|ip|domain} <v>
python tools/threat-intel/intel-cli.py urlhaus {url|hash|tag|recent-urls|recent-payloads} [<v>]
python tools/threat-intel/intel-cli.py urlscanio {submit|result|search|domain|ip} <v>
python tools/threat-intel/intel-cli.py shodan {ip|search} <v>
python tools/threat-intel/intel-cli.py abuseipdb ip <ip>
python tools/threat-intel/intel-cli.py greynoise ip <ip>
python tools/threat-intel/intel-cli.py ipinfo ip <ip>
python tools/threat-intel/intel-cli.py bgpview ip <ip>
python tools/threat-intel/intel-cli.py whois {domain|ip} <v>
python tools/threat-intel/intel-cli.py nist {cve|cpe|severity|keyword|cwe} <v>
python tools/threat-intel/intel-cli.py vulncheck {indexes|kev|kev-cve|mitre|mitre-cve|nvd2|nvd2-cve|backup} [<v>]
#   命名規則: 素の名前 = 一覧（引数は件数、既定100） / `-cve` 付き = 単一CVEの照会
#     kev [N]        一覧   ←→  kev-cve <CVE>    ある CVE が KEV に載っているか  ★単一CVEならこちら
#     mitre [N]      一覧   ←→  mitre-cve <CVE>
#     nvd2 [N]       一覧   ←→  nvd2-cve <CVE>
#     indexes        利用可能インデックス一覧 / backup  KEV のバックアップ取得
python tools/threat-intel/intel-cli.py malpedia {actors|families|payloads|actor|family|yara|sample} [<v>]
python tools/threat-intel/intel-cli.py malshare {list|hash} [<v>]
```

`malshare hash` は検体のダウンロードで、HTTP 本文を実行環境に平文で保存する。隔離 Docker / VM 内だけで使う。

### 補助
```
python tools/threat-intel/intel-cli.py status              # APIキー設定状況
python tools/threat-intel/intel-cli.py cache stats|clear|prune
python tools/threat-intel/intel-cli.py ioc extract <file|url>
python tools/threat-intel/intel-cli.py yara <rules> <target>
python tools/threat-intel/intel-cli.py attack <tag1> <tag2> ...
python tools/threat-intel/intel-cli.py report html|pdf <out> [--from <result.json>]
```

## グローバルフラグ（位置は前/後どちらでもOK）

```
--output-format text|json|csv     # 既定: text (色付き). JSON は jq 等にパイプ可
--proxy URL                       # HTTP/HTTPS/SOCKS5 (例: socks5://127.0.0.1:9050)
--no-cache                        # キャッシュ無効
--cache-ttl SEC                   # TTL (既定 3600)
--quiet / --verbose
--background 0|1                  # 0=明背景端末, 1=暗 (既定)
--report html|pdf --report-file PATH   # コマンド完了後にレポート生成
```

例: `intel-cli.py --output-format json correlate-hash <h> > result.json`

## IOC / 検体の公開投稿（`submit`、人間承認ゲート付き）

投稿は**公開・取り消し不可**。必ず `references/ioc-submission.md` を読んでから扱う。
```
python tools/threat-intel/intel-cli.py submit plan reports/campaigns/<name>.iocs.yaml   # ローカルにプランを保存。対象によって外部へ重複照会
! python tools/threat-intel/intel-cli.py submit approve <plan_id>                       # ← 人間だけが実行する
python tools/threat-intel/intel-cli.py submit run <plan_id>                             # 承認済みペイロードを送信
python tools/threat-intel/intel-cli.py submit show <plan_id> | submit ledger | submit resolve <attempt_id> ok|failed
```
- **Claude は approve を実行しない。承認ファイルも書かない。** hook（`.claude/hooks/guard_submit_approve.py`）がブロックする。
  plan の結果をユーザに見せ、`!` 付きで approve を実行してもらう。ブロックされても回避策を探さない。
- 投稿してよいのは、ユーザが自分で集めた OSINT 検体（`tlp: clear` + `source: osint`）だけ。仕事や顧客由来のものは投稿しない。
- 検体は Docker（`ti-sample-uploader`）内で復号してから送る。ホストに平文は出さない。
- フィッシング LP の URL / ドメインは URLhaus・ThreatFox の受付対象外なので `MANUAL` 行になる（ブラウザでの通報は後続フェーズ）。
- `submit run` は `run_in_background` で実行するか、timeout を最大にする（既定の 120 秒では途中で切られることがある）。
- 結果が `UNCERTAIN` / `UNRESOLVED` の行は再実行しない。リンク先を確認してから
  `submit resolve <attempt_id> ok|failed` を記録する（重複判定にだけ影響し、何も送らない）。

## .env (リポジトリルート)

既存の `VIRUSTOTAL_API_KEY`, `ABUSECH_AUTH_KEY` に加えて、以下追加可能（任意）:
```
ALIENVAULT_API_KEY=
HYBRID_ANALYSIS_API_KEY=
TRIAGE_API_KEY=
URLSCANIO_API_KEY=
SHODAN_API_KEY=
ABUSEIPDB_API_KEY=
GREYNOISE_API_KEY=
IPINFO_API_KEY=
VULNCHECK_API_KEY=
NIST_API_KEY=
MALSHARE_API_KEY=
MALPEDIA_API_KEY=
```
詳細は `references/api-keys-guide.md` 参照。

## 既存ツールとの使い分け
- **VT/Bazaar/ThreatFox/OTXの単発問合せ** → `tools/malware-fetch/malware-fetch.exe` (Go) の方が速い場合あり
- **横断相関 / NIST / VulnCheck / Triage / Shodan / AbuseIPDB / 他10サービス** → 本ツール (これらは malware-fetch にない)
- **C2クラスタプロファイル** → `tools/malware-fetch/intel/c2cluster.py` (本ツールの代替ではない)

## 設計原則
- **絶対にクラッシュしない** — APIキー未設定 / ネットワーク到達不可 / API異常応答すべて `{'error': '...'}` 辞書で graceful。
  exit code は **コマンド全体の成否** (0=成功, 2=入力エラー, 3=APIエラー, 4=想定外)。
  **個別サービスの失敗は exit code に出ない**（前掲「exit code と部分失敗」を参照）
- **キャッシュは透明** — 1回問合せた結果は SQLite (`~/.threat_intel_cache.db`) に1時間保存。同じ hash を別フローから問合せても再fetch しない
- **Claude Code が読める** — `--output-format json` で構造化出力。エラーも JSON で返るのでパイプライン化容易

## 参照

- [api-keys-guide](references/api-keys-guide.md)
- [ioc-submission](references/ioc-submission.md)

ライセンス `GPL-3.0-or-later`
