# IOC / 検体の公開投稿 (`intel-cli.py submit`)

解析で確定した IOC と検体を、ThreatFox / URLhaus / AbuseIPDB / MalwareBazaar / VirusTotal / Triage に投稿する。
**投稿はすべて公開され、取り消せない。** マニフェストを作り、plan、人間の承認、run の順に進める。

```
reports/campaigns/<name>.iocs.yaml
        │  submit plan   … 検証・ガード・重複照会。対象によって IOC を照会先へ送る。投稿は run の段階
        ▼
data/submit/plans/<id>.json   (送信内容そのもの。digest 付きで改ざん検知)
        │  submit approve  … 人間専用。Claude は hook でブロックされる
        ▼
data/submit/approvals/<id>.json
        │  submit run      … 承認済み plan のペイロードだけを 1 回ずつ送る
        ▼
data/submit/ledger.jsonl      (送信前に attempt、送信後に result を書く。重複投稿の防止にも使う)
        │  submit resolve <attempt_id> ok|failed   … UNCERTAIN / UNRESOLVED を手で確認した結果を記録する
```

`tools/threat-intel/data/submit/` は gitignore 済み。

## Claude の手順（厳守）

1. レポートと同じディレクトリに `*.iocs.yaml` を書く（スキーマは下記）。IOC を Markdown からスクレイプしない。
   - 確定した IOC だけを入れる。疑わしいだけのものは入れない（ThreatFox は違反が続くと BAN）。
   - `tlp: clear` と `source: osint` は、**ユーザが自分で収集した OSINT 検体の場合だけ**付ける。
     仕事や顧客から来たもの、提供元が不明なものは、`tlp` を空にしておく（plan 全体が BLOCK される）。
2. `python tools/threat-intel/intel-cli.py submit plan <manifest>` を実行する。
3. plan の表（READY / SKIP / BLOCKED / MANUAL）と、READY 行の送信ペイロードをユーザにそのまま見せる。BLOCKED の理由は要約して伝える。
4. ユーザに次のコマンドを実行してもらう: `! python tools/threat-intel/intel-cli.py submit approve <plan_id>`
   - **Claude 自身は approve を実行しない。承認ファイルも書かない**（`.claude/hooks/guard_submit_approve.py` がブロックする）。
     ブロックされたときに回避策を探してはいけない。
5. 承認されたら `submit run <plan_id>` を実行し、結果表とリンクをユーザに報告する。
   **Bash ツールの既定タイムアウト（120 秒）で途中で切られないよう、`run_in_background` で実行するか、timeout を最大にする。**
   POST は 1 件あたり最大 60 秒、検体コンテナは最大 30 分かかることがある。
6. 結果が `UNCERTAIN`（送信後のタイムアウトや、URLhaus で lookup にまだ出てこない場合）または `UNRESOLVED`（送信中にプロセスが落ちた）
   の行は、次の plan で BLOCK される。リンク先で登録されたかを確認し、
   `submit resolve <attempt_id> ok`（登録されていた）または `failed`（されていなかった）を記録する。
   resolve は台帳の重複判定にだけ影響し、何も送信しない。再投稿する場合は、改めて plan と承認が必要。

## マニフェスト（schema 1）

```yaml
schema: 1
title: Lumma via fake installer (2026-11)
report: reports/campaigns/20261121_xxx.md     # 参照用（リポジトリ相対）
tlp: clear                                     # clear 以外は全 BLOCK
source: osint                                  # osint 以外は全 BLOCK
reference: https://zenn.dev/.../articles/xxx   # 任意。公開済み記事の https URL。各サービスに送信される
defaults:                                      # 各 IOC に継承される
  malware: win.lumma                           # Malpedia 名（ThreatFox で必須）
  confidence: 80
  tags: [Lumma, FakeInstaller]
  first_seen: 2026-11-20
iocs:
  - {type: ip:port, value: "203.0.113.5:443", role: c2}
  - {type: domain,  value: "c2[.]example", role: c2}
  - type: url
    value: hxxps://dl[.]example/setup.exe      # defang されたままでよい（自動で refang）
    role: payload_delivery
    verified_online_at: 2026-11-21T10:00:00+09:00   # URLhaus に必須。malware-fetch で確認した時刻
  - type: sha256
    value: <64桁hex>
    role: sample
    file: tools/malware-fetch/Quarantine/<dir>/<ts>/setup.exe.enc.gz   # 暗号化 blob のみ受け付ける
    filename: setup.exe
    delivery_method: web_download
```

IOC ごとに書けるフィールド: `malware`, `confidence`, `tags`, `comment`, `first_seen`, `verified_online_at`,
`abuseipdb_categories`, `only` / `skip`（サービス名のリスト）, `allow_query`, `file`, `filename`, `delivery_method`

- `type`: `url` / `domain` / `ip` / `ip:port` / `sha256`
- `role`: `c2` / `payload_delivery` / `phishing_landing` / `sample`

## ルーティング（各プラットフォームの受付ポリシーに合わせている）

| type | role | 送信先 |
|---|---|---|
| ip:port | c2 | ThreatFox (`botnet_cc`) + AbuseIPDB (cat 15,20) |
| ip | c2 | AbuseIPDB（ThreatFox は ip:port 形式が必要） |
| domain / url | c2 | ThreatFox (`botnet_cc`) |
| url | payload_delivery | URLhaus + ThreatFox (`payload_delivery`) |
| domain / ip:port | payload_delivery | ThreatFox (`payload_delivery`)、IP は AbuseIPDB (cat 20) にも |
| sha256 | sample | MalwareBazaar / VirusTotal / Triage（コンテナからアップロード）+ ThreatFox (`payload`) |
| ip / ip:port | phishing_landing | AbuseIPDB (cat 7) |
| url / domain | phishing_landing | **MANUAL**。URLhaus は "Phishing is not Malware" として明示的に拒否する。ThreatFox もマルウェア IOC 用なので対象外 |

送信先を絞りたいときは、CLI で `--only` / `--skip` を指定するか、IOC 側に `only:` / `skip:` を書く。

## 自動ガード（plan で BLOCK / 警告）

| ガード | 内容 |
|---|---|
| TLP / 出所 | `tlp: clear` かつ `source: osint` のときだけ通す（未指定なら拒否） |
| 非グローバル IP | RFC1918、ループバック、TEST-NET、198.18/15（FakeNet 系）、CGNAT、リンクローカルなど |
| 正規インフラ | `tools/threat-intel/data/submit_allowlist.txt`。domain / ip は BLOCK、そのホスト上の URL は警告のみ（悪用された GitHub などの URL は正当な投稿対象のため） |
| 被害者識別子 | URL に含まれるメールアドレスや、`email` / `token` / `session` / `uid` などのクエリは BLOCK。手で確認したうえで `allow_query: true` を付ければ通る |
| 公開テキスト | `comment` / `tags` / `filename` / `reference` に、ローカルパス、メールアドレス、ホストやゲストのユーザ名があれば BLOCK |
| URLhaus 鮮度 | `verified_online_at` が未設定か、48 時間より古い場合（現在検体を配っている URL しか受け付けないため） |
| MalwareBazaar 鮮度 | `first_seen` が 10 日より古い場合は BLOCK（"refrain from uploading samples older than 10 days"） |
| Malpedia 名 | ThreatFox は `win.lumma` 形式の名前が必須 |
| 検体ファイル | `*.enc.gz`（gzip マジック確認）で、かつリポジトリ内にあるものだけ。平文ファイルのパスは拒否する |
| 重複 | 台帳に成功記録がある、または各サービスに既に登録済みなら SKIP（照会時はキャッシュを使わない） |
| AbuseIPDB | AbuseIPDB 側で whitelisted、または usageType が CDN の IP は BLOCK |

## 送信の実装

- **台帳**: 各アクションは、送信**前**に `attempt` 行、送信後に `result` 行を書く（fsync あり）。
  `result` の無い `attempt`（UNRESOLVED）と UNCERTAIN は、`resolve` するまで同じ IOC を BLOCK する。
  実行済みの plan は再実行できない。
- **IOC 系（ThreatFox / URLhaus / AbuseIPDB）**: ホストから `requests` で 1 回だけ送る。`create_session` は 5xx のとき POST も再送するので使わない。
  タイムアウトした場合は `UNCERTAIN` として記録する。
  - ThreatFox: 成功判定は `query_status == "ok"`（abuse.ch 共通の成功値）。`threat_type` と `ioc_type` の組み合わせは、
    plan 時に `types` クエリで照合する（一覧に無ければ BLOCK、照会できなければ警告）。
  - URLhaus: 投稿 API のレスポンス本文は文書化されていないため、本文からは成功と判定しない。
    投稿後に lookup API で URL が見えたときだけ OK とし、見えなければ UNCERTAIN にする。
  - AbuseIPDB: HTTP 200 で `data` が返れば OK（文書化されている形式）。
- **検体（MalwareBazaar / VT / Triage）**: `ti-sample-uploader` コンテナ（`tools/threat-intel/uploader/`）の中で処理する。
  暗号化 blob を読み取り専用でマウントし、メモリ上で復号して SHA-256 がマニフェストと一致することを確認してから送信する。
  コンテナは `--read-only --cap-drop ALL` で起動し、ディスクには書かない。イメージが無ければ初回の run で自動ビルドする。
- API キーは送信時に `.env` から読み込む。plan ファイルや台帳には保存しない。

## サービス別の要点（2026-11 に公式ドキュメントを読んで反映。実 API での送信はまだ未検証）

| サービス | 認証 | 無料枠 | 注意 |
|---|---|---|---|
| ThreatFox | `ABUSECH_AUTH_KEY` | 無料（非営利、fair use） | 確認済みの IOC だけを投稿する。`anonymous=0` で投稿し、アカウント名が表示される |
| URLhaus | `ABUSECH_AUTH_KEY`（ヘッダ） | 同上 | マルウェア配布 URL だけを受け付ける。フィッシング、リダイレクタ、アドウェアは不可。匿名投稿は不可 |
| MalwareBazaar | `ABUSECH_AUTH_KEY` | 同上 | 確定したマルウェアだけ。アドウェア、ファイル感染型、10 日より古い検体は不可 |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | 無料プランは check と report 合わせて 1,000 件/日 | 同じ IP は 15 分に 1 回まで。コメントに PII を書かない |
| VirusTotal | `VIRUSTOTAL_API_KEY` | 4 回/分、500 回/日。非商用に限る | 32MB を超えるファイルは upload_url 経由（最大 650MB） |
| Triage | `TRIAGE_API_KEY` | 公開サンドボックス | **"All submissions are publicly visible and cannot be deleted"**。無料アカウントで API キーが出るかはアカウントページで確認する |

投稿者名は、各サービスのアカウント名がそのまま表示される（API では変えられない）。アカウントを作るときに表示名を揃えておく。

## 承認 hook

`.claude/settings.json` で `.claude/hooks/guard_submit_approve.py` を PreToolUse に登録してある。

- Bash / PowerShell で `intel-cli ... submit approve` を実行しようとするとブロックする
- `data/submit/approvals/` 配下を触る操作（ファイル書き込みやシェルコマンド）もブロックする
- `!` プレフィックスで実行したコマンドは Claude のツール呼び出しではないので、hook は通らない想定（未検証）。
  もし `!` でもブロックされた場合は、別のターミナルで同じコマンドを実行する。
- **この hook は誤って承認してしまうのを防ぐための仕掛けで、強固な境界ではない。** コマンド文字列で照合しているだけなので、
  文字列を含まないスクリプトを経由すれば素通りする。Claude はそうした回避をしてはいけない。

## 後続フェーズ（未実装）

- フィッシング LP（MANUAL 行）の通報: Google Safe Browsing や Netcraft など、フォームでしか受け付けないサービスへの通報。
  ブラウザ操作でフォームを埋め、CAPTCHA と送信はユーザが押す。
- 台帳を使った定期チェック: 投稿した URL の online / offline の変化を追い、テイクダウンまでの日数を記録する。
