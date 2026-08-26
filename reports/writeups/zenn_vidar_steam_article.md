---
title: "Steamの無料ゲームがマルウェアだった件 — Vidar Stealerの中身を追う"
emoji: "🎮"
type: "tech"
topics: ["security", "malware", "reversing", "threatintel"]
published: false
---

## はじめに

2025年末から2026年にかけて、Steamで配布された無料ゲームに情報窃取マルウェアが仕込まれる事件が相次いだ。FBIが被害者を募る事態にまで発展している。

本記事では、そのうちの1つ **「Beyond The Dark」** に関連するVidar Stealerの検体を入手し、静的解析・動的解析・C2追跡まで一気通貫で行った記録をまとめる。

**「無料ゲームをインストールしただけで、ブラウザのパスワードもウォレットもCookieも全部抜かれる」** — その仕組みを技術的に明らかにしたい。

## Steamマルウェア事件の概要

### 何が起きたのか

| ゲーム名 | 時期 | 手口 |
|---|---|---|
| PirateFi | 2025年2月 | Vidar Stealer同梱、約1,500DL |
| Chemia | 2025年7月 | HijackLoader → Vidar + Fickle Stealer |
| BlockBlasters | 2025年8〜9月 | Cryptodrainer、約$150K被害 |
| **Beyond The Dark** | 2024年12月〜2026年5月 | Unity DLLにドロッパー隠蔽 |

Beyond The Darkは元々「Rodent Race」という名前で2024年12月にリリースされた。2026年5月頃にゲーム名・スクリーンショット・説明文が一斉に差し替えられ、Unity DLLの中にドロッパーが仕込まれた。セキュリティ研究者のEric Parkerが動画で暴露し、Valveが1日以内に削除した。

### 共通する攻撃パターン

これらの事件には共通点がある。

1. **無料 or 安価なゲーム**として配布（ターゲット層を広げる）
2. **正規のゲームエンジン**（Unity等）のDLLに偽装してマルウェアを埋め込む
3. 実行すると**情報窃取マルウェア（Infostealer）**がバックグラウンドで動作
4. 盗んだデータはC2サーバーに送信され、**闇市場で売買**される

FBIシアトル支局は2026年にこれらの事件を統合捜査し、被害者からの情報提供を呼びかけている。

## 検体の入手

Beyond The Dark自体はSteamから削除済みで直接入手できない。しかし、同キャンペーン（LARVA-208）で使われた **Vidar Stealer** の検体がマルウェア解析プラットフォーム [Triage](https://tria.ge/) で公開されていた。

ProdAFTが公開したIOCからSHA256ハッシュを特定し、Triageで検索してダウンロードした。

```
SHA256: 2cd8c0e75cf76381f06dfe465a542e52eefa713b0bea2557763e0c0c45b21481
SHA1:   26b9368b74adeae685421309df0aeaed719f0e9b
種別:   Vidar Stealer
```

## 静的解析 — 外殻を読む

### 基本情報

| 項目 | 値 |
|---|---|
| 形式 | PE32+ (x86-64) Windows GUI |
| コンパイラ | Clang |
| サイズ | 737,280 bytes |
| 関数数 | 1,248 |
| インポート | 107 API / **3 DLL のみ** |

まず目を引くのは**インポートの少なさ**。KERNEL32、USER32、GDI32の3つしかない。本物のStealerであれば、WININET（HTTP通信）やCRYPT32（暗号処理）が必要なはずだ。つまり、**この外殻は本体ではない**。

### 異常なセクション構成

```
Name       Size       Permissions   備考
.text      315KB      R-X           実行コード
.rdata     81KB       R--           読み取り専用データ
.eye       157,696B   RW-           ← 暗号化ペイロード①
.eye       157,696B   RW-           ← 暗号化ペイロード②
tdb        6,224B     RW-           構成データ / 復号鍵候補
```

`.eye`という名前のセクションが**2つ**（各157,696バイト、合計約308KB）存在し、どちらもRead/Write権限を持つ。通常のPEにこんなセクションは存在しない。ここに**暗号化されたVidar本体**が格納されている。

### 制御フロー平坦化（Control Flow Flattening）

デコンパイル結果を見ると、すべての関数がstate machineパターンで難読化されている。

```c
while (true) {
    if (iVar2 == -0x65c5eed1) {
        local_80 = (undefined8 *)*param_1;
        iVar2 = 0xe0c7245;
    }
    if (iVar2 == 0xe0c7245) break;
    if (iVar2 == 0x5276bfc0) {
        local_80 = param_1;
        iVar2 = iVar10;
    }
}
```

各基本ブロックの実行順序を定数（`0x5276bfc0`等）で管理するdispatcherループに変換されており、静的解析でのコードフロー追跡を困難にしている。このパターンはVidarで広く使われている難読化手法で、ビルダーが自動生成する。

### API Hash Resolution

`FUN_140001620`という関数が、ハッシュ値を引数に取ってAPIアドレスを動的に解決している。

```c
pcVar9 = (code *)FUN_140001620(handle, 0xea38c5c3, ...);
local_880 = (code *)FUN_140001620(handle, 0xf8381cdd, ...);
local_878 = (code *)FUN_140001620(handle, 0x41747577, ...);
local_870 = (code *)FUN_140001620(handle, 0x290711d7, ...);
// ... 計11個のAPI解決
```

`0xea38c5c3`のような定数はAPI名のハッシュ値で、実行時に`GetProcAddress`経由で実アドレスに変換される。これにより、インポートテーブルには最小限のAPIしか記録されず、静的解析ツールやAV製品のシグネチャ検出を回避する。

### 偽装GUI — "Cheating Engine"

文字列テーブルに `"Cheating Engine"` や `"Find"` `"BUTTON"` `"Pressed!"` といったGUI関連の文字列が見つかった。実行するとゲームのチートツールのようなウィンドウが表示されるが、その裏で`.eye`セクションの復号とペイロード注入が進行する。

### 静的解析のまとめ

```
vidar_sample.exe（外殻 / ローダー）
├── .eye x2 セクション = 暗号化されたVidar本体
├── 制御フロー平坦化 = 解析妨害
├── API Hash Resolution = インポート隠蔽
├── "Cheating Engine" GUI = ユーザー偽装
└── 本体のインポート: 3 DLL のみ（静的解析ではこれ以上追えない）
```

**判定: パッカー/ローダーであり、動的解析が必要。**

## 動的解析 — Process Hollowingの現場

### 実行環境

VMware Workstation上のWindows VM（Host-Onlyネットワーク隔離）で実行した。FakeNet-NGでDNS/HTTPの偽応答を返し、C2通信パターンをキャプチャする。

### 実行結果 — MSBuild.exe の出現

マルウェア実行後のプロセスdiffが決定的だった。

```diff
  実行前: 134プロセス
  実行後: 106プロセス

+ pid=5128, owner=DESKTOP-xxxxx\malwa, cmd=MSBuild.exe   ← ★ 新規出現
- （vidar_sample.exe はプロセスリストに不在）
```

`vidar_sample.exe`自身は既に終了しており、代わりに**`MSBuild.exe`**が常駐している。MSBuild.exeは.NET Frameworkに含まれるビルドツールで、Windowsに標準搭載されている正規プログラムだ。

### Process Hollowing（T1055.012）

これは**Process Hollowing**と呼ばれる手法で、以下のように動作する。

```
1. CreateProcess("MSBuild.exe", SUSPENDED)
   → MSBuild.exeを一時停止状態で起動

2. NtUnmapViewOfSection()
   → MSBuild.exeの元のコードをメモリから除去

3. VirtualAllocEx() + WriteProcessMemory()
   → 空いた領域にVidar本体を書き込む

4. ResumeThread()
   → MSBuild.exeとして動作開始（中身はVidar）
```

タスクマネージャーで見ると`MSBuild.exe`だが、実際に動いているのはVidar Stealer。セキュリティソフトの監視をすり抜けるための手法で、正規のMicrosoft署名付きバイナリのプロセスとして動作するため、ふるまい検知が困難になる。

### pe-sieveによるメモリダンプ

[pe-sieve](https://github.com/hasherezade/pe-sieve)でMSBuild.exeプロセスをスキャンすると、明確な改ざんが検出された。

```json
{
  "pid": 5356,
  "is_managed": 1,
  "main_image_path": "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exe",
  "scanned": {
    "total": 60,
    "modified": {
      "replaced": 1,        // ← 元のコードが置換されている
      "implanted_pe": 1     // ← PEイメージが注入されている
    }
  },
  "is_pe_replaced": 1,
  "dos_hdr_modified": 1,
  "file_hdr_modified": 1,
  "ep_modified": 1          // ← エントリポイントも書き換え済み
}
```

`400000.MSBuild.exe` として157,696バイトのダンプPEを取得 — これが**アンパック済みVidar本体**だ。

## アンパック済みVidarの解析 — 本体を読む

### 劇的な変化

ダンプしたPEをGhidraで再解析すると、外殻との違いは歴然だった。

| 項目 | 外殻（ローダー） | 本体（Vidar） |
|---|---|---|
| アーキテクチャ | x86-64 | **x86 (32bit)** |
| 関数数 | 1,248 | **249** |
| インポートDLL | 3 | **14** |
| 文字列数 | 554 | **412**（有意義な文字列が大量） |
| 難読化 | CFF + API Hash | なし |

### C2 Dead Drop Resolver — Steamプロフィールに隠されたC2

文字列テーブルから、**C2の所在を示すURL**が複数見つかった。

```
https://t.me/iry2am
https://steamcommunity.com/profiles/76561199878419187
```

Vidarは**Dead Drop Resolver (DDR)**という手法でC2サーバーのIPアドレスを取得する。C2のIPアドレスをバイナリにハードコードする代わりに、SteamやTelegramのプロフィールページに埋め込む。

実際にこのSteamプロフィールを調べると、ペルソナ名が以下のように設定されている。

```
i#xx https://116.203.165.217|
```

マルウェアはこのページのHTMLをパースし、`https://`と`|`の間からIPアドレスを抽出する。これにより、**C2のIPが変更になってもバイナリを再ビルドする必要がない** — プロフィールを編集するだけで全感染端末のC2先を一括更新できる。

:::message
Valveはこれらのマルウェア入りゲームの対応に批判を受けているが、DDR用プロフィールの削除については積極的な対策を取っていないとされる。筆者の調査時点（2026年5月）でもこのプロフィールは**公開状態**で閲覧可能だった。
:::

### C2 IPの追跡結果

| 項目 | 値 |
|---|---|
| IP | `116.203.165.217` |
| ホスティング | Hetzner Online GmbH (AS24940) |
| 所在地 | ドイツ・ニュルンベルク |
| 逆引き | `pbx.eu-brands.de` |
| VT評価 | Malicious: 3 / Suspicious: 3 |

HetznerはVidar C2の定番ホスティングで、研究者により同ASに21以上のVidar C2が確認されている。

### 窃取対象の全容

本体の文字列テーブルから、狙われるデータの全容が判明した。

**ブラウザ認証情報:**
```
Login Data          ← Chromium系パスワードDB
cookies.sqlite      ← Firefoxクッキー
formhistory.sqlite  ← Firefox自動入力
places.sqlite       ← Firefox閲覧履歴
Local State         ← Chrome暗号化マスターキー
"encrypted_key":"   ← DPAPI暗号化キーの抽出パターン
key4.db             ← Firefoxマスターパスワード
```

**暗号通貨ウォレット:**
```
\Monero\wallet0123456789    ← Moneroウォレット
chrome-extension_           ← MetaMask等の拡張機能
wallet_path                 ← ウォレットパス収集
\Local Extension Settings   ← ブラウザ拡張の保存データ
```

**その他:**
```
Soft\Steam\steam_tokens.txt ← Steamセッショントークン
\AppData\Roaming\FileZilla\recentservers.xml ← FTP認証情報
steam.exe                   ← Steamプロセス監視
```

## データはどう盗まれるのか

### Chromeパスワードの復号フロー

Vidarがブラウザのパスワードを盗む仕組みは、想像以上にシンプルだ。

```
1. %LOCALAPPDATA%\Google\Chrome\User Data\Local State を読む
2. "os_crypt.encrypted_key" を Base64デコード
3. 先頭5バイト "DPAPI" を除去
4. CryptUnprotectData() で AES マスターキーを復号
   → ログイン中のユーザー権限で呼べる（管理者権限不要）
5. Login Data (SQLite) を開く
6. 各エントリの暗号化パスワードから:
   - 先頭3バイト (v10/v11) を除去
   - 12バイトのIV/nonceを抽出
   - AES-256-GCM で復号 → 平文パスワード
```

**重要なのはステップ4**。`CryptUnprotectData`はWindowsのDPAPI（Data Protection API）で、ログイン中のユーザーコンテキストで呼べば特権なしで復号できる。マルウェアがユーザーとして実行されている時点で、Chromeの保存パスワードは事実上**平文と同じ**だ。

### C2への送信フォーマット

収集されたデータは以下の構造でZIPにまとめられ、C2に送信される。

```
files/
├── information.txt     OS/CPU/GPU/RAM/インストール済みソフト一覧
├── passwords.txt       全ブラウザから抽出したパスワード統合
├── screenshot.jpg      感染時点のデスクトップスクリーンショット
├── Autofill/           フォーム自動入力データ
├── CC/                 クレジットカード情報
├── Cookies/            セッションCookie
├── History/            閲覧履歴
├── Wallets/            暗号通貨ウォレットファイル
└── Soft/Authy/         2FAアプリケーションデータ
```

このZIPはBase64エンコードされ、HTTP POSTのmultipartフォームとしてC2に送信される。

## 盗まれたデータはどこへ行くのか

### Russian Market — 1件10ドルの個人情報

窃取されたデータは主に **Russian Market** と呼ばれるダークウェブのマーケットプレイスで売買される。

| 項目 | 詳細 |
|---|---|
| 販売単位 | 1被害者 = 1 "bot" |
| 価格 | **$5〜$100** (平均 約$10) |
| 規模 | 2025年上半期で **180,000件以上** のログが出品 |
| 主要ベンダー | 上位3名で出品の約70% |

$10で買えるのは**1人分のデジタルライフの全記録**だ。パスワード、Cookie、閲覧履歴、ウォレット、2FAデータ、スクリーンショット。

### Telegramチャンネル — VIPアクセス

2025年以降、大手サイバー犯罪フォーラムの閉鎖を受けて**Telegram**が取引の主戦場になっている。

- 無料サンプルチャンネル（集客用）
- 有料VIPチャンネル: **$300〜$900/月**（10〜15名限定）
- 自動化botによるログ配信・アクセス制御

### 購入者が何をするか

| 攻撃手法 | 使うデータ | 影響 |
|---|---|---|
| **セッションハイジャック** | Cookie | MFAを完全バイパスしてアカウント乗っ取り |
| **暗号通貨窃取** | ウォレットファイル + シードフレーズ | 即時送金（取り消し不可） |
| **クレデンシャルスタッフィング** | パスワードリスト | 同一パスワードの使い回しを突く大規模ATO |
| **ランサムウェアの初期アクセス** | 企業VPN認証情報 | ランサムウェア被害の54%にInfostealerログが先行（SpyCloud / Verizon DBIR 2025） |

### 数字で見るInfostealer被害（2024〜2025年）

- Vidar単体で **6,500万件以上のパスワード**を窃取（2024年下半期、KrakenLabs/Specops調べ）
- **5,170万件**のInfostealerログパッケージが処理（2025年、前年比72%増、Constella調べ）
- 毎月 **260億回** のクレデンシャルスタッフィング試行（Akamai調べ）
- クレデンシャルスタッフィングが **全侵害の22%** を占める（Verizon DBIR 2025）

## 脅威アクター: LARVA-208 / EncryptHub

### 概要

| 項目 | 詳細 |
|---|---|
| 名称 | LARVA-208 / EncryptHub |
| 追跡元 | PRODAFT |
| 活動開始 | 2024年6月 |
| 被害規模 | **618組織以上** |
| 動機 | 金銭目的 |

### 攻撃フロー（Chemiaキャンペーン）

```
Steam Early Accessゲーム "Chemia" を侵害
  │
  ├─ [7月22日] HijackLoader (CVKRUTNP.exe) を注入
  │     ├─ レジストリRun Keyで永続化
  │     └─ Vidar Stealer (v9d9d.exe) をダウンロード
  │           ├─ DDR: t.me/iry2am + Steamプロフィール
  │           ├─ C2 IP: 116.203.165.217 を取得
  │           └─ ブラウザ認証・ウォレット・Cookieを窃取
  │
  └─ [+3時間後] Fickle Stealer (cclib.dll) を追加投入
        ├─ PowerShell (worker.ps1) 経由
        └─ Vidarと異なる対象を窃取（冗長化）
```

同一キャンペーンで**Vidar + Fickle Stealerの2種類**を投入している。「1つが検出されてももう1つが動く」保険をかけた設計だ。

## 防御のヒント

### 検出ルール

Vidar DDRに対するSuricataルールが公開されている。

```
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"ET MALWARE Possible Vidar Stealer C2 Config In Steam Profile";
  sid:2043334;
)
```

### Shodan C2ハンティング

Vidar C2は特徴的なJARMフィンガープリントを持つ。

```
ssl.jarm:"21d19d00021d21d00021d21d43557f863337159163ca547c5ea19523"
http.html_hash:1765360226
org:"Hetzner Online GmbH"
```

### ユーザーとしてできること

1. **Steam等で無料ゲームをインストールする際は慎重に** — 特にAI生成アセットの粗悪なゲームは要注意
2. **ブラウザにパスワードを保存しない** — 専用のパスワードマネージャーを使う
3. **2FAはハードウェアキーまたはアプリを使う** — ただしAuthy等のデスクトップアプリもVidarの窃取対象
4. **Cookieの定期削除** — セッションCookieはMFAをバイパスできる

## まとめ

```
Steamの無料ゲームをインストール
  → Unity DLL内のドロッパーが起動
    → .eyeセクションからVidar本体を復号
      → MSBuild.exeにProcess Hollowing
        → SteamプロフィールからC2 IPを取得
          → ブラウザのパスワード・Cookie・ウォレットを窃取
            → ZIPにまとめてC2に送信
              → Russian Marketで1件$10で売買
```

「ゲームをインストールしただけ」で、ここまでの攻撃チェーンが完全に自動で動く。

マルウェアの内部は、制御フロー平坦化・API Hash Resolution・Process Hollowing・Dead Drop Resolverと、各段階で検出回避のための工夫が凝らされている。しかし一度アンパックしてしまえば、中身は「SQLiteを開いてDPAPIで復号する」という素朴なコードだ。

Infostealerは派手さこそないが、ランサムウェアの初期アクセスから暗号通貨窃取まで、あらゆるサイバー犯罪のサプライチェーンの起点になっている。2025年のランサムウェア被害の54%にInfostealerの先行感染が確認されているという事実が、その重要性を物語っている。

## 参考情報

### IOC一覧

```
[SHA256]
2cd8c0e75cf76381f06dfe465a542e52eefa713b0bea2557763e0c0c45b21481  # Vidar Stealer
ed076c27b420bfa66c251488b4121913fa461367a60c5fa32cee3953efcae32b  # Fickle Stealer Downloader
6fb7fd9763d6b269793c80bbc03a1be358390781af4b698fba1591cb8dbb8825  # Fickle Stealer
9a733b2de84e2bf466287abd034b04b18c8c269535606e8f6403eee2a3b288c4  # HijackLoader

[C2 / DDR]
https://t.me/iry2am
https://steamcommunity.com/profiles/76561199878419187
116.203.165.217 (Hetzner, DE)

[Infrastructure]
soft-gets[.]com
reaitek[.]com
safesurf.fastdomain-uoemathhvq.workers[.]dev

[MITRE ATT&CK]
T1055.012  Process Hollowing
T1218.004  MSBuild Abuse
T1102.001  Dead Drop Resolver (Steam/Telegram)
T1555.003  Credentials from Web Browsers
T1539      Steal Web Session Cookie
T1195.002  Supply Chain Compromise (Steam)
T1027.002  Software Packing
```

### 参考リンク

- [PRODAFT LARVA-208 IOC](https://github.com/prodaft/malware-ioc/blob/master/LARVA-208/SteamCampaign.md)
- [BleepingComputer - FBI seeks victims of Steam games](https://www.bleepingcomputer.com/news/security/fbi-seeks-victims-of-steam-games-used-to-spread-malware/)
- [Malwarebytes - Steam games abused](https://www.malwarebytes.com/blog/news/2025/07/steam-games-abused-to-deliver-malware-once-again)
- [Eric Parker - Beyond The Dark analysis (YouTube)](https://www.youtube.com/watch?v=oC78inB5bZ4)
- [Trend Micro - Vidar 2.0](https://www.trendmicro.com/en_us/research/25/j/how-vidar-stealer-2-upgrades-infostealer-capabilities.html)
- [Emerging Threats - Vidar Steam DDR](https://community.emergingthreats.net/t/vidar-stealer-picks-up-steam/271)
- [SECUINFRA - Vidar via Steam Store](https://www.secuinfra.com/en/techtalk/infostealer-malware-vidar-spread-via-the-steam-store/)
- [Rapid7 - Inside Russian Market](https://www.rapid7.com/blog/post/tr-inside-russian-market-uncovering-the-botnet-empire/)
- [eSentire - Vidar C2 Protocol Analysis](https://www.esentire.com/blog/esentire-threat-intelligence-malware-analysis-vidar-stealer)
