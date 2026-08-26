---
date: 2026-05-18
tags: [malware, campaign]
family: Toga Stealer
campaign: Toga Campaign (gutsyheartpeu)
platform: Windows / macOS / Linux
severity: High
---

# VPNを名乗る48MBのGoバイナリが、ブラウザの中身を5つのTelegramボットに流している件 — Davinci VPN 3.2 解析

GitHubの Releases ページに堂々と鎮座していた「Davinci VPN 3.2」。ユーザー `gutsyheartpeu` 氏による、誰に頼まれたわけでもないVPNクライアントである。

48MBのEXE。Go言語製。OpenGLでGUIを描画。VPN機能は？ ない。代わりに、Chrome、Firefox、Telegram、そしてあなたの暗号ウォレットの中身をZIPにまとめて、5つのTelegramボットに送信する機能がフル装備されている。

ネタバレ: これはVPNではない。

> **SHA256**: `3b5563c3993f051887091959e0be6c01412d6a9b0ec4c7ee4d2c1cfe71c465c8`
> **MD5**: `be06f733e4af47c1aa0da0940ab76368`
> **VT**: [12/75 — trojan.stealer](https://www.virustotal.com/gui/file/3b5563c3993f051887091959e0be6c01412d6a9b0ec4c7ee4d2c1cfe71c465c8)
> **Source**: `github.com/gutsyheartpeu/davinci-vpn/releases/download/3.2/Davinci.VPN.3.2.exe`

---

## 第一印象 — GitHubくん、もう少し頑張ろうよ

VTに投げた瞬間、12エンジンが反応した。TencentはストレートにLumma Stealerと呼び、KasperskyはTrojan-PSW（パスワード窃取型トロイ）と分類している。

| エンジン | 検出名 |
|---------|--------|
| Tencent | `Win64.Trojan.LummaStealer.Ogil` |
| Kaspersky | `Trojan-PSW.Win64.Stealer.atpg` |
| ESET-NOD32 | `Win64/PSW.Agent.XA trojan` |
| Alibaba | `TrojanPSW:Win64/Stealer.2ef5dead` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |

12/75。つまり75エンジン中63個が「問題なし」と判断している。GitHubのコンテンツモデレーションについては言わずもがな — Releases にそのまま公開されている（2026年5月17日取得時点）。

やれやれ。

---

## Ghidraが37,000関数に溺れたパート — 静的解析

### PE概要

Docker隔離ブラウザでダウンロードし（我々は野蛮人ではないので）、Ghidra Headless に食わせた。48MBのPE。37,021関数。解析タイムアウト366秒。Ghidraですら音を上げるサイズである。

| 項目 | 値 |
|------|-----|
| Format | PE x86-64 (Windows) |
| Compiler | Go + CGo (MinGW) |
| GUI Framework | Fyne + GLFW + OpenGL |
| Database | SQLite (embedded) |
| Functions | 37,021 |
| Sections | 13 (.text 20MB, .rdata 17MB) |
| Image Base | `0x140000000` |

### インポートテーブルの不自然な静けさ

正規のインポートはたったの **2ライブラリ、60関数**。`KERNEL32.DLL` から3つ（`EnterCriticalSection`, `ExitProcess`, `LeaveCriticalSection`）と `MSVCRT.DLL` からCランタイム関数のみ。

Go バイナリの常套手段 — 実行時に `LoadLibraryA` + `GetProcAddress` で動的解決する。文字列セクションに埋まっている実際のAPI呼び出しリストは190以上。ファイルI/O、スレッド管理、暗号、クリップボード操作、GDI…… 何でもありだ。

### 5つの窃取モジュール — Go シンボルは正直者

Go はシンボルを律儀にバイナリに残してくれる（マルウェア作者にとっては不幸なことに）。`strings` の出力から、5つの `Processor` 型が完全な形で浮かび上がった:

| Processor | 対象 | メソッド |
|-----------|------|---------|
| `ChromeBasedProcessor` | Chrome / Edge / Brave / Opera / Vivaldi | `ExtractData` → `decryptData` (DPAPI) → `CreateZip` → `SendToTelegram` |
| `FirefoxProcessor` | Firefox プロファイル | `ExtractData` → `CreateZip` (`Backup_%s_firefox_%s.zip`) → `SendToTelegram` |
| `CryptoWalletProcessor` | ブラウザ拡張 (MetaMask等) | `ExtractData` (Local Extension Settings) → `CreateZip` → `SendToTelegram` |
| `TelegramProcessor` | Telegram Desktop セッション | `ExtractData` → `isHexFolder` → `isValidFile` → `CreateZip` → `SendToTelegram` |
| `FilesProcessor` | 汎用ファイル | `ExtractData` → `CreateZip` → `SendToTelegram` |

全モジュールが同じパターン: 抽出 → ZIP → Telegramへ送信。美しい対称性だ。Goのインターフェース設計を教科書通りに実装している。マルウェアでなければ褒めたい。

### Cookie窃取SQLクエリ — 隠す気がゼロ

バイナリに平文で埋まっていた:

```sql
SELECT host_key, name, path, encrypted_value, expires_utc, is_secure, is_httponly FROM cookies
```

Chromium系ブラウザの `Cookies` SQLiteデータベースを直接クエリしている。`encrypted_value` はDPAPI（Windows Data Protection API）で保護されているが、`Local State` ファイルからAES-GCMの暗号化キーを抽出し、DPAPIで復号するパイプラインが `decryptData` メソッドに実装されている。

DPAPI復号失敗時のエラーメッセージまで丁寧に用意されている:

```
decrypt password for %s@%s failed: AES-GCM: %v, DPAPI: %v, encrypted len=%d, first bytes: %x
```

デバッグ親切設計。ありがとう。

### VersionInfo — 辻褄が合わない

| フィールド | 値 |
|-----------|-----|
| CompanyName | `DavinciLLC` |
| ProductName | `DAVINCI VPN` |
| FileDescription | `Davinci Client` |
| FileVersion | `2.5.1` |
| ProductVersion | `3.2` |
| OriginalFilename | `DAVINCI 3.2.exe` |
| InternalName | `davinciVPN.exe` |
| LegalCopyright | `Copyright 2026` |

FileVersion `2.5.1` なのにファイル名は `3.2`。InternalNameは `davinciVPN.exe` だがOriginalFilenameは `DAVINCI 3.2.exe`。「DavinciLLC」なる法人が存在するかどうかは、諸兄の想像にお任せする。

---

## Telegram外交官の晩餐会 — エクスフィルトレーション

### 5つのTelegramボットトークン

バイナリに平文で5つのBot APIトークンが埋まっていた。5つ。冗長構成のつもりだろうか。

| # | Token |
|---|-------|
| 1 | `8649265515:AAEeUSZ0z_4tl1kHJeiAXrT0x-Zy0gT3XAE` |
| 2 | `8795658457:AAGu9d8cIHqEKCKizhAzdG-ee4i_NaggUPE` |
| 3 | `8610259315:AAGMtr2V66B1dB-5r9SSG3sLyWzD5f_r1DY` |
| 4 | `8343732035:AAH_MIleKxP4UEEyerCF0fmDbABfCnSpyJg` |
| 5 | `8721316403:AAFrkixAcAz9YZtSA1FiVp65zaUKx4lVQkU` |

エクスフィルトレーションのフォーマット文字列:

```
https://api.telegram.org/bot%s/%s
```

各 `Processor` の `SendToTelegram()` メソッドが、窃取データをZIP化してこのAPIに送信する。C2サーバー不要。インフラコストゼロ。Telegram社がホスティングしてくれる。

最高かよ。

### 偵察

`https://api.ipify.org` — 被害者のパブリックIPアドレスを取得。取得結果は `system_info.json` / `source_info.json` と共にTelegramへ送信される。

---

## VMwareの上で何も起きなかったパート — 動的解析（第1ラウンド）

VMware Workstation上のWindows 10 VM（Host-Onlyネットワーク + FakeNet-NG）で実行した。

### 実行後即終了

プロセスリストに `Davinci.VPN.3.2.exe` は残っていなかった。起動から90秒後の時点で既に終了。典型的な grab-and-go 型 Stealer — データを盗んだら即退場。VPN のふりをする GUI すら表示されず、代わりに Windows の「どのアプリで開きますか？」ダイアログが表示された。

### 確認されたアーティファクト

| ファイル | 場所 | 内容 |
|---------|------|------|
| `toga_baup13.lock` | `%TEMP%` | ロックファイル。値: `188` |
| `.ses` | `%TEMP%` | セッションID + UUID: `11F6E068-6D86-4D9F-8CDD-2A8343139FD9` |

### ネットワーク活動

たったの **7接続**。すべてFakeNetへの自己ループバック。

| プロトコル | 件数 | 推定先 |
|-----------|------|--------|
| HTTPS (443) | 3 | `api.telegram.org` |
| HTTP (80) | 4 | `api.ipify.org` |

### Edgeブラウザデータへのアクセス

`Local State` ファイルが 23:08:11 にアクセスされた。DPAPIマスターキー抽出の証拠。しかし……7接続だけ？ 5つのモジュールがあるはずなのに？

何かがおかしい。

---

## 「VMwareですね？ じゃあ手抜きします」 — Anti-VM検知の発覚

ゲストVMのフィンガープリントを調査した結果、**13個のVMwareドライバ**、`VMware, Inc.` のBIOS文字列、`00:0C:29` のMAC OUIプレフィクス、`vmtoolsd` / `vm3dservice` プロセス — VMwareであることが完全にバレバレだった。

バイナリに埋まっていたVM検知文字列:

```
C:\Windows\System32\drivers\vmhgfs.sys    ← VMware共有フォルダ
C:\Windows\System32\drivers\vmmouse.sys   ← VMwareマウス
C:\Windows\System32\drivers\prl_tg.sys    ← Parallels
VMWARE                                    ← CPUID/SMBIOSチェック
VBOX_QEMU_                                ← VirtualBox/QEMUチェック
```

ドライバファイルの存在チェックと、CPUID/SMBIOS文字列マッチ。検出したら「手抜きモード」に入り、一部モジュールの実行をスキップしているようだ。

---

## 6バイトの手術 — バイナリパッチによるAnti-VM無効化

Ghidraコンテナ内でバイナリの文字列オフセットを特定し、各ファイルパスの先頭1バイトを変更した。`vmhgfs.sys` → `xmhgfs.sys`。それだけ。ドライバが見つからなくなるので、チェックは必ず失敗する。

| オフセット | パッチ前 | パッチ後 |
|-----------|---------|---------|
| `0x02034e55` | `vmhgfs.sys` | `xmhgfs.sys` |
| `0x02036350` | `vmmouse.sys` | `xmmouse.sys` |
| `0x02034e7b` | `prl_tg.sys` | `xrl_tg.sys` |
| `0x01ff68f3` | `VMWARE` | `XMWARE` |
| `0x01ff4616` | `vmware` | `xmware` |
| `0x01ff271b` | `VBOX_QEMU_` | `XBOX_XEMU_` |

合計6バイトの変更。パッチ後SHA256: `8f7beccc9acb3f738daab1424df6cc813ad644fe966f10c7fadf4271ddb60f09`

---

## 「本気出していいですか？」 — 動的解析（第2ラウンド: パッチ版）

同じVM環境、同じFakeNet-NG。違うのはバイナリの6バイトだけ。

### 結果比較

| 指標 | パッチ前 | パッチ後 | 倍率 |
|------|---------|---------|------|
| Lock file 値 | `188` | `888` | **4.7x** |
| ネットワーク接続数 | 7 | **~50** | **7.1x** |
| 外部IP接続 | 0 | **10** (`192.0.2.123:443`) | ∞ |
| HTTPS接続 | 3 | ~28 | **9.3x** |
| HTTP接続 | 4 | ~22 | **5.5x** |
| D3Dシェーダキャッシュ | なし | 作成 | — |

**7倍のネットワーク活動。**

パッチ前の `188` という lock file 値が、パッチ後に `888` に跳ね上がった。これはセッション内で処理されたデータ量/モジュール数のカウンタだと推測される。つまり、VM検知時にはモジュールの大部分がスキップされていた。

パッチ後は `192.0.2.123:443` への接続が10本追加されている。これはFakeNet-NGがDNSクエリ（おそらく `api.telegram.org`）を解決した結果の偽IPであり、Stealerが**実際にTelegram Bot APIへのデータ送信を積極的に試みた**ことを意味する。パッチ前はDNS解決すら行っていなかった。

D3Dシェーダキャッシュの生成は、Fyne GUI（偽VPNインターフェース）がレンダリングを試みた証拠。パッチ前は GUI 表示すら省略していた。

些細な話だ。たった6バイトで、マルウェアの「本気」と「手抜き」の差がこれほど出るとは。

---

## 永続化 — いや、ない

Registry `Run` / `RunOnce`、スケジュールタスク、hostsファイル改ざん — いずれも確認されなかった。

このStealerは永続化を一切行わない。起動 → 全データ窃取 → ZIP化 → Telegram送信 → 自己終了。完全なワンショット型。次回の窃取が必要なら、被害者にもう一度「Davinci VPN」をダウンロードさせればいい。

---

## 「Toga」キャンペーン全容 — 1つのアカウント、4つの顔、622人の被害者

GitHubアカウント `gutsyheartpeu` を掘り下げたところ、`davinci-vpn` は **4つのペルソナで展開される組織的な Info Stealer キャンペーンの一部** であることが判明した。

### 脅威アクター: gutsyheartpeu

| 項目 | 値 |
|------|-----|
| GitHub ID | 252013741 |
| アカウント作成日 | 2025-12-29 |
| Followers / Following | 0 / 0 |
| Bio / Company / Location | すべて空 |
| Public repos | 6 |

ゼロフォロワー、ゼロ活動、ゼロ自己紹介。教科書通りの使い捨てアカウントである。

### 配布リポジトリ一覧

| リポジトリ | 作成日 | ペルソナ | 配布バイナリ | DL数 |
|-----------|--------|---------|-------------|------|
| `davinci-vpn` | 2026-04-18 | 偽VPNクライアント | `.exe` / `.dmg` / `.AppImage` | **522** |
| `davinciVPN` | 2026-04-18 | 同上（ミラー） | リリースなし | — |
| `kjsa` | 2026-03-18 | 偽カジノアプリ「**Togasino**」 | `.exe` / `.dmg` / `.AppImage` | **54** |
| `kjsa` (旧タグ) | 2026-01-18 | 偽ウォレット「**Toga Wallet**」 | `.exe` / `.dmg` / `.AppImage` / `.zip` | **26** |
| `tgdw` | 2026-01-18 | Toga Wallet ランディングページ | GitHub Pages + リリース | **26** |
| `NaturalVision` | 2026-01-14 | 偽GTA Vモッド + 偽ゲーム「**Furry Realms**」 | `.zip` | **20** |
| `wallet-core` | 2026-02-25 | Trust Wallet偽装 | リリースなし | — |

**推定被害者数: 622+ ダウンロード**（Windows 406 + macOS 117 + Linux 92 + ZIP 8）

### 4つのペルソナ

1. **Davinci VPN** — VPNを求めるユーザーを狙う。395件のWindows版ダウンロードが最大の被害
2. **Toga Wallet** — 暗号資産ユーザーを狙う。`wallet.togadevelopment.org` に GitHub Pages でランディングページを構築。「Your Gateway to Web3」「50+ blockchains対応」と謳う。嘘である
3. **Togasino** — ギャンブル/カジノ好きを狙う。macOS版が31ダウンロードと比較的多い
4. **NaturalVision + Furry Realms** — ゲーマーを狙う。GTA Vのビジュアルモッドを偽装。「Furry Realms - The Vulpin Dominion」なるゲームも同梱

### クロスプラットフォーム展開

全ペルソナが `.exe`（Windows）/ `.dmg`（macOS）/ `.AppImage`（Linux）の3プラットフォームでバイナリを配布している。Go + Fyne であれば `GOOS=darwin/linux/windows` でクロスコンパイルが可能であり、同一コードベースから全プラットフォーム版を生成しているものと推測される。

### 「Toga」— キャンペーンの内部名

ロックファイル `toga_baup13.lock` の "toga" プレフィクスは偶然ではなかった:

- **Toga**sino（偽カジノ）
- **Toga** Wallet（偽ウォレット）
- **toga**development.org（ランディングページドメイン）
- **toga**_baup13.lock（セッションロック）

"Toga" はこのキャンペーン/Stealer ファミリの内部名称である。

### タイムライン

```
2025-12-29  gutsyheartpeu アカウント作成
2026-01-14  NaturalVision + Furry Realms リリース（ゲーマー標的）
2026-01-18  Toga Wallet リリース + tgdw ランディングページ（暗号資産標的）
2026-02-25  wallet-core リポジトリ作成（Trust Wallet偽装、未リリース）
2026-03-18  Togasino リリース（カジノ標的）
2026-04-18  Davinci VPN リリース（VPN標的）← 本解析対象
2026-05-17  本解析実施時点、全リポジトリ公開中
```

4ヶ月間にわたり、ターゲット層を変えながら同一の Stealer コアを再利用している。

### 関連脅威との比較

| 特徴 | Toga Campaign | Torg Grabber | NWHStealer | Storm-2561 |
|------|-------------|--------------|-----------|-----------|
| 配布方法 | GitHub Releases + ランディングページ | ClickFix | 偽Proton VPNサイト | SEO Poisoning + 偽VPNサイト |
| 言語 | Go (Fyne GUI) | 不明 | 不明 | 不明 |
| Exfil | Telegram Bot API (5トークン) | Telegram → HTTPS | AES-CBC + C2 | HTTP C2 |
| 対象ブラウザ | Chrome系 + Firefox + Yandex | 25 Chrome系 + 8 Firefox系 | Edge, Chrome, Opera, Brave | VPN設定ファイル |
| ウォレット | ブラウザ拡張 | 728種 | 25+フォルダ | — |
| プラットフォーム | Win / macOS / Linux | Windows | Windows | Windows |
| 初認 | 2026-01 | 2025-12 | 2026-04 | 2026-03 |

Toga Campaign は **GitHub Releases を配布インフラとして活用し、複数のペルソナで異なるユーザー層を標的にする点** が特徴的。Torg Grabber とは技術スタック（Go vs 不明）と配布方法（GitHub vs ClickFix）が異なるが、Telegram exfil と暗号ウォレット窃取という目的は共通している。

---

## ファミリ帰属 — Lummaなのか？

TencentはLumma Stealerと断言しているが、実態はやや異なる。

| 証拠 | Lummaとの一致 | 相違点 |
|------|-------------|--------|
| VT: `LummaStealer.Ogil` | 名前ベースの分類 | — |
| 窃取対象 (Chrome/Firefox/Wallet/Telegram) | 典型的なStealer構成 | Lumma固有のC2プロトコルが不在 |
| Telegram Bot APIによるexfil | Lummaも一部亜種で使用 | Lummaの主流はHTTP POST |
| Go言語製 + Fyne GUI | — | Lumma本流はC/C++ |
| 5つのBot Token平文埋め込み | — | Lumma は設定を暗号化 |
| `toga_baup13.lock` ロックファイル | — | Lumma固有ではない |

結論: **Lumma Stealerそのものではなく、「Toga Stealer」として独立したGo言語製の Info Stealer ファミリ**と判断する。Telegram Bot APIをC2/exfilの両方に使い、Go + Fyne でクロスコンパイル可能な構成にしている点が特徴的。作者はGoのインターフェース設計パターンを理解しており、ある程度の開発力がある。

2026年1月から4月にかけて、VPN・ウォレット・カジノ・ゲームモッドという4つのペルソナを使い分け、GitHub Releases 経由で Windows / macOS / Linux 全プラットフォームに配布。推定622件以上のダウンロードが確認されている。

---

## で、どうすればいいのか

### 即時対応

- [ ] `toga_baup13.lock` または `.ses` が `%TEMP%` に存在するか確認
- [ ] 上記5つのTelegram Bot Tokenを組織のProxyログで検索
- [ ] `api.telegram.org/bot8649265515:` 等のパターンでネットワークログを遡及検索
- [ ] Edge/Chrome の `Local State` ファイルの最終アクセス時刻を確認
- [ ] 感染が確認された場合: 全ブラウザ保存パスワードの変更、暗号ウォレットの移行

### Detection Rules

#### Sigma — Stealer Session File Detection

```yaml
title: Davinci Stealer Session Lock File
id: d4v1nc1-0001
status: experimental
logsource:
  category: file_event
  product: windows
detection:
  selection:
    TargetFilename|endswith:
      - '\toga_baup13.lock'
      - '\.ses'
    TargetFilename|contains: '\Temp\'
  condition: selection
level: high
tags:
  - attack.collection
  - attack.t1005
```

#### Sigma — Telegram Bot Exfiltration

```yaml
title: Davinci Stealer Telegram Exfiltration
id: d4v1nc1-0002
status: experimental
logsource:
  category: proxy
detection:
  selection:
    c-uri|contains:
      - 'api.telegram.org/bot8649265515:'
      - 'api.telegram.org/bot8795658457:'
      - 'api.telegram.org/bot8610259315:'
      - 'api.telegram.org/bot8343732035:'
      - 'api.telegram.org/bot8721316403:'
  condition: selection
level: critical
tags:
  - attack.exfiltration
  - attack.t1567
```

#### YARA

```yara
rule DavinciStealer_GoInfoStealer {
    meta:
        description = "Davinci VPN - Go-based Info Stealer with Telegram exfil"
        author = "claudecode-re-toolkit"
        date = "2026-05-18"
        hash = "3b5563c3993f051887091959e0be6c01412d6a9b0ec4c7ee4d2c1cfe71c465c8"

    strings:
        $lock = "toga_baup13.lock" ascii
        $sql  = "SELECT host_key, name, path, encrypted_value" ascii
        $tg   = "api.telegram.org/bot%s/%s" ascii
        $mod1 = "ChromeBasedProcessor" ascii
        $mod2 = "FirefoxProcessor" ascii
        $mod3 = "CryptoWalletProcessor" ascii
        $mod4 = "TelegramProcessor" ascii
        $mod5 = "FilesProcessor" ascii
        $vm1  = "vmhgfs.sys" ascii
        $vm2  = "vmmouse.sys" ascii
        $ip   = "api.ipify.org" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize > 40MB and
        $lock and $tg and
        3 of ($mod*) and
        1 of ($vm*)
}
```

---

## IOCまとめ

### File Indicators

| Type | Value | Description |
|------|-------|-------------|
| SHA256 | `3b5563c3993f051887091959e0be6c01412d6a9b0ec4c7ee4d2c1cfe71c465c8` | Davinci.VPN.3.2.exe (original) |
| MD5 | `be06f733e4af47c1aa0da0940ab76368` | Davinci.VPN.3.2.exe |
| SHA256 | `8f7beccc9acb3f738daab1424df6cc813ad644fe966f10c7fadf4271ddb60f09` | Patched version (anti-VM bypass) |
| SHA256 | `7e08ff98fa58f10914025d59b0cf8487ac3aed1c0932bdf6db10367eeeee12a2` | Dropped: `toga_baup13.lock` (VT sandbox) |
| Filename | `toga_baup13.lock` | Stealer lock file |
| Filename | `.ses` | Session tracking file |
| Filename | `Backup_%s_firefox_%s.zip` | Firefox data exfil archive |
| Filename | `system_info.json` | System profiling output |
| Filename | `source_info.json` | Source profiling output |

### Campaign Infrastructure

| Type | Value | Description |
|------|-------|-------------|
| GitHub User | `gutsyheartpeu` (ID: 252013741) | Throwaway account, created 2025-12-29 |
| GitHub Repo | `gutsyheartpeu/davinci-vpn` | Davinci VPN distribution (522 DL) |
| GitHub Repo | `gutsyheartpeu/davinciVPN` | Mirror repo (no releases) |
| GitHub Repo | `gutsyheartpeu/kjsa` | Togasino + Toga Wallet (80 DL) |
| GitHub Repo | `gutsyheartpeu/tgdw` | Toga Wallet landing page + releases (26 DL) |
| GitHub Repo | `gutsyheartpeu/NaturalVision` | Fake GTA V mod + Furry Realms (20 DL) |
| GitHub Repo | `gutsyheartpeu/wallet-core` | Trust Wallet impersonation (no releases) |
| Domain | `wallet.togadevelopment.org` | GitHub Pages landing page for Toga Wallet |
| Binary | `Davinci.VPN.3.2.dmg` | macOS variant (75 DL, 113MB) |
| Binary | `Davinci.VPN.3.2.AppImage` | Linux variant (52 DL, 111MB) |
| Binary | `Togasino.2.5.0.exe` | Fake casino (Windows) |
| Binary | `Toga.Wallet.2.1.4.exe` | Fake wallet (Windows, 49MB) |
| Binary | `NaturalVision.Enhanced.zip` | Fake GTA V mod (84MB) |
| Binary | `Furry.Realms.1.0.0.zip` | Fake game (8MB) |

### Network Indicators

| Type | Value | Description |
|------|-------|-------------|
| URL | `https://api.telegram.org/bot%s/%s` | Exfil endpoint (format string) |
| URL | `https://api.ipify.org` | Public IP lookup |
| Bot Token | `8649265515:AAEeUSZ0z_4tl1kHJeiAXrT0x-Zy0gT3XAE` | Telegram exfil bot #1 |
| Bot Token | `8795658457:AAGu9d8cIHqEKCKizhAzdG-ee4i_NaggUPE` | Telegram exfil bot #2 |
| Bot Token | `8610259315:AAGMtr2V66B1dB-5r9SSG3sLyWzD5f_r1DY` | Telegram exfil bot #3 |
| Bot Token | `8343732035:AAH_MIleKxP4UEEyerCF0fmDbABfCnSpyJg` | Telegram exfil bot #4 |
| Bot Token | `8721316403:AAFrkixAcAz9YZtSA1FiVp65zaUKx4lVQkU` | Telegram exfil bot #5 |
| DNS | `162.159.36.2` | Cloudflare DNS (VT sandbox observation) |

### Host Indicators

| Type | Value | Description |
|------|-------|-------------|
| VersionInfo | CompanyName: `DavinciLLC` | PE metadata |
| VersionInfo | ProductName: `DAVINCI VPN` | PE metadata |
| VersionInfo | InternalName: `davinciVPN.exe` | PE metadata |
| Anti-VM | `C:\Windows\System32\drivers\vmhgfs.sys` | VMware detection |
| Anti-VM | `C:\Windows\System32\drivers\vmmouse.sys` | VMware detection |
| Anti-VM | `C:\Windows\System32\drivers\prl_tg.sys` | Parallels detection |
| Mutex-like | `toga_baup13.lock` in `%TEMP%` | Execution lock |

---

## MITRE ATT&CK

| Tactic | Technique | ID | 根拠 |
|--------|-----------|-----|------|
| Defense Evasion | Virtualization/Sandbox Evasion: System Checks | T1497.001 | `vmhgfs.sys`/`vmmouse.sys` 存在チェック |
| Defense Evasion | Masquerading: Match Legitimate Name | T1036.005 | 「Davinci VPN」偽装 |
| Credential Access | Credentials from Password Stores: Chromium | T1555.003 | `ChromeBasedProcessor` + DPAPI復号 |
| Credential Access | Credentials from Password Stores: Firefox | T1555.004 | `FirefoxProcessor` |
| Credential Access | Steal Web Session Cookie | T1539 | Cookie SQLクエリ + DPAPI復号 |
| Collection | Data from Local System | T1005 | `FilesProcessor` |
| Collection | Data Staged: Local Data Staging | T1074.001 | ZIP化してから送信 |
| Discovery | System Information Discovery | T1082 | `system_info.json` / `api.ipify.org` |
| Exfiltration | Exfiltration Over Web Service | T1567 | Telegram Bot API |
| Resource Development | Acquire Infrastructure: Botnet | T1583.005 | 5つのTelegram Bot |

---

## 解析タイムライン

> 本解析は以下の手順で実施された。

| 時刻 | ツール | 操作 |
|------|--------|------|
| 22:37 | malware-fetch | `probe` — GitHub Releases URL のアクセス可否確認。Direct OK |
| 22:37 | malware-fetch | `fetch` — 48,675,328 bytes を AES-256-CBC 暗号化取得 |
| 22:38 | malware-fetch | `check` — VT ハッシュ照合。12/75 `trojan.stealer` |
| 22:38 | ghidra-headless | `quarantine-analyze` — PE 解析 (binary_info → list_functions → list_imports → list_exports → extract_strings → decompile_all) |
| 22:40 | malware-fetch | `behavior` — VT サンドボックスレポート取得。`toga_baup13.lock` ドロップ確認 |
| 22:42 | strings (container) | Go 埋め込み文字列抽出 — 5 Processor 型、Telegram Bot Token 5個、Cookie SQL クエリ、VM検知パス発見 |
| 22:56 | malware-sandbox | `analyze` — VMware sandbox 動的解析 (Host-Only + FakeNet)。90秒観察 |
| 23:04 | malware-sandbox | アーティファクト収集 — `toga_baup13.lock` (188), `.ses`, Edge `Local State` アクセス、7接続 |
| 23:09 | malware-sandbox | VM検知指標調査 — 13 VMware ドライバ、VMware BIOS、`00:0C:29` MAC 露出確認 |
| 23:35 | ghidra-headless (container) | バイナリパッチ — 6箇所のVM検知文字列を1バイトずつ変更 |
| 00:10 | malware-sandbox | パッチ版実行 — 120秒観察。~50接続、lock=888、D3Dキャッシュ生成 |
| 00:24 | — | 比較分析 — パッチ前後でネットワーク活動7倍差を確認 |

---

48MBの「VPNクライアント」。5つのTelegramボット。6バイトのパッチで本性が現れるAnti-VM。4つのペルソナ。3つのOS。622人の被害者。そしてGitHub Releasesに堂々と公開。

2025年12月に作られた使い捨てアカウントが、VPN、ウォレット、カジノ、ゲームモッドという4つの顔を使い分けて、4ヶ月間にわたり異なるユーザー層からクレデンシャルを収穫し続けていた。全ての道は `toga_baup13.lock` と5つのTelegramボットに通じている。

防御側の諸兄へ: `toga_baup13.lock` と `api.telegram.org/bot8649265515:` を今すぐ検索してほしい。ヒットしないことを祈っている。

ヒットした場合、ブラウザに保存したパスワードは全てTelegramのどこかのチャットに転送済みである。
