---
title: "GitHub Releasesで配布されていた偽VPNアプリ「Davinci VPN」を解析 — Toga Stealerキャンペーン"
emoji: "🎭"
type: "tech"
topics: ["security", "malware", "reverseengineering", "vpn", "cybersecurity"]
published: false
---

![Toga Campaign 全体構成図](https://static.zenn.studio/user-upload/099e2e3560d6-20260518.png)
## はじめに

GitHubのReleasesページで配布されていた「Davinci VPN 3.2」というアプリを解析したところ、VPN機能は一切実装されておらず、ブラウザの保存パスワード・Cookie・暗号ウォレット・Telegramセッションを窃取してTelegram Bot APIで送信するInfo Stealerであることが判明した。

さらに配布元アカウントを調査した結果、同一の攻撃者がVPN・カジノ・ウォレット・ゲームモッドという4つの偽装で同種のStealerを配布する「Toga Campaign」を2026年1月から展開していたことが分かった。

本記事ではその解析過程と調査結果を報告する。

:::message alert
本記事はマルウェア解析の技術的知見共有を目的としています。記載されたURL/ハッシュを使ったマルウェアの取得・実行は絶対に行わないでください。
:::

---

## 想定される感染経路

### GitHubでの配布

このStealerはGitHub Releasesページで配布されていた。SNSや検索エンジン経由でこのURLに誘導されたユーザーがダウンロード・実行する流れが想定される:

```
github.com/gutsyheartpeu/davinci-vpn/releases
```

GitHubは正規のソフトウェア配布に広く使われるプラットフォームであり、URLだけでは不審と判断しにくい点が攻撃者に悪用されている。

### Releasesページの構成

3プラットフォーム向けのバイナリが用意されていた:

| ファイル | OS | サイズ |
|---------|-----|--------|
| `Davinci.VPN.3.2.exe` | Windows | 48MB |
| `Davinci.VPN.3.2.dmg` | macOS | 113MB |
| `Davinci.VPN.3.2.AppImage` | Linux | 111MB |

3プラットフォーム対応で、一見すると正規プロジェクトのように見える構成になっている。

### 実行時の挙動

実行するとVPNのGUIは表示されず、Windowsの「どのアプリで開きますか？」ダイアログが表示されるだけで、ユーザーからは何も動いていないように見える。しかしバックグラウンドでは以下の処理が数秒で完了している:

![](https://static.zenn.studio/user-upload/f558b1374d1c-20260518.png)
*マルウェア実行の流れ*

永続化機構は実装されておらず、窃取完了後に自己終了するワンショット型のStealerである。

---

## 解析してみた

### VirusTotalの結果

> **SHA256**: `3b5563c3993f051887091959e0be6c01412d6a9b0ec4c7ee4d2c1cfe71c465c8`
> **VT検出率**: 12/75

75のアンチウイルスエンジンのうち、検出できたのは12だけ。Kasperskyは `Trojan-PSW.Win64.Stealer`（パスワード窃取型トロイ）、Tencentは `LummaStealer` と分類した。残りの63エンジンは「問題なし」と回答している。

### Go言語で書かれた本格的なStealer

Ghidra（リバースエンジニアリングツール）で解析すると、Go言語で書かれた48MBのバイナリであることが分かった。37,021個の関数を持ち、内部に5つの「窃取モジュール」が実装されている。

Goバイナリはシンボル（関数名）を丁寧に残してくれるため、意図がはっきり読み取れる:

| モジュール名 | 窃取対象 |
|-------------|---------|
| `ChromeBasedProcessor` | Chrome、Edge、Brave、Opera、Vivaldi の保存パスワード・Cookie |
| `FirefoxProcessor` | Firefox のログイン情報・Cookie |
| `CryptoWalletProcessor` | MetaMask等ブラウザ拡張の暗号ウォレット |
| `TelegramProcessor` | Telegram Desktopのセッションデータ |
| `FilesProcessor` | その他ファイル |

全モジュールが同じパターンで動く: **データ抽出 → ZIP圧縮 → Telegramに送信**。

### Chromeのパスワードはどう盗まれるのか

Chrome（やEdge等のChromium系ブラウザ）は保存パスワードをAES-GCMで暗号化して `Login Data` というSQLiteデータベースに格納している。暗号化キーは `Local State` ファイルにDPAPI（Windows Data Protection API）で保護された状態で保存されている。

このStealerは:

1. `Local State` を読んでDPAPIの暗号化キーを取得
2. `Login Data` をSQLiteでクエリ
3. 各パスワードをAES-GCMで復号

バイナリにはSQLクエリがそのまま埋まっていた:

```sql
SELECT host_key, name, path, encrypted_value,
       expires_utc, is_secure, is_httponly FROM cookies
```

Chromeに保存されたパスワードやCookieが復号・窃取される仕組みである。

### 盗んだデータの送信先: 5つのTelegramボット

このStealerは自前のC2サーバー（指令サーバー）を持たない。代わりに**Telegram Bot API**を使う。バイナリに5つのボットトークンが平文で埋め込まれていた:

```
8649265515:AAEeUSZ0z_4tl1kHJeiAXrT0x-Zy0gT3XAE
8795658457:AAGu9d8cIHqEKCKizhAzdG-ee4i_NaggUPE
8610259315:AAGMtr2V66B1dB-5r9SSG3sLyWzD5f_r1DY
8343732035:AAH_MIleKxP4UEEyerCF0fmDbABfCnSpyJg
8721316403:AAFrkixAcAz9YZtSA1FiVp65zaUKx4lVQkU
```

`https://api.telegram.org/bot<token>/sendDocument` で窃取データのZIPを送信する。C2サーバーの構築・維持が不要で、攻撃者にとってはコストのかからないインフラとなっている。

---

## サンドボックスで動かしてみた

### 1回目: VMwareだとバレた

VMware上のWindows 10で実行したところ、ネットワーク接続がたった**7件**しか発生しなかった。5つのモジュールがあるはずなのに、おかしい。

調べてみると、バイナリ内に**仮想マシン検知コード**が埋まっていた:

```
C:\Windows\System32\drivers\vmhgfs.sys   ← VMwareのドライバ
C:\Windows\System32\drivers\vmmouse.sys  ← VMwareのマウスドライバ
C:\Windows\System32\drivers\prl_tg.sys   ← Parallelsのドライバ
```

これらのファイルが存在するかチェックし、VMware上だと検知すると動作を大幅に制限していた。

### 2回目: 6バイト変えたら本気を出した

バイナリ内の検知文字列を1文字ずつ変更した。`vmhgfs.sys` → `xmhgfs.sys`。たった**6バイト**の修正。

結果は劇的だった:

| 指標 | パッチ前 | パッチ後 |
|------|---------|---------|
| ネットワーク接続数 | 7 | **約50** |
| ロックファイル値 | 188 | **888** |
| 外部IP接続 | 0 | **10** |
| GUI表示試行 | なし | **あり** |

**7倍のネットワーク活動。** VM検知を回避した途端、全モジュールが一斉に動き出し、Telegram APIへの送信を積極的に試みた。パッチ前は「解析環境っぽいから最低限だけ動こう」という判断を自動で行っていたことになる。

:::message
マルウェア解析において、Anti-VM回避は重要なステップです。バイナリパッチは本番環境では行わず、必ず隔離されたサンドボックス環境で実施してください。
:::

---

## 「Davinci VPN」は氷山の一角だった

### Toga Campaign: 4つの顔を持つキャンペーン

配布元のGitHubアカウント `gutsyheartpeu` を調査したところ、**Davinci VPNは4つのペルソナで展開される組織的キャンペーンの一部**であることが判明した。

このアカウントは2025年12月29日に作成され、フォロワー0、プロフィール空白。典型的な使い捨てアカウントだ。

```
gutsyheartpeu の6つのリポジトリ
├── davinci-vpn      (2026-04)  ← VPNユーザーを狙う
├── davinciVPN       (2026-04)  ← ミラー
├── kjsa             (2026-03)  ← カジノ好きを狙う「Togasino」
│   └── (旧タグ)     (2026-01)  ← 暗号資産ユーザーを狙う「Toga Wallet」
├── tgdw             (2026-01)  ← Toga Walletのランディングページ
├── NaturalVision    (2026-01)  ← ゲーマーを狙う（GTA Vモッド偽装）
└── wallet-core      (2026-02)  ← Trust Wallet偽装（未リリース）
```

### 4つのペルソナ、4つの標的層

| ペルソナ | 標的 | 手口 | ダウンロード数 |
|---------|------|------|:---:|
| 🔒 **Davinci VPN** | 無料VPNを探す人 | 「VPNクライアント」を装う | **522** |
| 🎰 **Togasino** | カジノ好き | 「カジノアプリ」を装う | **54** |
| 💰 **Toga Wallet** | 暗号資産保有者 | 「ウォレット」を装い、専用サイトまで用意 | **26** |
| 🎮 **NaturalVision** | ゲーマー | GTA Vの人気モッドを装う | **20** |

![Toga Campaign 全体構成図](https://static.zenn.studio/user-upload/099e2e3560d6-20260518.png)
*Toga Campaign 全体構成図*

合計**622件以上**のダウンロード。全プラットフォーム（Windows / macOS / Linux）対応。

### "Toga" は偶然ではない

このキャンペーンの内部名称は**「Toga」**だと考えられる。根拠:

- マルウェアが作成するロックファイル名: `toga_baup13.lock`
- 偽カジノアプリ名: **Toga**sino
- 偽ウォレット名: **Toga** Wallet
- ランディングページのドメイン: wallet.**toga**development.org

全てに "Toga" が含まれている。

### ランディングページの完成度

`wallet.togadevelopment.org` にはGitHub Pagesで構築された本格的なランディングページが存在していた:

- 「**Your Gateway to Web3**」というキャッチコピー
- 「50+ blockchains対応」
- 「No registration required • 100% Free」
- ダウンロードボタンは GitHub Releases の `.exe` / `.dmg` に直結

一見すると、本物のウォレットサービスと区別がつかない。

---

## 参考: 偽VPN/偽アプリによるStealer配布は業界全体で報告されている

Toga Campaignは孤立した事例ではない。2026年に入り、偽VPNや偽アプリを使ったInfo Stealer配布キャンペーンが複数のセキュリティベンダーから相次いで報告されている。

### 関連キャンペーン・レポート一覧

| 時期 | キャンペーン / マルウェア | 手口 | 報告元 |
|------|------------------------|------|--------|
| 2026-03 | **Storm-2561 / Hyrax** | Pulse Secure、Fortinet、Cisco等の**企業向けVPNクライアントを偽装**。SEO Poisoningで誘導し、C2サーバーへ認証情報を送信 | [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/03/12/storm-2561-uses-seo-poisoning-to-distribute-fake-vpn-clients-for-credential-theft/) |
| 2026-04 | **NWHStealer** | **偽Proton VPNサイト**（`vpn-proton-setup[.]com` 等）から配布。25以上の暗号ウォレットフォルダを窃取。C2障害時のフォールバックとして**Telegram dead drop**を使用 | [Malwarebytes](https://www.malwarebytes.com/blog/threat-intel/2026/04/from-fake-proton-vpn-sites-to-gaming-mods-this-windows-infostealer-is-everywhere) |
| 2025-12〜2026-02 | **Torg Grabber** | **728種の暗号ウォレット**と850のブラウザ拡張を標的。初期は**Telegram経由**でデータ送信、後にHTTPSに移行。3ヶ月で334検体がコンパイルされた | [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-torg-grabber-infostealer-malware-targets-728-crypto-wallets/) |
| 2026 | **Raccoon Stealer (偽VPN版)** | NordVPN、F-Secure Freedom、Avast Secureline等を偽装したインストーラーで配布。Inno Setupに正規VPNとStealerを同梱 | [Zscaler](https://www.zscaler.com/blogs/security-research/threat-actors-distribute-malicious-vpn-apps-masquerading-popular-vendors) |
| — | **Trojan:Win32/Toga** | Microsoft Defenderの検出名として `Trojan:Win32/Toga` が登録されている。詳細な技術情報は未公開 | [Microsoft Security Intelligence](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:Win32/Toga) |

### Toga Campaignとの共通点・相違点

これらのキャンペーンと今回のToga Campaignには共通するパターンがある:

- **偽アプリによる信頼の悪用**: 正規ソフトウェアを装ってユーザーに自発的にインストールさせる
- **ブラウザ認証情報 + 暗号ウォレット**: 狙う資産が共通している
- **Telegram の悪用**: NWHStealerはフォールバックC2に、Torg Grabberは初期のexfilに、Toga CampaignはメインのexfilにTelegramを使用

一方で、Toga Campaignには以下の独自性がある:

| 特徴 | Toga Campaign | 他キャンペーン |
|------|-------------|-------------|
| 配布インフラ | **GitHub Releases + GitHub Pages** | 独自ドメインの偽サイト |
| 言語 | **Go + Fyne** | C/C++, .NET 等 |
| プラットフォーム | **Win / macOS / Linux** | 多くはWindowsのみ |
| ペルソナ数 | **4種（VPN/Casino/Wallet/Game）** | 通常1〜2種 |
| C2 | **Telegram Bot APIのみ（5トークン）** | 専用C2サーバー |

偽VPNによるStealer配布は2026年現在、複数の脅威アクターが並行して展開する**主要な攻撃トレンド**となっている。Toga Campaignはその中でGitHub活用とクロスプラットフォーム展開に特徴を持つ一例と位置づけられる。

---

## 影響範囲と対処

### 感染時に想定される被害

- ブラウザに保存されたパスワード・Cookie の漏洩
- Cookieによるセッションハイジャック
- ブラウザ拡張型暗号ウォレットのデータ漏洩
- Telegram Desktopセッションの窃取
- パブリックIPおよびシステム情報の収集

### 感染が疑われる場合の対処

- [ ] `%TEMP%` フォルダに `toga_baup13.lock` または `.ses` ファイルがないか確認する
- [ ] ブラウザに保存したパスワードを変更する（優先: メール、金融系、SNS）
- [ ] 暗号ウォレットを使用している場合、資産を新しいウォレットに移行する
- [ ] Telegramの「アクティブなセッション」を確認し、不審なセッションを全て終了する
- [ ] 二要素認証（2FA）を有効にしていないサービスに設定する

### 予防策

**1. ソフトウェアの入手元を確認する**

GitHubは誰でもアカウントを作成しファイルをアップロードできるプラットフォームであり、Releasesにバイナリを置くのに審査はない。以下の点を確認するとリスクを低減できる:

- リポジトリにソースコードがあるか（Releasesにバイナリだけのリポジトリは注意）
- アカウントの作成時期、フォロワー数、Star数
- READMEにプロジェクトの説明があるか

**2. パスワード管理方法の見直し**

ブラウザの内蔵パスワードマネージャーはInfo Stealerの主要な窃取対象になっている。1PasswordやBitwarden等の専用パスワードマネージャーの使用も検討に値する。

**3. ダウンロード前のスキャン**

[VirusTotal](https://www.virustotal.com/) でファイルを事前に検査できる。ただし今回のケースでは検出率12/75であり、スキャン結果だけで安全性を判断できない点には留意が必要。

---

## まとめ

GitHub Releasesで配布されていた「Davinci VPN 3.2」はVPN機能を持たないInfo Stealerだった。5つの窃取モジュール（Chrome系・Firefox・暗号ウォレット・Telegram・汎用ファイル）でデータを収集し、5つのTelegram Botで送信する構成になっている。

配布元アカウントの調査により、同一攻撃者がVPN・カジノ・ウォレット・ゲームモッドの4つの偽装で同種のStealerを4ヶ月以上にわたり配布する「Toga Campaign」を展開していたことが判明した。推定622件以上のダウンロードが発生しており、Windows・macOS・Linuxの3プラットフォームが対象となっている。

非公式な配布元からのソフトウェアダウンロードには、このようなリスクが伴う。ソフトウェアの入手時には配布元の信頼性を確認し、ブラウザへのパスワード保存に依存しない運用を検討してほしい。

---

:::details IOC（セキュリティ担当者向け）

### ファイルハッシュ
| Type | Value |
|------|-------|
| SHA256 | `3b5563c3993f051887091959e0be6c01412d6a9b0ec4c7ee4d2c1cfe71c465c8` |
| MD5 | `be06f733e4af47c1aa0da0940ab76368` |

### Telegram Bot Tokens
```
8649265515:AAEeUSZ0z_4tl1kHJeiAXrT0x-Zy0gT3XAE
8795658457:AAGu9d8cIHqEKCKizhAzdG-ee4i_NaggUPE
8610259315:AAGMtr2V66B1dB-5r9SSG3sLyWzD5f_r1DY
8343732035:AAH_MIleKxP4UEEyerCF0fmDbABfCnSpyJg
8721316403:AAFrkixAcAz9YZtSA1FiVp65zaUKx4lVQkU
```

### ネットワーク
| Type | Value |
|------|-------|
| Exfil API | `https://api.telegram.org/bot<token>/sendDocument` |
| IP Lookup | `https://api.ipify.org` |

### ホストアーティファクト
| Indicator | Location |
|-----------|----------|
| `toga_baup13.lock` | `%TEMP%` |
| `.ses` | `%TEMP%` |

### GitHub（配布元）
| Repo | Persona |
|------|---------|
| `gutsyheartpeu/davinci-vpn` | Davinci VPN |
| `gutsyheartpeu/kjsa` | Togasino / Toga Wallet |
| `gutsyheartpeu/tgdw` | Toga Wallet landing page |
| `gutsyheartpeu/NaturalVision` | GTA V mod / Furry Realms |

### ドメイン
```
wallet.togadevelopment.org
```

:::