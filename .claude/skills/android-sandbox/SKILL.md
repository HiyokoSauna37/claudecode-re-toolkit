---
name: android-sandbox
description: >-
  Android SDK エミュレータ上で APK マルウェアの動的解析を行う。
  Frida server によるランタイムフック、CDP (Chrome DevTools Protocol) による
  WebView インスペクション、logcat によるネットワーク監視に対応。
  NMMP 等のパッカー保護された APK のランタイム DEX ダンプにも対応。
  Use when: Android APK解析, APKマルウェア, Android動的解析, android-sandbox,
  DEXダンプ, Frida Android, WebView解析, NMMP, APKアンパック, logcat,
  Android エミュレータ, APK sandbox, apk dynamic analysis
  Do NOT use for: Windows PE動的解析（malware-sandboxを使用）, 静的解析のみ（ghidra-headlessを使用）,
  Webサイトへの安全アクセス（malware-fetchを使用）
globs:
  - "tools/android-sandbox/**"
---

## 概要

**検体を扱う前に隔離を確認する。** 現行の `install` / `apk-triage` / `analyze` に `.enc.gz` を渡すと、ホスト上に復号 APK ができる。暗号化したまま Docker / VM に渡して静的調査し、平文はホストへコピーしない。

**悪性 APK にワンコマンドの `analyze` を使わない。** ネットワーク隔離と ADB の対象固定が組み込まれていない。動的解析へ進む前に、外部通信が遮断された専用エミュレータであることと、全コマンドで対象シリアルが固定されていることを確認する。両方を確認できない場合は静的調査や取得済みログを使う。

**保存済みの CDP・logcat を報告するときは、宛先・時刻・根拠だけを抜き出す。** フォーム入力、POST 本文、URL クエリに含まれる認証情報は伏せる。

Android SDK エミュレータ（ホスト上で直接実行）で APK マルウェアを動的解析する。
VMware VM ではなくホストの Android エミュレータを使用するため、VT-x を直接利用でき高速。

主な解析手法:
- **logcat + ネットワーク監視**: C2 通信先、URL、API 呼び出しの特定
- **CDP (Chrome DevTools Protocol)**: WebView 内部のページ内容・JS ブリッジ・ネットワークリクエストの傍受
- **Frida**: ランタイムフック（API フック、DEX ダンプ、暗号化通信の復号）
- **APK 静的トリアージ**: パッカー判定と JNI 文字列抽出。パッケージ名と権限は別途マニフェストを確認する

## 前提条件

- Android SDK cmdline-tools（`ANDROID_SDK_PATH` で指定）
- system-images;android-28;default;x86_64（または互換イメージ）
- Java 17+（SDK ツールの実行に必要）
- Python 3.11+（Frida を使う場合。3.10 は `NotRequired` import エラー）
- `frida-tools`（pip install、バージョンは Frida server と一致必須）

## 環境変数（.env）

```bash
ANDROID_SDK_PATH=           # Android SDK ルート（例: %USERPROFILE%\android-sdk）
ANDROID_AVD_NAME=malware_analysis  # 解析用 AVD 名
ANDROID_API_LEVEL=28        # システムイメージの API レベル
FRIDA_SERVER_VERSION=       # frida-server バージョン（frida-tools と一致必須）
```

## コマンド早見表

```bash
AS="bash tools/android-sandbox/android-sandbox.sh"

# === エミュレータ管理 ===
$AS preflight                      # 環境チェック
$AS start                          # エミュレータ起動（ヘッドレス）
$AS start --gui                    # エミュレータ起動（GUI 表示）
$AS stop                           # エミュレータ停止
$AS status                         # 状態確認（adb devices + エミュレータ情報）

# === APK 管理 ===
$AS install <apk_path>             # 検証用の無害な APK のみ
$AS uninstall <package>            # アンインストール
$AS launch <package>               # アプリ起動（am start）

# === ネットワーク ===
$AS net-isolate                    # ネットワーク遮断（airplane mode）
$AS net-enable                     # ネットワーク有効化

# === 解析 ===
$AS analyze <apk> [wait=60]        # 隔離を組み込んでいないため、無害な APK のみ
$AS logcat [filter]                # logcat キャプチャ
$AS screenshot [output]            # スクリーンショット
$AS processes                      # プロセスリスト
$AS network-connections            # TCP 接続一覧（IP デコード済み）

# === WebView 解析 (CDP) ===
$AS cdp-inspect <package>          # CDP 接続 → JS ブリッジ検出 + ページ情報取得
$AS cdp-eval <package> "<js>"      # CDP 経由で JS 実行
$AS cdp-monitor <package> [sec]    # CDP でネットワークリクエスト監視

# === Frida ===
$AS frida-setup                    # Frida server をエミュレータに導入・起動
$AS frida-hook <package> <script>  # Frida スクリプトでフック
$AS frida-dump-dex <package>       # ランタイム DEX ダンプ（NMMP 等のアンパック）

# === 静的トリアージ（エミュレータ不要）===
$AS apk-triage <apk>              # JNI 文字列・ファイル構成からのパッカー判定
```

## 解析ワークフロー

### 基本フロー

```
1. $AS preflight                # 環境チェック
2. # パッケージ名と権限は隔離環境でマニフェストを確認
3. $AS start                    # エミュレータ起動（ブート完了まで待機、ブロッキング）
4. $AS net-isolate              # ネットワーク遮断（airplane mode）
5. $AS install sample.apk       # APK インストール
6. $AS launch <package>         # アプリ起動（Step 2 で取得したパッケージ名）
7. $AS screenshot               # 画面キャプチャ
8. $AS net-enable               # ネットワーク有効化（通信先の特定が必要な場合）
9. $AS logcat "chromium|http|url|mega|snap"  # logcat で通信を監視（grep -iE）
10. $AS cdp-inspect <package>   # WebView内部を調査（JSブリッジ検出）
11. $AS frida-hook <package> hook_webview.js  # URLロード・暗号化をフック
12. $AS stop                    # エミュレータ停止
```

**`start` コマンドはブロッキング**: 内部で `adb wait-for-device` + `getprop sys.boot_completed` をポーリングし、ブート完了後に返る。

**`logcat` の filter**: 拡張正規表現を渡す。`"chromium|http|url"` で URL 関連ログを絞る。フィルタを省くと全ログを取得する。

### NMMP パッカー解析フロー

NMMP（nmm-protect）等のパッカーで保護された APK の場合:

```
1. $AS apk-triage sample.apk    # 静的トリアージ（エミュレータ不要）
   → libnmmp.so / libnmmvm.so 検出 → NMMP パッカー確定
   → JNI 文字列から機能マップ抽出
   → パッケージ名取得
   → isSandboxEnvironment 等のエミュレータ検知文字列の有無を確認

2. $AS start                    # エミュレータ起動（ブート完了まで待機）
3. $AS net-isolate              # ネットワーク遮断
4. $AS install sample.apk       # 無害な検証用 APK の場合

5. $AS frida-setup              # Frida server をエミュレータに導入・起動

6. $AS frida-dump-dex <package> # ランタイム DEX ダンプ
   → NMMP が復号した DEX をメモリからダンプ
   → 出力: output/dex_dump_YYYYMMDD_HHMMSS/*.dex

   # Step 1 で isSandboxEnvironment が検出された場合:
   # frida-dump-dex の代わりに手動で bypass を併用:
   # frida -U -l frida-scripts/bypass_root_detect.js \
   #        -l frida-scripts/dump_dex.js \
   #        -f <package> --no-pause

7. ダンプした DEX を Ghidra / jadx で解析
   → docker cp output/dex_dump_*/*.dex ghidra-headless:/input/
   → bash tools/ghidra-headless/ghidra.sh analyze /input/dumped_dex.dex
   → C2 URL、暗号鍵、通信プロトコルを特定

8. $AS stop                     # エミュレータ停止
```

**`apk-triage` は AndroidManifest.xml を解析しない。** パッケージ名や権限が必要なら、隔離環境で APK のマニフェストを別途読み取る。

### WebView フィッシング解析フロー

WebView で正規サイトを表示してクレデンシャルを窃取するタイプ:

```
1. # 隔離環境でマニフェストを確認してパッケージ名を得る
2. $AS start --gui               # エミュレータ起動（GUI 表示、ブート完了まで待機）
3. $AS net-isolate               # ネットワーク遮断（初期状態は安全側）
4. $AS install sample.apk        # APK インストール
5. # 外部通信を遮断したまま、取得済みの画面・通信記録やローカルの模擬応答を使う
6. $AS launch <package>          # アプリ起動
7. $AS screenshot                # 初期画面キャプチャ
8. $AS cdp-inspect <package>     # CDP 接続 → JS ブリッジ検出
   → 表示 URL（正規サイトか確認）
   → JS ブリッジ検出（addJavascriptInterface）
   → フォーム構造取得
9. $AS cdp-monitor <package> 60  # ネットワークリクエスト監視（60秒）
   → XHR/fetch フック → 送信データキャプチャ
10. $AS cdp-eval <package> "document.getElementById('password').value"
   → 入力値がアプリ側から読めることを実証
11. $AS network-connections      # TCP 接続一覧で通信先 IP を確認
12. $AS stop                     # エミュレータ停止
```

**CDP の前提条件**: アプリの WebView が `WebView.setWebContentsDebuggingEnabled(true)` を呼んでいる必要がある。多くのマルウェアはデバッグビルドまたはリリースビルドでもこれを有効にしている（開発時のまま出荷）。無効な場合は `cdp-inspect` が「No WebView debug endpoint found」を返す。

## ネットワーク安全管理

### 原則: エミュレータはホスト上で動作する

VMware VM と異なり、エミュレータはホスト OS 上で直接実行される。
マルウェア APK がネットワークアクセスを持つ = ホストのネットワークスタックを使う。

| モード | 方法 | 安全度 |
|--------|------|--------|
| **Airplane Mode** | `adb shell settings put global airplane_mode_on 1` | 高（推奨） |
| **emulator -no-internet** | 起動フラグ | 高 |
| **NAT（デフォルト）** | エミュレータ標準 | 低（C2 通信キャプチャ時のみ） |

**C2 通信のキャプチャが必要な場合のみ NAT を有効にする。**
マルウェアの VPN 機能が発動すると、ホストのトラフィックには影響しない
（エミュレータ内の VPN はエミュレータ内のトラフィックのみ対象）。

## .enc.gz ファイルの取り扱い

`.enc.gz` は暗号化したまま Docker / VM へ渡し、ホスト非共有の作業領域に復号する。平文 APK や DEX をホストへ取り出さず、必要な解析結果だけを回収する。安全な経路が用意できるまでは静的調査に留める。

## CDP (Chrome DevTools Protocol) 詳細

WebView の内部をリモートから完全制御できるプロトコル。

### 接続手順

```bash
# 1. WebView のデバッグソケットを特定
adb shell cat /proc/net/unix | grep webview_devtools

# 2. ポートフォワーディング
adb forward tcp:9224 localabstract:webview_devtools_remote_<PID>

# 3. ページ情報取得
curl http://localhost:9224/json
# → [{"title": "ログイン - 楽天", "url": "https://login.account.rakuten.com/...", "webSocketDebuggerUrl": "ws://..."}]

# 4. WebSocket で接続して JS 実行
# → Python の websocket-client ライブラリで Runtime.evaluate を送信
```

### CDP で確認すべき項目

| 確認項目 | CDP コマンド | 目的 |
|---|---|---|
| 表示 URL | `Runtime.evaluate: location.href` | 正規サイトか偽サイトか |
| JS ブリッジ | `Runtime.evaluate: window.Android` | addJavascriptInterface の検出 |
| フォーム構造 | `Runtime.evaluate: document.querySelectorAll('input')` | 入力フィールドの特定 |
| ネットワーク | `Network.enable` → `Network.requestWillBeSent` | XHR/fetch の監視 |
| Cookie | `Network.getCookies` | セッション Cookie の取得状況 |

## Frida スクリプト

### hook_webview.js
WebView の URL ロード、JS ブリッジ呼び出し、暗号化通信をフック。
→ `tools/android-sandbox/frida-scripts/hook_webview.js`

### dump_dex.js
NMMP 等のパッカーが復号した DEX をメモリからダンプ。
`InMemoryDexClassLoader` と `DexClassLoader` をフックし、ロード時に DEX バイト列を保存。
→ `tools/android-sandbox/frida-scripts/dump_dex.js`

### bypass_root_detect.js
エミュレータ検知・ルート検知をバイパス。
→ `tools/android-sandbox/frida-scripts/bypass_root_detect.js`

## 注意事項

- **Frida server とクライアントのバージョンは完全一致が必要**。不一致だと接続時にエラー
- **Python 3.10 では Frida 17.x が動かない**（`NotRequired` import エラー）。対策: Python 3.11+ にするか、`pip install "frida==16.5.6" "frida-tools==12.5.0"` で 3.10 対応版を使う
- **`adb root` が必須**: frida-server は root 権限で動かす必要がある。`adb root` を実行してから `adb push` + 起動。shell ユーザーだと `unable to find process with name 'system_server'` エラーになる
- **Frida spawn が `system_server` エラーで失敗する場合**: frida-server が shell ユーザーで動いている。`adb root` → frida-server 再起動で解決
- **エミュレータのサンドボックス検知**: マルウェアがエミュレータを検知して動作を制限することがある。`isSandboxEnvironment` 等の文字列が見つかった場合は `bypass_root_detect.js` を使用。検知項目の実例: `/dev/socket/qemud`, `/dev/qemu_pipe`, `/dev/goldfish_pipe`, `ro.kernel.qemu`, `qemu.sf.lcd_density`
- **NMMP パッカーの DEX ダンプが 0 件になる場合**: NMMP は `InMemoryDexClassLoader` を使わず、ネイティブコード内で独自に DEX をロードする。`dump_dex.js` の Java レベルフックでは捕まらない。この場合は CDP + logcat で C2/通信先を直接監視する方が有効
- **VMware との排他**: エミュレータ起動中は VMware VM の同時起動を避ける（VT-x 競合の可能性）
- **CDP の「次へ」ボタン**: 楽天等の React SPA では「次へ」が `<button>` ではなく `<div>` の場合がある。`document.querySelectorAll('button')` で見つからない場合は XPath (`//*[contains(text(),"次")]`) で検索

## 2026-09 解析事例: 楽天偽装 APK での知見

### 過去の観測

この事例では NMMP の特徴、パッケージ名 `org.mega.fast.snap` と権限 5 件を確認した。パッケージ名と権限はマニフェストから取得する。以下は当時の観測例で、実行前に冒頭の隔離・対象固定を確認する。

```bash

# 3. Frida バイパス (adb root 必須!)
adb root                          # ← これがないと frida-server が動かない
$AS frida-setup
frida -U -l bypass_root_detect.js -l hook_webview.js -f org.mega.fast.snap
# → エミュレータ検知バイパス成功
# → WebView.loadUrl: https://login.account.rakuten.com/... をキャプチャ
# → addJavascriptInterface: Android (class b2.n) getDeviceId をキャプチャ

# 4. CDP でログインフローを進行
$AS cdp-inspect org.mega.fast.snap
# → タイトル: "ログイン - 楽天"、URL: login.account.rakuten.com (正規)
# → JSブリッジ: window.Android.getDeviceId() → "f9a750dfebf73447"

$AS cdp-eval org.mega.fast.snap "<ユーザーID入力のJS>"
$AS cdp-eval org.mega.fast.snap "<パスワード入力のJS>"
# 注意: 「次へ」ボタンは <div> なので XPath で検索

# 5. CDP ネットワーク監視でPOSTキャプチャ
$AS cdp-monitor org.mega.fast.snap 45
# → POST /v2/login/start → user_id が平文で見える
# → POST /v2/login/complete → user_key (パスワード) が平文で見える
# → マルウェアの WebViewClient.shouldInterceptRequest() で傍受可能

# 6. NMMP DEX ダンプは失敗（NMMPは独自ローダーを使用）
$AS frida-dump-dex org.mega.fast.snap
# → 0件。InMemoryDexClassLoader を経由しないため
```

### 解析で判明した事実

| 項目 | 結果 |
|---|---|
| WebView 表示先 | 楽天の正規 SSO (`login.account.rakuten.com`) |
| JS ブリッジ | `window.Android.getDeviceId()` (class: `b2.n`) |
| 通信先 | Akamai CDN (楽天正規サーバー) のみ |
| C2 / VPN | エミュレータ検知バイパス後も未発動 |
| エミュレータ検知 | qemud/goldfish/qemu_pipe + SystemProperties |
| NMMP DEX ダンプ | 不可（ネイティブ独自ローダー） |

## 関連スキル連携

- **ghidra-headless**: 抽出した .so ファイルの静的解析（ELF/ARM 対応）。ダンプした DEX の解析
- **malware-fetch**: APK のダウンロード・暗号化保存。フィッシングページの取得
- **malware-sandbox**: Windows PE マルウェアの動的解析（Android は本スキル）
- **threat-intel**: APK ハッシュの VT/MalwareBazaar 照会
