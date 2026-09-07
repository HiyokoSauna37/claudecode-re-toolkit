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

Android SDK エミュレータ（ホスト上で直接実行）で APK マルウェアを動的解析する。
VMware VM ではなくホストの Android エミュレータを使用するため、VT-x を直接利用でき高速。

主な解析手法:
- **logcat + ネットワーク監視**: C2 通信先、URL、API 呼び出しの特定
- **CDP (Chrome DevTools Protocol)**: WebView 内部のページ内容・JS ブリッジ・ネットワークリクエストの傍受
- **Frida**: ランタイムフック（API フック、DEX ダンプ、暗号化通信の復号）
- **APK 静的トリアージ**: マニフェスト解析、パッカー判定、JNI 文字列抽出

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
$AS install <apk_path>             # APK インストール（.enc.gz 自動復号対応）
$AS uninstall <package>            # アンインストール
$AS launch <package>               # アプリ起動（am start）

# === ネットワーク ===
$AS net-isolate                    # ネットワーク遮断（airplane mode）
$AS net-enable                     # ネットワーク有効化

# === 解析 ===
$AS analyze <apk> [wait=60]        # ワンコマンド解析
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
$AS apk-triage <apk>              # マニフェスト解析 + JNI 文字列抽出 + パッカー判定
```

## 解析ワークフロー

### 基本フロー

```
1. $AS preflight                # 環境チェック
2. $AS apk-triage sample.apk   # 静的トリアージ → パッケージ名取得
3. $AS start                    # エミュレータ起動（ブート完了まで待機、ブロッキング）
4. $AS net-isolate              # ネットワーク遮断（airplane mode）
5. $AS install sample.apk       # APK インストール
6. $AS launch <package>         # アプリ起動（Step 2 で取得したパッケージ名）
7. $AS screenshot               # 画面キャプチャ
8. $AS net-enable               # ネットワーク有効化（通信先の特定が必要な場合）
9. $AS logcat "chromium\|http\|url\|mega\|snap"  # logcat で通信を監視（grep パターン）
10. $AS cdp-inspect <package>   # WebView内部を調査（JSブリッジ検出）
11. $AS frida-hook <package> hook_webview.js  # URLロード・暗号化をフック
12. $AS stop                    # エミュレータ停止
```

**`start` コマンドはブロッキング**: 内部で `adb wait-for-device` + `getprop sys.boot_completed` をポーリングし、ブート完了後に返る。

**`logcat` の filter**: grep 互換の正規表現パターンを渡す。例: `"chromium\|http\|url"` で URL 関連ログをフィルタ。フィルタなしで全ログを取得。

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
4. $AS install sample.apk       # APK インストール（.enc.gz の場合も自動復号対応）

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

**`apk-triage` は `.enc.gz` にも対応**: 内部で自動復号してトリアージを実行する（`QUARANTINE_PASSWORD` が必要）。

### WebView フィッシング解析フロー

WebView で正規サイトを表示してクレデンシャルを窃取するタイプ:

```
1. $AS apk-triage sample.apk    # 静的トリアージ → パッケージ名取得
2. $AS start --gui               # エミュレータ起動（GUI 表示、ブート完了まで待機）
3. $AS net-isolate               # ネットワーク遮断（初期状態は安全側）
4. $AS install sample.apk        # APK インストール
5. $AS net-enable                # ネットワーク有効化（WebView が正規サイトをロードするため必要）
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

malware-fetch で取得した `.enc.gz` ファイルは以下の手順で処理:

```bash
# Ghidra Docker コンテナ内で復号 → adb push
bash tools/ghidra-headless/ghidra.sh decrypt <file.enc.gz>
docker cp ghidra-headless:/tmp/<decrypted> /tmp/sample.apk
$AS install /tmp/sample.apk
rm /tmp/sample.apk  # ホスト上の復号済みファイルは即削除
```

または Python スクリプトでメモリ上復号 → 一時ファイル → adb install → 即削除:
```bash
$AS install <file.enc.gz>  # 自動復号 + インストール + 一時ファイル削除
```

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
- **Python 3.10 では Frida が動かない**（`NotRequired` import エラー）。3.11+ を使用
- **エミュレータのサンドボックス検知**: マルウェアがエミュレータを検知して動作を制限することがある。`isSandboxEnvironment` 等の文字列が見つかった場合は `bypass_root_detect.js` を使用
- **VMware との排他**: エミュレータ起動中は VMware VM の同時起動を避ける（VT-x 競合の可能性）
- **ホスト上の復号ファイル**: APK の復号は一時的にホスト上にファイルが存在する。`adb install` 完了後に即削除すること

## 関連スキル連携

- **ghidra-headless**: 抽出した .so ファイルの静的解析（ELF/ARM 対応）。ダンプした DEX の解析
- **malware-fetch**: APK のダウンロード・暗号化保存。フィッシングページの取得
- **malware-sandbox**: Windows PE マルウェアの動的解析（Android は本スキル）
- **threat-intel**: APK ハッシュの VT/MalwareBazaar 照会
