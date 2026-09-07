# Frida Android 解析ガイド

## 概要

Frida server をエミュレータ上で動作させ、ホストからリモートでランタイムフックを行う。
APK パッカー（NMMP 等）のアンパック、WebView の監視、暗号化通信の復号に使用。

## セットアップ

### 前提条件

- Python **3.11+**（3.10 は `NotRequired` import エラー）
- `pip install frida-tools`
- frida-server（GitHub Releases、**バージョン完全一致必須**）

### バージョン確認

```bash
# ホスト側
frida --version   # → 17.17.0

# frida-server も同じバージョンをダウンロード
# frida-server-17.17.0-android-x86_64.xz
```

### 導入

```bash
bash tools/android-sandbox/android-sandbox.sh frida-setup
```

## 提供スクリプト

### hook_webview.js

WebView の全操作をフック:

| フック対象 | 目的 |
|---|---|
| `WebView.loadUrl` | 表示 URL の記録 |
| `WebView.evaluateJavascript` | JS 注入の検出 |
| `WebView.addJavascriptInterface` | JS ブリッジの検出（メソッド一覧付き） |
| `URL.$init` | HTTP 接続先の記録 |
| `HttpURLConnection.getInputStream` | HTTP 通信の記録 |
| `Cipher.doFinal` | AES 等の暗号化/復号データ |
| `SharedPreferences.putString` | 設定値の保存 |
| `Base64.decode` | Base64 デコード結果 |
| `VpnService.Builder.*` | VPN 設定（addAddress, addRoute, establish） |
| `PackageInstaller.createSession` | APK インストール（ドロッパー検出） |

使用例:
```bash
bash tools/android-sandbox/android-sandbox.sh frida-hook org.mega.fast.snap hook_webview.js
```

### dump_dex.js

NMMP 等のパッカーがランタイムに復号する DEX をメモリからダンプ:

| フック対象 | 説明 |
|---|---|
| `InMemoryDexClassLoader.$init` | Android 8+ のメモリ内 DEX ロード |
| `DexClassLoader.$init` | ファイルベース DEX ロード |
| `PathClassLoader.$init` | パスベース DEX ロード |
| `DexFile.loadDex` | ネイティブ DEX ロード |

ダンプされた DEX は `/sdcard/dumped_dex_*.dex` に保存され、
`frida-dump-dex` コマンドが自動で `output/` にプルする。

使用例:
```bash
bash tools/android-sandbox/android-sandbox.sh frida-dump-dex org.mega.fast.snap
# → output/dex_dump_YYYYMMDD_HHMMSS/ に DEX ファイルが保存される
```

### bypass_root_detect.js

エミュレータ検知・ルート検知をバイパス:

| バイパス対象 | 手法 |
|---|---|
| `Build.*` プロパティ | Pixel 2 の値に偽装 |
| `File.exists` | `/system/bin/su`, `/dev/goldfish` 等をブロック |
| `SystemProperties.get` | `qemu`, `goldfish`, `nox` 系キーを空文字に |
| `TelephonyManager` | SIM: NTT DOCOMO、IMEI: ランダム生成 |
| `LocationManager` | GPS 有効を返す |
| `PackageManager` | Frida/Xposed/Magisk パッケージを除外 |

使用例:
```bash
# bypass + hook を同時に使う場合は 1 つのスクリプトにマージするか、
# Frida の -l フラグを複数指定
frida -U -l bypass_root_detect.js -l hook_webview.js -f org.mega.fast.snap --no-pause
```

## 注意事項

- **Frida server はエミュレータ起動ごとに再導入が必要**（`-wipe-data` でデータが消えるため）
- `frida -f` (spawn) は新規プロセスで起動するため、既に実行中のアプリには `frida -U <package>` (attach) を使う
- NMMP パッカーの DEX ロードは起動直後に発生するため、**spawn モード (`-f`) が必須**
- `timeout` コマンドで Frida の実行時間を制限すると安全（`timeout 60 frida ...`）
