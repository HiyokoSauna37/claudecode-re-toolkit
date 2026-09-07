# Android SDK エミュレータ セットアップガイド

## 前提条件

- Windows 10/11
- Java 17+（Eclipse Temurin 推奨）
- 3GB+ の空きディスク容量
- VMware VM が**停止中**であること（VT-x 競合回避）

## インストール手順

### 1. Android SDK command-line tools

```powershell
$SDK = "$env:USERPROFILE\android-sdk"
New-Item -ItemType Directory -Force -Path $SDK

# ダウンロード
Invoke-WebRequest -Uri "https://dl.google.com/android/repository/commandlinetools-win-11076708_latest.zip" `
  -OutFile "$env:TEMP\cmdline-tools.zip"

# 展開（ディレクトリ構造の修正が必要）
Expand-Archive "$env:TEMP\cmdline-tools.zip" -DestinationPath "$SDK\cmdline-tools-tmp" -Force
New-Item -ItemType Directory -Force -Path "$SDK\cmdline-tools"
Move-Item "$SDK\cmdline-tools-tmp\cmdline-tools" "$SDK\cmdline-tools\latest"
Remove-Item -Recurse "$SDK\cmdline-tools-tmp"
```

### 2. ライセンス承認 + パッケージインストール

```powershell
$sdkmanager = "$SDK\cmdline-tools\latest\bin\sdkmanager.bat"

# ライセンス承認
echo "y" | & $sdkmanager --sdk_root="$SDK" --licenses

# パッケージインストール
& $sdkmanager --sdk_root="$SDK" `
  "platform-tools" "emulator" "platforms;android-28" `
  "system-images;android-28;default;x86_64"
```

### 3. AVD 作成

```powershell
$avdmanager = "$SDK\cmdline-tools\latest\bin\avdmanager.bat"
echo "no" | & $avdmanager create avd -n "malware_analysis" `
  -k "system-images;android-28;default;x86_64" -d "pixel" --force
```

### 4. .env 設定

```bash
ANDROID_SDK_PATH=C:\Users\<user>\android-sdk
ANDROID_AVD_NAME=malware_analysis
ANDROID_API_LEVEL=28
```

### 5. 動作確認

```bash
bash tools/android-sandbox/android-sandbox.sh preflight
```

## Frida server セットアップ

### 1. ホスト側

```bash
pip install frida-tools  # Python 3.11+ 必須
```

### 2. Frida server ダウンロード

GitHub Releases から **frida-server-{version}-android-x86_64.xz** をダウンロード:
https://github.com/frida/frida/releases

```bash
# 解凍
xz -d frida-server-*.xz
# android-sandbox ディレクトリに配置
mv frida-server tools/android-sandbox/frida-server
```

**バージョンは `frida --version`（ホスト側）と完全一致が必須。**

### 3. エミュレータへの導入

```bash
bash tools/android-sandbox/android-sandbox.sh frida-setup
```

## websocket-client（CDP 用）

```bash
pip install websocket-client
```

## トラブルシューティング

### Frida `NotRequired` ImportError
```
ImportError: cannot import name 'NotRequired' from 'typing'
```
→ Python 3.10 では Frida が動かない。**3.11+ を使用**。

### エミュレータが起動しない
→ VMware VM が起動中だと VT-x が競合する。`vmrun list` で 0 台を確認してからエミュレータを起動。

### adb connect タイムアウト
→ エミュレータのブートには 30-60 秒かかる。`android-sandbox.sh start` は自動で待機する。
