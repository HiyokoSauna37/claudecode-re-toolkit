# NMMP パッカー解析ナレッジ

## 概要

NMMP (nmm-protect) は中国発のオープンソース Android APK プロテクター。
DEX バイトコードをカスタム VM コードに変換し、ネイティブライブラリ内の VM インタプリタで実行する。

## 識別指標

- `com/nmmedit/protect/NativeUtil` クラスが DEX に存在
- `libnmmp.so` + `libnmmvm.so` が `lib/` 配下に存在（x86, armeabi-v7a, arm64-v8a）
- `assets/` 内にランダム名の大きなファイル（暗号化ペイロード、各 10-12MB）
- `AndroidManifest.xml` の CRC が意図的に破損（BadPack 対策）

## 構造

```
APK
├── classes.dex          # NMMP ローダー + AndroidX（1.6MB）
│   └── NativeUtil       # JNI メソッド登録（classesInit0, getCacheClass 等）
├── lib/
│   ├── libnmmp.so       # JNI ブリッジ + 暗号化/復号ロジック
│   └── libnmmvm.so      # カスタム VM インタプリタ（vmInterpret）
├── assets/
│   ├── <random1>        # 暗号化ペイロード 1（~12MB）
│   └── <random2>        # 暗号化ペイロード 2（~12MB）
└── AndroidManifest.xml  # CRC 破損（BadPack）
```

## 解析手法

### 静的解析の限界

Ghidra で libnmmp.so をデコンパイルすると、ほぼすべての関数が `vmInterpret()` ラッパー。
暗号化アルゴリズムは VM バイトコード内に隠蔽されており、静的解除は困難。

### JNI 型シグネチャの漏洩

NMMP は DEX メソッドを VM 化するが、**JNI の型シグネチャは暗号化できない**。
JVM とネイティブコードの橋渡しに平文のシグネチャが必須なため。

`strings libnmmp.so` で以下が抽出可能:
- JNI メソッドシグネチャ（呼び出し先クラス・メソッド名・引数型）
- 使用する Java API（WebView, VpnService, Cipher 等）
- 文字列定数（多言語 UI テキスト、ファイル名等）

### ランタイム DEX ダンプ（推奨）

Frida で `InMemoryDexClassLoader` / `DexClassLoader` をフックし、
NMMP が復号・ロードした DEX をメモリからダンプする。

```bash
bash tools/android-sandbox/android-sandbox.sh frida-dump-dex <package>
```

ダンプした DEX を jadx / Ghidra で解析 → C2 URL、暗号鍵、通信プロトコルを特定。

## 暗号化

- **アセット暗号化**: AES/CBC/PKCS5Padding（libnmmp.so の strings で確認）
- **鍵導出**: APK 署名ブロック（SIGNING_BLOCK_MAGIC）から導出される可能性が高い
- **IV**: アセットファイルの先頭 16 バイト

## 2026-09 解析事例: 楽天偽装 APK

- パッケージ名: `org.mega.fast.snap`
- バージョン: 2.9.74
- 暗号化アセット 2 本（各 11.9MB、異なるハッシュ）
- JSブリッジ: `window.Android.getDeviceId()` のみ確認（class: `b2.n`）
- VT 検出率: 0/75（楽天版）/ 7/75（ANA版）/ 5/75（セゾン版）
- エミュレータ検知: GPS ポーリング + `isSandboxEnvironment` + ファイル存在チェック（`/dev/qemu_pipe`, `/dev/goldfish_pipe`）+ SystemProperties（`ro.kernel.qemu`）

### DEX ダンプ結果

`InMemoryDexClassLoader` / `DexClassLoader` / `PathClassLoader` のフックで **0 件**。
NMMP は Java レベルの ClassLoader を経由せず、**ネイティブコード（libnmmvm.so の vmInterpret）内で直接 DEX バイトコードを解釈実行**する。
標準的な Frida DEX ダンプ手法では捕まらない。

対処:
- CDP + logcat で通信先を直接監視（C2/URL は動的に取得されるため通信時に見える）
- Frida で `Cipher.doFinal` / `Base64.decode` をフック → 復号された通信内容を傍受
- `bypass_root_detect.js` でエミュレータ検知をバイパスすると WebView は正常動作する

### Frida バイパスで判明したエミュレータ検知項目

```
[File.exists] /dev/socket/qemud
[File.exists] /dev/qemu_pipe
[File.exists] /dev/goldfish_pipe
[File.exists] /system/lib/libc_malloc_debug_qemu.so
[File.exists] /sys/qemu_trace
[File.exists] /system/bin/qemu-props
[SystemProperties] ro.kernel.qemu = 1
[SystemProperties] qemu.hw.mainkeys = 0
[SystemProperties] qemu.sf.lcd_density = 420
[SystemProperties] init.svc.qemu-props = stopped
```
