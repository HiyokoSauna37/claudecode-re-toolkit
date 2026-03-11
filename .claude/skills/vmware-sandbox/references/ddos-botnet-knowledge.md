# DDoSボットネット解析ナレッジ（run.exe / 2026-02-24）

## 攻撃チェーン
1. **UPXドロッパー** (install.exe) → 展開 → `run.exe` をドロップ＆実行
2. **run.exe**: Go製C2ボット（DDoSボットネットクライアント）
3. C2サーバーから攻撃指令を受信 → SYN Flood / UDP Flood / HTTP Flood 等を実行

## Go製C2ボットの特徴
- **コンパイラ**: Go (GCC-Go or gc)。Ghidraでは`go.`プレフィクスの関数名で識別
- **関数名のmiddle dot**: Go内部パッケージパスに `·` (U+00B7, middle dot) を使用 → Jython/Python2で`UnicodeEncodeError`を起こす
- **インポートの特殊性**: Goバイナリは通常のPEインポートテーブルが最小限。syscall経由で直接呼び出すため、imports解析だけでは不十分
- **RTTI/型情報**: Goランタイムの型情報（`runtime.typestring`等）から構造体名やメソッド名を復元可能
- **大量の関数**: Goランタイム＋標準ライブラリが静的リンクされるため、関数数が5000+になることが多い
- **strings解析が有効**: C2アドレス、攻撃メソッド名、エラーメッセージ等がリテラル文字列として残りやすい

## 解析時の注意点
- Ghidra静的解析ではGoバイナリの関数名復元が不完全 → `list_functions.py`の結果でGoパッケージ構造を推測
- `strings`解析でC2 URL、攻撃メソッド名（syn, udp, http等）、設定値を探す
- 動的解析ではネットワーク通信をキャプチャしてC2プロトコルを特定（Host-Onlyモードではブロックされるため、必要に応じてNAT）
