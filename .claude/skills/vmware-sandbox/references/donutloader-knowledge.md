# DonutLoader解析ナレッジ（2026-02-25）

## 検体情報
- **SHA256**: `e7acc171f303d8c399f7e01f0091fe0e6253b8f81c6e444ec644d57463462f9d`
- **VT Detection**: 39/76 (trojan.tedy/zusy)
- **Packer**: MinGW-w64 + CFG Flattening + Sleep Bombing

## 特徴
- **CFG Flattening**: 20,292関数中98.1%が51-100bytesの均一サイズ（制御フロー平坦化）
- **Sleep Bombing**: 97.7%の関数（19,833/20,292）がSleepを呼び出し。合計115,000+回のSleep呼び出し
- **TLS Callbacks**: 2個のTLSコールバックでアンチデバッグ
- **暗号化ペイロード**: .rdataセクションに2.6MBのhex-encoded暗号化ペイロード
- **偽装情報**: 13個の偽Clangバージョン文字列、偽会社名"Modern Cyber Core Inc"
- **最終ペイロード**: Donutシェルコードフレームワーク（AMSI/WDLTD/ETWバイパス）→ StealC推定

## Frida解析結果
- **Sleep無効化**: 115,000+回のSleep呼び出しを全て0msに書き換え → 高速実行
- **VirtualAlloc**: 3回のアロケーション（512B RWX, 960KB RW×2 = ステージング領域）
- **VirtualProtect**: 32KBをPAGE_EXECUTE_READ(0x20)に変更 → ペイロード展開
- **メモリダンプ**: `dump_001_vp_215ffda1000_32768.bin` (32KB x86-64コード)
- **結果**: ペイロード展開後もVM検知が動作しプロセス終了（CPUID/VMware I/Oポート経由 — Fridaではフック不可）

## 教訓
- Frida DBI はユーザーモードAPI（Sleep, VirtualProtect等）のフックには有効
- CPUIDやVMwareバックドアI/Oポート（IN命令）はカーネルレベルのため、Fridaではバイパス不可
- カーネルレベルVM検知のバイパスにはVMX設定変更（Phase 1: harden-vmx）が必要
