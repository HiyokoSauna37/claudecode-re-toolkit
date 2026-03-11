# VMProtect二層構造とDevirtualization

VMProtectで保護されたバイナリには2つの保護層がある:

| 層 | 内容 | 除去ツール | 状態 |
|----|------|-----------|------|
| **Layer 1: パッキング** | コード暗号化、IAT隠蔽、アンチダンプ | memdump-racer (Level 1) | 除去可能 |
| **Layer 2: コード仮想化** | x86命令をVMP bytecodeに変換、VMディスパッチャで実行 | Mergen (LLVM lifting) | 対応中 |

## Layer 1: パッキング層（除去済み）
- memdump-racerのタイミングベースダンプで除去
- アンパック後のPEにはインポートテーブルが復元される
- Ghidraで基本的なデコンパイルが可能になる

## Layer 2: コード仮想化層（Mergenで対応）
- アンパック後もVMP仮想化された関数はデコンパイルできない
- Ghidraでは「VMディスパッチャループ」としか見えない
- Mergenで仮想化関数をLLVM IRにリフティング → 元のロジックを復元

## Devirtualizationパイプライン

```bash
# 1. パッキング層の除去（既存）
bash tools/vmware-sandbox/sandbox.sh unpack /path/to/packed.exe

# 2. VMP関数アドレスの検出
tools/dump-triage/dump-triage.exe --vmp-addrs /path/to/unpacked.exe > vmp_addrs.txt

# 3. Devirtualization（LLVM IRへの変換）
bash tools/mergen/mergen.sh devirt /path/to/unpacked.exe 0x140001000
# または一括:
bash tools/mergen/mergen.sh devirt-batch /path/to/unpacked.exe vmp_addrs.txt

# 4. Ghidra再解析（LLVM IR出力と照合）
bash tools/ghidra-headless/ghidra.sh analyze /path/to/unpacked.exe

# ワンコマンド（自動検出＋一括devirt）:
bash tools/vmware-sandbox/sandbox.sh devirt /path/to/unpacked.exe
```

## Mergenの使い方

**コンテナ管理:**
```bash
bash tools/mergen/mergen.sh start    # ビルド＆起動（初回: ~10分）
bash tools/mergen/mergen.sh stop     # 停止
bash tools/mergen/mergen.sh status   # 状態確認
bash tools/mergen/mergen.sh shell    # コンテナ内シェル
```

**Devirtualization:**
```bash
# 単一関数
bash tools/mergen/mergen.sh devirt <binary> <address>
# → tools/mergen/output/<binary>_<address>.ll にLLVM IR出力

# アドレスリストから一括
bash tools/mergen/mergen.sh devirt-batch <binary> <addresses.txt>
# → 各アドレスごとに.llファイル出力

# VMPセクションスキャン
bash tools/mergen/mergen.sh scan <binary>
# → VMP関数候補アドレスを表示
```

**LLVM IR出力の読み方:**
- `define` で始まる関数定義 = devirtualize済みの元のロジック
- `load`/`store` = メモリアクセス（レジスタ相当の操作含む）
- `call` = 外部API呼び出し（C2通信、ファイル操作等の特定に使える）
- 最適化パスにより冗長なVMハンドラコードが除去され、本質的なロジックのみ残る

**制限事項:**
- VMP 3.x の全ハンドラに対応しているとは限らない（新バージョンで追加されたハンドラは未対応の可能性）
- 間接ジャンプが3分岐以上の関数は失敗する場合がある
- devirt失敗時はTriton（動的シンボリック実行）をフォールバックとして検討

## dump-triage VMP アドレス検出

```bash
# VMP関数アドレスをMergen入力形式で出力
tools/dump-triage/dump-triage.exe --vmp-addrs <binary>
```

出力形式:
```
# VMP Address Candidates: install.exe
# ImageBase: 0x140000000
# EntryPoint RVA: 0x00001000 (VA: 0x140001000)
# EntryPoint is INSIDE a VMP section

# Section: .vmp0    VA=0x00001000 Size=0x50000

0x140001000
0x140002340
0x14000A100
...
```

検出ロジック:
- 非標準セクション名 + 実行可能属性 = VMPセクション
- セクション内のCALL/JMPターゲットを列挙
- エントリポイントがVMPセクション内の場合フラグ

## install.exe解析ナレッジ（VMP 3.x）

VMP 3.xの典型的なセクション構造:
- セクション名が難読化（`.uBq`, `.J)t`, `.sYB`等）
- VMPセクションがバイナリの90%以上を占有
- インポートテーブルが空（0個）
- エントリポイントがVMPセクション内

memdump-racer結果:
- Layer 1（パッキング）は200-300msのタイミングダンプで除去成功
- Layer 2（仮想化）はメモリダンプでは除去不可 → Mergenが必要
