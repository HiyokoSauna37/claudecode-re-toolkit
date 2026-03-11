# CYNEX推奨モニタリングツール・解析ガイド

## CYNEX推奨モニタリングツール一覧

ゲスト内解析ツールテーブルの追加（CYNEX ホワイトペーパー セクション6推奨）:

| ツール | パス | 用途 | 備考 |
|--------|------|------|------|
| Autoruns | tools\autoruns\autoruns64.exe | 永続化メカニズム一覧検出 | Sysinternals。Run/Service/Task/COM等を網羅 |
| Regshot | tools\regshot\Regshot-x64-ANSI.exe | レジストリ前後差分比較 | regshot_diff.pyと連携。1st→実行→2nd→Compare |
| Sysmon | サービスとしてインストール | カーネルレベルイベントログ | プロセス生成/ネットワーク/ファイル変更をEventLogに記録 |
| TCPView | tools\tcpview\tcpview64.exe | リアルタイムTCP/UDP接続監視 | Sysinternals。C2接続をリアルタイム確認 |
| Process Hacker | tools\processhacker\ProcessHacker.exe | 高機能プロセスマネージャ | メモリ読み書き/ハンドル操作/DLLインジェクション検出 |
| Wireshark | C:\Program Files\Wireshark\Wireshark.exe | パケットキャプチャ | FakeNet-NG併用でC2プロトコル詳細分析 |

**推奨追加ツール（手動インストール）:**

| 優先度 | ツール | 用途 | 備考 |
|---|---|---|---|
| HIGH | Autoruns | 永続化メカニズム検出 | Sysinternals |
| HIGH | Regshot | レジストリ前後比較 | regshot_diff.pyと連携 |
| MEDIUM | Sysmon | カーネルレベルイベントログ | 要サービスインストール |
| MEDIUM | TCPView | リアルタイム接続監視 | Sysinternals |
| MEDIUM | Process Hacker | 高機能プロセスマネージャ | メモリ/ハンドル操作 |
| LOW | BlobRunner | シェルコード実行補助 | デバッグ用 |
| LOW | Resource Hacker | PEリソース抽出 | アイコン/文字列 |

## 解析安全チェックリスト（CYNEX 4.3準拠）

### 解析前チェック
- [ ] クリーンスナップショットに復帰済み
- [ ] ネットワークがHost-Only（またはDisconnected）に切替済み
- [ ] `sandbox.sh net-status` で確認済み
- [ ] マルウェア検体は暗号化Zipで管理（パスワード付き）
- [ ] ホスト→ゲストのファイル共有は一方向（ゲスト→ホストの自動コピー無効）
- [ ] ホストOSのリアルタイム保護が有効（万一のエスケープ対策）

### 解析中チェック
- [ ] マルウェア実行前にモニタリングツールを起動（ProcMon/FakeNet/Regshot 1st等）
- [ ] 実行後の待機時間を十分確保（デフォルト60秒、Sleep bombing検体は延長）
- [ ] NATモード使用時はユーザー確認を取得済み
- [ ] 解析ログを記録中（`logs/YYYYMMDD_<target>.md`）

### 解析後チェック
- [ ] 解析結果（テキスト/スクリーンショット/ダンプ）をホストに回収済み
- [ ] クリーンスナップショットに復帰済み
- [ ] 解析ログを完成（Key Findings/IOCs記載）
- [ ] 暗号化Zip以外の形式でマルウェアがホスト上に残っていないことを確認

## デバッグ目的ガイド（CYNEX 4.4準拠）

| デバッグ目的 | 想定シーン | 推奨ツール | 手法 |
|---|---|---|---|
| **難読化解析** | CFG平坦化、VMProtect仮想化、文字列暗号化 | x64dbg + ScyllaHide, Frida DBI | ブレークポイントで復号後メモリを確認。Fridaで復号関数フック |
| **挙動詳細** | API呼び出し順序、引数・戻り値の確認 | API Monitor, ProcMon, Frida | API MonitorでAPI呼び出しトレース。ProcMonでファイル/レジストリ監視 |
| **暗号処理** | C2通信の暗号化/復号、データexfil方式 | x64dbg, Frida, Wireshark | 暗号API（BCrypt*/Crypt*）にブレーク。Fridaで引数/戻り値ダンプ |
| **解析回避対応** | Anti-Debug, Anti-VM, Sleep bombing | Frida bypass_vmdetect.js, ScyllaHide | Fridaで自動バイパス。ScyllaHideでNtQueryInformationProcess偽装 |

### 目的別推奨フロー

```
難読化解析:
  Ghidra静的解析 → 暗号化関数特定 → x64dbg/Fridaでランタイム復号 → 復号済みデータ取得

挙動詳細:
  ProcMon起動 → FakeNet起動 → マルウェア実行 → ログ回収 → ファイル/レジストリ/通信の時系列分析

暗号処理:
  imports解析でCrypt API特定 → Fridaフックで引数/戻り値キャプチャ → 暗号鍵/IV/平文を取得

解析回避対応:
  sandbox-evasion-check実行 → 検知項目修正 → Frida bypass有効化 → マルウェア再実行
```

## ツールプロセス名オブファスケーション（CYNEX 6章）

マルウェアはProcess32First/NextWで解析ツールのプロセス名をチェックする。
EXE名を変更することで検知を回避できる。

### リネーム対象と推奨名

| 元のEXE名 | リネーム例 | 備考 |
|---|---|---|
| procmon.exe | svchost2.exe | ProcMon |
| procmon64.exe | conhost2.exe | ProcMon 64bit |
| wireshark.exe | netcfg.exe | Wireshark |
| x64dbg.exe | notepad2.exe | デバッガ |
| x32dbg.exe | calc2.exe | デバッガ 32bit |
| processhacker.exe | dllhost2.exe | Process Hacker |
| fiddler.exe | explorer2.exe | Fiddler |
| die.exe | mspaint2.exe | Detect It Easy |
| pestudio.exe | winlogon2.exe | pestudio |
| fakenet.exe | lsass2.exe | FakeNet-NG |

### 運用手順

1. `sandbox.sh evasion-check` でプロセス名検知を確認
2. 検知されたツールのEXEをリネーム
3. 再度 `sandbox.sh evasion-check` で検知が解消されたことを確認
4. **注意**: リネーム後もショートカットや設定ファイル内のパスは元のままなので、必要に応じて更新

### sandbox-evasion-checkとの連携

```bash
# 1. 診断実行
bash tools/vmware-sandbox/sandbox.sh evasion-check

# 2. レポートで "Analysis tool processes" が FAIL なら
#    検知されたプロセスをリネーム

# 3. 再診断で PASS を確認
bash tools/vmware-sandbox/sandbox.sh evasion-check
```

## 通信エミュレーション拡張ガイド（CYNEX 6章）

マルウェアのC2通信を安全にキャプチャするための3レベル構成。

### Level 1: FakeNet-NG（現行・基本）

```bash
# ゲスト内でFakeNet-NG起動（ゲスト内ツールパスは環境依存）
bash tools/vmware-sandbox/sandbox.sh exec "<GUEST_TOOLS>/fakenet/fakenet3.5/fakenet.exe"
```

- **対応プロトコル**: DNS, HTTP, HTTPS, SMTP, FTP, IRC, BITS
- **特徴**: 全ドメインをlocalhost解決、偽HTTP応答
- **制限**: カスタムバイナリプロトコル、WebSocket、DoHには非対応
- **用途**: 基本的なC2ドメイン/URI/User-Agent特定

### Level 2: INetSim（計画）

- **対応プロトコル**: DNS, HTTP/HTTPS, FTP, SMTP, POP3, TFTP, NTP, Syslog等 14+
- **特徴**: 実際のファイルダウンロード応答、SSL証明書生成
- **用途**: より高度なC2エミュレーション、ファイルダウンロード追跡

### Level 3: Custom C2 Mock（上級・手動）

マルウェアファミリが特定された後、そのC2プロトコルに合わせたモックサーバーを構築。

- **用途**: StealC, Lumma等のC2 APIエンドポイントを再現
- **手法**: Python Flask/FastAPIで特定のレスポンスを返すサーバー
- **前提**: 静的解析/動的解析でC2プロトコルが判明していること

```python
# 例: StealC v2 C2モック（概念）
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route("/api", methods=["POST"])
def c2_handler():
    data = request.json
    if data.get("opcode") == "init":
        return jsonify({"status": "success", "config": "..."})
    return jsonify({"status": "waiting"})
```

### レベル選択指針

| 状況 | 推奨レベル |
|---|---|
| 初期トリアージ、C2ドメイン特定 | Level 1 (FakeNet-NG) |
| ダウンローダー、多段ペイロード | Level 2 (INetSim) |
| 特定ファミリの深掘り解析 | Level 3 (Custom Mock) |
