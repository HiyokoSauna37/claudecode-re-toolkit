# 補助解析ガイド

## Radare2との併用

Kaliコンテナにradare2がインストール済み。Ghidraとの使い分け:

| 目的 | ツール | コマンド例 |
|------|--------|-----------|
| 30秒トリアージ | **r2** | `docker exec kali bash -c "r2 -qc 'iI; iS; ii' /path/to/binary"` |
| エントロピー分析（パッカー判定） | **r2** | `docker exec kali bash -c "r2 -qc 'p=e' /path/to/binary"` |
| 暗号定数検出 | **r2** | `docker exec kali bash -c "r2 -qc '/cr' /path/to/binary"` |
| 文字列フィルタ検索 | **r2** | `docker exec kali bash -c "r2 -qc 'iz~http' /path/to/binary"` |
| 2検体のバイナリdiff | **r2** | `docker exec kali bash -c "radiff2 binary1 binary2"` |
| デコンパイル（C疑似コード） | **Ghidra** | `bash tools/ghidra-headless/ghidra.sh decompile <binary>` |
| 関数コールグラフ | **Ghidra** | `bash tools/ghidra-headless/ghidra.sh xrefs <binary>` |
| 不審API自動フラグ | **Ghidra** | `bash tools/ghidra-headless/ghidra.sh imports <binary>` |

推奨フロー: **r2で素早く「怪しい」を見つけて、Ghidraで「読む」**

## 暗号化/難読化ペイロードの動的解析エスカレーション

静的解析で以下の特徴が検出された場合、**自動的にVMware Sandbox動的解析を提案する**:

### エスカレーション条件
- 文字列の90%以上がhex-encoded/暗号化データ
- インポートテーブルが極端に少ない（<10個のDLL、動的API解決の兆候）
- .rdataや.rsrcに大きな暗号化ペイロードが埋め込まれている
- CFG平坦化・VMProtect・Themida等の難読化でデコンパイルが実質不可能
- C2アドレス・設定値がランタイム復号でしか取得できない

### 提案フロー
1. Ghidra静的解析完了
2. 上記条件に該当 → 「静的解析ではペイロード/C2の特定が不可能です。VMware Sandboxで動的解析を実行しますか？」とユーザーに提案
3. ユーザー同意 → malware-sandbox スキルで動的解析を実行
4. 動的解析結果（メモリダンプ/展開後バイナリ） → Ghidra再解析

### 動的解析で取得すべき情報
- **展開後ペイロード**: HollowsHunter/PE-sieveでメモリダンプ → Ghidra再解析でマルウェアファミリー特定
- **C2通信先**: プロセスモニタ/Wiresharkで通信先IP/ドメイン/URIパターン
- **API呼び出し**: API Monitorで動的に解決されたAPI一覧
- **ファイル/レジストリ変更**: ProcMonで永続化メカニズム特定

## ポスト解析: IOC活用ガイド

Ghidra解析で抽出したIOCを次のアクションに繋げる。OSINT自体はforensic-analysis/malware-sandboxが担当するが、**何を抽出し、どう使うか**は静的解析スキルの範囲内。

| 抽出したIOC | 次のアクション | 補足 |
|---|---|---|
| C2 IP/ドメイン | VTで関連検体検索、Shodanでインフラ調査 | `curl -s "https://www.virustotal.com/api/v3/domains/{domain}" -H "x-apikey: $VT_API_KEY"` |
| ハッシュ値 | VTで検出名・サンドボックス結果取得 | `curl -s "https://www.virustotal.com/api/v3/files/{hash}" -H "x-apikey: $VT_API_KEY"` |
| 特徴的文字列 | Google/GitHubでOSSベースのマルウェア特定 | ビルドパス、PDB情報、ユニークなエラーメッセージ等 |
| ファミリ名特定後 | ベンダブログで既知のTTPs/IOC取得 | MITRE ATT&CKマッピング |
| YARA向けパターン | 類似検体のハンティング | strings/imports結果からYARAルール素案を生成 |

**OSSベースのマルウェア判定**: ビルドパスやユニークな文字列をGitHubで検索し、ソースコードが公開されている場合はREADMEで機能一覧を把握できる（解析コスト大幅削減）。StealC v2のビルドパス発見と同じアプローチ。
