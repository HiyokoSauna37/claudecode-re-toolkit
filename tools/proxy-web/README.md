# Proxy Web - Sandboxed Malware Site Analysis Tool

危険なWebサイト（マルウェア配布サイト、フィッシングサイト等）に安全にアクセスし、フォレンジック分析を行うツール。

## 機能

- **完全隔離**: Dockerコンテナで実行、ホストシステムに影響なし
- **defang/refang**: マスクされたURLを自動検出・復元
- **スクリーンショット**: フルページキャプチャ
- **HTML取得**: ページのHTMLソースを保存
- **ダウンロード検知**: 実行可能ファイル等のダウンロードを検知
- **ハッシュ算出**: MD5, SHA1, SHA256
- **VirusTotal連携**: ハッシュ値を自動検索
- **ネットワークログ**: すべてのHTTP(S)通信をCSV形式で記録
- **暗号化保存**: ダウンロードファイルを暗号化＋圧縮して隔離
- **リトライ機能**: 接続失敗時に3回まで再試行（Torプロキシ対応）
- **ナレッジ蓄積**: 成功した接続方法をSKILLSフォルダに記録

## セットアップ

### 1. 依存関係インストール

```bash
cd Tools/proxy-web
pip install -r requirements.txt
```

### 2. Dockerイメージのビルド

```bash
docker build -t proxy-web-browser:latest .
```

### 3. 環境変数設定

`.env`ファイルに以下を追加：

```bash
# 必須: Quarantineファイルの暗号化パスワード（32文字以上推奨）
QUARANTINE_PASSWORD=your-strong-password-here-32chars-minimum

# オプション: VirusTotal API key
VIRUSTOTAL_API_KEY=your-virustotal-api-key
```

**重要**: パスワードを失うと復号化不可能になります。安全に保管してください。

## 使い方

### Claude Codeスキル経由（推奨）

```
/proxy-web
```

### 直接実行

```bash
cd Tools/proxy-web
python proxy_web.py
```

URLを入力：
```
Enter URL to analyze (supports defanged URLs):
> hxxps://malware-site[.]com/download
```

## 出力ファイル

```
Quarantine/
└── malware-site.com/
    └── 20260202_120000/
        ├── malware.exe.enc.gz    # 暗号化＋圧縮されたマルウェア
        ├── metadata.json          # メタデータ（URL、ハッシュ、VirusTotal結果等）
        ├── screenshot.png         # スクリーンショット
        ├── page.html              # ページHTML
        └── network.csv            # ネットワークログ（Timeline Explorer対応）
```

### metadata.json例

```json
{
  "url": "https://malware-site.com/download/trojan.exe",
  "timestamp": "2026-02-02T12:00:00Z",
  "domain": "malware-site.com",
  "final_url": "https://malware-site.com/download/trojan.exe",
  "downloads": [
    {
      "filename": "trojan.exe",
      "hashes": {
        "md5": "5d41402abc4b2a76b9719d911017c592",
        "sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
        "sha256": "a3f5d8e9b2c4f1a6e3d7c9b8a5f2e1d4c3b6a9f8e7d6c5b4a3f2e1d0c9b8a7f6"
      },
      "virustotal": {
        "detected": 45,
        "total": 72,
        "permalink": "https://www.virustotal.com/gui/file/a3f5d8...",
        "scan_date": "2026-02-02T12:01:00Z"
      },
      "encrypted_file": "trojan.exe.enc.gz"
    }
  ]
}
```

### network.csv（Timeline Explorer対応）

| Timestamp | Method | URL | Domain | StatusCode | ContentType | Description |
|-----------|--------|-----|--------|------------|-------------|-------------|
| 2026-02-02 12:00:01.234 | GET | https://malware-site.com/ | malware-site.com | 200 | text/html | Initial page load |
| 2026-02-02 12:00:02.567 | GET | https://malware-site.com/download/trojan.exe | malware-site.com | 200 | application/x-msdownload | Malware download |

## ファイル復号化

暗号化されたファイルを復号化：

```bash
python decrypt_quarantine.py Quarantine/malware-site.com/.../trojan.exe.enc.gz -o trojan.exe
```

または.envのパスワードを自動使用：
```bash
python decrypt_quarantine.py Quarantine/.../trojan.exe.enc.gz
```

**警告**: 復号化したファイルは危険です。隔離された環境で取り扱ってください。

## Timeline Explorer でのネットワークログ分析

1. Eric ZimmermanのTimeline Explorerをダウンロード
2. `network.csv`を開く
3. Timestampでソート
4. ドメイン、StatusCode、ContentTypeでフィルタ
5. 攻撃の流れを時系列で分析

## セキュリティ上の注意

- **プライベートリポジトリ限定**: Quarantineフォルダはローカルのみ（Gitignore設定済み）
- **暗号化パスワード管理**: `.env`を安全に保管、紛失時は復号化不可
- **マルウェア取り扱い**: 研究・教育目的のみ、配布・実行は違法
- **VirusTotal API**: 無料枠は4リクエスト/分、500リクエスト/日
- **Docker隔離**: コンテナ実行後は自動削除、ホストシステムへの影響なし

## トラブルシューティング

### Dockerイメージが見つからない

```bash
docker build -t proxy-web-browser:latest .
```

### 接続タイムアウト

- ツールが自動的に3回リトライします
- 2回目の失敗後、Torプロキシ経由を試行（設定されている場合）

### VirusTotal APIエラー

- レート制限（4リクエスト/分）を超過した場合、15秒待機して再試行
- API keyが無効な場合、VirusTotal検索はスキップされます

## ライセンス

研究・教育目的のみ。マルウェアの配布・実行は禁止。
