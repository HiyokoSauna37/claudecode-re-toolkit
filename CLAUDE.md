# CLAUDE.md

## About This Repository

Claude Codeを利用したマルウェア解析ツールキット。
静的解析（Ghidra Headless）、動的解析（VMware Sandbox）、Webフォレンジック（Proxy Web）の3つのスキルを統合し、Claude Codeからワンストップでマルウェア解析を実行できる。

## Repository Structure

```
cc-malware-toolkit/
├── .claude/skills/          # Claude Code スキル定義
│   ├── proxy-web/           # Web安全アクセス＆フォレンジック
│   ├── ghidra-headless/     # Ghidra静的解析（Docker）
│   └── vmware-sandbox/      # VMware動的解析
├── tools/
│   ├── proxy-web/           # Proxy Web ツール本体
│   ├── ghidra-headless/     # Ghidra Headless ツール本体
│   └── vmware-sandbox/      # VMware Sandbox ツール本体
└── reports/                 # 解析レポート出力先
```

## Setup

### 前提条件

- **Windows 10/11**（Linux/macOSは未サポート）
- [Claude Code](https://claude.com/claude-code) がインストール済み
- Docker Desktop がインストール・起動済み
- Go 1.21+ （Go版ツールのビルド用）
- Python 3.10+

### 環境変数

リポジトリルートに `.env` を作成（`.env.example` を参照）:

```bash
cp .env.example .env
# .env を編集して各APIキー・パスワードを設定
```

### 各ツールのセットアップ

#### proxy-web（Docker必須）

```bash
cd tools/proxy-web
go build -o proxy-web.exe .
docker build -t proxy-web-browser:latest .
```

#### ghidra-headless（Docker必須）

```bash
cd tools/ghidra-headless
docker compose up -d
```

#### vmware-sandbox（VMware Workstation必須）

[tools/vmware-sandbox/docs/VM-SETUP.md](tools/vmware-sandbox/docs/VM-SETUP.md) を参照してVM環境を構築。

## Skills

### proxy-web
危険なWebサイト（マルウェア配布サイト、フィッシングサイト等）にDockerコンテナ経由で安全にアクセスし、スクリーンショット・HTML・ダウンロードファイルを暗号化取得。VirusTotal / MalwareBazaar / ThreatFox連携。

### ghidra-headless
Ghidra Headless AnalyzerをDockerコンテナで実行し、バイナリの静的解析（インポート分析、文字列抽出、デコンパイル、YARA/CAPA/IOC抽出、マルウェア分類）を自動化。

### vmware-sandbox
VMware Workstation上のWindows VMをvmrun CLIで操作し、マルウェアの動的解析を実行。3-Level Unpacking System（memdump-racer / TinyTracer / x64dbg）、Frida DBI、FakeNet-NGによるC2通信キャプチャに対応。

## Analysis Workflow

```
1. proxy-web でURLアクセス → バイナリ取得（暗号化）
2. ghidra-headless で静的解析 → パッカー/ファミリー判定
3. パック済み or 静的解析限界 → vmware-sandbox で動的解析
4. アンパック後バイナリ → ghidra-headless で再解析
```

## Security Notes

- マルウェアファイルはコンテナ内でAES-256-CBC暗号化。ホストに生バイナリは出現しない
- VM動的解析は必ずネットワーク隔離（Host-Only）で実行
- Quarantine / output ディレクトリはGitignore設定済み
- **ホストOS上でマルウェアを復号化しないこと** — 必ずDocker/VM内で復号

## Claudeへの指示

### 回答スタイル
- 結論ファースト、簡潔に
- 段階報告不要

### マルウェアファイルの復号化
- **ホストOS上で絶対にマルウェアを復号化しない**
- 暗号化ファイルはそのままDocker/VMにコピーし、内部で復号する
- この規則は絶対に破らないこと

### Git管理
- 解析ツールのコード変更があればコミット＆プッシュ
- Quarantine / output / logs ディレクトリはコミットしない
