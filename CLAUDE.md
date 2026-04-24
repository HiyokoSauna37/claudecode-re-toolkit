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
- [VMware Workstation Pro](https://www.vmware.com/products/desktop-hypervisor/workstation-and-fusion)（vmware-sandboxスキルに必要、vmrun CLI利用）
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
docker build -t proxy-web-browser:latest tools/proxy-web/
```

proxy-web.exeはリポジトリに同梱済み。Goビルド不要。

#### ghidra-headless（Docker必須）

```bash
docker compose -f tools/ghidra-headless/docker-compose.yml up -d
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

### 個人情報（PII）漏洩防止 — 絶対厳守

このリポジトリは公開GitHub repo (`HiyokoSauna37/claudecode-re-toolkit`)。過去に実メール・ホストユーザー名がcommit/blobに混入し、履歴書き換え+force-pushで除去した経緯がある。**再発させない**。

#### 書き込み禁止パターン（具体値は書かず抽象化して理解する）
| カテゴリ | 置換先 |
|---|---|
| ホストWindowsの絶対パス（`C:\Users\<本名系>\...`） | `<host-user>` / `%USERPROFILE%` / `~` |
| VMゲストOSの絶対パス（`C:\Users\<ゲスト名>\...`） | `<guest-user>` / `<GUEST_TOOLS>` / `<GUEST_ANALYSIS_DIR>` |
| 個人メールアドレス（各種 ISP/プロバイダドメインの普通のメール） | `<ID>+<username>@users.noreply.github.com` |
| 個人Obsidianパス（`notes/*`）、ホスト上の外部プロジェクトパス | リポ内相対パスのみ使用 |

**許容される公開識別子**: GitHubハンドル・コミッター表示名のみ。具体的な値は `git config user.email` / `git log --format=%an | sort -u` で確認できるコミッターエイリアスの範囲にとどめる。

#### Go バイナリは `-trimpath` 必須
`go build` はソースファイルの絶対パスをバイナリに埋め込む。この repo では **全 Go バイナリを `-trimpath -ldflags="-s -w"` でビルドする**。

```bash
go build -trimpath -ldflags="-s -w" -o foo.exe .
```

確認: `strings foo.exe | grep -iE "C:/Users/|@gmail|@outlook"` で 0 ヒットになることを検証（ホストユーザー名・個人メールが埋め込まれていないか）

#### コミット前チェック（必ず実行）

ローカル環境のホスト/ゲストユーザー名を環境変数にセットしてから走らせる（このCLAUDE.md自体に具体値を書かないため）:

```bash
# 環境変数セット（実値は各自の環境に合わせる、CLAUDE.md には書かない）
export HOST_USER="$(whoami)"
export GUEST_USER="<your-vm-guest-username>"

# 1. tracked ファイルに個人情報が混入していないか
git ls-files | xargs -I{} grep -lE "C:\\\\+Users\\\\+(${HOST_USER}|${GUEST_USER})|@(outlook|gmail|yahoo|hotmail|icloud)\." "./{}" 2>/dev/null
# → 空出力が期待値（このCLAUDE.md自体もヒットしないこと）

# 2. Go バイナリに埋め込みパスがないか
for f in $(git ls-files '*.exe'); do
  hits=$(strings "$f" 2>/dev/null | grep -cE "C:/Users/(${HOST_USER}|${GUEST_USER})|@gmail|@outlook")
  [ "$hits" -eq 0 ] || echo "LEAK in $f: $hits hits"
done

# 3. コミット identity が noreply ドメインか
git config user.email | grep -q "users.noreply.github.com" && echo OK || echo "WARNING: non-noreply email"
```

#### test_out.txt / uploads/ 等の実行時成果物
Claude Agent SDK 経由のテスト出力や GUI のアップロードファイルは **ホストの絶対パス（cwd 等）を含む**。`.gitignore` で除外済みだが、新規の test/debug 出力ファイルを追加する際は必ず gitignore に追加する。

#### コミットメッセージにも注意
メッセージ本文に `C:\Users\shima` のような literal を書かないこと（過去にverificationログで混入した）。プレースホルダ表記に統一。

#### 新規 skill / ツール追加時のチェック
- SKILL.md 内に個人ユーザー名・実メール・具体的な `C:\Users\<本名系>\...` パスを書かない
- skill が他のskillに依存する際の参照は `~/.claude/skills/<skill>`（Unix風）で統一
- ゲストVMのパスは `<GUEST_TOOLS>` / `<GUEST_ANALYSIS_DIR>` プレースホルダで書く
