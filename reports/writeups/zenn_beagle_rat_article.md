---
title: "「Claude AI」を検索しただけで感染する — 偽サイトが配布するフルRAT（woman.dll）を解析した"
emoji: "🐕"
type: "tech"
topics: ["security", "malware", "reverseengineering", "claude", "cybersecurity"]
published: false
---

## はじめに

2026年5月、Sophosが「Claude AIの偽サイトからバックドアが配布されている」と報告した。"Beagle"と名付けられたそのバックドアは8コマンドのみの簡素なものだった。

本記事では、同じキャンペーンに属すると思われる**未報告の上位バリアント**を独自に解析した結果を報告する。最終ペイロードはBeagleよりはるかに高機能な**Delphi製フルRAT**で、DNS over HTTPSによるC2回避、1,454のYARAルールを全回避するHTML Padding、8台のC2サーバーによるフェイルオーバー構成を備えていた。

:::message alert
本記事はマルウェア解析の技術的知見共有を目的としています。記載されたURL/IPへのアクセスやツールの悪用は厳に慎んでください。
:::

---

## Google検索しただけで感染する

### いま何が起きているか

あなたが「Claude AI ダウンロード」や「Claude Code」とGoogleで検索したとき、**検索結果の最上位に表示される広告がマルウェアの入り口**になっている可能性がある。

```
┌─────────────────────────────────────────┐
│  [スポンサー] Claude Pro - AI Assistant  │ ← 攻撃者の広告
│  claude-pro.com                          │
├─────────────────────────────────────────┤
│  Claude \ Anthropic                      │ ← 本物（2番目）
│  claude.ai                               │
└─────────────────────────────────────────┘
```

Pillar Securityの調査によれば、2026年の最初10週間だけで**2025年全体を超える数のAIツール偽装キャンペーン**が発生している。標的はClaude、ChatGPT、Cursor、DeepSeek、Geminiと広範だ。

### 偽サイトの完成度

攻撃者が用意した `claude-pro[.]com` は本物の `claude.ai` のUIを完全にクローンしている。一見して区別はつかない。ただし一つだけ違いがある——**ダウンロードボタン以外のリンクがすべてトップページにリダイレクトする**。

サイトは "Claude-Pro Relay" なる**架空のデスクトップアプリ**を提供し、505MBのZIPアーカイブをダウンロードさせる。CDNにCloudflareを使っているため、URLフィルタリングでのブロックも困難だ。

---

## 感染までの7ステップ

被害者の視点でのフローを再現する。

| Step | 被害者の行動 | 裏側で起きていること |
|:---:|---|---|
| 1 | "Claude AI" をGoogle検索 | — |
| 2 | 最上位の広告をクリック | claude-pro.com へ遷移 |
| 3 | "Download for Windows" を押す | `Claude-Pro-windows-x64.zip` (505MB) ダウンロード開始 |
| 4 | ZIPを展開 | MSIインストーラーが出現 |
| 5 | MSIをダブルクリック | サイレントインストール開始 |
| 6 | 「あれ、何も起動しない...」 | **DLLサイドローディング発動** |
| 7 | PCを使い続ける | RAT が全通信を暗号化し、C2と接続完了 |

被害者が異常に気づくタイミングは**ない**。MSIインストーラーは署名付きバイナリを使うためSmartScreenも反応せず、プロセス名は"AdaptiveSc.exe"と無害に見え、通信はHTTPS（ポート443）なのでファイアウォールも通過する。

---

## 検体を手に入れた

筆者はマルウェア共有プラットフォーム（Triage）で同キャンペーンに属する検体を入手し、自前の解析環境で分析した。

```
ファイル: 260511-xbdenagx4x_pw_infected.zip (pw: infected)
  └── QDSIWSJF.msi
       ├── EngineSil64.exe  — 正規署名バイナリ（ローダー）
       ├── ucrtbase.dll     — トロイの木馬化DLL
       ├── msvcp_win.dll    — トロイの木馬化DLL
       ├── loader_sync.db   — 暗号化ペイロード (9.9MB)
       ├── buffer_opt.idx   — 設定ファイル
       └── その他正規DLL ×3
```

MSIの製品名は "Mum"、製造元は "Benzidine Champignon"（明らかに自動生成されたゴミ値）。Sophosが報告したclaude-pro.comルートとは**別の配布経路**から来たものだが、手法は完全に一致する。

---

## 解析: Stage 1 — DLLサイドローディング

### 正規バイナリの悪用

`EngineSil64.exe` は National Instruments（産業制御系ソフトウェア）のJenkins CIでビルドされた**正規の署名付きバイナリ**だ。PDBパスにその痕跡がある：

```
C:\jenkins\workspace\BUILD\GitRepos\dca-infra\build_windows_mainline\task\task.pdb
```

このEXEは起動時にCRTライブラリとして `ucrtbase.dll` を読み込む。攻撃者はこのDLLを**FNV-1aハッシュベースの動的API解決コードを仕込んだ偽物**にすり替えている。

### YARA検出

```
ucrtbase.dll  → MalDev_API_Hash_FNV1a  ✓
msvcp_win.dll → MalDev_API_Hash_FNV1a  ✓
```

正規バイナリが偽DLLを読み込み、偽DLLが暗号化ペイロードを復号する——これがDLLサイドローディングの典型パターンだ。

---

## 解析: Stage 2 — プロセスホロウイング

動的解析（VMware + Host-Only隔離環境）でMSIをインストールすると、以下の動作を確認した：

1. `EngineSil64.exe` が `C:\ProgramData\indexcli_stable\` に自身をコピー（永続化）
2. `loader_sync.db` (9.9MB) をHMAC-SHA256鍵導出で復号
3. `%LOCALAPPDATA%\AdaptiveSc.exe` を生成
4. AdaptiveSc.exe に対し**プロセスホロウイング**実行
5. 復号済みの8.9MB DLLを**反射的注入** (RWX, MEM_PRIVATE)

HollowsHunterの検出結果：

```json
{
  "pid": 5720,
  "main_image_path": "C:\\Users\\<user>\\AppData\\Local\\AdaptiveSc.exe",
  "modified": {
    "implanted_pe": 1,   // ← 8.9MB DLLが注入されている
    "other": 2
  }
}
```

---

## 解析: Stage 3 — 最終ペイロード `woman.dll`

HollowsHunterがダンプした8.9MBのDLLが最終ペイロードだ。

### 基本情報

| 項目 | 値 |
|------|-----|
| ファイル名 | `woman.dll` |
| SHA256 | `05e68390d992c77dc59661e6e95628d72145c37b3f5011558284e986cc2c5506` |
| サイズ | 8,941,568 bytes |
| コンパイラ | **Delphi / FreePascal (FMX FireMonkey)** |
| HTTPライブラリ | ICS THttpCli V9.4 |
| インポートAPI | 537個（うち52個が不審） |
| YARA検出 | **0 / 1,454ルール** |

### なぜYARAが全く効かないか

`.text` セクション（7.6MB）の大部分がWebページのHTMLテキストで埋められている：

```
...the United Kingdomfederal government<div style="margin 
depending on the description of the<div class="header
.min.js"></script>destruction of theslightly different...
```

これは**HTML Content Padding**と呼ばれる回避技術で、シグネチャベースの検出を完全に無効化する。1,454のYARAルール（YARA-Rules + Signature-Base + カスタムルール含む）が**1件もマッチしなかった**。

### Delphi RTTIから読み解くRAT構造

Delphiバイナリの特徴として、クラス名がRTTI（実行時型情報）としてバイナリに残る。これを利用して内部構造を特定した：

```
FMX.Controls.OleJxCA.CommandRecord    — C2コマンド構造体
FMX.Controls.OleJxCA.TBotDataRecord   — ボット管理データ
FMX.Controls.OleJxCA.M_OnlineRec      — オンライン接続管理
Apiariqtypuhe.SaveToZip               — データ窃取（ZIP化）
```

### 主要な能力（インポートAPIベース）

| 機能 | 使用API |
|------|---------|
| 暗号化通信 | CryptAcquireContext / DeriveKey / Encrypt / Decrypt |
| プロセス注入 | VirtualAllocEx + WriteProcessMemory |
| 権限昇格 | AdjustTokenPrivileges + OpenProcessToken |
| サービス永続化 | CreateServiceW + StartServiceW |
| レジストリ永続化 | RegSetValueExW |
| シェル実行 | CreateProcessAsUserW + ShellExecuteExW |
| 対デバッグ | IsDebuggerPresent |

Sophosが報告したBeagle（8コマンドのみ）とは比較にならない、**フル機能のRAT**だ。

---

## 解析: Stage 4 — C2通信の特定

### DNS over HTTPS (DoH) による回避

VMをNATモードに切り替え、ライブ通信をキャプチャした。ここで判明したのが、このRATの最も巧妙な点だ。

**C2ドメインの名前解決にDNS over HTTPSを使用している。**

```
https://cloudflare-dns.com/dns-query
https://dns.google/dns-query
https://dns.quad9.net/dns-query
https://dns.opendns.com/dns-query
https://doh.appliedprivacy.net/query
```

これにより：
- システムDNSキャッシュに痕跡が残らない
- FakeNet-NGのDNSリスナーを回避
- ネットワーク監視でDNSクエリが見えない（全てHTTPS通信に見える）

FakeNetでログが取れなかった原因もこれだ。DNSクエリ自体がHTTPS通信として暗号化されているため、従来のフォレンジック手法では観測できない。

### C2サーバー（8台フェイルオーバー）

NAT接続でAdaptiveSc.exe (PID 2076) のnetstat出力をキャプチャ：

```
ESTABLISHED  217.9.12.52:443      ← Primary C2
ESTABLISHED  193.202.84.78:443    ← Secondary
ESTABLISHED  176.65.132.184:443   ← Active
SYN_SENT ×18 144.31.167.11:443   ← Backup (最多試行)
SYN_SENT ×11 193.202.84.72:443   ← Backup
SYN_SENT ×10 121.127.37.125:443  ← Backup
SYN_SENT ×4  45.155.69.198:443   ← Backup
SYN_SENT ×2  79.132.131.86:443   ← Backup
```

8台のC2サーバーを同時並行で接続試行する冗長構成。1台が落ちても他で通信を継続できる。

---

## Sophos報告との比較：進化の証拠

| | Beagle (Sophos) | 本検体 |
|---|---|---|
| 暗号 | XOR (単純) | HMAC-SHA256鍵導出 |
| 回避 | なし | HTMLパディング + DoH + FNV-1a |
| C2 | 1ドメイン | 8 IP + DoH |
| 機能 | 8コマンド | フルRAT (サービス/権限昇格/注入/暗号化) |
| ペイロード | 小型backdoor | 8.9MB Delphi DLL |

同じ配布インフラ（MSI + DLLサイドローディング + 暗号化データファイル）を使いながら、最終ペイロードだけが大幅に強化されている。これは同一オペレーターによる**段階的な進化**を示唆する。

タイムラインで見ると：

```
2026/02  Beagle v1 (XOR + DonutLoader + 簡易backdoor)
2026/03  AdaptixC2 variant (同一XOR key)
2026/04  ★本検体★ (HMAC-SHA256 + Delphi フルRAT)  ← NEW
2026/05  Sophos公開
```

---

## 脅威アクターは誰か

### AdaptixC2とロシアの接続

Sophosの報告では、2026年3月のサンプルに**AdaptixC2**（オープンソースのC2フレームワーク）のシェルコードが含まれていた。

AdaptixC2の開発者 "RalfHacker" はロシアのペネトレーションテスター/マルウェア開発者で、ロシア語のTelegramチャンネルを運営している。このフレームワークはAkiraランサムウェア（250+組織に侵害、$42M身代金）のアフィリエイトが使用していることがUnit42により確認されている。

つまりこのキャンペーンの背後には、**ロシア語圏のサイバー犯罪グループ**がいると推定される。彼らは：
- 複数のブランド（Claude, CrowdStrike, SentinelOne, Trellix）を偽装
- インフラをローテーション（Cloudflare CDN + Alibaba Cloud C2）
- ペイロードを進化させながら配布を継続

---

## 自分の身を守るには

### 即効性のある対策

1. **URLを確認する**: Claudeの公式は `claude.ai` のみ。`claude-pro.com` や `claude-code.com` は偽物
2. **広告をクリックしない**: AIツールは必ず公式サイトに直接アクセス
3. **505MBのAIツールは存在しない**: Claude CodeはCLIツール（npm/pip経由）。巨大なZIPは異常
4. **uBlock Originを入れる**: マルバタイジングの大半をブロック

### 組織向け

```yaml
# Suricata / Snort ルール
alert tls any any -> any 443 (tls.sni; content:"cloudflare-dns.com"; sid:1000001;)
# → DoH通信の異常検知（通常のWebブラウジングではDoHは使わない）

# EDR監視
- EngineSil64.exe が AdaptiveSc.exe を生成
- ProgramData\indexcli_stable\ の出現
- 8MB超のRWXメモリ領域を持つプロセス
```

### YARA検出ルール

既存のYARAルール群はHTMLパディングで完全に回避されるため、**RTTIベースの検出**が有効：

```yara
rule Beagle_Campaign_Delphi_RAT {
    meta:
        description = "Beagle Campaign - Delphi/FMX RAT (woman.dll variant)"
        date = "2026-05-17"
    strings:
        $ns = "FMX.Controls.OleJxCA" ascii
        $bot = "TBotDataRecord" ascii
        $cmd = "CommandRecord" ascii
        $zip = "SaveToZip" ascii
        $export = "woman.dll" ascii
    condition:
        uint16(0) == 0x5A4D and filesize > 5MB and 3 of them
}
```

---

## まとめ

「Claude AIをダウンロードしよう」——そんな何気ない行動が、フルRAT感染の入り口になっている。

今回解析した検体は、Sophosが報告した「Beagle」の上位バリアントであり、8コマンドのみの簡易バックドアから**サービス登録・権限昇格・プロセス注入・DoH回避を備えたフル機能RAT**へと進化していた。1,454のYARAルールを全回避するHTMLパディング、8台のC2フェイルオーバー、DNS over HTTPSによるフォレンジック回避——いずれも「検出されないこと」に対する執念を感じさせる。

2026年はAIツールの爆発的普及と、それを悪用するマルウェアキャンペーンの爆発的増加が同時に起きている。「公式サイト以外からAIツールをダウンロードしない」——これだけで今回の脅威の大半は防げる。

---

## 参考資料

- [Donuts and Beagles: Fake Claude site spreads backdoor (Sophos X-Ops)](https://www.sophos.com/en-us/blog/donuts-and-beagles-fake-claude-site-spreads-backdoor)
- [Fake Claude AI website delivers new 'Beagle' Windows malware (BleepingComputer)](https://www.bleepingcomputer.com/news/security/fake-claude-ai-website-delivers-new-beagle-windows-malware/)
- [Windows and macOS Malware Spreads via Fake "Claude Code" Google Ads (Bitdefender)](https://www.bitdefender.com/en-us/blog/labs/fake-claude-code-google-ads-malware)
- [AI Coding Tools Under Fire: Mapping the Malvertising Campaigns (Pillar Security)](https://www.pillar.security/blog/ai-coding-tools-under-fire-mapping-the-malvertising-campaigns-targeting-the-vibe-coding-ecosystem)
- [AdaptixC2: A New Open-Source Framework Leveraged in Real-World Attacks (Unit42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [GHOSTPULSE haunts victims using defense evasion bag o' tricks (Elastic)](https://www.elastic.co/security-labs/ghostpulse-haunts-victims-using-defense-evasion-bag-o-tricks)

---

## IOC (Indicators of Compromise)

:::details ハッシュ・IP一覧（クリックで展開）

**SHA256**
```
729563f7b39c66b8b4d26734b208b880c089853f7a0cb878aaaf9f6bbb51baa9  QDSIWSJF.msi
cbb423fb06e3a2963de30237ca387f82fbe85b1a989a3bc3a64ac325ca0809f0  EngineSil64.exe
d93ce42cd625510b2355de086bcd19e2c11307ccade7bad62b09c7f340a866ba  ucrtbase.dll (malicious)
08f2fe38501a88a7d3c13976733c2ca08b5597c3328d51fa1f5f5d8474c33ecf  msvcp_win.dll (malicious)
05e68390d992c77dc59661e6e95628d72145c37b3f5011558284e986cc2c5506  woman.dll (final RAT)
e3aabd546bdf63153ff4dddfc693515f77ed97d3c07c5eab4b99d1d3d4aee86d  loader_sync.db
```

**C2 Servers (port 443)**
```
217.9.12.52
193.202.84.78
193.202.84.72
176.65.132.184
121.127.37.125
144.31.167.11
45.155.69.198
79.132.131.86
```

**Filesystem**
```
%LOCALAPPDATA%\Quadraphony\
C:\ProgramData\indexcli_stable\
%LOCALAPPDATA%\AdaptiveSc.exe
```
:::
