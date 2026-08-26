# Vidar Stealer ナレッジ

## Vidar Stealer C2プロトコル仕様

### 通信チェーン全体像
```
1. DNS解決 → Steam/Telegram等のDDRサービス
2. DDR (Dead Drop Resolver) → actual_persona_name から bare domain 抽出
3. DNS解決 → C2ドメイン
4. POST /api/config → セミコロン区切り設定レスポンス取得
5. POST /api/client → "ok" レスポンスで登録確認
6. 情報窃取 (ブラウザ、暗号資産ウォレット、ファイル等)
7. POST /api/ (exfiltration) → zipファイルでデータ送信
```

### Steam DDRフロー
- Vidarはサンプルごとにハードコードされた Steam Profile ID を持つ（例: `/id/XXXXXXXX`）
- Profile IDは Ghidra の strings / xrefs で特定可能
- Steamプロフィールページの `<span class="actual_persona_name">` タグからbare domainを抽出
- `</span>` を終了マーカーとして使用
- FakeNetで応答する場合: `input/templates/fake_steam_profile_template.html` を編集し、
  `REPLACE_DOMAIN` を偽C2ドメイン（FakeNetが解決するもの）に置換

### /api/config レスポンス仕様
- **Content-Type**: text/plain（JSONではない）
- **形式**: カンマ区切りフラグ + セミコロン区切りフィールド
- **フィールドマッピング**:
  ```
  flags(csv),botID,more_flags,timeout,
  ProfileName;SearchPath;FilePatterns;MaxSizeMB;Recursive;ExcludeExtensions;
  ```
- 例: `1,1,1,1,1,BOTID,1,1,1,1,250,Default;%DOCUMENTS%\;*.txt:*.dat;50;true;exe;`
- build_http_response.py の `--template vidar-config` で生成可能

### /api/client レスポンス仕様
- **Content-Type**: text/plain
- **ボディ**: `ok` （2文字のプレーンテキスト）
- このレスポンスがないとVidarは処理を中断する

### User-Agent
- `SystemInfo Client/1.0`（Vidar固有のUA）

### FakeNet Custom Response設定例
```ini
[VidarC2Config]
InstanceName:     HTTPListener443
HttpURIs:         /api/config
HttpRawFile:      vidar_config_response.txt

[VidarC2Client]
InstanceName:     HTTPListener443
HttpURIs:         /api/client
HttpStaticString: ok
```
