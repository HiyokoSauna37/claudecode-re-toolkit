# Chrome DevTools Protocol (CDP) WebView インスペクションガイド

## 概要

Android WebView はリモートデバッグをサポートしており、Chrome DevTools Protocol (CDP) 経由で
WebView 内のページを完全に制御できる。これにより以下が可能:

- 表示中の URL・タイトルの取得
- JavaScript の実行（DOM 読み取り、フォーム操作）
- JS ブリッジ（`addJavascriptInterface`）の検出
- ネットワークリクエストの監視（XHR/fetch のフック）
- Cookie の取得

## 接続手順

### 1. WebView デバッグソケットの特定

```bash
adb shell cat /proc/net/unix | grep webview_devtools
# → @webview_devtools_remote_<PID>
```

### 2. ポートフォワーディング

```bash
adb forward tcp:9224 localabstract:webview_devtools_remote_<PID>
```

### 3. ページ情報の取得

```bash
curl http://localhost:9224/json
```

レスポンス例:
```json
[{
  "title": "ログイン - 楽天",
  "url": "https://login.account.rakuten.com/sso/authorize?...",
  "webSocketDebuggerUrl": "ws://localhost:9224/devtools/page/XXXXXX"
}]
```

### 4. WebSocket 接続

Python `websocket-client` ライブラリを使用:

```python
import json, websocket

ws = websocket.create_connection("ws://localhost:9224/devtools/page/XXXXXX", timeout=10)

# JavaScript を実行
ws.send(json.dumps({
    "id": 1,
    "method": "Runtime.evaluate",
    "params": {"expression": "document.title + ' | ' + location.href"}
}))
result = json.loads(ws.recv())
print(result["result"]["result"]["value"])
```

## 主要コマンド

### JS ブリッジの検出

```javascript
// addJavascriptInterface で注入されたオブジェクトを列挙
(function() {
    var names = ['Android', 'android', 'JSBridge', 'native', 'app'];
    var found = [];
    for (var i = 0; i < names.length; i++) {
        if (typeof window[names[i]] !== 'undefined') {
            var methods = [];
            for (var m in window[names[i]]) { methods.push(m); }
            found.push(names[i] + ': [' + methods.join(', ') + ']');
        }
    }
    return found.join('\n') || 'No bridges found';
})()
```

### React フォームへの値設定

React の controlled input は通常の `input.value = x` では onChange が発火しない。
`HTMLInputElement.prototype.value` の setter を直接呼ぶ必要がある:

```javascript
var input = document.querySelector('input[name="username"]');
var setter = Object.getOwnPropertyDescriptor(
    window.HTMLInputElement.prototype, 'value'
).set;
setter.call(input, 'test@example.com');
input.dispatchEvent(new Event('input', { bubbles: true }));
input.dispatchEvent(new Event('change', { bubbles: true }));
```

### ネットワーク監視

```python
# Network.enable で XHR/fetch を監視
ws.send(json.dumps({"id": 2, "method": "Network.enable"}))

# 受信ループ
while True:
    msg = json.loads(ws.recv())
    if msg.get("method") == "Network.requestWillBeSent":
        req = msg["params"]["request"]
        print(f"{req['method']} {req['url']}")
        if req.get("postData"):
            print(f"  POST: {req['postData'][:200]}")
```

## 2026-09 解析事例: 楽天偽装 APK での発見

1. **表示URL**: `https://login.account.rakuten.com/sso/authorize?client_id=point_club_web&...`
   → 楽天の正規 SSO サーバー

2. **JSブリッジ**: `window.Android.getDeviceId()` → `"f9a750dfebf73447"`
   → `addJavascriptInterface` で注入されたデバイスID取得メソッド

3. **フォーム構造**: `input[name="username"]` + `input[name="password"]`
   → React ベースのフォーム（setter override が必要）

4. **ネットワーク**: 認証情報送信が `Network.requestWillBeSent` で捕捉された
