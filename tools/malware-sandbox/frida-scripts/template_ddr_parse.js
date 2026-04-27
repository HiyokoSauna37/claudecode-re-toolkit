// Template: Dead Drop Resolver (DDR) Parse Hook
// ================================================
// マルウェアが外部サービス (Steam, Telegram, Pastebin等) から
// C2ドメインを取得する際の string::find / substr を監視するテンプレート。
//
// 使い方:
//   1. TARGET_EXE をマルウェアのプロセス名に変更
//   2. Ghidra で string::find, substr の RVA を特定し、HOOK_OFFSETS を更新
//   3. frida -f target.exe -l template_ddr_parse.js --no-pause
//
// 対応エラー: DDRマーカー不明でパース失敗
// 参考: Vidar は actual_persona_name / </span> をマーカーとして使用

'use strict';

// ==== 設定 ====
var TARGET_EXE = "REPLACE_ME.exe";    // マルウェアプロセス名

// Ghidra で特定した関数オフセット (RVA)
// 例: Vidar babi.exe の場合
var HOOK_OFFSETS = {
    string_find:  0x17954,   // std::string::find(needle, pos)
    string_find2: 0x178e4,   // 終了マーカー検索 (別関数の場合)
    substr:       0x17560,   // std::string::substr(start, len)
    http_request: 0x3e7e0,   // 内部HTTP関数 (任意)
    string_set:   0x8a58     // string代入 (デバッグ用、任意)
};

// ==== MSVC std::string reader ====
function readStdString(ptr) {
    try {
        var mySize = ptr.add(0x10).readU64();
        var myRes  = ptr.add(0x18).readU64();
        var ns = Number(mySize);
        var nc = Number(myRes);
        if (ns > 0 && ns < 0x10000) {
            var str = (nc > 15)
                ? ptr.readPointer().readUtf8String(ns)
                : ptr.readUtf8String(ns);
            return { ok: true, str: str, size: ns };
        }
    } catch(e) {}
    return { ok: false, str: null, size: 0 };
}

function readAny(ptr) {
    // C string
    try {
        var s = ptr.readUtf8String(200);
        if (s && s.length > 0 && s.length < 200) return "[cstr] " + s;
    } catch(e) {}
    // std::string
    var r = readStdString(ptr);
    if (r.ok) return "[std:" + r.size + "] " + r.str;
    // hex dump
    try {
        var raw = new Uint8Array(ptr.readByteArray(32));
        var hex = "";
        for (var i = 0; i < raw.length; i++) hex += ("0" + raw[i].toString(16)).slice(-2) + " ";
        return "[hex] " + hex;
    } catch(e2) {
        return "[err] " + ptr;
    }
}

// ==== フック設置 ====
var mod = Process.getModuleByName(TARGET_EXE);
var base = mod.base;
console.log("[*] " + TARGET_EXE + " base: " + base);

// string::find (開始マーカー検索)
if (HOOK_OFFSETS.string_find) {
    Interceptor.attach(base.add(HOOK_OFFSETS.string_find), {
        onEnter: function(args) {
            console.log("[FIND] needle=" + readAny(args[1]) + " pos=" + args[2]);
        },
        onLeave: function(retval) {
            var r = retval.toInt32();
            console.log("[FIND] => " + (r !== -1 ? "offset " + r : "NOT FOUND"));
        }
    });
    console.log("[*] Hooked string_find");
}

// string::find2 (終了マーカー検索)
if (HOOK_OFFSETS.string_find2) {
    Interceptor.attach(base.add(HOOK_OFFSETS.string_find2), {
        onEnter: function(args) {
            console.log("[END] needle=" + readAny(args[1]) + " pos=" + args[2]);
        },
        onLeave: function(retval) {
            var r = retval.toInt32();
            console.log("[END] => " + (r !== -1 ? "offset " + r : "NOT FOUND"));
        }
    });
    console.log("[*] Hooked string_find2 (end marker)");
}

// substr (ドメイン抽出)
if (HOOK_OFFSETS.substr) {
    Interceptor.attach(base.add(HOOK_OFFSETS.substr), {
        onEnter: function(args) {
            console.log("[SUBSTR] src=" + readAny(args[1]) + " start=" + args[2] + " len=" + args[3]);
        }
    });
    console.log("[*] Hooked substr");
}

// HTTP internal (任意)
if (HOOK_OFFSETS.http_request) {
    Interceptor.attach(base.add(HOOK_OFFSETS.http_request), {
        onEnter: function(args) {
            console.log("[HTTP-INT] " + readAny(args[1]));
        }
    });
    console.log("[*] Hooked http_request");
}

// string_set (デバッグ用、大量出力注意)
if (HOOK_OFFSETS.string_set) {
    var setCount = 0;
    Interceptor.attach(base.add(HOOK_OFFSETS.string_set), {
        onEnter: function(args) {
            setCount++;
            if (setCount <= 300) {
                var s = readAny(args[1]);
                if (s.indexOf("[err]") === -1 && s.indexOf("[hex] 00 00") === -1) {
                    console.log("[SET #" + setCount + "] " + s);
                }
            }
        }
    });
    console.log("[*] Hooked string_set (limit 300)");
}

console.log("[*] DDR parse hooks ready. Waiting for activity...");
