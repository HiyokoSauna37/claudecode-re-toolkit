// Template: Delay-Load DLL Hook
// ================================
// delay-load される DLL (winhttp.dll, wininet.dll 等) の API を
// LoadLibrary 完了後に自動フックするテンプレート。
//
// 使い方:
//   1. TARGET_DLL, TARGET_EXPORTS を変更
//   2. installHooks() 内にフック本体を記述
//   3. frida -f target.exe -l template_delay_load_hook.js --no-pause
//
// 対応エラー: WinHTTPフック失敗 (delay-load DLL が未ロード時に
// Module.findExportByName() が null を返す問題)

'use strict';

// ==== 設定 ====
var TARGET_DLL = "winhttp.dll";           // フック対象DLL
var TARGET_EXPORTS = [                     // フック対象API
    "WinHttpConnect",
    "WinHttpOpenRequest",
    "WinHttpSendRequest",
    "WinHttpReadData",
    "WinHttpWriteData"
];

// ==== メイン ====
var hooked = false;

function installHooks() {
    if (hooked) return;

    var base = Module.findBaseAddress(TARGET_DLL);
    if (!base) return;

    hooked = true;
    console.log("[*] " + TARGET_DLL + " loaded at " + base + " - installing hooks");

    TARGET_EXPORTS.forEach(function(name) {
        var addr = Module.findExportByName(TARGET_DLL, name);
        if (!addr) {
            console.log("[!] Export not found: " + name);
            return;
        }

        Interceptor.attach(addr, {
            onEnter: function(args) {
                // --- ここにフックロジックを記述 ---
                console.log("[HOOK] " + name + " called");

                // 例: WinHttpConnect のホスト名取得
                // if (name === "WinHttpConnect") {
                //     console.log("  host=" + args[1].readUtf16String());
                //     console.log("  port=" + args[2].toInt32());
                // }
            },
            onLeave: function(retval) {
                // console.log("[HOOK] " + name + " => " + retval);
            }
        });
        console.log("[*] Hooked " + name);
    });
}

// 1. 既にロード済みならすぐフック
if (Module.findBaseAddress(TARGET_DLL)) {
    installHooks();
} else {
    // 2. LoadLibrary を監視して、ロード完了時にフック
    console.log("[*] " + TARGET_DLL + " not loaded yet. Monitoring LoadLibrary...");

    ["LoadLibraryW", "LoadLibraryExW", "LoadLibraryA"].forEach(function(fn) {
        var addr = Module.findExportByName("kernel32.dll", fn);
        if (addr) {
            Interceptor.attach(addr, {
                onLeave: function(retval) {
                    if (!hooked && Module.findBaseAddress(TARGET_DLL)) {
                        installHooks();
                    }
                }
            });
        }
    });
}

console.log("[*] delay_load_hook template ready");
