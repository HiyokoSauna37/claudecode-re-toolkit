/**
 * hook_webview.js — WebView URL loading, JS bridge calls, and crypto interception
 * Usage: frida -U -l hook_webview.js -f <package> --no-pause
 */
Java.perform(function() {
    // --- WebView.loadUrl ---
    try {
        var WebView = Java.use("android.webkit.WebView");
        WebView.loadUrl.overload("java.lang.String").implementation = function(url) {
            console.log("[WebView.loadUrl] " + url);
            this.loadUrl(url);
        };
        WebView.loadUrl.overload("java.lang.String", "java.util.Map").implementation = function(url, h) {
            console.log("[WebView.loadUrl+headers] " + url);
            this.loadUrl(url, h);
        };
        WebView.evaluateJavascript.implementation = function(script, cb) {
            console.log("[WebView.evaluateJavascript] " + script.substring(0, 200));
            this.evaluateJavascript(script, cb);
        };
        WebView.addJavascriptInterface.implementation = function(obj, name) {
            console.log("[WebView.addJavascriptInterface] name=" + name + " class=" + obj.getClass().getName());
            var methods = obj.getClass().getMethods();
            for (var i = 0; i < methods.length; i++) {
                var m = methods[i];
                if (m.isAnnotationPresent(Java.use("android.webkit.JavascriptInterface").class)) {
                    console.log("  @JavascriptInterface " + m.getName());
                }
            }
            this.addJavascriptInterface(obj, name);
        };
        console.log("[*] WebView hooks installed");
    } catch(e) { console.log("[!] WebView: " + e); }

    // --- URL constructor ---
    try {
        Java.use("java.net.URL").$init.overload("java.lang.String").implementation = function(url) {
            if (url.indexOf("google") === -1 && url.indexOf("gstatic") === -1) {
                console.log("[new URL] " + url);
            }
            this.$init(url);
        };
    } catch(e) {}

    // --- HttpURLConnection ---
    try {
        Java.use("java.net.HttpURLConnection").getInputStream.implementation = function() {
            console.log("[HttpURLConnection] " + this.getURL().toString());
            return this.getInputStream();
        };
    } catch(e) {}

    // --- Cipher.doFinal (AES etc.) ---
    try {
        Java.use("javax.crypto.Cipher").doFinal.overload("[B").implementation = function(input) {
            var result = this.doFinal(input);
            var algo = this.getAlgorithm();
            console.log("[Cipher.doFinal] algo=" + algo + " in=" + input.length + " out=" + result.length);
            try {
                var s = Java.use("java.lang.String").$new(result, "UTF-8");
                if (s.length() > 0 && s.length() < 2000) {
                    console.log("  decrypted: " + s);
                }
            } catch(e2) {}
            return result;
        };
    } catch(e) {}

    // --- SharedPreferences (config storage) ---
    try {
        Java.use("android.app.SharedPreferencesImpl$EditorImpl").putString.implementation = function(k, v) {
            console.log("[SharedPrefs] " + k + " = " + v);
            return this.putString(k, v);
        };
    } catch(e) {}

    // --- Base64.decode ---
    try {
        Java.use("android.util.Base64").decode.overload("[B", "int").implementation = function(input, flags) {
            var result = this.decode(input, flags);
            try {
                var s = Java.use("java.lang.String").$new(result, "UTF-8");
                if (s.length() > 5 && s.length() < 2000) {
                    console.log("[Base64.decode] " + s);
                }
            } catch(e2) {}
            return result;
        };
    } catch(e) {}

    // --- VpnService.Builder ---
    try {
        var VB = Java.use("android.net.VpnService$Builder");
        VB.addAddress.overload("java.lang.String", "int").implementation = function(a, p) {
            console.log("[VPN.addAddress] " + a + "/" + p);
            return this.addAddress(a, p);
        };
        VB.addRoute.overload("java.lang.String", "int").implementation = function(a, p) {
            console.log("[VPN.addRoute] " + a + "/" + p);
            return this.addRoute(a, p);
        };
        VB.establish.implementation = function() {
            console.log("[VPN.establish] VPN tunnel created!");
            return this.establish();
        };
    } catch(e) {}

    // --- PackageInstaller (dropper detection) ---
    try {
        Java.use("android.content.pm.PackageInstaller").createSession.implementation = function(p) {
            console.log("[PackageInstaller.createSession] " + p);
            return this.createSession(p);
        };
    } catch(e) {}

    console.log("\n[***] All hooks installed. Monitoring...\n");
});
