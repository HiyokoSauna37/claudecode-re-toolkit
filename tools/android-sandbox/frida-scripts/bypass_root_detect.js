/**
 * bypass_root_detect.js — Bypass emulator/root/sandbox detection
 * Usage: frida -U -l bypass_root_detect.js -f <package> --no-pause
 */
Java.perform(function() {
    // --- Build properties (emulator fingerprints) ---
    try {
        var Build = Java.use("android.os.Build");
        Build.FINGERPRINT.value = "google/walleye/walleye:8.1.0/OPM1.171019.011/4448085:user/release-keys";
        Build.MODEL.value = "Pixel 2";
        Build.MANUFACTURER.value = "Google";
        Build.BRAND.value = "google";
        Build.DEVICE.value = "walleye";
        Build.PRODUCT.value = "walleye";
        Build.HARDWARE.value = "walleye";
        Build.BOARD.value = "walleye";
        console.log("[*] Build properties spoofed");
    } catch(e) {}

    // --- File existence checks (common sandbox detection) ---
    try {
        var File = Java.use("java.io.File");
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            var blocked = [
                "/system/bin/su", "/system/xbin/su", "/sbin/su",
                "/dev/goldfish", "/dev/qemu_pipe",
                "/system/lib/libc_malloc_debug_qemu.so",
                "/sys/qemu_trace", "/system/bin/qemu-props",
                "/dev/socket/qemud", "/dev/qemu_pipe",
                "/proc/tty/drivers"
            ];
            for (var i = 0; i < blocked.length; i++) {
                if (path.indexOf(blocked[i]) !== -1) {
                    console.log("[File.exists] blocked: " + path);
                    return false;
                }
            }
            return this.exists();
        };
        console.log("[*] File.exists sandboxed");
    } catch(e) {}

    // --- System properties ---
    try {
        var SystemProperties = Java.use("android.os.SystemProperties");
        SystemProperties.get.overload("java.lang.String").implementation = function(key) {
            var val = this.get(key);
            if (key.indexOf("qemu") !== -1 || key.indexOf("goldfish") !== -1 ||
                key.indexOf("nox") !== -1 || key.indexOf("vbox") !== -1) {
                console.log("[SystemProperties] spoofed: " + key + " (was: " + val + ")");
                return "";
            }
            return val;
        };
    } catch(e) {}

    // --- TelephonyManager (SIM/IMEI checks) ---
    try {
        var TelMgr = Java.use("android.telephony.TelephonyManager");
        TelMgr.getSimOperatorName.implementation = function() {
            return "NTT DOCOMO";
        };
        TelMgr.getNetworkOperatorName.implementation = function() {
            return "NTT DOCOMO";
        };
        TelMgr.getDeviceId.overload().implementation = function() {
            return "352" + Math.floor(Math.random() * 1e12);
        };
        console.log("[*] TelephonyManager spoofed");
    } catch(e) {}

    // --- GPS/Location mock ---
    try {
        var LocationManager = Java.use("android.location.LocationManager");
        LocationManager.isProviderEnabled.implementation = function(provider) {
            return true;
        };
        console.log("[*] LocationManager spoofed");
    } catch(e) {}

    // --- Package manager (detect security apps check) ---
    try {
        var PM = Java.use("android.app.ApplicationPackageManager");
        PM.getInstalledPackages.implementation = function(flags) {
            var result = this.getInstalledPackages(flags);
            // Filter out emulator/frida packages
            var iter = result.iterator();
            while (iter.hasNext()) {
                var pkg = iter.next();
                var name = pkg.packageName.value;
                if (name.indexOf("frida") !== -1 || name.indexOf("xposed") !== -1 ||
                    name.indexOf("substrate") !== -1 || name.indexOf("magisk") !== -1) {
                    iter.remove();
                    console.log("[PM] removed: " + name);
                }
            }
            return result;
        };
    } catch(e) {}

    console.log("\n[***] Root/emulator detection bypass active\n");
});
