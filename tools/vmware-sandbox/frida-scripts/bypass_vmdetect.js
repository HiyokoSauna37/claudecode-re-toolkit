/**
 * bypass_vmdetect.js - Sleep Neutralization + Anti-Debug + Lightweight VM Bypass
 *
 * Frida 17.7.3 compatible (uses Process.getModuleByName().getExportByName())
 *
 * IMPORTANT: Heavy hooks on RegOpenKeyExW/CreateFileW/NtQuerySystemInformation
 * cause process initialization deadlock. Only essential hooks are enabled.
 *
 * Usage:
 *   frida -f malware.exe -l bypass_vmdetect.js -q -t 60 --kill-on-exit
 */

'use strict';

function getExport(dll, func) {
    try { return Process.getModuleByName(dll).getExportByName(func); }
    catch (e) { return null; }
}

function safeAttach(dll, func, callbacks) {
    try {
        var addr = getExport(dll, func);
        if (addr) { Interceptor.attach(addr, callbacks); return true; }
        return false;
    } catch (e) {
        console.log('[WARN] ' + dll + '!' + func + ': ' + e.message);
        return false;
    }
}

// ========== Sleep Bombing Neutralization ==========

var sleepCount = 0;
safeAttach('kernel32.dll', 'Sleep', {
    onEnter: function (args) {
        var ms = args[0].toInt32();
        if (ms > 0) {
            sleepCount++;
            args[0] = ptr(0);
            if (sleepCount <= 3 || sleepCount % 10000 === 0) {
                console.log('[Sleep] ' + ms + 'ms -> 0ms (total: ' + sleepCount + ')');
            }
        }
    }
});

safeAttach('kernel32.dll', 'SleepEx', {
    onEnter: function (args) {
        if (args[0].toInt32() > 0) args[0] = ptr(0);
    }
});

// ========== Anti-Debug Bypass ==========

safeAttach('kernel32.dll', 'IsDebuggerPresent', {
    onLeave: function (retval) { retval.replace(ptr(0)); }
});

safeAttach('kernel32.dll', 'CheckRemoteDebuggerPresent', {
    onLeave: function (retval) { retval.replace(ptr(0)); }
});

safeAttach('ntdll.dll', 'NtQueryInformationProcess', {
    onEnter: function (args) {
        this.cls = args[1].toInt32();
        this.buf = args[2];
    },
    onLeave: function (retval) {
        if (this.cls === 7) { try { this.buf.writePointer(ptr(0)); } catch (e) {} }
        if (this.cls === 30) { retval.replace(ptr(0xC0000353)); }
        if (this.cls === 31) { try { this.buf.writeU32(1); } catch (e) {} }
    }
});

console.log('');
console.log('=== VM Bypass Loaded (Frida ' + Frida.version + ') ===');
console.log('  [+] Sleep neutralization');
console.log('  [+] Anti-debug bypass');
console.log('==========================================');
console.log('');
