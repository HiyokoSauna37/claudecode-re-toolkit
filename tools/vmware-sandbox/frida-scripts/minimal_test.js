// Minimal hooks to find which one crashes the process
'use strict';

function getExport(dll, func) {
    try { return Process.getModuleByName(dll).getExportByName(func); }
    catch (e) { return null; }
}

function safeAttach(dll, func, callbacks) {
    try {
        var addr = getExport(dll, func);
        if (addr) { Interceptor.attach(addr, callbacks); console.log('[OK] ' + dll + '!' + func); return true; }
        console.log('[MISS] ' + dll + '!' + func);
        return false;
    } catch (e) {
        console.log('[FAIL] ' + dll + '!' + func + ': ' + e);
        return false;
    }
}

// 1. Sleep (known to work)
var sleepCount = 0;
safeAttach('kernel32.dll', 'Sleep', {
    onEnter: function(args) {
        sleepCount++;
        args[0] = ptr(0);
        if (sleepCount <= 3 || sleepCount % 5000 === 0) {
            console.log('[Sleep] count=' + sleepCount + ' ms=' + args[0].toInt32());
        }
    }
});

// 2. VirtualProtect
safeAttach('kernel32.dll', 'VirtualProtect', {
    onEnter: function(args) {
        console.log('[VP] addr=' + args[0] + ' size=' + args[1].toInt32() + ' prot=0x' + args[2].toInt32().toString(16));
    }
});

// 3. VirtualAlloc
safeAttach('kernel32.dll', 'VirtualAlloc', {
    onLeave: function(retval) {
        if (!retval.isNull()) console.log('[VA] addr=' + retval);
    }
});

// 4. CreateThread
safeAttach('kernel32.dll', 'CreateThread', {
    onEnter: function(args) {
        console.log('[CT] start=' + args[2]);
    }
});

// 5. IsDebuggerPresent
safeAttach('kernel32.dll', 'IsDebuggerPresent', {
    onLeave: function(retval) { retval.replace(ptr(0)); console.log('[ADB] IsDebuggerPresent -> 0'); }
});

// NO Process32 replace, NO CreateFileW, NO RegQuery hooks
console.log('=== Minimal Test Loaded ===');
