/**
 * dump_payload.js - Memory Dump on VirtualProtect/VirtualAlloc/CreateThread
 *
 * Frida 17.7.3 compatible
 *
 * Usage:
 *   frida -f malware.exe -l bypass_vmdetect.js -l dump_payload.js -q -t 60 --kill-on-exit
 */

'use strict';

var DUMP_DIR = 'C:\\Users\\malwa\\Desktop\\analysis\\dumps';
var MIN_DUMP_SIZE = 4096;
var dumpCount = 0;
var allocTracker = {};

function getExport(dll, func) {
    try { return Process.getModuleByName(dll).getExportByName(func); }
    catch (e) { return null; }
}

function safeAttach(dll, func, callbacks) {
    try {
        var addr = getExport(dll, func);
        if (addr) { Interceptor.attach(addr, callbacks); return true; }
        return false;
    } catch (e) { return false; }
}

// Create dump directory
try {
    var cdw = getExport('kernel32.dll', 'CreateDirectoryW');
    if (cdw) new NativeFunction(cdw, 'int', ['pointer', 'pointer'])(Memory.allocUtf16String(DUMP_DIR), ptr(0));
} catch (e) {}

function dumpMemory(addr, size, tag) {
    try {
        if (size < MIN_DUMP_SIZE) return null;
        if (size > 50 * 1024 * 1024) size = 50 * 1024 * 1024;

        dumpCount++;
        var pad = ('000' + dumpCount).slice(-3);
        var fn = DUMP_DIR + '\\dump_' + pad + '_' + tag + '_' +
                 addr.toString().replace('0x', '') + '_' + size + '.bin';

        var buf = addr.readByteArray(size);
        var f = new File(fn, 'wb');
        f.write(buf);
        f.close();

        // PE check
        var isPE = false;
        try { isPE = (addr.readU16() === 0x5A4D); } catch (e) {}
        console.log('[DUMP] ' + size + 'B -> ' + fn + (isPE ? ' [PE!]' : ''));
        return fn;
    } catch (e) {
        console.log('[DUMP FAIL] ' + addr + ': ' + e.message);
        return null;
    }
}

// ========== VirtualProtect ==========

safeAttach('kernel32.dll', 'VirtualProtect', {
    onEnter: function (args) {
        this.addr = args[0];
        this.size = args[1].toInt32();
        this.prot = args[2].toInt32();
    },
    onLeave: function (retval) {
        if (retval.toInt32() === 0) return;
        // PAGE_EXECUTE_READWRITE (0x40) or PAGE_EXECUTE_READ (0x20)
        if ((this.prot === 0x40 || this.prot === 0x20) && this.size >= MIN_DUMP_SIZE) {
            console.log('[VP] RWX addr=' + this.addr + ' size=' + this.size);
            dumpMemory(this.addr, this.size, 'vp');
        }
    }
});

// ========== VirtualAlloc ==========

safeAttach('kernel32.dll', 'VirtualAlloc', {
    onEnter: function (args) {
        this.sz = args[1].toInt32();
        this.prot = args[3].toInt32();
    },
    onLeave: function (retval) {
        if (retval.isNull()) return;
        if (this.prot === 0x40 || (this.prot === 0x04 && this.sz >= 100000)) {
            allocTracker[retval.toString()] = { addr: retval, size: this.sz, protect: this.prot };
            console.log('[VA] addr=' + retval + ' size=' + this.sz + ' prot=0x' + this.prot.toString(16));
        }
    }
});

// ========== CreateThread ==========

safeAttach('kernel32.dll', 'CreateThread', {
    onEnter: function (args) {
        var sa = args[2];
        var mod = Process.findModuleByAddress(sa);
        if (!mod) {
            console.log('[!!!] SHELLCODE THREAD: ' + sa);
            var found = null;
            for (var k in allocTracker) {
                var a = allocTracker[k];
                if (sa.compare(a.addr) >= 0 && sa.compare(a.addr.add(a.size)) < 0) { found = a; break; }
            }
            dumpMemory(found ? found.addr : sa, found ? found.size : 0x10000, 'shellcode');
        }
    }
});

// ========== New Module Detection ==========

var known = {};
Process.enumerateModules().forEach(function (m) { known[m.name.toLowerCase()] = true; });

var timer = setInterval(function () {
    try {
        Process.enumerateModules().forEach(function (m) {
            var k = m.name.toLowerCase();
            if (!known[k]) {
                known[k] = true;
                console.log('[MOD] ' + m.name + ' @ ' + m.base + ' sz=' + m.size);
                if (k.indexOf('temp') !== -1 || k.indexOf('appdata') !== -1) {
                    dumpMemory(m.base, m.size, 'mod');
                }
            }
        });
    } catch (e) {}
}, 3000);

setTimeout(function () { clearInterval(timer); }, 55000);

// Summary at 55s
setTimeout(function () {
    console.log('');
    console.log('=== Summary ===');
    console.log('Dumps: ' + dumpCount);
    console.log('Allocs tracked: ' + Object.keys(allocTracker).length);
    for (var k in allocTracker) {
        var a = allocTracker[k];
        console.log('  ' + a.addr + ' sz=' + a.size + ' prot=0x' + a.protect.toString(16));
    }
    console.log('===============');
}, 55000);

console.log('');
console.log('=== Payload Dump Loaded (Frida ' + Frida.version + ') ===');
console.log('  [+] VirtualProtect/Alloc monitoring');
console.log('  [+] CreateThread shellcode detection');
console.log('  [+] Module scan (55s)');
console.log('  Dump: ' + DUMP_DIR);
console.log('=============================================');
console.log('');
