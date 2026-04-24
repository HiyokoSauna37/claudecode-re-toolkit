// trace_sideload.js - DLL Sideloading + Shellcode tracer
// Tracks: LoadLibrary, VirtualAlloc/Protect, CoGetObjectContext, file reads, shellcode execution

'use strict';

// === DLL Load tracking ===
var loadLibW = Process.getModuleByName('kernel32.dll').getExportByName('LoadLibraryW');
Interceptor.attach(loadLibW, {
    onEnter: function(args) {
        this.path = args[0].readUtf16String();
        console.log('[LoadLibraryW] ' + this.path);
    },
    onLeave: function(retval) {
        console.log('[LoadLibraryW] -> 0x' + retval.toString(16));
    }
});

var loadLibA = Process.getModuleByName('kernel32.dll').getExportByName('LoadLibraryA');
Interceptor.attach(loadLibA, {
    onEnter: function(args) {
        this.path = args[0].readAnsiString();
        console.log('[LoadLibraryA] ' + this.path);
    },
    onLeave: function(retval) {
        console.log('[LoadLibraryA] -> 0x' + retval.toString(16));
    }
});

// === GetProcAddress tracking ===
var getProcAddr = Process.getModuleByName('kernel32.dll').getExportByName('GetProcAddress');
Interceptor.attach(getProcAddr, {
    onEnter: function(args) {
        var name;
        try { name = args[1].readAnsiString(); } catch(e) { name = 'ordinal#' + args[1].toInt32(); }
        this.funcName = name;
        console.log('[GetProcAddress] ' + name);
    },
    onLeave: function(retval) {
        if (this.funcName && this.funcName.indexOf('vk') === 0) {
            console.log('[GetProcAddress] ' + this.funcName + ' -> 0x' + retval.toString(16));
        }
    }
});

// === VirtualAlloc tracking + dump ===
var virtualAlloc = Process.getModuleByName('kernel32.dll').getExportByName('VirtualAlloc');
var allocCount = 0;
Interceptor.attach(virtualAlloc, {
    onEnter: function(args) {
        this.addr = args[0];
        this.size = args[1].toInt32();
        this.allocType = args[2].toInt32();
        this.protect = args[3].toInt32();
        console.log('[VirtualAlloc] size=0x' + this.size.toString(16) + ' protect=0x' + this.protect.toString(16));
    },
    onLeave: function(retval) {
        console.log('[VirtualAlloc] -> 0x' + retval.toString(16));
        // PAGE_EXECUTE_READWRITE = 0x40
        if (this.protect === 0x40 && this.size > 0x100) {
            console.log('[!] RWX allocation detected: addr=0x' + retval.toString(16) + ' size=0x' + this.size.toString(16));
            // Schedule dump after shellcode is copied
            var dumpAddr = retval;
            var dumpSize = this.size;
            var idx = allocCount++;
            setTimeout(function() {
                try {
                    var data = dumpAddr.readByteArray(dumpSize);
                    var fname = 'C:\\analysis\\dump_rwx_' + idx + '_0x' + dumpAddr.toString(16) + '.bin';
                    var f = new File(fname, 'wb');
                    f.write(data);
                    f.close();
                    console.log('[DUMP] Saved ' + dumpSize + ' bytes to ' + fname);
                } catch(e) {
                    console.log('[DUMP] Failed: ' + e);
                }
            }, 3000);
        }
    }
});

// === VirtualProtect tracking ===
var virtualProtect = Process.getModuleByName('kernel32.dll').getExportByName('VirtualProtect');
Interceptor.attach(virtualProtect, {
    onEnter: function(args) {
        this.addr = args[0];
        this.size = args[1].toInt32();
        this.newProtect = args[2].toInt32();
        console.log('[VirtualProtect] addr=0x' + this.addr.toString(16) + ' size=0x' + this.size.toString(16) + ' newProtect=0x' + this.newProtect.toString(16));
    }
});

// === COM tracking ===
try {
    var coInit = Process.getModuleByName('ole32.dll').getExportByName('CoInitializeEx');
    Interceptor.attach(coInit, {
        onEnter: function(args) {
            console.log('[CoInitializeEx] pvReserved=0x' + args[0].toString(16) + ' dwCoInit=' + args[1].toInt32());
        },
        onLeave: function(retval) {
            console.log('[CoInitializeEx] -> 0x' + retval.toString(16));
        }
    });
} catch(e) {
    // ole32.dll not loaded yet, hook when it loads
    var dllLoadCb = Process.getModuleByName('kernel32.dll').getExportByName('LoadLibraryW');
    // Will be tracked by LoadLibraryW hook above
}

try {
    var coGetObj = Process.getModuleByName('ole32.dll').getExportByName('CoGetObjectContext');
    Interceptor.attach(coGetObj, {
        onEnter: function(args) {
            console.log('[CoGetObjectContext] riid=0x' + args[0].toString(16) + ' ppv=0x' + args[1].toString(16));
        },
        onLeave: function(retval) {
            console.log('[CoGetObjectContext] -> 0x' + retval.toString(16));
        }
    });
} catch(e) {
    console.log('[*] ole32.dll not loaded yet, CoGetObjectContext hook deferred');
}

// === File I/O tracking (msvcrt fopen/fread) ===
try {
    var msvcrt = Process.getModuleByName('msvcrt.dll');
    var fopen_fn = msvcrt.getExportByName('fopen');
    Interceptor.attach(fopen_fn, {
        onEnter: function(args) {
            this.filename = args[0].readAnsiString();
            this.mode = args[1].readAnsiString();
            console.log('[fopen] "' + this.filename + '" mode="' + this.mode + '"');
        },
        onLeave: function(retval) {
            console.log('[fopen] -> 0x' + retval.toString(16));
        }
    });

    var fread_fn = msvcrt.getExportByName('fread');
    Interceptor.attach(fread_fn, {
        onEnter: function(args) {
            this.buf = args[0];
            this.size = args[1].toInt32();
            this.count = args[2].toInt32();
            console.log('[fread] size=' + this.size + ' count=' + this.count + ' (total=' + (this.size * this.count) + ')');
        },
        onLeave: function(retval) {
            console.log('[fread] -> read ' + retval.toInt32() + ' items');
        }
    });
} catch(e) {
    console.log('[*] msvcrt.dll hooks deferred');
}

// === Sleep bypass (anti-sleep-bombing) ===
var sleep_fn = Process.getModuleByName('kernel32.dll').getExportByName('Sleep');
Interceptor.attach(sleep_fn, {
    onEnter: function(args) {
        var ms = args[0].toInt32();
        if (ms > 1000 || ms === -1) {
            console.log('[Sleep] ' + (ms === -1 ? 'INFINITE' : ms + 'ms') + ' -> reduced to 10ms');
            args[0] = ptr(10);
        }
    }
});

// === Anti-debug bypass ===
var isDebugger = Process.getModuleByName('kernel32.dll').getExportByName('IsDebuggerPresent');
Interceptor.attach(isDebugger, {
    onLeave: function(retval) {
        retval.replace(ptr(0));
    }
});

// === CreateThread tracking (shellcode execution) ===
var createThread = Process.getModuleByName('kernel32.dll').getExportByName('CreateThread');
Interceptor.attach(createThread, {
    onEnter: function(args) {
        var startAddr = args[2];
        console.log('[CreateThread] startAddress=0x' + startAddr.toString(16));
        // Check if thread start is in RWX region (shellcode)
        try {
            var info = Process.getRangeByAddress(startAddr);
            console.log('[CreateThread] protection=' + info.protection + ' base=0x' + info.base.toString(16) + ' size=0x' + info.size.toString(16));
        } catch(e) {}
    }
});

// === Module load monitoring ===
Process.setExceptionHandler(function(details) {
    return false;
});

// Monitor new modules
var knownModules = {};
Process.enumerateModules().forEach(function(m) { knownModules[m.name.toLowerCase()] = true; });

setInterval(function() {
    Process.enumerateModules().forEach(function(m) {
        var name = m.name.toLowerCase();
        if (!knownModules[name]) {
            knownModules[name] = true;
            console.log('[NEW MODULE] ' + m.name + ' base=0x' + m.base.toString(16) + ' size=0x' + m.size.toString(16));

            // If vulkan-1.dll loaded, hook its exports
            if (name === 'vulkan-1.dll') {
                console.log('[!] vulkan-1.dll loaded! Hooking...');
                try {
                    var vkExport = m.getExportByName('vkEnumerateInstanceVersion');
                    console.log('[!] vkEnumerateInstanceVersion at 0x' + vkExport.toString(16));
                } catch(e) {}
            }

            // Hook ole32.dll when loaded
            if (name === 'ole32.dll') {
                try {
                    Interceptor.attach(m.getExportByName('CoInitializeEx'), {
                        onEnter: function(args) {
                            console.log('[CoInitializeEx] pvReserved=0x' + args[0].toString(16) + ' dwCoInit=' + args[1].toInt32());
                        },
                        onLeave: function(retval) {
                            console.log('[CoInitializeEx] -> 0x' + retval.toString(16));
                        }
                    });
                    Interceptor.attach(m.getExportByName('CoGetObjectContext'), {
                        onEnter: function(args) {
                            console.log('[CoGetObjectContext] riid=0x' + args[0].toString(16) + ' ppv=0x' + args[1].toString(16));
                        },
                        onLeave: function(retval) {
                            console.log('[CoGetObjectContext] -> 0x' + retval.toString(16));
                        }
                    });
                    console.log('[*] ole32.dll COM hooks installed');
                } catch(e) {
                    console.log('[*] ole32.dll hook error: ' + e);
                }
            }
        }
    });
}, 1000);

console.log('[*] trace_sideload.js loaded - monitoring DLL sideloading + shellcode');
