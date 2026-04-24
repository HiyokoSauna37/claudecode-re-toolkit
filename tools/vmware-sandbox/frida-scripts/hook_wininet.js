// hook_wininet.js - Hook WinINet APIs to capture C2 URLs and dump decrypted payload
'use strict';

// === Sleep bypass ===
var sleep_fn = Process.getModuleByName('kernel32.dll').getExportByName('Sleep');
Interceptor.attach(sleep_fn, {
    onEnter: function(args) {
        var ms = args[0].toInt32();
        if (ms > 1000 || ms === -1) {
            args[0] = ptr(10);
        }
    }
});

// === Anti-debug bypass ===
Interceptor.attach(Process.getModuleByName('kernel32.dll').getExportByName('IsDebuggerPresent'), {
    onLeave: function(retval) { retval.replace(ptr(0)); }
});

// === VirtualAlloc tracking + improved dump ===
var virtualAlloc = Process.getModuleByName('kernel32.dll').getExportByName('VirtualAlloc');
var rwxRegions = [];
Interceptor.attach(virtualAlloc, {
    onEnter: function(args) {
        this.size = args[1].toInt32();
        this.protect = args[3].toInt32();
    },
    onLeave: function(retval) {
        if (this.protect === 0x40 && this.size > 0x100) {
            console.log('[!] RWX alloc: addr=0x' + retval.toString(16) + ' size=0x' + this.size.toString(16));
            rwxRegions.push({ addr: retval, size: this.size });
        }
    }
});

// === VirtualProtect tracking ===
Interceptor.attach(Process.getModuleByName('kernel32.dll').getExportByName('VirtualProtect'), {
    onEnter: function(args) {
        var addr = args[0];
        var size = args[1].toInt32();
        var prot = args[2].toInt32();
        if (size > 0x10000) {
            console.log('[VirtualProtect] addr=0x' + addr.toString(16) + ' size=0x' + size.toString(16) + ' prot=0x' + prot.toString(16));
        }
    }
});

// === Dump decrypted payload from RWX and RW regions ===
function dumpRegion(tag, addr, size) {
    try {
        var fname = 'C:\\analysis\\dump_' + tag + '_0x' + addr.toString(16) + '.bin';
        var file = new File(fname, 'wb');
        file.write(Memory.readByteArray(addr, size));
        file.close();
        console.log('[DUMP] ' + tag + ': ' + size + ' bytes -> ' + fname);
    } catch(e) {
        console.log('[DUMP FAIL] ' + tag + ': ' + e);
    }
}

// === Monitor module loads for WinINet ===
var wininetHooked = false;
function hookWinINet() {
    if (wininetHooked) return;
    try {
        var wininet = Process.getModuleByName('wininet.dll');
        wininetHooked = true;
        console.log('[*] WinINet loaded, installing hooks...');

        // InternetOpenW
        Interceptor.attach(wininet.getExportByName('InternetOpenW'), {
            onEnter: function(args) {
                var agent = args[0].isNull() ? 'NULL' : args[0].readUtf16String();
                var accessType = args[1].toInt32();
                var proxy = args[2].isNull() ? 'NULL' : args[2].readUtf16String();
                console.log('[InternetOpenW] UserAgent="' + agent + '" accessType=' + accessType + ' proxy="' + proxy + '"');
            },
            onLeave: function(retval) {
                console.log('[InternetOpenW] -> handle=0x' + retval.toString(16));
            }
        });

        // InternetOpenUrlW
        Interceptor.attach(wininet.getExportByName('InternetOpenUrlW'), {
            onEnter: function(args) {
                var url = args[1].isNull() ? 'NULL' : args[1].readUtf16String();
                var headers = args[2].isNull() ? 'NULL' : args[2].readUtf16String();
                console.log('[InternetOpenUrlW] URL="' + url + '"');
                if (headers !== 'NULL') console.log('[InternetOpenUrlW] Headers="' + headers + '"');
            },
            onLeave: function(retval) {
                console.log('[InternetOpenUrlW] -> handle=0x' + retval.toString(16));
            }
        });

        // InternetConnectW
        try {
            Interceptor.attach(wininet.getExportByName('InternetConnectW'), {
                onEnter: function(args) {
                    var server = args[1].isNull() ? 'NULL' : args[1].readUtf16String();
                    var port = args[2].toInt32();
                    var user = args[3].isNull() ? 'NULL' : args[3].readUtf16String();
                    var service = args[6].toInt32();
                    console.log('[InternetConnectW] server="' + server + '" port=' + port + ' service=' + service);
                }
            });
        } catch(e) {}

        // HttpOpenRequestW
        try {
            Interceptor.attach(wininet.getExportByName('HttpOpenRequestW'), {
                onEnter: function(args) {
                    var verb = args[1].isNull() ? 'NULL' : args[1].readUtf16String();
                    var obj = args[2].isNull() ? 'NULL' : args[2].readUtf16String();
                    console.log('[HttpOpenRequestW] method="' + verb + '" path="' + obj + '"');
                }
            });
        } catch(e) {}

        // HttpSendRequestW
        try {
            Interceptor.attach(wininet.getExportByName('HttpSendRequestW'), {
                onEnter: function(args) {
                    var headers = args[1].isNull() ? '' : args[1].readUtf16String();
                    var dataLen = args[3].toInt32();
                    console.log('[HttpSendRequestW] headers="' + headers + '" dataLen=' + dataLen);
                    if (dataLen > 0 && dataLen < 4096 && !args[4].isNull()) {
                        try {
                            var data = args[4].readUtf8String(dataLen);
                            console.log('[HttpSendRequestW] data="' + data + '"');
                        } catch(e) {}
                    }
                }
            });
        } catch(e) {}

        // InternetReadFile
        Interceptor.attach(wininet.getExportByName('InternetReadFile'), {
            onEnter: function(args) {
                this.buf = args[1];
                this.bufSize = args[2].toInt32();
                this.bytesRead = args[3];
            },
            onLeave: function(retval) {
                var read = this.bytesRead.readU32();
                if (read > 0 && read < 4096) {
                    try {
                        var data = this.buf.readUtf8String(read);
                        console.log('[InternetReadFile] ' + read + ' bytes: "' + data.substring(0, 500) + '"');
                    } catch(e) {
                        console.log('[InternetReadFile] ' + read + ' bytes (binary)');
                    }
                } else {
                    console.log('[InternetReadFile] ' + read + ' bytes');
                }
            }
        });

    } catch(e) {
        console.log('[*] WinINet hook error: ' + e);
    }
}

// === Hook WSA/socket APIs ===
function hookWS2() {
    try {
        var ws2 = Process.getModuleByName('ws2_32.dll');

        // connect
        try {
            Interceptor.attach(ws2.getExportByName('connect'), {
                onEnter: function(args) {
                    var sa = args[1];
                    var family = sa.readU16();
                    if (family === 2) { // AF_INET
                        var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                        var ip = sa.add(4).readU8() + '.' + sa.add(5).readU8() + '.' + sa.add(6).readU8() + '.' + sa.add(7).readU8();
                        console.log('[connect] ' + ip + ':' + port);
                    }
                }
            });
        } catch(e) {}

        // getaddrinfo
        try {
            Interceptor.attach(ws2.getExportByName('getaddrinfo'), {
                onEnter: function(args) {
                    var node = args[0].isNull() ? 'NULL' : args[0].readAnsiString();
                    var service = args[1].isNull() ? 'NULL' : args[1].readAnsiString();
                    console.log('[getaddrinfo] node="' + node + '" service="' + service + '"');
                }
            });
        } catch(e) {}

    } catch(e) {}
}

// === DNS hooks (dnsapi) ===
function hookDns() {
    try {
        var dnsapi = Process.getModuleByName('DNSAPI.dll');
        Interceptor.attach(dnsapi.getExportByName('DnsQuery_W'), {
            onEnter: function(args) {
                var name = args[0].readUtf16String();
                var type = args[1].toInt32();
                console.log('[DnsQuery_W] name="' + name + '" type=' + type);
            }
        });
    } catch(e) {}
}

// === CreateProcessW tracking ===
Interceptor.attach(Process.getModuleByName('kernel32.dll').getExportByName('CreateProcessW'), {
    onEnter: function(args) {
        var app = args[0].isNull() ? 'NULL' : args[0].readUtf16String();
        var cmd = args[1].isNull() ? 'NULL' : args[1].readUtf16String();
        console.log('[CreateProcessW] app="' + app + '" cmd="' + cmd + '"');
    }
});

// === Module load monitor ===
var knownModules = {};
Process.enumerateModules().forEach(function(m) { knownModules[m.name.toLowerCase()] = true; });

setInterval(function() {
    Process.enumerateModules().forEach(function(m) {
        var name = m.name.toLowerCase();
        if (!knownModules[name]) {
            knownModules[name] = true;
            console.log('[NEW MODULE] ' + m.name + ' base=0x' + m.base.toString(16));
            if (name === 'wininet.dll') hookWinINet();
            if (name === 'ws2_32.dll') hookWS2();
            if (name === 'dnsapi.dll') hookDns();
        }
    });

    // Try to dump RWX regions periodically
    rwxRegions.forEach(function(r, i) {
        if (!r.dumped) {
            try {
                var firstByte = r.addr.readU8();
                if (firstByte !== 0) {
                    dumpRegion('rwx_' + i, r.addr, r.size);
                    r.dumped = true;
                }
            } catch(e) {}
        }
    });
}, 2000);

// Also try to hook already-loaded modules
try { hookWS2(); } catch(e) {}
try { hookDns(); } catch(e) {}

console.log('[*] hook_wininet.js loaded - monitoring C2 communications');
