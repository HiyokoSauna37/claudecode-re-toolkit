/**
 * dump_dex.js — Runtime DEX dumping for NMMP and other packers
 * Hooks InMemoryDexClassLoader and DexClassLoader to dump decrypted DEX at load time.
 * Usage: frida -U -l dump_dex.js -f <package> --no-pause
 */
Java.perform(function() {
    var dexCount = 0;

    function saveDex(dexBytes, label) {
        dexCount++;
        var fname = "/sdcard/dumped_dex_" + dexCount + "_" + label + ".dex";
        try {
            var FileOutputStream = Java.use("java.io.FileOutputStream");
            var fos = FileOutputStream.$new(fname);
            fos.write(dexBytes);
            fos.close();
            console.log("[DEX-DUMP] Saved " + dexBytes.length + " bytes → " + fname);
        } catch(e) {
            console.log("[DEX-DUMP] Save failed: " + e);
        }
    }

    // Hook InMemoryDexClassLoader (Android 8+, used by modern packers)
    try {
        var InMemoryDexClassLoader = Java.use("dalvik.system.InMemoryDexClassLoader");
        InMemoryDexClassLoader.$init.overload("java.nio.ByteBuffer", "java.lang.ClassLoader").implementation = function(buf, parent) {
            console.log("[InMemoryDexClassLoader] size=" + buf.remaining());
            try {
                var arr = Java.array('byte', new Array(buf.remaining()));
                var pos = buf.position();
                buf.get(arr);
                buf.position(pos);
                saveDex(arr, "inmemory");
            } catch(e) {
                console.log("[InMemoryDexClassLoader] dump error: " + e);
            }
            this.$init(buf, parent);
        };
        InMemoryDexClassLoader.$init.overload("[Ljava.nio.ByteBuffer;", "java.lang.ClassLoader").implementation = function(bufs, parent) {
            console.log("[InMemoryDexClassLoader] buffers=" + bufs.length);
            for (var i = 0; i < bufs.length; i++) {
                try {
                    var b = bufs[i];
                    var arr = Java.array('byte', new Array(b.remaining()));
                    var pos = b.position();
                    b.get(arr);
                    b.position(pos);
                    saveDex(arr, "inmemory_" + i);
                } catch(e) {}
            }
            this.$init(bufs, parent);
        };
        console.log("[*] InMemoryDexClassLoader hooked");
    } catch(e) { console.log("[!] InMemoryDexClassLoader: " + e); }

    // Hook DexClassLoader (older method)
    try {
        var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
        DexClassLoader.$init.implementation = function(dexPath, optDir, libPath, parent) {
            console.log("[DexClassLoader] path=" + dexPath);
            // Read the DEX file and dump it
            try {
                var File = Java.use("java.io.File");
                var FileInputStream = Java.use("java.io.FileInputStream");
                var ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
                var f = File.$new(dexPath);
                if (f.exists()) {
                    var fis = FileInputStream.$new(f);
                    var baos = ByteArrayOutputStream.$new();
                    var buf = Java.array('byte', new Array(4096));
                    var n;
                    while ((n = fis.read(buf)) !== -1) {
                        baos.write(buf, 0, n);
                    }
                    fis.close();
                    saveDex(baos.toByteArray(), "dexcl");
                }
            } catch(e) {
                console.log("[DexClassLoader] dump error: " + e);
            }
            this.$init(dexPath, optDir, libPath, parent);
        };
        console.log("[*] DexClassLoader hooked");
    } catch(e) { console.log("[!] DexClassLoader: " + e); }

    // Hook PathClassLoader (fallback)
    try {
        var PathClassLoader = Java.use("dalvik.system.PathClassLoader");
        PathClassLoader.$init.overload("java.lang.String", "java.lang.ClassLoader").implementation = function(path, parent) {
            console.log("[PathClassLoader] path=" + path);
            this.$init(path, parent);
        };
        console.log("[*] PathClassLoader hooked");
    } catch(e) {}

    // Hook openDexFile (native level)
    try {
        var DexFile = Java.use("dalvik.system.DexFile");
        DexFile.loadDex.implementation = function(sourceFile, outputFile, flags) {
            console.log("[DexFile.loadDex] src=" + sourceFile + " out=" + outputFile);
            return this.loadDex(sourceFile, outputFile, flags);
        };
        console.log("[*] DexFile.loadDex hooked");
    } catch(e) {}

    console.log("\n[***] DEX dump hooks installed. Launch the app to capture unpacked DEX.\n");
});
