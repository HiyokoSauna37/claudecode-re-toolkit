// Test alternative APIs
console.log('=== API Test ===');

// Try Module() constructor style
try {
    var k32 = Process.getModuleByName('kernel32.dll');
    console.log('kernel32 found: ' + k32.base);

    var sleepAddr = k32.getExportByName('Sleep');
    console.log('Sleep via getExportByName: ' + sleepAddr);

    Interceptor.attach(sleepAddr, {
        onEnter: function(args) {
            console.log('Sleep called: ' + args[0].toInt32() + 'ms');
        }
    });
    console.log('Sleep hook SUCCESS via getExportByName');
} catch(e) {
    console.log('getExportByName error: ' + e);
}

// Try DebugSymbol.getFunctionByName
try {
    var addr2 = DebugSymbol.getFunctionByName('kernel32.dll!VirtualProtect');
    console.log('VirtualProtect via DebugSymbol: ' + addr2);
} catch(e) {
    console.log('DebugSymbol error: ' + e);
}

// Try Module.load approach
try {
    var m = new Module('kernel32.dll');
    console.log('new Module: ' + typeof m);
} catch(e) {
    console.log('new Module error: ' + e);
}

// Check Module properties
console.log('Module keys: ' + Object.keys(Module));
console.log('Module.findExportByName: ' + Module.findExportByName);
console.log('Module.getExportByName: ' + Module.getExportByName);

console.log('=== Test Done ===');
