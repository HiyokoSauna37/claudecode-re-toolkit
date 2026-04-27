// WMI_Test.js - Test GetObject with WMI/WBEM interfaces in JScript
// This will test if we catch objects obtained through GetObject
// JScript malware often uses WMI for reconnaissance

WScript.Echo("Testing GetObject with WMI from JScript...");
WScript.Echo("==========================================");

// Test 1: GetObject with WMI moniker
try {
    var objWMIService = GetObject("winmgmts:\\\\.\\root\\cimv2");
    WScript.Echo("Got WMI Service via GetObject");
    
    // Query for processes - common malware technique
    var colProcesses = objWMIService.ExecQuery("SELECT * FROM Win32_Process WHERE Name = 'svchost.exe'");
    WScript.Echo("Queried for svchost.exe processes");
    
    // Enumerate using Enumerator (JScript specific)
    var enumProcesses = new Enumerator(colProcesses);
    var count = 0;
    for (; !enumProcesses.atEnd(); enumProcesses.moveNext()) {
        var objProcess = enumProcesses.item();
        WScript.Echo("  Process: " + objProcess.Name + " (PID: " + objProcess.ProcessId + ")");
        count++;
        if (count >= 3) break;  // Just show first 3
    }
    WScript.Echo("Total shown: " + count + " processes");
}
catch(e) {
    WScript.Echo("Failed to get WMI service: " + e.message);
}

// Test 2: Get existing object from ROT
WScript.Echo("");
WScript.Echo("Testing GetObject with existing objects...");

try {
    var objExcel = GetObject("", "Excel.Application");
    WScript.Echo("Found running Excel instance");
    objExcel.Visible = true;
}
catch(e) {
    WScript.Echo("No running Excel found (expected): 0x" + (e.number >>> 0).toString(16));
}

// Test 3: WMI method that returns objects
WScript.Echo("");
WScript.Echo("Testing WMI methods returning objects...");

try {
    var colOS = objWMIService.ExecQuery("SELECT * FROM Win32_OperatingSystem");
    var enumOS = new Enumerator(colOS);
    enumOS.moveNext();
    var objOS = enumOS.item();
    WScript.Echo("Windows Directory: " + objOS.WindowsDirectory);
    WScript.Echo("OS Caption: " + objOS.Caption);
    WScript.Echo("Total Visible Memory: " + Math.round(objOS.TotalVisibleMemorySize/1024) + " MB");
}
catch(e) {
    WScript.Echo("OS query failed: " + e.message);
}

// Test 4: Create WMI object directly
WScript.Echo("");
WScript.Echo("Testing direct WMI object creation...");

try {
    var objSWbemLocator = new ActiveXObject("WbemScripting.SWbemLocator");
    WScript.Echo("Created SWbemLocator");
    
    var objSWbemServices = objSWbemLocator.ConnectServer(".", "root\\cimv2");
    WScript.Echo("Connected to WMI namespace");
    
    // Try a different query
    var colDisks = objSWbemServices.ExecQuery("SELECT * FROM Win32_LogicalDisk WHERE DriveType = 3");
    var enumDisks = new Enumerator(colDisks);
    WScript.Echo("Fixed disk drives:");
    for (; !enumDisks.atEnd(); enumDisks.moveNext()) {
        var disk = enumDisks.item();
        var freeGB = (disk.FreeSpace / (1024*1024*1024)).toFixed(2);
        var sizeGB = (disk.Size / (1024*1024*1024)).toFixed(2);
        WScript.Echo("  " + disk.DeviceID + " - " + freeGB + " GB free of " + sizeGB + " GB");
    }
}
catch(e) {
    WScript.Echo("SWbemLocator failed: " + e.message);
}

// Test 5: JScript-specific - try XMLHttpRequest
WScript.Echo("");
WScript.Echo("Testing JScript XMLHttpRequest...");

try {
    var xhr = new ActiveXObject("MSXML2.XMLHTTP");
    WScript.Echo("Created XMLHTTP object");
    // Don't actually make a request, just test object creation
}
catch(e) {
    WScript.Echo("XMLHTTP creation failed: " + e.message);
}

WScript.Echo("");
WScript.Echo("JScript WMI Tests complete!");

// Note: JScript uses new ActiveXObject() instead of CreateObject()
// and new Enumerator() for collections instead of For Each