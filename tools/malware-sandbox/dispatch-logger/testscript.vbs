' ComprehensiveTest.vbs - Test all COM object creation methods
Option Explicit

WScript.Echo "Starting COM object creation tests..."

' Test 1: CreateObject with ProgID
WScript.Echo "Test 1: CreateObject with common ProgIDs"
Dim fso, shell, dict

On Error Resume Next

'Set vb = CreateObject("Project1.Class1")

Set fso = CreateObject("Scripting.FileSystemObject")
If Err.Number = 0 Then
    WScript.Echo "Created FileSystemObject"
    WScript.Echo "Temp path: " & fso.GetSpecialFolder(2)
Else
    WScript.Echo "Failed to create FileSystemObject: " & Err.Description
End If
Err.Clear

Set shell = CreateObject("WScript.Shell")  
If Err.Number = 0 Then
    WScript.Echo "Created WScript.Shell"
    WScript.Echo "Windows dir: " & shell.ExpandEnvironmentStrings("%WINDIR%")
Else
    WScript.Echo "Failed to create WScript.Shell: " & Err.Description
End If
Err.Clear

Set dict = CreateObject("Scripting.Dictionary")
If Err.Number = 0 Then
    WScript.Echo "Created Dictionary"
    dict.Add "test", "value"
    WScript.Echo "Dict test: " & dict.Item("test")
Else
    WScript.Echo "Failed to create Dictionary: " & Err.Description
End If
Err.Clear

' Test 2: Try XMLHTTP
Dim xhr
Set xhr = CreateObject("MSXML2.XMLHTTP")
If Err.Number = 0 Then
    WScript.Echo "Created XMLHTTP"
Else
    WScript.Echo "Failed to create XMLHTTP: " & Err.Description
End If
Err.Clear

' Test 3: WScript object properties
WScript.Echo "WScript.FullName: " & WScript.FullName
WScript.Echo "WScript.Version: " & WScript.Version

On Error Goto 0

WScript.Echo "Tests complete!"
