/*
   Malware Development Techniques (MDT) — Detection Rules
   ──────────────────────────────────────────────────────
   Source inspiration: f00crew / "Malware Development Essentials for Operators"
   Purpose: Defensive YARA rules to flag offensive Windows technique stacks
            commonly chained together by modern operators (loaders, implants,
            APT-grade kernel rootkits).

   Each rule maps to MITRE ATT&CK in metadata. False-positive risk is annotated.
   These rules are deliberately written for *technique* detection (not family
   attribution) so they complement signature-base/yara-forge rather than
   duplicate them.

   Categories:
     1. Dynamic API resolution (PEB walking + API hashing)
     2. Process injection variants (Hollowing, Early Bird APC, NtCreateThreadEx)
     3. Kernel-mode techniques (callback abuse, DKOM, token stealing)
     4. Multi-layer shellcode encryption (XOR + CryptoAPI)
*/

import "pe"

// ════════════════════════════════════════════════════════════════════════════
// 1. DYNAMIC API RESOLUTION  (T1027.007 / T1106 — PEB walking, API hashing)
// ════════════════════════════════════════════════════════════════════════════

rule MalDev_PEB_Walking_x64
{
    meta:
        author      = "cc-malware-toolkit"
        description = "x64 PEB walking via gs:[60h] — classic dynamic loader prelude"
        attack      = "T1027.007"  // Dynamic API Resolution
        reference   = "f00crew 0x33 — Malware Development Essentials"
        severity    = "medium"
        fp_risk     = "low (combined with $teb_walk anchors)"
    strings:
        // mov rax/rcx/rdx/r10 ... gs:[0x60]   — fetch PEB
        $peb_x64_a = { 65 48 8B ?? 25 60 00 00 00 }
        // mov rax, qword ptr gs:[0x60] (Intel syntax variant)
        $peb_x64_b = { 65 4? 8B 04 25 60 00 00 00 }
        // PEB->Ldr at +0x18, then InMemoryOrderModuleList at +0x20
        $ldr_off   = { 48 8B ?? 18 }
        $inmem_off = { 48 8B ?? 20 }
        // FullDllName.Buffer compare to "kernel32.dll" (UTF-16 LE)
        $kernel32  = "k\x00e\x00r\x00n\x00e\x00l\x00"
        $ntdll_w   = "n\x00t\x00d\x00l\x00l\x00"
    condition:
        uint16(0) == 0x5A4D and pe.is_64bit() and
        any of ($peb_x64_*) and $ldr_off and $inmem_off and
        any of ($kernel32, $ntdll_w)
}

rule MalDev_PEB_Walking_x86
{
    meta:
        author      = "cc-malware-toolkit"
        description = "x86 PEB walking via fs:[30h] — dynamic API resolution prelude"
        attack      = "T1027.007"
        severity    = "medium"
        fp_risk     = "low-medium"
    strings:
        // mov eax, fs:[30h]
        $peb_x86_a = { 64 A1 30 00 00 00 }
        // mov reg, fs:[30h]
        $peb_x86_b = { 64 8B ?? 25 30 00 00 00 }
        // mov reg, [reg+0Ch]   → PEB->Ldr
        $ldr12     = { 8B ?? 0C }
        // mov reg, [reg+14h]   → PEB_LDR_DATA->InMemoryOrderModuleList
        $inmem14   = { 8B ?? 14 }
        $kernel32  = "k\x00e\x00r\x00n\x00e\x00l\x00"
    condition:
        uint16(0) == 0x5A4D and not pe.is_64bit() and
        any of ($peb_x86_*) and $ldr12 and $inmem14 and $kernel32
}

rule MalDev_API_Hash_ROR13
{
    meta:
        author      = "cc-malware-toolkit"
        description = "ROR13 API hashing — Metasploit/Cobalt Strike heritage hashes"
        attack      = "T1027.007"
        severity    = "high"
        fp_risk     = "low — these are exact 32-bit constants"
        note        = "Hashes for kernel32!{LoadLibraryA, GetProcAddress, VirtualAlloc, ExitProcess, etc.}"
    strings:
        // Pre-computed ROR13 hashes seen in shellcode loaders
        // LoadLibraryA  = 0x0726774C  (some sources: 0xEC0E4E8E for slightly different impl)
        $h_loadlib_a   = { 4C 77 26 07 }
        $h_loadlib_b   = { 8E 4E 0E EC }
        // GetProcAddress = 0x7C0DFCAA
        $h_getproc     = { AA FC 0D 7C }
        // VirtualAlloc   = 0x91AFCA54
        $h_virtalloc   = { 54 CA AF 91 }
        // ExitProcess    = 0x73E2D87E
        $h_exitproc    = { 7E D8 E2 73 }
        // WinExec        = 0xE8AFE98
        $h_winexec     = { 98 FE 8A 0E }
        // RtlExitUserThread = 0xCEF676C9
        $h_rtlexit     = { C9 76 F6 CE }
        // The ROR13 inner-loop opcode pattern: ROR EAX, 0x0D
        $ror13         = { C1 C8 0D }
    condition:
        uint16(0) == 0x5A4D and
        $ror13 and 2 of ($h_*)
}

rule MalDev_API_Hash_FNV1a
{
    meta:
        author      = "cc-malware-toolkit"
        description = "FNV-1a API hashing — newer loaders prefer this over ROR13"
        attack      = "T1027.007"
        severity    = "medium"
        fp_risk     = "medium — FNV-1a is also legitimate"
    strings:
        // FNV-1a 32-bit prime: 0x01000193
        $fnv32_prime = { 93 01 00 01 }
        // FNV-1a 32-bit offset basis: 0x811C9DC5
        $fnv32_basis = { C5 9D 1C 81 }
        // FNV-1a 64-bit prime: 0x100000001b3
        $fnv64_prime = { B3 01 00 00 00 01 00 00 }
        // FNV-1a 64-bit offset basis: 0xCBF29CE484222325
        $fnv64_basis = { 25 23 22 84 E4 9C F2 CB }
    condition:
        uint16(0) == 0x5A4D and
        ( ($fnv32_prime and $fnv32_basis) or ($fnv64_prime and $fnv64_basis) )
}

rule MalDev_LowImports_DynamicLoader
{
    meta:
        author      = "cc-malware-toolkit"
        description = "PE with abnormally small IAT + presence of Ldr* APIs — dynamic resolver"
        attack      = "T1027.007"
        severity    = "low"
        fp_risk     = "high in isolation — combine with PEB walking rules"
    strings:
        $ldr1 = "LdrLoadDll"             ascii
        $ldr2 = "LdrGetProcedureAddress" ascii
        $ldr3 = "LdrFindEntryForAddress" ascii
        $rtl1 = "RtlImageNtHeader"       ascii
        $rtl2 = "RtlImageDirectoryEntryToData" ascii
    condition:
        uint16(0) == 0x5A4D and
        pe.number_of_imports >= 1 and pe.number_of_imports < 5 and
        any of ($ldr*, $rtl*)
}

// ════════════════════════════════════════════════════════════════════════════
// 2. PROCESS INJECTION VARIANTS  (T1055.012 / T1055.004 / T1055.005)
// ════════════════════════════════════════════════════════════════════════════

rule MalDev_ProcessHollowing_API_Set
{
    meta:
        author      = "cc-malware-toolkit"
        description = "Process Hollowing API quintet (RunPE) — Sirifef/ZeroAccess heritage"
        attack      = "T1055.012"
        reference   = "f00crew 0x33"
        severity    = "high"
        fp_risk     = "low — five APIs co-occurring is rare for benign code"
    strings:
        $a1 = "NtUnmapViewOfSection" ascii nocase
        $a2 = "ZwUnmapViewOfSection" ascii nocase
        $b  = "VirtualAllocEx"        ascii
        $c  = "WriteProcessMemory"    ascii
        $d  = "SetThreadContext"      ascii
        $e  = "ResumeThread"          ascii
    condition:
        uint16(0) == 0x5A4D and
        ($a1 or $a2) and $b and $c and $d and $e
}

rule MalDev_EarlyBird_APC_Injection
{
    meta:
        author      = "cc-malware-toolkit"
        description = "Early Bird APC injection — APT33/Elfin signature pattern"
        attack      = "T1055.004"
        reference   = "f00crew 0x33"
        severity    = "high"
        fp_risk     = "low — QueueUserAPC + CREATE_SUSPENDED is a distinct combo"
    strings:
        $cps  = "CreateProcessA"   ascii
        $cpsw = "CreateProcessW"   ascii
        $apc  = "QueueUserAPC"     ascii
        $apc2 = "NtQueueApcThread" ascii nocase
        $vae  = "VirtualAllocEx"   ascii
        $wpm  = "WriteProcessMemory" ascii
        $rt   = "ResumeThread"     ascii
    condition:
        uint16(0) == 0x5A4D and
        ($apc or $apc2) and ($cps or $cpsw) and $vae and $wpm and $rt
}

rule MalDev_NtCreateThreadEx_RemoteInject
{
    meta:
        author      = "cc-malware-toolkit"
        description = "NtCreateThreadEx remote thread — bypasses session boundary"
        attack      = "T1055.002"
        severity    = "medium"
        fp_risk     = "medium — also used by legit injection libs (Detours)"
    strings:
        $a = "NtCreateThreadEx"   ascii
        $b = "ZwCreateThreadEx"   ascii
        $c = "RtlCreateUserThread" ascii
        $d = "VirtualAllocEx"     ascii
        $e = "WriteProcessMemory" ascii
    condition:
        uint16(0) == 0x5A4D and
        any of ($a, $b, $c) and $d and $e
}

rule MalDev_Reflective_DLL_Injection
{
    meta:
        author      = "cc-malware-toolkit"
        description = "Reflective DLL loading — ReflectiveLoader export or stomped loader"
        attack      = "T1620"
        severity    = "high"
        fp_risk     = "low"
    strings:
        $exp1 = "ReflectiveLoader"     ascii
        $exp2 = "_ReflectiveLoader@4"  ascii
        $str_flush = "FlushInstructionCache" ascii
        // PE signature scan loop pattern: cmp word ptr [reg], 'MZ'
        $pe_scan = { 66 81 ?? 4D 5A }
    condition:
        uint16(0) == 0x5A4D and
        any of ($exp*) and $str_flush and $pe_scan
}

// ════════════════════════════════════════════════════════════════════════════
// 3. KERNEL-MODE TECHNIQUES  (T1014 — Rootkit / T1547.006 — Kernel Module)
// ════════════════════════════════════════════════════════════════════════════

rule MalDev_Kernel_Callback_Abuse
{
    meta:
        author      = "cc-malware-toolkit"
        description = "Kernel callback registration to monitor/block AV-EDR operations"
        attack      = "T1547.006"
        reference   = "f00crew 0x33"
        severity    = "high"
        fp_risk     = "very low for non-driver — high for legit drivers"
        note        = "Apply only to PE files with IMAGE_SUBSYSTEM_NATIVE or IMAGE_FILE_SYSTEM"
    strings:
        $cb1 = "PsSetCreateProcessNotifyRoutineEx" ascii
        $cb2 = "PsSetCreateProcessNotifyRoutine"   ascii
        $cb3 = "PsSetLoadImageNotifyRoutine"        ascii
        $cb4 = "PsSetCreateThreadNotifyRoutine"     ascii
        $cb5 = "ObRegisterCallbacks"                ascii
        $cb6 = "CmRegisterCallbackEx"               ascii
        $cb7 = "CmRegisterCallback"                 ascii
    condition:
        uint16(0) == 0x5A4D and
        pe.subsystem == pe.SUBSYSTEM_NATIVE and
        2 of ($cb*)
}

rule MalDev_DKOM_PsInitialSystemProcess
{
    meta:
        author      = "cc-malware-toolkit"
        description = "Direct Kernel Object Manipulation — token stealing / process hide"
        attack      = "T1014"
        reference   = "f00crew 0x33"
        severity    = "critical"
        fp_risk     = "very low — only seen in rootkits and PoC drivers"
        note        = "Offsets target Win10/11 x64 EPROCESS layout"
    strings:
        $a = "PsInitialSystemProcess"   ascii
        $b = "PsLookupProcessByProcessId" ascii
        $c = "PsGetProcessPeb"          ascii
        // EPROCESS field offsets used by token-steal / unlink primitives.
        // x64 mov-immediate "mov eax, 0xXXX" = B8 [imm32]
        $off_token_4b8 = { B8 B8 04 00 00 }    // Token at 0x4B8 (Win10 1809+)
        $off_apl_448   = { B8 48 04 00 00 }    // ActiveProcessLinks at 0x448
        $off_apl_2f0   = { B8 F0 02 00 00 }    // ActiveProcessLinks at 0x2F0 (older builds)
        $off_pid_440   = { B8 40 04 00 00 }    // UniqueProcessId at 0x440
        // x64 add reg, imm32 forms — REX-prefixed ADD with 32-bit imm
        $add_token_4b8 = { 48 81 C? B8 04 00 00 }
        $add_apl_448   = { 48 81 C? 48 04 00 00 }
        $add_apl_2f0   = { 48 81 C? F0 02 00 00 }
    condition:
        uint16(0) == 0x5A4D and
        pe.subsystem == pe.SUBSYSTEM_NATIVE and
        ($a or $b or $c) and any of ($off_*, $add_*)
}

rule MalDev_Driver_Hide_DriverObject
{
    meta:
        author      = "cc-malware-toolkit"
        description = "Driver self-hiding via InLoadOrderLinks unlink (DKOM)"
        attack      = "T1014"
        severity    = "critical"
        fp_risk     = "very low"
    strings:
        $do  = "DriverSection"      ascii
        $lo1 = "PsLoadedModuleList" ascii
        $lo2 = "MmGetSystemRoutineAddress" ascii
        $de  = "DriverEntry"        ascii
        // Typical unlink: blink->Flink = entry->Flink; entry->Flink->Blink = blink
        $unlink_x64 = { 48 8B 4? 08 48 8B 5? 00 48 89 5? 08 48 89 4? 00 }
    condition:
        uint16(0) == 0x5A4D and
        pe.subsystem == pe.SUBSYSTEM_NATIVE and
        $de and ($do or $lo1 or $lo2) and $unlink_x64
}

// ════════════════════════════════════════════════════════════════════════════
// 4. MULTI-LAYER SHELLCODE ENCRYPTION  (T1027 — Obfuscated Files)
// ════════════════════════════════════════════════════════════════════════════

rule MalDev_MultiLayer_Crypto_Loader
{
    meta:
        author      = "cc-malware-toolkit"
        description = "Two-stage decryption (XOR pre-stage + CryptoAPI/Bcrypt main stage)"
        attack      = "T1027"
        reference   = "f00crew 0x33 — 27→9→5 detection drop via layered crypto"
        severity    = "medium"
        fp_risk     = "medium — many packers also use this pattern"
    strings:
        // CryptoAPI — old style
        $c1 = "CryptDecrypt"        ascii
        $c2 = "CryptAcquireContextA" ascii
        $c3 = "CryptAcquireContextW" ascii
        // Bcrypt — modern style
        $b1 = "BCryptDecrypt"            ascii
        $b2 = "BCryptOpenAlgorithmProvider" ascii
        $b3 = "BCryptGenerateSymmetricKey"  ascii
        // XOR loop heuristic patterns (x64)
        // xor BYTE PTR [rcx+rdx], al  + inc rdx + cmp + jne
        $xor_loop_x64 = { 30 0? 1? 4? FF C? 4? 39 ?? 7? ?? }
        // x86 variant: xor [esi+edx], al ; inc edx ; cmp/jne
        $xor_loop_x86 = { 30 04 16 42 39 ?? 7? ?? }
    condition:
        uint16(0) == 0x5A4D and
        ( any of ($c*) or any of ($b*) ) and any of ($xor_loop_*)
}

rule MalDev_AES_Embedded_SBox_or_RCON
{
    meta:
        author      = "cc-malware-toolkit"
        description = "Embedded AES S-box or RCON table — inline AES (no CryptoAPI)"
        attack      = "T1027"
        severity    = "low"
        fp_risk     = "high — also in OpenSSL, Crypto++, etc.; combine with size <500KB"
    strings:
        // AES Forward S-Box first 8 bytes
        $sbox  = { 63 7C 77 7B F2 6B 6F C5 }
        // AES Inverse S-Box first 8 bytes
        $isbox = { 52 09 6A D5 30 36 A5 38 }
        // RCON table
        $rcon  = { 8D 01 02 04 08 10 20 40 80 1B 36 }
    condition:
        uint16(0) == 0x5A4D and
        any of ($sbox, $isbox, $rcon) and
        filesize < 1MB
}

// ════════════════════════════════════════════════════════════════════════════
// 5. COMBINED INDICATORS — high-confidence "operator-grade" implant flag
// ════════════════════════════════════════════════════════════════════════════

rule MalDev_Operator_Stack
{
    meta:
        author      = "cc-malware-toolkit"
        description = "Multiple operator-tier techniques in one binary — likely modern implant"
        attack      = "T1027.007 + T1055 + T1027"
        severity    = "high"
        fp_risk     = "very low — aggregator rule"
    condition:
        2 of (
            MalDev_PEB_Walking_x64,
            MalDev_PEB_Walking_x86,
            MalDev_API_Hash_ROR13,
            MalDev_API_Hash_FNV1a,
            MalDev_ProcessHollowing_API_Set,
            MalDev_EarlyBird_APC_Injection,
            MalDev_Reflective_DLL_Injection,
            MalDev_MultiLayer_Crypto_Loader
        )
}
