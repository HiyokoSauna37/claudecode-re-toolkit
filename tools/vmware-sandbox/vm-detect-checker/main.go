// vm-detect-checker: ゲスト内で実行してVM検知ポイントを洗い出す
//
// VMProtectが使うVM検知手法を全チェックし、
// どの項目がVMを示しているかレポートする。
//
// Usage: vm-detect-checker.exe > report.txt
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

var (
	ntdll    = syscall.NewLazyDLL("ntdll.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procNtQuerySystemInformation  = ntdll.NewProc("NtQuerySystemInformation")
	procGetSystemFirmwareTable    = kernel32.NewProc("GetSystemFirmwareTable")
	procGetAdaptersAddresses      = syscall.NewLazyDLL("iphlpapi.dll").NewProc("GetAdaptersAddresses")
)

const (
	SystemFirmwareTableInformation = 76
	RSMB                           = 0x52534D42 // 'RSMB'
	FIRM                           = 0x4649524D // 'FIRM'
)

func main() {
	fmt.Println("=== VM Detection Checker ===")
	fmt.Println("VMProtectが使う検知手法をチェックします")
	fmt.Println()

	checkSMBIOS()
	checkFIRM()
	checkCPUID()
	checkMACAddress()
	checkProcesses()
	checkRegistry()
	checkDrivers()
	checkDevices()

	fmt.Println("\n=== チェック完了 ===")
}

func checkSMBIOS() {
	fmt.Println("--- [1] SMBIOS (RSMB) テーブル ---")

	size, _, _ := procGetSystemFirmwareTable.Call(
		uintptr(RSMB), 0, 0, 0,
	)
	if size == 0 {
		fmt.Println("  [!] RSMB取得失敗")
		return
	}

	buf := make([]byte, size)
	ret, _, _ := procGetSystemFirmwareTable.Call(
		uintptr(RSMB), 0,
		uintptr(unsafe.Pointer(&buf[0])),
		size,
	)
	if ret == 0 {
		fmt.Println("  [!] RSMB読み取り失敗")
		return
	}

	vmKeywords := []string{"VMware", "vmware", "VMWARE", "Virtual", "virtual", "VIRTUAL",
		"VirtualBox", "VBOX", "Hyper-V", "Xen", "KVM", "QEMU", "Parallels"}

	data := string(buf)
	found := false
	for _, kw := range vmKeywords {
		if idx := strings.Index(data, kw); idx >= 0 {
			// Extract context around the match
			start := idx - 20
			if start < 0 {
				start = 0
			}
			end := idx + len(kw) + 20
			if end > len(data) {
				end = len(data)
			}
			context := sanitize(data[start:end])
			fmt.Printf("  [DETECT] \"%s\" found at offset %d (context: ...%s...)\n", kw, idx, context)
			found = true
		}
	}
	if !found {
		fmt.Println("  [OK] VM関連文字列なし")
	}
	fmt.Printf("  サイズ: %d bytes\n", size)
}

func checkFIRM() {
	fmt.Println("\n--- [2] FIRM (BIOS ROM) テーブル ---")

	// FIRM provider with table ID 0xC0000
	firmIDs := []uint32{0xC0000, 0xE0000}
	for _, tableID := range firmIDs {
		fmt.Printf("  テーブル 0x%X:\n", tableID)

		size, _, _ := procGetSystemFirmwareTable.Call(
			uintptr(FIRM), uintptr(tableID), 0, 0,
		)
		if size == 0 {
			fmt.Printf("    [!] 取得失敗 (サイズ0)\n")
			continue
		}

		buf := make([]byte, size)
		ret, _, _ := procGetSystemFirmwareTable.Call(
			uintptr(FIRM), uintptr(tableID),
			uintptr(unsafe.Pointer(&buf[0])),
			size,
		)
		if ret == 0 {
			fmt.Printf("    [!] 読み取り失敗\n")
			continue
		}

		vmKeywords := []string{"VMware", "vmware", "VMWARE", "Virtual", "virtual",
			"VirtualBox", "VBOX", "Hyper-V", "Xen", "KVM", "QEMU"}

		data := string(buf)
		found := false
		for _, kw := range vmKeywords {
			idx := 0
			for {
				pos := strings.Index(data[idx:], kw)
				if pos < 0 {
					break
				}
				absPos := idx + pos
				start := absPos - 16
				if start < 0 {
					start = 0
				}
				end := absPos + len(kw) + 16
				if end > len(data) {
					end = len(data)
				}
				context := sanitize(data[start:end])
				fmt.Printf("    [DETECT] \"%s\" at offset %d (context: ...%s...)\n", kw, absPos, context)
				found = true
				idx = absPos + len(kw)
			}
		}
		if !found {
			fmt.Printf("    [OK] VM関連文字列なし\n")
		}
		fmt.Printf("    サイズ: %d bytes\n", size)
	}
}

func checkCPUID() {
	fmt.Println("\n--- [3] CPUID ハイパーバイザビット ---")

	// We can't directly call CPUID from Go easily, but we can check
	// via WMI or registry
	// Check if hypervisor is present via registry
	var key syscall.Handle
	err := syscall.RegOpenKeyEx(
		syscall.HKEY_LOCAL_MACHINE,
		syscall.StringToUTF16Ptr(`HARDWARE\DESCRIPTION\System\CentralProcessor\0`),
		0, syscall.KEY_READ, &key)

	if err == nil {
		fmt.Println("  [INFO] CPUIDの直接チェックにはアセンブリが必要")
		fmt.Println("  [INFO] hypervisor.cpuid.v0=FALSE が設定済みならOK")
		syscall.RegCloseKey(key)
	}

	// Check via systeminfo
	fmt.Println("  [INFO] 別途CPUIDチェッカーで確認推奨")
}

func checkMACAddress() {
	fmt.Println("\n--- [4] MACアドレス ---")

	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("  [!] 取得失敗: %v\n", err)
		return
	}

	vmMACs := map[string]string{
		"00:0c:29": "VMware",
		"00:50:56": "VMware",
		"00:05:69": "VMware",
		"08:00:27": "VirtualBox",
		"00:1c:42": "Parallels",
		"00:16:3e": "Xen",
		"52:54:00": "QEMU/KVM",
		"00:15:5d": "Hyper-V",
	}

	for _, iface := range interfaces {
		mac := iface.HardwareAddr.String()
		if mac == "" {
			continue
		}
		prefix := strings.ToLower(mac[:8])
		if vendor, ok := vmMACs[prefix]; ok {
			fmt.Printf("  [DETECT] %s: %s (vendor: %s)\n", iface.Name, mac, vendor)
		} else {
			fmt.Printf("  [OK] %s: %s\n", iface.Name, mac)
		}
	}
}

func checkProcesses() {
	fmt.Println("\n--- [5] VM関連プロセス ---")

	vmProcesses := []string{
		"vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
		"VGAuthService.exe", "vm3dservice.exe",
		"VBoxService.exe", "VBoxTray.exe",
		"xenservice.exe",
	}

	// Use CreateToolhelp32Snapshot to list processes
	snapshot, err := syscall.CreateToolhelp32Snapshot(0x2, 0) // TH32CS_SNAPPROCESS
	if err != nil {
		fmt.Printf("  [!] プロセスリスト取得失敗: %v\n", err)
		return
	}
	defer syscall.CloseHandle(snapshot)

	var pe32 processEntry32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	err = process32First(snapshot, &pe32)
	found := false
	for err == nil {
		name := syscall.UTF16ToString(pe32.ExeFile[:])
		for _, vmProc := range vmProcesses {
			if strings.EqualFold(name, vmProc) {
				fmt.Printf("  [DETECT] %s (PID: %d)\n", name, pe32.ProcessID)
				found = true
			}
		}
		err = process32Next(snapshot, &pe32)
	}
	if !found {
		fmt.Println("  [OK] VM関連プロセスなし")
	}
}

func checkRegistry() {
	fmt.Println("\n--- [6] VM関連レジストリ ---")

	regPaths := []struct {
		root uint32
		path string
		desc string
	}{
		{0x80000002, `SOFTWARE\VMware, Inc.\VMware Tools`, "VMware Tools"},
		{0x80000002, `SOFTWARE\Oracle\VirtualBox Guest Additions`, "VirtualBox GA"},
		{0x80000002, `SYSTEM\CurrentControlSet\Services\VMTools`, "VMTools Service"},
		{0x80000002, `SYSTEM\CurrentControlSet\Services\vm3dservice`, "vm3dservice"},
		{0x80000002, `SYSTEM\CurrentControlSet\Services\vmci`, "VMCI"},
		{0x80000002, `SYSTEM\CurrentControlSet\Services\vmhgfs`, "VMHGFS"},
		{0x80000002, `SYSTEM\CurrentControlSet\Services\vmmouse`, "VMMouse"},
		{0x80000002, `SYSTEM\CurrentControlSet\Enum\PCI\VEN_15AD*`, "VMware PCI"},
	}

	// HKLM = 0x80000002
	for _, rp := range regPaths {
		var key syscall.Handle
		err := syscall.RegOpenKeyEx(
			syscall.Handle(rp.root),
			syscall.StringToUTF16Ptr(rp.path),
			0, syscall.KEY_READ, &key)
		if err == nil {
			fmt.Printf("  [DETECT] %s (%s)\n", rp.path, rp.desc)
			syscall.RegCloseKey(key)
		}
	}
}

func checkDrivers() {
	fmt.Println("\n--- [7] VM関連ドライバファイル ---")

	drivers := []string{
		`C:\Windows\System32\drivers\vmci.sys`,
		`C:\Windows\System32\drivers\vmhgfs.sys`,
		`C:\Windows\System32\drivers\vmmouse.sys`,
		`C:\Windows\System32\drivers\vmrawdsk.sys`,
		`C:\Windows\System32\drivers\vmusbmouse.sys`,
		`C:\Windows\System32\drivers\vm3dmp.sys`,
		`C:\Windows\System32\drivers\vm3dmp_loader.sys`,
		`C:\Windows\System32\drivers\vm3dmp-stats.sys`,
		`C:\Windows\System32\drivers\vm3dmp-debug.sys`,
		`C:\Windows\System32\drivers\vsock.sys`,
		`C:\Windows\System32\drivers\VBoxGuest.sys`,
		`C:\Windows\System32\drivers\VBoxMouse.sys`,
		`C:\Windows\System32\drivers\VBoxSF.sys`,
	}

	for _, d := range drivers {
		if _, err := os.Stat(d); err == nil {
			fmt.Printf("  [DETECT] %s\n", d)
		}
	}
}

func checkDevices() {
	fmt.Println("\n--- [8] VM関連デバイス ---")

	devices := []string{
		`\\.\HGFS`,       // VMware shared folders
		`\\.\vmci`,       // VMware VMCI
		`\\.\VBoxGuest`,  // VirtualBox
		`\\.\VBoxMiniRdr`, // VirtualBox
	}

	for _, dev := range devices {
		ptr, _ := syscall.UTF16PtrFromString(dev)
		handle, err := syscall.CreateFile(
			ptr,
			0, // GENERIC_READ not needed, just check existence
			syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
			nil,
			syscall.OPEN_EXISTING,
			0, 0)
		if err == nil {
			fmt.Printf("  [DETECT] %s (デバイス存在)\n", dev)
			syscall.CloseHandle(handle)
		}
	}
}

// Helper: sanitize non-printable characters
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r < 127 {
			b.WriteRune(r)
		} else {
			b.WriteRune('.')
		}
	}
	return b.String()
}

// Process enumeration structures
type processEntry32 struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [260]uint16
}

var (
	modkernel32      = syscall.NewLazyDLL("kernel32.dll")
	procProcess32First = modkernel32.NewProc("Process32FirstW")
	procProcess32Next  = modkernel32.NewProc("Process32NextW")
)

func process32First(snapshot syscall.Handle, pe *processEntry32) error {
	ret, _, err := procProcess32First.Call(uintptr(snapshot), uintptr(unsafe.Pointer(pe)))
	if ret == 0 {
		return err
	}
	return nil
}

func process32Next(snapshot syscall.Handle, pe *processEntry32) error {
	ret, _, err := procProcess32Next.Call(uintptr(snapshot), uintptr(unsafe.Pointer(pe)))
	if ret == 0 {
		return err
	}
	return nil
}

// For RegOpenKeyEx with HKLM
func init() {
	_ = binary.LittleEndian
	_ = bytes.Compare
}
