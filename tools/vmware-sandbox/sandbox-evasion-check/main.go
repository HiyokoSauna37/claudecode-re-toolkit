// sandbox-evasion-check: Diagnose sandbox detectability from malware's perspective.
//
// Checks software/behavioral indicators that malware uses to detect analysis environments.
// Complements vm-detect-checker (hardware-level VMware detection) with software-level checks.
//
// Build: GOOS=windows GOARCH=amd64 go build -o sandbox-evasion-check.exe
// Run inside VM: sandbox-evasion-check.exe

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const version = "1.0.0"

// Windows API
var (
	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	user32                = syscall.NewLazyDLL("user32.dll")
	psapi                 = syscall.NewLazyDLL("psapi.dll")
	iphlpapi              = syscall.NewLazyDLL("iphlpapi.dll")
	procGetTickCount64    = kernel32.NewProc("GetTickCount64")
	procGetDiskFreeSpaceExW = kernel32.NewProc("GetDiskFreeSpaceExW")
	procGlobalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetSystemMetrics  = user32.NewProc("GetSystemMetrics")
	procEnumProcesses     = psapi.NewProc("EnumProcesses")
)

// Result structures
type CheckResult struct {
	Category    string `json:"category"`
	Check       string `json:"check"`
	Status      string `json:"status"` // PASS, WARN, FAIL
	Detail      string `json:"detail"`
	Remediation string `json:"remediation,omitempty"`
}

type Report struct {
	Timestamp   string        `json:"timestamp"`
	ToolVersion string        `json:"tool_version"`
	Hostname    string        `json:"hostname"`
	Results     []CheckResult `json:"results"`
	Summary     Summary       `json:"summary"`
}

type Summary struct {
	Total int `json:"total"`
	Pass  int `json:"pass"`
	Warn  int `json:"warn"`
	Fail  int `json:"fail"`
}

// Analysis tool process names that malware checks for
var analysisTools = []string{
	// Debuggers
	"x64dbg.exe", "x32dbg.exe", "ollydbg.exe", "windbg.exe",
	"ida.exe", "ida64.exe", "idaq.exe", "idaq64.exe",
	"radare2.exe", "r2.exe",
	// Monitors
	"procmon.exe", "procmon64.exe", "procexp.exe", "procexp64.exe",
	"processhacker.exe", "tcpview.exe", "autoruns.exe",
	"filemon.exe", "regmon.exe",
	// Network
	"wireshark.exe", "tshark.exe", "dumpcap.exe",
	"fiddler.exe", "burpsuite.exe", "mitmproxy.exe",
	// Sandbox/Analysis
	"fakenet.exe", "inetsim.exe",
	"pestudio.exe", "die.exe", "exeinfope.exe",
	"hxd.exe", "010editor.exe",
	// AV/Security
	"mbam.exe", "mbamservice.exe",
	// Python/scripting (analysis context)
	"python.exe", "pythonw.exe",
	// API monitoring
	"apimonitor-x86.exe", "apimonitor-x64.exe",
}

// Suspicious analysis-related file paths
var analysisPathKeywords = []string{
	"\\tools\\", "\\analysis\\", "\\sandbox\\", "\\malware\\",
	"\\sample\\", "\\virus\\", "\\debug\\", "\\reverse\\",
	"\\ghidra\\", "\\ida\\", "\\x64dbg\\", "\\ollydbg\\",
}

// Username blacklist
var suspiciousUsernames = []string{
	"malware", "sandbox", "analyst", "virus", "sample",
	"test", "admin", "user", "debug", "reverse",
	"john", "peter", "miller", "emily", "johnson",
	"currentuser", "cuckoo", "joe", "tequila",
	"remnux", "flare",
}

func main() {
	fmt.Println("============================================================")
	fmt.Println("Sandbox Evasion Check v" + version)
	fmt.Println("Software-level analysis environment detectability diagnostic")
	fmt.Println("============================================================")
	fmt.Println()

	var results []CheckResult

	// 1. Analysis tool processes
	results = append(results, checkAnalysisProcesses()...)

	// 2. Analysis-related file paths
	results = append(results, checkAnalysisPaths()...)

	// 3. Username patterns
	results = append(results, checkUsername()...)

	// 4. Hardware specs
	results = append(results, checkHardwareSpecs()...)

	// 5. Recent files/documents
	results = append(results, checkRecentFiles()...)

	// 6. System uptime
	results = append(results, checkUptime()...)

	// 7. Screen resolution
	results = append(results, checkScreenResolution()...)

	// 8. Installed software count
	results = append(results, checkInstalledSoftware()...)

	// 9. Network adapter check
	results = append(results, checkNetworkAdapters()...)

	// 10. BIOS/firmware strings
	results = append(results, checkBIOSStrings()...)

	// Build summary
	summary := Summary{Total: len(results)}
	for _, r := range results {
		switch r.Status {
		case "PASS":
			summary.Pass++
		case "WARN":
			summary.Warn++
		case "FAIL":
			summary.Fail++
		}
	}

	hostname, _ := os.Hostname()
	report := Report{
		Timestamp:   time.Now().UTC().Format("2006-01-02T15:04:05"),
		ToolVersion: version,
		Hostname:    hostname,
		Results:     results,
		Summary:     summary,
	}

	// Print results
	for _, r := range results {
		icon := map[string]string{"PASS": "[OK]", "WARN": "[!!]", "FAIL": "[XX]"}[r.Status]
		fmt.Printf("  %s %-30s %s\n", icon, r.Check, r.Detail)
		if r.Remediation != "" && r.Status != "PASS" {
			fmt.Printf("       -> Fix: %s\n", r.Remediation)
		}
	}

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Printf("Summary: %d checks | PASS: %d | WARN: %d | FAIL: %d\n",
		summary.Total, summary.Pass, summary.Warn, summary.Fail)
	fmt.Println("============================================================")

	// Write JSON
	jsonData, _ := json.MarshalIndent(report, "", "  ")
	jsonPath := "sandbox-evasion-report.json"
	os.WriteFile(jsonPath, jsonData, 0644)
	fmt.Printf("\nJSON report: %s\n", jsonPath)
}

// =============================================================================
// Check Functions
// =============================================================================

func checkAnalysisProcesses() []CheckResult {
	pids := make([]uint32, 4096)
	var bytesReturned uint32

	ret, _, _ := procEnumProcesses.Call(
		uintptr(unsafe.Pointer(&pids[0])),
		uintptr(len(pids)*4),
		uintptr(unsafe.Pointer(&bytesReturned)),
	)

	if ret == 0 {
		return []CheckResult{{
			Category: "Processes",
			Check:    "Analysis tool processes",
			Status:   "WARN",
			Detail:   "Failed to enumerate processes",
		}}
	}

	// Get process names via snapshot
	snapshot, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return []CheckResult{{
			Category: "Processes",
			Check:    "Analysis tool processes",
			Status:   "WARN",
			Detail:   "Failed to create process snapshot",
		}}
	}
	defer syscall.CloseHandle(snapshot)

	var pe syscall.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	processNames := make(map[string]bool)
	err = syscall.Process32First(snapshot, &pe)
	for err == nil {
		name := syscall.UTF16ToString(pe.ExeFile[:])
		processNames[strings.ToLower(name)] = true
		err = syscall.Process32Next(snapshot, &pe)
	}

	var found []string
	for _, tool := range analysisTools {
		if processNames[strings.ToLower(tool)] {
			found = append(found, tool)
		}
	}

	if len(found) > 0 {
		return []CheckResult{{
			Category:    "Processes",
			Check:       "Analysis tool processes",
			Status:      "FAIL",
			Detail:      fmt.Sprintf("Detected %d tools: %s", len(found), strings.Join(found, ", ")),
			Remediation: "Rename analysis tool executables or close them before running malware",
		}}
	}

	return []CheckResult{{
		Category: "Processes",
		Check:    "Analysis tool processes",
		Status:   "PASS",
		Detail:   fmt.Sprintf("No analysis tools detected in %d processes", len(processNames)),
	}}
}

func checkAnalysisPaths() []CheckResult {
	var found []string
	analysisKeywords := []string{"tools", "analysis", "sandbox", "malware", "sample", "virus"}

	// Check Desktop for analysis-related directories
	desktopPath := filepath.Join(os.Getenv("USERPROFILE"), "Desktop")
	entries, err := os.ReadDir(desktopPath)
	if err == nil {
		for _, e := range entries {
			lower := strings.ToLower(e.Name())
			for _, keyword := range analysisKeywords {
				if strings.Contains(lower, keyword) {
					found = append(found, filepath.Join("Desktop", e.Name()))
				}
			}
		}
	}

	// Check drive root for analysis-related directories (C:\Tools, C:\analysis, etc.)
	systemDrive := os.Getenv("SystemDrive")
	if systemDrive == "" {
		systemDrive = "C:"
	}
	rootEntries, err := os.ReadDir(systemDrive + "\\")
	if err == nil {
		for _, e := range rootEntries {
			lower := strings.ToLower(e.Name())
			for _, keyword := range analysisKeywords {
				if strings.Contains(lower, keyword) {
					found = append(found, filepath.Join(systemDrive+"\\", e.Name()))
				}
			}
		}
	}

	// Check current working directory
	cwd, _ := os.Getwd()
	cwdLower := strings.ToLower(cwd)
	for _, keyword := range analysisPathKeywords {
		if strings.Contains(cwdLower, keyword) {
			found = append(found, fmt.Sprintf("CWD contains '%s'", keyword))
		}
	}

	if len(found) > 0 {
		return []CheckResult{{
			Category:    "File Paths",
			Check:       "Analysis-related paths",
			Status:      "WARN",
			Detail:      fmt.Sprintf("Found %d suspicious paths: %s", len(found), strings.Join(found, "; ")),
			Remediation: "Use neutral directory names (e.g., C:\\work, C:\\temp) instead of 'analysis', 'tools'",
		}}
	}

	return []CheckResult{{
		Category: "File Paths",
		Check:    "Analysis-related paths",
		Status:   "PASS",
		Detail:   "No suspicious analysis paths detected",
	}}
}

func checkUsername() []CheckResult {
	u, err := user.Current()
	if err != nil {
		return []CheckResult{{
			Category: "Username",
			Check:    "Username pattern",
			Status:   "WARN",
			Detail:   "Failed to get current user",
		}}
	}

	username := strings.ToLower(u.Username)
	// Remove domain prefix
	parts := strings.Split(username, "\\")
	if len(parts) > 1 {
		username = parts[len(parts)-1]
	}

	for _, suspicious := range suspiciousUsernames {
		if strings.Contains(username, suspicious) {
			return []CheckResult{{
				Category:    "Username",
				Check:       "Username pattern",
				Status:      "FAIL",
				Detail:      fmt.Sprintf("Username '%s' matches blacklist pattern '%s'", u.Username, suspicious),
				Remediation: "Use a realistic username (e.g., a common first name + last initial)",
			}}
		}
	}

	return []CheckResult{{
		Category: "Username",
		Check:    "Username pattern",
		Status:   "PASS",
		Detail:   fmt.Sprintf("Username '%s' does not match known sandbox patterns", u.Username),
	}}
}

func checkHardwareSpecs() []CheckResult {
	var results []CheckResult

	// Disk size
	var freeBytesAvailable, totalBytes, totalFreeBytes uint64
	rootPath, _ := syscall.UTF16PtrFromString("C:\\")
	ret, _, _ := procGetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(rootPath)),
		uintptr(unsafe.Pointer(&freeBytesAvailable)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFreeBytes)),
	)

	if ret != 0 {
		diskGB := totalBytes / (1024 * 1024 * 1024)
		if diskGB < 80 {
			results = append(results, CheckResult{
				Category:    "Hardware",
				Check:       "Disk size",
				Status:      "FAIL",
				Detail:      fmt.Sprintf("Disk: %d GB (< 80 GB threshold)", diskGB),
				Remediation: "Increase VM disk to 100+ GB",
			})
		} else {
			results = append(results, CheckResult{
				Category: "Hardware",
				Check:    "Disk size",
				Status:   "PASS",
				Detail:   fmt.Sprintf("Disk: %d GB", diskGB),
			})
		}
	}

	// RAM
	type memoryStatusEx struct {
		Length               uint32
		MemoryLoad           uint32
		TotalPhys            uint64
		AvailPhys            uint64
		TotalPageFile        uint64
		AvailPageFile        uint64
		TotalVirtual         uint64
		AvailVirtual         uint64
		AvailExtendedVirtual uint64
	}

	var memStatus memoryStatusEx
	memStatus.Length = uint32(unsafe.Sizeof(memStatus))
	ret, _, _ = procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&memStatus)))

	if ret != 0 {
		ramGB := memStatus.TotalPhys / (1024 * 1024 * 1024)
		if ramGB < 4 {
			results = append(results, CheckResult{
				Category:    "Hardware",
				Check:       "RAM size",
				Status:      "FAIL",
				Detail:      fmt.Sprintf("RAM: %d GB (< 4 GB threshold)", ramGB),
				Remediation: "Increase VM RAM to 4+ GB",
			})
		} else {
			results = append(results, CheckResult{
				Category: "Hardware",
				Check:    "RAM size",
				Status:   "PASS",
				Detail:   fmt.Sprintf("RAM: %d GB", ramGB),
			})
		}
	}

	// CPU count
	cpuCount := runtime.NumCPU()
	if cpuCount < 2 {
		results = append(results, CheckResult{
			Category:    "Hardware",
			Check:       "CPU cores",
			Status:      "WARN",
			Detail:      fmt.Sprintf("CPU: %d core(s) (low count may be flagged)", cpuCount),
			Remediation: "Increase VM CPU to 2+ cores",
		})
	} else {
		results = append(results, CheckResult{
			Category: "Hardware",
			Check:    "CPU cores",
			Status:   "PASS",
			Detail:   fmt.Sprintf("CPU: %d cores", cpuCount),
		})
	}

	return results
}

func checkRecentFiles() []CheckResult {
	recentPath := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Recent")
	entries, err := os.ReadDir(recentPath)
	if err != nil {
		return []CheckResult{{
			Category: "User Activity",
			Check:    "Recent files",
			Status:   "WARN",
			Detail:   "Failed to read Recent folder",
		}}
	}

	count := len(entries)
	if count < 10 {
		return []CheckResult{{
			Category:    "User Activity",
			Check:       "Recent files",
			Status:      "FAIL",
			Detail:      fmt.Sprintf("Only %d recent files (< 10 = sandbox indicator)", count),
			Remediation: "Open various documents, browse web pages to populate recent files",
		}}
	}

	return []CheckResult{{
		Category: "User Activity",
		Check:    "Recent files",
		Status:   "PASS",
		Detail:   fmt.Sprintf("%d recent files found", count),
	}}
}

func checkUptime() []CheckResult {
	ret, _, _ := procGetTickCount64.Call()
	// GetTickCount64 returns ULONGLONG (64-bit). On amd64, uintptr is 64-bit so
	// this cast is safe. On 32-bit builds, values >49.7 days would truncate,
	// but this tool targets GOARCH=amd64 only.
	uptimeMs := uint64(ret) //nolint:gosec // safe on amd64 target
	uptimeMin := uptimeMs / (1000 * 60)

	if uptimeMin < 5 {
		return []CheckResult{{
			Category:    "System",
			Check:       "System uptime",
			Status:      "FAIL",
			Detail:      fmt.Sprintf("Uptime: %d minutes (< 5 min = just booted)", uptimeMin),
			Remediation: "Wait at least 5-10 minutes after boot before executing malware",
		}}
	} else if uptimeMin < 15 {
		return []CheckResult{{
			Category:    "System",
			Check:       "System uptime",
			Status:      "WARN",
			Detail:      fmt.Sprintf("Uptime: %d minutes (low but acceptable)", uptimeMin),
			Remediation: "Consider waiting longer after boot for more realistic uptime",
		}}
	}

	hours := uptimeMin / 60
	mins := uptimeMin % 60
	return []CheckResult{{
		Category: "System",
		Check:    "System uptime",
		Status:   "PASS",
		Detail:   fmt.Sprintf("Uptime: %dh %dm", hours, mins),
	}}
}

func checkScreenResolution() []CheckResult {
	const SM_CXSCREEN = 0
	const SM_CYSCREEN = 1

	width, _, _ := procGetSystemMetrics.Call(uintptr(SM_CXSCREEN))
	height, _, _ := procGetSystemMetrics.Call(uintptr(SM_CYSCREEN))

	w := int(width)
	h := int(height)

	// Common VM default resolutions
	vmResolutions := map[string]bool{
		"800x600":   true,
		"1024x768":  true,
	}

	res := fmt.Sprintf("%dx%d", w, h)
	if vmResolutions[res] {
		return []CheckResult{{
			Category:    "Display",
			Check:       "Screen resolution",
			Status:      "FAIL",
			Detail:      fmt.Sprintf("Resolution: %s (common VM default)", res),
			Remediation: "Set resolution to 1920x1080 or higher",
		}}
	}

	if w < 1280 || h < 720 {
		return []CheckResult{{
			Category:    "Display",
			Check:       "Screen resolution",
			Status:      "WARN",
			Detail:      fmt.Sprintf("Resolution: %s (low, may be flagged)", res),
			Remediation: "Set resolution to 1920x1080 or higher",
		}}
	}

	return []CheckResult{{
		Category: "Display",
		Check:    "Screen resolution",
		Status:   "PASS",
		Detail:   fmt.Sprintf("Resolution: %s", res),
	}}
}

func checkInstalledSoftware() []CheckResult {
	// Check number of entries in Program Files
	var count int
	for _, dir := range []string{
		os.Getenv("ProgramFiles"),
		os.Getenv("ProgramFiles(x86)"),
	} {
		if dir == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err == nil {
			count += len(entries)
		}
	}

	if count < 10 {
		return []CheckResult{{
			Category:    "Software",
			Check:       "Installed software",
			Status:      "FAIL",
			Detail:      fmt.Sprintf("Only %d programs in Program Files (< 10 = sparse)", count),
			Remediation: "Install common software: Office, Chrome, Adobe Reader, 7-Zip, etc.",
		}}
	} else if count < 20 {
		return []CheckResult{{
			Category:    "Software",
			Check:       "Installed software",
			Status:      "WARN",
			Detail:      fmt.Sprintf("%d programs in Program Files (somewhat sparse)", count),
			Remediation: "Install more common software for a realistic profile",
		}}
	}

	return []CheckResult{{
		Category: "Software",
		Check:    "Installed software",
		Status:   "PASS",
		Detail:   fmt.Sprintf("%d programs in Program Files", count),
	}}
}

func checkNetworkAdapters() []CheckResult {
	var results []CheckResult

	interfaces, err := net.Interfaces()
	if err != nil {
		return []CheckResult{{
			Category: "Network",
			Check:    "Network adapters",
			Status:   "WARN",
			Detail:   "Failed to enumerate network interfaces",
		}}
	}

	var activeAdapters []string
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		activeAdapters = append(activeAdapters, iface.Name)

		// Check MAC prefix for VMware
		mac := iface.HardwareAddr.String()
		if strings.HasPrefix(mac, "00:0c:29") || strings.HasPrefix(mac, "00:50:56") {
			results = append(results, CheckResult{
				Category:    "Network",
				Check:       "VMware MAC address",
				Status:      "WARN",
				Detail:      fmt.Sprintf("Interface '%s' has VMware MAC: %s", iface.Name, mac),
				Remediation: "Change MAC address in VMX: ethernet0.address = \"XX:XX:XX:XX:XX:XX\"",
			})
		}
	}

	// Check external connectivity
	conn, err := net.DialTimeout("tcp", "8.8.8.8:53", 3*time.Second)
	if err == nil {
		conn.Close()
		results = append(results, CheckResult{
			Category:    "Network",
			Check:       "External connectivity",
			Status:      "WARN",
			Detail:      "External network access is available (NAT/Bridged detected)",
			Remediation: "Use Host-Only mode for malware analysis. NAT/Bridged allows C2 communication",
		})
	} else {
		results = append(results, CheckResult{
			Category: "Network",
			Check:    "External connectivity",
			Status:   "PASS",
			Detail:   "No external network access (Host-Only or Disconnected)",
		})
	}

	// Adapter count
	if len(activeAdapters) > 0 {
		results = append(results, CheckResult{
			Category: "Network",
			Check:    "Active adapters",
			Status:   "PASS",
			Detail:   fmt.Sprintf("%d active adapter(s): %s", len(activeAdapters), strings.Join(activeAdapters, ", ")),
		})
	}

	return results
}

func checkBIOSStrings() []CheckResult {
	// GetSystemFirmwareTable('RSMB', 0) to read SMBIOS data
	procGetSystemFirmwareTable := kernel32.NewProc("GetSystemFirmwareTable")

	// RSMB signature = 0x52534D42
	var rsmb uint32 = 0x52534D42

	// First call: get required buffer size
	size, _, _ := procGetSystemFirmwareTable.Call(
		uintptr(rsmb), 0, 0, 0,
	)
	if size == 0 {
		return []CheckResult{{
			Category: "Firmware",
			Check:    "BIOS/SMBIOS strings",
			Status:   "WARN",
			Detail:   "Failed to query SMBIOS firmware table size",
		}}
	}

	buf := make([]byte, size)
	ret, _, _ := procGetSystemFirmwareTable.Call(
		uintptr(rsmb), 0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
	)
	if ret == 0 {
		return []CheckResult{{
			Category: "Firmware",
			Check:    "BIOS/SMBIOS strings",
			Status:   "WARN",
			Detail:   "Failed to read SMBIOS firmware table",
		}}
	}

	// Extract printable ASCII strings from SMBIOS data and check for VM indicators
	vmIndicators := []string{
		"vmware", "virtualbox", "vbox", "qemu",
		"virtual machine", "kvm", "xen", "hyper-v",
		"parallels", "bhyve",
	}

	smbiosStr := strings.ToLower(string(buf))
	var found []string
	for _, indicator := range vmIndicators {
		if strings.Contains(smbiosStr, indicator) {
			found = append(found, indicator)
		}
	}

	if len(found) > 0 {
		return []CheckResult{{
			Category:    "Firmware",
			Check:       "BIOS/SMBIOS strings",
			Status:      "FAIL",
			Detail:      fmt.Sprintf("VM indicators in SMBIOS: %s", strings.Join(found, ", ")),
			Remediation: "Modify VMX BIOS settings: smbios.reflectHost = TRUE, board-id.reflectHost = TRUE",
		}}
	}

	return []CheckResult{{
		Category: "Firmware",
		Check:    "BIOS/SMBIOS strings",
		Status:   "PASS",
		Detail:   "No VM indicators found in SMBIOS data",
	}}
}
