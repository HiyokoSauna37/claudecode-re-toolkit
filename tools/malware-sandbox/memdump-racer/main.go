// memdump-racer: Memory dump racer for VMProtect unpacking
//
// Launches a target process via CreateProcessW (avoiding PID misidentification),
// waits a configurable delay, then dumps memory using pe-sieve64.exe and
// optionally MiniDumpWriteDump. Repeats with multiple delays to catch the
// unpacking window (~300ms for VMProtect).
//
// Build: GOOS=windows GOARCH=amd64 go build -o memdump-racer.exe .
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32          = windows.NewLazySystemDLL("kernel32.dll")
	dbghelp           = windows.NewLazySystemDLL("dbghelp.dll")
	procCreateProcess = kernel32.NewProc("CreateProcessW")
	procMiniDumpWrite = dbghelp.NewProc("MiniDumpWriteDump")
)

// MiniDumpWithFullMemory = 0x00000002
const MiniDumpWithFullMemory = 2

func main() {
	target := flag.String("target", "", "Path to target executable (required)")
	outdir := flag.String("outdir", "", "Output directory (default: .\\memdump_output)")
	delays := flag.String("delays", "0,100,200,300,500", "Comma-separated delay in ms")
	pesieve := flag.String("pesieve", "", "Path to pe-sieve64.exe (auto-detect in same dir or tools\\)")
	minidump := flag.Bool("minidump", true, "Also create MiniDump via dbghelp")
	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "Usage: memdump-racer.exe --target <path> [--outdir <dir>] [--delays <csv>] [--pesieve <path>] [--minidump]")
		os.Exit(1)
	}

	if *outdir == "" {
		*outdir = ".\\memdump_output"
	}
	os.MkdirAll(*outdir, 0o755)

	// Setup log file
	logPath := filepath.Join(*outdir, "log.txt")
	logFile, err := os.Create(logPath)
	if err != nil {
		log.Fatalf("Failed to create log file: %v", err)
	}
	defer logFile.Close()
	logger := log.New(logFile, "", log.LstdFlags)
	logger.Printf("memdump-racer started")
	logger.Printf("target: %s", *target)
	logger.Printf("outdir: %s", *outdir)
	logger.Printf("delays: %s", *delays)

	// Find pe-sieve64.exe
	pesievePath := findPeSieve(*pesieve)
	if pesievePath == "" {
		logger.Printf("WARNING: pe-sieve64.exe not found, skipping pe-sieve scans")
		fmt.Fprintln(os.Stderr, "WARNING: pe-sieve64.exe not found")
	} else {
		logger.Printf("pe-sieve64.exe: %s", pesievePath)
	}

	// Parse delays
	delayList := parseDelays(*delays)
	logger.Printf("delay list: %v ms", delayList)

	for i, delayMs := range delayList {
		roundDir := filepath.Join(*outdir, fmt.Sprintf("round_%d_%dms", i, delayMs))
		os.MkdirAll(roundDir, 0o755)

		logger.Printf("=== Round %d: delay=%dms ===", i, delayMs)
		fmt.Printf("[Round %d] delay=%dms\n", i, delayMs)

		// Create process (suspended is not needed; we want it to run and unpack)
		pid, hProcess, err := createProcess(*target)
		if err != nil {
			logger.Printf("CreateProcess failed: %v", err)
			fmt.Fprintf(os.Stderr, "  CreateProcess failed: %v\n", err)
			continue
		}
		logger.Printf("Process created: PID=%d", pid)
		fmt.Printf("  PID=%d\n", pid)

		// Wait for the unpacking window
		if delayMs > 0 {
			time.Sleep(time.Duration(delayMs) * time.Millisecond)
		}

		// MiniDump
		if *minidump {
			dumpPath := filepath.Join(roundDir, fmt.Sprintf("pid_%d.dmp", pid))
			if err := writeMiniDump(hProcess, pid, dumpPath); err != nil {
				logger.Printf("MiniDump failed: %v", err)
				fmt.Fprintf(os.Stderr, "  MiniDump failed: %v\n", err)
			} else {
				info, _ := os.Stat(dumpPath)
				logger.Printf("MiniDump: %s (%d bytes)", dumpPath, info.Size())
				fmt.Printf("  MiniDump: %s (%d bytes)\n", dumpPath, info.Size())
			}
		}

		// pe-sieve64
		if pesievePath != "" {
			runPeSieve(pesievePath, pid, roundDir, logger)
		}

		// Terminate the process
		if err := windows.TerminateProcess(hProcess, 1); err != nil {
			logger.Printf("TerminateProcess failed (may have already exited): %v", err)
		}
		windows.CloseHandle(hProcess)

		logger.Printf("Round %d complete", i)
		fmt.Printf("  Round %d complete\n", i)

		// Small gap between rounds for process cleanup
		time.Sleep(500 * time.Millisecond)
	}

	logger.Printf("All rounds complete")

	// Evaluate best round and write quality.txt / manifest.txt
	bestQuality, manifest := evaluateResults(*outdir, logger)
	writeQualityFile(filepath.Join(*outdir, "quality.txt"), bestQuality)
	writeManifestFile(filepath.Join(*outdir, "manifest.txt"), manifest)

	logger.Printf("Quality: %s (%d files in manifest)", bestQuality, len(manifest))
	fmt.Printf("\nDone. Results in: %s\n", *outdir)
	fmt.Printf("Quality: %s\n", bestQuality)
	fmt.Printf("Log: %s\n", logPath)
}

func createProcess(exePath string) (uint32, windows.Handle, error) {
	exePathW, err := windows.UTF16PtrFromString(exePath)
	if err != nil {
		return 0, 0, fmt.Errorf("UTF16PtrFromString: %w", err)
	}

	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation

	r1, _, lastErr := procCreateProcess.Call(
		uintptr(unsafe.Pointer(exePathW)), // lpApplicationName
		0,                                  // lpCommandLine
		0,                                  // lpProcessAttributes
		0,                                  // lpThreadAttributes
		0,                                  // bInheritHandles
		0,                                  // dwCreationFlags (normal start, not suspended)
		0,                                  // lpEnvironment
		0,                                  // lpCurrentDirectory
		uintptr(unsafe.Pointer(&si)),       // lpStartupInfo
		uintptr(unsafe.Pointer(&pi)),       // lpProcessInformation
	)
	if r1 == 0 {
		return 0, 0, fmt.Errorf("CreateProcessW: %w", lastErr)
	}

	// Close thread handle (we only need process handle)
	windows.CloseHandle(windows.Handle(pi.Thread))

	return pi.ProcessId, windows.Handle(pi.Process), nil
}

func writeMiniDump(hProcess windows.Handle, pid uint32, outPath string) error {
	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer f.Close()

	r1, _, lastErr := procMiniDumpWrite.Call(
		uintptr(hProcess),
		uintptr(pid),
		uintptr(f.Fd()),
		MiniDumpWithFullMemory, // dumpType
		0,                      // exceptionParam
		0,                      // userStreamParam
		0,                      // callbackParam
	)
	if r1 == 0 {
		return fmt.Errorf("MiniDumpWriteDump: %w", lastErr)
	}
	return nil
}

func runPeSieve(pesievePath string, pid uint32, outDir string, logger *log.Logger) {
	args := []string{
		fmt.Sprintf("/pid %d", pid),
		"/dmode 3",
		"/imp 3",
		"/shellc 3",
		fmt.Sprintf("/dir %s", outDir),
	}
	cmdStr := fmt.Sprintf("%s %s", pesievePath, strings.Join(args, " "))
	logger.Printf("Running: %s", cmdStr)
	fmt.Printf("  pe-sieve: PID=%d\n", pid)

	cmd := exec.Command(pesievePath,
		fmt.Sprintf("/pid"), fmt.Sprintf("%d", pid),
		"/dmode", "3",
		"/imp", "3",
		"/shellc", "3",
		"/dir", outDir,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Printf("pe-sieve error: %v", err)
		logger.Printf("pe-sieve output: %s", string(output))
		fmt.Fprintf(os.Stderr, "  pe-sieve error: %v\n", err)
	} else {
		logger.Printf("pe-sieve output: %s", string(output))
	}

	// Save pe-sieve output
	outFile := filepath.Join(outDir, "pe_sieve_output.txt")
	os.WriteFile(outFile, output, 0o644)
}

func findPeSieve(explicit string) string {
	if explicit != "" {
		if _, err := os.Stat(explicit); err == nil {
			return explicit
		}
		return ""
	}

	// Check common locations
	candidates := []string{
		"pe-sieve64.exe",
		".\\pe-sieve64.exe",
		"..\\pe-sieve64.exe",
		"tools\\pe-sieve64.exe",
		"..\\tools\\pe-sieve64.exe",
	}

	// Also check next to this executable
	exePath, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exePath)
		candidates = append(candidates, filepath.Join(exeDir, "pe-sieve64.exe"))
	}

	for _, c := range candidates {
		if abs, err := filepath.Abs(c); err == nil {
			if _, err := os.Stat(abs); err == nil {
				return abs
			}
		}
	}
	return ""
}

// evaluateResults scans all round directories for dumped PEs and counts imports.
// Returns the best quality rating and a list of all dumped file paths.
func evaluateResults(outdir string, logger *log.Logger) (string, []string) {
	var manifest []string
	bestImports := 0

	entries, err := os.ReadDir(outdir)
	if err != nil {
		logger.Printf("Failed to read outdir: %v", err)
		return "POOR", nil
	}

	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "round_") {
			continue
		}
		roundDir := filepath.Join(outdir, entry.Name())
		imports := countImportsFromPeSieveOutput(filepath.Join(roundDir, "pe_sieve_output.txt"), logger)
		if imports > bestImports {
			bestImports = imports
		}
		// Collect all dumped PE files (from pe-sieve subdirectories and .dmp files)
		collectDumpedFiles(roundDir, &manifest)
	}

	quality := "POOR"
	if bestImports > 5 {
		quality = "GOOD"
	}
	return quality, manifest
}

// countImportsFromPeSieveOutput parses pe-sieve output text for import count.
// pe-sieve reports "reconstructed_imports" or similar in its JSON/text output.
func countImportsFromPeSieveOutput(outputPath string, logger *log.Logger) int {
	data, err := os.ReadFile(outputPath)
	if err != nil {
		return 0
	}
	text := string(data)

	// pe-sieve text output contains lines like:
	//   "patched:  1"
	//   "replaced: 1"
	//   "total_suspicious: 2"
	// Look for replaced/implanted modules as indicator of successful dump.
	// Also scan for dumped PE subdirectories and count their import tables.

	// Check for "replaced" count > 0 as sign of successful unpack
	replaced := extractPeSieveField(text, "replaced")
	implanted := extractPeSieveField(text, "implanted")
	total := replaced + implanted

	logger.Printf("pe-sieve output [%s]: replaced=%d, implanted=%d", outputPath, replaced, implanted)

	if total == 0 {
		return 0
	}

	// Count imports in dumped PE files within the pe-sieve output directory
	// pe-sieve creates <PID>/ subdirectory with dumped modules
	dir := filepath.Dir(outputPath)
	maxImports := countImportsInDir(dir, logger)
	return maxImports
}

// extractPeSieveField extracts a numeric field from pe-sieve text output.
func extractPeSieveField(text, field string) int {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, field) {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				val := strings.TrimSpace(parts[len(parts)-1])
				if n, err := strconv.Atoi(val); err == nil {
					return n
				}
			}
		}
	}
	return 0
}

// countImportsInDir scans for PE files and counts import directory entries.
// Uses a simple PE header parse to count IMAGE_IMPORT_DESCRIPTOR entries.
func countImportsInDir(dir string, logger *log.Logger) int {
	maxImports := 0
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		// Check dumped PE files (pe-sieve names them like: <addr>.<name>.dll/.exe)
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".exe" && ext != ".dll" && ext != ".drv" && ext != ".sys" {
			// Also check files without standard extension but with pe-sieve naming
			if info.Size() < 512 {
				return nil
			}
		}
		n := countPEImports(path)
		if n > maxImports {
			maxImports = n
			logger.Printf("PE imports: %d in %s", n, path)
		}
		return nil
	})
	return maxImports
}

// countPEImports does a minimal PE parse to count import directory entries.
func countPEImports(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	// Read MZ header
	var mz [2]byte
	if _, err := f.Read(mz[:]); err != nil || mz[0] != 'M' || mz[1] != 'Z' {
		return 0
	}

	// Read e_lfanew at offset 0x3C
	buf := make([]byte, 4)
	if _, err := f.ReadAt(buf, 0x3C); err != nil {
		return 0
	}
	lfanew := int64(buf[0]) | int64(buf[1])<<8 | int64(buf[2])<<16 | int64(buf[3])<<24

	// Read PE signature
	peSig := make([]byte, 4)
	if _, err := f.ReadAt(peSig, lfanew); err != nil {
		return 0
	}
	if peSig[0] != 'P' || peSig[1] != 'E' || peSig[2] != 0 || peSig[3] != 0 {
		return 0
	}

	// COFF header at lfanew+4
	coffOff := lfanew + 4
	coffBuf := make([]byte, 20)
	if _, err := f.ReadAt(coffBuf, coffOff); err != nil {
		return 0
	}
	sizeOfOptional := int(coffBuf[16]) | int(coffBuf[17])<<8

	// Optional header starts at coffOff + 20
	optOff := coffOff + 20
	optBuf := make([]byte, 2)
	if _, err := f.ReadAt(optBuf, optOff); err != nil {
		return 0
	}
	magic := int(optBuf[0]) | int(optBuf[1])<<8

	var importDirRVA uint32
	var importDirSize uint32
	switch magic {
	case 0x10b: // PE32
		if sizeOfOptional < 104 {
			return 0
		}
		idBuf := make([]byte, 8)
		if _, err := f.ReadAt(idBuf, optOff+96+8); err != nil { // import table is data dir entry 1 (offset 96+8)
			return 0
		}
		importDirRVA = uint32(idBuf[0]) | uint32(idBuf[1])<<8 | uint32(idBuf[2])<<16 | uint32(idBuf[3])<<24
		importDirSize = uint32(idBuf[4]) | uint32(idBuf[5])<<8 | uint32(idBuf[6])<<16 | uint32(idBuf[7])<<24
	case 0x20b: // PE32+
		if sizeOfOptional < 120 {
			return 0
		}
		idBuf := make([]byte, 8)
		if _, err := f.ReadAt(idBuf, optOff+112+8); err != nil { // import table for PE32+ at offset 112+8
			return 0
		}
		importDirRVA = uint32(idBuf[0]) | uint32(idBuf[1])<<8 | uint32(idBuf[2])<<16 | uint32(idBuf[3])<<24
		importDirSize = uint32(idBuf[4]) | uint32(idBuf[5])<<8 | uint32(idBuf[6])<<16 | uint32(idBuf[7])<<24
	default:
		return 0
	}

	if importDirRVA == 0 || importDirSize == 0 {
		return 0
	}

	// Each IMAGE_IMPORT_DESCRIPTOR is 20 bytes; last one is null terminator
	count := int(importDirSize) / 20
	if count > 0 {
		count-- // subtract null terminator
	}
	if count < 0 {
		count = 0
	}
	return count
}

// collectDumpedFiles adds all PE/dump files found in a round directory to manifest.
func collectDumpedFiles(roundDir string, manifest *[]string) {
	filepath.Walk(roundDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".exe" || ext == ".dll" || ext == ".dmp" || ext == ".drv" || ext == ".sys" {
			abs, _ := filepath.Abs(path)
			*manifest = append(*manifest, abs)
		}
		return nil
	})
}

func writeQualityFile(path, quality string) {
	os.WriteFile(path, []byte(quality+"\n"), 0o644)
}

func writeManifestFile(path string, files []string) {
	content := strings.Join(files, "\n")
	if content != "" {
		content += "\n"
	}
	os.WriteFile(path, []byte(content), 0o644)
}

func parseDelays(csv string) []int {
	parts := strings.Split(csv, ",")
	var result []int
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if v, err := strconv.Atoi(p); err == nil {
			result = append(result, v)
		}
	}
	if len(result) == 0 {
		result = []int{0, 100, 200, 300, 500}
	}
	return result
}
