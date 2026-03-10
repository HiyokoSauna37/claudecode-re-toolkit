// tiny-unpack: TinyTracer-based automatic unpacker
//
// Automates the 2-pass TinyTracer workflow:
//   Pass 1: Trace execution with TinyTracer to detect OEP (section transition)
//   Pass 2: Re-run with stop_offsets.txt to pause at OEP, then dump with HollowsHunter
//
// Build: GOOS=windows GOARCH=amd64 go build -o tiny-unpack.exe .
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func main() {
	target := flag.String("target", "", "Path to target packed executable (required)")
	outdir := flag.String("outdir", "", "Output directory (default: .\\tiny_unpack_output)")
	pinDir := flag.String("pin-dir", "C:\\pin", "Intel PIN installation directory")
	hhPath := flag.String("hh", "", "Path to hollows_hunter64.exe (auto-detect)")
	stopTime := flag.Int("stop-time", 60, "Seconds to wait at OEP for dumping")
	skipPass1 := flag.Bool("skip-pass1", false, "Skip Pass 1 (use existing stop_offsets.txt)")
	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "Usage: tiny-unpack.exe --target <path> [--outdir <dir>] [--pin-dir <path>] [--hh <path>] [--stop-time <sec>] [--skip-pass1]")
		os.Exit(1)
	}

	if *outdir == "" {
		*outdir = ".\\tiny_unpack_output"
	}
	os.MkdirAll(*outdir, 0o755)

	// Setup logging
	logPath := filepath.Join(*outdir, "log.txt")
	logFile, err := os.Create(logPath)
	if err != nil {
		log.Fatalf("Failed to create log file: %v", err)
	}
	defer logFile.Close()
	// Log to both file and stdout
	multiW := io.MultiWriter(logFile, os.Stdout)
	logger := log.New(multiW, "", log.LstdFlags)

	logger.Printf("tiny-unpack started")
	logger.Printf("target: %s", *target)
	logger.Printf("outdir: %s", *outdir)
	logger.Printf("pin-dir: %s", *pinDir)
	logger.Printf("stop-time: %ds", *stopTime)

	// Verify target exists
	if _, err := os.Stat(*target); err != nil {
		logger.Fatalf("Target not found: %s", *target)
	}

	// Find pin.exe
	pinExe := filepath.Join(*pinDir, "pin.exe")
	if _, err := os.Stat(pinExe); err != nil {
		logger.Fatalf("pin.exe not found at %s. Install Intel PIN first.", pinExe)
	}
	logger.Printf("pin.exe: %s", pinExe)

	// Find TinyTracer DLL
	ttDll := findTinyTracerDLL(*pinDir)
	if ttDll == "" {
		logger.Fatalf("TinyTracer64.dll not found. Install TinyTracer first.")
	}
	logger.Printf("TinyTracer DLL: %s", ttDll)

	// Find hollows_hunter64.exe
	hhExePath := findHollowsHunter(*hhPath)
	if hhExePath == "" {
		logger.Fatalf("hollows_hunter64.exe not found. Provide --hh path or place it in tools\\")
	}
	logger.Printf("hollows_hunter64.exe: %s", hhExePath)

	// Working directory for TinyTracer (same as target for .tag output)
	targetDir := filepath.Dir(*target)
	targetBase := filepath.Base(*target)
	tagFile := filepath.Join(targetDir, strings.TrimSuffix(targetBase, filepath.Ext(targetBase))+".tag")

	// ============================================================
	// Pass 1: Trace to detect OEP
	// ============================================================
	var oepRVA string

	if *skipPass1 {
		logger.Printf("=== Pass 1: SKIPPED (--skip-pass1) ===")
		// Read existing stop_offsets.txt
		stopOffsetsPath := filepath.Join(filepath.Dir(ttDll), "stop_offsets.txt")
		data, err := os.ReadFile(stopOffsetsPath)
		if err != nil {
			logger.Fatalf("Cannot read existing stop_offsets.txt: %v", err)
		}
		oepRVA = strings.TrimSpace(string(data))
		logger.Printf("Using existing OEP RVA from stop_offsets.txt: %s", oepRVA)
	} else {
		logger.Printf("=== Pass 1: Tracing with TinyTracer ===")

		// Clear previous stop_offsets.txt
		stopOffsetsPath := filepath.Join(filepath.Dir(ttDll), "stop_offsets.txt")
		os.WriteFile(stopOffsetsPath, []byte(""), 0o644)

		// Remove previous .tag file
		os.Remove(tagFile)

		// Run: pin.exe -t TinyTracer64.dll -- <target>
		pass1Args := []string{"-t", ttDll, "--", *target}
		logger.Printf("Running: %s %s", pinExe, strings.Join(pass1Args, " "))

		cmd := exec.Command(pinExe, pass1Args...)
		cmd.Dir = targetDir
		output, err := cmd.CombinedOutput()
		if err != nil {
			logger.Printf("Pass 1 exited with error (may be normal for packed malware): %v", err)
		}
		logger.Printf("Pass 1 output:\n%s", string(output))

		// Parse .tag file for OEP
		oepRVA = parseTagFileForOEP(tagFile, logger)
		if oepRVA == "" {
			logger.Printf("ERROR: Could not detect OEP from .tag file")
			writeQualityFile(filepath.Join(*outdir, "quality.txt"), "POOR")
			writeManifestFile(filepath.Join(*outdir, "manifest.txt"), nil)
			logger.Printf("Pass 1 failed: no OEP detected. Try manual analysis (Level 3).")
			fmt.Println("FAILED: No OEP detected. Consider Level 3 (manual x64dbg).")
			os.Exit(1)
		}
		logger.Printf("Detected OEP RVA: 0x%s", oepRVA)

		// Write stop_offsets.txt for Pass 2
		os.WriteFile(stopOffsetsPath, []byte(oepRVA+"\n"), 0o644)
		logger.Printf("Wrote stop_offsets.txt: %s", stopOffsetsPath)
	}

	// ============================================================
	// Pass 2: Re-run with stop at OEP, then dump
	// ============================================================
	logger.Printf("=== Pass 2: Run with OEP stop + HollowsHunter dump ===")

	// Start target via TinyTracer (it will stop at OEP)
	pass2Args := []string{"-t", ttDll, "--", *target}
	logger.Printf("Running Pass 2: %s %s", pinExe, strings.Join(pass2Args, " "))

	pass2Cmd := exec.Command(pinExe, pass2Args...)
	pass2Cmd.Dir = targetDir
	pass2Cmd.Stdout = logFile
	pass2Cmd.Stderr = logFile

	if err := pass2Cmd.Start(); err != nil {
		logger.Fatalf("Pass 2 failed to start: %v", err)
	}
	pass2PID := pass2Cmd.Process.Pid
	logger.Printf("Pass 2 started: PID=%d (pin.exe wrapper)", pass2PID)

	// Wait for the process to reach OEP and stop
	// TinyTracer will pause execution at the stop_offsets address
	logger.Printf("Waiting 5s for process to reach OEP...")
	time.Sleep(5 * time.Second)

	// Find the actual target process name for HollowsHunter
	targetName := filepath.Base(*target)
	logger.Printf("Running HollowsHunter for process: %s", targetName)

	// Run HollowsHunter to dump
	hhOutDir := filepath.Join(*outdir, "hh_dump")
	os.MkdirAll(hhOutDir, 0o755)

	hhArgs := []string{
		"/pname", targetName,
		"/hooks",
		"/imp", "A",
		"/dir", hhOutDir,
	}
	logger.Printf("Running: %s %s", hhExePath, strings.Join(hhArgs, " "))

	hhCmd := exec.Command(hhExePath, hhArgs...)
	hhOutput, err := hhCmd.CombinedOutput()
	if err != nil {
		logger.Printf("HollowsHunter error (trying /pid fallback): %v", err)
		logger.Printf("HollowsHunter output: %s", string(hhOutput))

		// Fallback: try with /pid using pin.exe's PID tree
		// The actual target runs as a child of pin.exe
		hhArgs2 := []string{
			"/pid", fmt.Sprintf("%d", pass2PID),
			"/hooks",
			"/imp", "A",
			"/dir", hhOutDir,
		}
		logger.Printf("Fallback: %s %s", hhExePath, strings.Join(hhArgs2, " "))
		hhCmd2 := exec.Command(hhExePath, hhArgs2...)
		hhOutput2, err2 := hhCmd2.CombinedOutput()
		if err2 != nil {
			logger.Printf("HollowsHunter fallback also failed: %v", err2)
		}
		logger.Printf("HollowsHunter fallback output: %s", string(hhOutput2))
	} else {
		logger.Printf("HollowsHunter output: %s", string(hhOutput))
	}

	// Wait remaining stop-time then kill the process
	remainingWait := *stopTime - 5
	if remainingWait > 0 {
		logger.Printf("Waiting %ds for additional dump operations...", remainingWait)
		time.Sleep(time.Duration(remainingWait) * time.Second)
	}

	// Kill pin.exe process tree
	logger.Printf("Terminating pin.exe process tree...")
	killCmd := exec.Command("taskkill", "/F", "/T", "/PID", fmt.Sprintf("%d", pass2PID))
	killCmd.CombinedOutput()

	// ============================================================
	// Evaluate results
	// ============================================================
	logger.Printf("=== Evaluating dump results ===")

	manifest := collectDumpedFiles(hhOutDir)
	bestImports := 0
	for _, f := range manifest {
		n := countPEImports(f)
		if n > 0 {
			logger.Printf("  %s: %d imports", filepath.Base(f), n)
		}
		if n > bestImports {
			bestImports = n
		}
	}

	quality := "POOR"
	if bestImports > 5 {
		quality = "GOOD"
	}

	writeQualityFile(filepath.Join(*outdir, "quality.txt"), quality)
	writeManifestFile(filepath.Join(*outdir, "manifest.txt"), manifest)

	logger.Printf("Quality: %s (best imports: %d, files: %d)", quality, bestImports, len(manifest))
	fmt.Printf("\nDone. Results in: %s\n", *outdir)
	fmt.Printf("Quality: %s\n", quality)
	fmt.Printf("Log: %s\n", logPath)
}

// parseTagFileForOEP parses a TinyTracer .tag file to detect OEP via section transitions.
//
// .tag file format examples:
//   44c43b;[1111] -> [0000]       section transition (OEP candidate)
//   1d14b0;section: [0000]        first instruction in section
//   12345;kernel32.LoadLibraryA   API call
//
// OEP is detected by finding "[XXXX] -> [0000]" pattern (transition back to code section).
func parseTagFileForOEP(tagFile string, logger *log.Logger) string {
	f, err := os.Open(tagFile)
	if err != nil {
		logger.Printf("Cannot open .tag file: %v", err)
		return ""
	}
	defer f.Close()

	var oepCandidates []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Look for section transition pattern: RVA;[XXXX] -> [0000]
		// This indicates a jump from a packed section back to the original code section
		if strings.Contains(line, "-> [0000]") {
			parts := strings.SplitN(line, ";", 2)
			if len(parts) >= 1 {
				rva := strings.TrimSpace(parts[0])
				// Validate it looks like a hex address
				if _, err := strconv.ParseUint(rva, 16, 64); err == nil {
					logger.Printf("OEP candidate: 0x%s (from: %s)", rva, line)
					oepCandidates = append(oepCandidates, rva)
				}
			}
		}
	}

	if len(oepCandidates) == 0 {
		// Fallback: look for "section: [0000]" as first code section entry
		f.Seek(0, 0)
		scanner = bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.Contains(line, "section: [0000]") {
				parts := strings.SplitN(line, ";", 2)
				if len(parts) >= 1 {
					rva := strings.TrimSpace(parts[0])
					if _, err := strconv.ParseUint(rva, 16, 64); err == nil {
						logger.Printf("OEP candidate (section entry): 0x%s (from: %s)", rva, line)
						oepCandidates = append(oepCandidates, rva)
					}
				}
			}
		}
	}

	if len(oepCandidates) == 0 {
		return ""
	}

	// Return the last transition to [0000] as it's most likely the real OEP
	// (earlier transitions may be during unpacking stub initialization)
	return oepCandidates[len(oepCandidates)-1]
}

// findTinyTracerDLL looks for TinyTracer64.dll in common locations.
func findTinyTracerDLL(pinDir string) string {
	candidates := []string{
		filepath.Join(pinDir, "source", "tools", "TinyTracer", "install", "TinyTracer64.dll"),
		filepath.Join(pinDir, "TinyTracer64.dll"),
		"TinyTracer64.dll",
		".\\TinyTracer64.dll",
	}

	// Also check next to this executable
	exePath, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exePath)
		candidates = append(candidates, filepath.Join(exeDir, "TinyTracer64.dll"))
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

// findHollowsHunter looks for hollows_hunter64.exe in common locations.
func findHollowsHunter(explicit string) string {
	if explicit != "" {
		if _, err := os.Stat(explicit); err == nil {
			return explicit
		}
		return ""
	}

	candidates := []string{
		"hollows_hunter64.exe",
		".\\hollows_hunter64.exe",
		"..\\hollows_hunter64.exe",
		"tools\\hollows_hunter64.exe",
		"..\\tools\\hollows_hunter64.exe",
	}

	exePath, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exePath)
		candidates = append(candidates, filepath.Join(exeDir, "hollows_hunter64.exe"))
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

// collectDumpedFiles finds all PE/dump files in a directory tree.
func collectDumpedFiles(dir string) []string {
	var files []string
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".exe" || ext == ".dll" || ext == ".dmp" || ext == ".drv" || ext == ".sys" {
			abs, _ := filepath.Abs(path)
			files = append(files, abs)
			return nil
		}
		// Also pick up pe-sieve/hh output files without standard extensions
		if info.Size() >= 512 {
			if n := countPEImports(path); n > 0 {
				abs, _ := filepath.Abs(path)
				files = append(files, abs)
			}
		}
		return nil
	})
	return files
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

	// Optional header
	optOff := coffOff + 20
	optBuf := make([]byte, 2)
	if _, err := f.ReadAt(optBuf, optOff); err != nil {
		return 0
	}
	magic := int(optBuf[0]) | int(optBuf[1])<<8

	var importDirSize uint32
	switch magic {
	case 0x10b: // PE32
		if sizeOfOptional < 104 {
			return 0
		}
		idBuf := make([]byte, 8)
		if _, err := f.ReadAt(idBuf, optOff+96+8); err != nil {
			return 0
		}
		importDirSize = uint32(idBuf[4]) | uint32(idBuf[5])<<8 | uint32(idBuf[6])<<16 | uint32(idBuf[7])<<24
	case 0x20b: // PE32+
		if sizeOfOptional < 120 {
			return 0
		}
		idBuf := make([]byte, 8)
		if _, err := f.ReadAt(idBuf, optOff+112+8); err != nil {
			return 0
		}
		importDirSize = uint32(idBuf[4]) | uint32(idBuf[5])<<8 | uint32(idBuf[6])<<16 | uint32(idBuf[7])<<24
	default:
		return 0
	}

	if importDirSize == 0 {
		return 0
	}

	count := int(importDirSize) / 20
	if count > 0 {
		count--
	}
	if count < 0 {
		count = 0
	}
	return count
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
