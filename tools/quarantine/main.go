package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
)

type Download struct {
	Filename      string `json:"filename"`
	Size          int64  `json:"size"`
	MD5           string `json:"md5"`
	SHA1          string `json:"sha1"`
	SHA256        string `json:"sha256"`
	EncryptedFile string `json:"encrypted_file"`
	VTDetection   string `json:"vt_detection"`
	VTLink        string `json:"vt_link"`
}

type Metadata struct {
	URL        string     `json:"url"`
	Domain     string     `json:"domain"`
	Timestamp  string     `json:"timestamp"`
	Downloads  []Download `json:"downloads"`
	Screenshot string     `json:"screenshot"`
	HTML       string     `json:"html"`
}

type QuarantineEntry struct {
	Path     string
	Domain   string
	Time     string
	Metadata *Metadata
	EncFiles []string
}

func findQuarantineDir() string {
	exe, _ := os.Executable()
	repoRoot := filepath.Dir(filepath.Dir(filepath.Dir(exe)))

	candidates := []string{
		filepath.Join(repoRoot, "Tools", "proxy-web", "Quarantine"),
		filepath.Join("Tools", "proxy-web", "Quarantine"),
	}

	cwd, _ := os.Getwd()
	candidates = append(candidates, filepath.Join(cwd, "Tools", "proxy-web", "Quarantine"))

	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	return ""
}

func findGhidraScript() string {
	candidates := []string{
		filepath.Join("Tools", "ghidra-headless", "ghidra.sh"),
	}
	cwd, _ := os.Getwd()
	candidates = append(candidates, filepath.Join(cwd, "Tools", "ghidra-headless", "ghidra.sh"))

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	return ""
}

func loadMetadata(dir string) *Metadata {
	data, err := os.ReadFile(filepath.Join(dir, "metadata.json"))
	if err != nil {
		return nil
	}
	var m Metadata
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	return &m
}

func findEncFiles(dir string) []string {
	var files []string
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".enc.gz") {
			files = append(files, e.Name())
		}
	}
	return files
}

func scanQuarantine(qDir string) []QuarantineEntry {
	var entries []QuarantineEntry

	domains, _ := os.ReadDir(qDir)
	for _, d := range domains {
		if !d.IsDir() {
			continue
		}
		domainPath := filepath.Join(qDir, d.Name())
		timestamps, _ := os.ReadDir(domainPath)
		for _, t := range timestamps {
			if !t.IsDir() {
				continue
			}
			entryPath := filepath.Join(domainPath, t.Name())
			entries = append(entries, QuarantineEntry{
				Path:     entryPath,
				Domain:   d.Name(),
				Time:     t.Name(),
				Metadata: loadMetadata(entryPath),
				EncFiles: findEncFiles(entryPath),
			})
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Time > entries[j].Time
	})

	return entries
}

func cmdList(qDir string) {
	entries := scanQuarantine(qDir)
	if len(entries) == 0 {
		fmt.Println("No quarantine entries found.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "%s#\tDomain\tTimestamp\tFiles\tVT Detection%s\n", colorCyan, colorReset)
	fmt.Fprintf(w, "%s-\t------\t---------\t-----\t------------%s\n", colorGray, colorReset)

	for i, e := range entries {
		vtInfo := "-"
		fileCount := len(e.EncFiles)

		if e.Metadata != nil && len(e.Metadata.Downloads) > 0 {
			dl := e.Metadata.Downloads[0]
			if dl.VTDetection != "" {
				vtInfo = dl.VTDetection
			}
		}

		// Color VT detection
		vtColored := vtInfo
		if vtInfo != "-" && vtInfo != "" {
			vtColored = colorRed + vtInfo + colorReset
		}

		ts := e.Time
		if len(ts) == 15 { // YYYYMMDD_HHMMSS format
			if t, err := time.Parse("20060102_150405", ts); err == nil {
				ts = t.Format("2006-01-02 15:04")
			}
		}

		fmt.Fprintf(w, "%d\t%s\t%s\t%d enc\t%s\n", i+1, e.Domain, ts, fileCount, vtColored)
	}
	w.Flush()
}

func cmdInfo(qDir string, target string) {
	entries := scanQuarantine(qDir)

	// Find matching entry by index or domain substring
	var entry *QuarantineEntry
	for i := range entries {
		idx := fmt.Sprintf("%d", i+1)
		if target == idx || strings.Contains(entries[i].Domain, target) || strings.Contains(entries[i].Path, target) {
			entry = &entries[i]
			break
		}
	}

	if entry == nil {
		fmt.Fprintf(os.Stderr, "Entry not found: %s\n", target)
		os.Exit(1)
	}

	fmt.Printf("%sDomain:%s  %s\n", colorCyan, colorReset, entry.Domain)
	fmt.Printf("%sTime:%s    %s\n", colorCyan, colorReset, entry.Time)
	fmt.Printf("%sPath:%s    %s\n", colorCyan, colorReset, entry.Path)

	if entry.Metadata != nil {
		m := entry.Metadata
		fmt.Printf("%sURL:%s     %s\n", colorCyan, colorReset, m.URL)

		for _, dl := range m.Downloads {
			fmt.Println()
			fmt.Printf("  %sFile:%s      %s\n", colorYellow, colorReset, dl.Filename)
			fmt.Printf("  %sSize:%s      %d bytes\n", colorYellow, colorReset, dl.Size)
			fmt.Printf("  %sMD5:%s       %s\n", colorGray, colorReset, dl.MD5)
			fmt.Printf("  %sSHA1:%s      %s\n", colorGray, colorReset, dl.SHA1)
			fmt.Printf("  %sSHA256:%s    %s\n", colorGray, colorReset, dl.SHA256)
			fmt.Printf("  %sEncrypted:%s %s\n", colorGray, colorReset, dl.EncryptedFile)

			if dl.VTDetection != "" {
				fmt.Printf("  %sVT:%s        %s%s%s\n", colorRed, colorReset, colorRed, dl.VTDetection, colorReset)
			}
			if dl.VTLink != "" {
				fmt.Printf("  %sVT Link:%s   %s\n", colorGray, colorReset, dl.VTLink)
			}
		}
	}

	fmt.Println()
	fmt.Printf("%sEncrypted files:%s\n", colorCyan, colorReset)
	for _, f := range entry.EncFiles {
		fmt.Printf("  - %s\n", f)
	}
}

func cmdCheck() {
	container := "ghidra-headless"

	// Check container status
	out, err := exec.Command("docker", "inspect", "-f", "{{.State.Status}}", container).Output()
	status := strings.TrimSpace(string(out))

	if err != nil || status != "running" {
		fmt.Printf("%s[FAIL]%s Container '%s' is not running (status: %s)\n", colorRed, colorReset, container, status)
		fmt.Println("  Fix: bash Tools/ghidra-headless/ghidra.sh start")
	} else {
		fmt.Printf("%s[OK]%s Container '%s' is running\n", colorGreen, colorReset, container)
	}

	// Check Python3
	if status == "running" {
		pyOut, pyErr := exec.Command("docker", "exec", container, "python3", "--version").Output()
		if pyErr != nil {
			fmt.Printf("%s[FAIL]%s Python3 not available in container\n", colorRed, colorReset)
			fmt.Println("  Fix: Rebuild container (bash Tools/ghidra-headless/ghidra.sh stop && bash Tools/ghidra-headless/ghidra.sh start)")
		} else {
			fmt.Printf("%s[OK]%s %s\n", colorGreen, colorReset, strings.TrimSpace(string(pyOut)))
		}

		// Check cryptography module
		_, cryptErr := exec.Command("docker", "exec", container, "python3", "-c", "from cryptography.hazmat.primitives.ciphers import Cipher").Output()
		if cryptErr != nil {
			fmt.Printf("%s[FAIL]%s cryptography module not available\n", colorRed, colorReset)
		} else {
			fmt.Printf("%s[OK]%s cryptography module available\n", colorGreen, colorReset)
		}

		// Check decrypt script
		_, decErr := exec.Command("docker", "exec", container, "test", "-f", "/opt/ghidra-scripts/decrypt_quarantine.py").Output()
		if decErr != nil {
			fmt.Printf("%s[FAIL]%s decrypt_quarantine.py not found in container\n", colorRed, colorReset)
		} else {
			fmt.Printf("%s[OK]%s decrypt_quarantine.py available\n", colorGreen, colorReset)
		}

		// Check Ghidra
		_, ghErr := exec.Command("docker", "exec", container, "test", "-f", "/opt/ghidra/support/analyzeHeadless").Output()
		if ghErr != nil {
			fmt.Printf("%s[FAIL]%s Ghidra analyzeHeadless not found\n", colorRed, colorReset)
		} else {
			fmt.Printf("%s[OK]%s Ghidra analyzeHeadless available\n", colorGreen, colorReset)
		}
	}
}

func cmdAnalyze(qDir string, target string) {
	entries := scanQuarantine(qDir)

	var entry *QuarantineEntry
	for i := range entries {
		idx := fmt.Sprintf("%d", i+1)
		if target == idx || strings.Contains(entries[i].Domain, target) || strings.Contains(entries[i].Path, target) {
			entry = &entries[i]
			break
		}
	}

	if entry == nil {
		fmt.Fprintf(os.Stderr, "Entry not found: %s\n", target)
		os.Exit(1)
	}

	if len(entry.EncFiles) == 0 {
		fmt.Println("No encrypted files to analyze.")
		return
	}

	ghidra := findGhidraScript()
	if ghidra == "" {
		fmt.Fprintln(os.Stderr, "Error: ghidra.sh not found")
		os.Exit(1)
	}

	for _, encFile := range entry.EncFiles {
		encPath := filepath.Join(entry.Path, encFile)
		fmt.Printf("\n%s=== Analyzing: %s ===%s\n", colorCyan, encFile, colorReset)

		cmd := exec.Command("bash", ghidra, "quarantine-analyze", encPath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "%sError analyzing %s: %v%s\n", colorRed, encFile, err, colorReset)
		}
	}
}

func usage() {
	fmt.Println("Quarantine Manager - proxy-web quarantine file management")
	fmt.Println()
	fmt.Println("Usage: quarantine <command> [args...]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  list                  List all quarantine entries")
	fmt.Println("  info <#|domain>       Show details for an entry")
	fmt.Println("  check                 Verify Ghidra container readiness")
	fmt.Println("  analyze <#|domain>    Decrypt + Ghidra full analysis")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  quarantine list")
	fmt.Println("  quarantine info 1")
	fmt.Println("  quarantine info 39.106")
	fmt.Println("  quarantine check")
	fmt.Println("  quarantine analyze 1")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(0)
	}

	qDir := findQuarantineDir()
	cmd := os.Args[1]

	switch cmd {
	case "list", "ls":
		if qDir == "" {
			fmt.Fprintln(os.Stderr, "Error: Quarantine directory not found")
			os.Exit(1)
		}
		cmdList(qDir)

	case "info", "show":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: quarantine info <#|domain>")
			os.Exit(1)
		}
		if qDir == "" {
			fmt.Fprintln(os.Stderr, "Error: Quarantine directory not found")
			os.Exit(1)
		}
		cmdInfo(qDir, os.Args[2])

	case "check", "health":
		cmdCheck()

	case "analyze":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: quarantine analyze <#|domain>")
			os.Exit(1)
		}
		if qDir == "" {
			fmt.Fprintln(os.Stderr, "Error: Quarantine directory not found")
			os.Exit(1)
		}
		cmdAnalyze(qDir, os.Args[2])

	case "help", "-h", "--help":
		usage()

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		usage()
		os.Exit(1)
	}
}
