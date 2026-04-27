package main

import (
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/HiyokoSauna37/life/tools/proxy-web/orchestrator"
)

var execCommand = exec.Command

func main() {
	// Setup logging
	setupLogging()

	// Load .env: try exe-relative (tools/proxy-web/../../.env), then CWD-relative
	exe, _ := os.Executable()
	exeDir := filepath.Dir(exe)
	_ = orchestrator.LoadEnv(filepath.Join(exeDir, "..", "..", ".env"))

	cwd, _ := os.Getwd()
	if cwd != "" && cwd != filepath.Join(exeDir, "..", "..") {
		_ = orchestrator.LoadEnv(filepath.Join(cwd, ".env"))
	}

	// Parse subcommands
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "help", "-h", "--help":
		printUsage()
		return
	case "probe":
		handleProbe(os.Args[2:])
		return
	case "preflight":
		handlePreflight()
		return
	case "decrypt":
		handleDecrypt(os.Args[2:])
		return
	case "check":
		handleVT("check", os.Args[2:])
		return
	case "behavior":
		handleVT("behavior", os.Args[2:])
		return
	case "lookup":
		handleVT("lookup", os.Args[2:])
		return
	case "vt-ip":
		handleVTIP(os.Args[2:])
		return
	case "list":
		handleList(os.Args[2:])
		return
	case "bazaar":
		handleBazaar(os.Args[2:])
		return
	case "threatfox":
		handleThreatFox(os.Args[2:])
		return
	case "recon":
		handleRecon(os.Args[2:])
		return
	case "c2-profile":
		handleC2Profile(os.Args[2:])
		return
	case "otx":
		handleOTX(os.Args[2:])
		return
	case "classify":
		handleClassify(os.Args[2:])
		return
	case "batch-probe":
		handleBatchProbe(os.Args[2:])
		return
	case "ws":
		handleWS(os.Args[2:])
		return
	case "fetch":
		handleFetch(os.Args[2:])
		return
	}

	// Default: URL analysis mode
	handleAnalyze(os.Args[1:])
}

func handleDecrypt(args []string) {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	output := fs.String("o", "", "Output file path")
	password := fs.String("p", "", "Decryption password")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: proxy-web decrypt <file.enc.gz> [-o output] [-p password]")
		os.Exit(1)
	}

	encFile := fs.Arg(0)
	pw := *password
	if pw == "" {
		pw = os.Getenv("QUARANTINE_PASSWORD")
	}
	if pw == "" {
		fmt.Fprintln(os.Stderr, "Error: Password required (-p or QUARANTINE_PASSWORD env)")
		os.Exit(1)
	}

	if err := orchestrator.DecryptQuarantine(encFile, *output, pw); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func requireVTClient() *orchestrator.VTClient {
	apiKey := os.Getenv("VIRUSTOTAL_API_KEY")
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "Error: VIRUSTOTAL_API_KEY not set")
		os.Exit(1)
	}
	return orchestrator.NewVTClient(apiKey)
}

func handleVT(subcmd string, args []string) {
	jsonOut := false
	var hash string
	for _, arg := range args {
		switch arg {
		case "--json", "-j":
			jsonOut = true
		default:
			if hash == "" {
				hash = arg
			}
		}
	}
	if hash == "" {
		fmt.Fprintf(os.Stderr, "Usage: proxy-web %s <sha256> [--json|-j]\n", subcmd)
		os.Exit(1)
	}

	vt := requireVTClient()

	if jsonOut {
		var b []byte
		var err error
		switch subcmd {
		case "check":
			b, err = vt.CheckJSON(hash)
		case "behavior":
			b, err = vt.BehaviorJSON(hash)
		case "lookup":
			b, err = vt.LookupJSON(hash)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(b))
		return
	}

	switch subcmd {
	case "check":
		vt.CheckPrint(hash)
	case "behavior":
		vt.BehaviorPrint(hash)
	case "lookup":
		vt.LookupPrint(hash)
	}
}

func handleVTIP(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: proxy-web vt-ip <IP>")
		os.Exit(1)
	}
	requireVTClient().IPReportPrint(args[0])
}

func handleList(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: proxy-web list <url>")
		fmt.Fprintln(os.Stderr, "  Parses HTTP directory listing and displays file table")
		fmt.Fprintln(os.Stderr, "  Supports defanged URLs (hxxp://evil[.]com)")
		os.Exit(1)
	}
	if err := orchestrator.PrintDirectoryListing(args[0]); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func handleBazaar(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: proxy-web bazaar <subcommand> <value>")
		fmt.Fprintln(os.Stderr, "  hash     <sha256/md5/sha1>  - Hash lookup")
		fmt.Fprintln(os.Stderr, "  sig      <family_name>      - Signature/family search")
		fmt.Fprintln(os.Stderr, "  tag      <tag>              - Tag search")
		fmt.Fprintln(os.Stderr, "  download <sha256> [flags]   - Download sample ZIP")
		fmt.Fprintln(os.Stderr, "    --to-ghidra               Extract into ghidra-headless container /tmp/")
		fmt.Fprintln(os.Stderr, "    -o <dir>                  Output directory (default: current dir)")
		os.Exit(1)
	}

	jsonOut := false
	var filteredArgs []string
	for _, arg := range args {
		switch arg {
		case "--json", "-j":
			jsonOut = true
		default:
			filteredArgs = append(filteredArgs, arg)
		}
	}
	args = filteredArgs

	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: proxy-web bazaar <subcommand> <value> [--json|-j]")
		fmt.Fprintln(os.Stderr, "  hash     <sha256/md5/sha1>  - Hash lookup")
		fmt.Fprintln(os.Stderr, "  sig      <family_name>      - Signature/family search")
		fmt.Fprintln(os.Stderr, "  tag      <tag>              - Tag search")
		fmt.Fprintln(os.Stderr, "  download <sha256> [flags]   - Download sample ZIP")
		os.Exit(1)
	}

	mb := orchestrator.NewMBClient(os.Getenv("ABUSECH_AUTH_KEY"))

	if jsonOut {
		var b []byte
		var err error
		switch args[0] {
		case "hash":
			b, err = mb.HashLookupJSON(args[1])
		case "sig":
			b, err = mb.SigLookupJSON(args[1])
		case "tag":
			b, err = mb.TagLookupJSON(args[1])
		default:
			fmt.Fprintf(os.Stderr, "--json not supported for bazaar %s\n", args[0])
			os.Exit(1)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(b))
		return
	}

	switch args[0] {
	case "hash":
		mb.HashLookup(args[1])
	case "sig":
		mb.SigLookup(args[1])
	case "tag":
		mb.TagLookup(args[1])
	case "download":
		handleBazaarDownload(mb, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown bazaar subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func handleBazaarDownload(mb *orchestrator.MBClient, args []string) {
	// Reorder args: put flags before positional args (Go flag package stops at first non-flag)
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			flags = append(flags, args[i])
			// Check if this flag takes a value (next arg is not a flag)
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") && (args[i] == "-o") {
				flags = append(flags, args[i+1])
				i++
			}
		} else {
			positional = append(positional, args[i])
		}
	}
	reordered := append(flags, positional...)

	fs := flag.NewFlagSet("bazaar-download", flag.ExitOnError)
	toGhidra := fs.Bool("to-ghidra", false, "Extract into ghidra-headless container /tmp/")
	outputDir := fs.String("o", "", "Output directory (default: OS temp dir)")
	fs.Parse(reordered)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: proxy-web bazaar download <sha256> [--to-ghidra] [-o dir]")
		os.Exit(1)
	}
	sha256 := fs.Arg(0)

	// Determine output directory
	outDir := *outputDir
	if outDir == "" {
		outDir = os.TempDir()
	}

	// Download
	zipPath, err := mb.Download(sha256, outDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if !*toGhidra {
		fmt.Printf("[*] Sample saved to: %s\n", zipPath)
		fmt.Printf("[*] To extract: 7z x -pinfected %s\n", zipPath)
		return
	}

	// Transfer to ghidra-headless container and extract with 7z
	container := "ghidra-headless"
	fmt.Printf("[*] Transferring to %s container...\n", container)

	// Check container is running
	checkCmd := fmt.Sprintf("docker inspect -f '{{.State.Status}}' %s", container)
	out, err := runShell(checkCmd)
	if err != nil || strings.TrimSpace(out) != "running" {
		fmt.Fprintf(os.Stderr, "Error: %s container is not running. Start with: ghidra.sh start\n", container)
		os.Exit(1)
	}

	// Copy ZIP to container /tmp/
	zipName := filepath.Base(zipPath)
	cpCmd := fmt.Sprintf("docker cp \"%s\" %s:/tmp/%s", zipPath, container, zipName)
	if _, err := runShell(cpCmd); err != nil {
		fmt.Fprintf(os.Stderr, "Error: docker cp failed: %v\n", err)
		os.Exit(1)
	}

	// Extract with 7z inside container
	extractDir := "/tmp/mb_" + sha256[:12]
	extractCmd := fmt.Sprintf("docker exec %s bash -c \"mkdir -p %s && 7z x -pinfected -o%s /tmp/%s -y\"",
		container, extractDir, extractDir, zipName)
	out, err = runShell(extractCmd)
	if err != nil {
		// Fallback: try Python zipfile
		fmt.Println("[!] 7z failed, trying Python fallback...")
		pyCmd := fmt.Sprintf("docker exec %s python3 -c \""+
			"import zipfile; z=zipfile.ZipFile('/tmp/%s'); z.extractall('%s', pwd=b'infected'); "+
			"print('Extracted:', z.namelist())\"",
			container, zipName, extractDir)
		out, err = runShell(pyCmd)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: extraction failed in container: %v\n%s\n", err, out)
			os.Exit(1)
		}
	}
	fmt.Printf("%s", out)

	// Clean up ZIP in container
	cleanCmd := fmt.Sprintf("docker exec %s rm -f /tmp/%s", container, zipName)
	runShell(cleanCmd)

	// List extracted files
	lsCmd := fmt.Sprintf("docker exec %s ls -la %s", container, extractDir)
	out, _ = runShell(lsCmd)
	fmt.Printf("\n[+] Extracted to container %s:%s\n", container, extractDir)
	fmt.Printf("%s", out)

	// Clean up host temp ZIP
	os.Remove(zipPath)
	fmt.Printf("\n[+] Ready for Ghidra analysis:\n")
	fmt.Printf("    ghidra.sh analyze --container %s/<filename>\n", extractDir)
}

// runShell executes a shell command and returns stdout.
func runShell(cmd string) (string, error) {
	// Use bash on all platforms (Git Bash on Windows)
	c := execCommand("bash", "-c", cmd)
	// Prevent MSYS/Git Bash from converting /tmp/ to C:\Users\...\Temp\
	c.Env = append(os.Environ(), "MSYS_NO_PATHCONV=1")
	out, err := c.CombinedOutput()
	return string(out), err
}

func handleThreatFox(args []string) {
	jsonOut := false
	limit := 10
	var positional []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json", "-j":
			jsonOut = true
		case "--limit", "-l":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &limit)
				i++
			}
		default:
			positional = append(positional, args[i])
		}
	}

	if len(positional) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: proxy-web threatfox <subcommand> <value> [--limit N] [--json|-j]")
		fmt.Fprintln(os.Stderr, "  ioc     <ip:port/domain>  - IOC search")
		fmt.Fprintln(os.Stderr, "  hash    <sha256/md5>      - Hash search")
		fmt.Fprintln(os.Stderr, "  tag     <tag>             - Tag search (default limit=10, max=1000)")
		fmt.Fprintln(os.Stderr, "  malware <family>          - Malware family search (default limit=10, max=1000)")
		os.Exit(1)
	}

	tf := orchestrator.NewTFClient(os.Getenv("ABUSECH_AUTH_KEY"))
	subcmd, value := positional[0], positional[1]

	if jsonOut {
		var b []byte
		var err error
		switch subcmd {
		case "ioc":
			b, err = tf.IOCSearchJSON(value)
		case "hash":
			b, err = tf.HashSearchJSON(value)
		case "tag":
			b, err = tf.TagSearchJSON(value, limit)
		case "malware":
			b, err = tf.MalwareSearchJSON(value, limit)
		default:
			fmt.Fprintf(os.Stderr, "Unknown threatfox subcommand: %s\n", subcmd)
			os.Exit(1)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(b))
		return
	}

	switch subcmd {
	case "ioc":
		tf.IOCSearch(value)
	case "hash":
		tf.HashSearch(value)
	case "tag":
		tf.TagSearch(value, limit)
	case "malware":
		tf.MalwareSearch(value, limit)
	default:
		fmt.Fprintf(os.Stderr, "Unknown threatfox subcommand: %s\n", subcmd)
		os.Exit(1)
	}
}

func handleAnalyze(args []string) {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	useTor := fs.Bool("tor", false, "Route through Tor")
	skipPreflight := fs.Bool("skip-preflight", false, "Skip preflight Docker/env check")
	fs.Parse(args)

	log.Println("=== Proxy Web - Malware Site Analysis Tool ===")

	// Preflight: fail fast when Docker is not running (prevents 3 retries of identical failure).
	if !*skipPreflight {
		checks := orchestrator.RunPreflight()
		var dockerOK bool
		for _, c := range checks {
			if c.Name == "Docker daemon" {
				dockerOK = c.OK
				break
			}
		}
		if !dockerOK {
			log.Println("Preflight failed: Docker daemon not running.")
			log.Println("  Start Docker Desktop, then retry.")
			log.Println("  To diagnose: proxy-web.exe preflight")
			log.Println("  To bypass (advanced): --skip-preflight")
			os.Exit(1)
		}
	}

	// Get encryption password
	password := os.Getenv("QUARANTINE_PASSWORD")
	if password == "" {
		log.Fatal("QUARANTINE_PASSWORD not set in .env file")
	}
	vtAPIKey := os.Getenv("VIRUSTOTAL_API_KEY")

	// Get URL (required argument, no interactive input)
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: proxy-web [--tor] <URL>")
		os.Exit(1)
	}
	userInput := fs.Arg(0)

	// Refang
	targetURL := orchestrator.Refang(userInput)
	log.Printf("Target URL: %s", targetURL)
	if targetURL != userInput {
		log.Printf("Refanged from: %s", userInput)
	}

	// Extract domain
	parsed, err := url.Parse(targetURL)
	if err != nil {
		log.Fatalf("Invalid URL: %v", err)
	}
	domain := parsed.Host
	if domain == "" {
		domain = "unknown"
	}
	// Sanitize domain for safe filesystem path
	domain = strings.Map(func(r rune) rune {
		switch r {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|':
			return '_'
		}
		return r
	}, domain)

	// Output directory
	exe, _ := os.Executable()
	scriptDir := filepath.Dir(exe)
	timestamp := time.Now().Format("20060102_150405")
	quarantineDir := filepath.Join(scriptDir, "Quarantine", domain, timestamp)
	if err := os.MkdirAll(quarantineDir, 0o755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}
	log.Printf("Output directory: %s", quarantineDir)

	// Run in Docker
	var result *orchestrator.ContainerResult
	var lastErr error
	maxRetries := 3

	result, lastErr = orchestrator.RunInDocker(targetURL, quarantineDir, password, *useTor)
	if lastErr != nil {
		log.Printf("Analysis failed: %v", lastErr)
		for retry := 1; retry <= maxRetries; retry++ {
			log.Printf("Retry %d/%d...", retry, maxRetries)
			// Retry 1-2: same Tor setting as user specified
			// Retry 3 (final): flip Tor setting as last resort
			torRetry := *useTor
			if retry == maxRetries {
				torRetry = !torRetry
				if torRetry {
					log.Println("Final retry: switching to Tor")
				} else {
					log.Println("Final retry: switching to direct connection")
				}
			}
			result, lastErr = orchestrator.RunInDocker(targetURL, quarantineDir, password, torRetry)
			if lastErr == nil {
				break
			}
			log.Printf("Retry %d failed: %v", retry, lastErr)
		}
		if lastErr != nil {
			log.Fatal("All retries exhausted")
		}
	}

	// Process results
	var vt *orchestrator.VTClient
	if vtAPIKey != "" {
		vt = orchestrator.NewVTClient(vtAPIKey)
	}

	var downloads []orchestrator.Download
	for _, dl := range result.Downloads {
		d := orchestrator.Download{
			Filename: dl.Filename,
			Hashes:   dl.Hashes,
		}

		// VT check
		sha256 := dl.Hashes["sha256"]
		if sha256 != "" && vt != nil {
			vtResult, err := vt.Check(sha256)
			if err == nil {
				d.VirusTotal = vtResult
			}
		}

		downloads = append(downloads, d)
	}

	// Save network CSV
	if len(result.NetworkLog) > 0 {
		csvPath := filepath.Join(quarantineDir, "network.csv")
		if err := orchestrator.SaveNetworkCSV(result.NetworkLog, csvPath); err != nil {
			log.Printf("Failed to save network CSV: %v", err)
		} else {
			log.Printf("Network log saved: %s", csvPath)
		}
	}

	// Save metadata
	metadata := &orchestrator.Metadata{
		URL:            targetURL,
		OriginalInput:  userInput,
		Timestamp:      time.Now().Format(time.RFC3339),
		Domain:         domain,
		FinalURL:       result.FinalURL,
		Screenshot:     result.Screenshot,
		HTMLFile:        result.HTMLFile,
		Downloads:      downloads,
		NetworkLogFile: "network.csv",
		Success:        result.Success,
		Error:          result.Error,
	}

	metadataPath := filepath.Join(quarantineDir, "metadata.json")
	if err := orchestrator.SaveMetadata(metadata, metadataPath); err != nil {
		log.Printf("Failed to save metadata: %v", err)
	} else {
		log.Printf("Metadata saved: %s", metadataPath)
	}

	// Summary
	log.Println("\n=== Analysis Complete ===")
	log.Printf("Output: %s", quarantineDir)
	log.Printf("Downloaded files: %d", len(downloads))
	log.Printf("Network requests: %d", len(result.NetworkLog))

	for _, dl := range downloads {
		log.Printf("  %s: SHA256=%s", dl.Filename, dl.Hashes["sha256"])
		if dl.VirusTotal != nil {
			log.Printf("    VT: %d/%d %s", dl.VirusTotal.Detected, dl.VirusTotal.Total, dl.VirusTotal.Permalink)
		}
	}

	log.Println("=== Proxy Web Finished ===")
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `proxy-web - Malware Site Analysis Tool

Usage:
  proxy-web <URL>                       Analyze URL in Docker container
  proxy-web --tor <URL>                 Analyze URL via Tor
  proxy-web probe [--tor] <URL>         Lightweight URL pre-check
  proxy-web preflight                   Check Docker/env prerequisites
  proxy-web check <sha256>              VirusTotal hash check
  proxy-web behavior <sha256>           VirusTotal behavior report
  proxy-web lookup <sha256>             VirusTotal detailed lookup
  proxy-web vt-ip <IP>                  VirusTotal IP address report
  proxy-web list <URL>                  Parse HTTP directory listing
  proxy-web bazaar <hash|sig|tag|download> <val> MalwareBazaar search/download
  proxy-web threatfox <ioc|hash|tag|malware> <val>  ThreatFox search
  proxy-web recon <URL>                  C2 server reconnaissance
  proxy-web ws probe <ws://host/path>   WebSocket endpoint probe
  proxy-web ws capture <ws://host/path> [--duration N] [--json]  Capture WS messages
  proxy-web decrypt <file.enc.gz>       Decrypt quarantine file
  proxy-web help                        Show this help
`)
}

func handleWS(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, `Usage:
  proxy-web ws probe <ws://host:port/path>          Quick WebSocket probe
  proxy-web ws capture <ws://host:port/path> [opts]  Capture WS messages
    --duration N   Capture duration in seconds (default: 30)
    --json         JSON output`)
		os.Exit(1)
	}

	switch args[0] {
	case "probe":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: proxy-web ws probe <ws://host:port/path>")
			os.Exit(1)
		}
		orchestrator.RunWSProbe(args[1])

	case "capture":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: proxy-web ws capture <ws://host:port/path> [--duration N] [--json]")
			os.Exit(1)
		}
		wsURL := args[1]
		duration := 30
		jsonOut := false

		for i := 2; i < len(args); i++ {
			switch args[i] {
			case "--duration", "-d":
				if i+1 < len(args) {
					fmt.Sscanf(args[i+1], "%d", &duration)
					i++
				}
			case "--json":
				jsonOut = true
			}
		}
		orchestrator.RunWSCapture(wsURL, duration, jsonOut)

	default:
		fmt.Fprintf(os.Stderr, "Unknown ws subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func handleBatchProbe(args []string) {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			flags = append(flags, args[i])
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				flags = append(flags, args[i+1])
				i++
			}
		} else {
			positional = append(positional, args[i])
		}
	}
	reordered := append(flags, positional...)

	fs := flag.NewFlagSet("batch-probe", flag.ExitOnError)
	threads := fs.Int("threads", 30, "Concurrent threads")
	timeout := fs.Int("timeout", 10, "HTTP timeout in seconds")
	dnsOnly := fs.Bool("dns-only", false, "DNS resolution only (skip HTTP)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: proxy-web batch-probe <domains.txt> [--threads N] [--timeout N] [--dns-only]")
		fmt.Fprintln(os.Stderr, "  Probe multiple domains concurrently")
		fs.PrintDefaults()
	}
	fs.Parse(reordered)
	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}
	orchestrator.RunBatchProbe(fs.Arg(0), *threads, time.Duration(*timeout)*time.Second, !*dnsOnly)
}

func handleClassify(args []string) {
	// Reorder args: move flags before positional args (Go flag stops at first non-flag)
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			flags = append(flags, args[i])
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				flags = append(flags, args[i+1])
				i++
			}
		} else {
			positional = append(positional, args[i])
		}
	}
	reordered := append(flags, positional...)

	fs := flag.NewFlagSet("classify", flag.ExitOnError)
	target := fs.String("target", "", "Target domain (for classification context)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: proxy-web classify <network.csv> [--target domain]")
		fmt.Fprintln(os.Stderr, "  Classify network log entries by category")
		fs.PrintDefaults()
	}
	fs.Parse(reordered)
	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}
	orchestrator.RunNetLogClassify(fs.Arg(0), *target)
}

func handleOTX(args []string) {
	jsonOut := false
	var filtered []string
	for _, arg := range args {
		switch arg {
		case "--json", "-j":
			jsonOut = true
		default:
			filtered = append(filtered, arg)
		}
	}
	args = filtered

	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, `Usage: proxy-web otx <subcommand> <value> [--json|-j]
  domain  <domain>     - Domain pulse lookup
  ip      <IP>         - IP pulse lookup
  pulse   <pulseID>    - Pulse detail + IOC breakdown
  hashes  <pulseID>    - Extract file hashes from pulse
  urls    <pulseID>    - Extract URLs from pulse
  stats   <pulseID>    - IOC statistics (TLD, path, type distribution)`)
		os.Exit(1)
	}

	otx := orchestrator.NewOTXClient()

	if jsonOut {
		var b []byte
		var err error
		switch args[0] {
		case "domain":
			b, err = otx.DomainLookupJSON(args[1])
		case "ip":
			b, err = otx.IPLookupJSON(args[1])
		default:
			fmt.Fprintf(os.Stderr, "--json not supported for otx %s yet\n", args[0])
			os.Exit(1)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(b))
		return
	}

	switch args[0] {
	case "domain":
		otx.DomainLookup(args[1])
	case "ip":
		otx.IPLookup(args[1])
	case "pulse":
		otx.PulseLookup(args[1])
	case "hashes":
		otx.PulseHashes(args[1])
	case "urls":
		otx.PulseURLs(args[1])
	case "stats":
		otx.PulseStats(args[1])
	default:
		fmt.Fprintf(os.Stderr, "Unknown otx subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func handleC2Profile(args []string) {
	jsonOut := false
	var target string
	for _, arg := range args {
		switch arg {
		case "--json", "-j":
			jsonOut = true
		default:
			if target == "" {
				target = arg
			}
		}
	}
	if target == "" {
		fmt.Fprintln(os.Stderr, "Usage: proxy-web c2-profile <IP[:port]> [--json|-j]")
		fmt.Fprintln(os.Stderr, "  Automated C2 infrastructure profiling")
		fmt.Fprintln(os.Stderr, "  VT IP → ThreatFox → Passive DNS pivot → Port scan")
		os.Exit(1)
	}

	ip := target
	port := 0
	if parts := strings.SplitN(target, ":", 2); len(parts) == 2 {
		ip = parts[0]
		fmt.Sscanf(parts[1], "%d", &port)
	}

	if jsonOut {
		b, err := orchestrator.RunC2ProfileJSON(ip, port)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(b))
		return
	}
	orchestrator.RunC2Profile(ip, port)
}

func handleRecon(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: proxy-web recon <URL>")
		fmt.Fprintln(os.Stderr, "  Automated C2 server reconnaissance")
		fmt.Fprintln(os.Stderr, "  Supports defanged URLs (hxxp://evil[.]com)")
		os.Exit(1)
	}
	orchestrator.RunRecon(args[0])
}

func handleProbe(args []string) {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	useTor := fs.Bool("tor", false, "Also probe via Tor SOCKS5")
	batch := fs.Bool("batch", false, "Always exit 0 (for parallel execution)")
	jsonOut := fs.Bool("json", false, "Output as JSON")
	fs.BoolVar(jsonOut, "j", false, "Output as JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: proxy-web probe [--tor] [--batch] [--json|-j] <URL>")
		fmt.Fprintln(os.Stderr, "  Lightweight URL pre-check: DNS, HTTP status, FortiGate detection")
		fmt.Fprintln(os.Stderr, "  --json/-j: Machine-readable JSON output")
		fmt.Fprintln(os.Stderr, "  --batch:   Always exit 0 even if unreachable (for parallel Bash calls)")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}

	report := orchestrator.RunProbe(fs.Arg(0), *useTor)

	if *jsonOut {
		b, err := orchestrator.PrintProbeJSON(report)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(b))
		if report.Recommend == orchestrator.RecommendSkip && !*batch {
			os.Exit(2)
		}
		return
	}

	orchestrator.PrintProbeReport(report)
	if report.Recommend == orchestrator.RecommendSkip && !*batch {
		os.Exit(2)
	}
}

func handlePreflight() {
	jsonOut := false
	for _, arg := range os.Args[2:] {
		if arg == "--json" || arg == "-j" {
			jsonOut = true
		}
	}
	checks := orchestrator.RunPreflight()
	if jsonOut {
		b, err := orchestrator.PrintPreflightJSON(checks)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(b))
		return
	}
	ok := orchestrator.PrintPreflight(checks)
	if !ok {
		os.Exit(1)
	}
}

func setupLogging() {
	exe, _ := os.Executable()
	logDir := filepath.Join(filepath.Dir(exe), "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		log.SetFlags(log.Ldate | log.Ltime)
		return
	}

	today := time.Now()
	logFile := filepath.Join(logDir, today.Format("20060102")+".log")

	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		log.SetFlags(log.Ldate | log.Ltime)
		return
	}

	log.SetOutput(&dualWriter{file: f, console: os.Stdout})
	log.SetFlags(log.Ldate | log.Ltime)

	// Cleanup old logs
	cutoff := today.AddDate(0, 0, -30)
	entries, _ := os.ReadDir(logDir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".log" {
			continue
		}
		stem := e.Name()[:len(e.Name())-4]
		t, err := time.Parse("20060102", stem)
		if err != nil {
			continue
		}
		if t.Before(cutoff) {
			os.Remove(filepath.Join(logDir, e.Name()))
		}
	}
}

func handleFetch(args []string) {
	fs := flag.NewFlagSet("fetch", flag.ExitOnError)
	output := fs.String("o", "", "Output file name (default: derived from URL)")
	outDir := fs.String("d", "", "Output directory (default: Quarantine/<domain>/<ts>_fetch/)")
	ua := fs.String("ua", "", "User-Agent header")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: proxy-web fetch <URL> [-o filename] [-d output_dir] [-ua user-agent]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Raw HTTP fetch without browser rendering. Saves response body + headers.")
		fmt.Fprintln(os.Stderr, "Use for JS/CSS/JSON files that don't need Chromium rendering.")
		os.Exit(1)
	}

	targetURL := fs.Arg(0)
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	fmt.Printf("\033[36m=== proxy-web fetch ===\033[0m\n")
	fmt.Printf("Target: %s\n", targetURL)

	password := os.Getenv("QUARANTINE_PASSWORD")
	result, err := orchestrator.FetchRaw(targetURL, *outDir, *output, *ua, password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\033[31mError: %v\033[0m\n", err)
		os.Exit(1)
	}

	statusColor := "\033[32m" // green
	if result.StatusCode >= 400 {
		statusColor = "\033[31m" // red
	} else if result.StatusCode >= 300 {
		statusColor = "\033[33m" // yellow
	}

	fmt.Printf("Status: %s%d\033[0m\n", statusColor, result.StatusCode)
	fmt.Printf("Content-Type: %s\n", result.ContentType)
	fmt.Printf("Size: %d bytes\n", result.Size)
	if result.Encrypted {
		fmt.Printf("Saved: %s \033[33m[encrypted]\033[0m\n", result.OutputPath)
		fmt.Printf("Decrypt: tools/proxy-web/proxy-web.exe decrypt %s\n", result.OutputPath)
		fmt.Printf("\033[33mNote: Use 'python3 Tools/proxy-web/js_deobfuscate.py --url \"%s\"' to analyze without disk write\033[0m\n", targetURL)
	} else {
		fmt.Printf("Saved: %s\n", result.OutputPath)
	}
	fmt.Printf("Headers: %s\n", result.OutputPath+".headers")
	fmt.Printf("\033[36m=== fetch complete ===\033[0m\n")
}

type dualWriter struct {
	file    *os.File
	console *os.File
}

func (w *dualWriter) Write(p []byte) (int, error) {
	n, err := w.file.Write(p)
	if err != nil {
		return n, err
	}
	_, _ = w.console.Write(p)
	return n, nil
}
