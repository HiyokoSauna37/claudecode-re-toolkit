package main

import (
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/HiyokoSauna37/claudecode-re-toolkit/tools/proxy-web/orchestrator"
)

func main() {
	// Setup logging
	setupLogging()

	// Determine .env path relative to executable
	exe, _ := os.Executable()
	exeDir := filepath.Dir(exe)
	rootDir := filepath.Join(exeDir, "..", "..")
	envPath := filepath.Join(rootDir, ".env")
	_ = orchestrator.LoadEnv(envPath)

	// Also try relative to source
	scriptDir := exeDir
	rootDir2 := filepath.Join(scriptDir, "..", "..")
	envPath2 := filepath.Join(rootDir2, ".env")
	if envPath != envPath2 {
		_ = orchestrator.LoadEnv(envPath2)
	}

	// Parse subcommands
	if len(os.Args) >= 2 {
		switch os.Args[1] {
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
		case "list":
			handleList(os.Args[2:])
			return
		case "bazaar":
			handleBazaar(os.Args[2:])
			return
		case "threatfox":
			handleThreatFox(os.Args[2:])
			return
		}
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

func handleVT(subcmd string, args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: proxy-web %s <sha256>\n", subcmd)
		os.Exit(1)
	}

	hash := args[0]
	apiKey := os.Getenv("VIRUSTOTAL_API_KEY")
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "Error: VIRUSTOTAL_API_KEY not set")
		os.Exit(1)
	}

	vt := orchestrator.NewVTClient(apiKey)
	switch subcmd {
	case "check":
		vt.CheckPrint(hash)
	case "behavior":
		vt.BehaviorPrint(hash)
	case "lookup":
		vt.LookupPrint(hash)
	}
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
		fmt.Fprintln(os.Stderr, "  hash <sha256/md5/sha1>  - Hash lookup")
		fmt.Fprintln(os.Stderr, "  sig  <family_name>      - Signature/family search")
		fmt.Fprintln(os.Stderr, "  tag  <tag>              - Tag search")
		os.Exit(1)
	}

	authKey := os.Getenv("ABUSECH_AUTH_KEY")
	mb := orchestrator.NewMBClient(authKey)

	switch args[0] {
	case "hash":
		mb.HashLookup(args[1])
	case "sig":
		mb.SigLookup(args[1])
	case "tag":
		mb.TagLookup(args[1])
	default:
		fmt.Fprintf(os.Stderr, "Unknown bazaar subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func handleThreatFox(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: proxy-web threatfox <subcommand> <value>")
		fmt.Fprintln(os.Stderr, "  ioc     <ip:port/domain>  - IOC search")
		fmt.Fprintln(os.Stderr, "  hash    <sha256/md5>      - Hash search")
		fmt.Fprintln(os.Stderr, "  tag     <tag>             - Tag search")
		fmt.Fprintln(os.Stderr, "  malware <family>          - Malware family search")
		os.Exit(1)
	}

	authKey := os.Getenv("ABUSECH_AUTH_KEY")
	tf := orchestrator.NewTFClient(authKey)

	switch args[0] {
	case "ioc":
		tf.IOCSearch(args[1])
	case "hash":
		tf.HashSearch(args[1])
	case "tag":
		tf.TagSearch(args[1])
	case "malware":
		tf.MalwareSearch(args[1])
	default:
		fmt.Fprintf(os.Stderr, "Unknown threatfox subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func handleAnalyze(args []string) {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	useTor := fs.Bool("tor", false, "Route through Tor")
	fs.Parse(args)

	log.Println("=== Proxy Web - Malware Site Analysis Tool ===")

	// Get encryption password
	password := os.Getenv("QUARANTINE_PASSWORD")
	if password == "" {
		log.Fatal("QUARANTINE_PASSWORD not set in .env file")
	}
	vtAPIKey := os.Getenv("VIRUSTOTAL_API_KEY")

	// Get URL
	var userInput string
	if fs.NArg() > 0 {
		userInput = fs.Arg(0)
	} else {
		fmt.Println("\nEnter URL to analyze (supports defanged URLs):")
		fmt.Print("> ")
		fmt.Scanln(&userInput)
	}

	if userInput == "" {
		log.Fatal("No URL provided")
	}

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
	os.MkdirAll(quarantineDir, 0o755)
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
			torRetry := retry == 2
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
	var downloads []orchestrator.Download
	for _, dl := range result.Downloads {
		d := orchestrator.Download{
			Filename: dl.Filename,
			Hashes:   dl.Hashes,
		}

		// VT check
		sha256 := dl.Hashes["sha256"]
		if sha256 != "" && vtAPIKey != "" {
			vt := orchestrator.NewVTClient(vtAPIKey)
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

func setupLogging() {
	exe, _ := os.Executable()
	logDir := filepath.Join(filepath.Dir(exe), "logs")
	os.MkdirAll(logDir, 0o755)

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
