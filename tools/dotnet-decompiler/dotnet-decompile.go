package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/joho/godotenv"
)

const (
	containerName = "dotnet-decompiler"
	composeFile   = "docker-compose.yml"
)

type DecompileResult struct {
	Binary     string            `json:"binary"`
	OutputDir  string            `json:"output_dir"`
	Files      []string          `json:"files"`
	Namespaces []string          `json:"namespaces,omitempty"`
	Types      int               `json:"types"`
	Methods    int               `json:"methods"`
	Error      string            `json:"error,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	scriptDir := getScriptDir()
	loadEnv(scriptDir)

	switch os.Args[1] {
	case "decompile":
		if len(os.Args) < 3 {
			fmt.Println("Usage: dotnet-decompile decompile <binary|file.enc.gz>")
			os.Exit(1)
		}
		ensureRunning(scriptDir)
		if err := decompile(scriptDir, os.Args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "metadata":
		if len(os.Args) < 3 {
			fmt.Println("Usage: dotnet-decompile metadata <binary|file.enc.gz>")
			os.Exit(1)
		}
		ensureRunning(scriptDir)
		if err := metadata(scriptDir, os.Args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "list-types":
		if len(os.Args) < 3 {
			fmt.Println("Usage: dotnet-decompile list-types <binary|file.enc.gz>")
			os.Exit(1)
		}
		ensureRunning(scriptDir)
		if err := listTypes(scriptDir, os.Args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "preflight":
		preflight(scriptDir)
	case "start":
		start(scriptDir)
	case "stop":
		stop(scriptDir)
	default:
		// Default: treat as decompile if file exists
		if fileExists(os.Args[1]) || strings.HasSuffix(os.Args[1], ".enc.gz") {
			ensureRunning(scriptDir)
			if err := decompile(scriptDir, os.Args[1]); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		} else {
			printUsage()
			os.Exit(1)
		}
	}
}

func printUsage() {
	fmt.Println("dotnet-decompile - .NET Assembly Decompiler (ILSpy CLI in Docker)")
	fmt.Println()
	fmt.Println("Usage: dotnet-decompile <command> [args...]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  decompile <binary|file.enc.gz>   Full decompilation to C# source")
	fmt.Println("  metadata <binary|file.enc.gz>    Extract assembly metadata (refs, attributes)")
	fmt.Println("  list-types <binary|file.enc.gz>  List all types/classes in assembly")
	fmt.Println("  preflight                        Check Docker/image status")
	fmt.Println("  start                            Start container")
	fmt.Println("  stop                             Stop container")
	fmt.Println()
	fmt.Println("All commands auto-detect and decrypt .enc.gz quarantine files.")
}

func getScriptDir() string {
	exe, _ := os.Executable()
	return filepath.Dir(exe)
}

func loadEnv(scriptDir string) {
	// Try repo root .env first
	repoRoot := filepath.Join(scriptDir, "..", "..")
	envFile := filepath.Join(repoRoot, ".env")
	godotenv.Load(envFile)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func dockerExec(args ...string) (string, error) {
	cmdArgs := append([]string{"exec", containerName}, args...)
	cmd := exec.Command("docker", cmdArgs...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func ensureRunning(scriptDir string) {
	cmd := exec.Command("docker", "inspect", "-f", "{{.State.Status}}", containerName)
	out, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(out)) != "running" {
		fmt.Println("Container not running. Starting...")
		start(scriptDir)
	}
}

func start(scriptDir string) {
	composeFilePath := filepath.Join(scriptDir, composeFile)
	cmd := exec.Command("docker", "compose", "-f", composeFilePath, "up", "-d", "--build")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start container: %v\n", err)
		os.Exit(1)
	}
}

func stop(scriptDir string) {
	composeFilePath := filepath.Join(scriptDir, composeFile)
	cmd := exec.Command("docker", "compose", "-f", composeFilePath, "down")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

func preflight(scriptDir string) {
	fmt.Println("\033[36m=== dotnet-decompile preflight ===\033[0m")

	// Check Docker
	cmd := exec.Command("docker", "info")
	if err := cmd.Run(); err != nil {
		fmt.Println("  [\033[31mFAIL\033[0m] Docker daemon -- not running")
	} else {
		fmt.Println("  [\033[32mOK\033[0m] Docker daemon -- running")
	}

	// Check container
	cmd = exec.Command("docker", "inspect", "-f", "{{.State.Status}}", containerName)
	out, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(out)) != "running" {
		fmt.Println("  [\033[31mFAIL\033[0m] Container -- not running")
	} else {
		fmt.Println("  [\033[32mOK\033[0m] Container -- running")
	}

	// Check ilspycmd
	ilspyOut, err := dockerExec("ilspycmd", "--version")
	if err != nil {
		fmt.Println("  [\033[31mFAIL\033[0m] ilspycmd -- not found")
	} else {
		ver := strings.TrimSpace(ilspyOut)
		fmt.Printf("  [\033[32mOK\033[0m] ilspycmd -- %s\n", ver)
	}

	// Check QUARANTINE_PASSWORD
	pw := os.Getenv("QUARANTINE_PASSWORD")
	if pw == "" {
		fmt.Println("  [\033[33mWARN\033[0m] QUARANTINE_PASSWORD -- not set (needed for .enc.gz)")
	} else {
		fmt.Printf("  [\033[32mOK\033[0m] QUARANTINE_PASSWORD -- set (%s***)\n", pw[:3])
	}
}

// resolveBinary handles .enc.gz decryption inside container. Returns container-side path.
func resolveBinary(scriptDir, binaryPath string) (containerPath string, needsCleanup bool, err error) {
	basename := filepath.Base(binaryPath)

	if strings.HasSuffix(binaryPath, ".enc.gz") {
		fmt.Println("[*] Detected .enc.gz quarantine file, decrypting in container...")
		password := os.Getenv("QUARANTINE_PASSWORD")
		if password == "" {
			return "", false, fmt.Errorf("QUARANTINE_PASSWORD not set")
		}

		// Copy encrypted file to container /tmp/
		cmd := exec.Command("docker", "cp", binaryPath, containerName+":/tmp/"+basename)
		if out, err := cmd.CombinedOutput(); err != nil {
			return "", false, fmt.Errorf("docker cp failed: %s", string(out))
		}

		// Decrypt inside container
		decName := strings.TrimSuffix(basename, ".enc.gz")
		cmd = exec.Command("docker", "exec",
			"-e", "QUARANTINE_PASSWORD="+password,
			containerName,
			"python3", "/opt/scripts/decrypt_quarantine.py",
			"/tmp/"+basename, "-o", "/tmp/"+decName)
		if out, err := cmd.CombinedOutput(); err != nil {
			return "", false, fmt.Errorf("decryption failed: %s", string(out))
		}

		// Remove encrypted file from container
		exec.Command("docker", "exec", containerName, "rm", "-f", "/tmp/"+basename).Run()

		return "/tmp/" + decName, true, nil
	}

	// Plain binary: copy to container /tmp/
	cmd := exec.Command("docker", "cp", binaryPath, containerName+":/tmp/"+basename)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", false, fmt.Errorf("docker cp failed: %s", string(out))
	}
	return "/tmp/" + basename, true, nil
}

func cleanupContainer(containerPath string) {
	if containerPath != "" && strings.HasPrefix(containerPath, "/tmp/") {
		exec.Command("docker", "exec", containerName, "rm", "-f", containerPath).Run()
	}
}

func decompile(scriptDir, binaryPath string) error {
	containerPath, needsCleanup, err := resolveBinary(scriptDir, binaryPath)
	if err != nil {
		return err
	}
	if needsCleanup {
		defer cleanupContainer(containerPath)
	}

	basename := filepath.Base(containerPath)
	outputDir := "/analysis/output/" + strings.TrimSuffix(basename, filepath.Ext(basename))

	fmt.Printf("=== .NET Decompile: %s ===\n", basename)

	// Run ilspycmd full decompile
	out, err := dockerExec("ilspycmd", "-p", "-o", outputDir, containerPath)
	if err != nil {
		return fmt.Errorf("ilspycmd failed: %s\n%v", out, err)
	}
	fmt.Println(out)

	// List generated files
	listOut, _ := dockerExec("find", outputDir, "-type", "f", "-name", "*.cs")
	csFiles := strings.Split(strings.TrimSpace(listOut), "\n")

	// Count types and methods
	typeCount := 0
	methodCount := 0
	namespaces := map[string]bool{}
	for _, f := range csFiles {
		if f == "" {
			continue
		}
		content, _ := dockerExec("cat", f)
		typeCount += strings.Count(content, "class ") + strings.Count(content, "struct ") + strings.Count(content, "enum ")
		methodCount += strings.Count(content, "public ") + strings.Count(content, "private ") + strings.Count(content, "protected ") + strings.Count(content, "internal ")
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "namespace ") {
				ns := strings.TrimPrefix(line, "namespace ")
				ns = strings.TrimRight(ns, " {;")
				namespaces[ns] = true
			}
		}
	}

	nsList := []string{}
	for ns := range namespaces {
		nsList = append(nsList, ns)
	}

	// Copy output to host
	hostOutputDir := filepath.Join(scriptDir, "output", strings.TrimSuffix(basename, filepath.Ext(basename)))
	os.MkdirAll(hostOutputDir, 0755)
	cmd := exec.Command("docker", "cp", containerName+":"+outputDir+"/.", hostOutputDir)
	cmd.Run()

	// Write result JSON
	result := DecompileResult{
		Binary:     basename,
		OutputDir:  hostOutputDir,
		Files:      csFiles,
		Namespaces: nsList,
		Types:      typeCount,
		Methods:    methodCount,
	}

	jsonPath := filepath.Join(scriptDir, "output", basename+"_decompiled.json")
	jsonData, _ := json.MarshalIndent(result, "", "  ")
	os.WriteFile(jsonPath, jsonData, 0644)

	fmt.Printf("\n=== Decompilation Complete ===\n")
	fmt.Printf("  C# files:   %d\n", len(csFiles))
	fmt.Printf("  Namespaces: %d\n", len(nsList))
	fmt.Printf("  Types:      ~%d\n", typeCount)
	fmt.Printf("  Methods:    ~%d\n", methodCount)
	fmt.Printf("  Output:     %s\n", hostOutputDir)
	fmt.Printf("  JSON:       %s\n", jsonPath)

	return nil
}

func metadata(scriptDir, binaryPath string) error {
	containerPath, needsCleanup, err := resolveBinary(scriptDir, binaryPath)
	if err != nil {
		return err
	}
	if needsCleanup {
		defer cleanupContainer(containerPath)
	}

	basename := filepath.Base(containerPath)
	fmt.Printf("=== .NET Metadata: %s ===\n", basename)

	// List references
	out, err := dockerExec("ilspycmd", "--list", containerPath)
	if err != nil {
		return fmt.Errorf("ilspycmd --list failed: %s", out)
	}
	fmt.Println(out)

	// Save to file
	outFile := filepath.Join(scriptDir, "output", basename+"_metadata.txt")
	os.MkdirAll(filepath.Join(scriptDir, "output"), 0755)
	os.WriteFile(outFile, []byte(out), 0644)
	fmt.Printf("Saved to: %s\n", outFile)

	return nil
}

func listTypes(scriptDir, binaryPath string) error {
	containerPath, needsCleanup, err := resolveBinary(scriptDir, binaryPath)
	if err != nil {
		return err
	}
	if needsCleanup {
		defer cleanupContainer(containerPath)
	}

	basename := filepath.Base(containerPath)
	fmt.Printf("=== .NET Types: %s ===\n", basename)

	// Decompile to temp and extract type info
	tmpDir := "/tmp/types_" + basename
	out, err := dockerExec("ilspycmd", "-p", "-o", tmpDir, containerPath)
	if err != nil {
		return fmt.Errorf("ilspycmd failed: %s", out)
	}

	// Extract class/struct/enum definitions
	grepOut, _ := dockerExec("bash", "-c",
		fmt.Sprintf("grep -rn 'class \\|struct \\|enum \\|interface ' %s --include='*.cs' | head -200", tmpDir))
	fmt.Println(grepOut)

	// Cleanup temp
	exec.Command("docker", "exec", containerName, "rm", "-rf", tmpDir).Run()

	// Save
	outFile := filepath.Join(scriptDir, "output", basename+"_types.txt")
	os.MkdirAll(filepath.Join(scriptDir, "output"), 0755)
	os.WriteFile(outFile, []byte(grepOut), 0644)
	fmt.Printf("Saved to: %s\n", outFile)

	return nil
}
