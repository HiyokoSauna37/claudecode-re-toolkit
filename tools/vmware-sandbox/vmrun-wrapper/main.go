// vmrun-wrapper: vmrunコマンドのタイムアウト付きラッパー
//
// vmrunはコマンドによって無限にハングする問題がある。
// このラッパーは全コマンドにタイムアウトを付与し、安全に実行する。
//
// 対処する既知の問題:
// - getGuestIPAddress -wait が無限待機
// - runScriptInGuest が完了を検知できずハング
// - runProgramInGuest + cmd.exe /c リダイレクトがハング
//
// Usage:
//
//	vmrun-wrapper [--timeout 30] <vmrun args...>
//	vmrun-wrapper --timeout 15 -T ws -gu user -gp pass getGuestIPAddress "path.vmx"
//	vmrun-wrapper guest-exec "powershell command here"   # 安全なゲスト実行ショートカット
//	vmrun-wrapper guest-info                              # ゲスト情報取得
package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultTimeout = 30 // seconds
	vmrunPath      = `C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe`
)

type Config struct {
	VMXPath      string
	GuestUser    string
	GuestPass    string
	GuestProfile string
}

func loadEnv() Config {
	// Find .env relative to executable or current dir
	candidates := []string{}

	if exe, err := os.Executable(); err == nil {
		// Tools/vmware-sandbox/vmrun-wrapper/vmrun-wrapper.exe → ../../.env
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "..", "..", "..", ".env"))
	}

	cwd, _ := os.Getwd()
	candidates = append(candidates,
		filepath.Join(cwd, ".env"),
		filepath.Join(cwd, "..", ".env"),
		filepath.Join(cwd, "..", "..", ".env"),
		filepath.Join(cwd, "..", "..", "..", ".env"),
	)

	config := Config{}

	for _, path := range candidates {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			switch key {
			case "VM_VMX_PATH":
				config.VMXPath = value
			case "VM_GUEST_USER":
				config.GuestUser = value
			case "VM_GUEST_PASS":
				config.GuestPass = value
			case "VM_GUEST_PROFILE":
				config.GuestProfile = value
			}
		}
		break // 最初に見つかった.envを使う
	}

	return config
}

func runVmrun(timeout int, args []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, vmrunPath, args...)
	output, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		return string(output), fmt.Errorf("timeout after %ds", timeout)
	}

	if err != nil {
		return string(output), fmt.Errorf("vmrun error: %w\n%s", err, string(output))
	}

	return string(output), nil
}

// guestExec: PowerShellで安全にコマンド実行（ハング防止済み）
func guestExec(config Config, timeout int, command string) (string, error) {
	args := []string{
		"-T", "ws",
		"-gu", config.GuestUser,
		"-gp", config.GuestPass,
		"runProgramInGuest", config.VMXPath,
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		"-NoProfile", "-NonInteractive", "-Command", command,
	}
	return runVmrun(timeout, args)
}

// guestInfo: ゲストの基本情報を取得
func guestInfo(config Config, timeout int) {
	fmt.Println("=== Guest Information ===")

	// IP
	ip, err := runVmrun(timeout, []string{
		"-T", "ws",
		"-gu", config.GuestUser,
		"-gp", config.GuestPass,
		"getGuestIPAddress", config.VMXPath,
	})
	if err != nil {
		fmt.Printf("IP: error (%v)\n", err)
	} else {
		fmt.Printf("IP: %s", ip)
	}

	// Profile path
	fmt.Printf("Profile: %s\n", config.GuestProfile)

	// Process count
	procs, err := runVmrun(timeout, []string{
		"-T", "ws",
		"-gu", config.GuestUser,
		"-gp", config.GuestPass,
		"listProcessesInGuest", config.VMXPath,
	})
	if err != nil {
		fmt.Printf("Processes: error (%v)\n", err)
	} else {
		lines := strings.Split(strings.TrimSpace(procs), "\n")
		if len(lines) > 0 && strings.HasPrefix(lines[0], "Process list:") {
			fmt.Printf("Processes: %s\n", strings.TrimPrefix(lines[0], "Process list: "))
		}
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `vmrun-wrapper: vmrun with timeout support

Usage:
  vmrun-wrapper [--timeout SECONDS] <vmrun args...>
  vmrun-wrapper [--timeout SECONDS] guest-exec "<powershell command>"
  vmrun-wrapper [--timeout SECONDS] guest-info

Examples:
  vmrun-wrapper --timeout 15 -T ws list
  vmrun-wrapper guest-exec "Get-Process | Select-Object -First 10"
  vmrun-wrapper guest-info

Default timeout: %d seconds
Config: loaded from .env (VM_VMX_PATH, VM_GUEST_USER, VM_GUEST_PASS, VM_GUEST_PROFILE)
`, defaultTimeout)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(0)
	}

	args := os.Args[1:]
	timeout := defaultTimeout

	// Handle --help / -h / help before any other parsing
	if args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		printUsage()
		os.Exit(0)
	}

	// Parse --timeout
	if len(args) >= 2 && args[0] == "--timeout" {
		t, err := strconv.Atoi(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid timeout value: %s\n", args[1])
			os.Exit(1)
		}
		timeout = t
		args = args[2:]
	}

	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	config := loadEnv()

	switch args[0] {
	case "guest-exec":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: vmrun-wrapper guest-exec \"<command>\"")
			os.Exit(1)
		}
		if config.VMXPath == "" {
			fmt.Fprintln(os.Stderr, "ERROR: VM_VMX_PATH not found in .env")
			os.Exit(1)
		}
		output, err := guestExec(config, timeout, strings.Join(args[1:], " "))
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(output)

	case "guest-info":
		if config.VMXPath == "" {
			fmt.Fprintln(os.Stderr, "ERROR: VM_VMX_PATH not found in .env")
			os.Exit(1)
		}
		guestInfo(config, timeout)

	default:
		// パススルー: そのままvmrunに渡す（タイムアウト付き）
		output, err := runVmrun(timeout, args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			if strings.Contains(err.Error(), "timeout") {
				fmt.Fprintf(os.Stderr, "HINT: Increase timeout with --timeout <seconds>\n")
			}
			os.Exit(1)
		}
		fmt.Print(output)
	}
}
