package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
)

// PreflightResult holds the result of a single preflight check.
type PreflightCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// RunPreflight checks all prerequisites for proxy-web execution.
func RunPreflight() []PreflightCheck {
	var checks []PreflightCheck

	// 1. Docker daemon
	checks = append(checks, checkDocker())

	// 2. Docker image
	checks = append(checks, checkDockerImage())

	// 3. QUARANTINE_PASSWORD
	checks = append(checks, checkEnvVar("QUARANTINE_PASSWORD", true))

	// 4. VIRUSTOTAL_API_KEY
	checks = append(checks, checkEnvVar("VIRUSTOTAL_API_KEY", false))

	// 5. ABUSECH_AUTH_KEY
	checks = append(checks, checkEnvVar("ABUSECH_AUTH_KEY", false))

	return checks
}

func checkDocker() PreflightCheck {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return PreflightCheck{
			Name:   "Docker daemon",
			OK:     false,
			Detail: fmt.Sprintf("client init failed: %v", err),
		}
	}
	defer cli.Close()

	_, err = cli.Ping(ctx)
	if err != nil {
		return PreflightCheck{
			Name:   "Docker daemon",
			OK:     false,
			Detail: "not running — start Docker Desktop first",
		}
	}

	return PreflightCheck{
		Name:   "Docker daemon",
		OK:     true,
		Detail: "running",
	}
}

func checkDockerImage() PreflightCheck {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return PreflightCheck{
			Name:   "Docker image (" + dockerImage + ")",
			OK:     false,
			Detail: "cannot check — Docker client unavailable",
		}
	}
	defer cli.Close()

	images, err := cli.ImageList(ctx, image.ListOptions{})
	if err != nil {
		return PreflightCheck{
			Name:   "Docker image (" + dockerImage + ")",
			OK:     false,
			Detail: fmt.Sprintf("image list failed: %v", err),
		}
	}

	for _, img := range images {
		for _, tag := range img.RepoTags {
			if tag == dockerImage {
				return PreflightCheck{
					Name:   "Docker image (" + dockerImage + ")",
					OK:     true,
					Detail: "available",
				}
			}
		}
	}

	return PreflightCheck{
		Name:   "Docker image (" + dockerImage + ")",
		OK:     false,
		Detail: "not found — run: docker build -t proxy-web-browser:latest .",
	}
}

func checkEnvVar(name string, required bool) PreflightCheck {
	val := os.Getenv(name)
	if val != "" {
		// Mask the value
		masked := val[:min(3, len(val))] + strings.Repeat("*", max(0, len(val)-3))
		severity := "set"
		return PreflightCheck{
			Name:   name,
			OK:     true,
			Detail: fmt.Sprintf("%s (%s)", severity, masked),
		}
	}

	if required {
		return PreflightCheck{
			Name:   name,
			OK:     false,
			Detail: "NOT SET (required)",
		}
	}

	return PreflightCheck{
		Name:   name,
		OK:     false,
		Detail: "not set (optional — some features disabled)",
	}
}

// PrintPreflightJSON returns preflight results as JSON bytes.
func PrintPreflightJSON(checks []PreflightCheck) ([]byte, error) {
	ready := true
	for _, c := range checks {
		if !c.OK && (strings.Contains(c.Detail, "required") || c.Name == "Docker daemon") {
			ready = false
		}
	}
	return json.Marshal(map[string]interface{}{
		"ok":     ready,
		"checks": checks,
	})
}

// PrintPreflight outputs preflight results with ANSI colors.
// ANSI colors: see color.go
func PrintPreflight(checks []PreflightCheck) bool {
	fmt.Printf("\n%s=== proxy-web preflight ===%s\n\n", cCyan, cReset)

	allOK := true
	hasRequired := true
	for _, c := range checks {
		icon := cGreen + "OK" + cReset
		if !c.OK {
			if strings.Contains(c.Detail, "required") || c.Name == "Docker daemon" {
				icon = cRed + "NG" + cReset
				hasRequired = false
			} else {
				icon = cYellow + "WARN" + cReset
			}
			allOK = false
		}
		fmt.Printf("  [%s] %s — %s\n", icon, c.Name, c.Detail)
	}

	fmt.Println()
	if hasRequired {
		fmt.Printf("  %sReady to run proxy-web%s\n", cGreen, cReset)
	} else {
		fmt.Printf("  %sFix required items before running proxy-web%s\n", cRed, cReset)
	}
	fmt.Println()

	return allOK
}

