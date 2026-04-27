package orchestrator

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ProbeStatus represents the liveness state of a probed domain.
type ProbeStatus int

const (
	ProbeAlive    ProbeStatus = iota
	ProbeDead
	ProbeFiltered
)

func (s ProbeStatus) String() string {
	names := [...]string{"alive", "dead", "filtered"}
	if int(s) < len(names) {
		return names[s]
	}
	return "unknown"
}

// BatchProbeResult holds the result of probing a single domain.
type BatchProbeResult struct {
	Domain   string
	IP       string
	Status   ProbeStatus
	HTTPCode int
	Server   string
	Error    string
}

// RunBatchProbe reads domains from a file and probes them concurrently.
func RunBatchProbe(filePath string, threads int, timeout time.Duration, httpCheck bool) {
	domains, err := readDomainList(filePath)
	if err != nil {
		fmt.Printf("%sError: %v%s\n", cRed, err, cReset)
		return
	}
	if len(domains) == 0 {
		fmt.Printf("%sNo domains found in %s%s\n", cYellow, filePath, cReset)
		return
	}

	fmt.Printf("\n%s=== Batch Probe: %d domains, %d threads ===%s\n", cCyan, len(domains), threads, cReset)

	results := make([]BatchProbeResult, len(domains))
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)
	var alive, dead, filtered int64
	var processed int64
	total := int64(len(domains))

	for i, domain := range domains {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, d string) {
			defer wg.Done()
			defer func() { <-sem }()

			results[idx] = probeDomain(d, timeout, httpCheck)

			switch results[idx].Status {
			case ProbeAlive:
				atomic.AddInt64(&alive, 1)
			case ProbeDead:
				atomic.AddInt64(&dead, 1)
			case ProbeFiltered:
				atomic.AddInt64(&filtered, 1)
			}
			if n := atomic.AddInt64(&processed, 1); n%50 == 0 || n == total {
				fmt.Printf("\r  Progress: %d/%d", n, total)
			}
		}(i, domain)
	}
	wg.Wait()
	fmt.Println()

	printBatchResults(results, alive, dead, filtered)
}

func readDomainList(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var domains []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			domains = append(domains, line)
		}
	}
	return domains, scanner.Err()
}

func probeDomain(domain string, timeout time.Duration, httpCheck bool) BatchProbeResult {
	result := BatchProbeResult{Domain: domain}

	ips, err := net.LookupHost(domain)
	if err != nil {
		result.Status = ProbeDead
		result.Error = "DNS failed"
		return result
	}
	result.IP = ips[0]

	if !httpCheck {
		result.Status = ProbeAlive
		return result
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	resp, err := client.Get("https://" + domain + "/")
	if err != nil {
		switch classifyError(err.Error()) {
		case FailureTimeout:
			result.Status = ProbeFiltered
			result.Error = "timeout"
		case FailureRefused:
			if resp2, err2 := client.Get("http://" + domain + "/"); err2 == nil {
				resp2.Body.Close()
				result.Status = ProbeAlive
				result.HTTPCode = resp2.StatusCode
				result.Server = resp2.Header.Get("Server")
			} else {
				result.Status = ProbeDead
				result.Error = "refused"
			}
		default:
			result.Status = ProbeDead
			result.Error = err.Error()
		}
		return result
	}
	defer resp.Body.Close()

	result.HTTPCode = resp.StatusCode
	result.Server = resp.Header.Get("Server")

	if resp.StatusCode == 521 {
		result.Status = ProbeDead
		result.Error = "521 origin down"
	} else {
		result.Status = ProbeAlive
	}
	return result
}

func printBatchResults(results []BatchProbeResult, alive, dead, filtered int64) {
	fmt.Printf("\n%sSummary:%s\n", cCyan, cReset)
	fmt.Printf("  %sAlive:    %d%s\n", cGreen, alive, cReset)
	fmt.Printf("  %sFiltered: %d%s\n", cYellow, filtered, cReset)
	fmt.Printf("  Dead:     %d\n", dead)

	if alive > 0 {
		fmt.Printf("\n%sAlive domains:%s\n", cGreen, cReset)
		for _, r := range results {
			if r.Status != ProbeAlive {
				continue
			}
			extra := ""
			if r.HTTPCode > 0 {
				extra = fmt.Sprintf(" HTTP %d", r.HTTPCode)
			}
			if r.Server != "" {
				extra += fmt.Sprintf(" [%s]", r.Server)
			}
			fmt.Printf("  %s -> %s%s\n", r.Domain, r.IP, extra)
		}
	}

	if filtered > 0 {
		fmt.Printf("\n%sFiltered (FW/timeout):%s\n", cYellow, cReset)
		for _, r := range results {
			if r.Status == ProbeFiltered {
				fmt.Printf("  %s -> %s\n", r.Domain, r.IP)
			}
		}
	}
}
