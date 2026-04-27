package orchestrator

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// --- Configuration ---

const (
	reconDialTimeout = 3 * time.Second
	reconHTTPTimeout = 5 * time.Second
	reconBodyLimit   = 4096
	reconSnipLen     = 40
)
// ANSI colors: see color.go

// portDef defines a port and its expected service.
type portDef struct {
	Port    int
	Service string
}

var reconPorts = []portDef{
	{21, "FTP"}, {22, "SSH"}, {23, "Telnet"}, {25, "SMTP"},
	{53, "DNS"}, {80, "HTTP"}, {81, "HTTP-Alt"}, {443, "HTTPS"},
	{445, "SMB"}, {808, "HTTP-Alt"}, {888, "HTTP-Alt"},
	{1080, "SOCKS"}, {1443, "HTTPS-Alt"},
	{2082, "cPanel"}, {3000, "Dev"}, {3306, "MySQL"},
	{3333, "Dev"}, {3389, "RDP"}, {4000, "Dev"},
	{4443, "HTTPS-Alt"}, {4444, "Meterpreter"},
	{5000, "Dev"}, {5002, "Dev"}, {5555, "ADB/Dev"},
	{6379, "Redis"}, {7443, "HTTPS-Alt"},
	{8000, "HTTP-Alt"}, {8008, "HTTP-Alt"}, {8080, "HTTP-Proxy"},
	{8081, "HTTP-Alt"}, {8082, "HTTP-Alt"}, {8088, "HTTP-Alt"},
	{8443, "HTTPS-Alt"}, {8880, "HTTP-Alt"}, {8888, "HTTP-Alt"},
	{9000, "HTTP-Alt"}, {9090, "HTTP-Alt"}, {9200, "Elasticsearch"},
	{9443, "HTTPS-Alt"}, {27017, "MongoDB"},
}

var reconMethods = []string{
	"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE",
}

var reconExtensions = []string{
	".php", ".js", ".css", ".png", ".jpg", ".gif", ".ico", ".svg",
	".html", ".asp", ".jsp", ".xml", ".json", ".txt",
	".exe", ".dll", ".zip", ".ps1", ".bat",
}

// --- Result types ---

type portResult struct {
	Port    int
	Service string
	Open    bool
}

type methodResult struct {
	Method     string
	StatusCode int
	BodySize   int
	BodySnip   string
	Err        error
}

type extResult struct {
	Ext        string
	StatusCode int
}

// --- Shared HTTP client ---

func newReconClient() *http.Client {
	return &http.Client{
		Timeout: reconHTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func reconGET(client *http.Client, targetURL string) (*http.Response, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", CommonUserAgent)
	return client.Do(req)
}

// --- Entry point ---

// RunRecon performs automated C2 server reconnaissance.
func RunRecon(targetURL string) {
	targetURL = Refang(targetURL)

	parsed, err := url.Parse(targetURL)
	if err != nil {
		fmt.Printf("%sError: invalid URL: %v%s\n", cRed, err, cReset)
		return
	}
	host := parsed.Hostname()
	if host == "" {
		fmt.Printf("%sError: cannot extract host from URL%s\n", cRed, cReset)
		return
	}

	client := newReconClient()
	basePath := strings.TrimRight(parsed.Path, "/")

	fmt.Printf("\n%s=== proxy-web recon ===%s\n", cCyan, cReset)
	fmt.Printf("Target: %s\n", targetURL)

	scanPortsConcurrent(host)
	testHTTPMethods(client, targetURL)
	mapExtensionRouting(client, parsed, basePath)
	detectCatchAll(client, parsed, basePath)
	inspectSSLCert(host)
	printResponseHeaders(client, targetURL)

	fmt.Printf("\n%s=== recon complete ===%s\n\n", cCyan, cReset)
}

// --- Phase implementations ---

func scanPortsConcurrent(host string) {
	fmt.Printf("\n%s[Port Scan]%s ", cCyan, cReset)

	results := make([]portResult, len(reconPorts))
	var wg sync.WaitGroup

	for i, p := range reconPorts {
		wg.Add(1)
		go func(idx, port int, svc string) {
			defer wg.Done()
			addr := fmt.Sprintf("%s:%d", host, port)
			conn, err := net.DialTimeout("tcp", addr, reconDialTimeout)
			if err == nil {
				conn.Close()
				results[idx] = portResult{port, svc, true}
			} else {
				results[idx] = portResult{port, svc, false}
			}
		}(i, p.Port, p.Service)
	}
	wg.Wait()

	var open []portResult
	for _, r := range results {
		if r.Open {
			open = append(open, r)
		}
	}
	sort.Slice(open, func(i, j int) bool { return open[i].Port < open[j].Port })

	fmt.Printf("%d open ports\n", len(open))
	for _, r := range open {
		fmt.Printf("  %s%d/tcp%s   OPEN (%s)\n", cGreen, r.Port, cReset, r.Service)
	}
	if len(open) == 0 {
		fmt.Printf("  %s(none)%s\n", cGray, cReset)
	}
}

func testHTTPMethods(client *http.Client, targetURL string) {
	fmt.Printf("\n%s[Methods]%s Root path method test\n", cCyan, cReset)

	results := make([]methodResult, 0, len(reconMethods))

	for _, method := range reconMethods {
		req, err := http.NewRequest(method, targetURL, nil)
		if err != nil {
			results = append(results, methodResult{Method: method, Err: err})
			continue
		}
		req.Header.Set("User-Agent", CommonUserAgent)

		resp, err := client.Do(req)
		if err != nil {
			results = append(results, methodResult{Method: method, Err: err})
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, reconBodyLimit))
		resp.Body.Close()

		results = append(results, methodResult{
			Method:     method,
			StatusCode: resp.StatusCode,
			BodySize:   len(body),
			BodySnip:   sanitizeSnippet(string(body)),
		})
	}

	// GET is the baseline (first result)
	var baseStatus, baseSize int
	if len(results) > 0 && results[0].Err == nil {
		baseStatus = results[0].StatusCode
		baseSize = results[0].BodySize
	}

	for i, r := range results {
		if r.Err != nil {
			fmt.Printf("  %-8s %sERROR%s  %v\n", r.Method, cRed, cReset, r.Err)
			continue
		}
		line := fmt.Sprintf("  %-8s %s%d%s  %dB",
			r.Method, statusColor(r.StatusCode), r.StatusCode, cReset, r.BodySize)
		if r.BodySnip != "" && r.BodySize <= reconSnipLen {
			line += fmt.Sprintf("   \"%s\"", r.BodySnip)
		}
		if i > 0 && (r.StatusCode != baseStatus || r.BodySize != baseSize) {
			line += fmt.Sprintf("    %s<- DIFFERENT%s", cYellow, cReset)
		}
		fmt.Println(line)
	}
}

func mapExtensionRouting(client *http.Client, parsed *url.URL, basePath string) {
	fmt.Printf("\n%s[Extensions]%s Routing map\n", cCyan, cReset)

	fakeName := "nonexistent_test_" + randomHex(4)
	results := make([]extResult, len(reconExtensions))
	var wg sync.WaitGroup

	for i, ext := range reconExtensions {
		wg.Add(1)
		go func(idx int, ext string) {
			defer wg.Done()
			testURL := fmt.Sprintf("%s://%s%s/%s%s", parsed.Scheme, parsed.Host, basePath, fakeName, ext)
			resp, err := reconGET(client, testURL)
			if err != nil {
				results[idx] = extResult{ext, -1}
				return
			}
			resp.Body.Close()
			results[idx] = extResult{ext, resp.StatusCode}
		}(i, ext)
	}
	wg.Wait()

	// Group by status code
	groups := make(map[int][]string)
	for _, r := range results {
		groups[r.StatusCode] = append(groups[r.StatusCode], r.Ext)
	}
	codes := sortedKeys(groups)

	for _, code := range codes {
		exts := groups[code]
		label := fmt.Sprintf("%d", code)
		if code == -1 {
			label = "ERROR"
		}
		color := cGray
		switch {
		case code == 200:
			color = cYellow
			label += " (possible catch-all)"
		case code == 403:
			color = cRed
			label += " (forbidden)"
		case code == 404:
			color = cGreen
		}
		fmt.Printf("  %s%s%s: %s\n", color, label, cReset, strings.Join(exts, " "))
	}
}

func detectCatchAll(client *http.Client, parsed *url.URL, basePath string) {
	fmt.Printf("\n%s[Catch-all]%s ", cCyan, cReset)

	randomPath := fmt.Sprintf("%s://%s%s/%s", parsed.Scheme, parsed.Host, basePath, randomHex(16))
	resp, err := reconGET(client, randomPath)
	if err != nil {
		fmt.Printf("%sERROR: %v%s\n", cRed, err, cReset)
		return
	}
	resp.Body.Close()

	if resp.StatusCode == 200 {
		fmt.Printf("%sDETECTED%s — random path returns 200\n", cRed, cReset)
	} else {
		fmt.Printf("%sNot detected%s — random path returns %d\n", cGreen, cReset, resp.StatusCode)
	}
}

func inspectSSLCert(host string) {
	fmt.Printf("\n%s[SSL Certificate]%s ", cCyan, cReset)

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: reconDialTimeout},
		"tcp",
		net.JoinHostPort(host, "443"),
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		fmt.Printf("%sN/A (%v)%s\n", cGray, err, cReset)
		return
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		fmt.Printf("%sNo certificates presented%s\n", cGray, cReset)
		return
	}
	cert := certs[0]
	fmt.Println()

	fmt.Printf("  CN: %s\n", cert.Subject.CommonName)

	var sans []string
	for _, dns := range cert.DNSNames {
		sans = append(sans, dns)
	}
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	if len(sans) > 0 {
		fmt.Printf("  SAN: %s\n", strings.Join(sans, ", "))
	}

	fmt.Printf("  Issuer: %s\n", cert.Issuer.CommonName)

	selfSigned := cert.Issuer.CommonName == cert.Subject.CommonName && cert.Issuer.CommonName != ""
	if selfSigned {
		fmt.Printf("  Self-signed: %sYes%s\n", cYellow, cReset)
	} else {
		fmt.Printf("  Self-signed: %sNo%s\n", cGreen, cReset)
	}

	now := time.Now()
	validColor := cGreen
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		validColor = cRed
	}
	fmt.Printf("  Valid: %s%s to %s%s\n",
		validColor, cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"), cReset)
}

func printResponseHeaders(client *http.Client, targetURL string) {
	fmt.Printf("\n%s[Headers]%s\n", cCyan, cReset)

	resp, err := reconGET(client, targetURL)
	if err != nil {
		fmt.Printf("  %sERROR: %v%s\n", cRed, err, cReset)
		return
	}
	resp.Body.Close()

	names := make([]string, 0, len(resp.Header))
	for name := range resp.Header {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		for _, v := range resp.Header[name] {
			fmt.Printf("  %s: %s\n", name, v)
		}
	}
	if len(names) == 0 {
		fmt.Printf("  %s(no headers)%s\n", cGray, cReset)
	}
}

// --- Helpers ---

func statusColor(code int) string {
	switch {
	case code >= 400:
		return cRed
	case code >= 300:
		return cYellow
	default:
		return cGreen
	}
}

func sanitizeSnippet(s string) string {
	if len(s) > reconSnipLen {
		s = s[:reconSnipLen] + "..."
	}
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, s)
}

func sortedKeys(m map[int][]string) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
