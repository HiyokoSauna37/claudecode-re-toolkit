package orchestrator

import (
	"encoding/csv"
	"fmt"
	"os"
	"strings"
)

// NetLogCategory represents the classification of a network request.
type NetLogCategory int

const (
	CatTarget       NetLogCategory = iota
	CatBlockchainRPC
	CatC2API
	CatTracker
	CatCDN
	CatUnknown
)

func (c NetLogCategory) String() string {
	names := [...]string{"TARGET", "BLOCKCHAIN_RPC", "C2_API", "TRACKER", "CDN", "UNKNOWN"}
	if int(c) < len(names) {
		return names[c]
	}
	return "UNKNOWN"
}

func (c NetLogCategory) Color() string {
	colors := [...]string{cCyan, cRed, cRed, cYellow, cGray, cReset}
	if int(c) < len(colors) {
		return colors[c]
	}
	return cReset
}

func (c NetLogCategory) Alert() string {
	switch c {
	case CatBlockchainRPC:
		return "!! C2 config via blockchain"
	case CatC2API:
		return "!! Suspected C2 communication"
	case CatTracker:
		return "Tracking/beacons"
	default:
		return ""
	}
}

// ClassifiedRequest is a network log entry with classification.
type ClassifiedRequest struct {
	Timestamp   string
	Method      string
	URL         string
	Domain      string
	StatusCode  string
	ContentType string
	Category    NetLogCategory
	Reason      string
}

// --- Detection rules ---

var blockchainDomains = []string{
	// Ethereum
	"cloudflare-eth.com", "eth.llamarpc.com", "rpc.ankr.com",
	"1rpc.io", "eth.drpc.org",
	// Polygon
	"polygon.drpc.org", "polygon-bor-rpc.publicnode.com",
	"polygon.lava.build", "polygon.rpc.subquery.network",
	"polygon.nodies.app", "polygon-pokt.nodies.app",
	"polygon.gateway.tenderly.co", "gateway.tenderly.co",
	"api.zan.top",
	// BSC
	"bsc-dataseed", "bsc.publicnode.com",
	// Generic RPC providers
	"infura.io", "alchemy.com", "moralis.io", "quicknode.com",
	"tatum.io", "getblock.io", "chainstack.com",
}

var cdnDomains = []string{
	"cloudflare.com", "cdnjs.cloudflare.com",
	"googleapis.com", "gstatic.com",
	"wikimedia.org", "wikipedia.org",
	"jsdelivr.net", "unpkg.com",
	"bootstrapcdn.com", "fontawesome.com",
	"jquery.com", "cloudfront.net",
	"akamaized.net", "fastly.net",
}

var trackerPaths = []string{
	"/log.php", "/pixel", "/beacon", "/track",
	"/collect", "/analytics", "/stat",
}

// --- Classification engine ---

func classifyRequest(r ClassifiedRequest, targetLower string, isExternal bool) (NetLogCategory, string) {
	domainLower := strings.ToLower(r.Domain)
	urlLower := strings.ToLower(r.URL)

	// 1. Blockchain RPC (highest priority — always suspicious in web page context)
	for _, bd := range blockchainDomains {
		if strings.Contains(domainLower, bd) {
			return CatBlockchainRPC, identifyChain(domainLower) + " RPC — possible C2 config retrieval via smart contract"
		}
	}
	if r.Method == "POST" && containsAny(urlLower, "/matic", "/eth", "polygon", "ethereum") {
		return CatBlockchainRPC, "JSON-RPC POST to blockchain endpoint"
	}

	// 2. CDN (before tracker — CDN-hosted images are not trackers)
	for _, cd := range cdnDomains {
		if strings.Contains(domainLower, cd) {
			return CatCDN, "Legitimate CDN/asset"
		}
	}

	// 3. Tracker / beacon
	for _, tp := range trackerPaths {
		if strings.Contains(urlLower, tp) {
			return CatTracker, "Tracking/beacon endpoint"
		}
	}
	if isImageType(r.ContentType) {
		return CatTracker, fmt.Sprintf("Tracking pixel (%s)", r.ContentType)
	}

	// 4. Target domain
	if targetLower != "" && strings.Contains(domainLower, targetLower) {
		return CatTarget, "Target domain"
	}

	// 5. C2 API heuristics (external domain only)
	if isExternal {
		if strings.Contains(urlLower, "?q=") {
			return CatC2API, "Encrypted query parameter to external domain"
		}
		if strings.Contains(urlLower, "/api/") {
			return CatC2API, "External API call"
		}
		// External JS with query params (e.g., cf.js?v=2) — more likely loader than static asset
		if strings.HasSuffix(urlLower, ".js") || (strings.Contains(urlLower, ".js?") && !strings.Contains(domainLower, "cdn")) {
			return CatC2API, "External JavaScript loader"
		}
	}

	return CatUnknown, ""
}

func identifyChain(domain string) string {
	switch {
	case strings.Contains(domain, "polygon") || strings.Contains(domain, "matic"):
		return "Polygon(MATIC)"
	case strings.Contains(domain, "bsc"):
		return "BSC"
	case strings.Contains(domain, "eth"):
		return "Ethereum"
	default:
		return "Blockchain"
	}
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func isImageType(ct string) bool {
	ctLower := strings.ToLower(ct)
	return strings.Contains(ctLower, "image/gif") || strings.Contains(ctLower, "image/png")
}

// --- CSV parsing ---

func ClassifyNetworkLog(csvPath, targetDomain string) []ClassifiedRequest {
	f, err := os.Open(csvPath)
	if err != nil {
		fmt.Printf("%sError opening %s: %v%s\n", cRed, csvPath, err, cReset)
		return nil
	}
	defer f.Close()

	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		fmt.Printf("%sCSV parse error: %v%s\n", cRed, err, cReset)
		return nil
	}
	if len(records) < 2 {
		return nil
	}

	cols := make(map[string]int)
	for i, h := range records[0] {
		cols[strings.TrimSpace(h)] = i
	}

	targetLower := strings.ToLower(targetDomain)

	var results []ClassifiedRequest
	for _, row := range records[1:] {
		r := ClassifiedRequest{
			Timestamp:   colVal(row, cols, "Timestamp"),
			Method:      colVal(row, cols, "Method"),
			URL:         colVal(row, cols, "URL"),
			Domain:      colVal(row, cols, "Domain"),
			StatusCode:  colVal(row, cols, "StatusCode"),
			ContentType: colVal(row, cols, "ContentType"),
		}
		if r.URL == "" && r.Domain == "" {
			continue
		}

		isExternal := targetLower != "" && !strings.Contains(strings.ToLower(r.Domain), targetLower)
		r.Category, r.Reason = classifyRequest(r, targetLower, isExternal)
		results = append(results, r)
	}
	return results
}

func colVal(row []string, cols map[string]int, name string) string {
	idx, ok := cols[name]
	if !ok || idx >= len(row) {
		return ""
	}
	return strings.TrimSpace(row[idx])
}

// --- Output ---

func PrintClassifiedLog(results []ClassifiedRequest) {
	if len(results) == 0 {
		fmt.Printf("  %s(no network requests)%s\n", cGray, cReset)
		return
	}

	counts := make(map[NetLogCategory]int)
	for _, r := range results {
		counts[r.Category]++
	}

	fmt.Printf("\n%s=== Network Log Classification ===%s\n", cCyan, cReset)
	fmt.Printf("  Total requests: %d\n\n", len(results))

	// Summary
	fmt.Printf("  %sSummary:%s\n", cCyan, cReset)
	for _, cat := range []NetLogCategory{CatBlockchainRPC, CatC2API, CatTracker, CatTarget, CatCDN, CatUnknown} {
		if c := counts[cat]; c > 0 {
			fmt.Printf("    %s%-15s %d%s", cat.Color(), cat.String(), c, cReset)
			if alert := cat.Alert(); alert != "" {
				fmt.Printf("  %s%s%s", cat.Color(), alert, cReset)
			}
			fmt.Println()
		}
	}

	// Details
	fmt.Printf("\n  %sDetails:%s\n", cCyan, cReset)
	for _, r := range results {
		short := r.URL
		if len(short) > 80 {
			short = short[:77] + "..."
		}
		fmt.Printf("    %s[%-15s]%s %s %s %s", r.Category.Color(), r.Category.String(), cReset, r.Method, r.StatusCode, short)
		if r.Reason != "" && (r.Category == CatBlockchainRPC || r.Category == CatC2API) {
			fmt.Printf("\n      %s\u21b3 %s%s", r.Category.Color(), r.Reason, cReset)
		}
		fmt.Println()
	}
}

func RunNetLogClassify(csvPath, targetDomain string) {
	PrintClassifiedLog(ClassifyNetworkLog(csvPath, targetDomain))
}
