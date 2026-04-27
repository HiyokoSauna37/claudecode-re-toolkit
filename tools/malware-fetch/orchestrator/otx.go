package orchestrator

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const otxBaseURL = "https://otx.alienvault.com/api/v1"

// OTXClient provides AlienVault OTX API access (no key needed for read-only).
type OTXClient struct {
	Client *http.Client
}

func NewOTXClient() *OTXClient {
	return &OTXClient{Client: &http.Client{Timeout: 30 * time.Second}}
}

func (o *OTXClient) get(path string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", otxBaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := o.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		preview := string(body)
		if len(preview) > 200 {
			preview = preview[:200]
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, preview)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("JSON parse error: %w", err)
	}
	return result, nil
}

// --- Types ---

// OTXPulseInfo holds pulse metadata.
type OTXPulseInfo struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Author          string   `json:"author"`
	Created         string   `json:"created"`
	Tags            []string `json:"tags"`
	MalwareFamilies []string `json:"malware_families"`
	IndicatorCount  int      `json:"indicator_count"`
	References      []string `json:"references"`
}

// --- Domain / IP lookup ---

func (o *OTXClient) DomainLookup(domain string) {
	fmt.Printf("\n%s=== OTX Domain: %s ===%s\n", cCyan, domain, cReset)
	o.printPulses(o.lookupPulses("domain", domain))
}

func (o *OTXClient) IPLookup(ip string) {
	fmt.Printf("\n%s=== OTX IP: %s ===%s\n", cCyan, ip, cReset)
	o.printPulses(o.lookupPulses("IPv4", ip))
}

func (o *OTXClient) DomainLookupData(domain string) []OTXPulseInfo {
	return o.lookupPulses("domain", domain)
}

func (o *OTXClient) IPLookupData(ip string) []OTXPulseInfo {
	return o.lookupPulses("IPv4", ip)
}

// lookupPulses is the shared parser for both print and data variants.
func (o *OTXClient) lookupPulses(iocType, value string) []OTXPulseInfo {
	data, err := o.get(fmt.Sprintf("/indicators/%s/%s/general", iocType, value))
	if err != nil || data == nil {
		return nil
	}
	pi, ok := data["pulse_info"].(map[string]interface{})
	if !ok {
		return nil
	}
	pulses, _ := pi["pulses"].([]interface{})
	var results []OTXPulseInfo
	for _, p := range pulses {
		pm, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		authorName := ""
		if author, ok := pm["author"].(map[string]interface{}); ok {
			authorName, _ = author["username"].(string)
		}
		results = append(results, OTXPulseInfo{
			ID:              fmt.Sprintf("%v", pm["id"]),
			Name:            fmt.Sprintf("%v", pm["name"]),
			Author:          authorName,
			Created:         fmt.Sprintf("%v", pm["created"]),
			Tags:            toStringSlice(pm["tags"]),
			MalwareFamilies: toStringSlice(pm["malware_families"]),
			IndicatorCount:  toInt(pm["indicator_count"]),
			References:      toStringSlice(pm["references"]),
		})
	}
	return results
}

func (o *OTXClient) printPulses(pulses []OTXPulseInfo) {
	fmt.Printf("  Pulses: %d\n", len(pulses))
	for _, p := range pulses {
		fmt.Printf("\n  %s[%s]%s %s\n", cCyan, p.ID, cReset, p.Name)
		fmt.Printf("    Author: %s  Created: %s\n", p.Author, p.Created)
		fmt.Printf("    Indicators: %d\n", p.IndicatorCount)
		if len(p.Tags) > 0 {
			fmt.Printf("    Tags: %s\n", strings.Join(p.Tags, ", "))
		}
		if len(p.MalwareFamilies) > 0 {
			fmt.Printf("    %sMalware: %s%s\n", cRed, strings.Join(p.MalwareFamilies, ", "), cReset)
		}
	}
	if len(pulses) == 0 {
		fmt.Printf("  %s(no pulses found)%s\n", cGray, cReset)
	}
}

// --- Pulse detail ---

// getPulseData fetches pulse JSON once (shared by pulse/hashes/urls/stats).
func (o *OTXClient) getPulseData(pulseID string) (map[string]interface{}, []interface{}) {
	data, err := o.get("/pulses/" + pulseID)
	if err != nil {
		fmt.Printf("  %sError: %v%s\n", cRed, err, cReset)
		return nil, nil
	}
	indicators, _ := data["indicators"].([]interface{})
	return data, indicators
}

func (o *OTXClient) PulseLookup(pulseID string) {
	data, indicators := o.getPulseData(pulseID)
	if data == nil {
		return
	}

	fmt.Printf("\n%s=== OTX Pulse: %s ===%s\n", cCyan, pulseID, cReset)
	fmt.Printf("  Name:    %s\n", data["name"])
	fmt.Printf("  Author:  %s\n", data["author_name"])
	fmt.Printf("  Created: %s\n", data["created"])
	if tags := toStringSlice(data["tags"]); len(tags) > 0 {
		fmt.Printf("  Tags:    %s\n", strings.Join(tags, ", "))
	}
	if refs := toStringSlice(data["references"]); len(refs) > 0 {
		for _, r := range refs {
			fmt.Printf("  Ref:     %s\n", r)
		}
	}
	fmt.Printf("  Indicators: %d\n", len(indicators))

	typeCounts := countByField(indicators, "type")
	fmt.Printf("\n  %sType breakdown:%s\n", cCyan, cReset)
	for t, c := range typeCounts {
		fmt.Printf("    %-20s %d\n", t, c)
	}
}

func (o *OTXClient) PulseHashes(pulseID string) {
	_, indicators := o.getPulseData(pulseID)
	if indicators == nil {
		return
	}

	fmt.Printf("\n%s=== Hashes from pulse %s ===%s\n", cCyan, pulseID, cReset)
	count := 0
	for _, ind := range indicators {
		im, ok := ind.(map[string]interface{})
		if !ok {
			continue
		}
		t := fmt.Sprintf("%v", im["type"])
		if isHashType(t) {
			count++
			fmt.Printf("  %s  (%s)\n", im["indicator"], t)
		}
	}
	if count == 0 {
		fmt.Printf("  %s(no hashes)%s\n", cGray, cReset)
	}
}

func (o *OTXClient) PulseURLs(pulseID string) {
	_, indicators := o.getPulseData(pulseID)
	if indicators == nil {
		return
	}

	fmt.Printf("\n%s=== URLs from pulse %s ===%s\n", cCyan, pulseID, cReset)
	count := 0
	for _, ind := range indicators {
		im, ok := ind.(map[string]interface{})
		if !ok {
			continue
		}
		if fmt.Sprintf("%v", im["type"]) == "URL" {
			count++
			fmt.Printf("  %s\n", im["indicator"])
		}
	}
	if count == 0 {
		fmt.Printf("  %s(no URLs)%s\n", cGray, cReset)
	}
}

func (o *OTXClient) PulseStats(pulseID string) {
	data, indicators := o.getPulseData(pulseID)
	if data == nil {
		return
	}

	fmt.Printf("\n%s=== Pulse Stats: %s ===%s\n", cCyan, pulseID, cReset)
	fmt.Printf("  Name: %s\n", data["name"])
	fmt.Printf("  Total indicators: %d\n\n", len(indicators))

	typeCounts := countByField(indicators, "type")
	tldCounts := make(map[string]int)
	pathCounts := make(map[string]int)
	urlDomainSet := make(map[string]bool)

	for _, ind := range indicators {
		im, ok := ind.(map[string]interface{})
		if !ok {
			continue
		}
		iType := fmt.Sprintf("%v", im["type"])
		iVal := fmt.Sprintf("%v", im["indicator"])

		if iType == "hostname" {
			if parts := strings.Split(iVal, "."); len(parts) >= 2 {
				tldCounts["."+parts[len(parts)-1]]++
			}
		}
		if iType == "URL" {
			if parsed, err := url.Parse(iVal); err == nil {
				path := parsed.Path
				if path == "" {
					path = "/"
				}
				pathCounts[path]++
				urlDomainSet[parsed.Host] = true
			}
		}
	}

	printCountMap("Type breakdown", typeCounts, 0)
	printSortedCountMap("TLD distribution (hostnames)", tldCounts, 10)
	printSortedCountMap("Top URL paths", pathCounts, 15)

	if len(urlDomainSet) > 0 {
		fmt.Printf("\n  Unique domains in URLs: %d\n", len(urlDomainSet))
	}
}

// --- Helpers ---

func isHashType(t string) bool {
	return strings.Contains(t, "SHA") || strings.Contains(t, "MD5") || strings.Contains(strings.ToLower(t), "hash")
}

func countByField(items []interface{}, field string) map[string]int {
	counts := make(map[string]int)
	for _, item := range items {
		im, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		counts[fmt.Sprintf("%v", im[field])]++
	}
	return counts
}

type countEntry struct {
	Key   string
	Count int
}

func sortedCounts(m map[string]int) []countEntry {
	entries := make([]countEntry, 0, len(m))
	for k, v := range m {
		entries = append(entries, countEntry{k, v})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Count > entries[j].Count })
	return entries
}

func printCountMap(title string, m map[string]int, limit int) {
	fmt.Printf("  %s%s:%s\n", cCyan, title, cReset)
	entries := sortedCounts(m)
	for i, e := range entries {
		if limit > 0 && i >= limit {
			break
		}
		fmt.Printf("    %-20s %d\n", e.Key, e.Count)
	}
}

func printSortedCountMap(title string, m map[string]int, limit int) {
	if len(m) == 0 {
		return
	}
	fmt.Printf("\n  %s%s:%s\n", cCyan, title, cReset)
	entries := sortedCounts(m)
	for i, e := range entries {
		if limit > 0 && i >= limit {
			break
		}
		fmt.Printf("    %-40s %d\n", e.Key, e.Count)
	}
}

func toStringSlice(v interface{}) []string {
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	var result []string
	for _, item := range arr {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

// --- JSON output methods ---

// DomainLookupJSON returns OTX domain pulses as JSON.
func (o *OTXClient) DomainLookupJSON(domain string) ([]byte, error) {
	pulses := o.DomainLookupData(domain)
	return json.Marshal(map[string]interface{}{
		"domain":      domain,
		"pulse_count": len(pulses),
		"pulses":      pulses,
	})
}

// IPLookupJSON returns OTX IP pulses as JSON.
func (o *OTXClient) IPLookupJSON(ip string) ([]byte, error) {
	pulses := o.IPLookupData(ip)
	return json.Marshal(map[string]interface{}{
		"ip":          ip,
		"pulse_count": len(pulses),
		"pulses":      pulses,
	})
}
