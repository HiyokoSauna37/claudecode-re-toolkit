package orchestrator

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	mbBaseURL = "https://mb-api.abuse.ch/api/v1/"
	tfBaseURL = "https://threatfox-api.abuse.ch/api/v1/"
)

// MBClient provides MalwareBazaar API access.
type MBClient struct {
	AuthKey string
	Client  *http.Client
}

// TFClient provides ThreatFox API access.
type TFClient struct {
	AuthKey string
	Client  *http.Client
}

// NewMBClient creates a MalwareBazaar client.
func NewMBClient(authKey string) *MBClient {
	return &MBClient{
		AuthKey: authKey,
		Client:  &http.Client{Timeout: 30 * time.Second},
	}
}

// NewTFClient creates a ThreatFox client.
func NewTFClient(authKey string) *TFClient {
	return &TFClient{
		AuthKey: authKey,
		Client:  &http.Client{Timeout: 30 * time.Second},
	}
}

// --- MalwareBazaar ---

func (m *MBClient) post(params url.Values) (map[string]interface{}, error) {
	req, err := http.NewRequest("POST", mbBaseURL, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("MB create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if m.AuthKey != "" {
		req.Header.Set("Auth-Key", m.AuthKey)
	}

	resp, err := m.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("MB API request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("MB API HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	if errMsg, ok := result["error"]; ok {
		return nil, fmt.Errorf("MB API error: %v", errMsg)
	}
	return result, nil
}

// Download downloads a sample from MalwareBazaar by SHA256 hash.
// Returns the path to the downloaded ZIP file (encrypted with password "infected").
func (m *MBClient) Download(sha256, outputDir string) (string, error) {
	params := url.Values{
		"query":       {"get_file"},
		"sha256_hash": {sha256},
	}

	req, err := http.NewRequest("POST", mbBaseURL, strings.NewReader(params.Encode()))
	if err != nil {
		return "", fmt.Errorf("MB create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if m.AuthKey != "" {
		req.Header.Set("Auth-Key", m.AuthKey)
	}

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("MB download request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return "", fmt.Errorf("MB API 401 Unauthorized: ABUSECH_AUTH_KEY required for downloads")
	}
	if resp.StatusCode == 404 {
		return "", fmt.Errorf("sample not found on MalwareBazaar: %s", sha256)
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("MB API HTTP %d: %s", resp.StatusCode, string(body))
	}

	// Read first 2 bytes to check ZIP magic (PK = 0x50 0x4B)
	// MalwareBazaar may return Content-Type: application/json even for ZIP downloads
	header := make([]byte, 2)
	_, err = io.ReadFull(resp.Body, header)
	if err != nil {
		return "", fmt.Errorf("read response header: %w", err)
	}
	if header[0] != 0x50 || header[1] != 0x4B {
		// Not a ZIP — try to read as JSON error, never dump binary to terminal
		rest, _ := io.ReadAll(resp.Body)
		full := append(header, rest...)
		// Attempt JSON parse for structured error
		var errResp map[string]interface{}
		if json.Unmarshal(full, &errResp) == nil {
			if msg, ok := errResp["query_status"]; ok {
				return "", fmt.Errorf("MB API error: %v", msg)
			}
		}
		// Non-JSON, non-ZIP: show size and first bytes as hex (never raw binary)
		preview := full
		if len(preview) > 32 {
			preview = preview[:32]
		}
		return "", fmt.Errorf("MB API unexpected response (%d bytes, starts with %x)", len(full), preview)
	}

	// Save to output directory (prepend the 2 header bytes we already read)
	outPath := outputDir + "/" + sha256 + ".zip"
	f, err := os.Create(outPath)
	if err != nil {
		return "", fmt.Errorf("create output file: %w", err)
	}
	defer f.Close()

	// Write the 2-byte header first
	if _, err := f.Write(header); err != nil {
		return "", fmt.Errorf("write header: %w", err)
	}
	n, err := io.Copy(f, resp.Body)
	if err != nil {
		return "", fmt.Errorf("save download: %w", err)
	}

	fmt.Printf("[+] Downloaded %s (%d bytes)\n", outPath, n+2)
	fmt.Printf("[+] ZIP password: infected\n")
	return outPath, nil
}

// HashLookup queries MalwareBazaar by hash (SHA256/MD5/SHA1).
func (m *MBClient) HashLookup(hash string) {
	params := url.Values{
		"query": {"get_info"},
		"hash":  {hash},
	}
	data, err := m.post(params)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	printMBResult(data)
}

// SigLookup queries MalwareBazaar by signature/family name.
func (m *MBClient) SigLookup(sig string) {
	params := url.Values{
		"query":          {"get_siginfo"},
		"signature":      {sig},
		"limit":          {"10"},
	}
	data, err := m.post(params)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	printMBList(data)
}

// TagLookup queries MalwareBazaar by tag.
func (m *MBClient) TagLookup(tag string) {
	params := url.Values{
		"query": {"get_taginfo"},
		"tag":   {tag},
		"limit": {"10"},
	}
	data, err := m.post(params)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	printMBList(data)
}

func printMBResult(data map[string]interface{}) {
	status := strVal(data, "query_status")
	if status != "ok" && status != "hash_not_found" {
		fmt.Printf("Query status: %s\n", status)
	}
	if status == "hash_not_found" || status == "no_results" {
		fmt.Println("Not found on MalwareBazaar")
		return
	}

	// Single result (get_info returns "data" as array with one element)
	dataArr, ok := data["data"].([]interface{})
	if !ok || len(dataArr) == 0 {
		fmt.Println("No data returned")
		return
	}

	for _, item := range dataArr {
		entry, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		printMBEntry(entry)
	}
}

func printMBList(data map[string]interface{}) {
	status := strVal(data, "query_status")
	if status == "no_results" || status == "tag_not_found" || status == "signature_not_found" {
		fmt.Println("No results found")
		return
	}
	if status != "ok" {
		fmt.Printf("Query status: %s\n", status)
		return
	}

	dataArr, ok := data["data"].([]interface{})
	if !ok || len(dataArr) == 0 {
		fmt.Println("No data returned")
		return
	}

	fmt.Printf("Found %d results:\n\n", len(dataArr))
	for i, item := range dataArr {
		entry, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		fmt.Printf("--- [%d] ---\n", i+1)
		printMBEntry(entry)
		fmt.Println()
	}
}

func printMBEntry(e map[string]interface{}) {
	fmt.Printf("SHA256:    %s\n", strVal(e, "sha256_hash"))
	fmt.Printf("MD5:       %s\n", strVal(e, "md5_hash"))
	fmt.Printf("SHA1:      %s\n", strVal(e, "sha1_hash"))
	fmt.Printf("Filename:  %s\n", strVal(e, "file_name"))
	fmt.Printf("FileType:  %s\n", strVal(e, "file_type"))
	fmt.Printf("FileSize:  %v bytes\n", e["file_size"])
	fmt.Printf("Signature: %s\n", strVal(e, "signature"))
	fmt.Printf("Reporter:  %s\n", strVal(e, "reporter"))
	fmt.Printf("Date:      %s\n", strVal(e, "first_seen"))

	if tags, ok := e["tags"]; ok && tags != nil {
		fmt.Printf("Tags:      %v\n", tags)
	}

	fmt.Printf("Link:      https://bazaar.abuse.ch/sample/%s/\n", strVal(e, "sha256_hash"))
}

// --- ThreatFox ---

func (t *TFClient) post(payload map[string]interface{}) (map[string]interface{}, error) {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequest("POST", tfBaseURL, strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, fmt.Errorf("TF create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if t.AuthKey != "" {
		req.Header.Set("Auth-Key", t.AuthKey)
	}

	resp, err := t.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("TF API request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("TF API HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	if errMsg, ok := result["error"]; ok {
		return nil, fmt.Errorf("TF API error: %v", errMsg)
	}
	return result, nil
}

// IOCSearch searches ThreatFox by IOC (IP:port, domain, URL).
func (t *TFClient) IOCSearch(ioc string) {
	payload := map[string]interface{}{
		"query":      "search_ioc",
		"search_term": ioc,
	}
	data, err := t.post(payload)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	printTFResult(data)
}

// HashSearch searches ThreatFox by malware hash.
func (t *TFClient) HashSearch(hash string) {
	payload := map[string]interface{}{
		"query": "search_hash",
		"hash":  hash,
	}
	data, err := t.post(payload)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	printTFResult(data)
}

// TagSearch searches ThreatFox by tag with configurable limit (1-1000).
func (t *TFClient) TagSearch(tag string, limit int) {
	if limit <= 0 || limit > 1000 {
		limit = 10
	}
	payload := map[string]interface{}{
		"query": "taginfo",
		"tag":   tag,
		"limit": float64(limit),
	}
	data, err := t.post(payload)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	printTFResult(data)
}

// MalwareSearch searches ThreatFox by malware family with configurable limit (1-1000).
func (t *TFClient) MalwareSearch(family string, limit int) {
	if limit <= 0 || limit > 1000 {
		limit = 10
	}
	payload := map[string]interface{}{
		"query":   "malwareinfo",
		"malware": family,
		"limit":   float64(limit),
	}
	data, err := t.post(payload)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	printTFResult(data)
}

// TagSearchData returns structured tag search results (used by c2profile and cluster).
func (t *TFClient) TagSearchData(tag string, limit int) ([]map[string]interface{}, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	payload := map[string]interface{}{
		"query": "taginfo",
		"tag":   tag,
		"limit": float64(limit),
	}
	data, err := t.post(payload)
	if err != nil {
		return nil, err
	}
	if strVal(data, "query_status") != "ok" {
		return nil, nil
	}
	arr, ok := data["data"].([]interface{})
	if !ok {
		return nil, nil
	}
	results := make([]map[string]interface{}, 0, len(arr))
	for _, item := range arr {
		if m, ok := item.(map[string]interface{}); ok {
			results = append(results, m)
		}
	}
	return results, nil
}

func printTFResult(data map[string]interface{}) {
	status := strVal(data, "query_status")
	if status == "no_result" || status == "ioc_not_found" {
		fmt.Println("No results found on ThreatFox")
		return
	}
	if status != "ok" {
		fmt.Printf("Query status: %s\n", status)
		return
	}

	dataArr, ok := data["data"].([]interface{})
	if !ok || len(dataArr) == 0 {
		fmt.Println("No data returned")
		return
	}

	fmt.Printf("Found %d results:\n\n", len(dataArr))
	for i, item := range dataArr {
		entry, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		fmt.Printf("--- [%d] ---\n", i+1)
		printTFEntry(entry)
		fmt.Println()
	}
}

func printTFEntry(e map[string]interface{}) {
	fmt.Printf("IOC:         %s\n", strVal(e, "ioc"))
	fmt.Printf("Type:        %s\n", strVal(e, "ioc_type"))
	fmt.Printf("Threat:      %s\n", strVal(e, "threat_type"))
	fmt.Printf("Malware:     %s\n", strVal(e, "malware"))
	fmt.Printf("Printable:   %s\n", strVal(e, "malware_printable"))
	fmt.Printf("Confidence:  %v%%\n", e["confidence_level"])
	fmt.Printf("Reporter:    %s\n", strVal(e, "reporter"))
	fmt.Printf("First seen:  %s\n", strVal(e, "first_seen"))
	fmt.Printf("Last seen:   %s\n", strVal(e, "last_seen"))

	if tags, ok := e["tags"]; ok && tags != nil {
		fmt.Printf("Tags:        %v\n", tags)
	}
	if ref := strVal(e, "reference"); ref != "" {
		fmt.Printf("Reference:   %s\n", ref)
	}

	id := strVal(e, "id")
	if id != "" {
		fmt.Printf("Link:        https://threatfox.abuse.ch/ioc/%s/\n", id)
	}
}

// --- ThreatFox JSON output ---

// IOCSearchJSON returns ThreatFox IOC search results as JSON.
func (t *TFClient) IOCSearchJSON(ioc string) ([]byte, error) {
	data, err := t.post(map[string]interface{}{"query": "search_ioc", "search_term": ioc})
	if err != nil {
		return nil, err
	}
	return json.Marshal(data)
}

// HashSearchJSON returns ThreatFox hash search results as JSON.
func (t *TFClient) HashSearchJSON(hash string) ([]byte, error) {
	data, err := t.post(map[string]interface{}{"query": "search_hash", "hash": hash})
	if err != nil {
		return nil, err
	}
	return json.Marshal(data)
}

// TagSearchJSON returns ThreatFox tag search results as JSON.
func (t *TFClient) TagSearchJSON(tag string, limit int) ([]byte, error) {
	if limit <= 0 || limit > 1000 {
		limit = 10
	}
	data, err := t.post(map[string]interface{}{"query": "taginfo", "tag": tag, "limit": float64(limit)})
	if err != nil {
		return nil, err
	}
	return json.Marshal(data)
}

// MalwareSearchJSON returns ThreatFox malware search results as JSON.
func (t *TFClient) MalwareSearchJSON(family string, limit int) ([]byte, error) {
	if limit <= 0 || limit > 1000 {
		limit = 10
	}
	data, err := t.post(map[string]interface{}{"query": "malwareinfo", "malware": family, "limit": float64(limit)})
	if err != nil {
		return nil, err
	}
	return json.Marshal(data)
}

// --- MalwareBazaar JSON output ---

// HashLookupJSON returns MalwareBazaar hash lookup as JSON.
func (m *MBClient) HashLookupJSON(hash string) ([]byte, error) {
	data, err := m.post(url.Values{"query": {"get_info"}, "hash": {hash}})
	if err != nil {
		return nil, err
	}
	return json.Marshal(data)
}

// SigLookupJSON returns MalwareBazaar signature lookup as JSON.
func (m *MBClient) SigLookupJSON(sig string) ([]byte, error) {
	data, err := m.post(url.Values{"query": {"get_siginfo"}, "signature": {sig}, "limit": {"10"}})
	if err != nil {
		return nil, err
	}
	return json.Marshal(data)
}

// TagLookupJSON returns MalwareBazaar tag lookup as JSON.
func (m *MBClient) TagLookupJSON(tag string) ([]byte, error) {
	data, err := m.post(url.Values{"query": {"get_taginfo"}, "tag": {tag}, "limit": {"10"}})
	if err != nil {
		return nil, err
	}
	return json.Marshal(data)
}
