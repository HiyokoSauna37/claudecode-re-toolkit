package orchestrator

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	if m.AuthKey != "" {
		params.Set("auth_key", m.AuthKey)
	}

	resp, err := m.Client.PostForm(mbBaseURL, params)
	if err != nil {
		return nil, fmt.Errorf("MB API request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return result, nil
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
	if t.AuthKey != "" {
		payload["auth_key"] = t.AuthKey
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	resp, err := t.Client.Post(tfBaseURL, "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, fmt.Errorf("TF API request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
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

// TagSearch searches ThreatFox by tag.
func (t *TFClient) TagSearch(tag string) {
	payload := map[string]interface{}{
		"query": "tag",
		"tag":   tag,
		"limit": float64(10),
	}
	data, err := t.post(payload)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	printTFResult(data)
}

// MalwareSearch searches ThreatFox by malware family.
func (t *TFClient) MalwareSearch(family string) {
	payload := map[string]interface{}{
		"query":   "malwareinfo",
		"malware": family,
		"limit":   float64(10),
	}
	data, err := t.post(payload)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	printTFResult(data)
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
