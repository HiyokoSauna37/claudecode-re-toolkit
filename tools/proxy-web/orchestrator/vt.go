package orchestrator

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"
)

const vtBaseURL = "https://www.virustotal.com/api/v3"

// VTResult holds VirusTotal check results.
type VTResult struct {
	Detected  int    `json:"detected"`
	Total     int    `json:"total"`
	Permalink string `json:"permalink"`
	ScanDate  string `json:"scan_date"`
}

// VTClient provides VirusTotal API access.
type VTClient struct {
	APIKey string
	Client *http.Client
}

// NewVTClient creates a VT client.
func NewVTClient(apiKey string) *VTClient {
	return &VTClient{
		APIKey: apiKey,
		Client: &http.Client{Timeout: 15 * time.Second},
	}
}

func (v *VTClient) get(path string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", vtBaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-apikey", v.APIKey)

	resp, err := v.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == 404 {
		return nil, nil // Not found
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("VT API error %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// Check queries VT for a file hash and returns detection stats.
func (v *VTClient) Check(hash string) (*VTResult, error) {
	if v.APIKey == "" {
		return nil, fmt.Errorf("VT API key not set")
	}

	data, err := v.get("/files/" + hash)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return &VTResult{Detected: 0, Total: 0}, nil
	}

	attrs := nested(data, "data", "attributes")
	stats := nestedMap(attrs, "last_analysis_stats")

	malicious := intVal(stats, "malicious")
	total := 0
	for _, val := range stats {
		total += toInt(val)
	}

	return &VTResult{
		Detected:  malicious,
		Total:     total,
		Permalink: fmt.Sprintf("https://www.virustotal.com/gui/file/%s", hash),
		ScanDate:  time.Now().Format(time.RFC3339),
	}, nil
}

// CheckPrint prints a human-readable check result.
func (v *VTClient) CheckPrint(hash string) {
	data, err := v.get("/files/" + hash)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	if data == nil {
		fmt.Println("Hash not found on VirusTotal")
		return
	}

	attrs := nested(data, "data", "attributes")
	stats := nestedMap(attrs, "last_analysis_stats")

	malicious := intVal(stats, "malicious")
	total := 0
	for _, val := range stats {
		total += toInt(val)
	}

	fmt.Printf("Detection: %d/%d\n", malicious, total)
	fmt.Printf("Type: %s\n", strVal(attrs, "type_description"))
	fmt.Printf("Name: %s\n", strVal(attrs, "meaningful_name"))

	tags := strSlice(attrs, "tags")
	if len(tags) > 0 {
		fmt.Printf("Tags: %v\n", tags)
	}

	threat := nestedMap(attrs, "popular_threat_classification")
	label := strVal(threat, "suggested_threat_label")
	if label != "" {
		fmt.Printf("Threat label: %s\n", label)
	}

	fmt.Printf("Link: https://www.virustotal.com/gui/file/%s\n", hash)

	// Top detections
	results := nestedMap(attrs, "last_analysis_results")
	type detection struct {
		Engine string
		Result string
	}
	var detections []detection
	for engine, val := range results {
		vm, ok := val.(map[string]interface{})
		if !ok {
			continue
		}
		if strVal(vm, "category") == "malicious" {
			r := strVal(vm, "result")
			if r != "" {
				detections = append(detections, detection{engine, r})
			}
		}
	}
	sort.Slice(detections, func(i, j int) bool {
		return detections[i].Engine < detections[j].Engine
	})

	if len(detections) > 0 {
		limit := 15
		if len(detections) < limit {
			limit = len(detections)
		}
		fmt.Printf("\nTop detections (%d engines):\n", len(detections))
		for _, d := range detections[:limit] {
			fmt.Printf("  %s: %s\n", d.Engine, d.Result)
		}
	}
}

// BehaviorPrint prints behavioral analysis from VT.
func (v *VTClient) BehaviorPrint(hash string) {
	data, err := v.get("/files/" + hash + "/behaviour_summary")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	if data == nil {
		fmt.Println("No behavior data found")
		return
	}

	bdata := nestedMap(data, "data")

	printSection := func(key, title string) {
		if items, ok := bdata[key]; ok {
			if arr, ok := items.([]interface{}); ok && len(arr) > 0 {
				fmt.Printf("\n=== %s ===\n", title)
				limit := 20
				if len(arr) < limit {
					limit = len(arr)
				}
				for _, item := range arr[:limit] {
					fmt.Printf("  %v\n", item)
				}
			}
		}
	}

	// DNS
	if dns, ok := bdata["dns_lookups"]; ok {
		if items, ok := dns.([]interface{}); ok && len(items) > 0 {
			fmt.Println("=== DNS Lookups ===")
			for _, item := range items {
				m, _ := item.(map[string]interface{})
				fmt.Printf("  %s -> %v\n", strVal(m, "hostname"), m["resolved_ips"])
			}
		}
	}

	// HTTP
	if http, ok := bdata["http_conversations"]; ok {
		if items, ok := http.([]interface{}); ok && len(items) > 0 {
			fmt.Println("\n=== HTTP Conversations ===")
			for _, item := range items {
				m, _ := item.(map[string]interface{})
				fmt.Printf("  %s %s [%v]\n", strVal(m, "request_method"), strVal(m, "url"), m["response_status_code"])
			}
		}
	}

	// IP traffic
	if ip, ok := bdata["ip_traffic"]; ok {
		if items, ok := ip.([]interface{}); ok && len(items) > 0 {
			fmt.Println("\n=== IP Traffic ===")
			for _, item := range items {
				m, _ := item.(map[string]interface{})
				fmt.Printf("  %s:%v (%s)\n", strVal(m, "destination_ip"), m["destination_port"], strVal(m, "transport_layer_protocol"))
			}
		}
	}

	printSection("processes_created", "Processes Created")
	printSection("command_executions", "Commands Executed")
	printSection("files_opened", "Files Opened")
	printSection("files_written", "Files Written")
	printSection("files_deleted", "Files Deleted")
	printSection("files_dropped", "Files Dropped")
	printSection("mutexes_created", "Mutexes Created")
	printSection("modules_loaded", "Modules Loaded")
	printSection("services_started", "Services Started")
	printSection("services_created", "Services Created")

	// Registry (special format)
	for _, key := range []string{"registry_keys_set", "registry_keys_opened", "registry_keys_deleted"} {
		if items, ok := bdata[key]; ok {
			if arr, ok := items.([]interface{}); ok && len(arr) > 0 {
				fmt.Printf("\n=== %s ===\n", keyToTitle(key))
				for _, item := range arr {
					switch val := item.(type) {
					case map[string]interface{}:
						fmt.Printf("  %s = %v\n", strVal(val, "key"), val["value"])
					default:
						fmt.Printf("  %v\n", val)
					}
				}
			}
		}
	}
}

// LookupPrint prints detailed file information.
func (v *VTClient) LookupPrint(hash string) {
	data, err := v.get("/files/" + hash)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	if data == nil {
		fmt.Println("Hash not found on VirusTotal")
		return
	}

	attrs := nested(data, "data", "attributes")
	stats := nestedMap(attrs, "last_analysis_stats")

	malicious := intVal(stats, "malicious") + intVal(stats, "suspicious")
	total := 0
	for _, val := range stats {
		total += toInt(val)
	}

	fmt.Printf("Detection: %d/%d\n", malicious, total)
	fmt.Printf("Type: %s\n", strVal(attrs, "type_description"))
	fmt.Printf("Size: %v bytes\n", attrs["size"])
	fmt.Printf("Tags: %v\n", strSlice(attrs, "tags"))

	names := strSlice(attrs, "names")
	if len(names) > 5 {
		names = names[:5]
	}
	fmt.Printf("Names: %v\n", names)

	pop := nestedMap(attrs, "popular_threat_classification")
	fmt.Printf("Classification: %s\n", strVal(pop, "suggested_threat_label"))

	if fam, ok := pop["popular_threat_name"]; ok {
		if items, ok := fam.([]interface{}); ok {
			var families []string
			for i, item := range items {
				if i >= 5 {
					break
				}
				m, _ := item.(map[string]interface{})
				families = append(families, fmt.Sprintf("%s(%v)", strVal(m, "value"), m["count"]))
			}
			fmt.Printf("Families: %v\n", families)
		}
	}

	fmt.Printf("Link: https://www.virustotal.com/gui/file/%s\n", hash)
}

// --- JSON helpers (same pattern as vt-checker) ---

func nested(m map[string]interface{}, keys ...string) map[string]interface{} {
	cur := m
	for _, k := range keys {
		v, ok := cur[k]
		if !ok {
			return map[string]interface{}{}
		}
		cur, ok = v.(map[string]interface{})
		if !ok {
			return map[string]interface{}{}
		}
	}
	return cur
}

func nestedMap(m map[string]interface{}, key string) map[string]interface{} {
	v, ok := m[key]
	if !ok {
		return map[string]interface{}{}
	}
	result, ok := v.(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return result
}

func strVal(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Sprintf("%v", v)
	}
	return s
}

func intVal(m map[string]interface{}, key string) int {
	return toInt(m[key])
}

func toInt(v interface{}) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	default:
		return 0
	}
}

func strSlice(m map[string]interface{}, key string) []string {
	v, ok := m[key]
	if !ok {
		return nil
	}
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	var out []string
	for _, item := range arr {
		out = append(out, fmt.Sprintf("%v", item))
	}
	return out
}

func keyToTitle(key string) string {
	parts := make([]byte, 0, len(key))
	upper := true
	for i := 0; i < len(key); i++ {
		if key[i] == '_' {
			parts = append(parts, ' ')
			upper = true
		} else if upper {
			if key[i] >= 'a' && key[i] <= 'z' {
				parts = append(parts, key[i]-32)
			} else {
				parts = append(parts, key[i])
			}
			upper = false
		} else {
			parts = append(parts, key[i])
		}
	}
	return string(parts)
}
