package orchestrator

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

const vtBaseURL = "https://www.virustotal.com/api/v3"

// --- Types ---

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

// vtDetection represents a single engine detection.
type vtDetection struct {
	Engine string
	Result string
}

// NewVTClient creates a VT client.
func NewVTClient(apiKey string) *VTClient {
	return &VTClient{
		APIKey: apiKey,
		Client: &http.Client{Timeout: 15 * time.Second},
	}
}

// --- Low-level API ---

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
		return nil, nil
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

// --- File hash operations ---

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

	return &VTResult{
		Detected:  intVal(stats, "malicious"),
		Total:     statsTotal(stats),
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

	fmt.Printf("Detection: %d/%d\n", intVal(stats, "malicious"), statsTotal(stats))
	fmt.Printf("Type: %s\n", strVal(attrs, "type_description"))
	fmt.Printf("Name: %s\n", strVal(attrs, "meaningful_name"))

	if tags := strSlice(attrs, "tags"); len(tags) > 0 {
		fmt.Printf("Tags: %v\n", tags)
	}
	if label := strVal(nestedMap(attrs, "popular_threat_classification"), "suggested_threat_label"); label != "" {
		fmt.Printf("Threat label: %s\n", label)
	}

	fmt.Printf("Link: https://www.virustotal.com/gui/file/%s\n", hash)

	detections := extractDetections(nestedMap(attrs, "last_analysis_results"))
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
	if h, ok := bdata["http_conversations"]; ok {
		if items, ok := h.([]interface{}); ok && len(items) > 0 {
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

	fmt.Printf("Detection: %d/%d\n", intVal(stats, "malicious"), statsTotal(stats))
	if s := intVal(stats, "suspicious"); s > 0 {
		fmt.Printf("Suspicious: %d\n", s)
	}
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

// --- IP address operations ---

// IPReportPrint prints a human-readable VirusTotal IP address report.
func (v *VTClient) IPReportPrint(ip string) {
	data, err := v.get("/ip_addresses/" + ip)
	if err != nil {
		fmt.Printf("%sError: %v%s\n", cRed, err, cReset)
		return
	}
	if data == nil {
		fmt.Printf("%sIP not found on VirusTotal%s\n", cYellow, cReset)
		return
	}

	attrs := nested(data, "data", "attributes")
	v.printIPBasicInfo(ip, attrs)
	v.printIPDetections(attrs)
	v.printIPResolutions(ip)
	v.printIPCommunicatingFiles(ip)
	v.printIPRelatedURLs(ip)
	fmt.Printf("\n%sLink: https://www.virustotal.com/gui/ip-address/%s%s\n", cGray, ip, cReset)
}

func (v *VTClient) printIPBasicInfo(ip string, attrs map[string]interface{}) {
	stats := nestedMap(attrs, "last_analysis_stats")
	harmless := intVal(stats, "harmless")
	malicious := intVal(stats, "malicious")
	suspicious := intVal(stats, "suspicious")
	undetected := intVal(stats, "undetected")

	fmt.Printf("\n%s%s=== VirusTotal IP Report: %s ===%s\n", cBold, cCyan, ip, cReset)
	fmt.Printf("AS Owner: %s\n", strVal(attrs, "as_owner"))
	fmt.Printf("ASN: %s\n", strVal(attrs, "asn"))
	fmt.Printf("Country: %s\n", strVal(attrs, "country"))
	fmt.Printf("Network: %s\n", strVal(attrs, "network"))
	fmt.Printf("Reputation: %s\n", strVal(attrs, "reputation"))

	if tags := strSlice(attrs, "tags"); len(tags) > 0 {
		fmt.Printf("Tags: %v\n", tags)
	}
	if jarm := strVal(attrs, "jarm"); jarm != "" {
		fmt.Printf("JARM: %s\n", jarm)
	}

	color := cGreen
	if malicious > 0 {
		color = cRed
	} else if suspicious > 0 {
		color = cYellow
	}
	fmt.Printf("Analysis: %sHarmless=%d Malicious=%d Suspicious=%d Undetected=%d%s\n",
		color, harmless, malicious, suspicious, undetected, cReset)
}

func (v *VTClient) printIPDetections(attrs map[string]interface{}) {
	detections := extractDetections(nestedMap(attrs, "last_analysis_results"))
	if len(detections) > 0 {
		fmt.Printf("\n%sMalicious Detections (%d):%s\n", cRed, len(detections), cReset)
		for _, d := range detections {
			fmt.Printf("  %s: %s\n", d.Engine, d.Result)
		}
	}
}

func (v *VTClient) printIPResolutions(ip string) {
	fmt.Println()
	v.printRelation(
		"/ip_addresses/"+ip+"/resolutions?limit=20",
		"Passive DNS",
		func(itemAttrs map[string]interface{}) string {
			host := strVal(itemAttrs, "host_name")
			if host == "" {
				return ""
			}
			return fmt.Sprintf("  %s %s(%s)%s", host, cGray, floatTimestamp(itemAttrs, "date"), cReset)
		},
	)
}

func (v *VTClient) printIPCommunicatingFiles(ip string) {
	fmt.Println()
	v.printRelation(
		"/ip_addresses/"+ip+"/communicating_files?limit=10",
		"Communicating Files",
		func(itemAttrs map[string]interface{}) string {
			sha256 := strVal(itemAttrs, "sha256")
			if sha256 == "" {
				return ""
			}
			name := strVal(itemAttrs, "meaningful_name")
			if name == "" {
				name = strVal(itemAttrs, "type_description")
			}
			fStats := nestedMap(itemAttrs, "last_analysis_stats")
			mal := intVal(fStats, "malicious")
			total := statsTotal(fStats)
			color := cGreen
			if mal > 0 {
				color = cRed
			}
			return fmt.Sprintf("  %s%d/%d%s %s %s(%s)%s", color, mal, total, cReset, sha256[:16]+"...", cGray, name, cReset)
		},
	)
}

func (v *VTClient) printIPRelatedURLs(ip string) {
	fmt.Println()
	v.printRelation(
		"/ip_addresses/"+ip+"/urls?limit=10",
		"Related URLs",
		func(itemAttrs map[string]interface{}) string {
			u := strVal(itemAttrs, "url")
			if u == "" {
				return ""
			}
			uStats := nestedMap(itemAttrs, "last_analysis_stats")
			mal := intVal(uStats, "malicious")
			total := statsTotal(uStats)
			color := cGreen
			if mal > 0 {
				color = cRed
			}
			return fmt.Sprintf("  %s%d/%d%s %s", color, mal, total, cReset, u)
		},
	)
}

// printRelation fetches a VT relation endpoint and prints each item using the formatter.
func (v *VTClient) printRelation(path, title string, format func(map[string]interface{}) string) {
	data, err := v.get(path)
	if err != nil {
		if strings.Contains(err.Error(), "403") {
			fmt.Printf("%s=== %s ===%s\n", cCyan, title, cReset)
			fmt.Printf("  %s(VT Free API does not support this endpoint)%s\n", cGray, cReset)
		} else {
			fmt.Printf("%s  Error fetching %s: %v%s\n", cRed, title, err, cReset)
		}
		return
	}
	if data == nil {
		fmt.Printf("%s=== %s (0) ===%s\n", cCyan, title, cReset)
		fmt.Println("  (none)")
		return
	}

	items := dataArray(data)
	fmt.Printf("%s=== %s (%d) ===%s\n", cCyan, title, len(items), cReset)
	if len(items) == 0 {
		fmt.Println("  (none)")
		return
	}
	for _, item := range items {
		m, _ := item.(map[string]interface{})
		line := format(nestedMap(m, "attributes"))
		if line != "" {
			fmt.Println(line)
		}
	}
}

// --- Shared helpers ---

// statsTotal sums all values in an analysis_stats map.
func statsTotal(stats map[string]interface{}) int {
	total := 0
	for _, val := range stats {
		total += toInt(val)
	}
	return total
}

// extractDetections returns sorted malicious detections from analysis results.
func extractDetections(results map[string]interface{}) []vtDetection {
	var out []vtDetection
	for engine, val := range results {
		vm, ok := val.(map[string]interface{})
		if !ok {
			continue
		}
		if strVal(vm, "category") != "malicious" {
			continue
		}
		r := strVal(vm, "result")
		if r == "" {
			r = "malicious"
		}
		out = append(out, vtDetection{engine, r})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Engine < out[j].Engine })
	return out
}

// dataArray extracts the "data" array from a VT API response.
func dataArray(m map[string]interface{}) []interface{} {
	v, ok := m["data"]
	if !ok {
		return nil
	}
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	return arr
}

// floatTimestamp extracts a VT unix timestamp (JSON float64) and formats as YYYY-MM-DD.
func floatTimestamp(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok {
		return "N/A"
	}
	switch n := v.(type) {
	case float64:
		return time.Unix(int64(n), 0).Format("2006-01-02")
	case int:
		return time.Unix(int64(n), 0).Format("2006-01-02")
	default:
		return fmt.Sprintf("%v", v)
	}
}

// --- JSON helpers ---

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

// --- JSON output methods ---

// CheckJSON returns hash check results as JSON bytes.
func (v *VTClient) CheckJSON(hash string) ([]byte, error) {
	data, err := v.get("/files/" + hash)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return json.Marshal(map[string]interface{}{"hash": hash, "found": false})
	}
	attrs := nested(data, "data", "attributes")
	stats := nestedMap(attrs, "last_analysis_stats")
	detections := extractDetections(nestedMap(attrs, "last_analysis_results"))
	detList := make([]map[string]string, 0, len(detections))
	for _, d := range detections {
		detList = append(detList, map[string]string{"engine": d.Engine, "result": d.Result})
	}
	return json.Marshal(map[string]interface{}{
		"hash":            hash,
		"found":           true,
		"detected":        intVal(stats, "malicious"),
		"total":           statsTotal(stats),
		"type":            strVal(attrs, "type_description"),
		"name":            strVal(attrs, "meaningful_name"),
		"tags":            strSlice(attrs, "tags"),
		"threat_label":    strVal(nestedMap(attrs, "popular_threat_classification"), "suggested_threat_label"),
		"link":            "https://www.virustotal.com/gui/file/" + hash,
		"top_detections":  detList,
	})
}

// BehaviorJSON returns VT behavior summary as JSON bytes.
func (v *VTClient) BehaviorJSON(hash string) ([]byte, error) {
	data, err := v.get("/files/" + hash + "/behaviour_summary")
	if err != nil {
		return nil, err
	}
	if data == nil {
		return json.Marshal(map[string]interface{}{"hash": hash, "found": false})
	}
	return json.Marshal(map[string]interface{}{
		"hash":  hash,
		"found": true,
		"data":  nestedMap(data, "data"),
	})
}

// LookupJSON returns detailed VT file info as JSON bytes.
func (v *VTClient) LookupJSON(hash string) ([]byte, error) {
	data, err := v.get("/files/" + hash)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return json.Marshal(map[string]interface{}{"hash": hash, "found": false})
	}
	attrs := nested(data, "data", "attributes")
	stats := nestedMap(attrs, "last_analysis_stats")
	pop := nestedMap(attrs, "popular_threat_classification")
	names := strSlice(attrs, "names")
	if len(names) > 10 {
		names = names[:10]
	}
	return json.Marshal(map[string]interface{}{
		"hash":           hash,
		"found":          true,
		"detected":       intVal(stats, "malicious") + intVal(stats, "suspicious"),
		"total":          statsTotal(stats),
		"type":           strVal(attrs, "type_description"),
		"size_bytes":     attrs["size"],
		"tags":           strSlice(attrs, "tags"),
		"names":          names,
		"classification": strVal(pop, "suggested_threat_label"),
		"link":           "https://www.virustotal.com/gui/file/" + hash,
	})
}
