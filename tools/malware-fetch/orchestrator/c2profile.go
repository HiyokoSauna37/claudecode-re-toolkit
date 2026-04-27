package orchestrator

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// --- Types ---

// C2Node represents an IP node in the C2 infrastructure.
type C2Node struct {
	IP         string     `json:"ip"`
	ASOwner    string     `json:"as_owner"`
	ASN        string     `json:"asn"`
	Country    string     `json:"country"`
	Network    string     `json:"network"`
	Reputation string     `json:"reputation"`
	Malicious  int        `json:"malicious"`
	Total      int        `json:"total"`
	Source     string     `json:"source"`
	Domains    []C2Domain `json:"domains"`
	Files      []C2File   `json:"files"`
}

// C2Domain represents a passive DNS entry with live resolution status.
type C2Domain struct {
	Domain    string `json:"domain"`
	LastSeen  string `json:"last_seen"`
	CurrentIP string `json:"current_ip,omitempty"`
	Status    string `json:"status"`
}

// C2File represents a communicating file from VT.
type C2File struct {
	SHA256    string `json:"sha256"`
	Name      string `json:"name"`
	Malicious int    `json:"malicious"`
	Total     int    `json:"total"`
}

// C2IOC represents a ThreatFox IOC entry.
type C2IOC struct {
	IOC        string   `json:"ioc"`
	Type       string   `json:"type"`
	Threat     string   `json:"threat"`
	Malware    string   `json:"malware"`
	Confidence string   `json:"confidence"`
	Tags       []string `json:"tags"`
	FirstSeen  string   `json:"first_seen"`
	Link       string   `json:"link"`
}

// C2PortResult holds a single port scan result.
type C2PortResult struct {
	Port   int        `json:"port"`
	Status PortStatus `json:"status"`
	Banner string     `json:"banner,omitempty"`
}

// PortStatus represents the state of a scanned port.
type PortStatus int

const (
	PortOpen     PortStatus = iota
	PortClosed              // connection refused — service not running
	PortFiltered            // timeout — firewall dropping packets
)

func (s PortStatus) String() string {
	switch s {
	case PortOpen:
		return "OPEN"
	case PortClosed:
		return "CLOSED"
	case PortFiltered:
		return "FILTERED"
	default:
		return "UNKNOWN"
	}
}

const maxPivotDepth = 2 // prevent infinite passive DNS recursion

var c2CommonPorts = []int{
	22, 80, 443, 2222, 3000, 3306, 4000, 4443, 4444,
	5000, 5002, 5555, 6379, 7777, 8080, 8081, 8443,
	8888, 9001, 9090, 25001, 27017,
}

// --- VT / ThreatFox data-returning API methods ---

// IPReportData returns structured VT IP data (basic info + passive DNS + files).
func (v *VTClient) IPReportData(ip string) *C2Node {
	node := &C2Node{IP: ip}

	data, err := v.get("/ip_addresses/" + ip)
	if err != nil || data == nil {
		return node
	}

	attrs := nested(data, "data", "attributes")
	stats := nestedMap(attrs, "last_analysis_stats")

	node.ASOwner = strVal(attrs, "as_owner")
	node.ASN = strVal(attrs, "asn")
	node.Country = strVal(attrs, "country")
	node.Network = strVal(attrs, "network")
	node.Reputation = strVal(attrs, "reputation")
	node.Malicious = intVal(stats, "malicious")
	node.Total = statsTotal(stats)

	// Passive DNS
	if resData, err := v.get("/ip_addresses/" + ip + "/resolutions?limit=20"); err == nil && resData != nil {
		for _, item := range dataArray(resData) {
			m, _ := item.(map[string]interface{})
			itemAttrs := nestedMap(m, "attributes")
			if host := strVal(itemAttrs, "host_name"); host != "" {
				node.Domains = append(node.Domains, C2Domain{
					Domain:   host,
					LastSeen: floatTimestamp(itemAttrs, "date"),
				})
			}
		}
	}

	// Communicating files
	if filesData, err := v.get("/ip_addresses/" + ip + "/communicating_files?limit=10"); err == nil && filesData != nil {
		for _, item := range dataArray(filesData) {
			m, _ := item.(map[string]interface{})
			itemAttrs := nestedMap(m, "attributes")
			sha256 := strVal(itemAttrs, "sha256")
			if sha256 == "" {
				continue
			}
			name := strVal(itemAttrs, "meaningful_name")
			if name == "" {
				name = strVal(itemAttrs, "type_description")
			}
			fStats := nestedMap(itemAttrs, "last_analysis_stats")
			node.Files = append(node.Files, C2File{
				SHA256:    sha256,
				Name:      name,
				Malicious: intVal(fStats, "malicious"),
				Total:     statsTotal(fStats),
			})
		}
	}

	return node
}

// SearchIOCData returns structured ThreatFox IOC results.
func (t *TFClient) SearchIOCData(ioc string) []C2IOC {
	payload := map[string]interface{}{
		"query":       "search_ioc",
		"search_term": ioc,
	}
	data, err := t.post(payload)
	if err != nil || data == nil {
		return nil
	}
	if status, _ := data["query_status"].(string); status != "ok" {
		return nil
	}
	dataArr, ok := data["data"].([]interface{})
	if !ok {
		return nil
	}

	var results []C2IOC
	for _, item := range dataArr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		var tags []string
		if tagArr, ok := m["tags"].([]interface{}); ok {
			for _, tv := range tagArr {
				if s, ok := tv.(string); ok {
					tags = append(tags, s)
				}
			}
		}
		results = append(results, C2IOC{
			IOC:        fmt.Sprintf("%v", m["ioc"]),
			Type:       fmt.Sprintf("%v", m["ioc_type"]),
			Threat:     fmt.Sprintf("%v", m["threat_type"]),
			Malware:    fmt.Sprintf("%v", m["malware_printable"]),
			Confidence: fmt.Sprintf("%v", m["confidence_level"]),
			Tags:       tags,
			FirstSeen:  fmt.Sprintf("%v", m["first_seen_utc"]),
			Link:       fmt.Sprintf("https://threatfox.abuse.ch/ioc/%v/", m["id"]),
		})
	}
	return results
}

// --- Port scanning ---

func scanPort(ip string, port int, timeout time.Duration) C2PortResult {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		mode := classifyError(err.Error())
		switch mode {
		case FailureTimeout:
			return C2PortResult{Port: port, Status: PortFiltered}
		default:
			return C2PortResult{Port: port, Status: PortClosed}
		}
	}
	defer conn.Close()

	// Grab banner with short timeout
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	banner := ""
	if n > 0 {
		banner = strings.TrimSpace(string(buf[:n]))
		if len(banner) > 80 {
			banner = banner[:80] + "..."
		}
	}
	return C2PortResult{Port: port, Status: PortOpen, Banner: banner}
}

func scanAllPorts(ip string, ports []int) []C2PortResult {
	var wg sync.WaitGroup
	results := make([]C2PortResult, len(ports))
	for i, port := range ports {
		wg.Add(1)
		go func(idx, p int) {
			defer wg.Done()
			results[idx] = scanPort(ip, p, 5*time.Second)
		}(i, port)
	}
	wg.Wait()
	return results
}

// --- Main orchestrator ---

// RunC2Profile performs automated C2 infrastructure profiling.
func RunC2Profile(ip string, port int) {
	printBanner("C2 Infrastructure Profile: " + ip)

	vt := NewVTClient(os.Getenv("VIRUSTOTAL_API_KEY"))
	tf := NewTFClient(os.Getenv("ABUSECH_AUTH_KEY"))

	// Phase 1: Primary IP — VT + ThreatFox
	printPhase(1, "Primary IP: VirusTotal + ThreatFox")
	primaryNode := vt.IPReportData(ip)
	primaryNode.Source = "primary"
	printC2Node(primaryNode)

	allIOCs := collectIOCs(tf, ip, port)
	printC2IOCs(allIOCs)

	// Phase 1b: OTX AlienVault
	otx := NewOTXClient()
	otxPulses := otx.IPLookupData(ip)
	if len(otxPulses) > 0 {
		fmt.Printf("  OTX: %d pulses\n", len(otxPulses))
		for _, p := range otxPulses {
			fmt.Printf("    %s[%s]%s %s (by %s, %d IOCs)\n", cCyan, p.ID, cReset, p.Name, p.Author, p.IndicatorCount)
			if len(p.MalwareFamilies) > 0 {
				fmt.Printf("      %sMalware: %s%s\n", cRed, strings.Join(p.MalwareFamilies, ", "), cReset)
			}
		}
	}

	// Phase 2: Passive DNS pivot
	printPhase(2, "Passive DNS Pivot")
	seen := map[string]bool{ip: true}
	resolveDomains(primaryNode, ip, seen)

	// Phase 3: Investigate discovered IPs (with depth limit)
	printPhase(3, "Discovered IP Investigation")
	investigateNewIPs(vt, tf, primaryNode, ip, seen, 0)

	// Phase 4: Port scan all IPs
	printPhase(4, "Port Scan (all discovered IPs)")
	for scanIP := range seen {
		printPortScanResults(scanIP, scanAllPorts(scanIP, c2CommonPorts))
	}

	// Phase 5: Summary
	printSummary(primaryNode, allIOCs, seen, ip)
}

// RunC2ProfileJSON returns Phase 1 C2 profile data as JSON (primary node + IOCs + port scan).
func RunC2ProfileJSON(ip string, port int) ([]byte, error) {
	vt := NewVTClient(os.Getenv("VIRUSTOTAL_API_KEY"))
	tf := NewTFClient(os.Getenv("ABUSECH_AUTH_KEY"))

	node := vt.IPReportData(ip)
	node.Source = "primary"
	iocs := collectIOCs(tf, ip, port)

	portResults := scanAllPorts(ip, c2CommonPorts)
	var openPorts []map[string]interface{}
	for _, pr := range portResults {
		if pr.Status == PortOpen {
			m := map[string]interface{}{
				"port":   pr.Port,
				"status": pr.Status.String(),
			}
			if pr.Banner != "" {
				m["banner"] = pr.Banner
			}
			openPorts = append(openPorts, m)
		}
	}

	return json.Marshal(map[string]interface{}{
		"ip":         ip,
		"as_owner":   node.ASOwner,
		"asn":        node.ASN,
		"country":    node.Country,
		"malicious":  node.Malicious,
		"total":      node.Total,
		"domains":    node.Domains,
		"files":      node.Files,
		"iocs":       iocs,
		"open_ports": openPorts,
	})
}

// collectIOCs gathers ThreatFox IOCs for the IP, deduplicating IP and IP:port results.
func collectIOCs(tf *TFClient, ip string, port int) []C2IOC {
	iocs := tf.SearchIOCData(ip)
	if port <= 0 {
		return iocs
	}
	seen := make(map[string]bool, len(iocs))
	for _, i := range iocs {
		seen[i.IOC] = true
	}
	for _, i := range tf.SearchIOCData(fmt.Sprintf("%s:%d", ip, port)) {
		if !seen[i.IOC] {
			iocs = append(iocs, i)
			seen[i.IOC] = true
		}
	}
	return iocs
}

// resolveDomains resolves passive DNS domains and updates their status in-place.
func resolveDomains(node *C2Node, primaryIP string, seen map[string]bool) {
	for i := range node.Domains {
		d := &node.Domains[i] // pointer to actual element
		ips, err := net.LookupHost(d.Domain)
		if err != nil {
			d.Status = "dead"
			d.CurrentIP = ""
			fmt.Printf("  %s%-30s%s  %sDEAD (DNS failed)%s\n", cGray, d.Domain, cReset, cRed, cReset)
			continue
		}
		d.CurrentIP = ips[0]
		if d.CurrentIP == primaryIP {
			d.Status = "same"
			fmt.Printf("  %-30s  %s%s%s (same IP)\n", d.Domain, cGreen, d.CurrentIP, cReset)
		} else {
			d.Status = "migrated"
			fmt.Printf("  %-30s  %s%s (MIGRATED)%s\n", d.Domain, cYellow, d.CurrentIP, cReset)
			seen[d.CurrentIP] = true
		}
	}
}

// investigateNewIPs recursively investigates IPs discovered via passive DNS.
func investigateNewIPs(vt *VTClient, tf *TFClient, primaryNode *C2Node, primaryIP string, seen map[string]bool, depth int) {
	if depth >= maxPivotDepth {
		return
	}

	newIPs := make([]string, 0)
	for ip := range seen {
		if ip != primaryIP {
			newIPs = append(newIPs, ip)
		}
	}

	if len(newIPs) == 0 {
		fmt.Printf("  %s(No new IPs discovered)%s\n", cGray, cReset)
		return
	}

	for _, discoveredIP := range newIPs {
		fmt.Printf("\n  %s--- %s (via passive DNS) ---%s\n", cCyan, discoveredIP, cReset)
		node := vt.IPReportData(discoveredIP)
		node.Source = "passive_dns"
		printC2NodeCompact(node)

		// Resolve this node's domains too — may discover more IPs
		beforeCount := len(seen)
		for i := range node.Domains {
			d := &node.Domains[i]
			resolved, err := net.LookupHost(d.Domain)
			if err != nil {
				continue
			}
			d.CurrentIP = resolved[0]
			if !seen[d.CurrentIP] {
				seen[d.CurrentIP] = true
				fmt.Printf("    %sNEW IP: %s (via %s)%s\n", cYellow, d.CurrentIP, d.Domain, cReset)
			}
		}

		// ThreatFox on discovered IP
		if dIOCs := tf.SearchIOCData(discoveredIP); len(dIOCs) > 0 {
			for _, ioc := range dIOCs {
				fmt.Printf("    ThreatFox: %s [%s] %s\n", ioc.IOC, ioc.Threat, strings.Join(ioc.Tags, ","))
			}
		}

		// Recurse if we found new IPs
		if len(seen) > beforeCount {
			investigateNewIPs(vt, tf, primaryNode, primaryIP, seen, depth+1)
		}
	}
}

// --- Output helpers ---

func printBanner(title string) {
	bar := strings.Repeat("=", 44)
	fmt.Printf("\n%s%s%s%s\n", cBold, cCyan, bar, cReset)
	fmt.Printf("%s%s  %s%s\n", cBold, cCyan, title, cReset)
	fmt.Printf("%s%s%s%s\n\n", cBold, cCyan, bar, cReset)
}

func printPhase(n int, title string) {
	fmt.Printf("%s[Phase %d] %s%s\n", cCyan, n, title, cReset)
}

func printC2Node(n *C2Node) {
	fmt.Printf("  ASN:        %s (%s)\n", n.ASN, n.ASOwner)
	fmt.Printf("  Country:    %s\n", n.Country)
	fmt.Printf("  Network:    %s\n", n.Network)
	fmt.Printf("  Reputation: %s\n", n.Reputation)
	if n.Malicious > 0 {
		fmt.Printf("  Detection:  %s%d/%d malicious%s\n", cRed, n.Malicious, n.Total, cReset)
	} else {
		fmt.Printf("  Detection:  %s0/%d%s\n", cGreen, n.Total, cReset)
	}
	printDomainList("  ", n.Domains)
	printFileList("  ", n.Files)
}

func printC2NodeCompact(n *C2Node) {
	fmt.Printf("    ASN: %s (%s), Country: %s, Rep: %s", n.ASN, n.ASOwner, n.Country, n.Reputation)
	if n.Malicious > 0 {
		fmt.Printf(", %s%d/%d mal%s", cRed, n.Malicious, n.Total, cReset)
	}
	fmt.Println()
	printDomainList("    ", n.Domains)
}

func printDomainList(indent string, domains []C2Domain) {
	if len(domains) == 0 {
		return
	}
	fmt.Printf("%sPassive DNS: %d domains\n", indent, len(domains))
	for _, d := range domains {
		fmt.Printf("%s  %s %s(%s)%s\n", indent, d.Domain, cGray, d.LastSeen, cReset)
	}
}

func printFileList(indent string, files []C2File) {
	if len(files) == 0 {
		return
	}
	fmt.Printf("%sComm. files: %d\n", indent, len(files))
	for _, f := range files {
		short := f.SHA256
		if len(short) > 16 {
			short = short[:16] + "..."
		}
		fmt.Printf("%s  %s%d/%d%s %s (%s)\n", indent, cRed, f.Malicious, f.Total, cReset, short, f.Name)
	}
}

func printC2IOCs(iocs []C2IOC) {
	if len(iocs) == 0 {
		fmt.Printf("  ThreatFox: %s(no results)%s\n", cGray, cReset)
		return
	}
	fmt.Printf("  ThreatFox: %d IOCs\n", len(iocs))
	for _, ioc := range iocs {
		fmt.Printf("    %s [%s] %s conf:%s tags:%s\n",
			ioc.IOC, ioc.Threat, ioc.Malware, ioc.Confidence, strings.Join(ioc.Tags, ","))
		fmt.Printf("      %s%s | %s%s\n", cGray, ioc.FirstSeen, ioc.Link, cReset)
	}
}

func printPortScanResults(ip string, results []C2PortResult) {
	fmt.Printf("\n  %s--- %s ---%s\n", cCyan, ip, cReset)
	open, filtered, closed := 0, 0, 0
	for _, r := range results {
		switch r.Status {
		case PortOpen:
			open++
			banner := ""
			if r.Banner != "" {
				banner = fmt.Sprintf(" [%s]", r.Banner)
			}
			fmt.Printf("    %s%-6d OPEN%s%s\n", cGreen, r.Port, cReset, banner)
		case PortFiltered:
			filtered++
		case PortClosed:
			closed++
		}
	}
	if filtered > 0 {
		fmt.Printf("    %s%d ports FILTERED (FW dropping packets)%s\n", cYellow, filtered, cReset)
	}
	if closed > 0 {
		fmt.Printf("    %s%d ports CLOSED%s\n", cGray, closed, cReset)
	}
}

func printSummary(primary *C2Node, iocs []C2IOC, seen map[string]bool, primaryIP string) {
	printBanner("Summary")
	fmt.Printf("IPs discovered: %d\n", len(seen))
	fmt.Printf("ThreatFox IOCs: %d\n", len(iocs))
	fmt.Printf("Passive DNS:    %d domains\n", len(primary.Domains))

	if len(primary.Files) > 0 {
		fmt.Printf("\nRelated files:\n")
		for _, f := range primary.Files {
			fmt.Printf("  %s%d/%d%s %s (%s)\n", cRed, f.Malicious, f.Total, cReset, f.SHA256, f.Name)
		}
	}

	// IOC list for copy-paste
	fmt.Printf("\n%sIOC List (copy-paste):%s\n", cCyan, cReset)
	for ip := range seen {
		fmt.Printf("  %s\n", ip)
	}
	for _, d := range primary.Domains {
		fmt.Printf("  %s\n", d.Domain)
	}
	for _, ioc := range iocs {
		if !strings.Contains(ioc.IOC, primaryIP) {
			fmt.Printf("  %s\n", ioc.IOC)
		}
	}
	for _, f := range primary.Files {
		fmt.Printf("  %s\n", f.SHA256)
	}
	fmt.Println()
}
