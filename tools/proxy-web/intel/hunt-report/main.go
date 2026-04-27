// hunt-report: Aggregate results from all 4 offensive tool hunting methods
// into a unified report with statistics and BB concept extraction.
//
// Usage:
//
//	hunt-report merge -tf results_tf.json -gh results_gh.json -o report.json
//	hunt-report merge -tf results_tf.json -gh results_gh.json --markdown
//	hunt-report stats report.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// ============================================================
// Data structures for each method's output
// ============================================================

// ThreatFox sweep result
type ThreatFoxResult struct {
	Total int                       `json:"total"`
	ByTag map[string][]ThreatFoxIOC `json:"by_tag"`
}

type ThreatFoxIOC struct {
	IOC        string `json:"ioc"`
	Type       string `json:"type"`
	Threat     string `json:"threat"`
	Malware    string `json:"malware"`
	Family     string `json:"family"`
	Confidence string `json:"confidence"`
	FirstSeen  string `json:"first_seen"`
	Tags       string `json:"tags"`
	Link       string `json:"link"`
}

// GitHub hunt result
type GitHubResult map[string]GitHubCategory

type GitHubCategory struct {
	Label   string       `json:"label"`
	Results []GitHubRepo `json:"results"`
}

type GitHubRepo struct {
	Name    string `json:"name"`
	Stars   int    `json:"stars"`
	Desc    string `json:"desc"`
	Lang    string `json:"lang"`
	URL     string `json:"url"`
	Updated string `json:"updated"`
}

// C2 concept mapping
type C2Concept struct {
	C2               string `json:"c2"`
	OffensiveFeature string `json:"offensive_feature"`
	BBConcept        string `json:"bb_concept"`
}

// H1 patterns result
type H1Result struct {
	ReportsAnalyzed int            `json:"reports_analyzed"`
	VulnTypes       map[string]int `json:"vulnerability_types"`
	TopParams       map[string]int `json:"top_parameters"`
	TopEndpoints    map[string]int `json:"top_endpoints"`
	PayloadTypes    map[string]int `json:"payload_types"`
}

// ============================================================
// Unified report
// ============================================================

type UnifiedReport struct {
	Timestamp string        `json:"timestamp"`
	Summary   ReportSummary `json:"summary"`
	ThreatFox *TFSection    `json:"threatfox,omitempty"`
	GitHub    *GHSection    `json:"github,omitempty"`
	C2        *C2Section    `json:"c2_concepts,omitempty"`
	H1        *H1Section    `json:"h1_patterns,omitempty"`
}

type ReportSummary struct {
	TotalIOCs        int `json:"total_iocs"`
	UniqueC2Hosts    int `json:"unique_c2_hosts"`
	GitHubRepos      int `json:"github_repos"`
	BBConcepts       int `json:"bb_concepts"`
	MalwareFamilies  int `json:"malware_families"`
	VulnTypes        int `json:"vuln_types_detected"`
	H1Reports        int `json:"h1_reports_analyzed"`
}

type TFSection struct {
	Total    int                `json:"total"`
	Families map[string]int    `json:"families"`
	Hosts    []string           `json:"top_hosts"`
	Threats  map[string]int    `json:"threat_types"`
}

type GHSection struct {
	TotalRepos int              `json:"total_repos"`
	Categories map[string]int   `json:"categories"`
	TopRepos   []GitHubRepo     `json:"top_repos"`
}

type C2Section struct {
	TotalConcepts int         `json:"total_concepts"`
	Concepts      []C2Concept `json:"concepts"`
}

type H1Section struct {
	ReportsAnalyzed int            `json:"reports_analyzed"`
	VulnTypes       map[string]int `json:"vulnerability_types"`
	TopParams       []string       `json:"top_parameters"`
}

// ============================================================
// Loading functions
// ============================================================

func loadJSON(path string, v interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func extractHosts(tf *ThreatFoxResult) []string {
	hostSet := make(map[string]bool)
	for _, iocs := range tf.ByTag {
		for _, ioc := range iocs {
			val := ioc.IOC
			// ip:port format
			if strings.Contains(val, ":") && !strings.Contains(val, "://") {
				parts := strings.SplitN(val, ":", 2)
				hostSet[parts[0]] = true
			} else if strings.Contains(val, "://") {
				// URL format - extract domain
				val = strings.TrimPrefix(val, "https://")
				val = strings.TrimPrefix(val, "http://")
				parts := strings.SplitN(val, "/", 2)
				parts = strings.SplitN(parts[0], ":", 2)
				hostSet[parts[0]] = true
			}
		}
	}
	hosts := make([]string, 0, len(hostSet))
	for h := range hostSet {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return hosts
}

// ============================================================
// Commands
// ============================================================

func cmdMerge(args []string) {
	fs := flag.NewFlagSet("merge", flag.ExitOnError)
	tfPath := fs.String("tf", "", "ThreatFox sweep results JSON")
	ghPath := fs.String("gh", "", "GitHub hunt results JSON")
	c2Path := fs.String("c2", "", "C2 concepts JSON (from c2hunt concepts --json)")
	h1Path := fs.String("h1", "", "H1 patterns JSON (from h1patterns extract --json)")
	output := fs.String("o", "", "Output file (default: stdout)")
	markdown := fs.Bool("markdown", false, "Output as Markdown report")
	fs.Parse(args)

	report := UnifiedReport{
		Timestamp: time.Now().Format(time.RFC3339),
	}

	// Load ThreatFox
	if *tfPath != "" {
		var tf ThreatFoxResult
		if err := loadJSON(*tfPath, &tf); err != nil {
			fmt.Fprintf(os.Stderr, "[!] ThreatFox load error: %v\n", err)
		} else {
			families := make(map[string]int)
			threats := make(map[string]int)
			for family, iocs := range tf.ByTag {
				families[family] = len(iocs)
				for _, ioc := range iocs {
					threats[ioc.Threat]++
				}
			}
			hosts := extractHosts(&tf)
			report.ThreatFox = &TFSection{
				Total:    tf.Total,
				Families: families,
				Hosts:    hosts,
				Threats:  threats,
			}
			report.Summary.TotalIOCs = tf.Total
			report.Summary.UniqueC2Hosts = len(hosts)
			report.Summary.MalwareFamilies = len(families)
		}
	}

	// Load GitHub
	if *ghPath != "" {
		var gh GitHubResult
		if err := loadJSON(*ghPath, &gh); err != nil {
			fmt.Fprintf(os.Stderr, "[!] GitHub load error: %v\n", err)
		} else {
			categories := make(map[string]int)
			var allRepos []GitHubRepo
			for _, cat := range gh {
				categories[cat.Label] = len(cat.Results)
				allRepos = append(allRepos, cat.Results...)
			}
			sort.Slice(allRepos, func(i, j int) bool {
				return allRepos[i].Stars > allRepos[j].Stars
			})
			top := allRepos
			if len(top) > 20 {
				top = top[:20]
			}
			report.GitHub = &GHSection{
				TotalRepos: len(allRepos),
				Categories: categories,
				TopRepos:   top,
			}
			report.Summary.GitHubRepos = len(allRepos)
		}
	}

	// Load C2 concepts
	if *c2Path != "" {
		var concepts []C2Concept
		if err := loadJSON(*c2Path, &concepts); err != nil {
			fmt.Fprintf(os.Stderr, "[!] C2 concepts load error: %v\n", err)
		} else {
			report.C2 = &C2Section{
				TotalConcepts: len(concepts),
				Concepts:      concepts,
			}
			report.Summary.BBConcepts = len(concepts)
		}
	}

	// Load H1 patterns
	if *h1Path != "" {
		var h1 H1Result
		if err := loadJSON(*h1Path, &h1); err != nil {
			fmt.Fprintf(os.Stderr, "[!] H1 patterns load error: %v\n", err)
		} else {
			topParams := make([]string, 0)
			for p := range h1.TopParams {
				topParams = append(topParams, p)
			}
			sort.Strings(topParams)
			report.H1 = &H1Section{
				ReportsAnalyzed: h1.ReportsAnalyzed,
				VulnTypes:       h1.VulnTypes,
				TopParams:       topParams,
			}
			report.Summary.H1Reports = h1.ReportsAnalyzed
			report.Summary.VulnTypes = len(h1.VulnTypes)
		}
	}

	// Output
	if *markdown {
		md := renderMarkdown(&report)
		if *output != "" {
			if err := os.WriteFile(*output, []byte(md), 0644); err != nil {
				fmt.Fprintf(os.Stderr, "[!] Write error: %v\n", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "  Saved Markdown report to %s\n", *output)
		} else {
			fmt.Print(md)
		}
	} else {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] JSON marshal error: %v\n", err)
			os.Exit(1)
		}
		if *output != "" {
			if err := os.WriteFile(*output, data, 0644); err != nil {
				fmt.Fprintf(os.Stderr, "[!] Write error: %v\n", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "  Saved JSON report to %s\n", *output)
		} else {
			fmt.Println(string(data))
		}
	}
}

func renderMarkdown(r *UnifiedReport) string {
	var b strings.Builder
	b.WriteString("# Offensive Tool Hunt Report\n\n")
	b.WriteString(fmt.Sprintf("Generated: %s\n\n", r.Timestamp))

	// Summary
	b.WriteString("## Summary\n\n")
	b.WriteString(fmt.Sprintf("| Metric | Value |\n|--------|-------|\n"))
	b.WriteString(fmt.Sprintf("| Total IOCs | %d |\n", r.Summary.TotalIOCs))
	b.WriteString(fmt.Sprintf("| Unique C2 Hosts | %d |\n", r.Summary.UniqueC2Hosts))
	b.WriteString(fmt.Sprintf("| GitHub Repos | %d |\n", r.Summary.GitHubRepos))
	b.WriteString(fmt.Sprintf("| BB Concepts | %d |\n", r.Summary.BBConcepts))
	b.WriteString(fmt.Sprintf("| Malware Families | %d |\n", r.Summary.MalwareFamilies))
	b.WriteString(fmt.Sprintf("| H1 Reports Analyzed | %d |\n", r.Summary.H1Reports))
	b.WriteString("\n")

	// ThreatFox
	if r.ThreatFox != nil {
		b.WriteString("## ThreatFox / MalwareBazaar\n\n")
		b.WriteString(fmt.Sprintf("Total IOCs: %d | Unique hosts: %d\n\n", r.ThreatFox.Total, len(r.ThreatFox.Hosts)))
		b.WriteString("| Family | IOCs |\n|--------|------|\n")
		type kv struct{ k string; v int }
		var sorted []kv
		for k, v := range r.ThreatFox.Families {
			sorted = append(sorted, kv{k, v})
		}
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].v > sorted[j].v })
		for _, s := range sorted {
			b.WriteString(fmt.Sprintf("| %s | %d |\n", s.k, s.v))
		}
		b.WriteString("\n")

		if len(r.ThreatFox.Hosts) > 0 {
			b.WriteString("### C2 Hosts\n\n```\n")
			limit := len(r.ThreatFox.Hosts)
			if limit > 30 { limit = 30 }
			for _, h := range r.ThreatFox.Hosts[:limit] {
				b.WriteString(h + "\n")
			}
			if len(r.ThreatFox.Hosts) > 30 {
				b.WriteString(fmt.Sprintf("... +%d more\n", len(r.ThreatFox.Hosts)-30))
			}
			b.WriteString("```\n\n")
		}
	}

	// GitHub
	if r.GitHub != nil {
		b.WriteString("## GitHub Offensive Tools\n\n")
		b.WriteString(fmt.Sprintf("Total repos: %d\n\n", r.GitHub.TotalRepos))
		b.WriteString("| Stars | Repo | Description |\n|-------|------|-------------|\n")
		for _, repo := range r.GitHub.TopRepos {
			desc := repo.Desc
			if len(desc) > 60 { desc = desc[:60] + "..." }
			b.WriteString(fmt.Sprintf("| %d | %s | %s |\n", repo.Stars, repo.Name, desc))
		}
		b.WriteString("\n")
	}

	// C2 Concepts
	if r.C2 != nil {
		b.WriteString("## BB Conversion Concepts\n\n")
		b.WriteString(fmt.Sprintf("Total: %d concepts\n\n", r.C2.TotalConcepts))
		b.WriteString("| C2 | Feature | BB Tool Idea |\n|-----|---------|-------------|\n")
		for _, c := range r.C2.Concepts {
			b.WriteString(fmt.Sprintf("| %s | %s | %s |\n", c.C2, c.OffensiveFeature, c.BBConcept))
		}
		b.WriteString("\n")
	}

	// H1 Patterns
	if r.H1 != nil {
		b.WriteString("## HackerOne Report Patterns\n\n")
		b.WriteString(fmt.Sprintf("Reports analyzed: %d\n\n", r.H1.ReportsAnalyzed))
		if len(r.H1.VulnTypes) > 0 {
			b.WriteString("| Vulnerability Type | Count |\n|---|---|\n")
			type kv struct{ k string; v int }
			var sorted []kv
			for k, v := range r.H1.VulnTypes {
				sorted = append(sorted, kv{k, v})
			}
			sort.Slice(sorted, func(i, j int) bool { return sorted[i].v > sorted[j].v })
			for _, s := range sorted {
				b.WriteString(fmt.Sprintf("| %s | %d |\n", s.k, s.v))
			}
			b.WriteString("\n")
		}
		if len(r.H1.TopParams) > 0 {
			b.WriteString("### Top Parameters\n\n")
			for _, p := range r.H1.TopParams {
				b.WriteString(fmt.Sprintf("- `%s`\n", p))
			}
			b.WriteString("\n")
		}
	}

	return b.String()
}

func cmdStats(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: hunt-report stats <report.json>")
		os.Exit(1)
	}

	var report UnifiedReport
	if err := loadJSON(args[0], &report); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Load error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("  =============================================")
	fmt.Println("  Hunt Report Statistics")
	fmt.Println("  =============================================")
	fmt.Printf("  Generated:       %s\n", report.Timestamp)
	fmt.Printf("  Total IOCs:      %d\n", report.Summary.TotalIOCs)
	fmt.Printf("  Unique C2 Hosts: %d\n", report.Summary.UniqueC2Hosts)
	fmt.Printf("  GitHub Repos:    %d\n", report.Summary.GitHubRepos)
	fmt.Printf("  BB Concepts:     %d\n", report.Summary.BBConcepts)
	fmt.Printf("  Malware Families:%d\n", report.Summary.MalwareFamilies)
	fmt.Printf("  H1 Reports:     %d\n", report.Summary.H1Reports)
	fmt.Println()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("hunt-report: Aggregate offensive tool hunting results")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  hunt-report merge -tf tf.json -gh gh.json [-c2 c2.json] [-h1 h1.json] -o report.json")
		fmt.Println("  hunt-report merge -tf tf.json -gh gh.json --markdown -o report.md")
		fmt.Println("  hunt-report stats report.json")
		os.Exit(0)
	}

	switch os.Args[1] {
	case "merge":
		cmdMerge(os.Args[2:])
	case "stats":
		cmdStats(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}
