package orchestrator

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
)

// Metadata represents the analysis output metadata.
type Metadata struct {
	URL            string     `json:"url"`
	OriginalInput  string     `json:"original_input"`
	Timestamp      string     `json:"timestamp"`
	Domain         string     `json:"domain"`
	FinalURL       string     `json:"final_url"`
	Screenshot     string     `json:"screenshot"`
	HTMLFile       string     `json:"html_file"`
	Downloads      []Download `json:"downloads"`
	NetworkLogFile string     `json:"network_log_file"`
	Success        bool       `json:"success"`
	Error          string     `json:"error"`
}

// Download represents a downloaded file with hashes and VT results.
type Download struct {
	Filename   string            `json:"filename"`
	Hashes     map[string]string `json:"hashes"`
	VirusTotal *VTResult         `json:"virustotal,omitempty"`
}

// NetworkEntry represents one network request/response.
type NetworkEntry struct {
	Timestamp     string `json:"Timestamp"`
	RequestID     string `json:"RequestID"`
	Method        string `json:"Method"`
	URL           string `json:"URL"`
	Domain        string `json:"Domain"`
	DestinationIP string `json:"DestinationIP"`
	StatusCode    string `json:"StatusCode"`
	ContentType   string `json:"ContentType"`
	ContentLength string `json:"ContentLength"`
	Referer       string `json:"Referer"`
	UserAgent     string `json:"UserAgent"`
	SetCookie     string `json:"SetCookie"`
	Duration      string `json:"Duration"`
	RedirectTo    string `json:"RedirectTo"`
	Description   string `json:"Description"`
}

// SaveMetadata writes metadata as JSON.
func SaveMetadata(metadata *Metadata, outputPath string) error {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, data, 0o644)
}

// SaveNetworkCSV writes network traffic log as CSV (Timeline Explorer compatible).
func SaveNetworkCSV(entries []NetworkEntry, outputPath string) error {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// BOM for UTF-8 (Excel/Timeline Explorer compatibility)
	f.Write([]byte{0xEF, 0xBB, 0xBF})

	writer := csv.NewWriter(f)
	defer writer.Flush()

	// Header
	header := []string{
		"Timestamp", "RequestID", "Method", "URL", "Domain", "DestinationIP",
		"StatusCode", "ContentType", "ContentLength", "Referer", "UserAgent",
		"SetCookie", "Duration", "RedirectTo", "Description",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Rows
	for _, e := range entries {
		row := []string{
			e.Timestamp, e.RequestID, e.Method, e.URL, e.Domain, e.DestinationIP,
			e.StatusCode, e.ContentType, e.ContentLength, e.Referer, e.UserAgent,
			e.SetCookie, e.Duration, e.RedirectTo, e.Description,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}
