package orchestrator

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// ListingEntry represents one file/directory in an HTTP directory listing.
type ListingEntry struct {
	Name     string
	Href     string
	Size     string
	Modified string
	IsDir    bool
}

// reAnchor matches <a href="...">...</a> tags.
var reAnchor = regexp.MustCompile(`<a\s+[^>]*href="([^"]+)"[^>]*>([^<]+)</a>`)

// reDateSize matches common date+size patterns near anchor tags.
// Apache: "2026-03-01 12:34  1.2M"
// Nginx:  "01-Mar-2026 12:34  1234"
// Python http.server: "2026-03-01 12:34  1.2K"
var reDateSize = regexp.MustCompile(`(\d{1,4}[-/]\w{3,9}[-/]\d{2,4}\s+\d{2}:\d{2}(?::\d{2})?)\s+([\d.]+[KMGTkmgt]?|-)`)

// FetchDirectoryListing fetches a URL and parses it as an HTTP directory listing.
func FetchDirectoryListing(rawURL string) ([]ListingEntry, error) {
	targetURL := Refang(rawURL)

	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	return parseDirectoryListing(string(body)), nil
}

// parseDirectoryListing extracts file entries from HTML directory listing.
func parseDirectoryListing(html string) []ListingEntry {
	var entries []ListingEntry

	lines := strings.Split(html, "\n")
	for _, line := range lines {
		matches := reAnchor.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			href := m[1]
			name := strings.TrimSpace(m[2])

			// Skip parent directory and sort links
			if name == ".." || name == "../" || name == "." || name == "./" {
				continue
			}
			if href == "?" || strings.HasPrefix(href, "?") {
				continue
			}
			// Skip Apache column-sort links
			if strings.Contains(href, "?C=") {
				continue
			}

			entry := ListingEntry{
				Name:  name,
				Href:  href,
				IsDir: strings.HasSuffix(href, "/"),
			}

			// Try to extract date and size from the same line
			dateMatches := reDateSize.FindStringSubmatch(line)
			if len(dateMatches) >= 3 {
				entry.Modified = dateMatches[1]
				entry.Size = dateMatches[2]
			}

			entries = append(entries, entry)
		}
	}

	return entries
}

// PrintDirectoryListing prints directory listing in a table format.
func PrintDirectoryListing(rawURL string) error {
	entries, err := FetchDirectoryListing(rawURL)
	if err != nil {
		return err
	}

	if len(entries) == 0 {
		fmt.Println("No entries found (page may not be a directory listing)")
		return nil
	}

	// Calculate column widths
	maxName := 4 // "Name"
	maxSize := 4 // "Size"
	maxDate := 8 // "Modified"
	for _, e := range entries {
		if len(e.Name) > maxName {
			maxName = len(e.Name)
		}
		if len(e.Size) > maxSize {
			maxSize = len(e.Size)
		}
		if len(e.Modified) > maxDate {
			maxDate = len(e.Modified)
		}
	}
	if maxName > 60 {
		maxName = 60
	}

	// Header
	fmt.Printf("%-*s  %-*s  %-*s  %s\n", maxName, "Name", maxSize, "Size", maxDate, "Modified", "Type")
	fmt.Printf("%s  %s  %s  %s\n",
		strings.Repeat("-", maxName),
		strings.Repeat("-", maxSize),
		strings.Repeat("-", maxDate),
		strings.Repeat("-", 4))

	// Entries
	dirs := 0
	files := 0
	for _, e := range entries {
		name := e.Name
		if len(name) > maxName {
			name = name[:maxName-3] + "..."
		}
		typ := "file"
		if e.IsDir {
			typ = "dir"
			dirs++
		} else {
			files++
		}
		size := e.Size
		if size == "" {
			size = "-"
		}
		modified := e.Modified
		if modified == "" {
			modified = "-"
		}
		fmt.Printf("%-*s  %-*s  %-*s  %s\n", maxName, name, maxSize, size, maxDate, modified, typ)
	}

	fmt.Printf("\nTotal: %d files, %d directories\n", files, dirs)
	return nil
}
