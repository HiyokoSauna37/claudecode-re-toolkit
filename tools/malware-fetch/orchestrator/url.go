package orchestrator

import (
	"regexp"
	"strings"
)

var reHxxp = regexp.MustCompile(`(?i)hxxp(s?)`)

// Refang converts a defanged URL to a normal URL.
func Refang(url string) string {
	url = reHxxp.ReplaceAllString(url, "http$1")
	url = strings.ReplaceAll(url, "[.]", ".")
	url = strings.ReplaceAll(url, "(.)", ".")
	url = strings.ReplaceAll(url, "{.}", ".")
	url = strings.ReplaceAll(url, "[@]", "@")
	url = strings.ReplaceAll(url, "(@)", "@")
	url = strings.ReplaceAll(url, " ", "")
	return url
}
