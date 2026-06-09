package main

import (
	"fmt"
	"regexp"
	"strings"
)

// injectRegion replaces the content between <!-- docgen:begin:NAME --> and
// <!-- docgen:end:NAME -->, keeping the marker lines.
func injectRegion(doc, name, content string) (string, error) {
	begin := fmt.Sprintf("<!-- docgen:begin:%s -->", name)
	end := fmt.Sprintf("<!-- docgen:end:%s -->", name)
	bi := strings.Index(doc, begin)
	ei := strings.Index(doc, end)
	if bi < 0 || ei < 0 {
		return "", fmt.Errorf("docgen region %q: marker missing (begin found=%v, end found=%v)", name, bi >= 0, ei >= 0)
	}
	if ei < bi {
		return "", fmt.Errorf("docgen region %q: end marker before begin marker", name)
	}
	return doc[:bi+len(begin)] + "\n" + strings.TrimSpace(content) + "\n" + doc[ei:], nil
}

// statRule pins a numeric claim in prose/config files to generated stats. A
// rule that stops matching (MinHits violated) is a hard error so reworded
// prose cannot silently escape the pin.
type statRule struct {
	File    string // repo-relative path
	Pattern *regexp.Regexp
	Replace string // expansion template; numbers already substituted via Sprintf
	MinHits int
}

func applyStatRule(content string, r statRule) (string, error) {
	hits := len(r.Pattern.FindAllStringIndex(content, -1))
	if hits < r.MinHits {
		return "", fmt.Errorf("stat rule %q in %s matched %d times, want >= %d (was the phrasing changed?)",
			r.Pattern.String(), r.File, hits, r.MinHits)
	}
	return r.Pattern.ReplaceAllString(content, r.Replace), nil
}
