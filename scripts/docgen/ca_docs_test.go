package main

import (
	"os"
	"strings"
	"testing"
)

// TestSecurityAndDockerCADocsAgree guards #292: the security guide and the Docker
// deployment guide must not drift apart on how a private/self-signed OPNsense CA is
// trusted in the official image. The runtime image is distroless (no
// update-ca-certificates, and it does not merge /usr/local/share/ca-certificates into
// Go's trust roots), so the container recipe must use SSL_CERT_FILE + a mounted bundle.
// A bind mount into /usr/local/share/ca-certificates is the broken recipe and must not
// reappear.
func TestSecurityAndDockerCADocsAgree(t *testing.T) {
	repoRoot := findRepoRoot()

	security := readDoc(t, repoRoot+"/docs/security.md")
	docker := readDoc(t, repoRoot+"/docs/deployment/docker.md")

	// Both guides must document the verified container approach.
	for _, tc := range []struct {
		name string
		body string
	}{
		{"security.md", security},
		{"docs/deployment/docker.md", docker},
	} {
		if !strings.Contains(tc.body, "SSL_CERT_FILE") {
			t.Errorf("%s must document SSL_CERT_FILE for the distroless image's CA trust", tc.name)
		}
		// A container bind mount into the host CA directory does not work in the
		// distroless image. The host recipe uses `cp ... /usr/local/share/...`
		// (a space, not a `:` mount target), so this only catches the broken form.
		if strings.Contains(tc.body, ":/usr/local/share/ca-certificates") {
			t.Errorf("%s mounts a CA into /usr/local/share/ca-certificates; the distroless image "+
				"ignores that path -- use SSL_CERT_FILE + a mounted bundle instead (#292)", tc.name)
		}
	}

	// The security guide links to the canonical Docker recipe; that anchor must exist.
	if !strings.Contains(security, "deployment/docker.md#custom-ca-certificates") {
		t.Error("docs/security.md must link to deployment/docker.md#custom-ca-certificates")
	}
	if !strings.Contains(docker, "## Custom CA certificates") {
		t.Error("docs/deployment/docker.md must keep the '## Custom CA certificates' section (linked from security.md)")
	}
}

func readDoc(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(raw)
}
