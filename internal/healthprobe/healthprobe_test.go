package healthprobe_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/healthprobe"
)

// The probe exists because the runtime image is distroless (#438): there is no
// shell, no curl and no wget for a container healthcheck to call, and adding one
// would undo the deliberate minimal runtime. The binary probes itself instead.

func TestRun_HealthyReturnsZero(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer srv.Close()

	var out, errOut bytes.Buffer
	code := healthprobe.Run([]string{"--url=" + srv.URL + "/-/healthy"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	if gotPath != "/-/healthy" {
		t.Errorf("probed path = %q, want /-/healthy", gotPath)
	}
}

// The default URL must be usable with no arguments at all, which is what makes the
// published Compose healthcheck a single CMD entry.
func TestDefaultURLIsTheHealthyRoute(t *testing.T) {
	if !strings.HasSuffix(healthprobe.DefaultURL, "/-/healthy") {
		t.Errorf("DefaultURL = %q, want it to target /-/healthy (not the operator console root)", healthprobe.DefaultURL)
	}
	if !strings.Contains(healthprobe.DefaultURL, "127.0.0.1:8080") {
		t.Errorf("DefaultURL = %q, want the default listen address 127.0.0.1:8080", healthprobe.DefaultURL)
	}
}

func TestRun_NonOKReturnsOne(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Not Ready", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	var out, errOut bytes.Buffer
	code := healthprobe.Run([]string{"--url=" + srv.URL + "/-/healthy"}, &out, &errOut)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), "503") {
		t.Errorf("stderr = %q, want it to name the status code", errOut.String())
	}
}

func TestRun_UnreachableReturnsOne(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing is listening now

	var out, errOut bytes.Buffer
	code := healthprobe.Run([]string{"--url=" + url + "/-/healthy"}, &out, &errOut)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if errOut.Len() == 0 {
		t.Error("want a reason on stderr for an unreachable exporter")
	}
}

func TestRun_TimeoutReturnsOne(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer func() {
		close(release)
		srv.Close()
	}()

	var out, errOut bytes.Buffer
	start := time.Now()
	code := healthprobe.Run([]string{"--url=" + srv.URL + "/-/healthy", "--timeout=100ms"}, &out, &errOut)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("probe took %s, want it bounded by --timeout", elapsed)
	}
}

// A redirect is not a healthy exporter: /-/healthy answers 200 directly, so a 3xx
// means something else is on the other end of the socket.
func TestRun_RedirectReturnsOne(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, "http://example.invalid/", http.StatusFound)
	}))
	defer srv.Close()

	var out, errOut bytes.Buffer
	if code := healthprobe.Run([]string{"--url=" + srv.URL + "/-/healthy"}, &out, &errOut); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestRun_UnknownFlagReturnsOne(t *testing.T) {
	var out, errOut bytes.Buffer
	code := healthprobe.Run([]string{"--nope"}, &out, &errOut)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if errOut.Len() == 0 {
		t.Error("want usage output on stderr for an unknown flag")
	}
}

// --insecure exists so a TLS-enabled metrics port (--web.config.file) can still be
// probed from inside the image, where there is no curl -k to fall back on.
func TestRun_InsecureAllowsSelfSignedTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var out, errOut bytes.Buffer
	if code := healthprobe.Run([]string{"--url=" + srv.URL + "/-/healthy"}, &out, &errOut); code != 1 {
		t.Fatalf("without --insecure: exit code = %d, want 1 (untrusted cert)", code)
	}
	out.Reset()
	errOut.Reset()
	if code := healthprobe.Run([]string{"--url=" + srv.URL + "/-/healthy", "--insecure"}, &out, &errOut); code != 0 {
		t.Fatalf("with --insecure: exit code = %d, want 0 (stderr: %s)", code, errOut.String())
	}
}

// --help is a successful invocation, not a probe failure.
func TestRun_HelpReturnsZero(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := healthprobe.Run([]string{"--help"}, &out, &errOut); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(errOut.String(), "opnsense-exporter health") {
		t.Errorf("usage text missing: %q", errOut.String())
	}
}
