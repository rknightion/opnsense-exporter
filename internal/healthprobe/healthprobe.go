// Package healthprobe implements the exporter's `health` subcommand: a local
// HTTP GET of the liveness route that exits 0 when the exporter answers 200 and
// 1 otherwise.
//
// It exists because the runtime image is distroless (Dockerfile: no shell, no
// package manager, no curl, no wget), so a container healthcheck has nothing to
// execute — and installing a shell or wget purely to rescue the published
// example would undo the deliberate minimal runtime (#438). The binary already
// in the image probes itself instead.
//
// The probe deliberately makes NO OPNsense API call. It reports whether this
// process is serving, which is what a liveness check is for; upstream
// reachability is /-/ready's job and must not be wired to a restart trigger.
package healthprobe

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Command is the argv token that selects the probe. It is dispatched from
// os.Args before the exporter's flag parser runs, so the probe is independent
// of the ~250-flag server surface — including the required --opnsense.protocol
// and --opnsense.address, which a kubelet exec probe or a Compose healthcheck
// has no reason to supply.
const Command = "health"

const (
	// DefaultURL matches the default listen address (:8080) and the fixed
	// liveness route (server.HealthyPath). A non-default --web.listen-address
	// needs --url; there is no env var for the listen address to derive it from.
	DefaultURL = "http://127.0.0.1:8080/-/healthy"

	// DefaultTimeout bounds the whole probe. The liveness handler writes a
	// constant with no upstream dependency, so anything slower than this is a
	// process that cannot answer, not a slow answer.
	DefaultTimeout = 2 * time.Second
)

// Run executes the probe with args (the arguments AFTER the subcommand token)
// and returns the process exit code: 0 when the exporter answered 200, 1 for
// every other outcome including a usage error. Only 0 and 1 are ever returned —
// container runtimes read "unhealthy" from any nonzero code, and a wider code
// space would only invite scripts to branch on values this probe cannot
// meaningfully distinguish.
func Run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(Command, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: opnsense-exporter %s [flags]\n\n"+
			"Probes the exporter's own liveness route and exits 0 (healthy) or 1.\n"+
			"Makes no OPNsense API call.\n\nFlags:\n", Command)
		fs.PrintDefaults()
	}
	url := fs.String("url", DefaultURL, "liveness URL to probe")
	timeout := fs.Duration("timeout", DefaultTimeout, "overall probe timeout")
	insecure := fs.Bool("insecure", false, "skip TLS verification (for a --web.config.file TLS port with a private cert)")
	if err := fs.Parse(args); err != nil {
		// flag already wrote the error (or the usage text) to stderr.
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "health: unexpected argument %q\n", fs.Arg(0))
		return 1
	}
	if *timeout <= 0 {
		fmt.Fprintf(stderr, "health: --timeout must be positive, got %s\n", *timeout)
		return 1
	}

	if err := probe(*url, *timeout, *insecure); err != nil {
		fmt.Fprintf(stderr, "health: %v\n", err)
		return 1
	}
	return 0
}

// probe performs the request. A redirect is refused rather than followed: the
// liveness route answers 200 directly, so a 3xx means something other than this
// exporter is on the socket, and following it could turn an arbitrary reachable
// URL into a green healthcheck.
func probe(url string, timeout time.Duration, insecure bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("invalid --url %q: %w", url, err)
	}
	req.Header.Set("User-Agent", "opnsense-exporter-health/1")

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	if insecure {
		client.Transport = &http.Transport{
			//nolint:gosec // G402: opt-in only, for probing a metrics port secured with a private/self-signed cert.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("no answer from %s within %s", url, timeout)
		}
		return fmt.Errorf("%s unreachable: %w", url, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %d %s, want 200", url, resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	return nil
}
