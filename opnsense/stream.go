package opnsense

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// streamHandshakeTimeout bounds only the CONNECT half of a stream: DNS, TCP, TLS,
// auth and the response headers. Once headers are in, the body is read for as long
// as the caller holds it.
const streamHandshakeTimeout = 15 * time.Second

// OpenCPUStream opens `api/diagnostics/cpu_usage/stream` as a long-lived Server-Sent
// Events connection and returns its body. The caller owns the body and MUST close
// it; cancelling ctx aborts the read in flight, which is how internal/cpustream's
// stall watchdog forces a re-dial.
//
// WHY THIS DOES NOT GO THROUGH do(). The normal request path reads the whole
// response into memory, decodes it as JSON, retries, and may cache it — every one of
// which is wrong for a body that never ends. It also runs under the shared
// http.Client, whose Timeout bounds the ENTIRE request including the body read: on a
// stream that is not a safety net, it is a guaranteed disconnect every
// --opnsense.timeout seconds (15s by default).
//
// So this uses a second http.Client that SHARES the configured Transport — so TLS
// verification, the CA pool, --opnsense.insecure and the redirect policy are
// identical, with no duplicated security-relevant configuration — but carries no
// whole-request timeout. The connect half is bounded separately by
// streamHandshakeTimeout, so an unreachable box still fails promptly instead of
// hanging forever on the dial.
//
// It also deliberately does not take an upstream-concurrency slot: those bound
// concurrent POLLS, and a permanently held stream would occupy one forever.
func (c *Client) OpenCPUStream(ctx context.Context) (io.ReadCloser, error) {
	path, ok := c.endpoints["cpuUsageStream"]
	if !ok {
		return nil, fmt.Errorf("endpoint %q not found in client endpoints", "cpuUsageStream")
	}

	// Bound the handshake only. The timer is stopped once headers are in, leaving
	// the body read unbounded.
	dialCtx, cancelDial := context.WithCancel(ctx)
	handshake := time.AfterFunc(streamHandshakeTimeout, cancelDial)

	req, err := http.NewRequestWithContext(dialCtx, http.MethodGet, fmt.Sprintf("%s/%s", c.baseURL, path), nil)
	if err != nil {
		handshake.Stop()
		cancelDial()
		return nil, err
	}
	req.SetBasicAuth(c.key, c.secret)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	if ua, ok := c.headers["User-Agent"]; ok {
		req.Header.Set("User-Agent", ua)
	}
	// No Accept-Encoding: gzip. The transport would buffer to fill its decompressor
	// window, which on a ~70 bytes/sec stream means frames arrive in clumps minutes
	// apart — a stall the watchdog would correctly, and pointlessly, act on.
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := c.streamHTTPClient().Do(req)
	handshake.Stop()
	if err != nil {
		cancelDial()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		cancelDial()
		return nil, fmt.Errorf("cpu usage stream returned HTTP %d", resp.StatusCode)
	}

	// Ownership of dialCtx passes to the body: closing the body releases it.
	return &streamBody{ReadCloser: resp.Body, cancel: cancelDial}, nil
}

// streamBody ties the request context's cancel to Close so the connection is
// released exactly once, whoever ends it.
type streamBody struct {
	io.ReadCloser
	cancel context.CancelFunc
	once   sync.Once
}

func (b *streamBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.cancel)
	return err
}

// streamHTTPClient returns the timeout-free client used for streaming. Built per
// dial rather than cached: an http.Client is a thin value and the connection pool
// lives in the Transport, which is shared, so there is nothing to reuse — and a
// cached one would need a lock on a Client that is returned by value.
func (c *Client) streamHTTPClient() *http.Client {
	return &http.Client{
		Transport:     c.httpClient.Transport,
		CheckRedirect: c.httpClient.CheckRedirect,
		// Timeout deliberately zero — see OpenCPUStream.
	}
}
