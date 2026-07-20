// Package zenarmor receives Zenarmor's reporting data by posing as an
// Elasticsearch node.
//
// Zenarmor's ipdrstreamer can stream its six reporting families to an external
// Elasticsearch cluster. That is the only push export it offers below the licence
// tier that unlocks syslog, so impersonating an ES node is how this exporter gets
// the data at all. We serve the small handful of endpoints ipdrstreamer actually
// calls, take the documents out of its _bulk writes, and turn them into neutral
// logship Records.
//
// Two things about that client shape the whole package:
//
//   - It links the OFFICIAL github.com/elastic/go-elasticsearch, which runs a
//     product check before its first API call and hard-refuses any server that does
//     not return the X-Elastic-Product header ("the client noticed that the server is
//     not Elasticsearch and we do not support this unknown product"). Every response
//     written here carries it. Miss it and the receiver silently gets nothing.
//   - Zenarmor supports Elasticsearch 8.9.x-8.17.1 only, so we report 8.11.3.
//
// The endpoint set is not a guess: it is what a production Zenarmor was observed
// calling while it streamed 2,824 documents at a throwaway capture stub.
package zenarmor

import (
	"bytes"
	"compress/gzip"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/logship"
	"github.com/rknightion/opnsense-exporter/internal/logship/capture"
)

const (
	// esVersion is what GET / reports. Zenarmor refuses to stream to anything outside
	// 8.9.x-8.17.1, and this mirrors the ES the firewall itself runs.
	esVersion   = "8.11.3"
	esBuildHash = "64cf052f3b56b1fd4449f5454cb88aca7e739d9a"
	esBuildDate = "2023-12-08T11:33:53.634979452Z"
	// esClusterUUID is deliberately a fixed, made-up identity rather than anything
	// belonging to a real cluster: Zenarmor stores a ClusterUUID per streaming target,
	// and reusing a real cluster's uuid would alias us onto it.
	esClusterUUID = "Zx7QmKpLR2ODqW3nB8vTfA"

	// maxBodyBytes caps a single request body. Live bulk writes ran a few hundred KB;
	// this is generous enough to never clip one while still bounding what a broken or
	// hostile peer can make us buffer. It is applied TWICE, to two different sizes: to
	// the compressed wire bytes (http.MaxBytesReader) AND to the decompressed stream —
	// see readBody. The two are not the same number for a gzip body, and only the wire
	// limit says nothing about how far a zip bomb expands.
	maxBodyBytes = 64 << 20
)

// errBodyTooLarge is returned by readBody when the DECOMPRESSED stream would exceed
// maxBodyBytes. It joins the same 400 + reject("body") path as any other unreadable
// body — a distinct label would only split a signal the operator already reads as one.
var errBodyTooLarge = errors.New("zenarmor: decompressed body exceeds limit")

// Config is the receiver's runtime configuration. options.ZenarmorConfig is
// converted into it, so that this package never imports options for its own config
// type.
type Config struct {
	// Addr is the TCP address the receiver binds.
	Addr string
	// AllowedPeers, when non-empty, is an allowlist: any other peer is refused and
	// counted.
	AllowedPeers    []netip.Prefix
	DropSelfTraffic bool
	// Families restricts which reporting families are shipped. Empty means all.
	Families []string
	// Excludes drops records whose named field matches the rule's regex. Empty (the
	// default) drops nothing. Parsed and validated at startup by parseExcludeRules.
	Excludes []ExcludeRule
	// Enrich turns the per-record snapshot lookups on.
	Enrich bool
	// AuthUser and AuthPassword, when set, require HTTP basic auth.
	AuthUser     string
	AuthPassword string
	// TLSConfig, when non-nil, serves HTTPS instead of HTTP.
	TLSConfig *tls.Config
	// DebugCapture opts this receiver into the shared debug-capture sink (#330). The
	// sink itself arrives via Deps; this bool is what gates whether it is used.
	DebugCapture bool
}

// unhandledLogInterval throttles the unhandled-endpoint log per method+path. It is
// long because the log and the counter carry different halves of the signal: the
// counter carries the rate, so the log only has to carry the identity — once per
// route is enough to act on, and a route Zenarmor probes on a timer must not fill the
// log with a fact the operator already has.
const unhandledLogInterval = 15 * time.Minute

// unhandledLogMaxKeys bounds the limiter's key set. Unlike the pipeline's, these keys
// come off the wire, so the cap is what stops a broken or hostile peer walking
// distinct paths from growing the map without bound. Generous next to Zenarmor's real
// surface (a handful of routes) and small enough to stay negligible.
const unhandledLogMaxKeys = 64

// server implements the Elasticsearch surface. onBulk is called once per document
// in a _bulk write, on the request goroutine.
type server struct {
	cfg    Config
	onBulk func(index string, doc []byte, peer netip.Addr)
	m      *metrics
	log    *slog.Logger
	// cap is the debug-capture sink, or nil when this receiver did not opt in. A nil
	// *capture.Capturer is a no-op, so it is called unconditionally.
	cap *capture.Capturer
	// unhandledLog throttles the per-route log below, keyed by method+path.
	unhandledLog *logship.LogLimiter

	mu      sync.RWMutex
	indices map[string]bool
}

// newServer builds the ES handler. onBulk receives every document Zenarmor writes,
// paired with the index it was addressed to and the address that sent it; it MUST
// NOT retain doc, which points into the request body. m may be nil, and log may be
// nil (it then falls back to the default logger).
//
// peer is the sender's real address, which is what lets the receiver recognise a
// record describing its own ingest connection (see self.go). It is the zero Addr if
// RemoteAddr cannot be parsed — never a guess.
// newServer returns *server (not http.Handler) so a caller can set optional fields
// like cap after construction; *server implements http.Handler, so existing callers
// that use it as a handler are unaffected.
func newServer(cfg Config, onBulk func(index string, doc []byte, peer netip.Addr), m *metrics, log *slog.Logger) *server {
	if log == nil {
		log = slog.Default()
	}
	return &server{
		cfg: cfg, onBulk: onBulk, m: m, log: log,
		unhandledLog: logship.NewLogLimiter(unhandledLogInterval, unhandledLogMaxKeys),
		indices:      make(map[string]bool),
	}
}

// remotePeer resolves the request's sender address, unmapped so a v4-mapped v6 peer
// compares equal to the plain v4 address Zenarmor writes into its records.
func remotePeer(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// esHeaders stamps the product header on every single response. Without it the
// official go-elasticsearch client refuses to speak to us at all — this is the
// single most load-bearing line in the package.
func esHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Elastic-Product", "Elasticsearch")
	w.Header().Set("Content-Type", "application/json")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	esHeaders(w)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.peerAllowed(r) {
		s.m.reject("peer")
		esHeaders(w)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if !s.authOK(r) {
		s.m.reject("auth")
		esHeaders(w)
		w.Header().Set("WWW-Authenticate", `Basic realm="elasticsearch"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	path := r.URL.Path
	switch {
	case isBulkPath(path):
		s.handleBulk(w, r, path)

	case path == "/":
		// The product-check handshake.
		writeJSON(w, http.StatusOK, map[string]any{
			"name":         "opnsense-exporter",
			"cluster_name": "elasticsearch",
			"cluster_uuid": esClusterUUID,
			"version": map[string]any{
				"number":                              esVersion,
				"build_flavor":                        "default",
				"build_type":                          "tar",
				"build_hash":                          esBuildHash,
				"build_date":                          esBuildDate,
				"build_snapshot":                      false,
				"lucene_version":                      "9.8.0",
				"minimum_wire_compatibility_version":  "7.17.0",
				"minimum_index_compatibility_version": "7.0.0",
			},
			"tagline": "You Know, for Search",
		})

	case strings.HasPrefix(path, "/_cat/indices"), strings.HasPrefix(path, "/_cat/aliases"):
		// A JSON ARRAY, which is what a real ES returns and what the client's decoder
		// expects. Answering {} here is what the throwaway capture stub did, and it made
		// Zenarmor take a fallback path. Reporting none makes it create its own.
		writeJSON(w, http.StatusOK, []any{})

	case path == "/_aliases":
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	default:
		s.handleIndex(w, r, path)
	}
}

// handleIndex serves the bare /<index> paths: the exists probe, the create, and the
// alias delete. Anything else falls through to the permissive default.
func (s *server) handleIndex(w http.ResponseWriter, r *http.Request, path string) {
	idx := strings.Trim(path, "/")
	if idx == "" || strings.HasPrefix(idx, "_") || strings.Contains(idx, "/") {
		s.unhandled(w, r, path)
		return
	}
	switch r.Method {
	case http.MethodHead, http.MethodGet:
		if !s.hasIndex(idx) {
			esHeaders(w)
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"type":"index_not_found_exception","reason":"no such index"},"status":404}`))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{idx: map[string]any{
			"aliases": map[string]any{}, "mappings": map[string]any{}, "settings": map[string]any{},
		}})

	case http.MethodPut:
		s.addIndex(idx)
		writeJSON(w, http.StatusOK, map[string]any{
			"acknowledged": true, "shards_acknowledged": true, "index": idx,
		})

	case http.MethodDelete:
		// Forget it too, so the exists probe stays honest: if Zenarmor deletes and then
		// re-probes, it should be told to recreate rather than be lied to.
		s.dropIndex(idx)
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

	default:
		s.unhandled(w, r, path)
	}
}

// unhandled answers anything outside the observed endpoint set permissively, so a
// change in Zenarmor's client surface degrades into a counted signal rather than a
// silent outage. logs_rejected_total{reason="unhandled_endpoint"} tells an operator to
// come and look; the log line is what they look AT. Without it the counter names
// nothing and the only way left to identify the route is a packet capture on a
// multi-GB/day stream — the expensive path the counter exists to avoid (#285).
//
// The path is deliberately logged and NOT made a metric label: it embeds index names
// (zenarmor_<uuid>_<family>_write), so it is wire-sourced and unbounded, which #280
// forbids as a label. A log line is the surface that can carry such a value.
//
// The counter increments on every call, throttled or not: suppression must cost the
// operator log noise, never the rate.
func (s *server) unhandled(w http.ResponseWriter, r *http.Request, path string) {
	s.m.reject("unhandled_endpoint")
	// When debug-capture is on, the capture file carries this signal in full (method,
	// path, headers, body) — so the WARN is redundant noise and is suppressed. The
	// counter still fires either way, so the rate is never lost.
	if s.cap != nil {
		s.captureUnhandled(r, path)
	} else if s.unhandledLog.Allow(r.Method + " " + path) {
		// Keyed on method+path so a newly-appearing route is reported promptly rather than
		// inheriting the throttle of one already being suppressed.
		s.log.Warn("zenarmor called an endpoint this receiver does not implement (answered 200 {}; repeats throttled)",
			"method", r.Method, "path", path, "source", sourceName)
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

// captureBodyLimit bounds the body captured for an unhandled request. Generous for
// the control-plane calls seen in practice (GETs with no body) yet small enough that
// a hostile peer cannot make a debug dump expensive.
const captureBodyLimit = 64 << 10

// captureUnhandled dumps an unhandled request to the debug-capture sink: method,
// path, query, headers, and a bounded, gzip-decoded body. It reads the body here,
// which is safe precisely because unhandled is terminal — nothing else consumes it.
func (s *server) captureUnhandled(r *http.Request, path string) {
	fields := map[string]any{
		"method":  r.Method,
		"path":    path,
		"headers": map[string][]string(r.Header),
	}
	if r.URL.RawQuery != "" {
		fields["query"] = r.URL.RawQuery
	}
	if body := readCapturedBody(r); body != "" {
		fields["body"] = body
	}
	s.cap.Capture(sourceName, capture.KindUnhandledEndpoint, fields)
}

// readCapturedBody reads up to captureBodyLimit bytes of the request body,
// transparently decompressing gzip, and returns it as a string. It never errors:
// this is a best-effort debug read, and a body it cannot read is simply omitted.
func readCapturedBody(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	rdr := io.LimitReader(r.Body, captureBodyLimit)
	if strings.Contains(r.Header.Get("Content-Encoding"), "gzip") {
		zr, err := gzip.NewReader(rdr)
		if err != nil {
			return ""
		}
		defer func() { _ = zr.Close() }()
		rdr = io.LimitReader(zr, captureBodyLimit)
	}
	b, err := io.ReadAll(rdr)
	if err != nil {
		return ""
	}
	return string(b)
}

func isBulkPath(path string) bool {
	return path == "/_bulk" || strings.HasSuffix(path, "/_bulk")
}

func (s *server) hasIndex(idx string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.indices[idx]
}

func (s *server) addIndex(idx string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.indices[idx] = true
}

func (s *server) dropIndex(idx string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.indices, idx)
}

func (s *server) peerAllowed(r *http.Request) bool {
	if len(s.cfg.AllowedPeers) == 0 {
		return true
	}
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	peer := ap.Addr().Unmap() // a v4-mapped v6 peer must match a v4 prefix
	for _, p := range s.cfg.AllowedPeers {
		if p.Contains(peer) {
			return true
		}
	}
	return false
}

func (s *server) authOK(r *http.Request) bool {
	if s.cfg.AuthUser == "" && s.cfg.AuthPassword == "" {
		return true
	}
	u, p, ok := r.BasicAuth()
	if !ok {
		return false
	}
	// Both comparisons always run: && would short-circuit on a wrong username and
	// leak the password check's timing.
	userOK := subtle.ConstantTimeCompare([]byte(u), []byte(s.cfg.AuthUser)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(p), []byte(s.cfg.AuthPassword)) == 1
	return userOK && passOK
}

// readBody reads a capped request body, transparently decompressing gzip.
//
// Two ceilings, deliberately, and they are not the same rule. http.MaxBytesReader caps
// the COMPRESSED wire bytes; that bounds what the socket delivers but says nothing about
// what gzip expands it into — a few KB of repeated bytes inflate to gigabytes (#288). So
// the decoded stream is read through an io.LimitReader of maxBodyBytes+1: the extra byte
// is the overflow tell, and capping the read is what keeps a zip bomb from ever being
// fully buffered before we reject it.
//
// A gzip reader that fails is an error, never a fall back to the raw bytes: the raw
// bytes of a gzip stream are not NDJSON, and parsing them would manufacture garbage
// records out of a transport fault.
func readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var rdr io.Reader = r.Body
	if strings.Contains(r.Header.Get("Content-Encoding"), "gzip") {
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			return nil, err
		}
		defer func() { _ = zr.Close() }()
		rdr = zr
	}
	b, err := io.ReadAll(io.LimitReader(rdr, maxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxBodyBytes {
		return nil, errBodyTooLarge
	}
	return b, nil
}

// handleBulk parses the NDJSON action/document pairs and returns the response
// envelope the client needs to consider the write a success.
func (s *server) handleBulk(w http.ResponseWriter, r *http.Request, path string) {
	start := time.Now()
	b, err := readBody(w, r)
	if err != nil {
		// Answer honestly rather than claim success: a 200 with errors:false would make
		// the client drop a batch it never actually delivered.
		s.m.reject("body")
		esHeaders(w)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	s.m.observeBulk(len(b))

	defaultIdx := bulkDefaultIndex(path)
	// Non-nil so an empty bulk encodes as [] rather than null.
	items := make([]map[string]any, 0, 16)

	// Slicing the whole body rather than scanning it: every line then stays valid for
	// the life of the request, and there is no maximum token size to outgrow.
	for rest := b; len(rest) > 0; {
		var line []byte
		line, rest = nextLine(rest)
		if len(line) == 0 {
			continue
		}
		op, idx, id, ok := parseAction(line)
		if !ok {
			s.m.parseError("bulk")
			continue
		}
		if idx == "" {
			idx = defaultIdx
		}
		// index/create/update are followed by a source line; delete is not.
		if op == "index" || op == "create" || op == "update" {
			var doc []byte
			doc, rest = nextLine(rest)
			if len(doc) > 0 && s.onBulk != nil {
				s.onBulk(idx, doc, remotePeer(r))
			}
		}
		if id == "" {
			id = "0"
		}
		items = append(items, map[string]any{op: map[string]any{
			"_index": idx, "_id": id, "_version": 1, "result": "created",
			"_shards": map[string]any{"total": 1, "successful": 1, "failed": 0},
			"status":  http.StatusCreated,
		}})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"took":   time.Since(start).Milliseconds(),
		"errors": false,
		"items":  items,
	})
}

// bulkDefaultIndex extracts the index a /<idx>/_bulk URL targets. A bare /_bulk has
// none, and every action line then has to name its own.
func bulkDefaultIndex(path string) string {
	p := strings.Trim(path, "/")
	p = strings.TrimSuffix(p, "_bulk")
	p = strings.Trim(p, "/")
	if p == "" {
		return ""
	}
	return strings.Split(p, "/")[0]
}

// nextLine splits off the leading NDJSON line, returning it trimmed along with the
// remainder. Both slices alias the input.
func nextLine(b []byte) (line, rest []byte) {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		return bytes.TrimSpace(b[:i]), b[i+1:]
	}
	return bytes.TrimSpace(b), nil
}

// parseAction decodes a bulk action line — a single-key object naming the operation
// and its metadata, e.g. {"index":{"_index":"...","_id":"1"}}.
func parseAction(line []byte) (op, idx, id string, ok bool) {
	var action map[string]json.RawMessage
	if err := json.Unmarshal(line, &action); err != nil {
		return "", "", "", false
	}
	for k, v := range action {
		var meta struct {
			Index string `json:"_index"`
			ID    string `json:"_id"`
		}
		_ = json.Unmarshal(v, &meta)
		op, idx, id = k, meta.Index, meta.ID
	}
	if op == "" {
		return "", "", "", false
	}
	return op, idx, id, true
}
