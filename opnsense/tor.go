package opnsense

import (
	"bytes"
	"encoding/json"
	"net/http"
)

// Tor circuit-status vocabulary (torspec control-spec.txt §4.1.1). The spec
// explicitly states clients MUST accept purposes/statuses not listed here (the
// vocabulary is extensible), so an unrecognised value is bucketed under
// "other" rather than treated as an error.
var torCircuitStatusVocabulary = map[string]struct{}{
	"LAUNCHED":   {},
	"BUILT":      {},
	"GUARD_WAIT": {},
	"EXTENDED":   {},
	"FAILED":     {},
	"CLOSED":     {},
}

var torCircuitPurposeVocabulary = map[string]struct{}{
	"GENERAL":           {},
	"HS_CLIENT_INTRO":   {},
	"HS_CLIENT_REND":    {},
	"HS_SERVICE_INTRO":  {},
	"HS_SERVICE_REND":   {},
	"TESTING":           {},
	"CONTROLLER":        {},
	"MEASURE_TIMEOUT":   {},
	"HS_VANGUARDS":      {},
	"PATH_BIAS_TESTING": {},
	"CIRCUIT_PADDING":   {},
}

// Tor stream-status vocabulary (torspec control-spec.txt §4.1.2 / §3.9).
var torStreamStatusVocabulary = map[string]struct{}{
	"NEW":             {},
	"NEWRESOLVE":      {},
	"REMAP":           {},
	"SENTCONNECT":     {},
	"SENTRESOLVE":     {},
	"SUCCEEDED":       {},
	"FAILED":          {},
	"CLOSED":          {},
	"DETACHED":        {},
	"CONTROLLER_WAIT": {},
	"XOFF_SENT":       {},
	"XOFF_RECV":       {},
	"XON_SENT":        {},
	"XON_RECV":        {},
}

// torOtherLabel is the fixed fallback bucket for any status/purpose value that
// doesn't match the known vocabulary — including the misaligned rows produced
// by a real GETINFO stream-status column-shift bug in the os-tor plugin's
// Ruby parser (see torStreamRaw doc comment). It is a constant string, never a
// pass-through of the raw value, so a parser regression can never mint
// unbounded label cardinality.
const torOtherLabel = "other"

// torCircuitRaw is the shape of one entry in the circuits envelope's
// "response" object (keyed by ephemeral circuit ID, which is intentionally
// never parsed into a Go field — circuit IDs churn constantly and must never
// become a label, see TorCircuits).
//
// The os-tor plugin's tor_diag Ruby script parses Tor's GETINFO
// circuit-status text with fixed-position splitting:
//
//	data = line.split(' ')
//	circuit_id = data.shift.to_i
//	status = data.shift
//	hosts = data.shift.split(',').map { ... }
//	flags = data.map { |e| k, v = e.split('='); [k, v.split(',')] }.to_h
//
// When a circuit has no completed hop yet (observed on ONEHOP/internal
// circuits during an incomplete bootstrap), Tor omits the optional Path field
// from the line entirely, so `hosts` fixed-position-shifts one token too far
// and consumes what should have been the first "KEY=value" flag (typically
// "BUILD_FLAGS=..."), splitting it into bogus {host: "BUILD_FLAGS=...",
// nickname: nil} entries — verified against a real dev-box capture. Only
// tokens BEFORE that point are affected: `status` (always the second
// space-separated token) and `flags["PURPOSE"]` (a later, untouched token)
// stay correct even when this happens, which is why this struct deliberately
// only reads status and flags.PURPOSE and never parses "hosts" at all.
type torCircuitRaw struct {
	Status string `json:"status"`
	Flags  struct {
		Purpose []string `json:"PURPOSE"`
	} `json:"flags"`
}

// torCircuitsEnvelope is the api/tor/service/circuits response shape. Response
// is decoded in two stages (see FetchTorCircuits) because OPNsense's
// controller wraps whatever the tor_diag script printed to stdout, valid JSON
// or not, in {"response": ...}: a healthy box with zero circuits sends
// {"response": {}} (Tor's control port replies, empty result), while an
// unreachable control port (Tor not running, bad password, wrong port) makes
// the script raise an uncaught Ruby exception with no JSON on stdout, which
// PHP's json_decode() turns into {"response": null}. Those two must not be
// conflated: {} means "up, idle"; null means "not up".
type torCircuitsEnvelope struct {
	Response json.RawMessage `json:"response"`
}

// torStreamRaw is one entry in the streams envelope's "response" array.
//
// Real dev-box capture (2026-07-13, captures/tor/streams.json) surfaced a
// second, independent parser landmine in tor_diag's stream_status method:
//
//	stream_status_data.split(' ').each_slice(4) do |data_set|
//	  ...
//	  result << { stream_id: data_set[0], stream_status: data_set[1],
//	              circuit_id: data_set[2], destination_host: ..., ... }
//	end
//
// This flattens the ENTIRE multi-line GETINFO stream-status reply on
// whitespace (ignoring line breaks) and re-chunks it into fixed 4-token
// windows. Any one stream-status line with an unexpected token count (e.g. an
// extra key=value field Tor appends for some stream states) desyncs the
// window for every subsequent stream in the same response — observed
// alternating between good and shifted rows in the real capture, e.g.:
//
//	{"stream_id":"NEW","stream_status":"0",
//	 "circuit_id":"109.73.65.37.$...exit:9001","destination_host":null,...}
//
// Here a real exit-relay descriptor landed in circuit_id, and the literal
// tokens "NEW"/"0" landed in stream_id/stream_status. Because circuit_id and
// destination_host/port are never read into any field this exporter emits
// (never a label — see the "AGGREGATE ONLY" rule in TorStreams), the
// blast radius of this bug is fully contained to whether stream_status
// happens to be a real status word. It is always vocabulary-validated before
// use (torStreamStatusVocabulary), so a shifted row like the one above lands
// harmlessly in the "other" bucket instead of emitting "0" as a label value.
type torStreamRaw struct {
	StreamStatus string `json:"stream_status"`
}

// torStreamsEnvelope mirrors torCircuitsEnvelope's two-stage decode: a
// healthy, idle Tor answers {"response": []}; an unreachable control port
// answers {"response": null}.
type torStreamsEnvelope struct {
	Response json.RawMessage `json:"response"`
}

// torHiddenServicesResponse is the api/tor/service/get_hidden_services
// response shape: PHP's json_encode(array()) emits [] for zero configured
// hidden services and a {name: hostname} object once any exist — the same
// empty-array-vs-object quirk flexStringMap already exists to tolerate (see
// jsonflex.go; reused by dhcpv4/dhcpv6/dnsmasq's "interfaces" field).
type torHiddenServicesResponse struct {
	Response flexStringMap `json:"response"`
}

// TorCircuits holds the aggregated result of FetchTorCircuits.
type TorCircuits struct {
	Present bool // false when the os-tor plugin is not installed (HTTP 404)
	Up      bool // false when the control port is unreachable/misconfigured (response: null, or an unparseable body)

	// ByStatus and ByPurpose are aggregate counts only — never per-circuit
	// series. Circuit IDs are ephemeral and churn constantly; they are never
	// parsed into any field in this package, let alone emitted as a label.
	ByStatus  map[string]int
	ByPurpose map[string]int
}

// TorStreams holds the aggregated result of FetchTorStreams.
type TorStreams struct {
	Present bool
	Up      bool

	// ByStatus is an aggregate count only — never per-stream series, and
	// destination host/port are never parsed into any field in this package
	// (see torStreamRaw), so they can never leak into a label or a log line.
	ByStatus map[string]int
}

// TorHiddenServices holds the aggregated result of FetchTorHiddenServices.
type TorHiddenServices struct {
	Present bool
	// HostnameAvailable maps configured hidden-service name -> whether a
	// .onion hostname has been provisioned for it. The hostname value itself
	// is never retained or emitted anywhere (only the service name label and
	// a 0/1 availability flag) — .onion hostnames are sensitive.
	HostnameAvailable map[string]bool
}

// FetchTorCircuits calls api/tor/service/circuits and returns circuit counts
// aggregated by (validated) status and purpose. Never per-circuit.
func (c *Client) FetchTorCircuits() (TorCircuits, *APICallError) {
	var data TorCircuits

	url, ok := c.endpoints["torCircuits"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "torCircuits",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var env torCircuitsEnvelope
	if err := c.do("GET", url, nil, &env); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil // plugin absent
		}
		return data, err
	}
	data.Present = true

	trimmed := bytes.TrimSpace(env.Response)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		// Control port unreachable: the tor_diag script raised an uncaught
		// exception (Tor not running, bad control-port password/port) and
		// printed no JSON, which json_decode() turns into a top-level null.
		return data, nil
	}

	var entries map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &entries); err != nil {
		// An otherwise-malformed body. Never crash the scrape over it.
		return data, nil
	}
	// tor_diag's two config-validation failures ("invalid control port
	// found" / "no control port found") print {"error": "..."} to stdout
	// instead of a circuit map — which decodes successfully as a
	// map[string]json.RawMessage (same object shape as a real circuit map),
	// so it is not caught by the decode-error branch above and must be
	// checked explicitly. A real circuit map is keyed by numeric circuit
	// IDs and never carries an "error" key.
	if _, hasError := entries["error"]; hasError {
		return data, nil
	}
	data.Up = true

	data.ByStatus = make(map[string]int)
	data.ByPurpose = make(map[string]int)
	for _, raw := range entries {
		var circuit torCircuitRaw
		if err := json.Unmarshal(raw, &circuit); err != nil {
			// A single unparseable circuit entry never aborts the batch.
			continue
		}
		if circuit.Status != "" {
			data.ByStatus[torVocabularyBucket(circuit.Status, torCircuitStatusVocabulary)]++
		}
		if len(circuit.Flags.Purpose) > 0 && circuit.Flags.Purpose[0] != "" {
			data.ByPurpose[torVocabularyBucket(circuit.Flags.Purpose[0], torCircuitPurposeVocabulary)]++
		}
	}

	return data, nil
}

// FetchTorStreams calls api/tor/service/streams and returns stream counts
// aggregated by (validated) status. Never per-stream, never by destination.
func (c *Client) FetchTorStreams() (TorStreams, *APICallError) {
	var data TorStreams

	url, ok := c.endpoints["torStreams"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "torStreams",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var env torStreamsEnvelope
	if err := c.do("GET", url, nil, &env); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil // plugin absent
		}
		return data, err
	}
	data.Present = true

	trimmed := bytes.TrimSpace(env.Response)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return data, nil // control port unreachable, see FetchTorCircuits
	}

	var rows []json.RawMessage
	if err := json.Unmarshal(trimmed, &rows); err != nil {
		return data, nil // malformed body — treat as "not up", never crash
	}
	data.Up = true

	data.ByStatus = make(map[string]int)
	for _, raw := range rows {
		var stream torStreamRaw
		if err := json.Unmarshal(raw, &stream); err != nil {
			// A single unparseable stream row never aborts the batch.
			continue
		}
		if stream.StreamStatus == "" {
			continue
		}
		data.ByStatus[torVocabularyBucket(stream.StreamStatus, torStreamStatusVocabulary)]++
	}

	return data, nil
}

// FetchTorHiddenServices calls api/tor/service/get_hidden_services and
// returns, per configured hidden service, whether a .onion hostname has been
// provisioned. The hostname itself is discarded — never retained, never
// emitted (.onion hostnames are sensitive; only the admin-configured service
// name is used as a label, analogous to a WireGuard peer name).
func (c *Client) FetchTorHiddenServices() (TorHiddenServices, *APICallError) {
	var data TorHiddenServices

	url, ok := c.endpoints["torHiddenServices"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "torHiddenServices",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var resp torHiddenServicesResponse
	if err := c.do("GET", url, nil, &resp); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil // plugin absent
		}
		return data, err
	}
	data.Present = true

	data.HostnameAvailable = make(map[string]bool, len(resp.Response))
	for name, hostname := range resp.Response {
		data.HostnameAvailable[name] = hostname != "" && hostname != "not available"
	}

	return data, nil
}

// torVocabularyBucket returns value when it is a member of vocabulary, or the
// fixed "other" label otherwise. Centralising this ensures every status/
// purpose label emitted by the tor collector is drawn from a closed,
// developer-controlled set, regardless of what a plugin parsing regression
// hands back.
func torVocabularyBucket(value string, vocabulary map[string]struct{}) string {
	if _, ok := vocabulary[value]; ok {
		return value
	}
	return torOtherLabel
}
