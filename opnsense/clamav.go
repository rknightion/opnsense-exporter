package opnsense

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// clamavVersionResponse mirrors api/clamav/service/version (security/clamav
// plugin's ServiceController::versionAction, which shells out to
// `clamav version` / clamconf and reassembles the result with a fragile
// sed/cut pipeline). Every field is a free-text fragment that keeps the space
// following its source label's colon, hence the leading space on every value
// (e.g. `"clamav":" 1.5.2"`, `"signatures":" 3642597"`). The daily/main/bytecode
// fields additionally embed a human-readable build line:
//
//	" version 28059, sigs: 355490, built on Mon Jul 13 07:25:07 2026"
//
// When freshclam has never run, the daily/main/bytecode keys are omitted
// entirely (verified against a live OPNsense 26.7-devel box) rather than being
// present-but-empty, and signatures reads " 0". Confirmed against
// https://raw.githubusercontent.com/opnsense/plugins/master/security/clamav/src/opnsense/mvc/app/controllers/OPNsense/ClamAV/Api/ServiceController.php
type clamavVersionResponse struct {
	Version struct {
		ClamAV     flexString `json:"clamav"`
		Signatures flexString `json:"signatures"`
		Daily      flexString `json:"daily"`
		Main       flexString `json:"main"`
		Bytecode   flexString `json:"bytecode"`
	} `json:"version"`
}

// clamavVersionStringPattern parses one daily/main/bytecode free-text value
// (already trimmed of its leading space) into its numeric database version,
// signature count and build-date fragment. The signature count is deliberately
// not surfaced as its own metric (opnsense_clamav_signatures already reports
// the authoritative total from the top-level "signatures" field) but is
// captured so the pattern validates the whole line shape.
var clamavVersionStringPattern = regexp.MustCompile(`^version\s+(\d+),\s*sigs:\s*(\d+),\s*built on\s+(.+)$`)

// ClamAVSignatureDB is one parsed daily/main/bytecode signature database entry.
type ClamAVSignatureDB struct {
	Name string // "daily", "main", or "bytecode"
	// Version is the database's numeric version counter (increments on every
	// freshclam update).
	Version int64
	// BuiltTimestamp is the Unix time the database was built, parsed from the
	// free-text "built on <date>" fragment. 0 when the date fragment failed to
	// parse — never treat 0 as a real epoch value for this field.
	BuiltTimestamp float64
}

// ClamAVVersion is the normalised representation of api/clamav/service/version.
type ClamAVVersion struct {
	// Present is false when the os-clamav plugin is not installed (HTTP 404).
	Present bool
	// EngineVersion is the ClamAV engine (clamd) version string, e.g. "1.5.2".
	EngineVersion string
	// TotalSignatures is the aggregate signature count across every loaded
	// database, from the top-level "signatures" field. 0 both when freshclam
	// has never run and when the field failed to parse — HasTotalSignatures
	// distinguishes "reported zero" from "field absent/unparseable".
	TotalSignatures    int64
	HasTotalSignatures bool
	// Databases holds one entry per daily/main/bytecode database whose
	// free-text version string parsed successfully. A database whose string is
	// absent (never-ran shape) or malformed is simply omitted — never causes
	// an error.
	Databases []ClamAVSignatureDB
}

// parseClamAVSignatureDB parses one daily/main/bytecode free-text version
// value into a ClamAVSignatureDB. Returns ok=false when raw is empty (the
// never-ran shape, where the key is absent entirely) or does not match the
// expected "version N, sigs: N, built on <date>" shape — the caller must skip
// the database rather than fail the scrape. A date fragment that fails to
// parse still yields ok=true with BuiltTimestamp left at 0, since the version
// number itself is still valid, actionable data.
func parseClamAVSignatureDB(name, raw string) (ClamAVSignatureDB, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ClamAVSignatureDB{}, false
	}

	m := clamavVersionStringPattern.FindStringSubmatch(raw)
	if m == nil {
		return ClamAVSignatureDB{}, false
	}

	version, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return ClamAVSignatureDB{}, false
	}

	entry := ClamAVSignatureDB{Name: name, Version: version}

	// The build date has no timezone (C ctime/asctime format), so parse it as
	// UTC deterministically rather than resolving against the host's local
	// zone — mirrors parseLastCheckTimestamp's handling of the same ambiguity
	// in firmware.go. A failed parse leaves BuiltTimestamp at 0; it does not
	// invalidate the version number already extracted above.
	if t, dateErr := time.ParseInLocation(time.ANSIC, strings.TrimSpace(m[3]), time.UTC); dateErr == nil {
		entry.BuiltTimestamp = float64(t.Unix())
	}

	return entry, true
}

// FetchClamAVVersion calls the ClamAV service version endpoint and returns the
// engine version, total signature count and per-database freshness.
//
// If the os-clamav plugin is not installed the endpoint returns HTTP 404
// (confirmed against a live OPNsense 26.7-devel box). That is treated as
// "feature absent" — empty data with no error — so boxes without the plugin do
// not log errors or increment endpoint counters on every scrape.
func (c *Client) FetchClamAVVersion() (ClamAVVersion, *APICallError) {
	var raw json.RawMessage
	var data ClamAVVersion

	url, ok := c.endpoints["clamavVersion"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "clamavVersion",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &raw); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil
		}
		return data, err
	}

	data.Present = true

	var resp clamavVersionResponse
	// The backing configd "clamav version" call can, in principle, produce a
	// bare "[]" instead of an object (the same PHP empty-array/object ambiguity
	// flexString works around elsewhere) if clamconf output doesn't parse at
	// all. Never fail the scrape on that: report "present, no data" exactly
	// like a payload that parsed but had nothing to report.
	if err := json.Unmarshal(raw, &resp); err != nil {
		return data, nil
	}

	data.EngineVersion = strings.TrimSpace(resp.Version.ClamAV.String())

	if sigStr := strings.TrimSpace(resp.Version.Signatures.String()); sigStr != "" {
		if v, err := strconv.ParseInt(sigStr, 10, 64); err == nil {
			data.TotalSignatures = v
			data.HasTotalSignatures = true
		}
	}

	for _, db := range [...]struct {
		name string
		raw  flexString
	}{
		{"daily", resp.Version.Daily},
		{"main", resp.Version.Main},
		{"bytecode", resp.Version.Bytecode},
	} {
		if entry, ok := parseClamAVSignatureDB(db.name, db.raw.String()); ok {
			data.Databases = append(data.Databases, entry)
		}
	}

	return data, nil
}
