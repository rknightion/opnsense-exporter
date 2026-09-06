package syslog

import (
	"strings"
	"testing"

	"github.com/rknightion/opnsense2otel/v5/internal/geoip"
	"github.com/rknightion/opnsense2otel/v5/internal/logship"
)

// A real (reduced) EVE alert as it arrives over syslog when the box's syslog_eve
// setting is on. Shape verified against /var/log/suricata/eve.json on a live box.
const eveAlertLine = `{"timestamp":"2026-07-13T18:26:10.742503+0100","flow_id":663240461851186,"in_iface":"vtnet2","event_type":"alert","src_ip":"52.85.47.113","src_port":80,"dest_ip":"172.16.9.50","dest_port":48836,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2100498,"rev":7,"signature":"GPL ATTACK_RESPONSE id check returned root","category":"Potentially Bad Traffic","severity":2},"app_proto":"http","direction":"to_client"}`

func TestParseSuricata_EVEAlert(t *testing.T) {
	rec := BuildRecord(Envelope{Program: "suricata", Message: eveAlertLine, Severity: 5}, enrichSnap(), nil)
	a := rec.Attributes
	// Attribute names MIRROR the ids poll lane (internal/logship/ids.go) so a
	// dashboard does not care which path an alert arrived by.
	for k, want := range map[string]string{
		"event_type":         "alert",
		"alert_sid":          "2100498",
		"signature":          "GPL ATTACK_RESPONSE id check returned root",
		"alert_action":       "allowed",
		"src_ip":             "52.85.47.113",
		"dest_ip":            "172.16.9.50",
		"proto":              "TCP",
		"in_iface":           "vtnet2",
		"opnsense.subsystem": "ids",
	} {
		if a[k] != want {
			t.Errorf("attr %q = %q, want %q", k, a[k], want)
		}
	}
}

// A blocked alert is a warning; Suricata logs it at the same syslog severity as one
// it merely observed.
func TestParseSuricata_BlockedAlertIsWarn(t *testing.T) {
	line := strings.Replace(eveAlertLine, `"action":"allowed"`, `"action":"blocked"`, 1)
	rec := BuildRecord(Envelope{Program: "suricata", Message: line, Severity: 5}, nil, nil)
	if rec.Severity != logship.SeverityWarn {
		t.Errorf("severity = %v, want Warn for a blocked alert", rec.Severity)
	}
}

// The SAME program carries the engine's own plain-text log. It must not be mistaken
// for an alert, and it must not be dropped.
func TestParseSuricata_EngineTextShipsGeneric(t *testing.T) {
	const engine = `[207442] <Notice> -- rule reload complete`
	rec := BuildRecord(Envelope{Program: "suricata", Message: engine, Severity: 5}, nil, nil)
	if _, isAlert := rec.Attributes["signature"]; isAlert {
		t.Error("engine text was parsed as an alert")
	}
	if rec.Body != engine {
		t.Errorf("engine line lost its body: %q", rec.Body)
	}
}

// Malformed JSON under this program is not an alert we can trust. Ship it raw rather
// than emitting half-decoded fields that look authoritative.
func TestParseSuricata_MalformedJSONShipsRaw(t *testing.T) {
	const broken = `{"event_type":"alert","alert":{`
	rec := BuildRecord(Envelope{Program: "suricata", Message: broken}, nil, nil)
	if _, ok := rec.Attributes["signature"]; ok {
		t.Error("half-decoded JSON must not yield alert attributes")
	}
	if rec.Body != broken {
		t.Error("the raw body must survive")
	}
}

func TestParseSuricata_SetsAttrAction(t *testing.T) {
	env := Envelope{Program: "suricata", Message: `{"event_type":"alert","alert":{"action":"blocked","signature":"x","category":"c","signature_id":1}}`}
	rec, ok := parseSuricata(env, nil, nil)
	if !ok {
		t.Fatal("parse failed")
	}
	if got := rec.Attributes[logship.AttrAction]; got != logship.ActionBlock {
		t.Errorf("opnsense.action = %q, want %q", got, logship.ActionBlock)
	}
	if got := rec.Attributes["alert_action"]; got != "blocked" {
		t.Errorf("raw alert_action = %q, want blocked", got)
	}

	envAllowed := Envelope{Program: "suricata", Message: `{"event_type":"alert","alert":{"action":"allowed","signature":"x"}}`}
	recAllowed, _ := parseSuricata(envAllowed, nil, nil)
	if got := recAllowed.Attributes[logship.AttrAction]; got != logship.ActionPass {
		t.Errorf("opnsense.action = %q, want %q", got, logship.ActionPass)
	}
}

// eventType and severity reach a metric LABEL, and both are raw JSON values from a
// push sender whose source address is spoofable — so both are folded to closed
// vocabularies before they become one. The record keeps the raw value either way;
// only the label is constrained.
func TestMapEveEventType(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"alert", "alert"},
		{"anomaly", "anomaly"},
		{"", ""},
		{"flow", eveOther},
		{"a-value-a-sender-invented", eveOther},
		{"ALERT", eveOther}, // case-sensitive: EVE emits lowercase
	}
	for _, tt := range tests {
		if got := mapEveEventType(tt.in); got != tt.want {
			t.Errorf("mapEveEventType(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestMapEveSeverity(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"1", "1"},
		{"2", "2"},
		{"3", "3"},
		{"4", "4"},
		{"", ""},
		{"0", eveOther},
		{"5", eveOther},
		{"99999", eveOther},
		{"not-a-number", eveOther},
	}
	for _, tt := range tests {
		if got := mapEveSeverity(tt.in); got != tt.want {
			t.Errorf("mapEveSeverity(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// GeoIP (#528): both alert endpoints are geoip.Enrichable public addresses in the
// captured line, so both get geo attributes once a GeoIP source is configured.
func TestParseSuricata_GeoAttrs(t *testing.T) {
	geoLookup = fakeGeoLookup{results: map[string]geoip.Result{
		"52.85.47.113": {CountryISO: "US", ContinentCode: "NA", ASN: 16509, ASOrg: "Amazon.com, Inc."},
	}}
	t.Cleanup(func() { geoLookup = nil })

	rec := BuildRecord(Envelope{Program: "suricata", Message: eveAlertLine, Severity: 5}, enrichSnap(), nil)
	a := rec.Attributes
	for k, want := range map[string]string{
		"src.geo.country":        "US",
		"src.geo.country_source": "maxmind",
		"src.geo.continent":      "NA",
		"src.geo.asn":            "AS16509",
		"src.geo.as_org":         "Amazon.com, Inc.",
	} {
		if a[k] != want {
			t.Errorf("attr %q = %q, want %q", k, a[k], want)
		}
	}
	// 172.16.9.50 is RFC1918: never enrichable, so dest must carry no geo attribute.
	for k := range a {
		if strings.HasPrefix(k, "dst.geo.") {
			t.Errorf("attribute %q present for a private destination address", k)
		}
	}
}

// Without a configured GeoIP source, Suricata ships exactly as before #528.
func TestParseSuricata_GeoAttrs_AbsentWithNoLookupConfigured(t *testing.T) {
	geoLookup = nil
	rec := BuildRecord(Envelope{Program: "suricata", Message: eveAlertLine, Severity: 5}, enrichSnap(), nil)
	for k := range rec.Attributes {
		if strings.Contains(k, ".geo.") {
			t.Errorf("attribute %q present with no GeoIP source configured", k)
		}
	}
}
