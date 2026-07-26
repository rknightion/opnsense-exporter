package syslog

import (
	"testing"

	"github.com/rknightion/opnsense-exporter/internal/logship"
)

// fakeSink records every Observe* call it receives so a test can assert both
// which method fired and the exact label values passed.
type fakeSink struct {
	calls []fakeCall
}

type fakeCall struct {
	method string
	args   []string
}

func (f *fakeSink) ObserveFirewall(action, iface, ruleID, ruleName, scope string) {
	f.calls = append(f.calls, fakeCall{"firewall", []string{action, iface, ruleID, ruleName, scope}})
}

func (f *fakeSink) ObserveHAProxy(event, backend, server, state, statusClass string) {
	f.calls = append(f.calls, fakeCall{"haproxy", []string{event, backend, server, state, statusClass}})
}

func (f *fakeSink) ObserveSSHD(result, method, scope string) {
	f.calls = append(f.calls, fakeCall{"sshd", []string{result, method, scope}})
}

func (f *fakeSink) ObserveDHCP(action, iface, server string) {
	f.calls = append(f.calls, fakeCall{"dhcp", []string{action, iface, server}})
}

func (f *fakeSink) ObserveAudit(event, result string) {
	f.calls = append(f.calls, fakeCall{"audit", []string{event, result}})
}

func (f *fakeSink) ObserveIDS(eventType, action, category, severity string) {
	f.calls = append(f.calls, fakeCall{"ids", []string{eventType, action, category, severity}})
}

func (f *fakeSink) ObserveZenarmor(o logship.ZenarmorObservation) {
	f.calls = append(f.calls, fakeCall{"zenarmor", []string{o.Family, o.Action, o.Category, o.Interface, o.RCode, o.Severity, o.StatusClass}})
}

var _ logship.MetricSink = (*fakeSink)(nil)

func TestDeriveFamily(t *testing.T) {
	tests := []struct {
		program string
		want    family
		wantOK  bool
	}{
		{"filterlog", familyFirewall, true},
		{"haproxy", familyHAProxy, true},
		{"sshd", familySSHD, true},
		{"sshd-session", familySSHD, true},
		{"dhcpd", familyDHCP, true},
		{"dnsmasq", familyDHCP, true},
		{"dnsmasq-dhcp", familyDHCP, true},
		{"kea-dhcp4", familyDHCP, true},
		{"kea-dhcp6", familyDHCP, true},
		{"dhcrelay", familyDHCP, true},
		{"audit", familyAudit, true},
		{"configd.py", familyAudit, true},
		{"suricata", familyIDS, true},
		{"unbound", familyUnknown, false},
		{"", familyUnknown, false},
	}
	for _, tt := range tests {
		t.Run(tt.program, func(t *testing.T) {
			got, ok := deriveFamily(tt.program)
			if ok != tt.wantOK || (ok && got != tt.want) {
				t.Errorf("deriveFamily(%q) = (%v, %v), want (%v, %v)", tt.program, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

// TestEveryParserProgramHasAFamilyDecision replaces the "two parallel lists that
// should mirror each other" comment derive.go used to carry with an actual check:
// every program a Parser is registered for (the `parsers` map, populated by the
// RegisterParser calls in filterlog.go, haproxy.go, sshd.go, dhcp.go, audit.go,
// suricata.go, cron.go, radvd.go, unbound.go) must land EITHER in programFamily
// (it derives a metric) or in nonDerivedPrograms (an explicit, test-pinned
// decision that it deliberately does not). A program in neither is exactly how
// #396 happened: dnsmasq-dhcp was registered as a DHCP parser alias (#335) after
// the family map was built (#258), and nothing cross-checked the two against each
// other, so its lease lines parsed and shipped but never counted.
func TestEveryParserProgramHasAFamilyDecision(t *testing.T) {
	if len(parsers) == 0 {
		t.Fatal("parsers is empty; init() registrations did not run")
	}
	for prog := range parsers {
		_, derived := programFamily[prog]
		_, exempted := nonDerivedPrograms[prog]
		switch {
		case derived && exempted:
			t.Errorf("program %q is in BOTH programFamily and nonDerivedPrograms; pick one", prog)
		case !derived && !exempted:
			t.Errorf("program %q is registered as a parser but has no derived-family decision: "+
				"add it to programFamily (it should derive a metric) or nonDerivedPrograms "+
				"(it deliberately should not)", prog)
		}
	}
}

func TestObserveDerived_UnknownProgram(t *testing.T) {
	sink := &fakeSink{}
	counted := observeDerived(sink, "unbound", map[string]string{"foo": "bar"})
	if counted {
		t.Error("counted = true for an unknown program, want false")
	}
	if len(sink.calls) != 0 {
		t.Errorf("sink called %d times for an unknown program, want 0", len(sink.calls))
	}
}

func TestObserveDerived_Firewall(t *testing.T) {
	tests := []struct {
		name        string
		attrs       map[string]string
		wantCounted bool
		wantArgs    []string
	}{
		{
			name: "happy path with resolved interface and rule id",
			attrs: map[string]string{
				"action":           "block",
				logship.AttrAction: logship.ActionBlock,
				"interface.name":   "LAN",
				"interface":        "igb0",
				"rule.id":          "abc123",
				"rule.ref":         "rule #16.1",
				"rule.description": "block bad guys",
				"src.scope":        "lan",
			},
			wantCounted: true,
			wantArgs:    []string{"block", "LAN", "abc123", "block bad guys", "lan"},
		},
		{
			name: "falls back to raw interface and rule ref when unresolved",
			attrs: map[string]string{
				"action":           "pass",
				logship.AttrAction: logship.ActionPass,
				"interface":        "igb0",
				"rule.ref":         "rule #16.1",
			},
			wantCounted: true,
			wantArgs:    []string{"pass", "igb0", "rule #16.1", "", ""},
		},
		// The label carries the NORMALISED disposition, not the raw wire verb: pf's
		// "reject" is a block, and a label whose value depends on which verb the rule
		// happened to use is not aggregatable.
		{
			name: "reject is counted under the normalised block",
			attrs: map[string]string{
				"action":           "reject",
				logship.AttrAction: logship.ActionBlock,
				"interface":        "igb0",
			},
			wantCounted: true,
			wantArgs:    []string{"block", "igb0", "", "", ""},
		},
		// A NAT/rdr verb maps to no disposition at all, so filterlog leaves AttrAction
		// unset. The line still parsed, so it is still COUNTED -- under an empty action
		// rather than a guessed one. Dropping it here would under-report the counter and
		// (via sampleKeep) exempt the line from sampling for no reason.
		{
			name: "unrecognised verb is counted with an empty action",
			attrs: map[string]string{
				"action":    "rdr",
				"interface": "igb0",
			},
			wantCounted: true,
			wantArgs:    []string{"", "igb0", "", "", ""},
		},
		{
			name:        "missing action is not counted",
			attrs:       map[string]string{"interface": "igb0"},
			wantCounted: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink := &fakeSink{}
			counted := observeDerived(sink, "filterlog", tt.attrs)
			if counted != tt.wantCounted {
				t.Fatalf("counted = %v, want %v", counted, tt.wantCounted)
			}
			if !tt.wantCounted {
				if len(sink.calls) != 0 {
					t.Errorf("sink called %d times, want 0", len(sink.calls))
				}
				return
			}
			if len(sink.calls) != 1 || sink.calls[0].method != "firewall" {
				t.Fatalf("calls = %+v, want one firewall call", sink.calls)
			}
			assertArgs(t, sink.calls[0].args, tt.wantArgs)
		})
	}
}

func TestObserveDerived_HAProxy(t *testing.T) {
	tests := []struct {
		name        string
		attrs       map[string]string
		wantCounted bool
		wantArgs    []string
	}{
		{
			name: "server state with status class",
			attrs: map[string]string{
				"haproxy.event":   "server_state",
				"haproxy.backend": "bk-heavy",
				"haproxy.server":  "heavy-1",
				"haproxy.state":   "down",
			},
			wantCounted: true,
			wantArgs:    []string{"server_state", "bk-heavy", "heavy-1", "down", ""},
		},
		{
			name: "http log with status class",
			attrs: map[string]string{
				"haproxy.event":            "http_request",
				"haproxy.backend":          "bk-heavy",
				"haproxy.server":           "heavy-1",
				attrHTTPResponseStatusCode: "404",
			},
			wantCounted: true,
			wantArgs:    []string{"http_request", "bk-heavy", "heavy-1", "", "4xx"},
		},
		{
			name:        "missing event is not counted",
			attrs:       map[string]string{"haproxy.backend": "bk-heavy"},
			wantCounted: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink := &fakeSink{}
			counted := observeDerived(sink, "haproxy", tt.attrs)
			if counted != tt.wantCounted {
				t.Fatalf("counted = %v, want %v", counted, tt.wantCounted)
			}
			if !tt.wantCounted {
				return
			}
			if len(sink.calls) != 1 || sink.calls[0].method != "haproxy" {
				t.Fatalf("calls = %+v, want one haproxy call", sink.calls)
			}
			assertArgs(t, sink.calls[0].args, tt.wantArgs)
		})
	}
}

func TestObserveDerived_SSHD(t *testing.T) {
	tests := []struct {
		name        string
		program     string
		attrs       map[string]string
		wantCounted bool
		wantArgs    []string
	}{
		{
			name:    "accepted via sshd",
			program: "sshd",
			attrs: map[string]string{
				"auth.result": "accepted",
				"auth.method": "publickey",
				"src.scope":   "wan",
			},
			wantCounted: true,
			wantArgs:    []string{"accepted", "publickey", "wan"},
		},
		{
			name:    "failed via sshd-session",
			program: "sshd-session",
			attrs: map[string]string{
				"auth.result": "failed",
				"auth.method": "password",
			},
			wantCounted: true,
			wantArgs:    []string{"failed", "password", ""},
		},
		{
			name:        "missing result is not counted",
			program:     "sshd",
			attrs:       map[string]string{"auth.method": "password"},
			wantCounted: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink := &fakeSink{}
			counted := observeDerived(sink, tt.program, tt.attrs)
			if counted != tt.wantCounted {
				t.Fatalf("counted = %v, want %v", counted, tt.wantCounted)
			}
			if !tt.wantCounted {
				return
			}
			if len(sink.calls) != 1 || sink.calls[0].method != "sshd" {
				t.Fatalf("calls = %+v, want one sshd call", sink.calls)
			}
			assertArgs(t, sink.calls[0].args, tt.wantArgs)
		})
	}
}

func TestObserveDerived_DHCP(t *testing.T) {
	tests := []struct {
		name        string
		program     string
		attrs       map[string]string
		wantCounted bool
		wantArgs    []string
	}{
		{
			name:    "resolved interface name",
			program: "dhcpd",
			attrs: map[string]string{
				"dhcp.action":    "ack",
				"interface.name": "LAN",
				"interface":      "igb0",
				"dhcp.server_ip": "172.16.30.1",
			},
			wantCounted: true,
			wantArgs:    []string{"ack", "LAN", "172.16.30.1"},
		},
		{
			name:    "kea falls back to raw interface",
			program: "kea-dhcp4",
			attrs: map[string]string{
				"dhcp.action": "alloc",
				"interface":   "igb1",
			},
			wantCounted: true,
			wantArgs:    []string{"alloc", "igb1", ""},
		},
		{
			name:        "missing action is not counted",
			program:     "dnsmasq",
			attrs:       map[string]string{"interface": "igb0"},
			wantCounted: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink := &fakeSink{}
			counted := observeDerived(sink, tt.program, tt.attrs)
			if counted != tt.wantCounted {
				t.Fatalf("counted = %v, want %v", counted, tt.wantCounted)
			}
			if !tt.wantCounted {
				return
			}
			if len(sink.calls) != 1 || sink.calls[0].method != "dhcp" {
				t.Fatalf("calls = %+v, want one dhcp call", sink.calls)
			}
			assertArgs(t, sink.calls[0].args, tt.wantArgs)
		})
	}
}

func TestObserveDerived_Audit(t *testing.T) {
	tests := []struct {
		name        string
		program     string
		attrs       map[string]string
		wantCounted bool
		wantArgs    []string
	}{
		{
			name:        "config change has no audit.result",
			program:     "audit",
			attrs:       map[string]string{"event": "config_change"},
			wantCounted: true,
			wantArgs:    []string{"config_change", ""},
		},
		{
			name:    "authorization denied",
			program: "configd.py",
			attrs: map[string]string{
				"event":        "authorization",
				"audit.result": "denied",
			},
			wantCounted: true,
			wantArgs:    []string{"authorization", "denied"},
		},
		{
			name:        "missing event is not counted",
			program:     "audit",
			attrs:       map[string]string{"audit.result": "allowed"},
			wantCounted: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink := &fakeSink{}
			counted := observeDerived(sink, tt.program, tt.attrs)
			if counted != tt.wantCounted {
				t.Fatalf("counted = %v, want %v", counted, tt.wantCounted)
			}
			if !tt.wantCounted {
				return
			}
			if len(sink.calls) != 1 || sink.calls[0].method != "audit" {
				t.Fatalf("calls = %+v, want one audit call", sink.calls)
			}
			assertArgs(t, sink.calls[0].args, tt.wantArgs)
		})
	}
}

func TestObserveDerived_IDS(t *testing.T) {
	tests := []struct {
		name        string
		attrs       map[string]string
		wantCounted bool
		wantArgs    []string
	}{
		{
			name: "happy path",
			attrs: map[string]string{
				"event_type":       "alert",
				"alert_action":     "blocked",
				logship.AttrAction: logship.ActionBlock,
				"alert_category":   "trojan",
				"alert_severity":   "1",
			},
			wantCounted: true,
			// action is the normalised "block", not Suricata's wire word "blocked":
			// the same query must reach a filterlog block and a Suricata block.
			wantArgs: []string{"alert", "block", "trojan", "1"},
		},
		{
			name: "unrecognised alert action counts with an empty action",
			attrs: map[string]string{
				"event_type":     "alert",
				"alert_action":   "dropped",
				"alert_category": "trojan",
				"alert_severity": "2",
			},
			wantCounted: true,
			wantArgs:    []string{"alert", "", "trojan", "2"},
		},
		// event_type is a raw JSON value from a push sender. OPNsense's syslog_eve path
		// only ever emits "alert", so anything else folds into one bucket instead of
		// minting a label value per invented type.
		{
			name: "unknown event_type folds into other",
			attrs: map[string]string{
				"event_type":       "wat-injected",
				logship.AttrAction: logship.ActionPass,
				"alert_category":   "trojan",
				"alert_severity":   "3",
			},
			wantCounted: true,
			wantArgs:    []string{"other", "pass", "trojan", "3"},
		},
		// Severity is Suricata's numeric priority. 1-4 is the real range; anything
		// else is a sender inventing values and folds into one bucket.
		{
			name: "out-of-range severity folds into other",
			attrs: map[string]string{
				"event_type":     "alert",
				"alert_category": "trojan",
				"alert_severity": "99999",
			},
			wantCounted: true,
			wantArgs:    []string{"alert", "", "trojan", "other"},
		},
		{
			name: "absent severity stays empty",
			attrs: map[string]string{
				"event_type":     "alert",
				"alert_category": "trojan",
			},
			wantCounted: true,
			wantArgs:    []string{"alert", "", "trojan", ""},
		},
		{
			name:        "missing event_type is not counted",
			attrs:       map[string]string{"alert_action": "allowed"},
			wantCounted: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink := &fakeSink{}
			counted := observeDerived(sink, "suricata", tt.attrs)
			if counted != tt.wantCounted {
				t.Fatalf("counted = %v, want %v", counted, tt.wantCounted)
			}
			if !tt.wantCounted {
				return
			}
			if len(sink.calls) != 1 || sink.calls[0].method != "ids" {
				t.Fatalf("calls = %+v, want one ids call", sink.calls)
			}
			assertArgs(t, sink.calls[0].args, tt.wantArgs)
		})
	}
}

// TestObserveDerived_HAProxy_EndToEnd is the regression test for #277: derive.go
// must read the same attribute key haproxy.go's httplog parser actually writes.
// It drives a real HAProxy httplog line through parseHAProxy (reusing the fixture
// and helpers from haproxy_test.go) rather than hand-building the attribute map,
// so the parser and the deriver are checked against each other, not each checked
// against itself — which is exactly what let the two keys drift apart before.
func TestObserveDerived_HAProxy_EndToEnd(t *testing.T) {
	const line = `172.16.9.99:34000 [14/Jul/2026:12:00:00.123] ft-heavy bk-heavy/heavy-1 12/0/1/9/22 503 1234 - - ---- 5/3/2/1/0 0/0 "GET /api/health HTTP/1.1"`

	rec, ok, _ := parseHAProxyLine(t, line, 6)
	if !ok {
		t.Fatal("parseHAProxy returned ok=false for an httplog line")
	}

	sink := &fakeSink{}
	counted := observeDerived(sink, "haproxy", rec.Attributes)
	if !counted {
		t.Fatal("observeDerived did not count a well-formed httplog record")
	}
	if len(sink.calls) != 1 || sink.calls[0].method != "haproxy" {
		t.Fatalf("calls = %+v, want one haproxy call", sink.calls)
	}
	const wantStatusClass = "5xx" // line carries status 503
	if got := sink.calls[0].args[4]; got != wantStatusClass {
		t.Errorf("status_class = %q, want %q", got, wantStatusClass)
	}
}

// TestObserveDerived_DnsmasqDHCP_EndToEnd is the regression test for #396: a real
// dnsmasq-dhcp DHCPREQUEST/DHCPACK line, run through the actual parser (not a
// hand-built attribute map), must increment the DHCP derived counter. dnsmasq-dhcp
// was a registered DHCP parser alias (#335) missing from programFamily, so real
// lease lines parsed and shipped but observeDerived silently refused to count
// them — TestEveryParserProgramHasAFamilyDecision above is the general guard;
// this is the specific parser-to-observation path that guard cannot see (it only
// checks that a family decision EXISTS, not that observeDerived actually fires
// end to end for that program).
func TestObserveDerived_DnsmasqDHCP_EndToEnd(t *testing.T) {
	rec, ok := parseDHCP(dhcpEnvelope("dnsmasq-dhcp", "DHCPACK(ixl0_vlan50) 10.0.50.112 a8:9c:6c:24:b8:00 exporter-traffgen"), nil, func(string) {})
	if !ok {
		t.Fatal("parseDHCP returned ok=false for a dnsmasq-dhcp DHCPACK")
	}

	sink := &fakeSink{}
	counted := observeDerived(sink, "dnsmasq-dhcp", rec.Attributes)
	if !counted {
		t.Fatal("observeDerived did not count a well-formed dnsmasq-dhcp DHCPACK")
	}
	if len(sink.calls) != 1 || sink.calls[0].method != "dhcp" {
		t.Fatalf("calls = %+v, want one dhcp call", sink.calls)
	}
	// action=ack, interface falls back to the raw token (no enrichment snapshot was
	// passed to parseDHCP), server is empty (dnsmasq lines carry no server_ip).
	assertArgs(t, sink.calls[0].args, []string{"ack", "ixl0_vlan50", ""})

	// A DHCPREQUEST on the same alias must count too, not just DHCPACK.
	rec2, ok := parseDHCP(dhcpEnvelope("dnsmasq-dhcp", "DHCPREQUEST(ixl0_vlan50) 10.0.50.112 a8:9c:6c:24:b8:00"), nil, func(string) {})
	if !ok {
		t.Fatal("parseDHCP returned ok=false for a dnsmasq-dhcp DHCPREQUEST")
	}
	sink2 := &fakeSink{}
	if !observeDerived(sink2, "dnsmasq-dhcp", rec2.Attributes) {
		t.Fatal("observeDerived did not count a well-formed dnsmasq-dhcp DHCPREQUEST")
	}
	assertArgs(t, sink2.calls[0].args, []string{"request", "ixl0_vlan50", ""})
}

func TestStatusClass(t *testing.T) {
	tests := []struct {
		status string
		want   string
	}{
		{"200", "2xx"},
		{"301", "3xx"},
		{"404", "4xx"},
		{"503", "5xx"},
		{"", ""},
		{"garbage", ""},
		{"99", ""},
		{"1000", ""},
	}
	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			if got := statusClass(tt.status); got != tt.want {
				t.Errorf("statusClass(%q) = %q, want %q", tt.status, got, tt.want)
			}
		})
	}
}

func assertArgs(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("args = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("arg[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
