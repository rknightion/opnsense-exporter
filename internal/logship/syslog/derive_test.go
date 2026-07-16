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
				"action":    "pass",
				"interface": "igb0",
				"rule.ref":  "rule #16.1",
			},
			wantCounted: true,
			wantArgs:    []string{"pass", "igb0", "rule #16.1", "", ""},
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
				"event_type":     "alert",
				"alert_action":   "blocked",
				"alert_category": "trojan",
				"alert_severity": "1",
			},
			wantCounted: true,
			wantArgs:    []string{"alert", "blocked", "trojan", "1"},
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
