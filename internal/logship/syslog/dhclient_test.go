package syslog

import (
	"testing"
	"time"
)

// The production capture's exact envelope for a dhclient line: RFC5424, APP-NAME
// `dhclient`, with the daemon's PID in PROCID. The PID matters — it is what
// correlates an interface-less DHCPACK back to the interface its DHCPREQUEST named.
func dhclientEnv(t *testing.T, pid, message string) Envelope {
	t.Helper()

	env, err := ParseEnvelope([]byte("<30>1 2026-07-25T21:53:00+01:00 test-firewall dhclient "+pid+" - [meta sequenceId=\"sanitized-sequence\"] "+message), time.Time{})
	if err != nil {
		t.Fatalf("ParseEnvelope() error = %v", err)
	}
	return env
}

// The captured line's timestamp as Unix seconds, so the lease-gauge expectations are
// stated once rather than recomputed per case.
const dhclientCaptureUnix = 1785012780 // 2026-07-25T21:53:00+01:00

func TestDHCPClientRegisteredWithSubsystem(t *testing.T) {
	if _, exact := parsers["dhclient"]; !exact {
		t.Fatal("dhclient is not registered as an EXACT program name; before #541 it had ZERO matches in the registry")
	}
	if !parserEnrichesBody("dhclient") {
		t.Error("parserEnrichesBody(\"dhclient\") = false; these lines have carried peer.*/interface.* since #250")
	}
	// The blank subsystem was half of #541's gap: the lines shipped untyped.
	if got := subsystemFor("dhclient"); got != "dhcp" {
		t.Errorf("subsystemFor(\"dhclient\") = %q, want \"dhcp\"", got)
	}
}

// The four grammars CAPTURED VERBATIM on the production box (OPNsense 26.7.1_1,
// WAN = ixl1), plus the shapes modelled from ISC/OpenBSD dhclient source for the
// message types a working WAN never emits.
func TestDHCPClientCapturedGrammars(t *testing.T) {
	tests := []struct {
		name    string
		message string
		want    map[string]string
	}{
		{
			name:    "captured: DHCPREQUEST names the interface and the server",
			message: "DHCPREQUEST on ixl1 to 80.1.23.233 port 67",
			want: map[string]string{
				attrDHCPClientType:      dhcpClientTypeRequest,
				attrDHCPClientInterface: "ixl1",
				attrDHCPClientServer:    "80.1.23.233",
			},
		},
		{
			name:    "captured: dhclient-script Reason line, emitted under program dhclient",
			message: "dhclient-script: Reason RENEW on ixl1 executing",
			want: map[string]string{
				attrDHCPClientScriptReason: dhcpClientReasonRenew,
				attrDHCPClientInterface:    "ixl1",
			},
		},
		{
			name:    "from source: DHCPDISCOVER carries the optional interval suffix",
			message: "DHCPDISCOVER on ixl1 to 255.255.255.255 port 67 interval 3",
			want: map[string]string{
				attrDHCPClientType:      dhcpClientTypeDiscover,
				attrDHCPClientInterface: "ixl1",
				attrDHCPClientServer:    "255.255.255.255",
			},
		},
		{
			name:    "from source: DHCPRELEASE",
			message: "DHCPRELEASE on ixl1 to 80.1.23.233 port 67",
			want: map[string]string{
				attrDHCPClientType:      dhcpClientTypeRelease,
				attrDHCPClientInterface: "ixl1",
				attrDHCPClientServer:    "80.1.23.233",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dhcpClientIfaces.reset()
			rec, ok := parseDHCPClient(dhclientEnv(t, "97927", tt.message), nil, nil)
			if !ok {
				t.Fatal("parseDHCPClient() ok = false, want true")
			}
			for k, want := range tt.want {
				if got := rec.Attributes[k]; got != want {
					t.Errorf("attribute %s = %q, want %q", k, got, want)
				}
			}
			if rec.Body != tt.message {
				t.Errorf("Body = %q, want the message verbatim", rec.Body)
			}
		})
	}
}

// `DHCPACK from <ip>` and `bound to <ip> -- ...` carry NO interface. Both come from
// the SAME daemon process as the DHCPREQUEST that preceded them — verified in a
// captured renewal where PID 97927 emitted all three in sequence — so the PID
// resolves them. Without correlation these two lines could never key a per-interface
// gauge at all.
func TestDHCPClientPIDCorrelationResolvesInterfacelessLines(t *testing.T) {
	dhcpClientIfaces.reset()

	// The captured renewal, in order, all from PID 97927.
	if _, ok := parseDHCPClient(dhclientEnv(t, "97927", "DHCPREQUEST on ixl1 to 80.1.23.233 port 67"), nil, nil); !ok {
		t.Fatal("the DHCPREQUEST that teaches the correlation did not parse")
	}

	ack, ok := parseDHCPClient(dhclientEnv(t, "97927", "DHCPACK from 80.1.23.233"), nil, nil)
	if !ok {
		t.Fatal("parseDHCPClient(DHCPACK) ok = false, want true")
	}
	if got := ack.Attributes[attrDHCPClientInterface]; got != "ixl1" {
		t.Errorf("DHCPACK interface = %q, want %q from the PID correlation", got, "ixl1")
	}
	if got := ack.Attributes[attrDHCPClientType]; got != dhcpClientTypeAck {
		t.Errorf("DHCPACK type = %q, want %q", got, dhcpClientTypeAck)
	}

	bound, ok := parseDHCPClient(dhclientEnv(t, "97927", "bound to 82.7.80.148 -- renewal in 302400 seconds."), nil, nil)
	if !ok {
		t.Fatal("parseDHCPClient(bound to) ok = false, want true")
	}
	if got := bound.Attributes[attrDHCPClientInterface]; got != "ixl1" {
		t.Errorf("bound-to interface = %q, want %q from the PID correlation", got, "ixl1")
	}
}

// An unknown PID must resolve to EMPTY, never to a guess. The exporter routinely
// starts mid-lease and never sees the DHCPREQUEST that would teach it; an empty
// interface is the honest answer, and attributing the ACK to whichever interface
// happened to be seen last would be a lie a dashboard cannot detect.
func TestDHCPClientUncorrelatedInterfaceIsEmptyNeverGuessed(t *testing.T) {
	dhcpClientIfaces.reset()

	// A DIFFERENT process taught the table about a different interface.
	if _, ok := parseDHCPClient(dhclientEnv(t, "11111", "DHCPREQUEST on ixl1 to 80.1.23.233 port 67"), nil, nil); !ok {
		t.Fatal("setup DHCPREQUEST did not parse")
	}

	ack, ok := parseDHCPClient(dhclientEnv(t, "22222", "DHCPACK from 80.1.23.233"), nil, nil)
	if !ok {
		t.Fatal("parseDHCPClient(DHCPACK) ok = false, want true")
	}
	if got := ack.Attributes[attrDHCPClientInterface]; got != "" {
		t.Errorf("interface = %q for an uncorrelated PID, want empty - it must never borrow another process's interface", got)
	}
}

// dhclient-script runs as its OWN process (PIDs 7351/7769/8557 against the daemon's
// 97927 in one captured renewal), so its Reason line must NOT teach the correlation
// table. If it did, the next DHCPACK would be filed under a dead script PID.
func TestDHCPClientScriptDoesNotTeachThePIDCorrelation(t *testing.T) {
	dhcpClientIfaces.reset()

	if _, ok := parseDHCPClient(dhclientEnv(t, "7351", "dhclient-script: Reason RENEW on ixl1 executing"), nil, nil); !ok {
		t.Fatal("the script Reason line did not parse")
	}
	if got := dhcpClientIfaces.lookup("7351"); got != "" {
		t.Errorf("the script line taught the PID correlation table (%q); only daemon lines may", got)
	}
}

// The lease gauges. Two absolute timestamps computed from the LINE's own syslog
// timestamp plus dhclient's renewal interval — never from time.Now(), so a replayed
// or buffered line produces the deadline the firewall meant.
func TestDHCPClientBoundComputesAbsoluteLeaseTimestamps(t *testing.T) {
	tests := []struct {
		name        string
		message     string
		wantBound   string
		wantRenewal string
	}{
		{
			name:        "captured: a full 302400s renewal window",
			message:     "bound to 82.7.80.148 -- renewal in 302400 seconds.",
			wantBound:   "1785012780",
			wantRenewal: "1785315180",
		},
		{
			name:        "captured: a partial window, mid-lease",
			message:     "bound to 82.7.80.148 -- renewal in 213071 seconds.",
			wantBound:   "1785012780",
			wantRenewal: "1785225851",
		},
		{
			name:        "the trailing full stop is optional",
			message:     "bound to 82.7.80.148 -- renewal in 51044 seconds",
			wantBound:   "1785012780",
			wantRenewal: "1785063824",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dhcpClientIfaces.reset()
			rec, ok := parseDHCPClient(dhclientEnv(t, "97927", tt.message), nil, nil)
			if !ok {
				t.Fatal("parseDHCPClient() ok = false, want true")
			}
			if got := rec.Attributes[attrDHCPClientBoundTimestamp]; got != tt.wantBound {
				t.Errorf("bound timestamp = %q, want %q", got, tt.wantBound)
			}
			if got := rec.Attributes[attrDHCPClientRenewalTimestamp]; got != tt.wantRenewal {
				t.Errorf("renewal timestamp = %q, want %q", got, tt.wantRenewal)
			}
			// The leased address and the raw countdown still ship on the record.
			if got := rec.Attributes[attrDHCPClientAddress]; got != "82.7.80.148" {
				t.Errorf("leased address = %q, want it on the record", got)
			}
			if rec.Attributes[attrDHCPClientRenewalSeconds] == "" {
				t.Error("the raw renewal countdown is missing from the record")
			}
		})
	}

	// Sanity: the constant the expectations are built on is the captured line's own time.
	if got := dhclientEnv(t, "1", "x").Timestamp.Unix(); got != dhclientCaptureUnix {
		t.Fatalf("test envelope Unix time = %d, want %d", got, dhclientCaptureUnix)
	}
}

// A line whose envelope carried no timestamp (RFC5424 `-`) gets NO gauge attributes.
// Substituting time.Now() would silently mis-date the deadline, and a wrong deadline
// is worse than an absent one — the whole metric is "did the deadline pass".
func TestDHCPClientBoundWithoutTimestampSetsNoGauges(t *testing.T) {
	dhcpClientIfaces.reset()

	env, err := ParseEnvelope([]byte("<30>1 - test-firewall dhclient 97927 - - bound to 82.7.80.148 -- renewal in 302400 seconds."), time.Time{})
	if err != nil {
		t.Fatalf("ParseEnvelope() error = %v", err)
	}
	rec, ok := parseDHCPClient(env, nil, nil)
	if !ok {
		t.Fatal("parseDHCPClient() ok = false, want true - the record must still ship")
	}
	if got := rec.Attributes[attrDHCPClientBoundTimestamp]; got != "" {
		t.Errorf("bound timestamp = %q for an undated line, want none", got)
	}
	if got := rec.Attributes[attrDHCPClientRenewalTimestamp]; got != "" {
		t.Errorf("renewal timestamp = %q for an undated line, want none", got)
	}
	// The raw countdown and the address are still useful and still ship.
	if rec.Attributes[attrDHCPClientRenewalSeconds] != "302400" {
		t.Error("the raw renewal countdown must still ship on an undated line")
	}
}

// End to end through observeDerived: which sink calls a dhclient record produces.
func TestObserveDerived_DHCPClient(t *testing.T) {
	tests := []struct {
		name    string
		pid     string
		setup   string
		message string
		want    []fakeCall
	}{
		{
			name:    "a sent message counts one dhcp_client observation",
			pid:     "97927",
			message: "DHCPREQUEST on ixl1 to 80.1.23.233 port 67",
			want:    []fakeCall{{"dhcp_client", []string{"ixl1", dhcpClientTypeRequest}}},
		},
		{
			name:    "a received message counts under the correlated interface",
			pid:     "97927",
			setup:   "DHCPREQUEST on ixl1 to 80.1.23.233 port 67",
			message: "DHCPACK from 80.1.23.233",
			want:    []fakeCall{{"dhcp_client", []string{"ixl1", dhcpClientTypeAck}}},
		},
		{
			name:    "a NAK counts as its own type - the alertable one",
			pid:     "97927",
			setup:   "DHCPREQUEST on ixl1 to 80.1.23.233 port 67",
			message: "DHCPNAK from 80.1.23.233",
			want:    []fakeCall{{"dhcp_client", []string{"ixl1", dhcpClientTypeNak}}},
		},
		{
			name:    "a bind sets the lease gauges and counts no message type",
			pid:     "97927",
			setup:   "DHCPREQUEST on ixl1 to 80.1.23.233 port 67",
			message: "bound to 82.7.80.148 -- renewal in 302400 seconds.",
			want:    []fakeCall{{"dhcp_client_lease", []string{"ixl1", "1785012780", "1785315180"}}},
		},
		{
			name:    "a script Reason line counts under the script family",
			pid:     "7351",
			message: "dhclient-script: Reason RENEW on ixl1 executing",
			want:    []fakeCall{{"dhcp_client_script", []string{"ixl1", dhcpClientReasonRenew}}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dhcpClientIfaces.reset()
			if tt.setup != "" {
				if _, ok := parseDHCPClient(dhclientEnv(t, tt.pid, tt.setup), nil, nil); !ok {
					t.Fatalf("setup line %q did not parse", tt.setup)
				}
			}
			rec, ok := parseDHCPClient(dhclientEnv(t, tt.pid, tt.message), nil, nil)
			if !ok {
				t.Fatalf("parseDHCPClient(%q) ok = false, want true", tt.message)
			}

			sink := &fakeSink{}
			if !observeDerived(sink, "dhclient", rec.Attributes) {
				t.Fatal("observeDerived() counted = false, want true")
			}
			if len(sink.calls) != len(tt.want) {
				t.Fatalf("calls = %+v, want %+v", sink.calls, tt.want)
			}
			for i, want := range tt.want {
				got := sink.calls[i]
				if got.method != want.method || len(got.args) != len(want.args) {
					t.Fatalf("call %d = %+v, want %+v", i, got, want)
				}
				for j := range want.args {
					if got.args[j] != want.args[j] {
						t.Errorf("call %d arg %d = %q, want %q", i, j, got.args[j], want.args[j])
					}
				}
			}
		})
	}
}

// The DHCP server's address and this firewall's own leased address are NEVER labels.
// The server address changes when the ISP re-homes the circuit and the leased address
// changes on every re-bind — both are exactly the conditions these metrics watch for,
// so either as a label would churn the series set precisely during an incident.
func TestDHCPClientAddressesAreNeverLabels(t *testing.T) {
	dhcpClientIfaces.reset()

	for _, msg := range []string{
		"DHCPREQUEST on ixl1 to 80.1.23.233 port 67",
		"bound to 82.7.80.148 -- renewal in 302400 seconds.",
	} {
		rec, ok := parseDHCPClient(dhclientEnv(t, "97927", msg), nil, nil)
		if !ok {
			t.Fatalf("parseDHCPClient(%q) ok = false", msg)
		}
		sink := &fakeSink{}
		observeDerived(sink, "dhclient", rec.Attributes)
		for _, call := range sink.calls {
			for _, arg := range call.args {
				if arg == "80.1.23.233" || arg == "82.7.80.148" {
					t.Errorf("%q reached a label on %s", arg, call.method)
				}
			}
		}
	}

	// Both still ship on the record, which is where an operator finds them.
	rec, _ := parseDHCPClient(dhclientEnv(t, "97927", "bound to 82.7.80.148 -- renewal in 302400 seconds."), nil, nil)
	if rec.Attributes[attrDHCPClientAddress] != "82.7.80.148" {
		t.Error("the leased address must still ship as a record attribute")
	}
}

// Lines the parser must leave alone. The script's hostname and resolv.conf chatter
// are side effects rather than lease lifecycle; the rest are near misses that would
// mint a label value out of a token nobody has captured.
func TestDHCPClientUnmodelledLinesAreNotClaimed(t *testing.T) {
	lines := []string{
		// Captured, deliberately excluded.
		"dhclient-script: New Hostname (ixl1): opnsense",
		"dhclient-script: Creating resolv.conf",
		// Near misses.
		"DHCPREQUEST on ixl1 to 80.1.23.233",
		"DHCPWHATEVER on ixl1 to 80.1.23.233 port 67",
		"DHCPACK from 80.1.23.233 trailing junk",
		"bound to 82.7.80.148 -- renewal in soon seconds.",
		"dhclient-script: Reason RENEW on ixl1",
		// A verb the regex accepts but the label vocabulary deliberately refuses: a
		// relay-agent message a client never sends, so there is no honest label for it.
		"DHCPLEASEQUERY on ixl1 to 80.1.23.233 port 67",
	}

	for _, msg := range lines {
		t.Run(msg, func(t *testing.T) {
			dhcpClientIfaces.reset()
			env := dhclientEnv(t, "97927", msg)
			if _, ok := parseDHCPClient(env, nil, nil); ok {
				t.Errorf("parseDHCPClient() CLAIMED a line it must leave generic: %q", msg)
			}
			rec := genericRecord(env)
			sink := &fakeSink{}
			if observeDerived(sink, "dhclient", rec.Attributes) {
				t.Errorf("observeDerived() counted an unmodelled dhclient line: %q", msg)
			}
		})
	}
}

// The PID correlation table is BOUNDED. A dhclient restart loop mints a new PID
// every time, and without the cap that would grow this map for the life of the
// process — the same class of unbounded state the log_events key budget exists for.
func TestDHCPClientPIDMemoryIsBounded(t *testing.T) {
	mem := newPIDIfaceMemory(4)
	for i := 0; i < 100; i++ {
		mem.remember(string(rune('a'+i%26))+string(rune('0'+i/26)), "ixl1")
	}
	mem.mu.Lock()
	got := len(mem.byPID)
	order := len(mem.order)
	mem.mu.Unlock()
	if got > 4 || order > 4 {
		t.Errorf("PID memory grew to %d entries (order %d), want at most 4", got, order)
	}

	// Eviction is OLDEST-first, and a re-remembered PID must not double-insert.
	mem = newPIDIfaceMemory(2)
	mem.remember("1", "ixl1")
	mem.remember("2", "ixl2")
	mem.remember("2", "ixl2")
	if got := mem.lookup("1"); got != "ixl1" {
		t.Errorf("re-remembering an existing PID evicted another entry: lookup(1) = %q", got)
	}
	mem.remember("3", "ixl3")
	if got := mem.lookup("1"); got != "" {
		t.Errorf("lookup(1) = %q after overflow, want the OLDEST entry evicted", got)
	}
	if got := mem.lookup("3"); got != "ixl3" {
		t.Errorf("lookup(3) = %q, want ixl3", got)
	}
}
