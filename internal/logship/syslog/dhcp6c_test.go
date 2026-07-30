package syslog

import (
	"testing"
	"time"
)

// The production capture's exact envelope for a dhcp6c line: facility 1 (user),
// severity 5 (notice) — PRI 13 — APP-NAME `dhcp6c`, with the daemon's PID in PROCID.
// The PID matters for the same reason it did in #541: `Received REPLY for RENEW`
// names no interface and is resolved by correlating it with the `Sending Renew on
// <iface>` the same process emitted.
func dhcp6cEnv(t *testing.T, pid, message string) Envelope {
	t.Helper()

	env, err := ParseEnvelope([]byte("<13>1 2026-07-30T09:00:00+01:00 test-firewall dhcp6c "+pid+" - [meta sequenceId=\"sanitized-sequence\"] "+message), time.Time{})
	if err != nil {
		t.Fatalf("ParseEnvelope() error = %v", err)
	}
	return env
}

// The captured line's timestamp as Unix seconds, so the prefix-gauge expectations
// are stated once rather than recomputed per case.
const dhcp6cCaptureUnix = 1785398400 // 2026-07-30T09:00:00+01:00

func TestDHCP6CRegisteredWithSubsystem(t *testing.T) {
	if _, exact := parsers["dhcp6c"]; !exact {
		t.Fatal("dhcp6c is not registered as an EXACT program name; before #546 it shipped 1,444 lines/day unparsed")
	}
	if !parserEnrichesBody("dhcp6c") {
		t.Error("parserEnrichesBody(\"dhcp6c\") = false; these lines already carry interface/interface.name from the generic body scan and removing that is a live regression")
	}
	if got := subsystemFor("dhcp6c"); got != "dhcp" {
		t.Errorf("subsystemFor(\"dhcp6c\") = %q, want \"dhcp\"", got)
	}
}

// The SIX grammars captured verbatim on the production box, plus the sibling shapes
// the same format strings can produce (verified against opnsense/dhcp6c source and
// opnsense/core's dhcp6c_script.sh — see dhcp6c.go for the file/line of each).
func TestDHCP6CCapturedGrammars(t *testing.T) {
	tests := []struct {
		name    string
		message string
		want    map[string]string
	}{
		{
			name:    "captured: Sending Renew names the WAN interface",
			message: "Sending Renew on pppoe0",
			want: map[string]string{
				attrDHCP6CDirection: dhcp6cDirectionSent,
				attrDHCP6CType:      dhcp6cTypeRenew,
				attrDHCP6CInterface: "pppoe0",
			},
		},
		{
			name:    "captured: the reply names NO interface",
			message: "Received REPLY for RENEW",
			want: map[string]string{
				attrDHCP6CDirection: dhcp6cDirectionReceived,
				attrDHCP6CType:      dhcp6cTypeRenew,
				attrDHCP6CInterface: "",
			},
		},
		{
			name:    "captured: the script's lifecycle line",
			message: "dhcp6c_script: RENEW on pppoe0 executing",
			want: map[string]string{
				attrDHCP6CEvent:        dhcp6cEventScriptExecuting,
				attrDHCP6CScriptReason: dhcp6cTypeRenew,
				attrDHCP6CInterface:    "pppoe0",
			},
		},
		{
			name:    "captured: an address configured on a DOWNSTREAM interface",
			message: "add an address 2001:db8:0:9ab7:85ff:fe21:aff2/64 on ixl0",
			want: map[string]string{
				attrDHCP6CEvent:     dhcp6cEventAddressAdded,
				attrDHCP6CInterface: "ixl0",
				attrDHCP6CAddress:   "2001:db8:0:9ab7:85ff:fe21:aff2",
			},
		},
		{
			name:    "captured: the same on a VLAN child device",
			message: "add an address 2001:db8:100:0:ff:fe00:64/64 on ixl0_vlan100",
			want: map[string]string{
				attrDHCP6CEvent:     dhcp6cEventAddressAdded,
				attrDHCP6CInterface: "ixl0_vlan100",
			},
		},
		{
			name:    "from source: dhcp6c prefixes every C-source line with its function name",
			message: "client6_send: Sending Renew on pppoe0",
			want: map[string]string{
				attrDHCP6CDirection: dhcp6cDirectionSent,
				attrDHCP6CType:      dhcp6cTypeRenew,
				attrDHCP6CInterface: "pppoe0",
			},
		},
		{
			name:    "from source: Sending Information Request is a two-word type",
			message: "Sending Information Request on pppoe0",
			want: map[string]string{
				attrDHCP6CDirection: dhcp6cDirectionSent,
				attrDHCP6CType:      dhcp6cTypeInformationRequest,
				attrDHCP6CInterface: "pppoe0",
			},
		},
		{
			name:    "from source: a reply to an INFOREQ folds onto the same type vocabulary",
			message: "Received REPLY for INFOREQ",
			want: map[string]string{
				attrDHCP6CDirection: dhcp6cDirectionReceived,
				attrDHCP6CType:      dhcp6cTypeInformationRequest,
			},
		},
		{
			name:    "from source: remove an address",
			message: "remove an address 2001:db8:0:9ab7:85ff:fe21:aff2/64 on ixl0",
			want: map[string]string{
				attrDHCP6CEvent:     dhcp6cEventAddressRemoved,
				attrDHCP6CInterface: "ixl0",
			},
		},
		{
			name:    "from source: the script's connected-to-server line",
			message: "dhcp6c_script: REQUEST on pppoe0 connected to server",
			want: map[string]string{
				attrDHCP6CEvent:        dhcp6cEventScriptConnected,
				attrDHCP6CScriptReason: dhcp6cTypeRequest,
				attrDHCP6CInterface:    "pppoe0",
			},
		},
		{
			name:    "from source: the script's prefix-applied line, prefix as an ATTRIBUTE",
			message: "dhcp6c_script: RENEW on pppoe0 prefix now 2001:db8::/48",
			want: map[string]string{
				attrDHCP6CEvent:        dhcp6cEventScriptPrefixUpdated,
				attrDHCP6CScriptReason: dhcp6cTypeRenew,
				attrDHCP6CInterface:    "pppoe0",
				attrDHCP6CPrefix:       "2001:db8::/48",
			},
		},
		{
			name:    "from source: an unhandled REASON is ignored by the script and never becomes a label",
			message: "dhcp6c_script: DECLINE on pppoe0 ignored",
			want: map[string]string{
				attrDHCP6CEvent:        dhcp6cEventScriptIgnored,
				attrDHCP6CScriptReason: "",
				attrDHCP6CInterface:    "pppoe0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dhcp6cIfaces.reset()
			rec, ok := parseDHCP6C(dhcp6cEnv(t, "41234", tt.message), nil, nil)
			if !ok {
				t.Fatal("parseDHCP6C() ok = false, want true")
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

// The prefix-delegation lifetimes: #546's stated highest-value signal. Three
// ABSOLUTE timestamps computed from the LINE's own syslog timestamp plus dhcp6c's
// pltime/vltime — never a countdown recomputed at scrape time.
func TestDHCP6CPrefixComputesAbsoluteExpiryTimestamps(t *testing.T) {
	tests := []struct {
		name          string
		message       string
		wantEvent     string
		wantUpdated   string
		wantPreferred string
		wantValid     string
	}{
		{
			name:          "captured: the /48 delegation refreshed at every renewal",
			message:       "update a prefix 2001:db8::/48 pltime=3600, vltime=3600",
			wantEvent:     dhcp6cEventPrefixUpdated,
			wantUpdated:   "1785398400",
			wantPreferred: "1785402000",
			wantValid:     "1785402000",
		},
		{
			name:          "from source: the first delegation of a prefix says create, not update",
			message:       "update_prefix: create a prefix 2001:db8::/48 pltime=1800, vltime=3600",
			wantEvent:     dhcp6cEventPrefixCreated,
			wantUpdated:   "1785398400",
			wantPreferred: "1785400200",
			wantValid:     "1785402000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dhcp6cIfaces.reset()
			rec, ok := parseDHCP6C(dhcp6cEnv(t, "41234", tt.message), nil, nil)
			if !ok {
				t.Fatal("parseDHCP6C() ok = false, want true")
			}
			if got := rec.Attributes[attrDHCP6CEvent]; got != tt.wantEvent {
				t.Errorf("event = %q, want %q", got, tt.wantEvent)
			}
			if got := rec.Attributes[attrDHCP6CPrefixUpdatedTimestamp]; got != tt.wantUpdated {
				t.Errorf("updated timestamp = %q, want %q", got, tt.wantUpdated)
			}
			if got := rec.Attributes[attrDHCP6CPrefixPreferredTimestamp]; got != tt.wantPreferred {
				t.Errorf("preferred expiry = %q, want %q", got, tt.wantPreferred)
			}
			if got := rec.Attributes[attrDHCP6CPrefixValidTimestamp]; got != tt.wantValid {
				t.Errorf("valid expiry = %q, want %q", got, tt.wantValid)
			}
			// The prefix and both raw lifetimes still ship on the record.
			if got := rec.Attributes[attrDHCP6CPrefix]; got != "2001:db8::/48" {
				t.Errorf("prefix = %q, want it on the record", got)
			}
			if got := rec.Attributes[attrDHCP6CPrefixLength]; got != "48" {
				t.Errorf("prefix length = %q, want \"48\"", got)
			}
			if rec.Attributes[attrDHCP6CPreferredSeconds] == "" || rec.Attributes[attrDHCP6CValidSeconds] == "" {
				t.Error("the raw pltime/vltime must still ship on the record")
			}
		})
	}

	// Sanity: the constant the expectations are built on is the test line's own time.
	if got := dhcp6cEnv(t, "1", "x").Timestamp.Unix(); got != dhcp6cCaptureUnix {
		t.Fatalf("test envelope Unix time = %d, want %d", got, dhcp6cCaptureUnix)
	}
}

// The WAN ADDRESS-LEASE gauges (#560) — the IA_NA twin of the prefix triple, from a
// REAL capture on testbed VM 102 (2026-07-30), address anonymised to RFC 3849
// documentation space (2001:db8::/32) in place of the real globally-routable prefix.
// Shape, pltime/vltime values and interface names are preserved verbatim.
func TestDHCP6CAddressLeaseComputesAbsoluteExpiryTimestamps(t *testing.T) {
	tests := []struct {
		name          string
		message       string
		wantEvent     string
		wantUpdated   string
		wantPreferred string
		wantValid     string
	}{
		{
			// Captured verbatim (address anonymised): "update an address
			// 2001:db8::1004 pltime=1125, vltime=1800" — by far the most common
			// shape on the box, ~66x more frequent than "create".
			name:          "captured: an update refreshes the WAN address lease",
			message:       "update an address 2001:db8::1004 pltime=1125, vltime=1800",
			wantEvent:     dhcp6cEventAddressLeaseUpdated,
			wantUpdated:   "1785398400",
			wantPreferred: "1785399525",
			wantValid:     "1785400200",
		},
		{
			// Captured verbatim (address anonymised): "create an address
			// 2001:db8::1000 pltime=1125, vltime=1800" — the first lease for a
			// given IA_NA.
			name:          "captured: a create establishes the WAN address lease",
			message:       "create an address 2001:db8::1000 pltime=1125, vltime=1800",
			wantEvent:     dhcp6cEventAddressLeaseCreated,
			wantUpdated:   "1785398400",
			wantPreferred: "1785399525",
			wantValid:     "1785400200",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dhcp6cIfaces.reset()
			rec, ok := parseDHCP6C(dhcp6cEnv(t, "18837", tt.message), nil, nil)
			if !ok {
				t.Fatal("parseDHCP6C() ok = false, want true")
			}
			if got := rec.Attributes[attrDHCP6CEvent]; got != tt.wantEvent {
				t.Errorf("event = %q, want %q", got, tt.wantEvent)
			}
			if got := rec.Attributes[attrDHCP6CAddressLeaseUpdatedTimestamp]; got != tt.wantUpdated {
				t.Errorf("updated timestamp = %q, want %q", got, tt.wantUpdated)
			}
			if got := rec.Attributes[attrDHCP6CAddressLeasePreferredTimestamp]; got != tt.wantPreferred {
				t.Errorf("preferred expiry = %q, want %q", got, tt.wantPreferred)
			}
			if got := rec.Attributes[attrDHCP6CAddressLeaseValidTimestamp]; got != tt.wantValid {
				t.Errorf("valid expiry = %q, want %q", got, tt.wantValid)
			}
			// The address and both raw lifetimes still ship on the record.
			if got := rec.Attributes[attrDHCP6CAddress]; got != "2001:db8::1004" && got != "2001:db8::1000" {
				t.Errorf("address = %q, want it on the record", got)
			}
			if rec.Attributes[attrDHCP6CAddressLeasePreferredSeconds] == "" || rec.Attributes[attrDHCP6CAddressLeaseValidSeconds] == "" {
				t.Error("the raw pltime/vltime must still ship on the record")
			}
		})
	}
}

// Two simultaneous WAN interfaces each holding their own address lease at the same
// time (captured on testbed VM 102: ::1000 on vtnet1, ::1004 on vtnet0) must not be
// fused onto one series — the PID correlation is per-daemon-process, and a multi-WAN
// box runs one dhcp6c process per interface.
func TestDHCP6CAddressLeaseDoesNotFuseTwoSimultaneousWANInterfaces(t *testing.T) {
	dhcp6cIfaces.reset()

	if _, ok := parseDHCP6C(dhcp6cEnv(t, "100", "Sending Request on vtnet1"), nil, nil); !ok {
		t.Fatal("vtnet1's Sending line did not parse")
	}
	if _, ok := parseDHCP6C(dhcp6cEnv(t, "200", "Sending Request on vtnet0"), nil, nil); !ok {
		t.Fatal("vtnet0's Sending line did not parse")
	}

	rec1, ok := parseDHCP6C(dhcp6cEnv(t, "100", "update an address 2001:db8::1000 pltime=1125, vltime=1800"), nil, nil)
	if !ok {
		t.Fatal("vtnet1's address-lease line did not parse")
	}
	rec2, ok := parseDHCP6C(dhcp6cEnv(t, "200", "update an address 2001:db8::1004 pltime=1125, vltime=1800"), nil, nil)
	if !ok {
		t.Fatal("vtnet0's address-lease line did not parse")
	}

	if got := rec1.Attributes[attrDHCP6CInterface]; got != "vtnet1" {
		t.Errorf("PID 100's interface = %q, want vtnet1", got)
	}
	if got := rec2.Attributes[attrDHCP6CInterface]; got != "vtnet0" {
		t.Errorf("PID 200's interface = %q, want vtnet0", got)
	}
}

// The bare `remove an address <addr>` (no lifetime, no interface) is the WAN
// address-lease removal — distinct from `remove an address <addr>/<plen> on
// <iface>`, which is a downstream address. It resolves its interface the same way
// the create/update line does, and sets NO gauge attributes: the caller is expected
// to CLEAR the gauges on this event rather than freeze them.
func TestDHCP6CAddressLeaseRemoveResolvesInterfaceButSetsNoGauges(t *testing.T) {
	dhcp6cIfaces.reset()

	if _, ok := parseDHCP6C(dhcp6cEnv(t, "18837", "Sending Release on vtnet1"), nil, nil); !ok {
		t.Fatal("the Sending line did not parse")
	}

	rec, ok := parseDHCP6C(dhcp6cEnv(t, "18837", "remove an address 2001:db8::1000"), nil, nil)
	if !ok {
		t.Fatal("parseDHCP6C() ok = false, want true")
	}
	if got := rec.Attributes[attrDHCP6CEvent]; got != dhcp6cEventAddressLeaseRemoved {
		t.Errorf("event = %q, want %q", got, dhcp6cEventAddressLeaseRemoved)
	}
	if got := rec.Attributes[attrDHCP6CInterface]; got != "vtnet1" {
		t.Errorf("interface = %q, want vtnet1 from the PID correlation", got)
	}
	if got := rec.Attributes[attrDHCP6CAddress]; got != "2001:db8::1000" {
		t.Errorf("address = %q, want it on the record", got)
	}
	for _, k := range []string{attrDHCP6CAddressLeaseUpdatedTimestamp, attrDHCP6CAddressLeasePreferredTimestamp, attrDHCP6CAddressLeaseValidTimestamp} {
		if got := rec.Attributes[k]; got != "" {
			t.Errorf("%s = %q on a removal, want none", k, got)
		}
	}
}

// An undated line (RFC5424 `-`) gets NO gauge attributes. Substituting time.Now()
// would silently mis-date a deadline, and a wrong deadline is worse than an absent
// one — the whole metric is "did the deadline pass".
func TestDHCP6CPrefixWithoutTimestampSetsNoGauges(t *testing.T) {
	dhcp6cIfaces.reset()

	env, err := ParseEnvelope([]byte("<13>1 - test-firewall dhcp6c 41234 - - update a prefix 2001:db8::/48 pltime=3600, vltime=3600"), time.Time{})
	if err != nil {
		t.Fatalf("ParseEnvelope() error = %v", err)
	}
	rec, ok := parseDHCP6C(env, nil, nil)
	if !ok {
		t.Fatal("parseDHCP6C() ok = false, want true - the record must still ship")
	}
	for _, k := range []string{attrDHCP6CPrefixUpdatedTimestamp, attrDHCP6CPrefixPreferredTimestamp, attrDHCP6CPrefixValidTimestamp} {
		if got := rec.Attributes[k]; got != "" {
			t.Errorf("%s = %q for an undated line, want none", k, got)
		}
	}
	if rec.Attributes[attrDHCP6CPreferredSeconds] != "3600" {
		t.Error("the raw pltime must still ship on an undated line")
	}
}

// The WAN interface reaches the interface-less lines through the daemon's PID,
// exactly as #541 does for dhclient's `DHCPACK from <ip>`.
func TestDHCP6CPIDCorrelationResolvesInterfacelessLines(t *testing.T) {
	dhcp6cIfaces.reset()

	if _, ok := parseDHCP6C(dhcp6cEnv(t, "41234", "Sending Renew on pppoe0"), nil, nil); !ok {
		t.Fatal("the Sending line that teaches the correlation did not parse")
	}

	for _, tt := range []struct{ name, message string }{
		{"the reply", "Received REPLY for RENEW"},
		{"the prefix update", "update a prefix 2001:db8::/48 pltime=3600, vltime=3600"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rec, ok := parseDHCP6C(dhcp6cEnv(t, "41234", tt.message), nil, nil)
			if !ok {
				t.Fatalf("parseDHCP6C(%q) ok = false", tt.message)
			}
			if got := rec.Attributes[attrDHCP6CInterface]; got != "pppoe0" {
				t.Errorf("interface = %q, want %q from the PID correlation", got, "pppoe0")
			}
		})
	}

	// An unknown PID must resolve to EMPTY, never to a guess.
	rec, ok := parseDHCP6C(dhcp6cEnv(t, "99999", "Received REPLY for RENEW"), nil, nil)
	if !ok {
		t.Fatal("parseDHCP6C(reply) ok = false")
	}
	if got := rec.Attributes[attrDHCP6CInterface]; got != "" {
		t.Errorf("interface = %q for an uncorrelated PID, want empty", got)
	}
}

// `add an address <addr>/<plen> on ixl0` names a DOWNSTREAM interface the delegated
// prefix was applied to, not the WAN dhcp6c is renewing on — and it comes from the
// SAME daemon PID. If it taught the correlation table, the next `Received REPLY`
// would be attributed to a LAN interface. Same trap as #541's dhclient-script line,
// different mechanism.
func TestDHCP6CAddressLineDoesNotTeachThePIDCorrelation(t *testing.T) {
	dhcp6cIfaces.reset()

	if _, ok := parseDHCP6C(dhcp6cEnv(t, "41234", "Sending Renew on pppoe0"), nil, nil); !ok {
		t.Fatal("the Sending line did not parse")
	}
	if _, ok := parseDHCP6C(dhcp6cEnv(t, "41234", "add an address 2001:db8:0:9ab7:85ff:fe21:aff2/64 on ixl0"), nil, nil); !ok {
		t.Fatal("the address line did not parse")
	}
	if got := dhcp6cIfaces.lookup("41234"); got != "pppoe0" {
		t.Errorf("the address line overwrote the WAN correlation with %q; only the Sending line may teach it", got)
	}
}

// The script runs as its OWN process (logger -t dhcp6c from a shell script), so its
// lines must not teach the correlation table either.
func TestDHCP6CScriptDoesNotTeachThePIDCorrelation(t *testing.T) {
	dhcp6cIfaces.reset()

	if _, ok := parseDHCP6C(dhcp6cEnv(t, "7351", "dhcp6c_script: RENEW on pppoe0 executing"), nil, nil); !ok {
		t.Fatal("the script line did not parse")
	}
	if got := dhcp6cIfaces.lookup("7351"); got != "" {
		t.Errorf("the script line taught the PID correlation table (%q); only daemon lines may", got)
	}
}

// End to end through observeDerived: which sink calls a dhcp6c record produces.
func TestObserveDerived_DHCP6C(t *testing.T) {
	tests := []struct {
		name    string
		pid     string
		setup   string
		message string
		want    []fakeCall
	}{
		{
			name:    "a sent message counts one dhcp6c_message observation",
			pid:     "41234",
			message: "Sending Renew on pppoe0",
			want:    []fakeCall{{"dhcp6c_message", []string{"pppoe0", dhcp6cDirectionSent, dhcp6cTypeRenew}}},
		},
		{
			name:    "a reply counts under the correlated WAN interface",
			pid:     "41234",
			setup:   "Sending Renew on pppoe0",
			message: "Received REPLY for RENEW",
			want:    []fakeCall{{"dhcp6c_message", []string{"pppoe0", dhcp6cDirectionReceived, dhcp6cTypeRenew}}},
		},
		{
			name:    "a prefix update counts an event AND sets the three gauges",
			pid:     "41234",
			setup:   "Sending Renew on pppoe0",
			message: "update a prefix 2001:db8::/48 pltime=3600, vltime=3600",
			want: []fakeCall{
				{"dhcp6c_event", []string{"pppoe0", dhcp6cEventPrefixUpdated, ""}},
				{"dhcp6c_prefix", []string{"pppoe0", "48", "1785398400", "1785402000", "1785402000"}},
			},
		},
		{
			name:    "an address event counts under the DOWNSTREAM interface it names",
			pid:     "41234",
			setup:   "Sending Renew on pppoe0",
			message: "add an address 2001:db8:0:9ab7:85ff:fe21:aff2/64 on ixl0",
			want:    []fakeCall{{"dhcp6c_event", []string{"ixl0", dhcp6cEventAddressAdded, ""}}},
		},
		{
			name:    "a script line counts an event carrying its closed reason",
			pid:     "7351",
			message: "dhcp6c_script: RENEW on pppoe0 executing",
			want:    []fakeCall{{"dhcp6c_event", []string{"pppoe0", dhcp6cEventScriptExecuting, dhcp6cTypeRenew}}},
		},
		{
			name:    "an address-lease update counts an event AND sets the three gauges (#560)",
			pid:     "18837",
			setup:   "Sending Request on vtnet1",
			message: "update an address 2001:db8::1004 pltime=1125, vltime=1800",
			want: []fakeCall{
				{"dhcp6c_event", []string{"vtnet1", dhcp6cEventAddressLeaseUpdated, ""}},
				{"dhcp6c_address", []string{"vtnet1", "1785398400", "1785399525", "1785400200"}},
			},
		},
		{
			name:    "an address-lease create counts an event AND sets the three gauges",
			pid:     "18837",
			setup:   "Sending Request on vtnet1",
			message: "create an address 2001:db8::1000 pltime=1125, vltime=1800",
			want: []fakeCall{
				{"dhcp6c_event", []string{"vtnet1", dhcp6cEventAddressLeaseCreated, ""}},
				{"dhcp6c_address", []string{"vtnet1", "1785398400", "1785399525", "1785400200"}},
			},
		},
		{
			name:    "an address-lease removal counts an event AND clears the gauges",
			pid:     "18837",
			setup:   "Sending Release on vtnet1",
			message: "remove an address 2001:db8::1000",
			want: []fakeCall{
				{"dhcp6c_event", []string{"vtnet1", dhcp6cEventAddressLeaseRemoved, ""}},
				{"dhcp6c_address_clear", []string{"vtnet1"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dhcp6cIfaces.reset()
			if tt.setup != "" {
				if _, ok := parseDHCP6C(dhcp6cEnv(t, tt.pid, tt.setup), nil, nil); !ok {
					t.Fatalf("setup line %q did not parse", tt.setup)
				}
			}
			rec, ok := parseDHCP6C(dhcp6cEnv(t, tt.pid, tt.message), nil, nil)
			if !ok {
				t.Fatalf("parseDHCP6C(%q) ok = false, want true", tt.message)
			}

			sink := &fakeSink{}
			if !observeDerived(sink, "dhcp6c", rec.Attributes) {
				t.Fatal("observeDerived() counted = false, want true")
			}
			assertCalls(t, sink.calls, tt.want)
		})
	}
}

// THE HARD CONSTRAINT. The delegated prefix — even though it is the FIREWALL'S OWN
// /48 rather than a client's — must never reach a metric label: it changes on
// re-delegation, which is precisely the event these metrics exist to watch. Nor may
// any configured IPv6 address. Only the prefix LENGTH, which is the delegation SIZE
// and does not change when the prefix does.
func TestDHCP6CPrefixAndAddressesAreNeverLabels(t *testing.T) {
	secrets := []string{
		"2001:db8::/48",
		"2001:db8::",
		"2001:db8:0:9ab7:85ff:fe21:aff2",
		"2001:db8::1000",
		"2001:db8::1004",
	}

	for _, msg := range []string{
		"update a prefix 2001:db8::/48 pltime=3600, vltime=3600",
		"add an address 2001:db8:0:9ab7:85ff:fe21:aff2/64 on ixl0",
		"dhcp6c_script: RENEW on pppoe0 prefix now 2001:db8::/48",
		"update an address 2001:db8::1004 pltime=1125, vltime=1800",
		"create an address 2001:db8::1000 pltime=1125, vltime=1800",
		"remove an address 2001:db8::1000",
	} {
		t.Run(msg, func(t *testing.T) {
			dhcp6cIfaces.reset()
			rec, ok := parseDHCP6C(dhcp6cEnv(t, "41234", msg), nil, nil)
			if !ok {
				t.Fatalf("parseDHCP6C(%q) ok = false", msg)
			}
			sink := &fakeSink{}
			observeDerived(sink, "dhcp6c", rec.Attributes)
			for _, call := range sink.calls {
				for _, arg := range call.args {
					for _, secret := range secrets {
						if arg == secret {
							t.Errorf("%q reached a label on %s", arg, call.method)
						}
					}
				}
			}
		})
	}
}

// Lines the parser must leave alone: the daemon says plenty that is not lease
// lifecycle, and a near miss must never mint a label value out of an uncaptured token.
func TestDHCP6CUnmodelledLinesAreNotClaimed(t *testing.T) {
	lines := []string{
		// Real dhcp6c chatter outside the modelled grammars.
		"client6_recvreply: unexpected reply",
		"client6_recvreply: no server ID option",
		"dhcp6c_script: missing REASON or IFNAME",
		"get_ifname: if_indextoname failed",
		// Near misses.
		"Sending Renew",
		"Sending Confirm on pppoe0",
		"Received REPLY for IDLE",
		"Received REPLY",
		"update a prefix 2001:db8::/48 pltime=soon, vltime=3600",
		"update a prefix 2001:db8::/48",
		"add an address 2001:db8::1 on ixl0",
		"dhcp6c_script: RENEW on pppoe0",
		// Address-lease near misses (#560).
		"create an address 2001:db8::1000 pltime=soon, vltime=1800",
		"create an address 2001:db8::1000",
		"update an address 2001:db8::1000/128 pltime=1125, vltime=1800",
		"remove an address 2001:db8::1000/128",
	}

	for _, msg := range lines {
		t.Run(msg, func(t *testing.T) {
			dhcp6cIfaces.reset()
			env := dhcp6cEnv(t, "41234", msg)
			if _, ok := parseDHCP6C(env, nil, nil); ok {
				t.Errorf("parseDHCP6C() CLAIMED a line it must leave generic: %q", msg)
			}
			rec := genericRecord(env)
			sink := &fakeSink{}
			if observeDerived(sink, "dhcp6c", rec.Attributes) {
				t.Errorf("observeDerived() counted an unmodelled dhcp6c line: %q", msg)
			}
		})
	}
}
