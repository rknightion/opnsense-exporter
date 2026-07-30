package syslog

import (
	"testing"
	"time"
)

// assertCalls compares a fakeSink's recorded calls against the expectation, in
// order. It lives here rather than being copy-pasted into each new lane's table.
func assertCalls(t *testing.T, got, want []fakeCall) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("calls = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i].method != want[i].method || len(got[i].args) != len(want[i].args) {
			t.Fatalf("call %d = %+v, want %+v", i, got[i], want[i])
		}
		for j := range want[i].args {
			if got[i].args[j] != want[i].args[j] {
				t.Errorf("call %d arg %d = %q, want %q", i, j, got[i].args[j], want[i].args[j])
			}
		}
	}
}

func keaDHCP6Env(t *testing.T, message string) Envelope {
	t.Helper()

	env, err := ParseEnvelope([]byte("<12>1 2026-07-30T09:00:00+01:00 test-firewall kea-dhcp6 63611 - - "+message), time.Time{})
	if err != nil {
		t.Fatalf("ParseEnvelope() error = %v", err)
	}
	return env
}

// The captured DUID, verbatim from the production box. It must never reach a label.
const keaCapturedDUID = "00:01:00:01:31:61:d5:a9:40:ed:cf:79:e7:44"

// The three ALLOC_FAIL lines captured verbatim, plus the two siblings Kea's own
// source can emit on the same code path (alloc_engine.cc lines 745/793 — see
// dhcp.go). Two of the captured three are DELIBERATELY not counted.
func TestKeaDHCP6AllocFailGrammars(t *testing.T) {
	tests := []struct {
		name       string
		message    string
		wantLine   string
		wantReason string // empty = parsed but NOT counted
		wantExtra  map[string]string
	}{
		{
			name:       "captured: the SUBNET scope line - one per failure, but not the counted one",
			message:    "WARN  [kea-dhcp6.alloc-engine.0x4b6ab5a79810] ALLOC_ENGINE_V6_ALLOC_FAIL_SUBNET duid=[" + keaCapturedDUID + "], [no hwaddr info], tid=0x292a15: failed to allocate an IPv6 lease in the subnet 2001:8b0:1f05::/64, subnet-id 1, shared network (none)",
			wantLine:   keaAllocFailLineSubnet,
			wantReason: "",
			wantExtra: map[string]string{
				"dhcp.duid":                 keaCapturedDUID,
				"dhcp.tid":                  "0x292a15",
				"dhcp.alloc_fail_subnet":    "2001:8b0:1f05::/64",
				"dhcp.alloc_fail_subnet_id": "1",
				"dhcp.kea_event":            keaEventAllocFail,
			},
		},
		{
			name:       "captured: NO_POOLS is the CAUSE line and the one that counts",
			message:    "WARN  [kea-dhcp6.alloc-engine.0x4b6ab5a79810] ALLOC_ENGINE_V6_ALLOC_FAIL_NO_POOLS duid=[" + keaCapturedDUID + "], [no hwaddr info], tid=0x292a15: no pools were available for the lease allocation",
			wantLine:   keaAllocFailLineNoPools,
			wantReason: keaAllocFailReasonNoPools,
		},
		{
			name:       "captured: CLASSES is supplementary detail, never counted",
			message:    "WARN  [kea-dhcp6.alloc-engine.0x4b6ab5a79810] ALLOC_ENGINE_V6_ALLOC_FAIL_CLASSES duid=[" + keaCapturedDUID + "], [no hwaddr info], tid=0x292a15: Failed to allocate an IPv6 address for client with classes: ALL, UNKNOWN",
			wantLine:   keaAllocFailLineClasses,
			wantReason: "",
			wantExtra:  map[string]string{"dhcp.alloc_fail_classes": "ALL, UNKNOWN"},
		},
		{
			name:       "from source: the bare ALLOC_FAIL is the OTHER cause line, and it counts",
			message:    "WARN  [kea-dhcp6.alloc-engine.0x4b6ab5a79810] ALLOC_ENGINE_V6_ALLOC_FAIL duid=[" + keaCapturedDUID + "], [no hwaddr info], tid=0x292a15: failed to allocate an IPv6 lease after 3 attempt(s)",
			wantLine:   keaAllocFailLineExhausted,
			wantReason: keaAllocFailReasonExhausted,
		},
		{
			name:       "from source: a shared-network client gets the shared-network scope line",
			message:    "WARN  [kea-dhcp6.alloc-engine.0x4b6ab5a79810] ALLOC_ENGINE_V6_ALLOC_FAIL_SHARED_NETWORK duid=[" + keaCapturedDUID + "], [no hwaddr info], tid=0x292a15: failed to allocate a lease in the shared network net1: 2 subnets have no available leases, 1 subnets have no matching pools",
			wantLine:   keaAllocFailLineSharedNetwork,
			wantReason: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, ok := parseDHCP(keaDHCP6Env(t, tt.message), nil, nil)
			if !ok {
				t.Fatal("parseDHCP() ok = false, want true")
			}
			if got := rec.Attributes["dhcp.alloc_fail_line"]; got != tt.wantLine {
				t.Errorf("dhcp.alloc_fail_line = %q, want %q", got, tt.wantLine)
			}
			if got := rec.Attributes["dhcp.alloc_fail_reason"]; got != tt.wantReason {
				t.Errorf("dhcp.alloc_fail_reason = %q, want %q", got, tt.wantReason)
			}
			for k, want := range tt.wantExtra {
				if got := rec.Attributes[k]; got != want {
					t.Errorf("attribute %s = %q, want %q", k, got, want)
				}
			}
		})
	}
}

// THE TRIPLE-COUNT. One failed allocation emits a burst of up to three lines
// sharing a tid. Counting all three would report three failures for one. Exactly
// ONE of ALLOC_FAIL_NO_POOLS / ALLOC_FAIL fires per failure (alloc_engine.cc's
// `if (total_attempts == 0)`), so the cause line is the honest failure count and the
// scope and classes lines are parsed but not counted.
func TestKeaDHCP6AllocFailBurstCountsExactlyOnce(t *testing.T) {
	burst := []string{
		"WARN  [kea-dhcp6.alloc-engine.0x4b6ab5a79810] ALLOC_ENGINE_V6_ALLOC_FAIL_SUBNET duid=[" + keaCapturedDUID + "], [no hwaddr info], tid=0x292a15: failed to allocate an IPv6 lease in the subnet 2001:8b0:1f05::/64, subnet-id 1, shared network (none)",
		"WARN  [kea-dhcp6.alloc-engine.0x4b6ab5a79810] ALLOC_ENGINE_V6_ALLOC_FAIL_NO_POOLS duid=[" + keaCapturedDUID + "], [no hwaddr info], tid=0x292a15: no pools were available for the lease allocation",
		"WARN  [kea-dhcp6.alloc-engine.0x4b6ab5a79810] ALLOC_ENGINE_V6_ALLOC_FAIL_CLASSES duid=[" + keaCapturedDUID + "], [no hwaddr info], tid=0x292a15: Failed to allocate an IPv6 address for client with classes: ALL, UNKNOWN",
	}

	sink := &fakeSink{}
	for _, msg := range burst {
		rec, ok := parseDHCP(keaDHCP6Env(t, msg), nil, nil)
		if !ok {
			t.Fatalf("parseDHCP(%q) ok = false - every line of the burst must still ship structured", msg)
		}
		observeDerived(sink, "kea-dhcp6", rec.Attributes)
	}

	assertCalls(t, sink.calls, []fakeCall{
		{"dhcp6_alloc_fail", []string{keaAllocFailReasonNoPools}},
	})
}

// The DUID, the transaction id and the subnet prefix are unbounded and/or
// client-identifying. None may ever reach a label.
func TestKeaDHCP6AllocFailIdentifiersAreNeverLabels(t *testing.T) {
	msg := "WARN  [kea-dhcp6.alloc-engine.0x4b6ab5a79810] ALLOC_ENGINE_V6_ALLOC_FAIL_NO_POOLS duid=[" + keaCapturedDUID + "], [no hwaddr info], tid=0x292a15: no pools were available for the lease allocation"
	rec, ok := parseDHCP(keaDHCP6Env(t, msg), nil, nil)
	if !ok {
		t.Fatal("parseDHCP() ok = false")
	}
	sink := &fakeSink{}
	observeDerived(sink, "kea-dhcp6", rec.Attributes)

	for _, call := range sink.calls {
		for _, arg := range call.args {
			for _, forbidden := range []string{keaCapturedDUID, "0x292a15", "2001:8b0:1f05::/64"} {
				if arg == forbidden {
					t.Errorf("%q reached a label on %s", arg, call.method)
				}
			}
		}
	}
	// The DUID still ships on the record, which is where an operator finds who.
	if rec.Attributes["dhcp.duid"] != keaCapturedDUID {
		t.Error("the DUID must still ship as a record attribute")
	}
}

// The Lease File Cleanup lines stay EXCLUDED, matching the pre-#546 behaviour. They
// are memfile housekeeping on a timer, not a lease event and not a failure, so they
// keep shipping as generic records and count nothing.
func TestKeaDHCP6LFCLinesStayUnmodelled(t *testing.T) {
	for _, msg := range []string{
		"INFO  [kea-dhcp6.dhcpsrv.0x4b6ab5a79810] DHCPSRV_MEMFILE_LFC_START starting Lease File Cleanup",
		"INFO  [kea-dhcp6.dhcpsrv.0x4b6ab5a79810] DHCPSRV_MEMFILE_LFC_EXECUTE executing Lease File Cleanup using: /usr/local/sbin/kea-lfc -6 -x /var/db/kea/kea-leases6.csv.2 -i /var/db/kea/kea-leases6.csv.1",
	} {
		t.Run(msg, func(t *testing.T) {
			env := keaDHCP6Env(t, msg)
			if _, ok := parseDHCP(env, nil, nil); ok {
				t.Errorf("parseDHCP() CLAIMED an LFC line: %q", msg)
			}
			sink := &fakeSink{}
			if observeDerived(sink, "kea-dhcp6", genericRecord(env).Attributes) {
				t.Errorf("observeDerived() counted an LFC line: %q", msg)
			}
		})
	}
}

// A DHCPv4 allocation failure must NOT reach the v6 counter. Kea spells the v4
// family ALLOC_ENGINE_V4_ALLOC_FAIL_*, so the v6 regex must be anchored on V6.
func TestKeaDHCP4AllocFailIsNotCountedAsV6(t *testing.T) {
	env, err := ParseEnvelope([]byte("<12>1 2026-07-30T09:00:00+01:00 test-firewall kea-dhcp4 63610 - - WARN  [kea-dhcp4.alloc-engine.0x1] ALLOC_ENGINE_V4_ALLOC_FAIL_NO_POOLS [hwtype=1 bc:24:11:a5:a6:34], cid=[no info], tid=0x1: no pools were available for the lease allocation"), time.Time{})
	if err != nil {
		t.Fatalf("ParseEnvelope() error = %v", err)
	}
	rec, ok := parseDHCP(env, nil, nil)
	if ok {
		if rec.Attributes["dhcp.alloc_fail_reason"] != "" {
			t.Fatalf("a V4 alloc failure set dhcp.alloc_fail_reason = %q", rec.Attributes["dhcp.alloc_fail_reason"])
		}
	}
	sink := &fakeSink{}
	observeDerived(sink, "kea-dhcp4", rec.Attributes)
	for _, call := range sink.calls {
		if call.method == "dhcp6_alloc_fail" {
			t.Error("a kea-dhcp4 line reached the DHCPv6 allocation-failure counter")
		}
	}
}

// A normal lease event must keep counting exactly as it did before #546: adding the
// alloc-fail branch must not disturb the existing dhcp family.
func TestKeaDHCP6LeaseEventStillCountsAfterAllocFail(t *testing.T) {
	msg := "INFO  [kea-dhcp6.leases.0x1] DHCP6_LEASE_ALLOC duid=[" + keaCapturedDUID + "], [no hwaddr info], tid=0xa492a1: lease for address 2001:8b0:1f05::1057 and iaid=0 has been allocated for 1800 seconds"
	rec, ok := parseDHCP(keaDHCP6Env(t, msg), nil, nil)
	if !ok {
		t.Fatal("parseDHCP() ok = false")
	}
	sink := &fakeSink{}
	if !observeDerived(sink, "kea-dhcp6", rec.Attributes) {
		t.Fatal("observeDerived() counted = false")
	}
	assertCalls(t, sink.calls, []fakeCall{{"dhcp", []string{"alloc", "", ""}}})
}
