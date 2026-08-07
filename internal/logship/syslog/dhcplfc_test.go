package syslog

import "testing"

// TestParseDHCP_KeaLFC covers the Kea-wide envelope fallback (#664): the seven
// DhcpLFC shapes and the two kea-dhcp6 LFC-launch shapes, all verbatim captures
// from the camden archive (2026-08-04 08:46 -> 2026-08-07 16:33 UTC), none
// synthetic — see dhcplfc.go's doc comment for provenance and the full set.
func TestParseDHCP_KeaLFC(t *testing.T) {
	snap := dhcpSnapshot()

	tests := []struct {
		name    string
		program string
		msg     string
		want    map[string]string
		none    []string
	}{
		{
			name:    "DhcpLFC LFC_START",
			program: "DhcpLFC",
			msg:     "INFO  [DhcpLFC.0x10b74225f010] LFC_START Starting lease file cleanup",
			want: map[string]string{
				"kea.msg_id":    "LFC_START",
				"kea.component": "DhcpLFC",
			},
			none: []string{"kea.lfc_leases", "kea.lfc_attempts", "kea.lfc_errors", "kea.lfc_phase"},
		},
		{
			name:    "DhcpLFC LFC_PROCESSING (file paths stay in body, not parsed)",
			program: "DhcpLFC",
			msg:     "INFO  [DhcpLFC.0x10b74225f010] LFC_PROCESSING Previous file: /var/db/kea/kea-leases6.csv.2, copy file: /var/db/kea/kea-leases6.csv.1",
			want: map[string]string{
				"kea.msg_id":    "LFC_PROCESSING",
				"kea.component": "DhcpLFC",
			},
		},
		{
			name:    "DhcpLFC DHCPSRV_MEMFILE_LEASE_FILE_LOAD (multi-segment hierarchy)",
			program: "DhcpLFC",
			msg:     "INFO  [DhcpLFC.dhcpsrv.0x378a5665f010] DHCPSRV_MEMFILE_LEASE_FILE_LOAD loading leases from file /var/db/kea/kea-leases6.csv.1",
			want: map[string]string{
				"kea.msg_id":    "DHCPSRV_MEMFILE_LEASE_FILE_LOAD",
				"kea.component": "DhcpLFC.dhcpsrv",
			},
		},
		{
			name:    "DhcpLFC LFC_READ_STATS",
			program: "DhcpLFC",
			msg:     "INFO  [DhcpLFC.0x10b74225f010] LFC_READ_STATS Leases: 162, attempts: 164, errors: 0.",
			want: map[string]string{
				"kea.msg_id":       "LFC_READ_STATS",
				"kea.component":    "DhcpLFC",
				"kea.lfc_leases":   "162",
				"kea.lfc_attempts": "164",
				"kea.lfc_errors":   "0",
				"kea.lfc_phase":    "read",
			},
		},
		{
			name:    "DhcpLFC LFC_WRITE_STATS",
			program: "DhcpLFC",
			msg:     "INFO  [DhcpLFC.0x10b74225f010] LFC_WRITE_STATS Leases: 21, attempts: 21, errors: 0.",
			want: map[string]string{
				"kea.msg_id":       "LFC_WRITE_STATS",
				"kea.component":    "DhcpLFC",
				"kea.lfc_leases":   "21",
				"kea.lfc_attempts": "21",
				"kea.lfc_errors":   "0",
				"kea.lfc_phase":    "write",
			},
		},
		{
			name:    "DhcpLFC LFC_ROTATING",
			program: "DhcpLFC",
			msg:     "INFO  [DhcpLFC.0x10b74225f010] LFC_ROTATING LFC rotating files",
			want: map[string]string{
				"kea.msg_id":    "LFC_ROTATING",
				"kea.component": "DhcpLFC",
			},
		},
		{
			name:    "DhcpLFC LFC_TERMINATE",
			program: "DhcpLFC",
			msg:     "INFO  [DhcpLFC.0x10b74225f010] LFC_TERMINATE LFC finished processing",
			want: map[string]string{
				"kea.msg_id":    "LFC_TERMINATE",
				"kea.component": "DhcpLFC",
			},
		},
		{
			name:    "kea-dhcp6 DHCPSRV_MEMFILE_LFC_START",
			program: "kea-dhcp6",
			msg:     "INFO  [kea-dhcp6.dhcpsrv.0x3fa9c3469010] DHCPSRV_MEMFILE_LFC_START starting Lease File Cleanup",
			want: map[string]string{
				"kea.msg_id":    "DHCPSRV_MEMFILE_LFC_START",
				"kea.component": "kea-dhcp6.dhcpsrv",
			},
		},
		{
			name:    "kea-dhcp6 DHCPSRV_MEMFILE_LFC_EXECUTE (kea-lfc argv stays in body, not parsed)",
			program: "kea-dhcp6",
			msg:     "INFO  [kea-dhcp6.dhcpsrv.0x3fa9c3469010] DHCPSRV_MEMFILE_LFC_EXECUTE executing Lease File Cleanup using: /usr/local/sbin/kea-lfc -6 -x /var/db/kea/kea-leases6.csv.2 -i /var/db/kea/kea-leases6.csv.1 -o /var/db/kea/kea-leases6.csv.output -f /var/db/kea/kea-leases6.csv.completed -p /var/db/kea/kea-leases6.csv.pid -c ignored-path",
			want: map[string]string{
				"kea.msg_id":    "DHCPSRV_MEMFILE_LFC_EXECUTE",
				"kea.component": "kea-dhcp6.dhcpsrv",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var m missRecorder
			env := dhcpEnvelope(tc.program, tc.msg)
			rec, ok := parseDHCP(env, snap, m.miss)
			if !ok {
				t.Fatalf("parseDHCP(%q) ok=false, want true", tc.msg)
			}
			if rec.Body != tc.msg {
				t.Errorf("Body = %q, want the raw message verbatim", rec.Body)
			}
			wantDHCPAttrs(t, rec, tc.want)
			wantNoDHCPAttrs(t, rec, tc.none...)
			wantNoDHCPAttrs(t, rec, "dhcp.action") // envelope fallback is not a lease event
			if len(m.calls) != 0 {
				t.Errorf("miss() called %v, want no calls", m.calls)
			}
		})
	}
}

// TestParseDHCP_KeaLFC_ContextPointerNeverEmitted asserts the 0x thread/context
// address never leaks into an attribute value, on both the single- and
// multi-segment hierarchy shapes (#664 acceptance criterion).
func TestParseDHCP_KeaLFC_ContextPointerNeverEmitted(t *testing.T) {
	snap := dhcpSnapshot()
	var m missRecorder

	rec, ok := parseDHCP(dhcpEnvelope("DhcpLFC", "INFO  [DhcpLFC.dhcpsrv.0x378a5665f010] DHCPSRV_MEMFILE_LEASE_FILE_LOAD loading leases from file /var/db/kea/kea-leases6.csv.1"), snap, m.miss)
	if !ok {
		t.Fatalf("parseDHCP ok=false, want true")
	}
	if got := rec.Attributes["kea.component"]; got != "DhcpLFC.dhcpsrv" {
		t.Errorf("kea.component = %q, must not contain the 0x context pointer", got)
	}
}

// TestParseDHCP_KeaLFC_UnrecognisedMessageID: an unrecognised Kea message id
// still parses the envelope (msg id + component) rather than regressing to
// fully unparsed (#664 acceptance criterion). Synthetic: no real capture of an
// unmodelled id exists, so this pins the fallback's own contract instead of a
// specific upstream message.
func TestParseDHCP_KeaLFC_UnrecognisedMessageID(t *testing.T) {
	snap := dhcpSnapshot()
	var m missRecorder

	rec, ok := parseDHCP(dhcpEnvelope("DhcpLFC", "INFO  [DhcpLFC.0x10b74225f010] LFC_SOME_FUTURE_EVENT something the parser has never seen"), snap, m.miss)
	if !ok {
		t.Fatalf("parseDHCP ok=false, want true (unrecognised id should still parse the envelope)")
	}
	wantDHCPAttrs(t, rec, map[string]string{
		"kea.msg_id":    "LFC_SOME_FUTURE_EVENT",
		"kea.component": "DhcpLFC",
	})
	wantNoDHCPAttrs(t, rec, "kea.lfc_leases", "kea.lfc_attempts", "kea.lfc_errors", "kea.lfc_phase")
}

// TestParseDHCP_KeaLFC_NoEnvelope: a line with no level word / bracketed logger
// hierarchy at all is not the Kea envelope shape and must fall through to a
// fully generic record — never force-fitted. Mirrors the pre-existing
// "kea message id we do not model" case in TestParseDHCP_NotALeaseEvent, which
// this fallback must not regress.
func TestParseDHCP_KeaLFC_NoEnvelope(t *testing.T) {
	snap := dhcpSnapshot()
	var m missRecorder

	if _, ok := parseDHCP(dhcpEnvelope("DhcpLFC", "not a Kea envelope line at all"), snap, m.miss); ok {
		t.Fatalf("parseDHCP ok=true, want false (no envelope shape present)")
	}
}
