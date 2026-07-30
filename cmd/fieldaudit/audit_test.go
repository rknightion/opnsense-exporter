package main

import (
	"sort"
	"strings"
	"testing"
	"time"
)

// acceptanceFindings are fields found by hand (#544) that are unmarshalled from
// an OPNsense response and never read in production code. The audit must surface
// every one of them; they are the regression set for the analysis itself, quite
// apart from whether the ledger then exempts them.
var acceptanceFindings = []string{
	"opnsense.ndpEntry.Expire",
	"opnsense.hostDiscoveryRow.OrganizationName",
	"opnsense.InterfaceDetails.Driver",
	"opnsense.InterfaceDetails.HWOffloadCapabilities",
}

func auditOnce(t *testing.T) []Finding {
	t.Helper()
	_, findings := auditBoth(t)
	return findings
}

func auditBoth(t *testing.T) (map[string]bool, []Finding) {
	t.Helper()
	root, err := FindModuleRoot(".")
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}
	start := time.Now()
	all, findings, err := auditModule(root)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	t.Logf("audit checked %d json-tagged fields and produced %d findings in %s",
		len(all), len(findings), time.Since(start).Round(time.Millisecond))
	return all, findings
}

// TestAuditFindsKnownDeadFields pins the analysis itself: these were found by
// hand and a textual scan misses at least one of them (ndpEntry.Expire).
func TestAuditFindsKnownDeadFields(t *testing.T) {
	findings := auditOnce(t)
	got := map[string]bool{}
	for _, f := range findings {
		got[f.Key] = true
	}
	for _, want := range acceptanceFindings {
		if !got[want] {
			t.Errorf("audit did not flag %s, which is parsed and never read", want)
		}
	}
}

// liveFields are fields that ARE read in production, one per way the analysis
// could get it wrong: a plain selector read, a read of an envelope counter whose
// siblings are dead, a same-named field on a sibling type where the other copy IS
// dead (MacInfo is read on the Kea row and dead on the dnsmasq one), and two
// fields carried wholesale by a struct conversion rather than by name.
var liveFields = []string{
	"opnsense.ndpEntry.Intf",
	"opnsense.dhcpv4LeaseResponse.Total",
	"opnsense.hostDiscoveryRow.LastSeen",
	"opnsense.keaLeaseRow.MacInfo",
	"opnsense.firewallStatEntry.Label",
	"opnsense.ipsecPoolRow.Online",
}

// TestAuditIgnoresReadFields is the false-positive side of the gate. A checker
// that flags live fields gets exemptions written for data that is in fact
// exported, which is worse than no checker.
func TestAuditIgnoresReadFields(t *testing.T) {
	all, findings := auditBoth(t)
	got := map[string]bool{}
	for _, f := range findings {
		got[f.Key] = true
	}
	for _, live := range liveFields {
		if !all[live] {
			t.Errorf("%s is not a json-tagged field in package opnsense — fix the expectation, "+
				"it is not evidence of anything", live)
			continue
		}
		if got[live] {
			t.Errorf("audit flagged %s, which is read in production code", live)
		}
	}
}

// TestSearchGridEnvelopeIsExempted pins the #544 requirement that the bootgrid
// envelope fields are cleared by the ledger rather than by a special case in the
// checker — the checker has no notion of an envelope, and should not grow one.
func TestSearchGridEnvelopeIsExempted(t *testing.T) {
	for _, key := range []string{
		"opnsense.hostDiscoverySearchResponse.Total",
		"opnsense.hostDiscoverySearchResponse.RowCount",
		"opnsense.hostDiscoverySearchResponse.Current",
	} {
		if _, ok := Exemptions[key]; !ok {
			t.Errorf("%s should be cleared by an exemption, not by checker logic", key)
		}
	}
}

// TestNoUnexemptedDeadFields is the gate. A new collector that decodes a payload
// dimension and drops it fails here until it is either used or exempted with a
// written reason.
func TestNoUnexemptedDeadFields(t *testing.T) {
	findings := auditOnce(t)
	var unexempted []string
	for _, f := range findings {
		if _, ok := Exemptions[f.Key]; !ok {
			unexempted = append(unexempted, f.Key+" ("+f.Pos+", json:\""+f.JSONTag+"\")")
		}
	}
	sort.Strings(unexempted)
	if len(unexempted) > 0 {
		t.Errorf("%d struct field(s) are decoded from an OPNsense response but never read.\n"+
			"Either surface the data, or add an entry to Exemptions in cmd/fieldaudit/exemptions.go\n"+
			"with an honest reason (>%d chars):\n\t%s",
			len(unexempted), minReasonLen, strings.Join(unexempted, "\n\t"))
	}
}

// TestExemptionLedgerIsCurrent fails on a stale ledger: an entry naming a field
// that no longer exists, or one that is now read, has to go.
func TestExemptionLedgerIsCurrent(t *testing.T) {
	findings := auditOnce(t)
	live := map[string]bool{}
	for _, f := range findings {
		live[f.Key] = true
	}
	var stale []string
	for key := range Exemptions {
		if !live[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("%d stale exemption(s) — the field is gone, or is now read. Delete them:\n\t%s",
			len(stale), strings.Join(stale, "\n\t"))
	}
}

// TestExemptionReasonsAreWritten mirrors grafana/annotations.py's NOT_ANNOTATED
// gate: an exemption without a real reason is a silent deletion.
func TestExemptionReasonsAreWritten(t *testing.T) {
	for key, reason := range Exemptions {
		if len(strings.TrimSpace(reason)) <= minReasonLen {
			t.Errorf("exemption %s: reason %q is shorter than %d chars — say why the field is decoded and not read",
				key, reason, minReasonLen)
		}
	}
}
