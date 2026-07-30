package collector

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/options"
)

// TestBodyCacheDefaultsOutliveThePollCeiling pins the reason the per-endpoint
// response-body cache survives the poll scheduler (#338, follow-on to #336).
//
// Since #336 an endpoint is fetched by its collector's poll timer, not by the
// Prometheus scrape — so a body TTL is only useful when it outlives that timer. The
// scheduler clamps every interval, tier or operator override, to at most
// IntervalCeil, which makes the ceiling the strongest general bound: a default at or
// below it could never serve a hit for the slowest-polling collector and would be
// pure overhead. That is exactly the "the response cache is now redundant"
// hypothesis, and this test is what keeps it answered.
//
// The one deliberate exception is options' ruleIDsCacheTTL (1m), which is not on a
// collector's poll timer at all: it absorbs bursts of unknown-rule-id lookups from
// the syslog enrichment refresher (#248), where a long TTL would keep replaying a
// stale rule map.
func TestBodyCacheDefaultsOutliveThePollCeiling(t *testing.T) {
	for name, ttl := range map[string]time.Duration{
		"--exporter.cache-ttl":          options.DefaultCacheTTL,
		"--exporter.firmware-cache-ttl": options.DefaultFirmwareCacheTTL,
	} {
		if ttl <= IntervalCeil {
			t.Errorf("%s default is %v, which is not longer than the %v poll ceiling: "+
				"the cache could never serve a hit for a collector polling at the ceiling",
				name, ttl, IntervalCeil)
		}
	}
}

// notPolled marks a body-cached endpoint that no collector poll timer fetches.
const notPolled = "<not fetched by a polled collector>"

// bodyCacheOwners names the collector whose poll pays for each body-cached
// endpoint. Hand-maintained on purpose: the response cache is keyed per ENDPOINT
// and knows nothing about poll intervals, so attaching a TTL is the one place a
// slow cache could be pinned onto fast-moving data. Adding a body TTL without an
// entry here fails TestBodyCachedEndpointsPollSlowerThanTheirTTL, which forces the
// author to say which collector fetches it and at what tier.
var bodyCacheOwners = map[string]string{
	"firmware":                 FirmwareSubsystem,
	"firmwareInfo":             FirmwareSubsystem,
	"cpuType":                  SystemSubsystem,
	"systemInformation":        SystemSubsystem,
	"dmidecodeInfo":            HardwareSubsystem,
	"certificates":             CertificatesSubsystem,
	"caCertificates":           CertificatesSubsystem,
	"acmeCertificates":         ACMESubsystem,
	"unboundBlocklistPolicies": UnboundDNSSubsystem,
	"unboundLocalZones":        UnboundDNSSubsystem,
	"unboundLocalData":         UnboundDNSSubsystem,
	"unboundInsecureDomains":   UnboundDNSSubsystem,
	"backupHistory":            BackupSubsystem,
	"snapshotsSearch":          SnapshotsSubsystem,
	"snapshotsIsSupported":     SnapshotsSubsystem,
	"clamavVersion":            ClamAVSubsystem,
	"crowdsecVersion":          CrowdSecSubsystem,
	"torHiddenServices":        TorSubsystem,
	"authUsers":                AuthSubsystem,
	"authAPIKeys":              AuthSubsystem,
	"authGroups":               AuthSubsystem,
	"firewallGeoIP":            FirewallSubsystem,
	"natSourceNATRules":        FirewallSubsystem,
	"natDNATRules":             FirewallSubsystem,
	"natOneToOneRules":         FirewallSubsystem,
	"natNPTRules":              FirewallSubsystem,
	// The rule-id map is fetched by the syslog enrichment refresher (#248) when a
	// filterlog line carries an unknown rid, never by a poll timer — which is why
	// its TTL is deliberately capped at a minute rather than the full cache-ttl.
	"firewallRuleIDs": notPolled,
}

// minFastTierJustificationLen is the floor on a fast-tier body-cache
// justification's written reason, mirroring cmd/fieldaudit's minReasonLen and
// grafana/annotations.py's NOT_ANNOTATED gate: a justification with no real
// sentence behind it is a silent re-opening of the blanket tier ban this table
// replaces (#567).
const minFastTierJustificationLen = 20

// fastTierBodyCacheJustifications is the per-endpoint opt-out from the fast-tier
// body-cache ban (#567, decision B on #550). The original rule 2 in
// TestBodyCachedEndpointsPollSlowerThanTheirTTL was a blanket ban: ANY endpoint
// owned by a fast-tier collector was rejected outright, even though #344's
// promise — "the tier follows the collector's live half, the body cache handles
// its static half" — is honoured for every OTHER tier. A tier is assigned per
// collector, but a body TTL is attached per endpoint, so a fast-tier collector can
// still fetch one genuinely static endpoint alongside its volatile ones.
//
// An entry here does not disable the check — it moves the review from "the tier
// forbids it" to "someone wrote down why this specific payload cannot go stale in
// a way that matters" (mirroring cmd/fieldaudit's Exemptions ledger). Every
// endpoint absent from this map — which today is all of them — keeps the original
// behaviour: a fast-tier owner with a body TTL fails
// TestBodyCachedEndpointsPollSlowerThanTheirTTL. Rule 1 (ttl > poll interval)
// still applies unconditionally on top of this map — a justification never
// excuses a TTL that can never serve a hit.
//
// This issue deliberately does not attach a TTL to any fast-tier endpoint (e.g.
// netflow's static endpoints, #550/#567's motivating example); that is a
// follow-up with its own freshness argument to make per endpoint, so this map
// starts empty.
var fastTierBodyCacheJustifications = map[string]string{}

// bodyCacheRuleViolations checks the two rules for one body-cached endpoint's TTL
// against its owner's poll interval:
//   - the fast-tier justification rule: if the owner is on the fast tier, a
//     written, non-trivial justification must be recorded for the endpoint (in
//     fastTierBodyCacheJustifications), or the TTL is rejected outright exactly as
//     before #567.
//   - rule 1: the TTL must exceed the owner's poll interval, or the cache can
//     never serve a hit and is pure overhead. This applies unconditionally,
//     including to a fast-tier endpoint with a valid justification.
//
// Extracted from TestBodyCachedEndpointsPollSlowerThanTheirTTL so both the real
// tables and the synthetic cases below exercise identical logic.
func bodyCacheRuleViolations(endpoint, owner string, ttl, interval time.Duration, justification string) []string {
	var errs []string
	if interval == IntervalFast && len(strings.TrimSpace(justification)) <= minFastTierJustificationLen {
		errs = append(errs, fmt.Sprintf("endpoint %q is fetched by the fast-tier %q collector but carries a "+
			"%v body TTL with no written justification in fastTierBodyCacheJustifications (or one no longer "+
			"than %d chars): say why this specific payload cannot go stale in a way that matters, or drop "+
			"the TTL", endpoint, owner, ttl, minFastTierJustificationLen))
	}
	if ttl <= interval {
		errs = append(errs, fmt.Sprintf("endpoint %q has a %v body TTL but %q polls every %v: the cache can "+
			"never serve a hit", endpoint, ttl, owner, interval))
	}
	return errs
}

// TestBodyCachedEndpointsPollSlowerThanTheirTTL is the guard the per-endpoint
// design needs: the response cache is keyed on the endpoint path, so it happily
// replays an hour-old body to a collector polling every 15 seconds. Nothing in the
// cache itself prevents that — this test does, via bodyCacheRuleViolations.
func TestBodyCachedEndpointsPollSlowerThanTheirTTL(t *testing.T) {
	ttls := options.BodyCacheTTLs(options.DefaultCacheTTL, options.DefaultFirmwareCacheTTL)
	if len(ttls) == 0 {
		t.Fatal("BodyCacheTTLs returned nothing; the defaults should populate it")
	}

	for endpoint, ttl := range ttls {
		owner, ok := bodyCacheOwners[endpoint]
		if !ok {
			t.Errorf("endpoint %q has a %v body TTL but no entry in bodyCacheOwners: "+
				"name the collector that fetches it (or %q) and confirm its payload is "+
				"wholly slow-moving", endpoint, ttl, notPolled)
			continue
		}
		if owner == notPolled {
			continue
		}

		interval, tiered := collectorTiers[owner]
		if !tiered {
			interval = IntervalMedium
		}
		for _, msg := range bodyCacheRuleViolations(endpoint, owner, ttl, interval, fastTierBodyCacheJustifications[endpoint]) {
			t.Error(msg)
		}
	}
}

// TestBodyCacheRuleViolations_FastTierRequiresJustification is a synthetic,
// table-driven proof of the fast-tier opt-out gate (#567 acceptance items 1+2):
// bodyCacheRuleViolations must reject a fast-tier endpoint with no justification,
// or one that is empty/whitespace/too short, and must accept one with a real
// written reason. The production tables (bodyCacheOwners,
// fastTierBodyCacheJustifications) currently have no fast-tier entry at all, so
// this exercises the logic directly rather than via real data.
func TestBodyCacheRuleViolations_FastTierRequiresJustification(t *testing.T) {
	cases := []struct {
		name          string
		justification string
		wantViolation bool
	}{
		{"missing justification", "", true},
		{"whitespace-only justification", "   \t  ", true},
		{"too-short justification", "static payload", true},
		{"written justification", "this payload is generated once at boot and never changes again in the box's lifetime", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// ttl (1h) > interval (IntervalFast) so rule 1 never fires here — this
			// isolates the justification rule.
			violations := bodyCacheRuleViolations("fakeEndpoint", "fakeFastCollector", time.Hour, IntervalFast, tc.justification)
			got := false
			for _, v := range violations {
				if strings.Contains(v, "justification") {
					got = true
				}
			}
			if got != tc.wantViolation {
				t.Errorf("justification %q: got violation=%v, want %v (violations: %v)",
					tc.justification, got, tc.wantViolation, violations)
			}
		})
	}
}

// TestBodyCacheRuleViolations_TTLRuleAppliesEvenWithJustification proves
// acceptance item 3: rule 1 (ttl > poll interval) is unconditional, including for
// a fast-tier endpoint carrying an otherwise-valid justification. A justification
// says the payload cannot go stale in a way that matters — it never claims the
// cache can serve a hit against a TTL shorter than the poll interval.
func TestBodyCacheRuleViolations_TTLRuleAppliesEvenWithJustification(t *testing.T) {
	justification := "this payload is generated once at boot and never changes again in the box's lifetime"
	violations := bodyCacheRuleViolations("fakeEndpoint", "fakeFastCollector", 5*time.Second, IntervalFast, justification)
	found := false
	for _, v := range violations {
		if strings.Contains(v, "can never serve a hit") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a rule-1 (ttl <= interval) violation even with a valid justification, got: %v", violations)
	}
}

// staleEndpoints returns the keys of entries that no longer appear in ttls, used
// to keep both bodyCacheOwners and fastTierBodyCacheJustifications honest: an
// endpoint whose TTL was removed must not linger in either table pretending to
// still be cached.
func staleEndpoints(entries map[string]string, ttls map[string]time.Duration) []string {
	var stale []string
	for endpoint := range entries {
		if _, ok := ttls[endpoint]; !ok {
			stale = append(stale, endpoint)
		}
	}
	return stale
}

// TestStaleEndpointsDetectsRemovedTTL is a synthetic proof of acceptance item 4:
// an entry whose endpoint no longer carries a TTL must be flagged, whichever
// table it lives in. The real fastTierBodyCacheJustifications map is empty today,
// so this exercises staleEndpoints directly rather than via live data.
func TestStaleEndpointsDetectsRemovedTTL(t *testing.T) {
	entries := map[string]string{
		"stillCached": "owner-or-justification",
		"longGone":    "a justification that used to apply before the TTL was removed",
	}
	ttls := map[string]time.Duration{"stillCached": time.Minute}

	stale := staleEndpoints(entries, ttls)
	if len(stale) != 1 || stale[0] != "longGone" {
		t.Fatalf("staleEndpoints(entries, ttls) = %v, want exactly [longGone]", stale)
	}
}

// TestFastTierBodyCacheJustificationsAreWritten mirrors
// cmd/fieldaudit's TestExemptionReasonsAreWritten: a recorded justification with
// no real sentence behind it is a silent re-opening of the tier ban.
func TestFastTierBodyCacheJustificationsAreWritten(t *testing.T) {
	for endpoint, justification := range fastTierBodyCacheJustifications {
		if len(strings.TrimSpace(justification)) <= minFastTierJustificationLen {
			t.Errorf("fastTierBodyCacheJustifications[%q]: justification %q is shorter than %d chars — "+
				"say why this specific payload cannot go stale in a way that matters",
				endpoint, justification, minFastTierJustificationLen)
		}
	}
}

// TestBodyCacheOwnersHaveNoStaleEntries keeps both tables honest in the other
// direction: an endpoint whose TTL was removed must not linger in bodyCacheOwners
// or fastTierBodyCacheJustifications pretending to be cached.
func TestBodyCacheOwnersHaveNoStaleEntries(t *testing.T) {
	ttls := options.BodyCacheTTLs(options.DefaultCacheTTL, options.DefaultFirmwareCacheTTL)
	for _, endpoint := range staleEndpoints(bodyCacheOwners, ttls) {
		t.Errorf("bodyCacheOwners lists %q, which no longer has a body TTL; drop it", endpoint)
	}
	for _, endpoint := range staleEndpoints(fastTierBodyCacheJustifications, ttls) {
		t.Errorf("fastTierBodyCacheJustifications lists %q, which no longer has a body TTL; drop it", endpoint)
	}
}
