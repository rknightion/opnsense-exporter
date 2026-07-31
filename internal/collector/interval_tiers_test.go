package collector

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/opnsense2otel/v4/internal/options"
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

// fastTierMembers pins the shipped fast-tier membership as settled by the #569
// audit. The fast tier is the only one where being wrong is expensive (5,760 polls
// per collector per day, two configd RPCs and two audit lines each, #535), so a
// collector must not drift into or out of it as a side effect of another change:
// adding or removing a name here is the deliberate act of applying the admission
// rule written above collectorTiers, and it comes with the per-collector clause
// annotation that rule demands.
//
// log_events and flow were promoted by #569. Both make no API call at all — their
// receivers fill an in-memory store out of band, exactly as cpu does — so the cost
// paragraph is cleared outright and clause (c) decides them on their rate-shaped
// dashboard panels.
var fastTierMembers = map[string]bool{
	GatewaysSubsystem:   true,
	InterfacesSubsystem: true,
	ProtocolSubsystem:   true,
	PFStatsSubsystem:    true,
	NetflowSubsystem:    true,
	CARPSubsystem:       true,
	CPUSubsystem:        true,
	LogEventsSubsystem:  true,
	FlowSubsystem:       true,
}

func TestFastTierMembershipIsDeliberate(t *testing.T) {
	got := map[string]bool{}
	for name, d := range collectorTiers {
		if d == IntervalFast {
			got[name] = true
		}
	}
	for name := range got {
		if !fastTierMembers[name] {
			t.Errorf("collector %q is on the fast tier but is not listed in fastTierMembers: "+
				"apply the admission rule above collectorTiers, annotate the entry with the "+
				"clause that admits it, and add it here", name)
		}
	}
	for name := range fastTierMembers {
		if !got[name] {
			t.Errorf("fastTierMembers lists %q but collectorTiers no longer puts it on the fast "+
				"tier; record the demotion and drop it here", name)
		}
	}
}

// TestZeroCostFastTierMembersStayInTheTable guards the three fast-tier collectors
// that issue no API request (cpu #559, log_events and flow #569). They are admitted
// on freshness alone precisely because their firewall cost is zero; if one of them
// ever gains a Fetch call the cost paragraph starts applying to it and the tier has
// to be re-argued. Pinning them by name keeps that re-argument from being skipped.
func TestZeroCostFastTierMembersStayInTheTable(t *testing.T) {
	for _, name := range []string{CPUSubsystem, LogEventsSubsystem, FlowSubsystem} {
		if collectorTiers[name] != IntervalFast {
			t.Errorf("collector %q should be on the fast tier (it makes no API call, so the "+
				"cost paragraph is cleared outright), got %v", name, collectorTiers[name])
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
	// #574: pure-config GETs that postdate (or fell through) #194's survey. All are
	// fetched by medium-tier collectors, so rule 1 holds against the 30m default with
	// room to spare, and none is fast-tier so no written justification is required.
	"idsSettings":                   IDSSubsystem,
	"idsRulesets":                   IDSSubsystem,
	"keaSubnets4":                   KeaSubsystem,
	"keaSubnets6":                   KeaSubsystem,
	"keaPdPools6":                   KeaSubsystem,
	"dnsmasqRanges":                 DnsmasqSubsystem,
	"captivePortalVoucherProviders": CaptivePortalSubsystem,
	// The first fast-tier body caches (#572, #573). Both owners are on the 15s tier,
	// so each also needs a written entry in fastTierBodyCacheJustifications below —
	// the owner entry alone does not admit them.
	"netflowGetConfig":   NetflowSubsystem,
	"netflowIsEnabled":   NetflowSubsystem,
	"interfacesOverview": InterfacesSubsystem,
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
// #567 left this map empty on purpose and named the follow-ups; #572 and #573 are
// those follow-ups, and their entries are the first three. Each states the
// DEGRADATION, not just the claim that the payload is static — what actually gets
// worse, and by how much, is the thing a reviewer needs to weigh.
var fastTierBodyCacheJustifications = map[string]string{
	// #572. Pure config: the configured capture interface set. #550 measured it
	// byte-identical (1,080 B) across its whole window. Degradation: an admin adding
	// or removing a capture interface takes up to one cache-ttl to appear in
	// opnsense_netflow_capture_enabled. No alert or recording rule reads any
	// capture-config series. The collector's LIVE half (netflowStatus run-state,
	// netflowCacheStats counters — the series OPNsenseNetFlowHookDead evaluates)
	// stays uncached at 15s, so the tier keeps doing the job it was admitted for.
	"netflowGetConfig": "config-only payload (configured capture interface set), byte-identical over #550's " +
		"whole measurement window; changes only on an admin edit. Degradation: an interface added to or " +
		"removed from the capture set surfaces up to one cache-ttl late. No alert or recording rule reads " +
		"any capture-config series; netflowStatus and netflowCacheStats stay uncached at 15s.",
	// #572. 23 bytes, and it still pays the full #535 request tax every 15s — the
	// cost paragraph in collectorTiers calls this endpoint out by name.
	"netflowIsEnabled": "config-only payload (the netflow enabled and local-capture flags), 23 bytes that still " +
		"pay the full two-configd-RPC request tax 5,760 times a day. Changes only when an admin toggles the " +
		"feature. Degradation: opnsense_netflow_enabled reflects a toggle up to one cache-ttl late; nothing " +
		"alerts on it, and the series itself never disappears.",
	// #573. The one entry here that is NOT purely config, which is why its TTL is
	// 60s rather than the global one.
	"interfacesOverview": "mostly config (admin_up, media/VLAN identity, LAGG and bridge membership), plus two " +
		"live-ish members held at medium-tier cadence by a 60s TTL rather than the global one: lagg_flapping_total " +
		"becomes a step function with <=60s detection lag (the counter TOTAL stays exact — under #336 the snapshot " +
		"is replayed at collection cadence, so under-polling costs detection lag, not rate() samples), and the SFP " +
		"DOM readings (temperature, voltage, optical power, TX bias) update every 60s instead of 15s. None of those " +
		"is read at sub-minute resolution by any panel or rule. Critically this does NOT touch the #568 clause (c) " +
		"case that admits the collector: RX/TX bps and pps come from the uncached 'interfaces' and " +
		"'interfaceStatistics' endpoints, as does link_state, so link up/down detection and throughput fidelity " +
		"are unchanged. Only the two recording rules instance:opnsense_interface_{rx,tx}_bits:rate5m read this " +
		"subsystem at all, and they read the traffic endpoints.",
}

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

// TestInterfaceThroughputEndpointsAreNeverCached pins the distinction #573 rests
// on. The interfaces collector is on the 15s tier under #568 clause (c) —
// dashboard THROUGHPUT fidelity, the RX/TX bps and pps graphs — and #573 caches
// one of its three endpoints. That is only sound because the throughput series do
// not come from the cached one: rx/tx bytes and packets come from
// "interfaceStatistics", and link_state and line_rate from "interfaces", both of
// which must stay uncached at 15s.
//
// Without this, a later change could attach a TTL to either and silently flat-line
// the exact panels the collector's fast tier is paid for, with every other guard
// still green: bodyCacheOwners would take a written entry, and a plausible-sounding
// justification would satisfy fastTierBodyCacheJustifications. Freezing throughput
// is not a freshness tradeoff to weigh — it is the thing the tier exists to prevent
// — so this is a flat prohibition rather than another justification slot.
func TestInterfaceThroughputEndpointsAreNeverCached(t *testing.T) {
	// Probe with generous knobs, not the shipped defaults: a future default of 0
	// must not hide a TTL added here.
	ttls := options.BodyCacheTTLs(time.Hour, 12*time.Hour)

	for _, endpoint := range []string{"interfaces", "interfaceStatistics"} {
		if ttl, cached := ttls[endpoint]; cached {
			t.Errorf("endpoint %q carries a %v body TTL. It is the source of the interfaces "+
				"collector's throughput and link-state series, which is the entire #568 clause (c) case "+
				"for its 15s tier — caching it turns those panels into step functions while every other "+
				"guard stays green. Cache interfacesOverview (the config+DOM payload) instead; that is "+
				"what #573 did.", endpoint, ttl)
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
