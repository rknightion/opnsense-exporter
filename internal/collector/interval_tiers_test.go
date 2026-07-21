package collector

import (
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

// TestBodyCachedEndpointsPollSlowerThanTheirTTL is the guard the per-endpoint
// design needs: the response cache is keyed on the endpoint path, so it happily
// replays an hour-old body to a collector polling every 15 seconds. Nothing in the
// cache itself prevents that — this test does.
//
// Two rules per body-cached endpoint:
//   - its owning collector must not be on the fast tier. Fast means the data is
//     volatile enough to be worth 15s polls, which is the opposite of the
//     "wholly slow-moving payload" test a body TTL is supposed to pass.
//   - the TTL must exceed the owner's poll interval, or the cache can never serve
//     a hit and is pure overhead.
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
		if interval == IntervalFast {
			t.Errorf("endpoint %q is fetched by the fast-tier %q collector but carries a %v "+
				"body TTL: a collector polling every %v would replay the same cached payload "+
				"for %v, flat-lining the series", endpoint, owner, ttl, interval, ttl)
		}
		if ttl <= interval {
			t.Errorf("endpoint %q has a %v body TTL but %q polls every %v: the cache can "+
				"never serve a hit", endpoint, ttl, owner, interval)
		}
	}
}

// TestBodyCacheOwnersHaveNoStaleEntries keeps the owner table honest in the other
// direction: an endpoint whose TTL was removed must not linger here pretending to
// be cached.
func TestBodyCacheOwnersHaveNoStaleEntries(t *testing.T) {
	ttls := options.BodyCacheTTLs(options.DefaultCacheTTL, options.DefaultFirmwareCacheTTL)
	for endpoint := range bodyCacheOwners {
		if _, ok := ttls[endpoint]; !ok {
			t.Errorf("bodyCacheOwners lists %q, which no longer has a body TTL; drop it", endpoint)
		}
	}
}
