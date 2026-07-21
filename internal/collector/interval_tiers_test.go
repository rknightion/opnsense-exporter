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
