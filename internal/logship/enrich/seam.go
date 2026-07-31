package enrich

import (
	"time"

	"github.com/rknightion/opnsense2otel/v4/internal/fetchshare"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

// The refresher's inputs that a metrics collector also fetches (#571). Before the
// seam, this package re-fetched every one of them on its own tickers, on top of the
// collector poll that had already decoded the same payload — 10,872 duplicate
// requests a day, each costing the firewall two configd RPCs and two audit lines
// whatever it returned (#535).
//
// Reading one of these from the seam is not "using a cache": nothing here ever
// short-circuits a Fetch*, and the collectors' poll cadence and exported metrics are
// untouched. It is this package declining to ask a second time for something already
// in memory. See the internal/fetchshare package comment.
const (
	seamOutcomeHit  = "hit"
	seamOutcomeMiss = "miss"
)

// SeamEndpoints is the closed set of endpoints this package will read from the
// seam — every value the `endpoint` label of logs_enrich_seam_reads_total can take.
// Exported so NewMetrics can pre-initialise the series, and asserted against the
// real call sites by TestSeamEndpointsMatchReadCallSites.
var SeamEndpoints = []string{
	string(fetchshare.KeyArpTable),
	string(fetchshare.KeyNDPTable),
	string(fetchshare.KeyKeaLeases4),
	string(fetchshare.KeyKeaLeases6),
	string(fetchshare.KeyDnsmasqLeases),
	string(fetchshare.KeyDHCPv4Leases),
	string(fetchshare.KeyDHCPv6Leases),
	string(fetchshare.KeyInterfacesOverview),
	string(fetchshare.KeyInterfaces),
	string(fetchshare.KeyIPsecPhase1),
	string(fetchshare.KeyOpenVPNInstances),
}

// seamOr returns the published result for key when the seam holds one younger than
// maxAge, and otherwise calls fetch — which is exactly what this package did before
// the seam existed, for every input, every time.
//
// Every failure mode lands on the fetch path with no special case: no seam wired, a
// collector disabled by flag, its poll failing, a plugin absent so the endpoint is
// never fetched by anyone, or a startup where no collector has polled yet. That is
// the property that makes this safe to sprinkle across the refresh functions — the
// worst case is the previous behaviour.
//
// maxAge is the caller's table TTL. See the freshness note on Refresher.seamMaxAge
// for what that costs and why it is the right bound.
func seamOr[T any](r *Refresher, key fetchshare.Key, maxAge time.Duration, fetch func() (T, *opnsense.APICallError)) (T, *opnsense.APICallError) {
	if v, ok := fetchshare.Fresh[T](r.seam, key, maxAge); ok {
		r.countSeamRead(key, seamOutcomeHit)
		return v, nil
	}
	r.countSeamRead(key, seamOutcomeMiss)
	return fetch()
}

// countSeamRead records the outcome of one seam read. Nil-metric-safe, because
// several tests build a Refresher without one.
func (r *Refresher) countSeamRead(key fetchshare.Key, outcome string) {
	if r == nil || r.m == nil || r.m.SeamReads == nil {
		return
	}
	r.m.SeamReads.WithLabelValues(string(key), outcome).Inc()
}
