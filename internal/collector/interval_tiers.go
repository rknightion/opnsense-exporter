package collector

import "time"

// Data-volatility tiers for the internal poll scheduler (#336). Each sub-collector
// polls the OPNsense API on its own timer rather than on the Prometheus scrape; the
// tier a collector declares (via PollInterval) reflects how fast its data actually
// changes, so we neither under-sample volatile series (gateways, traffic, pf) nor
// hammer the firewall for near-static ones (firmware, certificates, SMART).
//
// The ceiling is deliberately 15m: polling slower than that leaves Grafana with
// sparse, flat-plateau series that read as gaps. The floor guards the firewall from
// an operator setting an abusive interval.
const (
	// IntervalFast suits volatile, per-second-ish data (gateways, traffic, pf_stats).
	IntervalFast = 15 * time.Second
	// IntervalMedium is the global default when a collector declares no tier.
	IntervalMedium = 60 * time.Second
	// IntervalSlow suits data that drifts over minutes (services, wireguard, dhcp).
	IntervalSlow = 5 * time.Minute
	// IntervalCold suits near-static data (firmware, certificates, SMART, acme).
	IntervalCold = 15 * time.Minute

	// IntervalFloor is the hard minimum for any poll interval.
	IntervalFloor = 5 * time.Second
	// IntervalCeil is the hard maximum for any poll interval (see the 15m rationale above).
	IntervalCeil = 15 * time.Minute
)

// IntervalCollector is an optional interface a CollectorInstance may implement to
// declare its default poll interval (its data-volatility tier). A collector that
// does not implement it polls at the scheduler's global default. The declared value
// is always clamped to [IntervalFloor, IntervalCeil].
type IntervalCollector interface {
	CollectorInstance
	PollInterval() time.Duration
}

// clampInterval bounds d to [IntervalFloor, IntervalCeil]. A non-positive d (an
// unset/zero declaration) is treated as "no preference" and returns the floor's
// caller default instead; callers pass their own default explicitly, so clampInterval
// only enforces the hard bounds.
func clampInterval(d time.Duration) time.Duration {
	if d < IntervalFloor {
		return IntervalFloor
	}
	if d > IntervalCeil {
		return IntervalCeil
	}
	return d
}

// resolvePollInterval returns the effective poll interval for a collector: its
// declared tier (clamped) if it implements IntervalCollector, otherwise the supplied
// global default (clamped).
func resolvePollInterval(coll CollectorInstance, global time.Duration) time.Duration {
	if ic, ok := coll.(IntervalCollector); ok {
		if d := ic.PollInterval(); d > 0 {
			return clampInterval(d)
		}
	}
	return clampInterval(global)
}
