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

// collectorTiers assigns each collector a poll tier by data volatility (#336).
// Only deviations from the medium (global-default) tier are listed; every collector
// absent from this table polls at the global default (--collector.poll-interval, 60s).
// A per-collector --collector.poll-interval-override always wins over this table.
//
// Rationale by tier:
//   - fast: per-second-ish live counters/states where freshness is alerting-critical
//     (gateway RTT/loss, interface + protocol + pf counters, netflow, CARP failover
//     state).
//   - slow: data that drifts over minutes, or is comparatively expensive to fetch
//     (rule hit-counters, alias table contents, NTP/chrony peers, dyndns/qfeeds status,
//     shaper pipes, siproxd registrations, tor circuits, LLDP neighbours).
//   - cold: near-static inventory/health (firmware, certificates, ACME, SMART, cron,
//     snapshots, vnstat's aggregated history, local auth inventory, config-backup
//     history, ClamAV signature-database version).
//
// A collector belongs in cold when its data changes only on an admin action, NOT
// merely because its endpoint carries a body cache TTL: the tier must state the
// volatility on its own, so the poll stays sane at --exporter.cache-ttl=0. Where a
// collector mixes live and static endpoints in one poll (firewall, unbound_dns,
// hardware, system, crowdsec, tor), the tier follows the LIVE half and the body
// cache handles the static endpoints — a per-collector interval cannot split them
// (#344).
//
// The activity collector is deliberately ABSENT from this table (medium, #559). It
// was fast, at a measured 2.15 s of firewall work per call — a permanent 14% duty
// cycle at 15s — for CPU percentages that now come from the cpu_usage SSE stream
// instead. What is left is thread-state counts: instantaneous gauges with no
// sub-minute alerting story, where 60s loses nothing.
var collectorTiers = map[string]time.Duration{
	// fast (15s)
	GatewaysSubsystem:   IntervalFast,
	InterfacesSubsystem: IntervalFast,
	ProtocolSubsystem:   IntervalFast,
	PFStatsSubsystem:    IntervalFast,
	NetflowSubsystem:    IntervalFast,
	CARPSubsystem:       IntervalFast,
	// The one fast-tier collector that costs the firewall NOTHING: it makes no API
	// call at all, reading an accumulator the cpu_usage SSE stream fills out of band
	// (#559). Fast so that an operator running --otlp.fast-export-interval gets 15s
	// CPU resolution for free, and so a stalled stream shows up in
	// cpu_stream_last_frame_age_seconds within 15s rather than 60s. Under #550's lane
	// clamp this still resolves to 60s when no fast lane is configured, so the
	// default deployment gains nothing to pay for.
	CPUSubsystem: IntervalFast,
	// slow (5m)
	FirewallRulesSubsystem: IntervalSlow,
	AliasSubsystem:         IntervalSlow,
	NTPSubsystem:           IntervalSlow,
	DynDNSSubsystem:        IntervalSlow,
	QFeedsSubsystem:        IntervalSlow,
	TrafficShaperSubsystem: IntervalSlow,
	SiproxdSubsystem:       IntervalSlow,
	TorSubsystem:           IntervalSlow,
	ChronySubsystem:        IntervalSlow,
	LLDPSubsystem:          IntervalSlow,
	// Zone occupancy drifts over minutes, and the failure/sleep counters are
	// cumulative since boot, so a 5m sample loses nothing an alert needs. Slow is
	// also what makes the collector affordable enough to ship default-ON: one extra
	// GET every five minutes rather than one per scrape.
	KernelMemorySubsystem: IntervalSlow,
	// cold (15m)
	FirmwareSubsystem:     IntervalCold,
	CertificatesSubsystem: IntervalCold,
	ACMESubsystem:         IntervalCold,
	SMARTSubsystem:        IntervalCold,
	CronTableSubsystem:    IntervalCold,
	SnapshotsSubsystem:    IntervalCold,
	VnstatSubsystem:       IntervalCold,
	AuthSubsystem:         IntervalCold,
	BackupSubsystem:       IntervalCold,
	ClamAVSubsystem:       IntervalCold,
}

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

// resolvePollInterval returns the code-assigned poll interval for a collector: its
// self-declared tier (IntervalCollector) if any, else the central collectorTiers
// table, else the supplied global default. The result is always clamped. Per-collector
// operator overrides are applied above this by (*Collector).resolveInterval.
func resolvePollInterval(coll CollectorInstance, global time.Duration) time.Duration {
	if ic, ok := coll.(IntervalCollector); ok {
		if d := ic.PollInterval(); d > 0 {
			return clampInterval(d)
		}
	}
	if d, ok := collectorTiers[coll.Name()]; ok {
		return clampInterval(d)
	}
	return clampInterval(global)
}
