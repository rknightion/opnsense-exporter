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
// FAST-TIER ADMISSION RULE (#568). Apply this to a CANDIDATE; it is a test, not a
// description of who is already in the tier. The fast tier is the only one where being
// wrong is expensive — 5,760 polls per collector per day, each request costing the
// firewall two configd RPCs and two audit lines (#535) — so a collector is admitted
// only if it passes one of the three clauses AND the cost paragraph.
//
// A collector belongs on the fast tier when ANY of:
//
//	(a) a CHANGE IN ITS VALUE IS ITSELF THE ALERTABLE EVENT, and detecting that change
//	    a minute late is a real operational loss (CARP failover state, gateway
//	    up/down). Churn is NOT the test: a series that is byte-identical for days
//	    still qualifies, because the transition is the whole point of sampling it.
//	(b) it feeds a rate() or delta that is ALERTED ON, or read on a dashboard, at
//	    SUB-MINUTE RESOLUTION. A 5m or 45m evaluation window does not qualify — that
//	    alert reads the same off a 60s poll.
//	(c) a DASHBOARD PANEL GENUINELY READS DIFFERENTLY at 15s than at 60s — a stacked
//	    throughput or protocol-counter graph does, an instantaneous gauge does not.
//	    Panels here use $__rate_interval, which follows the sample spacing, so a 15s
//	    poll buys real shape rather than a smoother line.
//
// Clause (c) is deliberate and settled (Rob, 2026-07-30, recorded on #568): dashboard
// fidelity admits a collector on its own, with no alerting story required. The
// counter-argument — that only alerting should buy fast-tier cost — has been made and
// OVERRULED; it would re-demote interfaces and protocol. Do not re-litigate it.
//
// COST MUST BE PROPORTIONATE TO THE CASE. Cost has two independent axes and they rank
// endpoints differently, so weigh both:
//   - per REQUEST: every call is two configd RPCs and two audit lines whatever it
//     returns. netflowIsEnabled is 23 bytes and still pays it in full. A collector
//     issuing four requests per poll pays four times over.
//   - per BYTE, and per unit of firewall WORK to build the payload: a large response,
//     or one the box has to compute, is expensive even if it is a single request.
//
// The weighing is one-directional: cost can only RAISE the bar a candidate has to
// clear, never lower it. A collector that costs the firewall nothing clears the cost
// paragraph outright and is judged on clauses (a)–(c) alone — so a collector reading
// an out-of-band accumulator, or anything else that issues no request, is admitted on
// its freshness case with nothing further to justify. An expensive candidate needs a
// correspondingly stronger clause, because the fast tier pays that cost 5,760 times a
// day. There is no numeric threshold; state the measured cost and the clause it buys.
//
// WORKED COUNTER-EXAMPLE — the activity collector. It was fast-tier and satisfied NO
// clause: its remaining metrics are instantaneous thread-state gauges, with no
// sub-minute alert and no rate-shaped panel. It cost a measured 2.15 s of firewall
// work per call — a permanent 14% duty cycle at 15s. Freshness bought nothing and the
// cost was the largest in the tier; #559 removed it. That is what the rule is for.
//
// Rationale by tier:
//   - fast: admitted by the rule above; see the per-collector clause annotations in
//     collectorTiers.
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
// hardware, system, crowdsec, tor — and, per #567, a fast-tier collector too, given
// a written per-endpoint justification in fastTierBodyCacheJustifications), the
// tier follows the LIVE half and the body cache handles the static endpoints — a
// per-collector interval cannot split them (#344). The fast tier is not exempt
// from this arrangement; it is simply the one tier where the opt-out must be
// justified in writing rather than assumed, because it is the tier with the most
// to lose from a silently flat-lined series.
//
// The activity collector is deliberately ABSENT from this table (medium, #559) — it
// is the admission rule's worked counter-example, restated here so the absence is not
// read as an oversight. It
// was fast, at a measured 2.15 s of firewall work per call — a permanent 14% duty
// cycle at 15s — for CPU percentages that now come from the cpu_usage SSE stream
// instead. What is left is thread-state counts: instantaneous gauges with no
// sub-minute alerting story, where 60s loses nothing.
var collectorTiers = map[string]time.Duration{
	// fast (15s) — each member is annotated with the clause of the admission rule
	// above that admits it, checked against the alert rules in
	// grafana/alerts/build_rules.py and the panels in grafana/tabs/ (#568).
	//
	// Clause (a): opnsense_gateways_status going to 0 IS the event —
	// OPNsenseGatewayDown alerts on {default_gateway="true"} < 1 and
	// OPNsenseGatewayDownFailover on the secondaries. RTT/loss (OPNsenseGatewayHighRTT,
	// OPNsenseGatewayHighLoss) are instantaneous gauges on 10m windows and would not
	// admit it on their own; the up/down transition does.
	GatewaysSubsystem: IntervalFast,
	// Clause (c). No alert rule reads any opnsense_interfaces_* series, and the
	// recording rules instance:opnsense_interface_rx_bits:rate5m / :tx_bits:rate5m use
	// a 5m window, so clause (b) does not apply. It is admitted on dashboard fidelity:
	// "Interface RX Throughput" / "Interface TX Throughput" (bps) and "Packets RX" /
	// "Packets TX" (pps) in grafana/tabs/interfaces.py are $__rate_interval throughput
	// graphs that genuinely read differently at 15s. This is the pairing Rob's #568
	// steer names by hand.
	InterfacesSubsystem: IntervalFast,
	// Clause (c), same basis as interfaces and named alongside it in the #568 steer.
	// No alert rule reads any opnsense_protocol_* series. "TCP Packets (rate)" and
	// "TCP Connection Lifecycle (rate)" in grafana/tabs/protocols.py are exactly the
	// stacked protocol-counter graphs clause (c) is written around.
	ProtocolSubsystem: IntervalFast,
	// Clause (c). Note the trap: OPNsensePFStateTableNearLimit reads
	// opnsense_firewall_pf_states_current / _limit, which belong to the FIREWALL
	// collector (medium), not to pf_stats — it does not admit this collector. What
	// does is "PF State Table Operations/s" (searches/inserts/removals) and "PF
	// Counters (rate)" in grafana/tabs/firewall.py; per-second state-table churn on a
	// busy box is rate-shaped and reads differently at 15s. The gauges in the same
	// row ("PF State Table Entries", "PF Memory Limits by Pool") would not qualify.
	PFStatsSubsystem: IntervalFast,
	// Clause (c), and the tier's most marginal admission — recorded as such rather
	// than smoothed over. Only ONE panel qualifies: "Cache Packets (rate)" (pps by
	// interface) in grafana/tabs/netflow.py. Everything else the collector feeds is an
	// instantaneous stat ("NetFlow Capture", "NetFlow Service", "Collectors") or a
	// cache-occupancy gauge, and the one alert, OPNsenseNetFlowHookDead, evaluates
	// increase(opnsense_netflow_cache_packets_total[45m]) — a 45m window that reads
	// identically off a 60s poll, so clause (b) does not apply. Against that it is the
	// most request-expensive member of the tier: four GETs per poll
	// (netflowIsEnabled, status, cache stats, capture config), and the cost paragraph
	// says an expensive candidate needs the stronger case. It passes, but it is the
	// first collector the #569 audit should re-weigh. Tier UNCHANGED here — retiering
	// is out of scope for #568.
	NetflowSubsystem: IntervalFast,
	// Clause (a), and the case the rule exists to protect. opnsense_carp_vip_status is
	// byte-identical for days on a healthy box; zero churn is NOT disqualifying,
	// because the MASTER/BACKUP transition is itself the alertable event —
	// OPNsenseCARPVIPFault and OPNsenseCARPStateFlapping both alert on that series,
	// and the "CARP VIP Status" state timeline exists to show the transition.
	// Detecting a failover 60s late is the failure.
	CARPSubsystem: IntervalFast,
	// Clauses (a) and (c), and it clears the cost paragraph outright: it makes no API
	// call at all, reading an accumulator the cpu_usage SSE stream fills out of band
	// (#559), so its firewall cost is zero and the rule's one-directional weighing
	// leaves it judged on freshness alone. (a): a stalled stream is the event —
	// OPNsenseCPUStreamStalled alerts on opnsense_cpu_stream_last_frame_age_seconds,
	// which reaches the threshold 15s sooner at this tier. (c): the "CPU Usage" panel
	// is a stacked percent graph of 100 * rate(opnsense_cpu_seconds_total) over
	// $__rate_interval — a per-mode breakdown that visibly loses shape at 60s. Under
	// #550's lane clamp this still resolves to 60s when no fast lane is configured, so
	// the default deployment gains nothing to pay for.
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
