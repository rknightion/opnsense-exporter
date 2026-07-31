package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

type firewallCollector struct {
	log                 *slog.Logger
	inIPv4PassPackets   *prometheus.Desc
	outIPv4PassPackets  *prometheus.Desc
	inIPv4BlockPackets  *prometheus.Desc
	outIPv4BlockPackets *prometheus.Desc

	inIPv6PassPackets   *prometheus.Desc
	outIPv6PassPackets  *prometheus.Desc
	inIPv6BlockPackets  *prometheus.Desc
	outIPv6BlockPackets *prometheus.Desc

	inIPv4PassBytes   *prometheus.Desc
	outIPv4PassBytes  *prometheus.Desc
	inIPv4BlockBytes  *prometheus.Desc
	outIPv4BlockBytes *prometheus.Desc

	inIPv6PassBytes   *prometheus.Desc
	outIPv6PassBytes  *prometheus.Desc
	inIPv6BlockBytes  *prometheus.Desc
	outIPv6BlockBytes *prometheus.Desc

	pfStatesCurrent *prometheus.Desc
	pfStatesLimit   *prometheus.Desc
	pfInterfaceRefs *prometheus.Desc

	// pfCountersClearedTimestamp is pf's own per-interface "counters reset at"
	// marker (#580): without it, every pass/block rate() series above shows a
	// bogus negative delta or spurious plateau across a `pfctl -z`/filter
	// reload with nothing to explain it.
	pfCountersClearedTimestamp *prometheus.Desc

	interfaceLogEntries *prometheus.Desc

	// GeoIP alias-database freshness (#221): cheap, cache-eligible, and always
	// on — a GeoIP alias silently stops matching any traffic once the database
	// stops updating (expired MaxMind key, download failure), so this is a
	// direct health signal, not an optional extra.
	geoipAliasUsages         *prometheus.Desc
	geoipAddresses           *prometheus.Desc
	geoipFiles               *prometheus.Desc
	geoipLastUpdateTimestamp *prometheus.Desc

	// NAT rule inventory counts (#221): opt-in (natCountsEnabled) since it costs
	// four extra GETs per scheduled poll on top of the always-on pf/GeoIP calls above.
	natRules         *prometheus.Desc
	natCountsEnabled bool

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &firewallCollector{
		subsystem: FirewallSubsystem,
	})
}

func (c *firewallCollector) Name() string {
	return c.subsystem
}

// SetNATCountsEnabled enables the opt-in NAT rule inventory count metric,
// which costs four extra GETs per scheduled poll (#221).
func (c *firewallCollector) SetNATCountsEnabled(enabled bool) {
	c.natCountsEnabled = enabled
}

func (c *firewallCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.inIPv4PassPackets = buildPrometheusDesc(c.subsystem, "in_ipv4_pass_packets_total",
		"The number of IPv4 incoming packets that were allowed to pass through the firewall by interface",
		[]string{"interface"},
	)

	c.outIPv4PassPackets = buildPrometheusDesc(c.subsystem, "out_ipv4_pass_packets_total",
		"The number of IPv4 outgoing packets that were allowed to pass through the firewall by interface",
		[]string{"interface"},
	)

	c.inIPv4BlockPackets = buildPrometheusDesc(c.subsystem, "in_ipv4_block_packets_total",
		"The number of IPv4 incoming packets that were blocked by the firewall by interface",
		[]string{"interface"},
	)

	c.outIPv4BlockPackets = buildPrometheusDesc(c.subsystem, "out_ipv4_block_packets_total",
		"The number of IPv4 outgoing packets that were blocked by the firewall by interface",
		[]string{"interface"},
	)

	c.inIPv6PassPackets = buildPrometheusDesc(c.subsystem, "in_ipv6_pass_packets_total",
		"The number of IPv6 incoming packets that were allowed to pass through the firewall by interface",
		[]string{"interface"},
	)

	c.outIPv6PassPackets = buildPrometheusDesc(c.subsystem, "out_ipv6_pass_packets_total",
		"The number of IPv6 outgoing packets that were allowed to pass through the firewall by interface",
		[]string{"interface"},
	)

	c.inIPv6BlockPackets = buildPrometheusDesc(c.subsystem, "in_ipv6_block_packets_total",
		"The number of IPv6 incoming packets that were blocked by the firewall by interface",
		[]string{"interface"},
	)

	c.outIPv6BlockPackets = buildPrometheusDesc(c.subsystem, "out_ipv6_block_packets_total",
		"The number of IPv6 outgoing packets that were blocked by the firewall by interface",
		[]string{"interface"},
	)

	c.inIPv4PassBytes = buildPrometheusDesc(c.subsystem, "in_ipv4_pass_bytes_total",
		"The number of IPv4 incoming bytes that were allowed to pass through the firewall by interface",
		[]string{"interface"},
	)

	c.outIPv4PassBytes = buildPrometheusDesc(c.subsystem, "out_ipv4_pass_bytes_total",
		"The number of IPv4 outgoing bytes that were allowed to pass through the firewall by interface",
		[]string{"interface"},
	)

	c.inIPv4BlockBytes = buildPrometheusDesc(c.subsystem, "in_ipv4_block_bytes_total",
		"The number of IPv4 incoming bytes that were blocked by the firewall by interface",
		[]string{"interface"},
	)

	c.outIPv4BlockBytes = buildPrometheusDesc(c.subsystem, "out_ipv4_block_bytes_total",
		"The number of IPv4 outgoing bytes that were blocked by the firewall by interface",
		[]string{"interface"},
	)

	c.inIPv6PassBytes = buildPrometheusDesc(c.subsystem, "in_ipv6_pass_bytes_total",
		"The number of IPv6 incoming bytes that were allowed to pass through the firewall by interface",
		[]string{"interface"},
	)

	c.outIPv6PassBytes = buildPrometheusDesc(c.subsystem, "out_ipv6_pass_bytes_total",
		"The number of IPv6 outgoing bytes that were allowed to pass through the firewall by interface",
		[]string{"interface"},
	)

	c.inIPv6BlockBytes = buildPrometheusDesc(c.subsystem, "in_ipv6_block_bytes_total",
		"The number of IPv6 incoming bytes that were blocked by the firewall by interface",
		[]string{"interface"},
	)

	c.outIPv6BlockBytes = buildPrometheusDesc(c.subsystem, "out_ipv6_block_bytes_total",
		"The number of IPv6 outgoing bytes that were blocked by the firewall by interface",
		[]string{"interface"},
	)

	c.pfStatesCurrent = buildPrometheusDesc(c.subsystem, "pf_states_current",
		"Current number of active PF states",
		nil,
	)

	c.pfStatesLimit = buildPrometheusDesc(c.subsystem, "pf_states_limit",
		"Maximum number of PF states allowed",
		nil,
	)

	// The only per-interface breakdown of PF state-table usage the box exposes
	// anywhere: pf_states_current is a single global number, so without this
	// there is no way to answer "which interface is consuming the state table"
	// without shelling into the firewall (#542).
	c.pfInterfaceRefs = buildPrometheusDesc(c.subsystem, "pf_interface_references",
		"Number of PF state-table entries currently referencing each interface — the per-interface "+
			"breakdown of the global pf_states_current. A live depth, not a cumulative counter: it rises "+
			"and falls with connection count, so never wrap it in rate()/increase(). "+
			"skipped=\"true\" means pf \"skip on interface\" is enabled for that device, so pf is not "+
			"filtering it at all — the reference count is still real, but no rules are being evaluated. "+
			"The pfctl \" (skip)\" name suffix is stripped out of the interface label so toggling that "+
			"option does not rename the series. The pfctl \"all\" aggregate row is deliberately NOT "+
			"emitted: it is the sum of every other row, so including it would double every total in any "+
			"panel that aggregates this family — use sum() in PromQL instead. Do not add it back.",
		[]string{"interface", "skipped"},
	)

	// Sourced from diagnostics/firewall/stats, which counts occurrences per
	// interface over only the most recent ~5000 firewall *log* records and
	// returns the top 10 plus a synthetic "other" aggregate bucket. It rises and
	// falls as lines age out of that fixed window, so it is a gauge, not a
	// monotonic counter — never wrap it in rate()/increase() (#74). The
	// "interface" label is the interface description (e.g. LAN), and "other" is
	// an aggregate of everything beyond the top 10, not a real interface.
	c.interfaceLogEntries = buildPrometheusDesc(c.subsystem, "interface_log_entries_recent",
		"Firewall log entries per interface within the most recent ~5000-record log window "+
			"(sliding, not a counter; interface=\"other\" is an aggregate of interfaces beyond the top 10)",
		[]string{"interface"},
	)

	c.geoipAliasUsages = buildPrometheusDesc(c.subsystem, "geoip_alias_usages",
		"Number of configured firewall aliases of type GeoIP, regardless of whether the GeoIP database itself has ever downloaded",
		nil,
	)
	c.geoipAddresses = buildPrometheusDesc(c.subsystem, "geoip_addresses",
		"Number of GeoIP addresses/networks currently loaded from the downloaded database (0 until a MaxMind/ipinfo key is configured and a download has succeeded)",
		nil,
	)
	c.geoipFiles = buildPrometheusDesc(c.subsystem, "geoip_files",
		"Number of per-country GeoIP alias table files currently written (0 until a MaxMind/ipinfo key is configured and a download has succeeded)",
		nil,
	)
	c.geoipLastUpdateTimestamp = buildPrometheusDesc(c.subsystem, "geoip_last_update_timestamp_seconds",
		"Unix timestamp of the last successful GeoIP database download. Absent until the first successful download; compare against time() to alert on a stale/failed GeoIP database (e.g. an expired MaxMind license key).",
		nil,
	)

	// #580: pf's own "counters reset at" timestamp per interface. Absent until
	// the API reports a parseable value — a fresh box, or an interface pf has
	// never zeroed, legitimately has none (see ClearedUnixSeconds in
	// opnsense/firewall.go for why absent/unparseable is never epoch 0).
	c.pfCountersClearedTimestamp = buildPrometheusDesc(c.subsystem, "pf_counters_cleared_timestamp_seconds",
		"Unix timestamp (UTC) of pf's last counters reset for this interface — pfctl's own "+
			"\"Cleared\" marker, the same instant a `pfctl -z` or a filter/rule reload zeroed the "+
			"pass/block packet and byte counters above for that interface. OPNsense reports this "+
			"timestamp with no timezone marker at all, so it is decoded assuming UTC and can be off "+
			"by the firewall's real UTC offset — treat this as \"a reset happened\" (a step change, "+
			"or a value newer than your rate() window), not a to-the-minute clock. A rate()/increase() "+
			"query spanning a reset already reads a bogus negative delta or spurious plateau on the "+
			"pass/block counters above; use this timestamp to explain that away rather than chase it "+
			"as a real traffic drop. Absent entirely when the box has never reported a parseable value "+
			"for this interface.",
		[]string{"interface"},
	)

	c.natRules = buildPrometheusDesc(c.subsystem, "nat_rules",
		"Number of MVC-managed NAT rules by type and enabled state (source_nat, d_nat, one_to_one, npt). Rules created before an admin migrated to the MVC-managed NAT backend are not counted.",
		[]string{"type", "enabled"},
	)
}

func (c *firewallCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.inIPv4PassPackets
	ch <- c.outIPv4PassPackets
	ch <- c.inIPv4BlockPackets
	ch <- c.outIPv4BlockPackets

	ch <- c.inIPv6PassPackets
	ch <- c.outIPv6PassPackets
	ch <- c.inIPv6BlockPackets
	ch <- c.outIPv6BlockPackets

	ch <- c.inIPv4PassBytes
	ch <- c.outIPv4PassBytes
	ch <- c.inIPv4BlockBytes
	ch <- c.outIPv4BlockBytes

	ch <- c.inIPv6PassBytes
	ch <- c.outIPv6PassBytes
	ch <- c.inIPv6BlockBytes
	ch <- c.outIPv6BlockBytes

	ch <- c.pfStatesCurrent
	ch <- c.pfStatesLimit
	ch <- c.pfInterfaceRefs
	ch <- c.pfCountersClearedTimestamp

	ch <- c.interfaceLogEntries

	ch <- c.geoipAliasUsages
	ch <- c.geoipAddresses
	ch <- c.geoipFiles
	ch <- c.geoipLastUpdateTimestamp

	ch <- c.natRules
}

func (c *firewallCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchPFStatsByInterface()
	if err != nil {
		return err
	}

	for _, v := range data.Interfaces {
		// These pf pass/block byte and packet totals are cumulative,
		// reset-on-reboot counters — emit as CounterValue so rate()/increase()
		// and TYPE-aware tooling handle them correctly (#106).
		//
		// Each metric is emitted through its own explicit c.<field> call site
		// (rather than a shared map[*prometheus.Desc]int64 loop keyed by a
		// single generic loop variable) so scripts/docgen's static per-field
		// type resolution (collectEmittedValueTypes) can attribute the
		// CounterValue argument back to the exact desc field declared in
		// Register(), instead of falling back to the _total-suffix heuristic
		// and misdocumenting the unsuffixed packet counters as Gauges (#418).
		ch <- prometheus.MustNewConstMetric(c.inIPv4PassPackets, prometheus.CounterValue,
			float64(v.In4PassPackets), v.InterfaceName, c.instance)
		ch <- prometheus.MustNewConstMetric(c.outIPv4PassPackets, prometheus.CounterValue,
			float64(v.Out4PassPackets), v.InterfaceName, c.instance)
		ch <- prometheus.MustNewConstMetric(c.inIPv4BlockPackets, prometheus.CounterValue,
			float64(v.In4BlockPackets), v.InterfaceName, c.instance)
		ch <- prometheus.MustNewConstMetric(c.outIPv4BlockPackets, prometheus.CounterValue,
			float64(v.Out4BlockPackets), v.InterfaceName, c.instance)
		ch <- prometheus.MustNewConstMetric(c.inIPv6PassPackets, prometheus.CounterValue,
			float64(v.In6PassPackets), v.InterfaceName, c.instance)
		ch <- prometheus.MustNewConstMetric(c.outIPv6PassPackets, prometheus.CounterValue,
			float64(v.Out6PassPackets), v.InterfaceName, c.instance)
		ch <- prometheus.MustNewConstMetric(c.inIPv6BlockPackets, prometheus.CounterValue,
			float64(v.In6BlockPackets), v.InterfaceName, c.instance)
		ch <- prometheus.MustNewConstMetric(c.outIPv6BlockPackets, prometheus.CounterValue,
			float64(v.Out6BlockPackets), v.InterfaceName, c.instance)
		ch <- prometheus.MustNewConstMetric(c.inIPv4PassBytes, prometheus.CounterValue,
			float64(v.In4PassBytes), v.InterfaceName, c.instance)
		ch <- prometheus.MustNewConstMetric(c.outIPv4PassBytes, prometheus.CounterValue,
			float64(v.Out4PassBytes), v.InterfaceName, c.instance)
		ch <- prometheus.MustNewConstMetric(c.inIPv4BlockBytes, prometheus.CounterValue,
			float64(v.In4BlockBytes), v.InterfaceName, c.instance)
		ch <- prometheus.MustNewConstMetric(c.outIPv4BlockBytes, prometheus.CounterValue,
			float64(v.Out4BlockBytes), v.InterfaceName, c.instance)
		ch <- prometheus.MustNewConstMetric(c.inIPv6PassBytes, prometheus.CounterValue,
			float64(v.In6PassBytes), v.InterfaceName, c.instance)
		ch <- prometheus.MustNewConstMetric(c.outIPv6PassBytes, prometheus.CounterValue,
			float64(v.Out6PassBytes), v.InterfaceName, c.instance)
		ch <- prometheus.MustNewConstMetric(c.inIPv6BlockBytes, prometheus.CounterValue,
			float64(v.In6BlockBytes), v.InterfaceName, c.instance)
		ch <- prometheus.MustNewConstMetric(c.outIPv6BlockBytes, prometheus.CounterValue,
			float64(v.Out6BlockBytes), v.InterfaceName, c.instance)

		// Unlike every counter above, this one is a live depth, not a cumulative
		// total — GaugeValue (#542). Zero-referenced interfaces are emitted too:
		// an absent series and a genuinely idle interface must not look the same.
		skipped := "false"
		if v.Skipped {
			skipped = "true"
		}
		ch <- prometheus.MustNewConstMetric(c.pfInterfaceRefs, prometheus.GaugeValue,
			float64(v.References), v.InterfaceName, skipped, c.instance)

		// #580: a Gauge holding Unix seconds, never a self-reported "age" — see
		// LastRefresh in internal/logship/enrich/metrics.go for why an age value
		// set once and never touched again would read as stale-forever. Emitted
		// only when the box reported a parseable value: an absent series and a
		// counter history that has genuinely never been reset must not look the
		// same as a fabricated epoch-0 "reset in 1970".
		if v.HasClearedTimestamp {
			ch <- prometheus.MustNewConstMetric(c.pfCountersClearedTimestamp, prometheus.GaugeValue,
				v.ClearedTimestamp, v.InterfaceName, c.instance)
		}
	}

	pfStates, pfErr := client.FetchPFStates()
	if pfErr != nil {
		return pfErr
	}
	ch <- prometheus.MustNewConstMetric(
		c.pfStatesCurrent,
		prometheus.GaugeValue,
		float64(pfStates.Current),
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.pfStatesLimit,
		prometheus.GaugeValue,
		float64(pfStates.Limit),
		c.instance,
	)

	fwStats, fwErr := client.FetchFirewallStats()
	if fwErr != nil {
		c.log.Warn("failed to fetch firewall aggregate stats", "error", fwErr.Error())
	} else {
		for _, hit := range fwStats {
			ch <- prometheus.MustNewConstMetric(
				c.interfaceLogEntries,
				prometheus.GaugeValue,
				float64(hit.Value),
				hit.Label,
				c.instance,
			)
		}
	}

	geoip, geoipErr := client.FetchFirewallGeoIPStatus()
	if geoipErr != nil {
		// Non-fatal (like the aggregate stats above): a transient failure of this
		// one cheap, cached read must not blank out the rest of an otherwise
		// healthy firewall collector's metrics.
		c.log.Warn("failed to fetch firewall GeoIP status", "error", geoipErr.Error())
	} else {
		ch <- prometheus.MustNewConstMetric(c.geoipAliasUsages, prometheus.GaugeValue,
			geoip.AliasUsages, c.instance)
		ch <- prometheus.MustNewConstMetric(c.geoipAddresses, prometheus.GaugeValue,
			geoip.AddressCount, c.instance)
		ch <- prometheus.MustNewConstMetric(c.geoipFiles, prometheus.GaugeValue,
			geoip.FileCount, c.instance)
		// Emit only when the database has actually downloaded at least once —
		// never emit epoch 0, which would misreport a never-configured GeoIP
		// database as "stale since 1970" instead of simply absent (#221).
		if geoip.HasLastUpdateTimestamp {
			ch <- prometheus.MustNewConstMetric(c.geoipLastUpdateTimestamp, prometheus.GaugeValue,
				geoip.LastUpdateTimestamp, c.instance)
		}
	}

	if c.natCountsEnabled {
		natCounts, natErr := client.FetchFirewallNATRuleCounts()
		if natErr != nil {
			c.log.Warn("failed to fetch firewall NAT rule counts", "error", natErr.Error())
		} else {
			for _, rc := range natCounts {
				ch <- prometheus.MustNewConstMetric(c.natRules, prometheus.GaugeValue,
					float64(rc.Enabled), rc.Type, "true", c.instance)
				ch <- prometheus.MustNewConstMetric(c.natRules, prometheus.GaugeValue,
					float64(rc.Disabled), rc.Type, "false", c.instance)
			}
		}
	}

	return nil
}
