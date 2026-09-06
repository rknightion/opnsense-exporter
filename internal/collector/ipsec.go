package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v5/opnsense"
)

// saLimitMin folds a newly observed hard/soft byte or allocation limit into an
// aggregate, preferring the smallest CONFIGURED (non-zero) value seen. A limit
// of 0 means "unlimited" (#578), not "already exhausted" — a naive min() would
// let a single unlimited row (0) in a reqid group permanently mask a real
// configured limit reported by its sibling row, even though in practice both
// rows in a group share the same static child-SA policy and should already
// agree.
func saLimitMin(current, next int64) int64 {
	if next == 0 {
		return current
	}
	if current == 0 || next < current {
		return next
	}
	return current
}

type ipsecCollector struct {
	log                 *slog.Logger
	phase1              *prometheus.Desc
	phase1_install_time *prometheus.Desc
	phase1_bytes_in     *prometheus.Desc
	phase1_bytes_out    *prometheus.Desc
	phase1_packets_in   *prometheus.Desc
	phase1_packets_out  *prometheus.Desc
	phase2              *prometheus.Desc
	phase2_install_time *prometheus.Desc
	phase2_bytes_in     *prometheus.Desc
	phase2_bytes_out    *prometheus.Desc
	phase2_packets_in   *prometheus.Desc
	phase2_packets_out  *prometheus.Desc
	phase2_rekey_time   *prometheus.Desc
	phase2_life_time    *prometheus.Desc
	// #578: per-child-SA established state, the only phase2-level health signal
	// (Connected lives solely at phase1/IKE-SA level).
	phase2_established *prometheus.Desc
	serviceRunning     *prometheus.Desc
	poolOnline         *prometheus.Desc
	poolOffline        *prometheus.Desc
	poolSize           *prometheus.Desc

	// #213 kernel (setkey) tables, per-lease detail, pending-config flag.
	sadEntries     *prometheus.Desc
	saAge          *prometheus.Desc
	saLifetimeHard *prometheus.Desc
	saLifetimeSoft *prometheus.Desc
	sadNat         *prometheus.Desc
	spdPolicies    *prometheus.Desc
	leaseOnline    *prometheus.Desc
	configDirty    *prometheus.Desc
	legacyEnabled  *prometheus.Desc

	// #578: per-reqid (child-SA) byte/allocation usage + rekey limits, same
	// label set and aggregation granularity as saAge/saLifetimeHard/saLifetimeSoft
	// above. *Current are Counters (they reset to 0 on every rekey, exactly like
	// the already-Counter phase1/phase2 bytes-in/out — see the _total comment on
	// phase1_bytes_in below); *Limit are Gauges (a static configured ceiling, not
	// a count of anything) and are only emitted when the box actually configured
	// one — see the emission-site comment in Update for why 0 is gated out.
	saBytesCurrent       *prometheus.Desc
	saBytesSoftLimit     *prometheus.Desc
	saBytesHardLimit     *prometheus.Desc
	saAllocatedCurrent   *prometheus.Desc
	saAllocatedSoftLimit *prometheus.Desc
	saAllocatedHardLimit *prometheus.Desc

	// detailsEnabled gates the per-lease opnsense_ipsec_lease_online series,
	// whose `user` label is unbounded road-warrior identity (#213). Off by
	// default; the pool aggregates stay always-on.
	detailsEnabled bool

	subsystem string
	instance  string
}

// SetDetailsEnabled toggles the opt-in per-lease detail metric (user label).
func (c *ipsecCollector) SetDetailsEnabled(enabled bool) {
	c.detailsEnabled = enabled
}

func init() {
	collectorInstances = append(collectorInstances, &ipsecCollector{
		subsystem: IPsecSubsystem,
	})
}

func (c *ipsecCollector) Name() string {
	return c.subsystem
}

func (c *ipsecCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel

	c.log.Debug("Registering collector", "collector", c.Name())

	c.phase1 = buildPrometheusDesc(c.subsystem, "phase1_status",
		"IPsec phase1 (1 = connected, 0 = down)",
		[]string{"description", "name"},
	)
	c.phase1_install_time = buildPrometheusDesc(c.subsystem, "phase1_install_time",
		"IPsec phase1 install time",
		[]string{"description", "name"},
	)
	// #464: named with a _total suffix — these are Counters (CounterValue below),
	// and OTLP->Prometheus canonicalization appends _total to every monotonic sum
	// regardless of the Go-declared name, so an unsuffixed Counter descriptor
	// disagrees with what the supported OTLP-fed live backend exports.
	c.phase1_bytes_in = buildPrometheusDesc(c.subsystem, "phase1_bytes_in_total",
		"IPsec phase1 bytes in",
		[]string{"description", "name"},
	)
	c.phase1_bytes_out = buildPrometheusDesc(c.subsystem, "phase1_bytes_out_total",
		"IPsec phase1 bytes out",
		[]string{"description", "name"},
	)
	c.phase1_packets_in = buildPrometheusDesc(c.subsystem, "phase1_packets_in_total",
		"IPsec phase1 packets in",
		[]string{"description", "name"},
	)
	c.phase1_packets_out = buildPrometheusDesc(c.subsystem, "phase1_packets_out_total",
		"IPsec phase1 packets out",
		[]string{"description", "name"},
	)

	c.phase2_install_time = buildPrometheusDesc(c.subsystem, "phase2_install_time",
		"IPsec phase2 install time",
		[]string{"description", "name", "phase1_name"},
	)
	// #464: same _total naming fix as phase1 above.
	c.phase2_bytes_in = buildPrometheusDesc(c.subsystem, "phase2_bytes_in_total",
		"IPsec phase2 bytes in",
		[]string{"description", "name", "phase1_name"},
	)
	c.phase2_bytes_out = buildPrometheusDesc(c.subsystem, "phase2_bytes_out_total",
		"IPsec phase2 bytes out",
		[]string{"description", "name", "phase1_name"},
	)
	c.phase2_packets_in = buildPrometheusDesc(c.subsystem, "phase2_packets_in_total",
		"IPsec phase2 packets in",
		[]string{"description", "name", "phase1_name"},
	)
	c.phase2_packets_out = buildPrometheusDesc(c.subsystem, "phase2_packets_out_total",
		"IPsec phase2 packets out",
		[]string{"description", "name", "phase1_name"},
	)
	c.phase2_rekey_time = buildPrometheusDesc(c.subsystem, "phase2_rekey_time",
		"IPsec phase2 rekey time",
		[]string{"description", "name", "phase1_name"},
	)
	c.phase2_life_time = buildPrometheusDesc(c.subsystem, "phase2_life_time",
		"IPsec phase2 life time",
		[]string{"description", "name", "phase1_name"},
	)
	// #578: Connected only exists at phase1 (IKE SA), so a tunnel with phase1 up
	// and one dead child SA reads fully healthy without this. 1 only for the
	// vici child-SA state "INSTALLED" (fully up and passing traffic); every
	// other state (CREATED/ROUTED/INSTALLING/UPDATING/REKEYING/REKEYED/RETRYING/
	// DELETING/DELETED/DESTROYING) reads 0 — deliberately conservative, since a
	// child mid-rekey handoff is not yet the SA an operator should trust.
	c.phase2_established = buildPrometheusDesc(c.subsystem, "phase2_established",
		"Whether the IPsec phase2 (child SA) is fully installed and passing traffic (1 = INSTALLED, 0 = any other transitional/rekeying/deleting state). Phase1 being connected does not guarantee every child SA is up; check this alongside opnsense_ipsec_phase1_status to catch a tunnel where the parent IKE SA is fine but one traffic selector's child SA has failed or is stuck rekeying.",
		[]string{"description", "name", "phase1_name"},
	)

	c.serviceRunning = buildPrometheusDesc(c.subsystem, "service_running",
		"Whether the service is running (1 = running, 0 = stopped/disabled)",
		nil,
	)

	poolLabels := []string{"pool", "net"}
	c.poolOnline = buildPrometheusDesc(c.subsystem, "pool_leases_online",
		"Number of online leases in the IPsec mode-cfg pool",
		poolLabels,
	)
	c.poolOffline = buildPrometheusDesc(c.subsystem, "pool_leases_offline",
		"Number of offline leases in the IPsec mode-cfg pool",
		poolLabels,
	)
	c.poolSize = buildPrometheusDesc(c.subsystem, "pool_size",
		"Total size (address capacity) of the IPsec mode-cfg pool",
		poolLabels,
	)

	// #213 kernel security-association database (setkey -D). SPI is never a
	// label (churns every rekey); reqid IS a label — it is bounded by the
	// configured child-SA count and stable across rekeys, and it disambiguates
	// series when the ikeid/phaseNdesc join fields come back null (as they do on
	// the live box). ikeid/phaseNdesc add human context when populated.
	c.sadEntries = buildPrometheusDesc(c.subsystem, "sad_entries",
		"Number of installed kernel IPsec security associations (setkey -D), grouped by satype",
		[]string{"satype", "ikeid", "phase1desc"},
	)
	saLabels := []string{"ikeid", "phase2desc", "reqid"}
	c.saAge = buildPrometheusDesc(c.subsystem, "sa_age_seconds",
		"Age in seconds of the oldest installed kernel SA in each reqid (child-SA) group",
		saLabels,
	)
	c.saLifetimeHard = buildPrometheusDesc(c.subsystem, "sa_lifetime_hard_seconds",
		"Soonest hard-expiry lifetime in seconds across the kernel SAs in each reqid group",
		saLabels,
	)
	c.saLifetimeSoft = buildPrometheusDesc(c.subsystem, "sa_lifetime_soft_seconds",
		"Soonest soft-expiry (rekey) lifetime in seconds across the kernel SAs in each reqid group",
		saLabels,
	)
	// #578: byte/allocation (packet-count) usage and rekey limits, the volume-based
	// sibling of the time-based age/lifetime metrics above. Counter/_total for the
	// usage fields: like phase1/phase2 bytes-in/out, they reset to 0 on every
	// rekey (a new SPI starts counting from zero), which is exactly what a
	// Prometheus Counter models — a monotonic value that occasionally resets, not
	// a value that never goes down. Limit gauges are only emitted when the box
	// actually configured one (see the >0 gate in Update); a value of 0 in
	// setkey/strongSwan's own convention means "unlimited", not "zero budget
	// left", so a bare 0 gauge would misinform rather than clarify.
	c.saBytesCurrent = buildPrometheusDesc(c.subsystem, "sa_bytes_current_total",
		"Cumulative bytes processed by the most-utilized installed kernel SA in each reqid (child-SA) group (the higher of the two during a brief rekey overlap). Resets to a small value on every rekey (a new SPI starts counting from zero) — compare against sa_bytes_soft_limit to see how close the group is to its next byte-triggered rekey.",
		saLabels,
	)
	c.saBytesSoftLimit = buildPrometheusDesc(c.subsystem, "sa_bytes_soft_limit",
		"Configured soft (rekey-triggering) byte-count limit for the kernel SAs in each reqid group. Only present when the box configures a byte-count lifetime for this child SA; a limit of 0 means unlimited and is not exported as a fabricated zero.",
		saLabels,
	)
	c.saBytesHardLimit = buildPrometheusDesc(c.subsystem, "sa_bytes_hard_limit",
		"Configured hard (forced-expiry) byte-count limit for the kernel SAs in each reqid group. Only present when the box configures a byte-count lifetime for this child SA; a limit of 0 means unlimited and is not exported as a fabricated zero.",
		saLabels,
	)
	c.saAllocatedCurrent = buildPrometheusDesc(c.subsystem, "sa_allocated_current_total",
		"Cumulative packets (\"allocations\") processed by the most-utilized installed kernel SA in each reqid (child-SA) group (the higher of the two during a brief rekey overlap). The packet-count equivalent of sa_bytes_current_total; some child SAs are configured with a packet-count rekey margin instead of, or alongside, a byte-count one.",
		saLabels,
	)
	c.saAllocatedSoftLimit = buildPrometheusDesc(c.subsystem, "sa_allocated_soft_limit",
		"Configured soft (rekey-triggering) packet-count limit for the kernel SAs in each reqid group. Only present when the box configures a packet-count lifetime for this child SA; a limit of 0 means unlimited and is not exported as a fabricated zero.",
		saLabels,
	)
	c.saAllocatedHardLimit = buildPrometheusDesc(c.subsystem, "sa_allocated_hard_limit",
		"Configured hard (forced-expiry) packet-count limit for the kernel SAs in each reqid group. Only present when the box configures a packet-count lifetime for this child SA; a limit of 0 means unlimited and is not exported as a fabricated zero.",
		saLabels,
	)
	c.sadNat = buildPrometheusDesc(c.subsystem, "sad_nat_traversal",
		"Whether any kernel SA for the IKE SA is NAT-traversed (1 = NAT-T detected, 0 = not)",
		[]string{"ikeid"},
	)
	c.spdPolicies = buildPrometheusDesc(c.subsystem, "spd_policies",
		"Number of installed kernel IPsec security policies (setkey -DP), grouped by direction",
		[]string{"direction"},
	)
	// Opt-in (--exporter.enable-ipsec-lease-details): the `user` label is
	// unbounded road-warrior identity.
	c.leaseOnline = buildPrometheusDesc(c.subsystem, "lease_online",
		"Whether the IPsec mode-cfg lease is currently online (1 = online, 0 = offline). Per-user detail; only emitted with --exporter.enable-ipsec-lease-details",
		[]string{"pool", "user"},
	)
	c.configDirty = buildPrometheusDesc(c.subsystem, "config_dirty",
		"Whether there is an uncommitted (staged but not applied) IPsec configuration change (1 = dirty, 0 = clean)",
		nil,
	)
	c.legacyEnabled = buildPrometheusDesc(c.subsystem, "legacy_enabled",
		"Whether IPsec is enabled in the configuration (1 = enabled, 0 = disabled)",
		nil,
	)
}

func (c *ipsecCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.phase1
	ch <- c.phase1_install_time
	ch <- c.phase1_bytes_in
	ch <- c.phase1_bytes_out
	ch <- c.phase1_packets_in
	ch <- c.phase1_packets_out

	ch <- c.phase2_install_time
	ch <- c.phase2_bytes_in
	ch <- c.phase2_bytes_out
	ch <- c.phase2_packets_in
	ch <- c.phase2_packets_out
	ch <- c.phase2_rekey_time
	ch <- c.phase2_life_time
	ch <- c.phase2_established
	ch <- c.serviceRunning
	ch <- c.poolOnline
	ch <- c.poolOffline
	ch <- c.poolSize

	ch <- c.sadEntries
	ch <- c.saAge
	ch <- c.saLifetimeHard
	ch <- c.saLifetimeSoft
	ch <- c.saBytesCurrent
	ch <- c.saBytesSoftLimit
	ch <- c.saBytesHardLimit
	ch <- c.saAllocatedCurrent
	ch <- c.saAllocatedSoftLimit
	ch <- c.saAllocatedHardLimit
	ch <- c.sadNat
	ch <- c.spdPolicies
	ch <- c.leaseOnline
	ch <- c.configDirty
	ch <- c.legacyEnabled
}

func (c *ipsecCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	phase1s, err := client.FetchIPsecPhase1()
	if err != nil {
		return err
	}
	for _, phase1 := range phase1s.Rows {
		ch <- prometheus.MustNewConstMetric(
			c.phase1,
			prometheus.GaugeValue,
			float64(phase1.Connected),
			phase1.Phase1desc,
			phase1.Name,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.phase1_install_time,
			prometheus.GaugeValue,
			float64(phase1.InstallTime),
			phase1.Phase1desc,
			phase1.Name,
			c.instance,
		)
		// Phase1 bytes/packets are cumulative counters (the aggregated sums of the
		// phase2 child-SA counters, which are already CounterValue). Emit as
		// CounterValue so the same quantity isn't typed two different ways (#106).
		ch <- prometheus.MustNewConstMetric(
			c.phase1_bytes_in,
			prometheus.CounterValue,
			float64(phase1.BytesIn),
			phase1.Phase1desc,
			phase1.Name,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.phase1_bytes_out,
			prometheus.CounterValue,
			float64(phase1.BytesOut),
			phase1.Phase1desc,
			phase1.Name,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.phase1_packets_in,
			prometheus.CounterValue,
			float64(phase1.PacketsIn),
			phase1.Phase1desc,
			phase1.Name,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.phase1_packets_out,
			prometheus.CounterValue,
			float64(phase1.PacketsOut),
			phase1.Phase1desc,
			phase1.Name,
			c.instance,
		)

		// Without the SPI labels, overlapping SAs for the same child (the old and
		// new SA are both installed briefly during a rekey) would produce duplicate
		// label sets and fail the scrape. Dedupe by (description, name), keeping
		// the row with the smallest InstallTime: install time is age-in-seconds,
		// so the smallest value is the newest SA.
		type phase2Key struct{ desc, name string }
		newest := make(map[phase2Key]int)
		for i, phase2 := range phase1.Phase2 {
			key := phase2Key{phase2.Phase2desc, phase2.Name}
			if j, ok := newest[key]; !ok || phase2.InstallTime < phase1.Phase2[j].InstallTime {
				newest[key] = i
			}
		}

		for i, phase2 := range phase1.Phase2 {
			if newest[phase2Key{phase2.Phase2desc, phase2.Name}] != i {
				continue
			}

			ch <- prometheus.MustNewConstMetric(
				c.phase2_install_time,
				prometheus.GaugeValue,
				float64(phase2.InstallTime),
				phase2.Phase2desc,
				phase2.Name,
				phase1.Name,
				c.instance,
			)
			ch <- prometheus.MustNewConstMetric(
				c.phase2_bytes_in,
				prometheus.CounterValue,
				float64(phase2.BytesIn),
				phase2.Phase2desc,
				phase2.Name,
				phase1.Name,
				c.instance,
			)
			ch <- prometheus.MustNewConstMetric(
				c.phase2_bytes_out,
				prometheus.CounterValue,
				float64(phase2.BytesOut),
				phase2.Phase2desc,
				phase2.Name,
				phase1.Name,
				c.instance,
			)
			ch <- prometheus.MustNewConstMetric(
				c.phase2_packets_in,
				prometheus.CounterValue,
				float64(phase2.PacketsIn),
				phase2.Phase2desc,
				phase2.Name,
				phase1.Name,
				c.instance,
			)
			ch <- prometheus.MustNewConstMetric(
				c.phase2_packets_out,
				prometheus.CounterValue,
				float64(phase2.PacketsOut),
				phase2.Phase2desc,
				phase2.Name,
				phase1.Name,
				c.instance,
			)
			ch <- prometheus.MustNewConstMetric(
				c.phase2_rekey_time,
				prometheus.GaugeValue,
				float64(phase2.RekeyTime),
				phase2.Phase2desc,
				phase2.Name,
				phase1.Name,
				c.instance,
			)
			ch <- prometheus.MustNewConstMetric(
				c.phase2_life_time,
				prometheus.GaugeValue,
				float64(phase2.LifeTime),
				phase2.Phase2desc,
				phase2.Name,
				phase1.Name,
				c.instance,
			)
			// #578: 1 only for the vici "INSTALLED" state — see the Desc comment
			// in Register for why every other state (including REKEYING/REKEYED,
			// which do carry live traffic briefly) reads 0.
			established := 0.0
			if phase2.State == "INSTALLED" {
				established = 1.0
			}
			ch <- prometheus.MustNewConstMetric(
				c.phase2_established,
				prometheus.GaugeValue,
				established,
				phase2.Phase2desc,
				phase2.Name,
				phase1.Name,
				c.instance,
			)
		}
	}

	status, sErr := client.FetchServiceStatus("ipsecServiceStatus")
	if sErr != nil {
		c.log.Warn("failed to fetch service status", "err", sErr)
	} else {
		val := 0.0
		if status == "running" {
			val = 1.0
		}
		ch <- prometheus.MustNewConstMetric(
			c.serviceRunning, prometheus.GaugeValue,
			val, c.instance,
		)
	}

	// Pool utilisation — partial-failure tolerance: on error, log and continue.
	pools, poolErr := client.FetchIPsecPools()
	if poolErr != nil {
		c.log.Warn("failed to fetch ipsec pools", "err", poolErr)
	} else {
		for _, pool := range pools.Pools {
			ch <- prometheus.MustNewConstMetric(
				c.poolOnline, prometheus.GaugeValue,
				pool.Online, pool.Name, pool.Net, c.instance,
			)
			ch <- prometheus.MustNewConstMetric(
				c.poolOffline, prometheus.GaugeValue,
				pool.Offline, pool.Name, pool.Net, c.instance,
			)
			ch <- prometheus.MustNewConstMetric(
				c.poolSize, prometheus.GaugeValue,
				pool.Size, pool.Name, pool.Net, c.instance,
			)
		}

		// Per-lease detail is opt-in: the `user` label is unbounded road-warrior
		// identity. Dedupe by (pool, user) so multiple leases for one user can't
		// collide into a duplicate label set.
		if c.detailsEnabled {
			type leaseKey struct{ pool, user string }
			online := make(map[leaseKey]bool)
			for _, l := range pools.Leases {
				k := leaseKey{l.Pool, l.User}
				online[k] = online[k] || l.Online
			}
			for k, on := range online {
				v := 0.0
				if on {
					v = 1.0
				}
				ch <- prometheus.MustNewConstMetric(
					c.leaseOnline, prometheus.GaugeValue,
					v, k.pool, k.user, c.instance,
				)
			}
		}
	}

	// Kernel SA database (setkey -D). Partial-failure tolerant.
	sad, sadErr := client.FetchIPsecSAD()
	if sadErr != nil {
		c.log.Warn("failed to fetch ipsec SAD", "err", sadErr)
	} else {
		// sad_entries: count of installed SAs grouped by (satype, ikeid,
		// phase1desc). Map grouping guarantees unique label sets.
		type entKey struct{ satype, ikeid, phase1 string }
		entCounts := make(map[entKey]int)

		// Age/lifetime aggregated per reqid (child-SA) group. reqid is the
		// bounded, rekey-stable anchor; ikeid/phase2desc are context labels.
		type saKey struct{ ikeid, phase2, reqid string }
		type saAgg struct {
			maxAge, minHard, minSoft int

			// #578: byte/allocation usage + rekey limits, aggregated across the
			// group the same way age/lifetime are above. "current" usage takes
			// the max across the group's raw rows: during the brief window a
			// rekey overlaps two SAs for one reqid, the about-to-be-replaced SA
			// is the one closer to its limit and is what an operator needs to
			// see, and summing (as the phase1-level aggregate does across ALL
			// child SAs of a connection) would double-count one logical flow's
			// traffic here. "limit" fields take the min of the non-zero values
			// seen — see saLimitMin below for why zero must not win outright.
			maxBytesCurrent, maxAllocatedCurrent                           int64
			minBytesHard, minBytesSoft, minAllocatedHard, minAllocatedSoft int64
		}
		groups := make(map[saKey]*saAgg)

		// NAT-T per ikeid: 1 if any SA under the IKE SA is NAT-traversed.
		natByIke := make(map[string]bool)

		for _, sa := range sad.Entries {
			entCounts[entKey{sa.SAType, sa.IkeID, sa.Phase1desc}]++

			k := saKey{sa.IkeID, sa.Phase2desc, sa.ReqID}
			if g, ok := groups[k]; ok {
				if sa.AgeSeconds > g.maxAge {
					g.maxAge = sa.AgeSeconds
				}
				if sa.LifetimeHard < g.minHard {
					g.minHard = sa.LifetimeHard
				}
				if sa.LifetimeSoft < g.minSoft {
					g.minSoft = sa.LifetimeSoft
				}
				if sa.BytesCurrent > g.maxBytesCurrent {
					g.maxBytesCurrent = sa.BytesCurrent
				}
				if sa.AllocatedCurrent > g.maxAllocatedCurrent {
					g.maxAllocatedCurrent = sa.AllocatedCurrent
				}
				g.minBytesHard = saLimitMin(g.minBytesHard, sa.BytesHardLimit)
				g.minBytesSoft = saLimitMin(g.minBytesSoft, sa.BytesSoftLimit)
				g.minAllocatedHard = saLimitMin(g.minAllocatedHard, sa.AllocatedHardLimit)
				g.minAllocatedSoft = saLimitMin(g.minAllocatedSoft, sa.AllocatedSoftLimit)
			} else {
				groups[k] = &saAgg{
					maxAge:              sa.AgeSeconds,
					minHard:             sa.LifetimeHard,
					minSoft:             sa.LifetimeSoft,
					maxBytesCurrent:     sa.BytesCurrent,
					maxAllocatedCurrent: sa.AllocatedCurrent,
					minBytesHard:        sa.BytesHardLimit,
					minBytesSoft:        sa.BytesSoftLimit,
					minAllocatedHard:    sa.AllocatedHardLimit,
					minAllocatedSoft:    sa.AllocatedSoftLimit,
				}
			}

			natByIke[sa.IkeID] = natByIke[sa.IkeID] || sa.NATTraversal
		}

		for k, n := range entCounts {
			ch <- prometheus.MustNewConstMetric(
				c.sadEntries, prometheus.GaugeValue,
				float64(n), k.satype, k.ikeid, k.phase1, c.instance,
			)
		}
		for k, g := range groups {
			ch <- prometheus.MustNewConstMetric(
				c.saAge, prometheus.GaugeValue,
				float64(g.maxAge), k.ikeid, k.phase2, k.reqid, c.instance,
			)
			ch <- prometheus.MustNewConstMetric(
				c.saLifetimeHard, prometheus.GaugeValue,
				float64(g.minHard), k.ikeid, k.phase2, k.reqid, c.instance,
			)
			ch <- prometheus.MustNewConstMetric(
				c.saLifetimeSoft, prometheus.GaugeValue,
				float64(g.minSoft), k.ikeid, k.phase2, k.reqid, c.instance,
			)

			// #578: current usage is always real (0 legitimately means "just
			// installed, no traffic yet") and always emitted. Limits are gated:
			// a 0 here means "no cap configured" per setkey/strongSwan's own
			// convention, not "already exhausted" — emitting it as a literal 0
			// gauge would misreport an unlimited SA as one out of budget, so no
			// series is emitted at all (matches the "absent field -> no series"
			// convention used everywhere else in this exporter, applied here to
			// an absent CONFIGURATION rather than an absent wire field).
			ch <- prometheus.MustNewConstMetric(
				c.saBytesCurrent, prometheus.CounterValue,
				float64(g.maxBytesCurrent), k.ikeid, k.phase2, k.reqid, c.instance,
			)
			ch <- prometheus.MustNewConstMetric(
				c.saAllocatedCurrent, prometheus.CounterValue,
				float64(g.maxAllocatedCurrent), k.ikeid, k.phase2, k.reqid, c.instance,
			)
			if g.minBytesSoft > 0 {
				ch <- prometheus.MustNewConstMetric(
					c.saBytesSoftLimit, prometheus.GaugeValue,
					float64(g.minBytesSoft), k.ikeid, k.phase2, k.reqid, c.instance,
				)
			}
			if g.minBytesHard > 0 {
				ch <- prometheus.MustNewConstMetric(
					c.saBytesHardLimit, prometheus.GaugeValue,
					float64(g.minBytesHard), k.ikeid, k.phase2, k.reqid, c.instance,
				)
			}
			if g.minAllocatedSoft > 0 {
				ch <- prometheus.MustNewConstMetric(
					c.saAllocatedSoftLimit, prometheus.GaugeValue,
					float64(g.minAllocatedSoft), k.ikeid, k.phase2, k.reqid, c.instance,
				)
			}
			if g.minAllocatedHard > 0 {
				ch <- prometheus.MustNewConstMetric(
					c.saAllocatedHardLimit, prometheus.GaugeValue,
					float64(g.minAllocatedHard), k.ikeid, k.phase2, k.reqid, c.instance,
				)
			}
		}
		for ike, natOn := range natByIke {
			v := 0.0
			if natOn {
				v = 1.0
			}
			ch <- prometheus.MustNewConstMetric(
				c.sadNat, prometheus.GaugeValue, v, ike, c.instance,
			)
		}
	}

	// Kernel policy database (setkey -DP): count per direction. Partial-failure
	// tolerant.
	spd, spdErr := client.FetchIPsecSPD()
	if spdErr != nil {
		c.log.Warn("failed to fetch ipsec SPD", "err", spdErr)
	} else {
		dirCounts := make(map[string]int)
		for _, d := range spd.Directions {
			dirCounts[d]++
		}
		for dir, n := range dirCounts {
			ch <- prometheus.MustNewConstMetric(
				c.spdPolicies, prometheus.GaugeValue,
				float64(n), dir, c.instance,
			)
		}
	}

	// Pending-config / enabled flags. Partial-failure tolerant.
	legacy, legacyErr := client.FetchIPsecLegacyStatus()
	if legacyErr != nil {
		c.log.Warn("failed to fetch ipsec legacy status", "err", legacyErr)
	} else {
		dirty := 0.0
		if legacy.IsDirty {
			dirty = 1.0
		}
		ch <- prometheus.MustNewConstMetric(
			c.configDirty, prometheus.GaugeValue, dirty, c.instance,
		)
		enabled := 0.0
		if legacy.Enabled {
			enabled = 1.0
		}
		ch <- prometheus.MustNewConstMetric(
			c.legacyEnabled, prometheus.GaugeValue, enabled, c.instance,
		)
	}

	return nil
}
