package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

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
	serviceRunning      *prometheus.Desc
	poolOnline          *prometheus.Desc
	poolOffline         *prometheus.Desc
	poolSize            *prometheus.Desc

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
	c.phase1_bytes_in = buildPrometheusDesc(c.subsystem, "phase1_bytes_in",
		"IPsec phase1 bytes in",
		[]string{"description", "name"},
	)
	c.phase1_bytes_out = buildPrometheusDesc(c.subsystem, "phase1_bytes_out",
		"IPsec phase1 bytes out",
		[]string{"description", "name"},
	)
	c.phase1_packets_in = buildPrometheusDesc(c.subsystem, "phase1_packets_in",
		"IPsec phase1 packets in",
		[]string{"description", "name"},
	)
	c.phase1_packets_out = buildPrometheusDesc(c.subsystem, "phase1_packets_out",
		"IPsec phase1 packets out",
		[]string{"description", "name"},
	)

	c.phase2_install_time = buildPrometheusDesc(c.subsystem, "phase2_install_time",
		"IPsec phase2 install time",
		[]string{"description", "name", "phase1_name"},
	)
	c.phase2_bytes_in = buildPrometheusDesc(c.subsystem, "phase2_bytes_in",
		"IPsec phase2 bytes in",
		[]string{"description", "name", "phase1_name"},
	)
	c.phase2_bytes_out = buildPrometheusDesc(c.subsystem, "phase2_bytes_out",
		"IPsec phase2 bytes out",
		[]string{"description", "name", "phase1_name"},
	)
	c.phase2_packets_in = buildPrometheusDesc(c.subsystem, "phase2_packets_in",
		"IPsec phase2 packets in",
		[]string{"description", "name", "phase1_name"},
	)
	c.phase2_packets_out = buildPrometheusDesc(c.subsystem, "phase2_packets_out",
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
	ch <- c.serviceRunning
	ch <- c.poolOnline
	ch <- c.poolOffline
	ch <- c.poolSize

	ch <- c.sadEntries
	ch <- c.saAge
	ch <- c.saLifetimeHard
	ch <- c.saLifetimeSoft
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
			} else {
				groups[k] = &saAgg{
					maxAge:  sa.AgeSeconds,
					minHard: sa.LifetimeHard,
					minSoft: sa.LifetimeSoft,
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
