package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

// kernelMemoryCollector exports FreeBSD's own allocator accounting from
// api/diagnostics/system/memory: every UMA zone and every malloc type the kernel
// reports, with no allowlist.
//
// WHY EVERY ZONE AND EVERY TYPE. `fail` is FreeBSD's canonical "the kernel could
// not allocate this" counter, and which zone runs out is exactly what is not known
// in advance — an allowlist is a guess about where exhaustion will happen, made
// before it happens, and a hole in the family is indistinguishable from a healthy
// zone. Measured on the live boxes 2026-07-30, the whole family is about 2,600
// series (prod 26.1: 228 zones x 8 + 258 malloc types x 3 + 1 catch-all; the two dev
// boxes 219 + ~250) against a 100k global budget the exporter currently uses ~4.6k
// of, so there is no cost argument either. Zone and malloc-type names are stable
// kernel identifiers, not churning values, so this is cardinality, not label churn.
//
// The exact set is a property of the box, not of the release: it tracks which kernel
// modules are loaded. Prod carries NetFlow and `buffer arena-*` zones the dev boxes
// lack; the dev boxes carry IPFW and wg zones prod lacks; and 27.1.a's newer FreeBSD
// base adds an `inotify` malloc type. A zone appearing or disappearing is therefore
// expected and must not be read as drift.
//
// SUBSYSTEM NAME. Deliberately kernel_memory and not system_memory: the system
// collector already exports opnsense_system_memory_used_bytes (total RAM in use,
// which backs the OPNsenseMemoryHigh alert). These are unrelated numbers — one is
// physical RAM, the other is allocator bookkeeping — and a near-identical prefix
// would be misread by anyone skimming a dashboard.
//
// RELATIONSHIP TO THE mbuf COLLECTOR. Six zones here have a counterpart in the mbuf
// collector, which reads the different systemMbuf endpoint; see the help text on
// zoneFailures for the mapping and the rule against summing the two families.
type kernelMemoryCollector struct {
	log *slog.Logger

	zoneUsed        *prometheus.Desc
	zoneFree        *prometheus.Desc
	zoneLimit       *prometheus.Desc
	zoneItemSize    *prometheus.Desc
	zoneRequests    *prometheus.Desc
	zoneFailures    *prometheus.Desc
	zoneSleeps      *prometheus.Desc
	zoneXDomain     *prometheus.Desc
	zoneFailuresAll *prometheus.Desc

	mallocInUse    *prometheus.Desc
	mallocBytes    *prometheus.Desc
	mallocRequests *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &kernelMemoryCollector{
		subsystem: KernelMemorySubsystem,
	})
}

func (c *kernelMemoryCollector) Name() string {
	return c.subsystem
}

func (c *kernelMemoryCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.zoneUsed = buildPrometheusDesc(c.subsystem, "zone_used",
		"Items currently allocated out of this UMA zone. A UMA zone is a kernel pool of "+
			"fixed-size objects (firewall states, sockets, mbufs, ...). Multiply by "+
			"opnsense_kernel_memory_zone_item_size_bytes for the bytes in use. Where the box "+
			"reported the same zone name more than once (one row per NUMA domain, or one per "+
			"instance of a kernel module's zone) the rows are summed into a single series.",
		[]string{"zone"},
	)
	c.zoneFree = buildPrometheusDesc(c.subsystem, "zone_free",
		"Items sitting free in this UMA zone's caches, already charged to the kernel and "+
			"available for immediate reuse. A zone with used climbing and free at zero is "+
			"about to have to ask the VM system for more memory, which is where allocation "+
			"failures start.",
		[]string{"zone"},
	)
	c.zoneLimit = buildPrometheusDesc(c.subsystem, "zone_limit",
		"Configured hard ceiling on items in this UMA zone. ZERO MEANS NO CEILING IS "+
			"CONFIGURED, not a ceiling of zero - verified on a live OPNsense 26.1 firewall, "+
			"where 'pf state keys' reports limit 0 while holding 16275 items. Any saturation "+
			"ratio must therefore skip zones whose limit is 0, e.g. "+
			"opnsense_kernel_memory_zone_used / (opnsense_kernel_memory_zone_limit > 0). "+
			"Where several rows were merged into one series the ceilings are summed, which is "+
			"the correct aggregate ceiling for that zone across the box.",
		[]string{"zone"},
	)
	c.zoneItemSize = buildPrometheusDesc(c.subsystem, "zone_item_size_bytes",
		"Size in bytes of ONE item in this UMA zone - not the zone's total footprint. "+
			"It is a near-constant property of the kernel build; it is exported so bytes can "+
			"be derived from the item counts without hard-coding struct sizes per release.",
		[]string{"zone"},
	)
	c.zoneRequests = buildPrometheusDesc(c.subsystem, "zone_requests_total",
		"Allocation requests made against this UMA zone since boot, successful or not. "+
			"Useful as the denominator for a failure ratio and as the churn rate of the "+
			"underlying resource.",
		[]string{"zone"},
	)
	c.zoneFailures = buildPrometheusDesc(c.subsystem, "zone_failures_total",
		"Allocations this UMA zone could NOT satisfy since boot. A non-zero rate means the "+
			"kernel asked for an object and was refused, and the caller had to give up: on "+
			"'pf states' a connection was not tracked, on 'socket' or 'tcp_inpcb' a connection "+
			"was refused, on an mbuf zone a packet was dropped. Alert on the rate, not the "+
			"level - the counter never resets before a reboot. Two zone families are noisy by "+
			"design and are NOT operator-actionable: the 'N Bucket' zones (UMA's own per-CPU "+
			"cache bucket allocator, which is expected to fail and fall back - all three live "+
			"boxes show large non-zero values) and 'vm pgcache'. Six zones overlap the mbuf "+
			"collector, which reads the separate systemMbuf endpoint: mbuf<->type=mbuf, "+
			"mbuf_packet<->packet, mbuf_cluster<->cluster, mbuf_jumbo_page<->jumbop, "+
			"mbuf_jumbo_9k<->jumbo9, mbuf_jumbo_16k<->jumbo16 (the mbuf collector's "+
			"type=sfbufs has no UMA zone). Those are two independent readings of the same "+
			"kernel counters taken from two endpoints at two different times; treat them as "+
			"corroboration and NEVER sum the two families together, or every mbuf failure is "+
			"counted twice.",
		[]string{"zone"},
	)
	c.zoneSleeps = buildPrometheusDesc(c.subsystem, "zone_sleeps_total",
		"Allocations from this UMA zone that had to BLOCK waiting for memory since boot. "+
			"The softer twin of zone_failures_total: the allocation eventually succeeded, so "+
			"nothing was dropped, but the requesting thread stalled - which on a packet path "+
			"shows up as latency rather than loss. Sleeps rising is the warning that precedes "+
			"failures. Same overlap rule as zone_failures_total: do not sum with "+
			"opnsense_mbuf_sleeps_total.",
		[]string{"zone"},
	)
	c.zoneXDomain = buildPrometheusDesc(c.subsystem, "zone_xdomain_total",
		"Allocations this UMA zone satisfied from a REMOTE NUMA domain since boot, because "+
			"the local domain had nothing free. Not an error - the allocation succeeded - but "+
			"on a NUMA box a rising rate means memory is being touched across the interconnect "+
			"and is a latency, not a correctness, signal. Flat zero on single-domain hardware.",
		[]string{"zone"},
	)
	c.zoneFailuresAll = buildPrometheusDesc(c.subsystem, "zone_failures_all_total",
		"Allocation failures summed across EVERY UMA zone the box reports, including zones "+
			"that have no dedicated panel and zones a future kernel adds. It exists so a "+
			"failure in a zone nobody thought to look at is still visible on one series; use "+
			"it as the catch-all alert and the per-zone series to find the culprit. It "+
			"includes the benign 'N Bucket' and 'vm pgcache' families, which on every live box "+
			"dominate the absolute value - so this counter is only meaningful as a rate, and "+
			"a baseline above zero is normal.",
		nil,
	)

	c.mallocInUse = buildPrometheusDesc(c.subsystem, "malloc_in_use",
		"Live allocations currently held by this kernel malloc type (vmstat -m's InUse). "+
			"Malloc types are variable-size kernel allocations, as distinct from the "+
			"fixed-size UMA zones above; a type whose InUse climbs monotonically over weeks "+
			"of uptime is the shape of a kernel memory leak.",
		[]string{"type"},
	)
	c.mallocBytes = buildPrometheusDesc(c.subsystem, "malloc_bytes",
		"Bytes currently held by this kernel malloc type (vmstat -m's MemUse). Reported in "+
			"bytes by the API despite the OPNsense UI labelling the total 'k'.",
		[]string{"type"},
	)
	c.mallocRequests = buildPrometheusDesc(c.subsystem, "malloc_requests_total",
		"Allocation requests made against this kernel malloc type since boot. There is no "+
			"per-type failure counter in this payload - vmstat -m does not report one - so "+
			"malloc-type exhaustion is inferred from in_use/bytes growth, not observed "+
			"directly. The failure signal lives on the UMA zones above.",
		[]string{"type"},
	)
}

func (c *kernelMemoryCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.zoneUsed
	ch <- c.zoneFree
	ch <- c.zoneLimit
	ch <- c.zoneItemSize
	ch <- c.zoneRequests
	ch <- c.zoneFailures
	ch <- c.zoneSleeps
	ch <- c.zoneXDomain
	ch <- c.zoneFailuresAll
	ch <- c.mallocInUse
	ch <- c.mallocBytes
	ch <- c.mallocRequests
}

func (c *kernelMemoryCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchKernelMemory()
	if err != nil {
		return err
	}

	for _, z := range data.Zones {
		ch <- prometheus.MustNewConstMetric(c.zoneUsed, prometheus.GaugeValue, float64(z.Used), z.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.zoneFree, prometheus.GaugeValue, float64(z.Free), z.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.zoneLimit, prometheus.GaugeValue, float64(z.Limit), z.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.zoneItemSize, prometheus.GaugeValue, float64(z.ItemSizeBytes), z.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.zoneRequests, prometheus.CounterValue, float64(z.Requests), z.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.zoneFailures, prometheus.CounterValue, float64(z.Failures), z.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.zoneSleeps, prometheus.CounterValue, float64(z.Sleeps), z.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.zoneXDomain, prometheus.CounterValue, float64(z.XDomain), z.Name, c.instance)
	}

	// Emitted unconditionally, including on a box that reported no zones at all: a
	// catch-all that disappears when there is nothing to report cannot be alerted on.
	ch <- prometheus.MustNewConstMetric(c.zoneFailuresAll, prometheus.CounterValue, float64(data.ZoneFailuresTotal), c.instance)

	for _, m := range data.MallocTypes {
		ch <- prometheus.MustNewConstMetric(c.mallocInUse, prometheus.GaugeValue, float64(m.InUse), m.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.mallocBytes, prometheus.GaugeValue, float64(m.Bytes), m.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.mallocRequests, prometheus.CounterValue, float64(m.Requests), m.Name, c.instance)
	}

	return nil
}
