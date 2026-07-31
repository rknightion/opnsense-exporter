package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type aliasCollector struct {
	log *slog.Logger

	tablesTotal       *prometheus.Desc
	tableEntries      *prometheus.Desc
	tableEntriesUsed  *prometheus.Desc
	tableEntriesLimit *prometheus.Desc
	tableEvaluations  *prometheus.Desc
	tablePackets      *prometheus.Desc
	tableBytes        *prometheus.Desc
	tableUpdated      *prometheus.Desc

	subsystem      string
	instance       string
	detailsEnabled bool
}

func init() {
	collectorInstances = append(collectorInstances, &aliasCollector{
		subsystem: AliasSubsystem,
	})
}

func (c *aliasCollector) Name() string { return c.subsystem }

func (c *aliasCollector) SetDetailsEnabled(enabled bool) {
	c.detailsEnabled = enabled
}

func (c *aliasCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	tableLabels := []string{"table"}

	c.tablesTotal = buildPrometheusDesc(c.subsystem, "tables_total",
		"Total number of pf alias tables", nil)
	c.tableEntries = buildPrometheusDesc(c.subsystem, "table_entries",
		"Current number of entries in this pf alias table", tableLabels)
	c.tableEntriesUsed = buildPrometheusDesc(c.subsystem, "table_entries_used",
		"Number of pf table-entries slots currently in use (global)", nil)
	c.tableEntriesLimit = buildPrometheusDesc(c.subsystem, "table_entries_limit",
		"Maximum number of pf table-entries slots (global)", nil)
	c.tableEvaluations = buildPrometheusDesc(c.subsystem, "table_evaluations_total",
		"Packet evaluations against this alias table since last reset",
		[]string{"table", "result"})
	c.tablePackets = buildPrometheusDesc(c.subsystem, "table_packets_total",
		"Packets matched against this alias table since last reset",
		[]string{"table", "direction", "action"})
	c.tableBytes = buildPrometheusDesc(c.subsystem, "table_bytes_total",
		"Bytes matched against this alias table since last reset",
		[]string{"table", "direction", "action"})
	// #583. NOT gated behind --exporter.enable-alias-details: the detail flag
	// exists to hold back the 10 pf counter series per table, and this is one
	// low-cardinality gauge that is the sole signal for a whole failure mode.
	// Emitted alongside table_entries, which is on by default for the same
	// reason.
	c.tableUpdated = buildPrometheusDesc(c.subsystem, "table_updated_timestamp_seconds",
		"Unix timestamp of the last time this alias table's persisted content was written - i.e. when a DNS- or URL-backed alias (a threat feed, say) last refreshed. A feed that silently stops refreshing is a security control failing open, and no other metric can see it: the table still holds its stale rows, so table_entries looks healthy. Only emitted for tables that HAVE persisted content; a static host/network alias has no refresh cycle and emits no series rather than a misleading epoch 0. Derived from the file mtime as a timezone-less local timestamp and read as UTC, so the absolute value can be off by the firewall's UTC offset - compare ages, not wall clocks.",
		tableLabels)
}

func (c *aliasCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.tablesTotal
	ch <- c.tableEntries
	ch <- c.tableEntriesUsed
	ch <- c.tableEntriesLimit
	ch <- c.tableEvaluations
	ch <- c.tablePackets
	ch <- c.tableBytes
	ch <- c.tableUpdated
}

func (c *aliasCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchAliasTables()
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(c.tablesTotal, prometheus.GaugeValue,
		float64(len(data.Tables)), c.instance)
	ch <- prometheus.MustNewConstMetric(c.tableEntriesUsed, prometheus.GaugeValue,
		data.Used, c.instance)
	ch <- prometheus.MustNewConstMetric(c.tableEntriesLimit, prometheus.GaugeValue,
		data.Limit, c.instance)

	for _, tb := range data.Tables {
		ch <- prometheus.MustNewConstMetric(c.tableEntries, prometheus.GaugeValue,
			tb.Entries, tb.Name, c.instance)

		if tb.HasUpdated {
			ch <- prometheus.MustNewConstMetric(c.tableUpdated, prometheus.GaugeValue,
				tb.UpdatedTimestamp, tb.Name, c.instance)
		}

		if c.detailsEnabled {
			ch <- prometheus.MustNewConstMetric(c.tableEvaluations, prometheus.CounterValue,
				tb.EvalMatch, tb.Name, "match", c.instance)
			ch <- prometheus.MustNewConstMetric(c.tableEvaluations, prometheus.CounterValue,
				tb.EvalNomatch, tb.Name, "nomatch", c.instance)
			ch <- prometheus.MustNewConstMetric(c.tablePackets, prometheus.CounterValue,
				tb.InBlockP, tb.Name, "in", "block", c.instance)
			ch <- prometheus.MustNewConstMetric(c.tablePackets, prometheus.CounterValue,
				tb.InPassP, tb.Name, "in", "pass", c.instance)
			ch <- prometheus.MustNewConstMetric(c.tablePackets, prometheus.CounterValue,
				tb.OutBlockP, tb.Name, "out", "block", c.instance)
			ch <- prometheus.MustNewConstMetric(c.tablePackets, prometheus.CounterValue,
				tb.OutPassP, tb.Name, "out", "pass", c.instance)
			ch <- prometheus.MustNewConstMetric(c.tableBytes, prometheus.CounterValue,
				tb.InBlockB, tb.Name, "in", "block", c.instance)
			ch <- prometheus.MustNewConstMetric(c.tableBytes, prometheus.CounterValue,
				tb.InPassB, tb.Name, "in", "pass", c.instance)
			ch <- prometheus.MustNewConstMetric(c.tableBytes, prometheus.CounterValue,
				tb.OutBlockB, tb.Name, "out", "block", c.instance)
			ch <- prometheus.MustNewConstMetric(c.tableBytes, prometheus.CounterValue,
				tb.OutPassB, tb.Name, "out", "pass", c.instance)
		}
	}

	return nil
}
