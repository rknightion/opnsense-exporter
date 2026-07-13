package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

// clamavCollector surfaces ClamAV (os-clamav plugin) engine version and
// signature-database freshness. Running state is already covered by the
// services collector, so this stays focused on the data that lets an operator
// alert on "signatures older than N hours" (a broken/unreachable freshclam
// mirror is otherwise a silent failure mode).
type clamavCollector struct {
	log *slog.Logger

	info             *prometheus.Desc
	signaturesTotal  *prometheus.Desc
	dbVersion        *prometheus.Desc
	dbBuiltTimestamp *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &clamavCollector{
		subsystem: ClamAVSubsystem,
	})
}

func (c *clamavCollector) Name() string {
	return c.subsystem
}

func (c *clamavCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.info = buildPrometheusDesc(c.subsystem, "version_info",
		"ClamAV engine version information (value is always 1; use labels)",
		[]string{"version"})

	c.signaturesTotal = buildPrometheusDesc(c.subsystem, "signatures",
		"Total number of ClamAV virus signatures loaded across all databases (0 both when freshclam has never run and when the field is unavailable)",
		nil)

	c.dbVersion = buildPrometheusDesc(c.subsystem, "signature_db_version",
		"Version number of a ClamAV signature database (increments on every freshclam update), by database",
		[]string{"db"})

	c.dbBuiltTimestamp = buildPrometheusDesc(c.subsystem, "signature_db_built_timestamp_seconds",
		"Unix timestamp of when a ClamAV signature database was built, from the freshclam build metadata, by database. Absent when the build-date fragment could not be parsed.",
		[]string{"db"})
}

func (c *clamavCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.info
	ch <- c.signaturesTotal
	ch <- c.dbVersion
	ch <- c.dbBuiltTimestamp
}

func (c *clamavCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchClamAVVersion()
	if err != nil {
		return err
	}

	// os-clamav absent → Present=false; stay silent (#204, mirrors the ACME/
	// SMART/DynDNS plugin-gated convention).
	if !data.Present {
		return nil
	}

	ch <- prometheus.MustNewConstMetric(c.info, prometheus.GaugeValue, 1, data.EngineVersion, c.instance)

	if data.HasTotalSignatures {
		ch <- prometheus.MustNewConstMetric(c.signaturesTotal, prometheus.GaugeValue, float64(data.TotalSignatures), c.instance)
	}

	for _, db := range data.Databases {
		ch <- prometheus.MustNewConstMetric(c.dbVersion, prometheus.GaugeValue, float64(db.Version), db.Name, c.instance)

		if db.BuiltTimestamp > 0 {
			ch <- prometheus.MustNewConstMetric(c.dbBuiltTimestamp, prometheus.GaugeValue, db.BuiltTimestamp, db.Name, c.instance)
		}
	}

	return nil
}
