package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

type cronCollector struct {
	log        *slog.Logger
	jobsStatus *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &cronCollector{
		subsystem: CronTableSubsystem,
	})
}

func (c *cronCollector) Name() string {
	return c.subsystem
}

func (c *cronCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	// uuid (the stable OPNsense config row id) is included so two cron rows
	// that share schedule/description/command/origin — e.g. a job cloned and
	// its original disabled — don't collapse to the same label tuple and fail
	// the whole scrape (#81).
	c.jobsStatus = buildPrometheusDesc(c.subsystem, "job_status",
		"Cron job status by name and description (1 = enabled, 0 = disabled)",
		[]string{"uuid", "schedule", "description", "command", "origin"},
	)
}

func (c *cronCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.jobsStatus
}

func (c *cronCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	crons, err := client.FetchCronTable()
	if err != nil {
		return err
	}
	for _, cron := range crons.Cron {
		ch <- prometheus.MustNewConstMetric(
			c.jobsStatus,
			prometheus.GaugeValue,
			float64(cron.Status),
			cron.UUID,
			cron.Schedule,
			cron.Description,
			cron.Command,
			cron.Origin,
			c.instance,
		)
	}
	return nil
}
