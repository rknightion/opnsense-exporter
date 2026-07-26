package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

// torCollector collects circuit and stream telemetry from the os-tor plugin's
// control port. Opt-in (--exporter.enable-tor, default off): each scheduled poll
// costs two extra configd execs (a Ruby script dialing the Tor control port)
// on top of the plugin/setup dependency, per #206.
//
// AGGREGATE ONLY: circuit/stream counts are always grouped by a validated,
// closed status/purpose vocabulary (opnsense.torVocabularyBucket) — never a
// per-circuit or per-stream series (circuit/stream IDs are ephemeral and are
// never even parsed), and destination hosts/.onion hostnames are never read
// into a label or a log line anywhere in this file.
type torCollector struct {
	log *slog.Logger

	controlPortUp                  *prometheus.Desc
	circuits                       *prometheus.Desc
	circuitsByPurpose              *prometheus.Desc
	streams                        *prometheus.Desc
	hiddenServices                 *prometheus.Desc
	hiddenServiceHostnameAvailable *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &torCollector{
		subsystem: TorSubsystem,
	})
}

func (c *torCollector) Name() string { return c.subsystem }

func (c *torCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.controlPortUp = buildPrometheusDesc(c.subsystem, "control_port_up",
		"Whether the Tor control port answered the last circuit and stream query (1 = up, 0 = unreachable/misconfigured)", nil)
	c.circuits = buildPrometheusDesc(c.subsystem, "circuits",
		"Number of Tor circuits by build status (unrecognised status values are bucketed as \"other\")",
		[]string{"status"})
	c.circuitsByPurpose = buildPrometheusDesc(c.subsystem, "circuits_by_purpose",
		"Number of Tor circuits by purpose (unrecognised purpose values are bucketed as \"other\")",
		[]string{"purpose"})
	c.streams = buildPrometheusDesc(c.subsystem, "streams",
		"Number of Tor streams by status (unrecognised status values are bucketed as \"other\"); never labeled by destination",
		[]string{"status"})
	c.hiddenServices = buildPrometheusDesc(c.subsystem, "hidden_services",
		"Number of configured Tor hidden services", nil)
	c.hiddenServiceHostnameAvailable = buildPrometheusDesc(c.subsystem, "hidden_service_hostname_available",
		"Whether a .onion hostname has been provisioned for a configured hidden service (1 = available, 0 = not available); the hostname itself is never exposed",
		[]string{"service"})
}

func (c *torCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		c.controlPortUp, c.circuits, c.circuitsByPurpose, c.streams,
		c.hiddenServices, c.hiddenServiceHostnameAvailable,
	} {
		ch <- d
	}
}

func (c *torCollector) Update(_ context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	circuits, cErr := client.FetchTorCircuits()
	if cErr != nil {
		return cErr
	}
	streams, sErr := client.FetchTorStreams()
	if sErr != nil {
		return sErr
	}
	hidden, hErr := client.FetchTorHiddenServices()
	if hErr != nil {
		return hErr
	}

	// Plugin absent (404 on all three): stay completely silent.
	if !circuits.Present && !streams.Present && !hidden.Present {
		return nil
	}

	if circuits.Present || streams.Present {
		up := 0.0
		if circuits.Up && streams.Up {
			up = 1.0
		}
		ch <- prometheus.MustNewConstMetric(c.controlPortUp, prometheus.GaugeValue, up, c.instance)
	}

	if circuits.Up {
		for status, count := range circuits.ByStatus {
			ch <- prometheus.MustNewConstMetric(c.circuits, prometheus.GaugeValue, float64(count), status, c.instance)
		}
		for purpose, count := range circuits.ByPurpose {
			ch <- prometheus.MustNewConstMetric(c.circuitsByPurpose, prometheus.GaugeValue, float64(count), purpose, c.instance)
		}
	}

	if streams.Up {
		for status, count := range streams.ByStatus {
			ch <- prometheus.MustNewConstMetric(c.streams, prometheus.GaugeValue, float64(count), status, c.instance)
		}
	}

	if hidden.Present {
		ch <- prometheus.MustNewConstMetric(c.hiddenServices, prometheus.GaugeValue, float64(len(hidden.HostnameAvailable)), c.instance)
		for service, available := range hidden.HostnameAvailable {
			v := 0.0
			if available {
				v = 1.0
			}
			ch <- prometheus.MustNewConstMetric(c.hiddenServiceHostnameAvailable, prometheus.GaugeValue, v, service, c.instance)
		}
	}

	return nil
}
