package collector

import (
	"context"
	"log/slog"
	"strconv"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

type gatewaysCollector struct {
	log                  *slog.Logger
	info                 *prometheus.Desc
	monitor              *prometheus.Desc
	rtt                  *prometheus.Desc
	rttd                 *prometheus.Desc
	rttLow               *prometheus.Desc
	rttHigh              *prometheus.Desc
	lossPercentage       *prometheus.Desc
	lossLow              *prometheus.Desc
	lossHigh             *prometheus.Desc
	interval             *prometheus.Desc
	period               *prometheus.Desc
	timeout              *prometheus.Desc
	status               *prometheus.Desc
	forceDown            *prometheus.Desc
	virtual              *prometheus.Desc
	dynamic              *prometheus.Desc
	priority             *prometheus.Desc
	thresholdParseErrors *prometheus.Desc

	// killStates/killStatesPriority: whether pf states are killed when this
	// gateway is marked down (#584). Same label surface and unconditional
	// (Enabled-independent) emission convention as forceDown/virtual/dynamic
	// above -- see Update()'s doc comment on why they are not presence-gated.
	killStates               *prometheus.Desc
	killStatesPriority       *prometheus.Desc
	thresholdParseErrorCount atomic.Uint64

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances,
		&gatewaysCollector{
			subsystem: GatewaysSubsystem,
		},
	)
}

func (c *gatewaysCollector) Name() string {
	return c.subsystem
}

func (c *gatewaysCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.info = buildPrometheusDesc(c.subsystem, "info",
		"Information of the gateway",
		[]string{"name", "description", "device", "protocol", "enabled", "weight", "interface", "upstream"},
	)
	c.monitor = buildPrometheusDesc(
		c.subsystem, "monitor_info",
		"Gateway monitoring configuration",
		[]string{"name", "enabled", "no_route", "address"},
	)
	c.rtt = buildPrometheusDesc(
		c.subsystem, "rtt_milliseconds",
		"RTT is the average (mean) of the round trip time in milliseconds by name and address",
		[]string{"name", "address"},
	)
	c.rttd = buildPrometheusDesc(
		c.subsystem, "rttd_milliseconds",
		"RTTd is the standard deviation of the round trip time in milliseconds by name and address",
		[]string{"name", "address"},
	)
	c.rttLow = buildPrometheusDesc(
		c.subsystem, "rtt_low_milliseconds",
		"Gateway low latency threshold",
		[]string{"name", "address"},
	)
	c.rttHigh = buildPrometheusDesc(
		c.subsystem, "rtt_high_milliseconds",
		"Gateway high latency threshold",
		[]string{"name", "address"},
	)
	c.lossPercentage = buildPrometheusDesc(
		c.subsystem, "loss_percentage",
		"The current gateway loss percentage by name and address",
		[]string{"name", "address"},
	)
	c.lossLow = buildPrometheusDesc(
		c.subsystem, "loss_low_percentage",
		"Gateway low packet loss threshold",
		[]string{"name", "address"},
	)
	c.lossHigh = buildPrometheusDesc(
		c.subsystem, "loss_high_percentage",
		"Gateway high packet loss threshold",
		[]string{"name", "address"},
	)
	c.interval = buildPrometheusDesc(
		c.subsystem, "probe_interval_seconds",
		"Gateway probe interval",
		[]string{"name", "address"},
	)
	c.period = buildPrometheusDesc(
		c.subsystem, "probe_period_seconds",
		"Gateway probe period",
		[]string{"name", "address"},
	)
	c.timeout = buildPrometheusDesc(
		c.subsystem, "probe_timeout_seconds",
		"Gateway probe timeout",
		[]string{"name", "address"},
	)
	c.status = buildPrometheusDesc(c.subsystem, "status",
		"Status of the gateway by name and address (0 = Offline, 1 = Online, 2 = Unknown, 3 = Pending, 4 = Packetloss, 5 = Latency, 6 = Offline (forced))",
		[]string{"name", "address", "default_gateway"},
	)
	c.forceDown = buildPrometheusDesc(
		c.subsystem, "force_down",
		"1 if the gateway is administratively forced down, 0 otherwise",
		[]string{"name", "address"},
	)
	c.virtual = buildPrometheusDesc(
		c.subsystem, "virtual",
		"1 if the gateway is virtual, 0 otherwise",
		[]string{"name", "address"},
	)
	c.dynamic = buildPrometheusDesc(
		c.subsystem, "dynamic",
		"1 if the gateway is dynamically configured, 0 otherwise",
		[]string{"name", "address"},
	)
	c.priority = buildPrometheusDesc(
		c.subsystem, "priority",
		"Gateway priority (lower value = higher priority)",
		[]string{"name", "address"},
	)
	c.thresholdParseErrors = buildPrometheusDesc(
		c.subsystem,
		"threshold_parse_errors_total",
		"Total number of non-empty gateway threshold and probe values that could not be parsed and were omitted from the corresponding threshold series; intentionally blank values are not counted.",
		nil,
	)
	c.killStates = buildPrometheusDesc(
		c.subsystem, "monitor_killstates",
		"1 if pf states are killed for this gateway when its monitor marks it down, 0 otherwise. "+
			"Determines what a failover actually does to already-established connections through "+
			"this gateway.",
		[]string{"name", "address"},
	)
	c.killStatesPriority = buildPrometheusDesc(
		c.subsystem, "monitor_killstates_priority",
		"1 if this gateway's state-killing on down is priority-scoped, 0 otherwise. Sibling "+
			"configuration to monitor_killstates.",
		[]string{"name", "address"},
	)
}

func (c *gatewaysCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.info
	ch <- c.monitor
	ch <- c.rtt
	ch <- c.rttd
	ch <- c.rttLow
	ch <- c.rttHigh
	ch <- c.lossPercentage
	ch <- c.lossLow
	ch <- c.lossHigh
	ch <- c.interval
	ch <- c.period
	ch <- c.timeout
	ch <- c.status
	ch <- c.forceDown
	ch <- c.virtual
	ch <- c.dynamic
	ch <- c.priority
	ch <- c.thresholdParseErrors
	ch <- c.killStates
	ch <- c.killStatesPriority
}

// emitThreshold parses a string gateway threshold/probe value (e.g. latency or
// loss limits, probe interval/period/timeout) and emits it as a gauge. An empty
// or unparseable value is skipped rather than emitted as a misleading 0, since
// these OPNsense fields are configuration strings that are legitimately blank
// when a gateway has no monitor configuration set. Unparseable values are
// counted and warned so an omitted series is observable at the default log level.
func (c *gatewaysCollector) emitThreshold(ch chan<- prometheus.Metric, desc *prometheus.Desc, field, raw, name, monitor string) {
	if raw == "" {
		c.log.Debug("skipping gateway threshold metric: empty value", "gateway", name, "field", field)
		return
	}
	f64, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		c.thresholdParseErrorCount.Add(1)
		c.log.Warn("skipping gateway threshold metric: unparseable value",
			"gateway", name, "field", field, "value", raw, "error", err)
		return
	}
	ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, f64, name, monitor, c.instance)
}

func (c *gatewaysCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchGateways()
	if err != nil {
		return err
	}
	for _, v := range data.Gateways {
		monitorEnabledFloat := 1.0
		if !v.MonitorEnabled {
			monitorEnabledFloat = 0.0
		}
		interfaceEnabledFloat := 1.0
		if !v.Enabled {
			interfaceEnabledFloat = 0.0
		}

		ch <- prometheus.MustNewConstMetric(
			c.info,
			prometheus.GaugeValue,
			interfaceEnabledFloat,
			v.Name,
			v.Description,
			// device = the OS network device (JSON "if", e.g. pppoe0), held by the
			// misleadingly-named Interface struct field. interface = the OPNsense
			// interface assignment (JSON "interface", e.g. opt7), held by
			// HardwareInterface. Verified against a live OPNsense 26.1 box.
			v.Interface,
			v.IPProtocol,
			strconv.FormatBool(v.Enabled),
			v.Weight,
			v.HardwareInterface,
			strconv.FormatBool(v.Upstream),
			c.instance,
		)

		forceDownFloat := 0.0
		if v.ForceDown {
			forceDownFloat = 1.0
		}
		ch <- prometheus.MustNewConstMetric(
			c.forceDown,
			prometheus.GaugeValue,
			forceDownFloat,
			v.Name,
			v.Gateway,
			c.instance,
		)

		virtualFloat := 0.0
		if v.Virtual {
			virtualFloat = 1.0
		}
		ch <- prometheus.MustNewConstMetric(
			c.virtual,
			prometheus.GaugeValue,
			virtualFloat,
			v.Name,
			v.Gateway,
			c.instance,
		)

		dynamicFloat := 0.0
		if v.Dynamic {
			dynamicFloat = 1.0
		}
		ch <- prometheus.MustNewConstMetric(
			c.dynamic,
			prometheus.GaugeValue,
			dynamicFloat,
			v.Name,
			v.Gateway,
			c.instance,
		)

		if v.Priority != "" {
			priorityFloat, err := strconv.ParseFloat(v.Priority, 64)
			if err != nil {
				c.log.Debug("skipping gateway priority metric: unparseable value",
					"gateway", v.Name, "priority", v.Priority, "error", err)
			} else {
				ch <- prometheus.MustNewConstMetric(
					c.priority,
					prometheus.GaugeValue,
					priorityFloat,
					v.Name,
					v.Gateway,
					c.instance,
				)
			}
		} else {
			c.log.Debug("skipping gateway priority metric: empty value", "gateway", v.Name)
		}

		// monitor_killstates/monitor_killstates_priority (#584): emitted
		// unconditionally per gateway, same as force_down/virtual/dynamic
		// above and for the same reason -- both are BooleanField config
		// values with no legitimate "absent" state distinct from a
		// deliberately-unset false (the model carries no third state), and
		// the "== \"1\"" parse above already turns a genuinely missing/null
		// wire value into the safe false default rather than a fabricated
		// true. Not gated on v.Enabled: a disabled gateway still has a real
		// (if inert) kill-states configuration.
		killStatesFloat := 0.0
		if v.MonitorKillStates {
			killStatesFloat = 1.0
		}
		ch <- prometheus.MustNewConstMetric(
			c.killStates,
			prometheus.GaugeValue,
			killStatesFloat,
			v.Name,
			v.Gateway,
			c.instance,
		)
		killStatesPriorityFloat := 0.0
		if v.MonitorKillStatesPriority {
			killStatesPriorityFloat = 1.0
		}
		ch <- prometheus.MustNewConstMetric(
			c.killStatesPriority,
			prometheus.GaugeValue,
			killStatesPriorityFloat,
			v.Name,
			v.Gateway,
			c.instance,
		)

		if v.Enabled {
			ch <- prometheus.MustNewConstMetric(
				c.monitor,
				prometheus.GaugeValue,
				monitorEnabledFloat,
				v.Name,
				strconv.FormatBool(v.MonitorEnabled),
				strconv.FormatBool(v.MonitorNoRoute),
				v.Monitor,
				c.instance,
			)
			// The API reports a real status independent of monitoring, so emit
			// it for every enabled gateway — not only monitor-enabled ones.
			// Otherwise a default gateway with monitoring disabled (a common
			// PPPoE/DHCPv6-PD pattern) has no opnsense_gateways_status series at
			// all, and the OPNsenseGatewayDown alert can never fire for it (#77).
			ch <- prometheus.MustNewConstMetric(
				c.status,
				prometheus.GaugeValue,
				float64(v.Status),
				v.Name,
				v.Monitor,
				strconv.FormatBool(v.DefaultGateway),
				c.instance,
			)
			if v.MonitorEnabled {
				if v.Delay >= 0 {
					ch <- prometheus.MustNewConstMetric(
						c.rtt,
						prometheus.GaugeValue,
						v.Delay,
						v.Name,
						v.Monitor,
						c.instance,
					)
				}
				if v.StdDev >= 0 {
					ch <- prometheus.MustNewConstMetric(
						c.rttd,
						prometheus.GaugeValue,
						v.StdDev,
						v.Name,
						v.Monitor,
						c.instance,
					)
				}
				c.emitThreshold(ch, c.rttLow, "latencylow", v.LatencyLow, v.Name, v.Monitor)
				c.emitThreshold(ch, c.rttHigh, "latencyhigh", v.LatencyHigh, v.Name, v.Monitor)
				if v.Loss >= 0 {
					ch <- prometheus.MustNewConstMetric(
						c.lossPercentage,
						prometheus.GaugeValue,
						v.Loss,
						v.Name,
						v.Monitor,
						c.instance,
					)
				}
				c.emitThreshold(ch, c.lossLow, "losslow", v.LossLow, v.Name, v.Monitor)
				c.emitThreshold(ch, c.lossHigh, "losshigh", v.LossHigh, v.Name, v.Monitor)
				c.emitThreshold(ch, c.interval, "interval", v.Interval, v.Name, v.Monitor)
				c.emitThreshold(ch, c.period, "time_period", v.TimePeriod, v.Name, v.Monitor)
				c.emitThreshold(ch, c.timeout, "loss_interval", v.LossInterval, v.Name, v.Monitor)
			}
		}
	}
	ch <- prometheus.MustNewConstMetric(
		c.thresholdParseErrors,
		prometheus.CounterValue,
		float64(c.thresholdParseErrorCount.Load()),
		c.instance,
	)
	return nil
}
