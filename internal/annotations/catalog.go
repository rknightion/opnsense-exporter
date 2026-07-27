// Package annotations pushes OPNsense change events into Grafana's own annotation
// store, so an operator can see WHY a graph stepped without having to build a
// datasource annotation query for every event class first (#421).
//
// It is opt-in (`--annotations.enabled`) because it is the exporter's only outbound
// write: everything else here is read-only polling.
//
// # How an event is detected
//
// Every event this package emits comes from a metric whose VALUE is an instant —
// `opnsense_system_config_last_change` is the epoch of the last configuration
// change, not a count of them. So detection is a diff, not a parse: gather the
// watched families from the same registry `/metrics` replays, and emit when a
// series' value changes to a new non-zero instant. The annotation is then stamped
// at that instant rather than at the moment of detection, which is what makes it
// correct on a cold-tier collector that may not notice for fifteen minutes.
//
// Reading the registry rather than instrumenting each collector is deliberate:
// there is one detector for all event classes, no collector knows this package
// exists, and a new instant-valued metric becomes an annotation by adding a row to
// the table below.
package annotations

// Watch is one annotation-emitting metric.
//
// LabelKeys are the metric's own labels that identify WHICH thing the event
// happened to, and they become annotation tags. They must be closed vocabularies:
// a tag is indexed and queryable across dashboards, so an address, a hostname or
// operator free text must never be one.
type Watch struct {
	Metric    string
	Kind      string // stable, low-cardinality event name; becomes a tag
	Text      string // annotation text; %s is filled from LabelKeys, in order
	LabelKeys []string

	// UptimeOffsetOf names a metric whose value is a system-uptime reading rather
	// than an epoch, to be added to this Watch's metric to get the instant. The
	// interface attach/reset marker is the one case: the kernel reports it as
	// "uptime at attach or stat reset", so it only becomes an instant once the
	// boot epoch is added to it.
	UptimeOffsetOf string
}

// BootMetric is the epoch the box booted, and the anchor for any uptime-relative
// marker. Added in #421 precisely so an instant does not have to be derived from
// `time() - uptime`, which drifts between evaluations.
const BootMetric = "opnsense_system_boot_timestamp_seconds"

// Watches is the emitted-event catalogue. It is deliberately the same set as the
// dashboard's own annotation layers (`grafana/annotations.py`): the dashboard can
// derive these events from the metrics directly, and this package pushes them so
// they are also available to other dashboards, to Explore, and to anything else
// reading Grafana's annotation store. `grafana/tests/test_annotations.py` fails if
// the two sets drift apart.
//
// Only genuine events are here. A heartbeat (`*_last_poll_*`, a per-peer WireGuard
// handshake) advances continuously and would emit an annotation per poll forever;
// a future-dated value (`*_next_update_*`) would post an annotation ahead of now.
// The reasons for every exclusion live in `NOT_ANNOTATED` in the Python module.
var Watches = []Watch{
	{
		Metric: BootMetric,
		Kind:   "reboot",
		Text:   "OPNsense rebooted",
	},
	{
		Metric: "opnsense_system_config_last_change",
		Kind:   "config-change",
		Text:   "OPNsense configuration changed",
	},
	{
		Metric:         "opnsense_interfaces_attach_or_statistics_reset_uptime_seconds",
		UptimeOffsetOf: BootMetric,
		Kind:           "interface-reset",
		Text:           "Interface %s attached or its counters were reset",
		LabelKeys:      []string{"interface"},
	},
	{
		Metric: "opnsense_snapshots_active_created_timestamp_seconds",
		Kind:   "upgrade",
		Text:   "Boot environment created (OPNsense upgrade)",
	},
	{
		Metric:    "opnsense_acme_certificate_last_update_timestamp_seconds",
		Kind:      "certificate-renewal",
		Text:      "ACME certificate %s issued or renewed",
		LabelKeys: []string{"name"},
	},
	{
		Metric: "opnsense_firewall_geoip_last_update_timestamp_seconds",
		Kind:   "geoip-update",
		Text:   "GeoIP database updated",
	},
	{
		Metric: "opnsense_nginx_config_load_timestamp_seconds",
		Kind:   "nginx-reload",
		Text:   "nginx configuration reloaded",
	},
	{
		Metric:    "opnsense_dyndns_account_last_update_timestamp_seconds",
		Kind:      "public-ip-change",
		Text:      "DynDNS updated the public address via %s",
		LabelKeys: []string{"service"},
	},
	{
		Metric:    "opnsense_ids_ruleset_last_updated_timestamp_seconds",
		Kind:      "ids-ruleset-update",
		Text:      "IDS ruleset %s updated",
		LabelKeys: []string{"ruleset"},
	},
	{
		Metric:    "opnsense_qfeeds_feed_last_update_timestamp_seconds",
		Kind:      "threat-feed-update",
		Text:      "Threat feed %s updated",
		LabelKeys: []string{"feed"},
	},
}

// BaseTag is on every annotation this exporter writes, and is what a dashboard
// queries to show them all. Kept deliberately short and product-scoped: a tag
// query is the only way back to these annotations.
const BaseTag = "opnsense-exporter"
