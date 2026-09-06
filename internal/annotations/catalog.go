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
// `opnsense_system_config_last_change_timestamp_seconds` is the epoch of the last configuration
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

	// DefaultOff keeps a kind out of the default push set. It is for an event whose
	// CADENCE, not whose importance, makes it wrong to write org-wide: a pushed
	// annotation is visible on every dashboard, in Explore and beside every alert,
	// so an event refreshing every twenty minutes buries the timeline everywhere at
	// once. `--annotations.kinds` turns it back on for a deployment that wants it.
	//
	// This flag exists to keep the push set and the dashboard's default layer set in
	// agreement (#540): the dashboard's per-kind toggle only ever governed the
	// DERIVED copy, so a kind that is default-off there and pushed here reaches the
	// dashboard anyway through the catch-all tag query, and the toggle looks broken.
	// `grafana/tests/test_annotations.py` fails if the two sides disagree.
	DefaultOff bool

	// UptimeOffsetOf names a metric whose value is a system-uptime reading rather
	// than an epoch, to be added to this Watch's metric to get the instant. The
	// interface attach/reset marker is the one case: the kernel reports it as
	// "uptime at attach or stat reset", so it only becomes an instant once the
	// boot epoch is added to it.
	UptimeOffsetOf string

	// Coalesce merges every candidate that shares this watch's (kind, timestamp)
	// into ONE annotation instead of one per series (#637). It exists for a
	// metric whose labels legitimately fan out to dozens of series that all move
	// at the same instant — a Suricata ruleset sync touches every rule file at
	// once, so without this a single sync proposed one candidate per file,
	// saturating MaxPerCycle and self-inflicting a 429 storm against Grafana on
	// every sync.
	//
	// A coalesced annotation's Text is filled from the COUNT rather than from
	// LabelKeys, so it must contain exactly one %d (the count) followed by one
	// %s (an empty string, or "s", for the plural) — never the per-entity %s
	// this struct's own doc describes. Naming one series out of a group would
	// be arbitrary; the full roster is already on the metric's own labels. Its
	// tags are the base tag and the kind tag only — LabelKeys stays declared
	// on the entry (it is still what identifies the series to detect() and to
	// the dedupe set) but stops feeding the text and tags when coalescing.
	Coalesce bool
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
		Metric: "opnsense_system_config_last_change_timestamp_seconds",
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
		// The pf-side twin of interface-reset above (#580). pf reports its own
		// "counters cleared at" time per interface, so a `pfctl -z` gets a marker on
		// the interface whose counters actually moved, instead of every pf rate()
		// panel showing an unexplained negative delta or plateau.
		//
		// Unlike interface-reset this is an absolute timestamp, not an uptime offset,
		// so it needs no UptimeOffsetOf. It is parsed upstream from a naive,
		// timezone-less string and read as UTC, so the marker can sit off by the
		// box's real offset — it answers "a reset happened around here".
		Metric:    "opnsense_firewall_pf_counters_cleared_timestamp_seconds",
		Kind:      "pf-counter-reset",
		Text:      "pf counters cleared on %s (pfctl -z)",
		LabelKeys: []string{"interface"},
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
		// #637: one Suricata ruleset sync updates every series of this
		// metric at the same instant (62 of them on a live box), so
		// treating each as its own candidate fanned out to one annotation
		// per file against a MaxPerCycle far smaller than that,
		// self-inflicting a rate-limit storm against Grafana on every
		// sync. Coalesce turns that fan-out back into the single "a sync
		// happened" event the annotation is actually for; the per-ruleset
		// breakdown stays available on the metric itself.
		Metric:    "opnsense_ids_ruleset_last_updated_timestamp_seconds",
		Kind:      "ids-ruleset-update",
		Text:      "IDS rulesets updated (%d file%s)",
		LabelKeys: []string{"ruleset"},
		Coalesce:  true,
	},
	{
		Metric:    "opnsense_qfeeds_feed_last_update_timestamp_seconds",
		Kind:      "threat-feed-update",
		Text:      "Threat feed %s updated",
		LabelKeys: []string{"feed"},
		// Q-Feeds refreshes on a much tighter schedule than an IDS ruleset — a
		// live box writes one of these every twenty minutes per feed — which is
		// exactly why the dashboard layer is default-off too.
		DefaultOff: true,
	},
}

// KnownKinds is every event kind in the catalogue, for validating
// `--annotations.kinds` at startup rather than silently writing nothing.
func KnownKinds() []string {
	kinds := make([]string, 0, len(Watches))
	for _, watch := range Watches {
		kinds = append(kinds, watch.Kind)
	}
	return kinds
}

// DefaultOffKinds is the complement of DefaultKinds, for naming them in the flag
// help rather than making an operator diff two lists to find them.
func DefaultOffKinds() []string {
	kinds := make([]string, 0, len(Watches))
	for _, watch := range Watches {
		if watch.DefaultOff {
			kinds = append(kinds, watch.Kind)
		}
	}
	return kinds
}

// DefaultKinds is what an unconfigured deployment writes: the catalogue minus the
// DefaultOff entries.
func DefaultKinds() []string {
	kinds := make([]string, 0, len(Watches))
	for _, watch := range Watches {
		if !watch.DefaultOff {
			kinds = append(kinds, watch.Kind)
		}
	}
	return kinds
}

// enabledKindSet resolves the configured kinds into a lookup set. An empty list is
// "unconfigured", which is the default set — NOT "write nothing", because a
// deployment that wants nothing written turns `--annotations.enabled` off instead.
func enabledKindSet(configured []string) map[string]bool {
	kinds := configured
	if len(kinds) == 0 {
		kinds = DefaultKinds()
	}
	set := make(map[string]bool, len(kinds))
	for _, kind := range kinds {
		set[kind] = true
	}
	return set
}

// BaseTag is on every annotation this exporter writes, and is what a dashboard
// queries to show them all. Kept deliberately short and product-scoped: a tag
// query is the only way back to these annotations.
const BaseTag = "opnsense2otel"
