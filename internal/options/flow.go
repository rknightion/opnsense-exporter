package options

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/kingpin/v2"
)

var (
	// Default ON, unlike most opt-in features. Phase 1 opens no socket and adds no
	// dependency: it derives volume counters from documents the exporter has already
	// received and parsed, at the cost of one map insert each. Defaulting it off
	// would ship a metric family that is absent on every deployment until someone
	// finds the flag — the same failure the flow DNS cache was cut for. The part
	// that genuinely warrants opt-in is phase 2's unauthenticated NetFlow listener,
	// which stays behind --flow.netflow.enabled.
	flowEnabled = kingpin.Flag(
		"flow.enabled",
		"Enable flow rollups: bounded byte and packet volume counters derived from flow records. "+
			"Costs nothing where no flow source is configured - the metrics are simply silent, like "+
			"log_events without the syslog receiver. Set --exporter.disable-flow to remove the "+
			"collector entirely.",
	).Envar("OPNSENSE_EXPORTER_FLOW_ENABLED").Default("true").Bool()

	flowZenarmor = kingpin.Flag(
		"flow.zenarmor",
		"Derive flow records from the Zenarmor receiver's conn documents. Adds no new log records "+
			"to Loki: the conn document ships exactly as before and this only feeds the metric "+
			"rollup. Requires --logs.zenarmor.enabled to produce anything.",
	).Envar("OPNSENSE_EXPORTER_FLOW_ZENARMOR").Default("true").Bool()

	// topN bounds the EMITTED series; maxKeys bounds the LIVE map. They are separate
	// bounds and neither substitutes for the other — see internal/flow/rollup.go.
	//
	// Sized from the live corpus: 24 app_category values across ~5 interfaces, 4
	// directions, ~4 transports, 3 actions and 4 scopes is ~24,000 combinations in
	// theory and 500-2,000 occupied in practice. 1,000 emits essentially everything
	// real while still bounding the family; 2,500 caps the live map just above
	// realistic occupancy, so novelty is bounded without steady-state traffic ever
	// being folded.
	flowTopN = kingpin.Flag(
		"flow.top-n",
		"Maximum flow series emitted per scrape. Everything beyond folds into a single __other__ "+
			"series per source, so the family still sums exactly at any limit. 0 emits every tracked "+
			"combination.",
	).Envar("OPNSENSE_EXPORTER_FLOW_TOP_N").Default("1000").Int()

	flowMaxKeys = kingpin.Flag(
		"flow.max-keys",
		"Maximum distinct label combinations the flow accumulator tracks in memory. A separate "+
			"bound from --flow.top-n: this caps memory between scrapes, that caps emitted series. "+
			"Combinations first seen at the cap fold into __other__ and are counted by "+
			"opnsense_flow_rollup_capped_total. 0 is unbounded.",
	).Envar("OPNSENSE_EXPORTER_FLOW_MAX_KEYS").Default("2500").Int()

	// The NetFlow lane is opt-in, and stays opt-in even though --flow.enabled is not.
	// The difference is real rather than stylistic: the Zenarmor lane derives records
	// from documents the exporter already receives, while this one opens a UDP socket
	// that anything on the network can write to.
	flowNetflowEnabled = kingpin.Flag(
		"flow.netflow.enabled",
		"Enable the NetFlow v5/v9 receiver. Opens an UNAUTHENTICATED UDP socket: NetFlow has no "+
			"authentication of any kind, so restrict it with --flow.netflow.allowed-peers or by "+
			"firewalling the port. Requires --flow.enabled.",
	).Envar("OPNSENSE_EXPORTER_FLOW_NETFLOW_ENABLED").Default("false").Bool()

	flowNetflowListen = kingpin.Flag(
		"flow.netflow.listen",
		"Address the NetFlow receiver binds, host:port. Bound eagerly at startup, so a port "+
			"already in use is a startup error rather than a receiver that is silently never there.",
	).Envar("OPNSENSE_EXPORTER_FLOW_NETFLOW_LISTEN").Default(":2055").String()

	flowNetflowPeers = kingpin.Flag(
		"flow.netflow.allowed-peers",
		"CIDR allowlist of exporters permitted to send flow records, repeatable. Empty means "+
			"accept from anyone, which is a deliberate decision to trust the network rather than a "+
			"default to drift into: anything that can reach the port can inject flow records.",
	).Envar("OPNSENSE_EXPORTER_FLOW_NETFLOW_ALLOWED_PEERS").Strings()

	// ng_netflow's ifIndex is a 1-based counter over ifinfo output, NOT an OS or SNMP
	// index, and adding or removing ANY interface renumbers everything (#346). The
	// exporter derives the map from the API, but that derivation cannot be proven to
	// reproduce ifinfo's ordering on every box, and a WRONG interface label is worse
	// than a missing one -- so an operator who has read the mapping off their own box
	// can pin it here and win outright.
	flowNetflowIfIndexMap = kingpin.Flag(
		"flow.netflow.ifindex-map",
		"Override the derived NetFlow ifIndex-to-device map, as comma-separated index=device "+
			"pairs (e.g. \"1=ixl0,5=igb0,13=ixl0_vlan50\"). Entries listed here beat the derived "+
			"map; indices not listed still use it. Read yours off the box with: "+
			"ngctl list | grep netflow.",
	).Envar("OPNSENSE_EXPORTER_FLOW_NETFLOW_IFINDEX_MAP").Default("").String()

	// Correlation joins the two sources' view of one conversation. It is a pass-through
	// when only one source is configured, so the no-second-source deployment pays
	// nothing; turning it off makes NetFlow emit one log per raw fragment (mean 3.75 per
	// connection) instead of one collapsed record.
	flowCorrelate = kingpin.Flag(
		"flow.correlate",
		"Correlate NetFlow fragments and Zenarmor conn documents into one merged flow record per "+
			"connection-window. A pass-through when only one source is present. Off emits NetFlow "+
			"records raw and per-fragment.",
	).Envar("OPNSENSE_EXPORTER_FLOW_CORRELATE").Default("true").Bool()

	flowCorrelateWindow = kingpin.Flag(
		"flow.correlate.window",
		"How long the correlator holds a connection-window before emitting. Also the maximum a flow "+
			"log is delayed. NetFlow export lag runs to ~30m for long flows (#346), so a flow whose "+
			"records straddle the window emits a partial per window rather than one joined record.",
	).Envar("OPNSENSE_EXPORTER_FLOW_CORRELATE_WINDOW").Default("3m").Duration()

	flowCorrelateMaxEntries = kingpin.Flag(
		"flow.correlate.max-entries",
		"Hard cap on live correlator entries. At the cap the oldest is force-emitted (never "+
			"dropped) and counted. The NetFlow ingress is unauthenticated, so this bounds memory "+
			"against a flood. 0 is unbounded (unwise with the listener on).",
	).Envar("OPNSENSE_EXPORTER_FLOW_CORRELATE_MAX_ENTRIES").Default("50000").Int()

	flowLogMode = kingpin.Flag(
		"flow.log-mode",
		"Flow log emission: \"per_flow\" ships one OTLP log record per correlated flow on the shared "+
			"log pipeline; \"off\" ships none while still deriving all metrics. Zenarmor conn documents "+
			"ship on their own lane regardless.",
	).Envar("OPNSENSE_EXPORTER_FLOW_LOG_MODE").Default("per_flow").Enum("per_flow", "off")

	flowMaxLogsPerWindow = kingpin.Flag(
		"flow.max-logs-per-window",
		"Cap on flow log records shipped per minute; excess is TRUNCATED (never sampled) and counted. "+
			"A flood guard on the unauthenticated NetFlow ingress. 0 is unlimited. Metrics are never "+
			"truncated.",
	).Envar("OPNSENSE_EXPORTER_FLOW_MAX_LOGS_PER_WINDOW").Default("0").Int()

	// Opt-in because the host label is unbounded cardinality — one series per internal
	// host, unlike every other flow metric, which is exactly why it is off by default
	// and gated on the operator asking for it (§9).
	flowTopTalkers = kingpin.Flag(
		"flow.top-talkers",
		"Emit opnsense_flow_top_talker_bytes_total: bytes per internal host and direction, top-N with "+
			"an __other__ remainder. OFF by default because the host label is high cardinality; the top-N "+
			"bounds it but a host label is still one series per host.",
	).Envar("OPNSENSE_EXPORTER_FLOW_TOP_TALKERS").Default("false").Bool()

	flowDNSCacheSize = kingpin.Flag(
		"flow.dns-cache.size",
		"Entries in the DNS answer cache that gives a flow to a bare IP its dst.domain, fed by the "+
			"Zenarmor dns family. Over the cap it stops inserting rather than evicting hot entries. 0 "+
			"disables domain enrichment.",
	).Envar("OPNSENSE_EXPORTER_FLOW_DNS_CACHE_SIZE").Default("50000").Int()
)

// parseAllowedPeers turns the repeatable CIDR flag into prefixes. A bare address is
// REJECTED rather than widened to a /32: an operator who writes one has almost
// certainly mistyped, and quietly accepting it in a form that matches nothing would
// leave the listener open while looking configured.
func parseAllowedPeers(in []string) ([]netip.Prefix, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("flow: --flow.netflow.allowed-peers %q is not a CIDR prefix "+
				"(a bare address needs an explicit /32 or /128): %w", s, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// parseIfIndexMap parses the "1=ixl0,5=igb0" override. Every malformed entry is an
// error: a silently dropped entry would leave records labelled with the derived
// mapping the operator was explicitly trying to override.
func parseIfIndexMap(s string) (map[uint32]string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	out := map[uint32]string{}
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		k, v, ok := strings.Cut(pair, "=")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ok || k == "" || v == "" {
			return nil, fmt.Errorf("flow: --flow.netflow.ifindex-map entry %q is not index=device", pair)
		}
		idx, err := strconv.ParseUint(k, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("flow: --flow.netflow.ifindex-map index %q is not a number: %w", k, err)
		}
		if prev, dup := out[uint32(idx)]; dup {
			return nil, fmt.Errorf("flow: --flow.netflow.ifindex-map lists index %d twice (%q and %q)",
				idx, prev, v)
		}
		out[uint32(idx)] = v
	}
	return out, nil
}

// FlowConfig is the resolved flow configuration.
//
// The two lanes differ in default deliberately: --flow.enabled is on because it only
// reads documents the exporter already has, while --flow.netflow.enabled is off
// because it opens an unauthenticated UDP socket.
type FlowConfig struct {
	Enabled        bool
	Zenarmor       bool
	NetflowEnabled bool
	TopN           int
	MaxKeys        int

	NetflowListen       string
	NetflowAllowedPeers []netip.Prefix
	NetflowIfIndexMap   map[uint32]string

	Correlate           bool
	CorrelateWindow     time.Duration
	CorrelateMaxEntries int
	LogMode             string
	MaxLogsPerWindow    int
	TopTalkers          bool
	DNSCacheSize        int
}

// Flow returns the resolved flow configuration, validated.
func Flow() (FlowConfig, error) {
	peers, err := parseAllowedPeers(*flowNetflowPeers)
	if err != nil {
		return FlowConfig{}, err
	}
	ifmap, err := parseIfIndexMap(*flowNetflowIfIndexMap)
	if err != nil {
		return FlowConfig{}, err
	}
	c := FlowConfig{
		Enabled:             *flowEnabled,
		Zenarmor:            *flowZenarmor,
		NetflowEnabled:      *flowNetflowEnabled,
		TopN:                *flowTopN,
		MaxKeys:             *flowMaxKeys,
		NetflowListen:       *flowNetflowListen,
		NetflowAllowedPeers: peers,
		NetflowIfIndexMap:   ifmap,
		Correlate:           *flowCorrelate,
		CorrelateWindow:     *flowCorrelateWindow,
		CorrelateMaxEntries: *flowCorrelateMaxEntries,
		LogMode:             *flowLogMode,
		MaxLogsPerWindow:    *flowMaxLogsPerWindow,
		TopTalkers:          *flowTopTalkers,
		DNSCacheSize:        *flowDNSCacheSize,
	}
	if err := c.Validate(); err != nil {
		return FlowConfig{}, err
	}
	return c, nil
}

// Validate rejects configurations that would silently do nothing. A flag that
// quietly no-ops looks exactly like a quiet network — the same reasoning behind
// --logs.zenarmor.families' strict validation.
func (c FlowConfig) Validate() error {
	if c.NetflowEnabled && !c.Enabled {
		return fmt.Errorf("flow: --flow.netflow.enabled requires --flow.enabled")
	}
	// An enabled receiver with nowhere to bind is the "quiet no-op" failure again:
	// the operator sees the flag accepted and no records ever arrive.
	if c.NetflowEnabled && strings.TrimSpace(c.NetflowListen) == "" {
		return fmt.Errorf("flow: --flow.netflow.enabled requires a --flow.netflow.listen address")
	}
	if c.TopN < 0 {
		return fmt.Errorf("flow: --flow.top-n must not be negative (got %d); 0 means unbounded", c.TopN)
	}
	if c.MaxKeys < 0 {
		return fmt.Errorf("flow: --flow.max-keys must not be negative (got %d); 0 means unbounded", c.MaxKeys)
	}
	// Incoherent rather than merely odd: the emit cap can never bind above the
	// insert cap, so an operator who sets this believes they raised a limit that
	// cannot take effect.
	if c.TopN > 0 && c.MaxKeys > 0 && c.TopN > c.MaxKeys {
		return fmt.Errorf(
			"flow: --flow.top-n (%d) exceeds --flow.max-keys (%d); the accumulator never tracks more "+
				"than max-keys combinations, so the larger top-n can never take effect",
			c.TopN, c.MaxKeys)
	}
	// A correlator that holds nothing collapses no fragments and joins no sources, so a
	// zero or negative window is the quiet no-op again rather than a fast correlator.
	if c.Correlate && c.CorrelateWindow <= 0 {
		return fmt.Errorf("flow: --flow.correlate.window must be positive (got %s)", c.CorrelateWindow)
	}
	if c.CorrelateMaxEntries < 0 {
		return fmt.Errorf("flow: --flow.correlate.max-entries must not be negative (got %d); 0 is unbounded",
			c.CorrelateMaxEntries)
	}
	if c.MaxLogsPerWindow < 0 {
		return fmt.Errorf("flow: --flow.max-logs-per-window must not be negative (got %d); 0 is unlimited",
			c.MaxLogsPerWindow)
	}
	if c.DNSCacheSize < 0 {
		return fmt.Errorf("flow: --flow.dns-cache.size must not be negative (got %d); 0 disables it",
			c.DNSCacheSize)
	}
	return nil
}
