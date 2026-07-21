package options

import (
	"fmt"

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
			"Costs nothing where no flow source is configured — the metrics are simply silent, like "+
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
)

// FlowConfig is the resolved flow configuration.
//
// NetflowEnabled has no flag behind it yet — the NetFlow receiver is phase 2. It is
// modelled now so the cross-field validation below is already in place and tested
// before anything can set it, rather than being written at the same time as the
// thing it is meant to guard.
type FlowConfig struct {
	Enabled        bool
	Zenarmor       bool
	NetflowEnabled bool
	TopN           int
	MaxKeys        int
}

// Flow returns the resolved flow configuration, validated.
func Flow() (FlowConfig, error) {
	c := FlowConfig{
		Enabled:  *flowEnabled,
		Zenarmor: *flowZenarmor,
		TopN:     *flowTopN,
		MaxKeys:  *flowMaxKeys,
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
	return nil
}
