package collector

import (
	"cmp"
	"context"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

// pftop is an opt-in fallback for installations that do not use the NetFlow
// receiver. It is a sampled API view, not a second flow pipeline: pf state
// bytes are cumulative state values while traffic-top values are a two-second
// iftop rate sample, so combining either source with internal/flow would make
// the resulting series lie about its unit.
const (
	PftopTopN         = 100
	pftopInventoryTTL = 5 * time.Minute
)

type pftopStateIdentity struct {
	Proto   string
	Dir     string
	SrcAddr string
	SrcPort string
	DstAddr string
	DstPort string
	GwAddr  string
	GwPort  string
	Rule    string
}

type pftopStateValue struct {
	Bytes                 int64
	Packets               int64
	Records               int64
	State                 string
	representativeBytes   int64
	representativePackets int64
}

type pftopStateGroup struct {
	identity pftopStateIdentity
	value    pftopStateValue
}

type pftopTalkerIdentity struct {
	Interface string
	Address   string
}

type pftopTalkerValue struct {
	RateBitsIn  int64
	RateBitsOut int64
	RateBits    int64
	Records     int64
}

type pftopTalkerGroup struct {
	identity pftopTalkerIdentity
	value    pftopTalkerValue
}

type pftopCollector struct {
	log       *slog.Logger
	subsystem string
	instance  string

	stateBytes           *prometheus.Desc
	statePackets         *prometheus.Desc
	stateRecords         *prometheus.Desc
	stateOverflowBytes   *prometheus.Desc
	stateOverflowPackets *prometheus.Desc
	stateOverflowRecords *prometheus.Desc

	talkerRateBits         *prometheus.Desc
	talkerOverflowRateBits *prometheus.Desc
	talkerOverflowRecords  *prometheus.Desc
	cardinalityCapped      *prometheus.Desc
	cardinalityKeys        *prometheus.Desc

	stateInventory  *boundedInventory[pftopStateIdentity, pftopStateValue]
	talkerInventory *boundedInventory[pftopTalkerIdentity, pftopTalkerValue]
}

func init() {
	collectorInstances = append(collectorInstances, &pftopCollector{subsystem: PftopSubsystem})
}

func (c *pftopCollector) Name() string { return c.subsystem }

func (c *pftopCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	if c.stateInventory == nil {
		c.stateInventory = newBoundedInventory[pftopStateIdentity, pftopStateValue](PftopTopN, pftopInventoryTTL, comparePFTopStateIdentity)
	}
	if c.talkerInventory == nil {
		c.talkerInventory = newBoundedInventory[pftopTalkerIdentity, pftopTalkerValue](PftopTopN, pftopInventoryTTL, comparePFTopTalkerIdentity)
	}

	stateLabels := []string{"protocol", "direction", "source_address", "source_port", "destination_address", "destination_port", "gateway_address", "gateway_port", "rule", "state"}
	c.stateBytes = buildPrometheusDesc(c.subsystem, "state_bytes",
		"Current cumulative bytes summed by pf state identity. The state board is a bounded top-100 API snapshot; duplicate rows are folded before ranking and rows outside the board are represented by the overflow gauge.", stateLabels)
	c.statePackets = buildPrometheusDesc(c.subsystem, "state_packets",
		"Current cumulative packets summed by pf state identity. This is a gauge because the sampled pf state can disappear or reset between polls.", stateLabels)
	c.stateRecords = buildPrometheusDesc(c.subsystem, "state_records",
		"Number of pfTop records folded into this state identity in the latest successful snapshot.", stateLabels)
	c.stateOverflowBytes = buildPrometheusDesc(c.subsystem, "state_overflow_bytes",
		"Bytes from pfTop state groups outside the named top-100 board or refused by its bounded inventory in the latest successful snapshot.", nil)
	c.stateOverflowPackets = buildPrometheusDesc(c.subsystem, "state_overflow_packets",
		"Packets from pfTop state groups outside the named top-100 board or refused by its bounded inventory in the latest successful snapshot.", nil)
	c.stateOverflowRecords = buildPrometheusDesc(c.subsystem, "state_overflow_records",
		"Record count from pfTop state groups outside the named top-100 board or refused by its bounded inventory in the latest successful snapshot.", nil)

	talkerLabels := []string{"interface", "address", "direction"}
	c.talkerRateBits = buildPrometheusDesc(c.subsystem, "talker_rate_bits",
		"Bits per second for a host/interface identity from the latest two-second traffic-top sample, split by in, out and total direction. Only status=ok interfaces are included.", talkerLabels)
	c.talkerOverflowRateBits = buildPrometheusDesc(c.subsystem, "talker_overflow_rate_bits",
		"Bits per second from traffic-top identities outside the named top-100 board or refused by its bounded inventory in the latest successful snapshot, split by in, out and total direction.", []string{"direction"})
	c.talkerOverflowRecords = buildPrometheusDesc(c.subsystem, "talker_overflow_records",
		"Record count from traffic-top identities outside the named top-100 board or refused by its bounded inventory in the latest successful snapshot.", nil)
	c.cardinalityCapped = buildPrometheusDesc(c.subsystem, "cardinality_capped_total",
		"Cumulative number of leaderboard candidate observations refused by a bounded 100-key inventory.", []string{"family"})
	c.cardinalityKeys = buildPrometheusDesc(c.subsystem, "cardinality_keys",
		"Number of live identities retained by a five-minute leaderboard inventory.", []string{"family"})
}

func (c *pftopCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.stateBytes
	ch <- c.statePackets
	ch <- c.stateRecords
	ch <- c.stateOverflowBytes
	ch <- c.stateOverflowPackets
	ch <- c.stateOverflowRecords
	ch <- c.talkerRateBits
	ch <- c.talkerOverflowRateBits
	ch <- c.talkerOverflowRecords
	ch <- c.cardinalityCapped
	ch <- c.cardinalityKeys
}

func (c *pftopCollector) Update(_ context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	states, err := client.FetchPFTop()
	if err != nil {
		return err
	}
	overview, err := client.FetchInterfacesOverview()
	if err != nil {
		return err
	}
	identifiers := enabledPFTopInterfaceIdentifiers(overview.Interfaces)
	talkers, err := client.FetchTrafficTop(identifiers)
	if err != nil {
		return err
	}

	now := time.Now()
	c.emitStates(foldPFTopStates(states.States), now, ch)
	c.emitTalkers(foldPFTopTalkers(talkers), now, ch)
	return nil
}

func enabledPFTopInterfaceIdentifiers(interfaces []opnsense.InterfaceOverview) []string {
	ids := make([]string, 0, len(interfaces))
	seen := make(map[string]struct{}, len(interfaces))
	for _, iface := range interfaces {
		if !iface.Enabled {
			continue
		}
		id := strings.TrimSpace(iface.Identifier)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func foldPFTopStates(rows []opnsense.PFTopState) []pftopStateGroup {
	groups := make(map[pftopStateIdentity]*pftopStateGroup, len(rows))
	for _, row := range rows {
		identity := pftopStateIdentity{
			Proto: row.Proto, Dir: row.Dir, SrcAddr: row.SrcAddr, SrcPort: row.SrcPort,
			DstAddr: row.DstAddr, DstPort: row.DstPort, GwAddr: row.GwAddr, GwPort: row.GwPort,
			Rule: row.Rule,
		}
		group := groups[identity]
		if group == nil {
			group = &pftopStateGroup{identity: identity}
			groups[identity] = group
		}
		first := group.value.Records == 0
		group.value.Bytes += row.Bytes
		group.value.Packets += row.Packets
		group.value.Records++
		if first || row.Bytes > group.value.representativeBytes ||
			(row.Bytes == group.value.representativeBytes && row.Packets > group.value.representativePackets) ||
			(row.Bytes == group.value.representativeBytes && row.Packets == group.value.representativePackets && row.State < group.value.State) {
			group.value.State = row.State
			group.value.representativeBytes = row.Bytes
			group.value.representativePackets = row.Packets
		}
	}

	out := make([]pftopStateGroup, 0, len(groups))
	for _, group := range groups {
		out = append(out, *group)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].value.Bytes != out[j].value.Bytes {
			return out[i].value.Bytes > out[j].value.Bytes
		}
		return comparePFTopStateIdentity(out[i].identity, out[j].identity) < 0
	})
	return out
}

func foldPFTopTalkers(response opnsense.TrafficTop) []pftopTalkerGroup {
	groups := make(map[pftopTalkerIdentity]*pftopTalkerGroup)
	for iface, sample := range response.Interfaces {
		if sample.Status != "ok" {
			continue
		}
		for _, row := range sample.Records {
			identity := pftopTalkerIdentity{Interface: iface, Address: row.Address}
			group := groups[identity]
			if group == nil {
				group = &pftopTalkerGroup{identity: identity}
				groups[identity] = group
			}
			group.value.RateBitsIn += row.RateBitsIn
			group.value.RateBitsOut += row.RateBitsOut
			group.value.RateBits += row.RateBits
			group.value.Records++
		}
	}
	out := make([]pftopTalkerGroup, 0, len(groups))
	for _, group := range groups {
		out = append(out, *group)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].value.RateBits != out[j].value.RateBits {
			return out[i].value.RateBits > out[j].value.RateBits
		}
		return comparePFTopTalkerIdentity(out[i].identity, out[j].identity) < 0
	})
	return out
}

func comparePFTopStateIdentity(a, b pftopStateIdentity) int {
	for _, pair := range [][2]string{
		{a.Proto, b.Proto}, {a.Dir, b.Dir}, {a.SrcAddr, b.SrcAddr}, {a.SrcPort, b.SrcPort},
		{a.DstAddr, b.DstAddr}, {a.DstPort, b.DstPort}, {a.GwAddr, b.GwAddr}, {a.GwPort, b.GwPort},
		{a.Rule, b.Rule},
	} {
		if result := cmp.Compare(pair[0], pair[1]); result != 0 {
			return result
		}
	}
	return 0
}

func comparePFTopTalkerIdentity(a, b pftopTalkerIdentity) int {
	if result := cmp.Compare(a.Interface, b.Interface); result != 0 {
		return result
	}
	return cmp.Compare(a.Address, b.Address)
}

func (c *pftopCollector) admitPFTopStates(groups []pftopStateGroup, now time.Time) (pftopStateValue, []pftopStateGroup) {
	c.stateInventory.live(now)
	var overflow pftopStateValue
	accepted := make([]pftopStateGroup, 0, min(PftopTopN, len(groups)))
	for i, group := range groups {
		if i >= PftopTopN {
			addPFTopStateValue(&overflow, group.value)
			continue
		}
		refusals := c.stateInventory.refused()
		c.stateInventory.seen(group.identity, group.value, now)
		if c.stateInventory.refused() != refusals {
			addPFTopStateValue(&overflow, group.value)
			continue
		}
		accepted = append(accepted, group)
	}
	return overflow, accepted
}

func (c *pftopCollector) admitPFTopTalkers(groups []pftopTalkerGroup, now time.Time) (pftopTalkerValue, []pftopTalkerGroup) {
	c.talkerInventory.live(now)
	var overflow pftopTalkerValue
	accepted := make([]pftopTalkerGroup, 0, min(PftopTopN, len(groups)))
	for i, group := range groups {
		if i >= PftopTopN {
			addPFTopTalkerValue(&overflow, group.value)
			continue
		}
		refusals := c.talkerInventory.refused()
		c.talkerInventory.seen(group.identity, group.value, now)
		if c.talkerInventory.refused() != refusals {
			addPFTopTalkerValue(&overflow, group.value)
			continue
		}
		accepted = append(accepted, group)
	}
	return overflow, accepted
}

func addPFTopStateValue(dst *pftopStateValue, src pftopStateValue) {
	dst.Bytes += src.Bytes
	dst.Packets += src.Packets
	dst.Records += src.Records
}

func addPFTopTalkerValue(dst *pftopTalkerValue, src pftopTalkerValue) {
	dst.RateBitsIn += src.RateBitsIn
	dst.RateBitsOut += src.RateBitsOut
	dst.RateBits += src.RateBits
	dst.Records += src.Records
}

func (c *pftopCollector) emitStates(groups []pftopStateGroup, now time.Time, ch chan<- prometheus.Metric) {
	overflow, accepted := c.admitPFTopStates(groups, now)
	for _, group := range accepted {
		labels := []string{
			group.identity.Proto, group.identity.Dir, group.identity.SrcAddr, group.identity.SrcPort,
			group.identity.DstAddr, group.identity.DstPort, group.identity.GwAddr, group.identity.GwPort,
			group.identity.Rule, group.value.State, c.instance,
		}
		ch <- prometheus.MustNewConstMetric(c.stateBytes, prometheus.GaugeValue, float64(group.value.Bytes), labels...)
		ch <- prometheus.MustNewConstMetric(c.statePackets, prometheus.GaugeValue, float64(group.value.Packets), labels...)
		ch <- prometheus.MustNewConstMetric(c.stateRecords, prometheus.GaugeValue, float64(group.value.Records), labels...)
	}
	ch <- prometheus.MustNewConstMetric(c.stateOverflowBytes, prometheus.GaugeValue, float64(overflow.Bytes), c.instance)
	ch <- prometheus.MustNewConstMetric(c.stateOverflowPackets, prometheus.GaugeValue, float64(overflow.Packets), c.instance)
	ch <- prometheus.MustNewConstMetric(c.stateOverflowRecords, prometheus.GaugeValue, float64(overflow.Records), c.instance)
	ch <- prometheus.MustNewConstMetric(c.cardinalityCapped, prometheus.CounterValue, c.stateInventory.refused(), "state", c.instance)
	ch <- prometheus.MustNewConstMetric(c.cardinalityKeys, prometheus.GaugeValue, float64(c.stateInventory.len()), "state", c.instance)
}

func (c *pftopCollector) emitTalkers(groups []pftopTalkerGroup, now time.Time, ch chan<- prometheus.Metric) {
	overflow, accepted := c.admitPFTopTalkers(groups, now)
	for _, group := range accepted {
		for _, sample := range []struct {
			direction string
			value     int64
		}{
			{direction: "in", value: group.value.RateBitsIn},
			{direction: "out", value: group.value.RateBitsOut},
			{direction: "total", value: group.value.RateBits},
		} {
			ch <- prometheus.MustNewConstMetric(c.talkerRateBits, prometheus.GaugeValue, float64(sample.value),
				group.identity.Interface, group.identity.Address, sample.direction, c.instance)
		}
	}
	ch <- prometheus.MustNewConstMetric(c.talkerOverflowRateBits, prometheus.GaugeValue, float64(overflow.RateBitsIn), "in", c.instance)
	ch <- prometheus.MustNewConstMetric(c.talkerOverflowRateBits, prometheus.GaugeValue, float64(overflow.RateBitsOut), "out", c.instance)
	ch <- prometheus.MustNewConstMetric(c.talkerOverflowRateBits, prometheus.GaugeValue, float64(overflow.RateBits), "total", c.instance)
	ch <- prometheus.MustNewConstMetric(c.talkerOverflowRecords, prometheus.GaugeValue, float64(overflow.Records), c.instance)
	ch <- prometheus.MustNewConstMetric(c.cardinalityCapped, prometheus.CounterValue, c.talkerInventory.refused(), "talker", c.instance)
	ch <- prometheus.MustNewConstMetric(c.cardinalityKeys, prometheus.GaugeValue, float64(c.talkerInventory.len()), "talker", c.instance)
}
