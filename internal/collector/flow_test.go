package collector

import (
	"context"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/promslog"
	"github.com/rknightion/opnsense-exporter/internal/flow"
)

// descVarLabels extracts a Desc's variable labels. Substring matching cannot do
// this job — "transport" contains "port", so a naive forbidden-substring check can
// never pass — so parse the label group and compare element-wise, the same way
// scripts/docgen/verify.go:19 does.
var descVarLabelsRe = regexp.MustCompile(`variableLabels: \{([^}]*)\}`)

func descVarLabels(t *testing.T, d *prometheus.Desc) []string {
	t.Helper()
	m := descVarLabelsRe.FindStringSubmatch(d.String())
	if m == nil {
		t.Fatalf("could not read variable labels from %s", d)
	}
	var out []string
	for _, l := range strings.Split(m[1], ",") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func newFlowTestCollector(t *testing.T, store *FlowStore) *flowCollector {
	t.Helper()
	c := &flowCollector{subsystem: FlowSubsystem, store: store}
	c.Register(namespace, "test", promslog.NewNopLogger())
	return c
}

// The guard test. The emitted label set must equal the allowlist EXACTLY, so a
// future change cannot add an IP, port, app_name, hostname or community_id label
// without this failing.
func TestFlowCollector_VolumeLabelSetIsExactlyTheAllowlist(t *testing.T) {
	c := newFlowTestCollector(t, newFlowStore(10, 100))
	want := append(flow.RollupLabelNames(), instanceLabelName)
	sort.Strings(want)

	for _, d := range []*prometheus.Desc{c.bytes, c.packets, c.records} {
		got := descVarLabels(t, d)
		sort.Strings(got)
		if len(got) != len(want) {
			t.Fatalf("%s labels = %v, want %v", d, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s labels = %v, want %v", d, got, want)
			}
		}
	}
}

// The literal spelled in Register() must match RollupLabelNames(), or the metric
// and the accumulator disagree about which value goes on which label. The literal
// exists because scripts/docgen resolves the argument statically and cannot see
// through a function call.
func TestFlowCollector_LiteralLabelsMatchRollupLabelNames(t *testing.T) {
	c := newFlowTestCollector(t, newFlowStore(10, 100))
	got := descVarLabels(t, c.bytes)
	want := append(flow.RollupLabelNames(), instanceLabelName)
	if len(got) != len(want) {
		t.Fatalf("collector labels %v do not match flow.RollupLabelNames() %v", got, want)
	}
	// Order matters here, unlike the set test above: Update passes
	// RollupKey.Values() positionally, so a reordering silently puts every value on
	// the wrong label.
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("label %d = %q, want %q (order is load-bearing: Values() is positional)", i, got[i], want[i])
		}
	}
}

// No high-cardinality dimension may appear on any of this collector's metrics.
func TestFlowCollector_NoHighCardinalityLabels(t *testing.T) {
	c := newFlowTestCollector(t, newFlowStore(10, 100))
	forbidden := map[string]bool{
		"src_addr": true, "dst_addr": true, "ip_src_saddr": true, "ip_dst_saddr": true,
		"src_port": true, "dst_port": true, "port": true, "app_name": true,
		"hostname": true, "src_hostname": true, "dst_hostname": true,
		"community_id": true, "conn_uuid": true, "domain": true, "ja3": true, "host": true,
	}
	ch := make(chan *prometheus.Desc, 64)
	c.Describe(ch)
	close(ch)
	for d := range ch {
		// top_talker_bytes_total is the ONE deliberate exception: it carries a host
		// label, which is exactly why it is opt-in behind --flow.top-talkers and bounded
		// by top-N + __other__ (§9). Every other flow metric stays under the rule.
		if descFQName(d.String()) == "opnsense_flow_top_talker_bytes_total" {
			continue
		}
		for _, l := range descVarLabels(t, d) {
			if forbidden[l] {
				t.Fatalf("forbidden high-cardinality label %q on %s", l, d)
			}
		}
	}
}

func flowRec(iface, cat string, bytes, packets uint64) flow.Record {
	return flow.Record{
		Source: flow.SourceZenarmor, Proto: 6,
		SrcAddr: netip.MustParseAddr("192.0.2.1"), DstAddr: netip.MustParseAddr("198.51.100.1"),
		In: flow.Iface{Name: iface}, Direction: flow.DirectionOutbound,
		L7:  flow.L7{AppCategory: cat},
		Zen: flow.Counters{TxBytes: bytes, TxPackets: packets, Present: true},
	}
}

func collect(t *testing.T, c *flowCollector) map[string]float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 128)
	if err := c.Update(context.Background(), nil, ch); err != nil {
		t.Fatalf("Update returned %v", err)
	}
	close(ch)
	out := map[string]float64{}
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("writing metric: %v", err)
		}
		var key strings.Builder
		key.WriteString(descFQName(m.Desc().String()))
		for _, lp := range pb.GetLabel() {
			if lp.GetName() == instanceLabelName {
				continue
			}
			key.WriteString("|" + lp.GetName() + "=" + lp.GetValue())
		}
		v := pb.GetCounter().GetValue()
		if pb.GetGauge() != nil {
			v = pb.GetGauge().GetValue()
		}
		out[key.String()] = v
	}
	return out
}

var fqNameRe = regexp.MustCompile(`fqName: "([^"]+)"`)

func descFQName(s string) string {
	m := fqNameRe.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return m[1]
}

func TestFlowCollector_EmitsAccumulatedVolume(t *testing.T) {
	store := newFlowStore(10, 100)
	store.Observe(flowRec("LAN", "Web Browsing", 1000, 10))
	store.Observe(flowRec("LAN", "Web Browsing", 500, 5))
	c := newFlowTestCollector(t, store)

	got := collect(t, c)
	// Label pairs come back sorted by name, not in emission order.
	const series = "|action=|category=Web Browsing|direction=outbound|interface=LAN|scope=|source=zenarmor|transport=tcp"
	if v := got["opnsense_flow_bytes_total"+series]; v != 1500 {
		t.Fatalf("bytes = %v, want 1500 (got %v)", v, got)
	}
	if v := got["opnsense_flow_packets_total"+series]; v != 15 {
		t.Fatalf("packets = %v, want 15", v)
	}
	if v := got["opnsense_flow_records_total"+series]; v != 2 {
		t.Fatalf("records = %v, want 2", v)
	}
}

func TestFlowCollector_EmitsUniqueDestinationsAndTopTalkers(t *testing.T) {
	store := newFlowStore(10, 100)
	store.topTalkers.Configure(true, flow.SourceZenarmor)
	// Two flows from one internal host to two destinations on the LAN interface.
	store.Observe(talkerFlowRec("LAN", "10.0.0.5", "198.51.100.1", 1000))
	store.Observe(talkerFlowRec("LAN", "10.0.0.5", "198.51.100.2", 500))
	c := newFlowTestCollector(t, store)

	got := collect(t, c)
	if v := got["opnsense_flow_unique_destinations|interface=LAN"]; v != 2 {
		t.Errorf("unique_destinations = %v, want 2", v)
	}
	if v := got["opnsense_flow_top_talker_bytes_total|direction=outbound|host=10.0.0.5"]; v != 1500 {
		t.Errorf("top_talker_bytes_total for 10.0.0.5 = %v, want 1500", v)
	}
}

func TestFlowCollector_DNSCacheMetricsPublishedFromZeroWhenWired(t *testing.T) {
	store := newFlowStore(10, 100)
	cache := flow.NewDNSCache(50, 0)
	store.SetDNSCacheStats(cache.Stats)
	c := newFlowTestCollector(t, store)

	got := collect(t, c)
	for _, name := range []string{
		"opnsense_flow_dns_cache_entries",
		"opnsense_flow_dns_cache_hits_total",
		"opnsense_flow_dns_cache_misses_total",
		"opnsense_flow_dns_cache_rejected_total",
	} {
		if _, ok := got[name]; !ok {
			t.Errorf("%s not published from zero once the cache is wired", name)
		}
	}
}

// Without the wiring the DNS cache metrics are absent, not zero — a zero would claim a
// cache exists on a deployment that never built one (flow disabled).
func TestFlowCollector_DNSCacheMetricsAbsentUntilWired(t *testing.T) {
	c := newFlowTestCollector(t, newFlowStore(10, 100))
	got := collect(t, c)
	if _, ok := got["opnsense_flow_dns_cache_entries"]; ok {
		t.Error("dns_cache_entries emitted with no cache wired; must be absent")
	}
}

// talkerFlowRec is a zenarmor flow record with a local source, for the talker/dest tests.
func talkerFlowRec(iface, src, dst string, bytes uint64) flow.Record {
	return flow.Record{
		Source: flow.SourceZenarmor, Proto: 6,
		SrcAddr: netip.MustParseAddr(src), DstAddr: netip.MustParseAddr(dst),
		In: flow.Iface{Name: iface}, Direction: flow.DirectionOutbound,
		Enrich: flow.Enrichment{SrcScope: "local", DstScope: "remote"},
		Zen:    flow.Counters{TxBytes: bytes, Present: true},
	}
}

// The saturation self-metrics are published from zero, so an operator can tell "a
// few small categories folded" from "the map saturated and everything new is
// invisible" — and can see a healthy accumulator reading a flat zero rather than
// nothing at all.
func TestFlowCollector_PublishesSaturationSelfMetricsFromZero(t *testing.T) {
	c := newFlowTestCollector(t, newFlowStore(7, 9))
	got := collect(t, c)
	for name, want := range map[string]float64{
		"opnsense_flow_rollup_keys":                 0,
		"opnsense_flow_rollup_keys_folded":          0,
		"opnsense_flow_rollup_keys_max":             9,
		"opnsense_flow_rollup_top_n":                7,
		"opnsense_flow_rollup_capped_total":         0,
		"opnsense_flow_payload_byte_fallback_total": 0,
	} {
		v, ok := got[name]
		if !ok {
			t.Fatalf("%s not published; a self-metric that only appears once it fires is invisible when it matters", name)
		}
		if v != want {
			t.Errorf("%s = %v, want %v", name, v, want)
		}
	}
}

func TestFlowCollector_CountsThePayloadByteFallback(t *testing.T) {
	store := newFlowStore(10, 100)
	r := flowRec("LAN", "Network Management", 74, 1)
	r.Repairs.PayloadByteFallback = true
	store.Observe(r)
	store.Observe(flowRec("LAN", "Network Management", 1000, 5)) // no fallback

	if v := collect(t, newFlowTestCollector(t, store))["opnsense_flow_payload_byte_fallback_total"]; v != 1 {
		t.Fatalf("payload_byte_fallback_total = %v, want 1", v)
	}
}

// ConfigureFlow retunes the process-wide store's bounds without discarding what it
// has already accumulated. It exists so main can size the accumulator from flags,
// and it must be callable at any time: StartPolling launches a poller per
// collector, so a resize that swapped the accumulator would be a data race.
func TestConfigureFlow_RetunesWithoutLosingTotals(t *testing.T) {
	store := newFlowStore(1000, 2500)
	store.Observe(flowRec("LAN", "a", 100, 1))
	store.setBounds(5, 10)
	store.Observe(flowRec("LAN", "b", 200, 2))

	c := newFlowTestCollector(t, store)
	got := collect(t, c)
	if got["opnsense_flow_rollup_keys_max"] != 10 || got["opnsense_flow_rollup_top_n"] != 5 {
		t.Fatalf("bounds not applied: %v", got)
	}
	var total float64
	for k, v := range got {
		if strings.HasPrefix(k, "opnsense_flow_bytes_total") {
			total += v
		}
	}
	if total != 300 {
		t.Fatalf("retuning discarded totals: bytes = %v, want 300", total)
	}
}

// The package-level singleton is the seam the receiver lanes are handed, so it must
// actually satisfy the sink interface.
func TestFlowStoreSatisfiesTheSinkInterface(t *testing.T) {
	var _ flow.Sink = Flow
	if Flow == nil {
		t.Fatal("collector.Flow must exist at init; the receiver lanes are handed it directly")
	}
}
