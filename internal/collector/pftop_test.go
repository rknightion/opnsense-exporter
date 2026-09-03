package collector

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

func TestPFTopCollectorFoldsAndRanks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/diagnostics/firewall/query_pf_top":
			_, _ = w.Write([]byte(`{"rows":[
{"proto":"tcp","dir":"in","src_addr":"10.0.0.2","src_port":"2","dst_addr":"192.0.2.1","dst_port":"443","state":"CLOSED","pkts":8,"bytes":90,"rule":"r2"},
{"proto":"tcp","dir":"in","src_addr":"10.0.0.2","src_port":"2","dst_addr":"192.0.2.1","dst_port":"443","state":"ESTABLISHED","pkts":10,"bytes":100,"rule":"r2"},
{"proto":"udp","dir":"in","src_addr":"10.0.0.1","src_port":"1","dst_addr":"192.0.2.1","dst_port":"53","state":"OPEN","pkts":2,"bytes":190,"rule":"r1"}
]}`))
		case "/api/interfaces/overview/interfaces_info":
			_, _ = w.Write([]byte(`{"rows":[
{"device":"ix0","identifier":"opt1","description":"OPT1","status":"up","flags":["up"],"enabled":true},
{"device":"ix1","identifier":"lan","description":"LAN","status":"up","flags":["up"],"enabled":true},
{"device":"ix2","identifier":"disabled","description":"DISABLED","status":"up","flags":["up"],"enabled":false}
]}`))
		case "/api/diagnostics/traffic/top/lan,opt1":
			_, _ = w.Write([]byte(`{"lan":{"status":"ok","records":[
{"address":"10.0.0.3","rate_bits_in":30,"rate_bits_out":20,"rate_bits":50},
{"address":"10.0.0.3","rate_bits_in":2,"rate_bits_out":3,"rate_bits":5}]},
"opt1":{"status":"timeout","records":[{"address":"10.0.0.4","rate_bits_in":100,"rate_bits_out":100,"rate_bits":200}]}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)
	c := &pftopCollector{subsystem: PftopSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	metrics := collectMetrics(t, c, client)
	assertNoDuplicateSeries(t, metrics)

	// Two state groups (one folded duplicate) and one talker group. Each board
	// always contributes its fixed overflow and two diagnostic gauges/counters.
	if len(metrics) != 2*3+1*3+3+4+4 {
		t.Fatalf("metric count = %d, want %d", len(metrics), 2*3+1*3+3+4+4)
	}

	valueFor := func(name string, want map[string]string) (float64, bool) {
		for _, metric := range metrics {
			if !hasFqName(metric, name) {
				continue
			}
			labels := getMetricLabels(metric)
			matched := true
			for key, value := range want {
				if labels[key] != value {
					matched = false
					break
				}
			}
			if matched {
				return getMetricValue(metric), true
			}
		}
		return 0, false
	}
	if got, ok := valueFor("opnsense_pftop_state_bytes", map[string]string{
		"protocol": "tcp", "direction": "in", "source_address": "10.0.0.2", "source_port": "2",
		"destination_address": "192.0.2.1", "destination_port": "443", "gateway_address": "", "gateway_port": "",
		"rule": "r2", "state": "ESTABLISHED", "opnsense_instance": "test",
	}); !ok || got != 190 {
		t.Fatalf("folded state bytes = %v, want 190", got)
	}
	if got, ok := valueFor("opnsense_pftop_state_records", map[string]string{
		"protocol": "tcp", "direction": "in", "source_address": "10.0.0.2", "source_port": "2",
		"destination_address": "192.0.2.1", "destination_port": "443", "gateway_address": "", "gateway_port": "",
		"rule": "r2", "state": "ESTABLISHED", "opnsense_instance": "test",
	}); !ok || got != 2 {
		t.Fatalf("folded state records = %v, want 2", got)
	}
	if got, ok := valueFor("opnsense_pftop_talker_rate_bits", map[string]string{
		"interface": "lan", "address": "10.0.0.3", "direction": "total", "opnsense_instance": "test",
	}); !ok || got != 55 {
		t.Fatalf("folded talker rate = %v, want 55", got)
	}
	if got, ok := valueFor("opnsense_pftop_state_overflow_bytes", map[string]string{"opnsense_instance": "test"}); !ok || got != 0 {
		t.Fatalf("state overflow = %v, want 0", got)
	}
	if got, ok := valueFor("opnsense_pftop_talker_overflow_rate_bits", map[string]string{"direction": "total", "opnsense_instance": "test"}); !ok || got != 0 {
		t.Fatalf("talker overflow = %v, want 0", got)
	}
}

func TestPFTopRankingAndInventoryRefusalAreDeterministic(t *testing.T) {
	c := &pftopCollector{
		subsystem:       PftopSubsystem,
		stateInventory:  newBoundedInventory[pftopStateIdentity, pftopStateValue](1, 5*time.Minute, comparePFTopStateIdentity),
		talkerInventory: newBoundedInventory[pftopTalkerIdentity, pftopTalkerValue](1, 5*time.Minute, comparePFTopTalkerIdentity),
	}

	stateGroups := foldPFTopStates([]opnsense.PFTopState{
		{Proto: "tcp", Dir: "in", SrcAddr: "b", Bytes: 10, Packets: 1, Rule: "r"},
		{Proto: "tcp", Dir: "in", SrcAddr: "a", Bytes: 10, Packets: 1, Rule: "r"},
	})
	if comparePFTopStateIdentity(stateGroups[0].identity, stateGroups[1].identity) >= 0 {
		t.Fatalf("state groups were not lexical after equal-byte rank: %#v", stateGroups)
	}
	// The first ranked key is admitted; the second selected key is refused and
	// contributes to overflow, rather than silently disappearing.
	c.Register(namespace, "test", promslog.NewNopLogger())
	stateOverflow, accepted := c.admitPFTopStates(stateGroups, time.Unix(1, 0))
	if len(accepted) != 1 || stateOverflow.Records != 1 {
		t.Fatalf("state admission accepted=%d overflow=%#v", len(accepted), stateOverflow)
	}
	if got := c.stateInventory.refused(); got != 1 {
		t.Fatalf("state refusal count = %v, want 1", got)
	}
}

func TestPFTopRejectedExistingIdentityUpdateMovesToOverflow(t *testing.T) {
	c := &pftopCollector{
		subsystem:      PftopSubsystem,
		stateInventory: newBoundedInventory[pftopStateIdentity, pftopStateValue](1, 5*time.Minute, comparePFTopStateIdentity),
	}
	c.Register(namespace, "test", promslog.NewNopLogger())
	identity := pftopStateIdentity{Proto: "tcp", SrcAddr: "source"}

	_, accepted := c.admitPFTopStates([]pftopStateGroup{{
		identity: identity,
		value:    pftopStateValue{Bytes: 1, Packets: 1, Records: 1, State: "ESTABLISHED"},
	}}, time.Unix(1, 0))
	if len(accepted) != 1 {
		t.Fatalf("initial admission accepted=%d, want 1", len(accepted))
	}

	overflow, accepted := c.admitPFTopStates([]pftopStateGroup{{
		identity: identity,
		value: pftopStateValue{
			Bytes: 2, Packets: 3, Records: 1,
			State: strings.Repeat("x", maxRetainedKeyBytes+1),
		},
	}}, time.Unix(2, 0))
	if len(accepted) != 0 || overflow.Bytes != 2 || overflow.Packets != 3 || overflow.Records != 1 {
		t.Fatalf("rejected update accepted=%d overflow=%#v, want complete overflow", len(accepted), overflow)
	}
	if got := c.stateInventory.refused(); got != 1 {
		t.Fatalf("state refusal count = %v, want 1", got)
	}
}

func TestFoldPFTopStatesSelectsRepresentativeStateDeterministically(t *testing.T) {
	groups := foldPFTopStates([]opnsense.PFTopState{
		{Proto: "tcp", SrcAddr: "source", State: "SYN_SENT", Bytes: 100, Packets: 9},
		{Proto: "tcp", SrcAddr: "source", State: "ESTABLISHED", Bytes: 100, Packets: 10},
		{Proto: "tcp", SrcAddr: "source", State: "CLOSED", Bytes: 100, Packets: 10},
	})
	if len(groups) != 1 || groups[0].value.State != "CLOSED" {
		t.Fatalf("representative state = %#v, want lexical state after byte and packet ties", groups)
	}
}

func TestPFTopOverflowPreservesSnapshotTotals(t *testing.T) {
	c := &pftopCollector{
		subsystem:       PftopSubsystem,
		stateInventory:  newBoundedInventory[pftopStateIdentity, pftopStateValue](1, 5*time.Minute, comparePFTopStateIdentity),
		talkerInventory: newBoundedInventory[pftopTalkerIdentity, pftopTalkerValue](1, 5*time.Minute, comparePFTopTalkerIdentity),
	}
	c.Register(namespace, "test", promslog.NewNopLogger())
	now := time.Unix(1, 0)

	stateGroups := foldPFTopStates([]opnsense.PFTopState{
		{Proto: "tcp", SrcAddr: "a", Bytes: 20, Packets: 2},
		{Proto: "tcp", SrcAddr: "b", Bytes: 10, Packets: 1},
	})
	stateOverflow, acceptedStates := c.admitPFTopStates(stateGroups, now)
	stateTotal := stateOverflow
	for _, group := range acceptedStates {
		addPFTopStateValue(&stateTotal, group.value)
	}
	if stateTotal.Bytes != 30 || stateTotal.Packets != 3 || stateTotal.Records != 2 {
		t.Fatalf("state named plus overflow = %#v, want complete returned snapshot", stateTotal)
	}

	talkerGroups := foldPFTopTalkers(opnsense.TrafficTop{Interfaces: map[string]opnsense.TrafficTopInterface{
		"lan": {Status: "ok", Records: []opnsense.TrafficTopRecord{
			{Address: "a", RateBitsIn: 2, RateBitsOut: 3, RateBits: 5},
			{Address: "b", RateBitsIn: 7, RateBitsOut: 11, RateBits: 18},
		}},
	}})
	talkerOverflow, acceptedTalkers := c.admitPFTopTalkers(talkerGroups, now)
	talkerTotal := talkerOverflow
	for _, group := range acceptedTalkers {
		addPFTopTalkerValue(&talkerTotal, group.value)
	}
	if talkerTotal.RateBitsIn != 9 || talkerTotal.RateBitsOut != 14 || talkerTotal.RateBits != 23 || talkerTotal.Records != 2 {
		t.Fatalf("talker named plus overflow = %#v, want complete returned snapshot", talkerTotal)
	}
}

func TestPFTopCollectorDescriptorsAreGauges(t *testing.T) {
	c := &pftopCollector{subsystem: PftopSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	ch := make(chan *prometheus.Desc, 32)
	go func() { c.Describe(ch); close(ch) }()
	if n := len(func() []*prometheus.Desc {
		var out []*prometheus.Desc
		for d := range ch {
			out = append(out, d)
		}
		return out
	}()); n != 11 {
		t.Fatalf("descriptor count = %d, want 11", n)
	}
}

func TestPFTopCollectorSeriesCeiling(t *testing.T) {
	c := &pftopCollector{subsystem: PftopSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	states := make([]opnsense.PFTopState, PftopTopN+1)
	talkerRows := make([]opnsense.TrafficTopRecord, PftopTopN+1)
	for i := range states {
		states[i] = opnsense.PFTopState{
			Proto: "tcp", Dir: "in", SrcAddr: fmt.Sprintf("source-%03d", i),
			DstAddr: "destination", State: "ESTABLISHED", Bytes: int64(PftopTopN + 1 - i), Packets: 1,
		}
		talkerRows[i] = opnsense.TrafficTopRecord{
			Address: fmt.Sprintf("talker-%03d", i), RateBitsIn: 1, RateBitsOut: 2, RateBits: int64(PftopTopN + 1 - i),
		}
	}

	ch := make(chan prometheus.Metric, 700)
	now := time.Unix(1, 0)
	c.emitStates(foldPFTopStates(states), now, ch)
	c.emitTalkers(foldPFTopTalkers(opnsense.TrafficTop{Interfaces: map[string]opnsense.TrafficTopInterface{
		"lan": {Status: "ok", Records: talkerRows},
	}}), now, ch)
	close(ch)

	count := 0
	for range ch {
		count++
	}
	if count != 611 {
		t.Fatalf("series count = %d, want hard ceiling 611", count)
	}
}
