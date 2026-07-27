package collector

import (
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/common/promslog"
	"github.com/rknightion/opnsense-exporter/internal/logship"
)

func newTestLogEventStore(t testing.TB) *LogEventStore {
	t.Helper()
	s := newLogEventStore()
	t.Cleanup(s.Close)
	return s
}

func newStalledSnapshotStore(t *testing.T, capacity int) (*LogEventStore, func()) {
	t.Helper()
	entered := make(chan struct{})
	release := make(chan struct{})
	snapshotDone := make(chan struct{})
	var releaseOnce sync.Once
	var hookOnce sync.Once
	s := newLogEventStoreWithCapacity(capacity, func() {
		hookOnce.Do(func() {
			close(entered)
			<-release
		})
	})
	releaseSnapshot := func() {
		releaseOnce.Do(func() { close(release) })
		<-snapshotDone
	}
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		<-snapshotDone
		s.Close()
	})
	go func() {
		defer close(snapshotDone)
		_, _ = s.snapshot()
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("snapshot owner did not enter snapshot work")
	}
	return s, releaseSnapshot
}

func TestLogEventStore_NormalConcurrentLoadIsExact(t *testing.T) {
	const (
		producers    = 16
		observations = 2000
	)
	s := newTestLogEventStore(t)
	s.SetMaxKeys(1)
	start := make(chan struct{})
	var wg sync.WaitGroup
	var rejected atomic.Uint64
	for producer := range producers {
		ruleID := strconv.Itoa(producer)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range observations {
				if !s.ObserveFirewall("pass", "igb0", ruleID, "", "wan") {
					rejected.Add(1)
				}
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := rejected.Load(); got != 0 {
		t.Fatalf("rejected observations = %d, want 0 below handoff capacity", got)
	}
	snap, ok := s.snapshot()
	if !ok {
		t.Fatal("snapshot failed")
	}
	var got float64
	for _, point := range snap.fw {
		got += point.v
	}
	var overflow float64
	for _, sat := range snap.sat {
		if sat.family == logFamilyFirewall {
			overflow = sat.capped
			break
		}
	}
	if want := float64(producers * observations); got+overflow != want {
		t.Fatalf("live + overflow = %v + %v, want %v", got, overflow, want)
	}
	if got != observations {
		t.Fatalf("live observations = %v, want one producer's %d observations", got, observations)
	}
}

// Receiver-side metric observation must never wait for a scrape that is copying
// the live tuple maps. It is admitted immediately while bounded handoff capacity
// remains, even when the map owner is stalled inside real snapshot work.
func TestLogEventStore_ObservationReturnsImmediatelyWhenSnapshotIsStalled(t *testing.T) {
	const capacity = 4
	s, releaseSnapshot := newStalledSnapshotStore(t, capacity)

	returned := make(chan bool, 1)
	go func() {
		returned <- s.ObserveFirewall("pass", "igb0", "1", "", "wan")
	}()

	select {
	case accepted := <-returned:
		if !accepted {
			t.Fatal("accepted = false with free handoff capacity")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("ObserveFirewall blocked behind a stalled snapshot")
	}
	releaseSnapshot()
}

func TestLogEventsCollector_ReportsFullHandoffDrops(t *testing.T) {
	const capacity = 4
	store, releaseSnapshot := newStalledSnapshotStore(t, capacity)
	c := &logEventsCollector{store: store, subsystem: LogEventsSubsystem}
	c.Register(namespace, "opnsense.example.com", promslog.NewNopLogger())

	for range capacity {
		if !c.store.ObserveFirewall("pass", "igb0", "1", "", "wan") {
			t.Fatal("observation refused before the bounded handoff filled")
		}
	}
	if c.store.ObserveFirewall("pass", "igb0", "1", "", "wan") {
		t.Fatal("observation accepted after the bounded handoff filled")
	}
	releaseSnapshot()

	metrics := collectMetrics(t, c, nil)
	for _, m := range metrics {
		if !hasFqName(m, "opnsense_log_events_observation_dropped_total") {
			continue
		}
		labels := getMetricLabels(m)
		if labels["reason"] != logEventObservationDropReasonHandoffFull {
			t.Fatalf("reason = %q, want %q", labels["reason"], logEventObservationDropReasonHandoffFull)
		}
		if got := getMetricValue(m); got != 1 {
			t.Fatalf("drop total = %v, want 1", got)
		}
		return
	}
	t.Fatal("observation_dropped_total was not emitted")
}

func BenchmarkLogEventStore_ObserveFirewall(b *testing.B) {
	s := newTestLogEventStore(b)
	if !s.ObserveFirewall("pass", "igb0", "1", "", "wan") {
		b.Fatal("pre-seed observation was refused")
	}
	s.sync()

	const batchSize = 1024
	b.ReportAllocs()
	b.ResetTimer()
	for completed := 0; completed < b.N; {
		batch := min(batchSize, b.N-completed)
		for range batch {
			if !s.ObserveFirewall("pass", "igb0", "1", "", "wan") {
				b.Fatal("accepted-path benchmark saturated its handoff")
			}
		}
		completed += batch

		// Keep every timed batch below handoff capacity. Processing the accepted
		// observations is deliberately outside the receiver-side timing.
		b.StopTimer()
		s.sync()
		b.StartTimer()
	}
	b.StopTimer()
}

func TestLogEventStore_ObserveZenarmor(t *testing.T) {
	s := newTestLogEventStore(t)
	flow := logship.ZenarmorObservation{Family: "flow", Action: "block", Category: "File Transfer", Interface: "LAN"}
	s.ObserveZenarmor(flow)
	s.ObserveZenarmor(flow)
	s.ObserveZenarmor(logship.ZenarmorObservation{Family: "dns", Action: "pass", Category: "Technology and Computer", RCode: "0"})
	s.sync()

	if got := s.zen.m[zenKey{family: "flow", action: "block", category: "File Transfer", iface: "LAN"}]; got != 2 {
		t.Errorf("flow/block = %v, want 2", got)
	}
	if got := s.zen.m[zenKey{family: "dns", action: "pass", category: "Technology and Computer", rcode: "0"}]; got != 1 {
		t.Errorf("dns/pass = %v, want 1", got)
	}
	// Distinct dimensions must not collapse into one series.
	if got := s.zen.len(); got != 2 {
		t.Errorf("distinct keys = %d, want 2", got)
	}
}

func TestLogEventStore_ObserveGateway(t *testing.T) {
	s := newTestLogEventStore(t)
	if !s.ObserveGateway("alarm_started", "TEST_GATEWAY") {
		t.Fatal("first observation was refused")
	}
	if !s.ObserveGateway("alarm_started", "TEST_GATEWAY") {
		t.Fatal("second observation was refused")
	}
	if !s.ObserveGateway("alarm_cleared", "TEST_GATEWAY") {
		t.Fatal("distinct event observation was refused")
	}
	s.sync()

	if got := s.gateway.m[gatewayKey{event: "alarm_started", gateway: "TEST_GATEWAY"}]; got != 2 {
		t.Errorf("alarm_started count = %v, want 2", got)
	}
	if got := s.gateway.m[gatewayKey{event: "alarm_cleared", gateway: "TEST_GATEWAY"}]; got != 1 {
		t.Errorf("alarm_cleared count = %v, want 1", got)
	}
}

func TestLogEventStore_ObserveCARP(t *testing.T) {
	s := newTestLogEventStore(t)
	if !s.ObserveCARP("state_changed", "backup", "master", "vtnet2", "9") {
		t.Fatal("first observation was refused")
	}
	if !s.ObserveCARP("state_changed", "backup", "master", "vtnet2", "9") {
		t.Fatal("second observation was refused")
	}
	// A demotion names no state, interface or vhid — an all-empty tail is a real,
	// distinct series, not a degenerate one that should collapse into another.
	if !s.ObserveCARP("demoted", "", "", "", "") {
		t.Fatal("demotion observation was refused")
	}
	if !s.ObserveCARP("promoted", "", "", "", "") {
		t.Fatal("promotion observation was refused")
	}
	s.sync()

	if got := s.carp.m[carpKey{event: "state_changed", from: "backup", to: "master", iface: "vtnet2", vhid: "9"}]; got != 2 {
		t.Errorf("state_changed count = %v, want 2", got)
	}
	if got := s.carp.m[carpKey{event: "demoted"}]; got != 1 {
		t.Errorf("demoted count = %v, want 1", got)
	}
	if got := s.carp.m[carpKey{event: "promoted"}]; got != 1 {
		t.Errorf("promoted count = %v, want 1", got)
	}
	if got := s.carp.len(); got != 3 {
		t.Errorf("distinct keys = %d, want 3", got)
	}
}

func TestLogEventStore_ObserveUPnP(t *testing.T) {
	s := newTestLogEventStore(t)
	if !s.ObserveUPnP("expired", "ok", "udp") {
		t.Fatal("first observation was refused")
	}
	if !s.ObserveUPnP("expired", "ok", "udp") {
		t.Fatal("second observation was refused")
	}
	// Three of the five grammars name no protocol, so an empty protocol is a real,
	// distinct series rather than a degenerate one that should collapse into another.
	if !s.ObserveUPnP("cleanup_failed", "failure", "") {
		t.Fatal("cleanup_failed observation was refused")
	}
	if !s.ObserveUPnP("lease_file_error", "failure", "") {
		t.Fatal("lease_file_error observation was refused")
	}
	s.sync()

	if got := s.upnp.m[upnpKey{event: "expired", result: "ok", protocol: "udp"}]; got != 2 {
		t.Errorf("expired count = %v, want 2", got)
	}
	if got := s.upnp.m[upnpKey{event: "cleanup_failed", result: "failure"}]; got != 1 {
		t.Errorf("cleanup_failed count = %v, want 1", got)
	}
	if got := s.upnp.m[upnpKey{event: "lease_file_error", result: "failure"}]; got != 1 {
		t.Errorf("lease_file_error count = %v, want 1", got)
	}
	if got := s.upnp.len(); got != 3 {
		t.Errorf("distinct keys = %d, want 3", got)
	}
}

func TestLogEventStore_ObserveRADIUS(t *testing.T) {
	s := newTestLogEventStore(t)
	if !s.ObserveRADIUS("access", "accepted", "configured") {
		t.Fatal("first accepted observation was refused")
	}
	if !s.ObserveRADIUS("access", "accepted", "configured") {
		t.Fatal("second accepted observation was refused")
	}
	if !s.ObserveRADIUS("access", "rejected", "configured") {
		t.Fatal("rejected observation was refused")
	}
	s.sync()

	if got := s.radius.m[radiusKey{event: "access", result: "accepted", clientScope: "configured"}]; got != 2 {
		t.Errorf("accepted count = %v, want 2", got)
	}
	if got := s.radius.m[radiusKey{event: "access", result: "rejected", clientScope: "configured"}]; got != 1 {
		t.Errorf("rejected count = %v, want 1", got)
	}
}

func TestLogEventStore_ObserveVPN(t *testing.T) {
	s := newTestLogEventStore(t)
	if !s.ObserveVPN("ipsec", "established", "success", "TESTLAN to LXC105") {
		t.Fatal("first ipsec observation was refused")
	}
	if !s.ObserveVPN("ipsec", "established", "success", "TESTLAN to LXC105") {
		t.Fatal("second ipsec observation was refused")
	}
	if !s.ObserveVPN("openvpn", "authentication_failed", "failure", "") {
		t.Fatal("openvpn observation with an unresolved connection was refused")
	}
	s.sync()

	if got := s.vpn.m[vpnKey{backend: "ipsec", event: "established", result: "success", connection: "TESTLAN to LXC105"}]; got != 2 {
		t.Errorf("ipsec established count = %v, want 2", got)
	}
	// An unresolved connection is a legitimate, expected series — not a reason to
	// refuse the observation or to substitute a placeholder.
	if got := s.vpn.m[vpnKey{backend: "openvpn", event: "authentication_failed", result: "failure"}]; got != 1 {
		t.Errorf("openvpn authentication_failed count = %v, want 1", got)
	}
}

func TestLogEventStore_VPNObservationReturnsImmediatelyWhenSnapshotIsStalled(t *testing.T) {
	s, releaseSnapshot := newStalledSnapshotStore(t, 1)

	returned := make(chan bool, 1)
	go func() {
		returned <- s.ObserveVPN("ipsec", "established", "success", "TESTLAN to LXC105")
	}()

	select {
	case accepted := <-returned:
		if !accepted {
			t.Fatal("accepted = false with free handoff capacity")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("ObserveVPN blocked behind a stalled snapshot")
	}
	releaseSnapshot()
}

// connection is the one deployment-scale dimension on the vpn tuple, so it is what
// the per-family budget has to bound.
func TestLogEventStore_VPNKeysAreCappedWithoutLoss(t *testing.T) {
	s := newTestLogEventStore(t)
	s.SetMaxKeys(1)
	for _, connection := range []string{"TESTLAN to LXC105", "BRANCH to HQ"} {
		for range 2 {
			if !s.ObserveVPN("ipsec", "established", "success", connection) {
				t.Fatalf("observation for %s was refused", connection)
			}
		}
	}
	s.sync()

	if got := s.vpn.len(); got != 1 {
		t.Errorf("live keys = %d, want 1", got)
	}
	live, overflow := s.vpn.snapshot()
	if got := live[vpnKey{backend: "ipsec", event: "established", result: "success", connection: "TESTLAN to LXC105"}]; got != 2 {
		t.Errorf("first connection count = %v, want 2", got)
	}
	if overflow != 2 {
		t.Errorf("overflow = %v, want 2", overflow)
	}
}

func TestLogEventStore_GatewayObservationReturnsImmediatelyWhenSnapshotIsStalled(t *testing.T) {
	s, releaseSnapshot := newStalledSnapshotStore(t, 1)

	returned := make(chan bool, 1)
	go func() {
		returned <- s.ObserveGateway("alarm_started", "TEST_GATEWAY")
	}()

	select {
	case accepted := <-returned:
		if !accepted {
			t.Fatal("accepted = false with free handoff capacity")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("ObserveGateway blocked behind a stalled snapshot")
	}
	releaseSnapshot()
}

func TestLogEventStore_RADIUSObservationReturnsImmediatelyWhenSnapshotIsStalled(t *testing.T) {
	s, releaseSnapshot := newStalledSnapshotStore(t, 1)

	returned := make(chan bool, 1)
	go func() {
		returned <- s.ObserveRADIUS("access", "accepted", "configured")
	}()

	select {
	case accepted := <-returned:
		if !accepted {
			t.Fatal("accepted = false with free handoff capacity")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("ObserveRADIUS blocked behind a stalled snapshot")
	}
	releaseSnapshot()
}

func TestLogEventStore_GatewayKeysAreCappedWithoutLoss(t *testing.T) {
	s := newTestLogEventStore(t)
	s.SetMaxKeys(1)
	for _, gateway := range []string{"TEST_GATEWAY", "WAN_DHCP"} {
		for range 2 {
			if !s.ObserveGateway("alarm_started", gateway) {
				t.Fatalf("observation for %s was refused", gateway)
			}
		}
	}
	s.sync()

	if got := s.gateway.len(); got != 1 {
		t.Errorf("live keys = %d, want 1", got)
	}
	live, overflow := s.gateway.snapshot()
	if got := live[gatewayKey{event: "alarm_started", gateway: "TEST_GATEWAY"}]; got != 2 {
		t.Errorf("first gateway count = %v, want 2", got)
	}
	if overflow != 2 {
		t.Errorf("overflow = %v, want 2", overflow)
	}
}

func TestLogEventStore_RADIUSKeysAreCappedWithoutLoss(t *testing.T) {
	s := newTestLogEventStore(t)
	s.SetMaxKeys(1)
	for _, result := range []string{"accepted", "rejected"} {
		for range 2 {
			if !s.ObserveRADIUS("access", result, "configured") {
				t.Fatalf("observation for %s was refused", result)
			}
		}
	}
	s.sync()

	if got := s.radius.len(); got != 1 {
		t.Errorf("live keys = %d, want 1", got)
	}
	live, overflow := s.radius.snapshot()
	if got := live[radiusKey{event: "access", result: "accepted", clientScope: "configured"}]; got != 2 {
		t.Errorf("accepted count = %v, want 2", got)
	}
	if overflow != 2 {
		t.Errorf("overflow = %v, want 2", overflow)
	}
}

// Every family gets a counter, including ones that are empty on any given network
// (voip/sip). A family silently missing a counter looks identical to a family with
// no traffic.
func TestLogEventStore_ObserveZenarmorEveryFamily(t *testing.T) {
	s := newTestLogEventStore(t)
	for _, f := range []string{"flow", "dns", "tls", "web", "ids", "voip"} {
		s.ObserveZenarmor(logship.ZenarmorObservation{Family: f, Action: "pass"})
	}
	s.sync()
	if got := s.zen.len(); got != 6 {
		t.Errorf("distinct families counted = %d, want 6", got)
	}
}

// The store must satisfy the sink contract in full. This is exactly what breaks
// when a method is added to MetricSink and an implementation is missed — main.go's
// `var _ logship.MetricSink = collector.LogEvents` catches it at build time, and
// this catches it here, where the failure is legible.
func TestLogEventStore_SatisfiesMetricSink(t *testing.T) {
	var _ logship.MetricSink = (*LogEventStore)(nil)
}

// The whole point of the budget: a sender that mints novel tuples stops growing the
// map at the ceiling, and NOTHING is lost — every observation is still accounted
// for, either in a live series or in the family's overflow total.
func TestLogEventStore_CapsNovelKeysWithoutLosingObservations(t *testing.T) {
	const (
		budget       = 3
		distinct     = 10
		observations = 2
	)
	s := newTestLogEventStore(t)
	s.SetMaxKeys(budget)

	for i := 0; i < distinct; i++ {
		for j := 0; j < observations; j++ {
			// ruleID is one of the genuinely free-form dimensions: it is whatever the
			// sender's filterlog line carried.
			s.ObserveFirewall("block", "igb0", "rule-"+strconv.Itoa(i), "desc", "wan")
		}
	}
	s.sync()

	if got := s.fw.len(); got != budget {
		t.Errorf("live keys = %d, want the budget %d", got, budget)
	}
	live, overflow := s.fw.snapshot()
	var sum float64
	for _, v := range live {
		sum += v
	}
	if want := float64(budget * observations); sum != want {
		t.Errorf("summed live series = %v, want %v", sum, want)
	}
	if want := float64((distinct - budget) * observations); overflow != want {
		t.Errorf("overflow = %v, want exactly the excess %v", overflow, want)
	}
	// The invariant that makes the cap safe to reason about: series + overflow is
	// the true observed count, at every scrape.
	if want := float64(distinct * observations); sum+overflow != want {
		t.Errorf("series + overflow = %v, want the observation count %v", sum+overflow, want)
	}
}

// An already-tracked tuple keeps counting after the ceiling is hit. Steady-state
// traffic must be unaffected once the working set is established — only NOVELTY is
// bounded.
func TestLogEventStore_KnownKeysKeepCountingAtTheCeiling(t *testing.T) {
	s := newTestLogEventStore(t)
	s.SetMaxKeys(1)
	s.ObserveFirewall("block", "igb0", "rule-1", "desc", "wan")
	s.ObserveFirewall("block", "igb0", "rule-2", "desc", "wan") // novel, refused, folded
	s.ObserveFirewall("block", "igb0", "rule-1", "desc", "wan")
	s.sync()

	live, overflow := s.fw.snapshot()
	if got := live[fwKey{action: "block", iface: "igb0", ruleID: "rule-1", ruleName: "desc", scope: "wan"}]; got != 2 {
		t.Errorf("known key = %v, want 2", got)
	}
	if overflow != 1 {
		t.Errorf("overflow = %v, want 1", overflow)
	}
}

// 0 is the documented "disabled" value of --logs.max-metric-keys, not a budget of
// zero keys. Getting this backwards would silently fold EVERY tuple.
func TestLogEventStore_ZeroMaxKeysDisablesTheCap(t *testing.T) {
	s := newTestLogEventStore(t)
	s.SetMaxKeys(0)
	for i := 0; i < 200; i++ {
		s.ObserveFirewall("block", "igb0", "rule-"+strconv.Itoa(i), "desc", "wan")
	}
	s.sync()
	if got := s.fw.len(); got != 200 {
		t.Errorf("live keys = %d, want all 200 (cap disabled)", got)
	}
	if _, overflow := s.fw.snapshot(); overflow != 0 {
		t.Errorf("overflow = %v, want 0 with the cap disabled", overflow)
	}
}

// SetMaxKeys must reach EVERY family. A family missed here is an unbounded map that
// no other test would notice, because each family is fed by a different program.
func TestLogEventStore_SetMaxKeysAppliesToEveryFamily(t *testing.T) {
	s := newTestLogEventStore(t)
	s.SetMaxKeys(1)

	for i := 0; i < 3; i++ {
		n := strconv.Itoa(i)
		s.ObserveFirewall("block", "igb"+n, "", "", "")
		s.ObserveHAProxy("http_request", "bk-"+n, "", "", "")
		s.ObserveSSHD("failed", "publickey-"+n, "")
		s.ObserveDHCP("ack", "igb"+n, "")
		s.ObserveAudit("config_change-"+n, "")
		s.ObserveIDS("alert", "block", "cat-"+n, "")
		s.ObserveGateway("alarm_started", "gateway-"+n)
		s.ObserveRADIUS("access", []string{"accepted", "rejected", "rejected"}[i], "configured")
		s.ObserveZenarmor(logship.ZenarmorObservation{Family: "flow", Category: "cat-" + n})
	}
	s.sync()

	type sat struct {
		keys     int
		overflow float64
	}
	families := map[string]sat{
		logFamilyFirewall: {s.fw.len(), overflowOf(s.fw.snapshot())},
		logFamilyHAProxy:  {s.ha.len(), overflowOf(s.ha.snapshot())},
		logFamilySSHD:     {s.ssh.len(), overflowOf(s.ssh.snapshot())},
		logFamilyDHCP:     {s.dhcp.len(), overflowOf(s.dhcp.snapshot())},
		logFamilyAudit:    {s.audit.len(), overflowOf(s.audit.snapshot())},
		logFamilyIDS:      {s.ids.len(), overflowOf(s.ids.snapshot())},
		logFamilyGateway:  {s.gateway.len(), overflowOf(s.gateway.snapshot())},
		logFamilyRADIUS:   {s.radius.len(), overflowOf(s.radius.snapshot())},
		logFamilyZenarmor: {s.zen.len(), overflowOf(s.zen.snapshot())},
	}
	if len(families) != 9 {
		t.Fatalf("families asserted = %d, want all 9 (duplicate family constant?)", len(families))
	}
	for name, got := range families {
		if got.keys != 1 {
			t.Errorf("%s live keys = %d, want 1", name, got.keys)
		}
		if got.overflow != 2 {
			t.Errorf("%s overflow = %v, want 2", name, got.overflow)
		}
	}
}

// overflowOf drops a snapshot's map so a call fits in a struct literal.
func overflowOf[K comparable](_ map[K]float64, overflow float64) float64 { return overflow }

// The saturation series must actually be emitted — one per family, every scrape,
// including the families sitting at zero. A counter that materialises only once it
// is non-zero cannot be alerted on before it matters.
func TestLogEventsCollector_EmitsSaturationSeries(t *testing.T) {
	c := &logEventsCollector{store: newTestLogEventStore(t), subsystem: LogEventsSubsystem}
	c.Register(namespace, "opnsense.example.com", promslog.NewNopLogger())
	c.store.SetMaxKeys(1)
	c.store.ObserveFirewall("block", "igb0", "rule-1", "", "")
	c.store.ObserveFirewall("block", "igb0", "rule-2", "", "") // folded

	metrics := collectMetrics(t, c, nil)
	assertNoDuplicateSeries(t, metrics)

	capped := map[string]float64{}
	keys := map[string]float64{}
	for _, m := range metrics {
		switch {
		case hasFqName(m, "opnsense_log_events_cardinality_capped_total"):
			capped[getMetricLabels(m)["family"]] = getMetricValue(m)
		case hasFqName(m, "opnsense_log_events_cardinality_keys"):
			keys[getMetricLabels(m)["family"]] = getMetricValue(m)
		}
	}

	// 13 families: firewall, haproxy, sshd, dhcp, audit, ids, gateway, radius, vpn,
	// carp, upnp, zenarmor, and the zenarmor_device INVENTORY (#474) — which is not a
	// counter family but reports saturation through the same pair, because a truncated
	// device inventory is exactly as invisible as a truncated counter. Bump it when a
	// family is added — the point of the count is that EVERY family publishes its
	// saturation pair from zero, so a family wired into the store without a saturation
	// entry fails here rather than going unmonitored.
	if len(capped) != 13 {
		t.Errorf("capped families emitted = %d, want 13: %v", len(capped), capped)
	}
	if len(keys) != 13 {
		t.Errorf("keys families emitted = %d, want 13: %v", len(keys), keys)
	}
	if capped[logFamilyFirewall] != 1 {
		t.Errorf("firewall capped = %v, want 1", capped[logFamilyFirewall])
	}
	if keys[logFamilyFirewall] != 1 {
		t.Errorf("firewall keys = %v, want 1", keys[logFamilyFirewall])
	}
	if capped[logFamilyZenarmor] != 0 {
		t.Errorf("zenarmor capped = %v, want 0 published from zero", capped[logFamilyZenarmor])
	}
	if capped[logFamilyGateway] != 0 {
		t.Errorf("gateway capped = %v, want 0 published from zero", capped[logFamilyGateway])
	}
	if capped[logFamilyVPN] != 0 {
		t.Errorf("vpn capped = %v, want 0 published from zero", capped[logFamilyVPN])
	}
	if capped[logFamilyRADIUS] != 0 {
		t.Errorf("radius capped = %v, want 0 published from zero", capped[logFamilyRADIUS])
	}
	if keys[logFamilyRADIUS] != 0 {
		t.Errorf("radius keys = %v, want 0 published from zero", keys[logFamilyRADIUS])
	}
	if capped[logFamilyCARP] != 0 {
		t.Errorf("carp capped = %v, want 0 published from zero", capped[logFamilyCARP])
	}
	if keys[logFamilyCARP] != 0 {
		t.Errorf("carp keys = %v, want 0 published from zero", keys[logFamilyCARP])
	}
	if capped[logFamilyUPnP] != 0 {
		t.Errorf("upnp capped = %v, want 0 published from zero", capped[logFamilyUPnP])
	}
	if keys[logFamilyUPnP] != 0 {
		t.Errorf("upnp keys = %v, want 0 published from zero", keys[logFamilyUPnP])
	}
	assertMetricsAreCounters(t, metrics, "opnsense_log_events_cardinality_capped_total")
}

func TestLogEventsCollector_EmitsGatewayCounter(t *testing.T) {
	c := &logEventsCollector{store: newTestLogEventStore(t), subsystem: LogEventsSubsystem}
	c.Register(namespace, "opnsense.example.com", promslog.NewNopLogger())
	c.store.ObserveGateway("alarm_started", "TEST_GATEWAY")
	c.store.ObserveGateway("alarm_started", "TEST_GATEWAY")

	metrics := collectMetrics(t, c, nil)
	for _, m := range metrics {
		if !hasFqName(m, "opnsense_log_events_gateway_total") {
			continue
		}
		labels := getMetricLabels(m)
		if len(labels) != 3 {
			t.Fatalf("gateway labels = %v, want only event, gateway and opnsense_instance", labels)
		}
		if labels["event"] != "alarm_started" || labels["gateway"] != "TEST_GATEWAY" || labels["opnsense_instance"] != "opnsense.example.com" {
			t.Fatalf("gateway labels = %v, want event/alarm_started gateway/TEST_GATEWAY instance/opnsense.example.com", labels)
		}
		if got := getMetricValue(m); got != 2 {
			t.Errorf("gateway counter = %v, want 2", got)
		}
		return
	}
	t.Fatal("gateway_total was not emitted")
}

// The frozen #405 metric contract: exactly event, from, to, interface, vhid and the
// standard opnsense_instance. THE KERNEL'S CAUSE MUST NEVER BE A LABEL, and neither
// may the signed demotion delta or the resulting total — a reason, reason_class,
// delta or total label must fail this test on the label count alone.
func TestLogEventsCollector_EmitsCARPCounter(t *testing.T) {
	c := &logEventsCollector{store: newTestLogEventStore(t), subsystem: LogEventsSubsystem}
	c.Register(namespace, "opnsense.example.com", promslog.NewNopLogger())
	c.store.ObserveCARP("state_changed", "backup", "master", "vtnet2", "9")
	c.store.ObserveCARP("state_changed", "backup", "master", "vtnet2", "9")

	metrics := collectMetrics(t, c, nil)
	for _, m := range metrics {
		if !hasFqName(m, "opnsense_log_events_carp_total") {
			continue
		}
		labels := getMetricLabels(m)
		if len(labels) != 6 {
			t.Fatalf("carp labels = %v, want only event, from, to, interface, vhid and opnsense_instance", labels)
		}
		for _, forbidden := range []string{"reason", "reason_class", "cause", "delta", "total", "demotion"} {
			if _, present := labels[forbidden]; present {
				t.Errorf("carp carries a %q label; the kernel cause and demotion values must stay log attributes", forbidden)
			}
		}
		if labels["event"] != "state_changed" ||
			labels["from"] != "backup" ||
			labels["to"] != "master" ||
			labels["interface"] != "vtnet2" ||
			labels["vhid"] != "9" ||
			labels["opnsense_instance"] != "opnsense.example.com" {
			t.Fatalf("carp labels = %v, want state_changed/backup/master/vtnet2/9/opnsense.example.com", labels)
		}
		if got := getMetricValue(m); got != 2 {
			t.Errorf("carp counter = %v, want 2", got)
		}
		return
	}
	t.Fatal("carp_total was not emitted")
}

// A demotion record names neither an interface nor a VHID, so it must emit with those
// four label values EMPTY rather than being dropped or given placeholder values.
func TestLogEventsCollector_EmitsCARPDemotionWithEmptyStateLabels(t *testing.T) {
	c := &logEventsCollector{store: newTestLogEventStore(t), subsystem: LogEventsSubsystem}
	c.Register(namespace, "opnsense.example.com", promslog.NewNopLogger())
	c.store.ObserveCARP("promoted", "", "", "", "")

	metrics := collectMetrics(t, c, nil)
	for _, m := range metrics {
		if !hasFqName(m, "opnsense_log_events_carp_total") {
			continue
		}
		labels := getMetricLabels(m)
		if labels["event"] != "promoted" {
			t.Fatalf("carp labels = %v, want event/promoted", labels)
		}
		for _, empty := range []string{"from", "to", "interface", "vhid"} {
			if labels[empty] != "" {
				t.Errorf("carp %s = %q on a demotion record, want empty", empty, labels[empty])
			}
		}
		return
	}
	t.Fatal("carp_total was not emitted for a demotion record")
}

// The frozen #409 metric contract: exactly event, result, protocol and the standard
// opnsense_instance. A PORT LABEL MUST NEVER APPEAR — an ephemeral client port is
// unbounded and would mint a series per mapping — and neither may the daemon's opaque
// addr= token, a lease-file path, a mapping description or any client identity. Nor
// may a mapping COUNT: #409 forbids an active-mapping gauge, so a `mappings` or
// `active` label (or any gauge-shaped series in this family) must fail here.
func TestLogEventsCollector_EmitsUPnPCounter(t *testing.T) {
	c := &logEventsCollector{store: newTestLogEventStore(t), subsystem: LogEventsSubsystem}
	c.Register(namespace, "opnsense.example.com", promslog.NewNopLogger())
	c.store.ObserveUPnP("expired", "ok", "udp")
	c.store.ObserveUPnP("expired", "ok", "udp")

	metrics := collectMetrics(t, c, nil)
	for _, m := range metrics {
		if !hasFqName(m, "opnsense_log_events_upnp_total") {
			continue
		}
		labels := getMetricLabels(m)
		if len(labels) != 4 {
			t.Fatalf("upnp labels = %v, want only event, result, protocol and opnsense_instance", labels)
		}
		for _, forbidden := range []string{
			"port", "iport", "eport", "internal_port", "external_port",
			"addr", "address", "client", "description", "lease_file", "mappings", "active",
		} {
			if _, present := labels[forbidden]; present {
				t.Errorf("upnp carries a %q label; ports, client identity and mapping counts must never be labels", forbidden)
			}
		}
		if labels["event"] != "expired" ||
			labels["result"] != "ok" ||
			labels["protocol"] != "udp" ||
			labels["opnsense_instance"] != "opnsense.example.com" {
			t.Fatalf("upnp labels = %v, want expired/ok/udp/opnsense.example.com", labels)
		}
		if got := getMetricValue(m); got != 2 {
			t.Errorf("upnp counter = %v, want 2", got)
		}
		return
	}
	t.Fatal("upnp_total was not emitted")
}

// A cleanup failure and a lease-file error name no protocol, so they must emit with
// that label EMPTY rather than being dropped or given a placeholder. The dominant
// production record (1,527 of 1,598) is exactly this shape.
func TestLogEventsCollector_EmitsUPnPWithEmptyProtocol(t *testing.T) {
	c := &logEventsCollector{store: newTestLogEventStore(t), subsystem: LogEventsSubsystem}
	c.Register(namespace, "opnsense.example.com", promslog.NewNopLogger())
	c.store.ObserveUPnP("cleanup_failed", "failure", "")

	metrics := collectMetrics(t, c, nil)
	for _, m := range metrics {
		if !hasFqName(m, "opnsense_log_events_upnp_total") {
			continue
		}
		labels := getMetricLabels(m)
		if labels["event"] != "cleanup_failed" || labels["result"] != "failure" {
			t.Fatalf("upnp labels = %v, want cleanup_failed/failure", labels)
		}
		if labels["protocol"] != "" {
			t.Errorf("upnp protocol = %q on a cleanup failure, want empty", labels["protocol"])
		}
		return
	}
	t.Fatal("upnp_total was not emitted for a cleanup failure")
}

// The frozen #406 metric contract: exactly backend, event, result, connection and
// the standard opnsense_instance. A username, certificate CN/serial, IKE identity,
// peer address, port, SPI or error-text label must fail this test on the label
// count alone.
func TestLogEventsCollector_EmitsVPNCounter(t *testing.T) {
	c := &logEventsCollector{store: newTestLogEventStore(t), subsystem: LogEventsSubsystem}
	c.Register(namespace, "opnsense.example.com", promslog.NewNopLogger())
	c.store.ObserveVPN("ipsec", "established", "success", "TESTLAN to LXC105")
	c.store.ObserveVPN("ipsec", "established", "success", "TESTLAN to LXC105")

	metrics := collectMetrics(t, c, nil)
	for _, m := range metrics {
		if !hasFqName(m, "opnsense_log_events_vpn_total") {
			continue
		}
		labels := getMetricLabels(m)
		if len(labels) != 5 {
			t.Fatalf("vpn labels = %v, want only backend, event, result, connection and opnsense_instance", labels)
		}
		if labels["backend"] != "ipsec" ||
			labels["event"] != "established" ||
			labels["result"] != "success" ||
			labels["connection"] != "TESTLAN to LXC105" ||
			labels["opnsense_instance"] != "opnsense.example.com" {
			t.Fatalf("vpn labels = %v, want ipsec/established/success/TESTLAN to LXC105/opnsense.example.com", labels)
		}
		if got := getMetricValue(m); got != 2 {
			t.Errorf("vpn counter = %v, want 2", got)
		}
		return
	}
	t.Fatal("vpn_total was not emitted")
}

// An unresolved connection ships as an EMPTY label, never a placeholder and never
// the raw UUID the log line carried.
func TestLogEventsCollector_EmitsVPNCounterWithAnEmptyConnection(t *testing.T) {
	c := &logEventsCollector{store: newTestLogEventStore(t), subsystem: LogEventsSubsystem}
	c.Register(namespace, "opnsense.example.com", promslog.NewNopLogger())
	c.store.ObserveVPN("openvpn", "certificate_failed", "failure", "")

	metrics := collectMetrics(t, c, nil)
	for _, m := range metrics {
		if !hasFqName(m, "opnsense_log_events_vpn_total") {
			continue
		}
		labels := getMetricLabels(m)
		if labels["connection"] != "" {
			t.Fatalf("connection = %q, want empty for an unresolved tunnel", labels["connection"])
		}
		if labels["backend"] != "openvpn" || labels["event"] != "certificate_failed" || labels["result"] != "failure" {
			t.Fatalf("vpn labels = %v, want openvpn/certificate_failed/failure", labels)
		}
		return
	}
	t.Fatal("vpn_total was not emitted")
}

func TestLogEventsCollector_EmitsRADIUSCounter(t *testing.T) {
	c := &logEventsCollector{store: newTestLogEventStore(t), subsystem: LogEventsSubsystem}
	c.Register(namespace, "opnsense.example.com", promslog.NewNopLogger())
	c.store.ObserveRADIUS("access", "accepted", "configured")
	c.store.ObserveRADIUS("access", "accepted", "configured")

	metrics := collectMetrics(t, c, nil)
	for _, m := range metrics {
		if !hasFqName(m, "opnsense_log_events_radius_total") {
			continue
		}
		labels := getMetricLabels(m)
		if len(labels) != 4 {
			t.Fatalf("radius labels = %v, want only event, result, client_scope and opnsense_instance", labels)
		}
		if labels["event"] != "access" ||
			labels["result"] != "accepted" ||
			labels["client_scope"] != "configured" ||
			labels["opnsense_instance"] != "opnsense.example.com" {
			t.Fatalf("radius labels = %v, want access/accepted/configured/opnsense.example.com", labels)
		}
		if got := getMetricValue(m); got != 2 {
			t.Errorf("radius counter = %v, want 2", got)
		}
		return
	}
	t.Fatal("radius_total was not emitted")
}

// --- #474: the bounded Zenarmor device inventory ----------------------------

// The picker's whole reason for existing: one series per live device, value 1, with
// the name as a LABEL so label_values() can enumerate it. Loki cannot do this at all
// — device_name is structured metadata there — which is why the metric is here and
// not a promoted Loki label (#473).
func TestLogEventsCollector_EmitsZenarmorDeviceInfo(t *testing.T) {
	c := &logEventsCollector{store: newTestLogEventStore(t), subsystem: LogEventsSubsystem}
	c.Register(namespace, "opnsense.example.com", promslog.NewNopLogger())
	c.store.ObserveZenarmorDevice("robs-laptop", "laptop", "IOT")
	c.store.ObserveZenarmorDevice("robs-laptop", "laptop", "IOT") // a repeat is one series
	c.store.ObserveZenarmorDevice("hallway-cam", "camera", "IOT")

	var seen []map[string]string
	for _, m := range collectMetrics(t, c, nil) {
		if !hasFqName(m, "opnsense_log_events_zenarmor_device_info") {
			continue
		}
		labels := getMetricLabels(m)
		if len(labels) != 4 {
			t.Fatalf("device_info labels = %v, want device_name, device_category, interface and opnsense_instance", labels)
		}
		if got := getMetricValue(m); got != 1 {
			t.Errorf("device_info value = %v, want 1 — an info metric's payload is its labels", got)
		}
		if labels["opnsense_instance"] != "opnsense.example.com" {
			t.Errorf("device_info instance = %q", labels["opnsense_instance"])
		}
		seen = append(seen, labels)
	}
	if len(seen) != 2 {
		t.Fatalf("emitted %d device series, want 2 (the repeat must not duplicate): %v", len(seen), seen)
	}
	// Sorted by name, so a scrape diff shows real changes only.
	if seen[0]["device_name"] != "hallway-cam" || seen[1]["device_name"] != "robs-laptop" {
		t.Errorf("device series out of order: %v", seen)
	}
}

// An empty name is not a device. Left in, it would be a permanent empty-named series
// that reads as a real entry on the picker.
func TestLogEventStore_ZenarmorDeviceIgnoresAnEmptyName(t *testing.T) {
	s := newTestLogEventStore(t)
	if s.ObserveZenarmorDevice("", "laptop", "LAN") {
		t.Error("ObserveZenarmorDevice accepted an empty name")
	}
	s.sync()
	snap, ok := s.snapshot()
	if !ok {
		t.Fatal("snapshot failed")
	}
	if len(snap.zenDevs) != 0 {
		t.Fatalf("inventory = %v, want empty", snap.zenDevs)
	}
}

// The TTL is what stops a device that visited once from reading as present forever —
// the failure mode a plain capped map cannot fix, because a cap alone never shrinks.
func TestLogEventStore_ZenarmorDeviceExpires(t *testing.T) {
	s := newTestLogEventStore(t)
	now := time.Unix(0, 0).UTC()
	s.setClock(func() time.Time { return now })

	s.ObserveZenarmorDevice("visitor", "mobile", "GUEST")
	s.sync()
	if snap, _ := s.snapshot(); len(snap.zenDevs) != 1 {
		t.Fatalf("inventory = %v, want the device present while fresh", snap.zenDevs)
	}

	now = now.Add(zenarmorDeviceTTL + time.Second)
	snap, _ := s.snapshot()
	if len(snap.zenDevs) != 0 {
		t.Fatalf("inventory = %v, want empty once the device is a TTL stale", snap.zenDevs)
	}
}

// The cap is the guard against the churning DNS-derived names that made device_name
// unpromotable in #473. Refusals must be COUNTED, under the inventory's own family,
// so a truncated picker is visible rather than looking like a small network.
func TestLogEventStore_ZenarmorDeviceCapIsCountedNotSilent(t *testing.T) {
	s := newTestLogEventStore(t)
	for i := range maxZenarmorDevices + 10 {
		s.ObserveZenarmorDevice("dev-"+strconv.Itoa(i), "other", "LAN")
	}
	s.sync()
	snap, ok := s.snapshot()
	if !ok {
		t.Fatal("snapshot failed")
	}
	if n := len(snap.zenDevs); n != maxZenarmorDevices {
		t.Fatalf("inventory holds %d devices, want the cap of %d", n, maxZenarmorDevices)
	}
	for _, sat := range snap.sat {
		if sat.family != logFamilyZenarmorDevice {
			continue
		}
		if sat.capped != 10 {
			t.Errorf("capped = %v, want the 10 refused devices", sat.capped)
		}
		if sat.keys != float64(maxZenarmorDevices) {
			t.Errorf("keys = %v, want %d", sat.keys, maxZenarmorDevices)
		}
		return
	}
	t.Fatalf("no saturation entry for family %q", logFamilyZenarmorDevice)
}

// #476, end to end: a device seen before the enrichment snapshot loaded and again
// afterwards is ONE row, carrying the resolved interface. It used to be two — one
// naming the kernel device, one the description-space name — because the interface
// was part of the inventory key, and the stale row then sat out its full 24h TTL.
func TestLogEventsCollector_ZenarmorDeviceIsOneRowAcrossEnrichment(t *testing.T) {
	c := &logEventsCollector{store: newTestLogEventStore(t), subsystem: LogEventsSubsystem}
	c.Register(namespace, "opnsense.example.com", promslog.NewNopLogger())
	c.store.ObserveZenarmorDevice("jules", "camera", "ixl0") // pre-enrichment
	c.store.ObserveZenarmorDevice("jules", "camera", "LAN")  // enrichment resolved

	var rows []map[string]string
	for _, m := range collectMetrics(t, c, nil) {
		if hasFqName(m, "opnsense_log_events_zenarmor_device_info") {
			rows = append(rows, getMetricLabels(m))
		}
	}
	if len(rows) != 1 {
		t.Fatalf("emitted %d rows for one device, want 1: %v", len(rows), rows)
	}
	if rows[0]["interface"] != "LAN" {
		t.Errorf("interface = %q, want LAN — the most recent sighting wins", rows[0]["interface"])
	}
}

// A device that genuinely changes category is still one row, for the same reason.
func TestLogEventStore_ZenarmorDeviceCategoryIsLastWriteWins(t *testing.T) {
	s := newTestLogEventStore(t)
	s.ObserveZenarmorDevice("thing", "other", "LAN")
	s.ObserveZenarmorDevice("thing", "iot", "LAN")
	s.sync()
	snap, ok := s.snapshot()
	if !ok {
		t.Fatal("snapshot failed")
	}
	if len(snap.zenDevs) != 1 {
		t.Fatalf("inventory = %v, want one entry", snap.zenDevs)
	}
	if snap.zenDevs[0].val.category != "iot" {
		t.Errorf("category = %q, want iot", snap.zenDevs[0].val.category)
	}
}
