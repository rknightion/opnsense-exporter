package collector

import (
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/promslog"
)

// metricIsGauge reports whether a metric wrote itself as a GAUGE. The lease
// timestamps must be gauges: emitted as counters, Prometheus would treat a re-bind
// that shortens the deadline as a counter reset and rate() over them would be
// nonsense.
func metricIsGauge(t *testing.T, m interface{ Write(*dto.Metric) error }) bool {
	t.Helper()
	d := &dto.Metric{}
	if err := m.Write(d); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	return d.Gauge != nil
}

func TestLogEventStore_ObserveNetmapRingFull(t *testing.T) {
	s := newTestLogEventStore(t)
	for i := 0; i < 3; i++ {
		if !s.ObserveNetmapRingFull("ixl0") {
			t.Fatalf("observation %d was refused", i)
		}
	}
	if !s.ObserveNetmapRingFull("ixl1") {
		t.Fatal("second-device observation was refused")
	}
	s.sync()

	if got := s.netmap.m[netmapKey{device: "ixl0"}]; got != 3 {
		t.Errorf("ixl0 count = %v, want 3", got)
	}
	if got := s.netmap.m[netmapKey{device: "ixl1"}]; got != 1 {
		t.Errorf("ixl1 count = %v, want 1", got)
	}
	if got := s.netmap.len(); got != 2 {
		t.Errorf("distinct keys = %d, want 2", got)
	}
}

func TestLogEventStore_ObserveARPMove(t *testing.T) {
	s := newTestLogEventStore(t)
	// A flap is two moves on ONE interface, not two series: the contested address and
	// both MACs never reach the key.
	for i := 0; i < 2; i++ {
		if !s.ObserveARPMove("ixl0_vlan90") {
			t.Fatalf("observation %d was refused", i)
		}
	}
	s.sync()

	if got := s.arp.m[arpKey{iface: "ixl0_vlan90"}]; got != 2 {
		t.Errorf("count = %v, want 2", got)
	}
	if got := s.arp.len(); got != 1 {
		t.Errorf("distinct keys = %d, want 1; a flap must not fork a series per MAC", got)
	}
}

func TestLogEventStore_ObserveDHCPClient(t *testing.T) {
	s := newTestLogEventStore(t)
	for i := 0; i < 5; i++ {
		if !s.ObserveDHCPClient("ixl1", "request") {
			t.Fatalf("observation %d was refused", i)
		}
	}
	if !s.ObserveDHCPClient("ixl1", "ack") {
		t.Fatal("ack observation was refused")
	}
	// An uncorrelated received message keys under an EMPTY interface, which is a real
	// distinct series rather than one that should collapse into the correlated one.
	if !s.ObserveDHCPClient("", "ack") {
		t.Fatal("uncorrelated ack observation was refused")
	}
	if !s.ObserveDHCPClientScript("ixl1", "renew") {
		t.Fatal("script observation was refused")
	}
	s.sync()

	if got := s.dhcpCli.m[dhcpClientKey{iface: "ixl1", msgType: "request"}]; got != 5 {
		t.Errorf("request count = %v, want 5", got)
	}
	if got := s.dhcpCli.m[dhcpClientKey{iface: "ixl1", msgType: "ack"}]; got != 1 {
		t.Errorf("ack count = %v, want 1", got)
	}
	if got := s.dhcpCli.m[dhcpClientKey{msgType: "ack"}]; got != 1 {
		t.Errorf("uncorrelated ack count = %v, want 1", got)
	}
	if got := s.dhcpCli.len(); got != 3 {
		t.Errorf("distinct keys = %d, want 3", got)
	}
	if got := s.dhcpScr.m[dhcpClientScriptKey{iface: "ixl1", reason: "renew"}]; got != 1 {
		t.Errorf("script count = %v, want 1", got)
	}
}

// The lease family is a GAUGE: a later bind OVERWRITES the interface's pair rather
// than accumulating. Accumulating would produce a timestamp in the far future within
// a few renewals and silently break every "the deadline passed" query.
func TestLogEventStore_ObserveDHCPClientLeaseOverwritesRatherThanAccumulates(t *testing.T) {
	s := newTestLogEventStore(t)
	if !s.ObserveDHCPClientLease("ixl1", 1785012780, 1785315180) {
		t.Fatal("first lease observation was refused")
	}
	if !s.ObserveDHCPClientLease("ixl1", 1785099180, 1785401580) {
		t.Fatal("second lease observation was refused")
	}
	s.sync()

	got := s.dhcpLease.m[dhcpClientLeaseKey{iface: "ixl1"}]
	if got.bound != 1785099180 || got.renewal != 1785401580 {
		t.Errorf("lease = %+v, want the LATEST pair (1785099180/1785401580), not a sum", got)
	}
	if n := len(s.dhcpLease.m); n != 1 {
		t.Errorf("distinct keys = %d, want 1", n)
	}
}

// The gauge family carries the SAME insert-time key budget as every counter family,
// and a refusal folds into the same counted overflow. Without that, an unbounded
// interface label on a push-fed family would grow this map for the life of the
// process — the memory half of the problem cappedCounter exists to solve.
func TestLogEventStore_DHCPClientLeaseBudgetIsEnforcedAndCounted(t *testing.T) {
	s := newTestLogEventStore(t)
	s.SetMaxKeys(2)
	for _, iface := range []string{"ixl1", "ixl2", "ixl3", "ixl4"} {
		if !s.ObserveDHCPClientLease(iface, 1, 2) {
			t.Fatalf("observation for %s was refused by the handoff", iface)
		}
	}
	s.sync()

	if n := len(s.dhcpLease.m); n != 2 {
		t.Errorf("live gauge keys = %d, want the budget of 2", n)
	}
	if _, overflow := s.dhcpLease.snapshot(); overflow != 2 {
		t.Errorf("gauge overflow = %v, want 2 refused novel keys counted", overflow)
	}
	// An interface already in the map keeps being UPDATED after the budget is met.
	if !s.ObserveDHCPClientLease("ixl1", 99, 100) {
		t.Fatal("update of an existing key was refused")
	}
	s.sync()
	if got := s.dhcpLease.m[dhcpClientLeaseKey{iface: "ixl1"}]; got.bound != 99 {
		t.Errorf("existing key = %+v, want the update to land", got)
	}
}

// The frozen #536 netmap contract: exactly `device` plus the standard
// opnsense_instance. hwcur, hwtail and qlen must fail on the label count alone — and
// so must any attempt to rename the metric into something that reads as packets.
func TestLogEventsCollector_EmitsNetmapRingFullCounter(t *testing.T) {
	c := &logEventsCollector{store: newTestLogEventStore(t), subsystem: LogEventsSubsystem}
	c.Register(namespace, "opnsense.example.com", promslog.NewNopLogger())
	c.store.ObserveNetmapRingFull("ixl0")
	c.store.ObserveNetmapRingFull("ixl0")

	metrics := collectMetrics(t, c, nil)
	for _, m := range metrics {
		if !hasFqName(m, "opnsense_log_events_netmap_ring_full_events_total") {
			continue
		}
		labels := getMetricLabels(m)
		if len(labels) != 2 {
			t.Fatalf("netmap labels = %v, want only device and opnsense_instance", labels)
		}
		for _, forbidden := range []string{"hwcur", "hwtail", "qlen", "ring", "queue", "packets"} {
			if _, present := labels[forbidden]; present {
				t.Errorf("netmap carries a %q label; ring indices change per line and must never be labels", forbidden)
			}
		}
		if labels["device"] != "ixl0" || labels["opnsense_instance"] != "opnsense.example.com" {
			t.Fatalf("netmap labels = %v, want ixl0/opnsense.example.com", labels)
		}
		if got := getMetricValue(m); got != 2 {
			t.Errorf("netmap counter = %v, want 2", got)
		}
		return
	}
	t.Fatal("netmap_ring_full_events_total was not emitted")
}

// The name is a HARD contract. `netmap_transmit()` is kernel-rate-limited to 2
// lines/sec, so anything derived from it counts OCCURRENCES and saturates; a metric
// named `..._drops_total` would produce a number that looks like packets and is not.
// The help text must also say so, or an operator reads a flat 2/s as a bounded
// problem.
func TestLogEventsCollector_NetmapIsNamedForOccurrencesNotDrops(t *testing.T) {
	c := &logEventsCollector{store: newTestLogEventStore(t), subsystem: LogEventsSubsystem}
	c.Register(namespace, "opnsense.example.com", promslog.NewNopLogger())

	desc := c.netmapRingFull.String()
	if !containsAll(desc, "netmap_ring_full_events_total") {
		t.Fatalf("netmap desc = %s, want the events_total name", desc)
	}
	if containsAny(desc, "drops_total", "dropped_total", "drop_total") {
		t.Errorf("netmap metric is named as a DROP count; it is rate-limited to 2 lines/sec and is not a packet count: %s", desc)
	}
	for _, phrase := range []string{"OCCURRENCES", "2 lines per second", "NOT no drops"} {
		if !containsAll(desc, phrase) {
			t.Errorf("netmap help text is missing %q; without it a flat 2/s reads as a bounded problem: %s", phrase, desc)
		}
	}
}

// The frozen #536 ARP contract: exactly `interface` plus opnsense_instance. The
// contested IP and both MACs are unbounded and identify individual machines.
func TestLogEventsCollector_EmitsARPMovesCounter(t *testing.T) {
	c := &logEventsCollector{store: newTestLogEventStore(t), subsystem: LogEventsSubsystem}
	c.Register(namespace, "opnsense.example.com", promslog.NewNopLogger())
	c.store.ObserveARPMove("ixl0_vlan90")

	metrics := collectMetrics(t, c, nil)
	for _, m := range metrics {
		if !hasFqName(m, "opnsense_log_events_arp_address_moves_total") {
			continue
		}
		labels := getMetricLabels(m)
		if len(labels) != 2 {
			t.Fatalf("arp labels = %v, want only interface and opnsense_instance", labels)
		}
		for _, forbidden := range []string{"ip", "address", "mac", "mac_previous", "mac_current", "host", "client"} {
			if _, present := labels[forbidden]; present {
				t.Errorf("arp carries a %q label; the contested address and MACs are unbounded and PII-shaped", forbidden)
			}
		}
		if labels["interface"] != "ixl0_vlan90" {
			t.Fatalf("arp labels = %v, want ixl0_vlan90", labels)
		}
		return
	}
	t.Fatal("arp_address_moves_total was not emitted")
}

// The frozen #541 client contract: exactly interface and type, plus
// opnsense_instance. The DHCP server address and this firewall's leased address
// must fail on the label count alone.
func TestLogEventsCollector_EmitsDHCPClientCounters(t *testing.T) {
	c := &logEventsCollector{store: newTestLogEventStore(t), subsystem: LogEventsSubsystem}
	c.Register(namespace, "opnsense.example.com", promslog.NewNopLogger())
	c.store.ObserveDHCPClient("ixl1", "request")
	c.store.ObserveDHCPClient("ixl1", "request")
	c.store.ObserveDHCPClientScript("ixl1", "renew")

	var sawClient, sawScript bool
	for _, m := range collectMetrics(t, c, nil) {
		switch {
		case hasFqName(m, "opnsense_log_events_dhcp_client_total"):
			sawClient = true
			labels := getMetricLabels(m)
			if len(labels) != 3 {
				t.Fatalf("dhcp_client labels = %v, want only interface, type and opnsense_instance", labels)
			}
			for _, forbidden := range []string{"server", "address", "ip", "lease", "mac"} {
				if _, present := labels[forbidden]; present {
					t.Errorf("dhcp_client carries a %q label; addresses change under exactly the conditions this watches for", forbidden)
				}
			}
			if labels["interface"] != "ixl1" || labels["type"] != "request" {
				t.Fatalf("dhcp_client labels = %v, want ixl1/request", labels)
			}
			if got := getMetricValue(m); got != 2 {
				t.Errorf("dhcp_client counter = %v, want 2", got)
			}
		case hasFqName(m, "opnsense_log_events_dhcp_client_script_total"):
			sawScript = true
			labels := getMetricLabels(m)
			if len(labels) != 3 {
				t.Fatalf("dhcp_client_script labels = %v, want only interface, reason and opnsense_instance", labels)
			}
			if labels["interface"] != "ixl1" || labels["reason"] != "renew" {
				t.Fatalf("dhcp_client_script labels = %v, want ixl1/renew", labels)
			}
		}
	}
	if !sawClient {
		t.Error("dhcp_client_total was not emitted")
	}
	if !sawScript {
		t.Error("dhcp_client_script_total was not emitted")
	}
}

// The two lease metrics are GAUGES of absolute Unix seconds, keyed by interface
// alone, and they are emitted TOGETHER from one stored pair. A bind time published
// without its deadline is the half-state the pair exists to prevent, and a counter
// here would make a shortened deadline look like a counter reset.
func TestLogEventsCollector_EmitsLeaseTimestampGaugesTogether(t *testing.T) {
	c := &logEventsCollector{store: newTestLogEventStore(t), subsystem: LogEventsSubsystem}
	c.Register(namespace, "opnsense.example.com", promslog.NewNopLogger())
	c.store.ObserveDHCPClientLease("ixl1", 1785012780, 1785315180)

	var sawBound, sawRenewal bool
	for _, m := range collectMetrics(t, c, nil) {
		switch {
		case hasFqName(m, "opnsense_log_events_dhcp_client_lease_bound_timestamp_seconds"):
			sawBound = true
			if !metricIsGauge(t, m) {
				t.Error("the bound timestamp is not a GAUGE; a counter would read a re-bind as a reset")
			}
			labels := getMetricLabels(m)
			if len(labels) != 2 || labels["interface"] != "ixl1" {
				t.Fatalf("bound labels = %v, want only interface and opnsense_instance", labels)
			}
			if got := getMetricValue(m); got != 1785012780 {
				t.Errorf("bound timestamp = %v, want 1785012780", got)
			}
		case hasFqName(m, "opnsense_log_events_dhcp_client_lease_renewal_timestamp_seconds"):
			sawRenewal = true
			if !metricIsGauge(t, m) {
				t.Error("the renewal timestamp is not a GAUGE")
			}
			labels := getMetricLabels(m)
			if len(labels) != 2 || labels["interface"] != "ixl1" {
				t.Fatalf("renewal labels = %v, want only interface and opnsense_instance", labels)
			}
			if got := getMetricValue(m); got != 1785315180 {
				t.Errorf("renewal timestamp = %v, want 1785315180", got)
			}
		}
	}
	if !sawBound || !sawRenewal {
		t.Fatalf("lease gauges emitted: bound=%v renewal=%v; both must be published from one stored pair", sawBound, sawRenewal)
	}
}

// The gauges must survive a scrape that saw no new bind. They are current state, not
// a running total, so the snapshot must NOT drain them — a series that vanished
// between scrapes reads as "the interface went away" rather than "no new bind
// happened", and nothing else re-emits it.
func TestLogEventsCollector_LeaseGaugesPersistAcrossScrapes(t *testing.T) {
	c := &logEventsCollector{store: newTestLogEventStore(t), subsystem: LogEventsSubsystem}
	c.Register(namespace, "opnsense.example.com", promslog.NewNopLogger())
	c.store.ObserveDHCPClientLease("ixl1", 1785012780, 1785315180)

	for scrape := 1; scrape <= 3; scrape++ {
		found := false
		for _, m := range collectMetrics(t, c, nil) {
			if hasFqName(m, "opnsense_log_events_dhcp_client_lease_renewal_timestamp_seconds") {
				found = true
				if got := getMetricValue(m); got != 1785315180 {
					t.Errorf("scrape %d renewal = %v, want the value unchanged", scrape, got)
				}
			}
		}
		if !found {
			t.Fatalf("scrape %d lost the lease gauge; it is current state and must not be drained", scrape)
		}
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
