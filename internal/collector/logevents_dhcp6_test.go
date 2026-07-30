package collector

import (
	"testing"

	"github.com/prometheus/common/promslog"
)

// The frozen #546 dhcp6c message contract: exactly interface, direction and type,
// plus opnsense_instance. Anything address-shaped must fail on the label count alone.
func TestLogEventsCollector_EmitsDHCP6CMessageCounter(t *testing.T) {
	c := &logEventsCollector{store: newTestLogEventStore(t), subsystem: LogEventsSubsystem}
	c.Register(namespace, "opnsense.example.com", promslog.NewNopLogger())
	c.store.ObserveDHCP6CMessage("pppoe0", "sent", "renew")
	c.store.ObserveDHCP6CMessage("pppoe0", "sent", "renew")
	c.store.ObserveDHCP6CMessage("pppoe0", "received", "renew")

	counts := map[string]float64{}
	for _, m := range collectMetrics(t, c, nil) {
		if !hasFqName(m, "opnsense_log_events_dhcp6c_message_total") {
			continue
		}
		labels := getMetricLabels(m)
		if len(labels) != 4 {
			t.Fatalf("dhcp6c_message labels = %v, want only interface, direction, type and opnsense_instance", labels)
		}
		for _, forbidden := range []string{"prefix", "address", "duid", "server"} {
			if _, present := labels[forbidden]; present {
				t.Errorf("dhcp6c_message carries a %q label", forbidden)
			}
		}
		if labels["interface"] != "pppoe0" {
			t.Errorf("interface = %q, want pppoe0", labels["interface"])
		}
		counts[labels["direction"]+"/"+labels["type"]] = getMetricValue(m)
	}

	if counts["sent/renew"] != 2 {
		t.Errorf("sent/renew = %v, want 2", counts["sent/renew"])
	}
	if counts["received/renew"] != 1 {
		t.Errorf("received/renew = %v, want 1", counts["received/renew"])
	}
}

// The event counter's third dimension is the script REASON, and it is legitimately
// EMPTY on the prefix and address events — which name none — so an empty value must
// still produce a series rather than being folded away.
func TestLogEventsCollector_EmitsDHCP6CEventCounterWithAnEmptyReason(t *testing.T) {
	c := &logEventsCollector{store: newTestLogEventStore(t), subsystem: LogEventsSubsystem}
	c.Register(namespace, "opnsense.example.com", promslog.NewNopLogger())
	c.store.ObserveDHCP6CEvent("pppoe0", "prefix_updated", "")
	c.store.ObserveDHCP6CEvent("ixl0", "address_added", "")
	c.store.ObserveDHCP6CEvent("pppoe0", "script_executing", "renew")

	seen := map[string]map[string]string{}
	for _, m := range collectMetrics(t, c, nil) {
		if !hasFqName(m, "opnsense_log_events_dhcp6c_event_total") {
			continue
		}
		labels := getMetricLabels(m)
		if len(labels) != 4 {
			t.Fatalf("dhcp6c_event labels = %v, want only interface, event, reason and opnsense_instance", labels)
		}
		seen[labels["event"]] = labels
	}

	if got := seen["prefix_updated"]; got == nil || got["interface"] != "pppoe0" || got["reason"] != "" {
		t.Errorf("prefix_updated labels = %v, want pppoe0 with an empty reason", got)
	}
	// The DOWNSTREAM interface, which is the honest reading of `add an address … on ixl0`.
	if got := seen["address_added"]; got == nil || got["interface"] != "ixl0" {
		t.Errorf("address_added labels = %v, want the downstream interface ixl0", got)
	}
	if got := seen["script_executing"]; got == nil || got["reason"] != "renew" {
		t.Errorf("script_executing labels = %v, want reason=renew", got)
	}
}

// The three prefix-delegation metrics are GAUGES of absolute Unix seconds, keyed by
// interface and prefix LENGTH only, and they are emitted TOGETHER from one stored
// triple. The prefix itself must fail on the label count alone.
func TestLogEventsCollector_EmitsDHCP6CPrefixGaugesTogether(t *testing.T) {
	c := &logEventsCollector{store: newTestLogEventStore(t), subsystem: LogEventsSubsystem}
	c.Register(namespace, "opnsense.example.com", promslog.NewNopLogger())
	c.store.ObserveDHCP6CPrefix("pppoe0", "48", 1785398400, 1785400200, 1785402000)

	want := map[string]float64{
		"opnsense_log_events_dhcp6c_prefix_updated_timestamp_seconds":          1785398400,
		"opnsense_log_events_dhcp6c_prefix_preferred_expiry_timestamp_seconds": 1785400200,
		"opnsense_log_events_dhcp6c_prefix_valid_expiry_timestamp_seconds":     1785402000,
	}
	seen := map[string]bool{}

	for _, m := range collectMetrics(t, c, nil) {
		for name, wantValue := range want {
			if !hasFqName(m, name) {
				continue
			}
			seen[name] = true
			if !metricIsGauge(t, m) {
				t.Errorf("%s is not a GAUGE; a counter would read a shortened deadline as a reset", name)
			}
			labels := getMetricLabels(m)
			if len(labels) != 3 {
				t.Fatalf("%s labels = %v, want only interface, prefix_length and opnsense_instance", name, labels)
			}
			if labels["interface"] != "pppoe0" || labels["prefix_length"] != "48" {
				t.Errorf("%s labels = %v, want pppoe0//48", name, labels)
			}
			if _, present := labels["prefix"]; present {
				t.Errorf("%s carries a prefix label; the delegation changes under exactly the conditions this watches for", name)
			}
			if got := getMetricValue(m); got != wantValue {
				t.Errorf("%s = %v, want %v", name, got, wantValue)
			}
		}
	}

	for name := range want {
		if !seen[name] {
			t.Errorf("%s was not emitted; the three come from one line and must be published together", name)
		}
	}
}

// The prefix gauges are current state, so a scrape that saw no renewal must not lose
// them. A series that vanished would read as "the delegation went away" rather than
// "no new update happened" — and nothing else re-emits it.
func TestLogEventsCollector_DHCP6CPrefixGaugesPersistAcrossScrapes(t *testing.T) {
	c := &logEventsCollector{store: newTestLogEventStore(t), subsystem: LogEventsSubsystem}
	c.Register(namespace, "opnsense.example.com", promslog.NewNopLogger())
	c.store.ObserveDHCP6CPrefix("pppoe0", "48", 1785398400, 1785400200, 1785402000)

	for scrape := 1; scrape <= 3; scrape++ {
		found := false
		for _, m := range collectMetrics(t, c, nil) {
			if hasFqName(m, "opnsense_log_events_dhcp6c_prefix_valid_expiry_timestamp_seconds") {
				found = true
				if got := getMetricValue(m); got != 1785402000 {
					t.Errorf("scrape %d valid expiry = %v, want the value unchanged", scrape, got)
				}
			}
		}
		if !found {
			t.Fatalf("scrape %d lost the prefix gauge; it is current state and must not be drained", scrape)
		}
	}
}

// A re-delegation OVERWRITES the interface's row rather than adding to it: these are
// deadlines, not a running total, and a second /48 on the same WAN is last-write-wins
// by design.
func TestLogEventStore_DHCP6CPrefixOverwritesRatherThanAccumulates(t *testing.T) {
	c := &logEventsCollector{store: newTestLogEventStore(t), subsystem: LogEventsSubsystem}
	c.Register(namespace, "opnsense.example.com", promslog.NewNopLogger())
	c.store.ObserveDHCP6CPrefix("pppoe0", "48", 1785398400, 1785400200, 1785402000)
	c.store.ObserveDHCP6CPrefix("pppoe0", "48", 1785402000, 1785403800, 1785405600)

	rows := 0
	for _, m := range collectMetrics(t, c, nil) {
		if !hasFqName(m, "opnsense_log_events_dhcp6c_prefix_updated_timestamp_seconds") {
			continue
		}
		rows++
		if got := getMetricValue(m); got != 1785402000 {
			t.Errorf("updated timestamp = %v, want the LATEST value 1785402000", got)
		}
	}
	if rows != 1 {
		t.Errorf("prefix gauge rows = %d, want 1 - a re-delegation updates the row, it does not fork one", rows)
	}
}

// The DHCPv6 allocation-failure counter: reason is its ONLY dimension. The DUID, the
// transaction id and the subnet must fail on the label count alone.
func TestLogEventsCollector_EmitsDHCP6AllocFailCounter(t *testing.T) {
	c := &logEventsCollector{store: newTestLogEventStore(t), subsystem: LogEventsSubsystem}
	c.Register(namespace, "opnsense.example.com", promslog.NewNopLogger())
	c.store.ObserveDHCP6AllocFail("no_pools")
	c.store.ObserveDHCP6AllocFail("no_pools")
	c.store.ObserveDHCP6AllocFail("exhausted")

	counts := map[string]float64{}
	for _, m := range collectMetrics(t, c, nil) {
		if !hasFqName(m, "opnsense_log_events_dhcp6_alloc_fail_total") {
			continue
		}
		labels := getMetricLabels(m)
		if len(labels) != 2 {
			t.Fatalf("dhcp6_alloc_fail labels = %v, want only reason and opnsense_instance", labels)
		}
		for _, forbidden := range []string{"duid", "tid", "subnet", "client"} {
			if _, present := labels[forbidden]; present {
				t.Errorf("dhcp6_alloc_fail carries a %q label", forbidden)
			}
		}
		counts[labels["reason"]] = getMetricValue(m)
	}

	if counts["no_pools"] != 2 {
		t.Errorf("no_pools = %v, want 2", counts["no_pools"])
	}
	if counts["exhausted"] != 1 {
		t.Errorf("exhausted = %v, want 1", counts["exhausted"])
	}
}

// Every new family reports its own saturation through the existing
// cardinality_capped_total/cardinality_keys pair, so a capped dhcp6c family shows up
// on the alert that already exists rather than needing a metric of its own.
func TestLogEventsCollector_NewDHCP6FamiliesReportSaturation(t *testing.T) {
	c := &logEventsCollector{store: newTestLogEventStore(t), subsystem: LogEventsSubsystem}
	c.Register(namespace, "opnsense.example.com", promslog.NewNopLogger())
	c.store.SetMaxKeys(1)

	for i := 0; i < 3; i++ {
		n := string(rune('a' + i))
		c.store.ObserveDHCP6CMessage("pppoe"+n, "sent", "renew")
		c.store.ObserveDHCP6CEvent("pppoe"+n, "prefix_updated", "")
		c.store.ObserveDHCP6CPrefix("pppoe"+n, "48", 1, 2, 3)
		c.store.ObserveDHCP6AllocFail("reason-" + n)
	}

	capped := map[string]float64{}
	keys := map[string]float64{}
	for _, m := range collectMetrics(t, c, nil) {
		labels := getMetricLabels(m)
		switch {
		case hasFqName(m, "opnsense_log_events_cardinality_capped_total"):
			capped[labels["family"]] = getMetricValue(m)
		case hasFqName(m, "opnsense_log_events_cardinality_keys"):
			keys[labels["family"]] = getMetricValue(m)
		}
	}

	for _, family := range []string{"dhcp6c_message", "dhcp6c_event", "dhcp6c_prefix", "dhcp6_alloc_fail"} {
		if capped[family] != 2 {
			t.Errorf("%s capped = %v, want 2 refused tuples folded into the overflow", family, capped[family])
		}
		if keys[family] != 1 {
			t.Errorf("%s keys = %v, want 1", family, keys[family])
		}
	}
}
