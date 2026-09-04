package main

import (
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/rknightion/opnsense2otel/v4/internal/flow"
	"github.com/rknightion/opnsense2otel/v4/internal/flow/netflow"
	"github.com/rknightion/opnsense2otel/v4/internal/logship/enrich"
)

// TestShutdownFlowQuiescesBeforeFinalFlush releases a held NetFlow record at the
// shutdown seam. The release must enter the correlator before its one final flush,
// while the log pipeline is still live.
func TestShutdownFlowQuiescesBeforeFinalFlush(t *testing.T) {
	now := time.Unix(1784652010, 0)
	var delivered int
	pipelineDrained := false
	corr := flow.NewCorrelator(flow.CorrelatorConfig{
		Enabled:    true,
		Window:     time.Hour,
		MaxEntries: 10,
	}, func(flow.Record) {
		if pipelineDrained {
			t.Error("correlator emitted after the log pipeline drained")
		}
		delivered++
	})
	proc := flow.NewProcessor(corr, flow.NewRepairer(100, 1000), nil)
	proc.SetIfMap(flow.BuildIfMap(flow.IfMapInput{
		Order: []string{"lan", "wan"},
		Ifaces: []enrich.IfaceInfo{
			{Device: "lan", Name: "LAN"},
			{Device: "wan", Name: "WAN", IsWAN: true},
			{Device: "lan_vlan50", Name: "IOT", VlanTag: "50", VlanParent: "lan"},
		},
		Built: now,
	}))

	// The trunk-side record is held by the processor, so it is still accepted work
	// when shutdown begins and must be released by the NetFlow stop hook.
	proc.ObserveDatagram(&netflow.Datagram{Records: []netflow.Record{{
		Proto: 6, Bytes: 1000, Packets: 10,
		SrcAddr: netip.MustParseAddr("10.0.0.5"), DstAddr: netip.MustParseAddr("203.0.113.5"),
		SrcPort: 40000, DstPort: 443,
		InIfIndex: 1, OutIfIndex: 2,
		First: now.Add(-5 * time.Second), Last: now,
	}}}, now)
	if got := proc.Stats().RecordsHeld; got != 1 {
		t.Fatalf("RecordsHeld before shutdown = %d, want 1", got)
	}

	events := make([]string, 0, 5)
	var correlatorFlushes int
	stopNetflow := func() {
		events = append(events, "netflow-listener-closed")
		// The production listener's Serve goroutine waits for all workers after Close.
		events = append(events, "netflow-workers-done")
		proc.Flush(now)
		events = append(events, "processor-flush")
	}
	stopFlowLog := func() {
		events = append(events, "correlator-expiry-cancel")
		correlatorFlushes++
		corr.Flush()
		events = append(events, "correlator-flush")
	}
	drain := func() error {
		events = append(events, "log-pipeline-drain")
		pipelineDrained = true
		return nil
	}

	// The log pipeline reaches this seam only after its push sources, including
	// Zenarmor, have returned. Its queue remains live until the callback ends.
	events = append(events, "log-push-sources-done")
	stopFlowProducers(stopNetflow, stopFlowLog)
	if err := drain(); err != nil {
		t.Fatalf("drain: %v", err)
	}

	wantEvents := []string{
		"log-push-sources-done",
		"netflow-listener-closed",
		"netflow-workers-done",
		"processor-flush",
		"correlator-expiry-cancel",
		"correlator-flush",
		"log-pipeline-drain",
	}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Errorf("shutdown order = %v, want %v", events, wantEvents)
	}
	if correlatorFlushes != 1 {
		t.Errorf("correlator flushes = %d, want exactly one", correlatorFlushes)
	}
	if delivered != 1 {
		t.Errorf("delivered records = %d, want 1; a held record was stranded", delivered)
	}
	if got := proc.Stats().RecordsHeld; got != 0 {
		t.Errorf("RecordsHeld after shutdown = %d, want 0", got)
	}
	if got := corr.Stats().Entries; got != 0 {
		t.Errorf("correlator entries after shutdown = %d, want 0", got)
	}
}
