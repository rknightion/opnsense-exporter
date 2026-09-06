package main

import (
	"context"
	"net/netip"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rknightion/opnsense2otel/v5/internal/flow"
	"github.com/rknightion/opnsense2otel/v5/internal/flow/netflow"
	"github.com/rknightion/opnsense2otel/v5/internal/logship"
	"github.com/rknightion/opnsense2otel/v5/internal/logship/enrich"
	"github.com/rknightion/opnsense2otel/v5/internal/logship/flowlog"
)

// TestShutdownFlowQuiescesBeforeFinalFlush releases a held NetFlow record at the
// shutdown seam through the real flowlog bridge. The bridge's push-source Run has
// already returned when AfterSourcesStopped runs, but the final correlator flush
// must still enter the live pipeline callback before it is unbound.
func TestShutdownFlowQuiescesBeforeFinalFlush(t *testing.T) {
	now := time.Unix(1784652010, 0)
	bridge := flowlog.New()
	bridge.Configure(flowlog.LogModePerFlow, 0)
	bridgeCtx, cancelBridge := context.WithCancel(context.Background())
	bridgeDone := make(chan struct{})
	var delivered atomic.Uint64
	go func() {
		_ = bridge.Run(bridgeCtx, func(_ logship.Record) { delivered.Add(1) })
		close(bridgeDone)
	}()
	// Confirm Run has captured the pipeline callback before simulating the
	// pipeline cancellation that precedes AfterSourcesStopped.
	for deadline := time.Now().Add(time.Second); bridge.Stats().Emitted == 0 && time.Now().Before(deadline); {
		bridge.Emit(flow.Record{Source: flow.SourceNetflow})
		time.Sleep(time.Millisecond)
	}
	beforeShutdown := bridge.Stats()
	if beforeShutdown.Emitted == 0 {
		t.Fatalf("bridge did not capture the pipeline callback; stats = %+v", beforeShutdown)
	}
	cancelBridge()
	<-bridgeDone

	pipelineDrained := false
	corr := flow.NewCorrelator(flow.CorrelatorConfig{
		Enabled:    true,
		Window:     time.Hour,
		MaxEntries: 10,
	}, func(r flow.Record) {
		if pipelineDrained {
			t.Error("correlator emitted after the log pipeline drained")
		}
		bridge.Emit(r)
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
		bridge.Unbind()
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
	if got := delivered.Load(); got != beforeShutdown.Emitted+1 {
		t.Errorf("delivered records = %d, want %d; final held flow was not enqueued", got, beforeShutdown.Emitted+1)
	}
	if got := bridge.Stats(); got.Emitted != beforeShutdown.Emitted+1 || got.Dropped != beforeShutdown.Dropped {
		t.Errorf("bridge stats after final flush = %+v, want emitted=%d dropped=%d", got, beforeShutdown.Emitted+1, beforeShutdown.Dropped)
	}
	bridge.Emit(flow.Record{Source: flow.SourceNetflow})
	if got := bridge.Stats(); got.Emitted != beforeShutdown.Emitted+1 || got.Dropped != beforeShutdown.Dropped+1 {
		t.Errorf("bridge stats after late emit = %+v, want emitted=%d dropped=%d", got, beforeShutdown.Emitted+1, beforeShutdown.Dropped+1)
	}
	if got := proc.Stats().RecordsHeld; got != 0 {
		t.Errorf("RecordsHeld after shutdown = %d, want 0", got)
	}
	if got := corr.Stats().Entries; got != 0 {
		t.Errorf("correlator entries after shutdown = %d, want 0", got)
	}
}
