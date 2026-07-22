package flowlog

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/flow"
	"github.com/rknightion/opnsense-exporter/internal/logship"
)

func rec(source flow.Source) flow.Record {
	return flow.Record{
		Source:  source,
		Proto:   6,
		SrcAddr: netip.MustParseAddr("192.0.2.1"),
		DstAddr: netip.MustParseAddr("203.0.113.9"),
		SrcPort: 5000,
		DstPort: 443,
		NF:      flow.Counters{TxBytes: 100, Present: true},
	}
}

// runBridge starts a bridge's Run and returns a captured-record sink plus a stop func.
func runBridge(t *testing.T, b *Bridge) (*[]logship.Record, func()) {
	t.Helper()
	var got []logship.Record
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = b.Run(ctx, func(r logship.Record) { got = append(got, r) })
		close(done)
	}()
	// Wait until Run has captured the emit callback.
	for i := 0; i < 1000 && b.emit.Load() == nil; i++ {
		time.Sleep(time.Millisecond)
	}
	return &got, func() { cancel(); <-done }
}

// Mode off ships nothing even with an active pipeline.
func TestBridge_OffEmitsNothing(t *testing.T) {
	b := New() // defaults to off
	got, stop := runBridge(t, b)
	defer stop()
	b.Emit(rec(flow.SourceMerged))
	if len(*got) != 0 {
		t.Fatalf("mode off emitted %d records, want 0", len(*got))
	}
}

// per_flow ships one record, stamped with the flow subsystem and the per-record source
// override, carrying the flow attributes.
func TestBridge_PerFlowShipsWithSubsystemAndSource(t *testing.T) {
	b := New()
	b.Configure(LogModePerFlow, 0)
	got, stop := runBridge(t, b)
	defer stop()

	b.Emit(rec(flow.SourceMerged))
	if len(*got) != 1 {
		t.Fatalf("want 1 emitted record, got %d", len(*got))
	}
	r := (*got)[0]
	if r.Source != "merged" {
		t.Errorf("source override = %q, want merged", r.Source)
	}
	if r.Attributes[logship.AttrSubsystem] != subsystem {
		t.Errorf("subsystem = %q, want %q", r.Attributes[logship.AttrSubsystem], subsystem)
	}
	if r.Attributes["dst.port"] != "443" {
		t.Errorf("flow attributes missing: %v", r.Attributes)
	}
	if st := b.Stats(); st.Emitted != 1 {
		t.Errorf("Emitted = %d, want 1", st.Emitted)
	}
}

// A blocked flow raises severity above Info.
func TestBridge_BlockedRaisesSeverity(t *testing.T) {
	b := New()
	b.Configure(LogModePerFlow, 0)
	got, stop := runBridge(t, b)
	defer stop()

	r := rec(flow.SourceNetflow)
	r.Verdict = flow.VerdictBlock
	b.Emit(r)
	if (*got)[0].Severity != logship.SeverityWarn {
		t.Errorf("severity = %v, want Warn for a blocked flow", (*got)[0].Severity)
	}
}

// The per-window budget truncates over the cap and counts every truncation; metrics
// (elsewhere) are untouched. Removing the budget check ships all five.
func TestBridge_BudgetTruncatesAndCounts(t *testing.T) {
	b := New()
	b.Configure(LogModePerFlow, 3)
	fixed := time.Unix(1_700_000_000, 0)
	b.clock = func() time.Time { return fixed } // one budget window
	got, stop := runBridge(t, b)
	defer stop()

	for range 5 {
		b.Emit(rec(flow.SourceNetflow))
	}
	if len(*got) != 3 {
		t.Fatalf("budget of 3 shipped %d records, want 3", len(*got))
	}
	if st := b.Stats(); st.Emitted != 3 || st.Truncated != 2 {
		t.Fatalf("stats emitted/truncated = %d/%d, want 3/2", st.Emitted, st.Truncated)
	}
}

// A new budget window resets the allowance.
func TestBridge_BudgetResetsNextWindow(t *testing.T) {
	b := New()
	b.Configure(LogModePerFlow, 1)
	now := time.Unix(1_700_000_000, 0)
	b.clock = func() time.Time { return now }
	got, stop := runBridge(t, b)
	defer stop()

	b.Emit(rec(flow.SourceNetflow)) // window 1: allowed
	b.Emit(rec(flow.SourceNetflow)) // window 1: truncated
	now = now.Add(budgetWindow)     // advance to window 2
	b.Emit(rec(flow.SourceNetflow)) // window 2: allowed again
	if len(*got) != 2 {
		t.Fatalf("want 2 shipped across two windows, got %d", len(*got))
	}
}

// With no active pipeline (Run not started), Emit drops and counts it rather than
// panicking on a nil callback.
func TestBridge_DropsWhenNoPipeline(t *testing.T) {
	b := New()
	b.Configure(LogModePerFlow, 0)
	b.Emit(rec(flow.SourceNetflow))
	if st := b.Stats(); st.Dropped != 1 || st.Emitted != 0 {
		t.Fatalf("dropped/emitted = %d/%d, want 1/0", st.Dropped, st.Emitted)
	}
}
