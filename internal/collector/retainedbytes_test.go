package collector

import (
	"cmp"
	"strings"
	"testing"
	"time"
	"unsafe"
)

func TestLogEventValuesDetachFromLargeParserFrame(t *testing.T) {
	frame := strings.Repeat("x", 64<<10)
	value := frame[len(frame)-8:]
	cmd := detachLogEventValues(logEventCommand{values: [7]string{value}})

	frameStart := uintptr(unsafe.Pointer(unsafe.StringData(frame)))
	detachedStart := uintptr(unsafe.Pointer(unsafe.StringData(cmd.values[0])))
	if detachedStart >= frameStart && detachedStart < frameStart+uintptr(len(frame)) {
		t.Fatal("retained metric value still shares the full parser frame backing allocation")
	}
	if cmd.values[0] != value {
		t.Fatalf("detached value = %q, want %q", cmd.values[0], value)
	}
}

func TestCappedCounterBoundsNovelKeyBytes(t *testing.T) {
	c := newCappedCounter[string](0)
	c.inc(strings.Repeat("x", maxRetainedKeyBytes+1))
	if len(c.m) != 0 || c.overflow != 1 || c.bytes != 0 {
		t.Fatalf("oversized key retained: len=%d overflow=%v bytes=%d", len(c.m), c.overflow, c.bytes)
	}
	c.inc("normal")
	if c.bytes != len("normal") {
		t.Fatalf("retained bytes = %d", c.bytes)
	}
}

func TestCappedGaugeReleasesKeyBudgetOnUnset(t *testing.T) {
	g := newCappedGauge[string, string](0)
	g.set("normal", "value")
	if g.bytes == 0 {
		t.Fatal("gauge did not account retained strings")
	}
	g.unset("normal")
	if g.bytes != 0 {
		t.Fatalf("gauge retained bytes after unset = %d", g.bytes)
	}
}

func TestBoundedInventoryBoundsAndReleasesStringBytes(t *testing.T) {
	inv := newBoundedInventory[string, string](0, time.Second, cmp.Compare[string])
	inv.seen(strings.Repeat("x", maxRetainedKeyBytes+1), "value", time.Time{})
	if inv.len() != 0 || inv.refused() != 1 {
		t.Fatalf("oversized inventory entry retained: len=%d refused=%v", inv.len(), inv.refused())
	}
	inv.seen("normal", "value", time.Time{})
	if inv.bytes == 0 {
		t.Fatal("inventory did not account retained strings")
	}
	_ = inv.live(time.Unix(2, 0))
	if inv.bytes != 0 {
		t.Fatalf("inventory retained bytes after expiry = %d", inv.bytes)
	}
}
