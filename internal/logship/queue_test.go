package logship

import (
	"sync"
	"testing"
)

func mkEntry(body string) Entry {
	return Entry{Source: "test", Record: Record{Body: body}}
}

func TestBoundedQueue_DropOldestOnOverflow(t *testing.T) {
	var dropped []string
	q := newBoundedQueue(2, func(e Entry) { dropped = append(dropped, e.Record.Body) })
	q.push(mkEntry("a"))
	q.push(mkEntry("b"))
	q.push(mkEntry("c")) // evicts "a"

	if len(dropped) != 1 || dropped[0] != "a" {
		t.Fatalf("expected oldest 'a' dropped, got %v", dropped)
	}
	batch, ok := q.drainUpTo(10)
	if !ok {
		t.Fatal("drain returned not-ok on a non-empty queue")
	}
	if len(batch) != 2 || batch[0].Record.Body != "b" || batch[1].Record.Body != "c" {
		t.Fatalf("expected [b c], got %v", bodies(batch))
	}
}

func TestBoundedQueue_DrainUpToRespectsMax(t *testing.T) {
	q := newBoundedQueue(10, nil)
	for _, s := range []string{"a", "b", "c", "d"} {
		q.push(mkEntry(s))
	}
	batch, ok := q.drainUpTo(2)
	if !ok || len(batch) != 2 {
		t.Fatalf("expected 2 entries, got ok=%v n=%d", ok, len(batch))
	}
	if q.length() != 2 {
		t.Fatalf("expected 2 remaining, got %d", q.length())
	}
}

func TestBoundedQueue_CloseDrainsThenSignalsDone(t *testing.T) {
	q := newBoundedQueue(10, nil)
	q.push(mkEntry("a"))
	q.close()
	// Buffered entry still drains.
	batch, ok := q.drainUpTo(10)
	if !ok || len(batch) != 1 {
		t.Fatalf("expected final drain of 1, got ok=%v n=%d", ok, len(batch))
	}
	// Now empty + closed => not-ok, unblocks the emitter loop.
	if _, ok := q.drainUpTo(10); ok {
		t.Fatal("expected not-ok after closed+drained")
	}
}

func TestBoundedQueue_DrainBlocksUntilPush(t *testing.T) {
	q := newBoundedQueue(10, nil)
	done := make(chan Entry, 1)
	go func() {
		b, _ := q.drainUpTo(10)
		done <- b[0]
	}()
	q.push(mkEntry("x"))
	got := <-done
	if got.Record.Body != "x" {
		t.Fatalf("expected x, got %q", got.Record.Body)
	}
}

func TestBoundedQueue_ConcurrentPushIsSafe(t *testing.T) {
	q := newBoundedQueue(100, func(Entry) {})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				q.push(mkEntry("x"))
			}
		}()
	}
	wg.Wait()
	// No panic / race is the assertion (run with -race). Queue capped at 100.
	if q.length() > 100 {
		t.Fatalf("queue exceeded capacity: %d", q.length())
	}
}

// #304: drainUpTo handed the batch out but left the drained slots pointing at the
// same Records, so delivered bodies and attribute maps stayed GC-reachable through
// the backing array. Hygiene, not an unbounded leak — but the slots must be zeroed.
func TestBoundedQueue_DrainClearsDrainedSlots(t *testing.T) {
	q := newBoundedQueue(4, nil)
	q.push(mkEntry("a"))
	q.push(mkEntry("b"))

	if _, ok := q.drainUpTo(10); !ok {
		t.Fatal("drain returned not-ok on a non-empty queue")
	}
	// Fully drained, so buf is reset to the FRONT of its backing array and the
	// stale slots are addressable again via the retained capacity.
	stale := q.buf[:cap(q.buf)]
	for i, qe := range stale[:2] {
		if qe.entry.Record.Body != "" || qe.size != 0 {
			t.Fatalf("drained slot %d still retains the record: %+v", i, qe)
		}
	}
}

// Eviction returns the evicted record's bytes to the budget. Without this the
// running total only ever grows and the queue would evict on every push forever.
//
// (evictOldestLocked also zeroes the vacated slot, for the same #304 reason as the
// drain path. That is deliberately NOT asserted here: drop-oldest reslices forward
// with buf[1:], so the next append reallocates and the zeroed slot belongs to an
// array nothing references any more — there is no way to observe it without
// asserting on unreachable memory. The drain path, where the clear actually
// matters, is covered by TestBoundedQueue_DrainClearsDrainedSlots above.)
func TestBoundedQueue_EvictionReleasesBytes(t *testing.T) {
	q := newBoundedQueue(1, func(Entry) {})
	q.push(mkEntry("a"))
	q.push(mkEntry("b")) // evicts "a"

	if q.length() != 1 {
		t.Fatalf("queue length = %d, want 1", q.length())
	}
	if got, want := q.queuedBytes(), recordBytes(mkEntry("b").Record); got != want {
		t.Fatalf("byte accounting drifted after eviction: bytes=%d want=%d", got, want)
	}
}

// #318: the queue was bounded by COUNT only. A receiver retains each record's full
// raw body, so a handful of large records can consume far more memory than the
// record count implies. The byte budget must evict the OLDEST entry and count it
// through onDrop, exactly as the count cap does.
func TestBoundedQueue_ByteBudgetDropsOldest(t *testing.T) {
	big := string(make([]byte, 1024))
	one := recordBytes(Record{Body: big})

	var dropped []string
	// Count cap is generous (100) so only the byte budget can bite; budget fits 2.
	q := newBoundedQueueBytes(100, 2*one+one/2, func(e Entry) {
		dropped = append(dropped, e.Record.Attributes["id"])
	})
	for _, id := range []string{"1", "2", "3"} {
		q.push(Entry{Source: "test", Record: Record{Body: big, Attributes: map[string]string{"id": id}}})
	}

	if len(dropped) != 1 || dropped[0] != "1" {
		t.Fatalf("expected the oldest record (id=1) evicted by the byte budget, got %v", dropped)
	}
	if q.length() != 2 {
		t.Fatalf("queue length = %d, want 2", q.length())
	}
	if q.queuedBytes() > 2*one+one/2 {
		t.Fatalf("queued bytes %d exceed the budget", q.queuedBytes())
	}
}

// Both bounds apply: a byte budget must not disable the count cap.
func TestBoundedQueue_CountCapStillAppliesWithByteBudget(t *testing.T) {
	var dropped int
	q := newBoundedQueueBytes(2, 1<<30, func(Entry) { dropped++ })
	q.push(mkEntry("a"))
	q.push(mkEntry("b"))
	q.push(mkEntry("c"))
	if dropped != 1 || q.length() != 2 {
		t.Fatalf("count cap not enforced: dropped=%d length=%d", dropped, q.length())
	}
}

// Draining must return the freed bytes to the budget, or the queue slowly starves
// itself into evicting on every push.
func TestBoundedQueue_DrainReleasesBytes(t *testing.T) {
	q := newBoundedQueueBytes(10, 1<<20, nil)
	q.push(mkEntry("aaaa"))
	q.push(mkEntry("bbbb"))
	if q.queuedBytes() == 0 {
		t.Fatal("queuedBytes should be non-zero after two pushes")
	}
	if _, ok := q.drainUpTo(1); !ok {
		t.Fatal("drain returned not-ok")
	}
	if got, want := q.queuedBytes(), recordBytes(mkEntry("bbbb").Record); got != want {
		t.Fatalf("queuedBytes after partial drain = %d, want %d", got, want)
	}
	if _, ok := q.drainUpTo(10); !ok {
		t.Fatal("drain returned not-ok")
	}
	if got := q.queuedBytes(); got != 0 {
		t.Fatalf("queuedBytes after full drain = %d, want 0", got)
	}
}

// With no per-record cap configured, a single record larger than the whole budget
// must not wedge the queue: it is evicted and counted like any other overflow.
func TestBoundedQueue_SingleOversizedRecordIsEvictedNotRetained(t *testing.T) {
	var dropped int
	q := newBoundedQueueBytes(10, 64, func(Entry) { dropped++ })
	q.push(Entry{Source: "test", Record: Record{Body: string(make([]byte, 4096))}})
	if q.length() != 0 || q.queuedBytes() != 0 {
		t.Fatalf("oversized record retained: length=%d bytes=%d", q.length(), q.queuedBytes())
	}
	if dropped != 1 {
		t.Fatalf("oversized record eviction not counted: dropped=%d", dropped)
	}
}

func TestRecordBytes_CountsBodyAndAttributes(t *testing.T) {
	bare := recordBytes(Record{Body: "abc"})
	withAttr := recordBytes(Record{Body: "abc", Attributes: map[string]string{"k": "v"}})
	if withAttr <= bare {
		t.Fatalf("attributes must contribute to the size estimate: %d <= %d", withAttr, bare)
	}
	if bare <= 3 {
		t.Fatalf("size estimate must include per-record overhead, got %d", bare)
	}
}

func bodies(es []Entry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.Record.Body
	}
	return out
}
