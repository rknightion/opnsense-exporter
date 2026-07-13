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

func bodies(es []Entry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.Record.Body
	}
	return out
}
