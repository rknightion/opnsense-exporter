package logship

import "sync"

// boundedQueue is the counted backpressure valve between pollers and the
// emitter. It is a fixed-capacity ring: when full, push drops the OLDEST entry
// and invokes onDrop (so overflow is counted, not silent — unlike the OTLP SDK's
// own batch queue). drainUpTo blocks until at least one entry is available or the
// queue is closed, then greedily takes up to max already-queued entries without
// waiting (low-latency, no flush timer).
type boundedQueue struct {
	mu     sync.Mutex
	cond   *sync.Cond
	buf    []Entry
	cap    int
	closed bool
	onDrop func(e Entry)
}

func newBoundedQueue(capacity int, onDrop func(e Entry)) *boundedQueue {
	if capacity < 1 {
		capacity = 1
	}
	q := &boundedQueue{
		buf:    make([]Entry, 0, capacity),
		cap:    capacity,
		onDrop: onDrop,
	}
	q.cond = sync.NewCond(&q.mu)
	return q
}

// push appends e, dropping the oldest entry (and counting it via onDrop) when
// the queue is at capacity. Pushing to a closed queue is a no-op.
func (q *boundedQueue) push(e Entry) {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return
	}
	if len(q.buf) >= q.cap {
		dropped := q.buf[0]
		q.buf = q.buf[1:]
		if q.onDrop != nil {
			q.onDrop(dropped)
		}
	}
	q.buf = append(q.buf, e)
	q.cond.Signal()
	q.mu.Unlock()
}

// drainUpTo blocks until at least one entry is queued or the queue is closed. It
// returns up to max currently-queued entries and ok=false only when the queue is
// closed AND drained (so the emitter loop terminates cleanly after a final
// flush).
func (q *boundedQueue) drainUpTo(max int) (batch []Entry, ok bool) {
	q.mu.Lock()
	for len(q.buf) == 0 && !q.closed {
		q.cond.Wait()
	}
	if len(q.buf) == 0 && q.closed {
		q.mu.Unlock()
		return nil, false
	}
	if max < 1 {
		max = 1
	}
	n := len(q.buf)
	if n > max {
		n = max
	}
	batch = make([]Entry, n)
	copy(batch, q.buf[:n])
	q.buf = q.buf[n:]
	// Reclaim the backing array once fully drained so a burst doesn't pin cap.
	if len(q.buf) == 0 {
		q.buf = q.buf[:0]
	}
	q.mu.Unlock()
	return batch, true
}

// close marks the queue closed and wakes any waiter. Buffered entries remain
// drainable so the emitter can flush them before terminating.
func (q *boundedQueue) close() {
	q.mu.Lock()
	q.closed = true
	q.cond.Broadcast()
	q.mu.Unlock()
}

// length reports the current number of queued entries (for the queue-length
// self-metric).
func (q *boundedQueue) length() int {
	q.mu.Lock()
	n := len(q.buf)
	q.mu.Unlock()
	return n
}
