package logship

import "sync"

// Record-size accounting (#318).
//
// The queue is bounded by BOTH a record count (--logs.buffer-size) and an
// aggregate byte budget (--logs.buffer-max-bytes), because the count alone does
// not bound memory: a receiver retains each record's full raw body, so a handful
// of multi-megabyte records can outweigh thousands of syslog lines. recordBytes is
// the ONE definition of "how big is this record" used by every bound — the
// per-record ingest cap, the queue's aggregate budget, and the queue_bytes gauge —
// so operators tuning one flag against the other are reading the same number.
//
// It is a deliberate ESTIMATE of retained heap, not an exact sizeof:
//   - the payload bytes are exact (body, source name, attribute keys and values);
//   - recordEntryOverheadBytes covers the fixed struct cost that travels with every
//     queued record (Record + Entry headers, the time.Time, the string headers, the
//     queue slot itself);
//   - recordAttrOverheadBytes covers per-attribute map-bucket and string-header cost.
//
// Both constants are round, conservative numbers: the point is that a byte budget
// tracks reality within a small constant factor, not that it is exact. Under-counting
// would let the budget be exceeded, so they err high.
const (
	recordEntryOverheadBytes = 128
	recordAttrOverheadBytes  = 48
)

// recordBytes estimates the heap a queued Record retains. See the block comment
// above for the definition; every byte bound in this package goes through here.
func recordBytes(r Record) int {
	n := recordEntryOverheadBytes + len(r.Body) + len(r.Source)
	for k, v := range r.Attributes {
		n += recordAttrOverheadBytes + len(k) + len(v)
	}
	return n
}

// queuedEntry is an Entry plus its recordBytes size, memoised at push time. The
// size is stored rather than recomputed on eviction/drain so the running total can
// never drift from what was actually added (recomputing would also re-walk the
// attribute map on every drain, on the hot path).
type queuedEntry struct {
	entry Entry
	size  int
}

// boundedQueue is the backpressure valve between pollers and the emitter. It is a
// drop-oldest buffer bounded two ways, both of which apply at once: a record COUNT
// cap and an aggregate BYTE budget (#318). When either is exceeded, push drops the
// OLDEST entry and invokes onDrop (so overflow is counted, not silent — unlike the
// OTLP SDK's own batch queue). drainUpTo blocks until at least one entry is
// available or the queue is closed, then greedily takes up to max already-queued
// entries without waiting (low-latency, no flush timer).
type boundedQueue struct {
	mu   sync.Mutex
	cond *sync.Cond
	buf  []queuedEntry
	cap  int
	// maxBytes is the aggregate byte budget; 0 disables it. bytes is the running
	// sum of the queued entries' memoised sizes.
	maxBytes int
	bytes    int
	closed   bool
	onDrop   func(e Entry)
}

// newBoundedQueue builds a count-bounded queue with no byte budget. Kept for the
// callers that only exercise the count cap; production wiring uses
// newBoundedQueueBytes.
func newBoundedQueue(capacity int, onDrop func(e Entry)) *boundedQueue {
	return newBoundedQueueBytes(capacity, 0, onDrop)
}

// newBoundedQueueBytes builds a queue bounded by both a record count and an
// aggregate byte budget. maxBytes <= 0 disables the byte budget (the count cap
// always applies).
func newBoundedQueueBytes(capacity, maxBytes int, onDrop func(e Entry)) *boundedQueue {
	if capacity < 1 {
		capacity = 1
	}
	if maxBytes < 0 {
		maxBytes = 0
	}
	q := &boundedQueue{
		buf:      make([]queuedEntry, 0, capacity),
		cap:      capacity,
		maxBytes: maxBytes,
		onDrop:   onDrop,
	}
	q.cond = sync.NewCond(&q.mu)
	return q
}

// push appends e, dropping the oldest entries (and counting each via onDrop) until
// the queue is within BOTH the count cap and the byte budget. Pushing to a closed
// queue is a no-op.
//
// The byte check runs AFTER the append, so an entry that on its own exceeds the
// whole budget is admitted and then immediately evicted — dropped and counted like
// any other overflow rather than silently ignored or left to wedge the queue. In
// production --logs.max-record-bytes rejects such a record at ingest before it ever
// gets here (see pipeline.enqueue), so this is the backstop for maxRecordBytes=0.
func (q *boundedQueue) push(e Entry) {
	size := recordBytes(e.Record)
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return
	}
	for len(q.buf) >= q.cap {
		q.evictOldestLocked()
	}
	q.buf = append(q.buf, queuedEntry{entry: e, size: size})
	q.bytes += size
	for q.maxBytes > 0 && q.bytes > q.maxBytes && len(q.buf) > 0 {
		q.evictOldestLocked()
	}
	q.cond.Signal()
	q.mu.Unlock()
}

// evictOldestLocked removes the head entry, returns its bytes to the budget and
// reports it via onDrop. The vacated slot is zeroed so the evicted Record's body
// and attribute map stop being reachable through the backing array (#304). Caller
// must hold q.mu.
func (q *boundedQueue) evictOldestLocked() {
	if len(q.buf) == 0 {
		return
	}
	dropped := q.buf[0]
	q.buf[0] = queuedEntry{}
	q.buf = q.buf[1:]
	q.bytes -= dropped.size
	if q.bytes < 0 {
		q.bytes = 0
	}
	if q.onDrop != nil {
		q.onDrop(dropped.entry)
	}
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
	freed := 0
	for i := 0; i < n; i++ {
		batch[i] = q.buf[i].entry
		freed += q.buf[i].size
	}
	q.bytes -= freed
	if q.bytes < 0 {
		q.bytes = 0
	}
	// Zero the drained slots before releasing them: without this the delivered
	// Record bodies and attribute maps stay GC-reachable through the backing array
	// until a later growslice replaces it (#304). Bounded and self-healing, but it
	// pins up to one queue capacity of already-delivered records for no reason.
	fullyDrained := n == len(q.buf)
	clear(q.buf[:n])
	if fullyDrained {
		// Reset to the FRONT of the current backing array rather than walking
		// forward with buf[n:], which shrinks the usable capacity every drain until
		// append has to reallocate. buf[:0] genuinely reuses the array; buf[n:] on a
		// fully-drained queue would be an empty slice pinned at the far end of it.
		q.buf = q.buf[:0]
	} else {
		q.buf = q.buf[n:]
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

// queuedBytes reports the estimated heap currently retained by queued records (for
// the queue-bytes self-metric). See the recordBytes block comment for what the
// estimate covers.
func (q *boundedQueue) queuedBytes() int {
	q.mu.Lock()
	n := q.bytes
	q.mu.Unlock()
	return n
}
