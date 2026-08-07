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
//
// MEASURED AGAINST A REAL PAYLOAD, 2026-08-07 (#663). Two record shapes exported through
// the real OTLP sink over a real socket, weighed as uncompressed protobuf —
// TestRecordBytesTracksTheRealWirePayload is the harness and prints the live numbers:
//
//	                          body   attrs   recordBytes   measured wire   ratio
//	zenarmor conn (captured)  1747B    32       4034B          2539B       1.6x
//	syslog unbound query        98B    17       1356B           524B       2.6x
//
// So the estimate NEVER under-counts the wire, which is the direction that matters —
// --logs.max-export-bytes sizes a batch by summing this, and an under-count would put
// more bytes on the wire than the operator's budget allows. It over-counts by up to
// ~2.6x on attribute-heavy small records, because recordAttrOverheadBytes charges Go map
// and string-header cost that protobuf does not pay (17 attributes are 816 B of that
// syslog estimate). That is right for this function's PRIMARY job — retained heap for
// the queue's memory budget — and merely conservative for the wire, so it is left alone
// rather than tuned to split the difference and become wrong for both.
//
// The same measurement settles #663's other question. The live rejection reported 2705
// bytes/record, which looked like a ~20x multiplier over 100-150 byte syslog DNS lines.
// It is not a multiplier at all: a Zenarmor record's Body is the raw NDJSON document
// verbatim, and one real captured conn document bills at ~2549 B on its own. The batch's
// bytes were Zenarmor documents, not syslog lines. There is no runaway per-record
// metadata set and no per-partition resource duplication — resource attributes travel
// once per ResourceLogs on the wire, not once per record.
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
//
// TWO CAPS, and the byte one exists for a different reason than the queue's own byte
// budget (#506). maxBytes bounds what goes to the WIRE in one request, not what is held
// in memory. The OTLP exporter refuses an oversized request before making any HTTP call
// (vendor/…/otlploghttp/client.go:177, 64 MiB against the UNCOMPRESSED protobuf — gzip is
// applied later, in newRequest, so it does not raise this ceiling). Because nothing
// reaches the wire, no delivery outcome is observed, and classifyPartition can only treat
// it as retryable — so the batch would burn the entire --logs.ship-max-attempts budget
// re-marshalling identical bytes that can never be accepted. Bounding the drain is what
// stops such a batch being built at all. maxBytes <= 0 disables the cap.
//
// AT LEAST ONE ENTRY IS ALWAYS RETURNED, however big it is. A strict cap would leave an
// oversized entry at the head of the queue forever: the emitter would block on it and
// every record behind it would oldest-drop. A permanently wedged pipeline is far worse
// than one export that fails and is counted, and --logs.max-record-bytes already rejects
// oversized records at ingest, which is the right place for that bound.
func (q *boundedQueue) drainUpTo(max, maxBytes int) (batch []Entry, ok bool) {
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
	if maxBytes > 0 {
		acc := 0
		for i := range n {
			next := acc + q.buf[i].size
			// i == 0 always passes: see the always-return-one rule above.
			if i > 0 && next > maxBytes {
				n = i
				break
			}
			acc = next
		}
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
