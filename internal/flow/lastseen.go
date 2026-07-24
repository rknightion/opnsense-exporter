package flow

import (
	"sync"
	"time"
)

// lastSeenIfaceCap bounds how many distinct interfaces are tracked. The label set
// comes from the ifIndex map and is realistically under 20, but the NetFlow socket
// is unauthenticated, so the map is bounded rather than trusted. Well above any
// real box so the cap is a backstop, never a working limit.
const lastSeenIfaceCap = 256

// LastSeen records when a NetFlow record was last attributed to each interface.
//
// It exists to make "configured to capture, exporting nothing" expressible (#366).
// An interface that has gone quiet produces no series in the volume metrics at all,
// so `rate()` over them yields nothing rather than zero — absence is unqueryable.
// A timestamp turns that absence into a number.
//
// READ THE LIMIT BEFORE TRUSTING IT: the interface on a NetFlow record is not
// necessarily the interface that CAPTURED it. ng_netflow stamps the capturing
// hook's index on one side of the flow and fills the other side from a FIB lookup,
// so records captured on the LAN hook name the egress WAN too. On the reference box
// this was measured directly on 2026-07-24 — netflow_pppoe0 had processed zero
// packets (`ngctl msg netflow_pppoe0: info` returned only its timeouts) while the
// exporter reported 11 GB against that interface, all of it FIB-attributed from
// other nodes' records. So a fresh timestamp here proves the interface is being
// NAMED, not that its own capture hook is alive.
type LastSeen struct {
	mu sync.Mutex
	at map[string]time.Time
}

// NewLastSeen returns an empty tracker.
func NewLastSeen() *LastSeen {
	return &LastSeen{at: make(map[string]time.Time)}
}

// Observe records now against this record's interface, for NetFlow records only.
//
// The source filter is load-bearing. Zenarmor and NetFlow are independent lanes
// over the same traffic, so letting a Zenarmor record set or refresh the timestamp
// would keep an interface looking healthy while its ng_netflow hook exports
// nothing — masking the exact fault this exists to surface.
//
// now is the ARRIVAL time, not the flow's own timestamps: ng_netflow can export a
// flow whose end time is well in the past, and the question here is when we last
// heard about the interface, not when the traffic happened.
//
// Safe for concurrent callers; takes a short mutex and does no I/O.
func (l *LastSeen) Observe(r Record, now time.Time) {
	if r.Source != SourceNetflow {
		return
	}
	iface := interfaceLabel(r)
	if iface == "" {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// An UPDATE is always allowed. Only admitting a NEW interface is capped:
	// refusing to move a known interface's timestamp would freeze it, which invents
	// precisely the "stopped exporting" fault this is meant to detect.
	if _, known := l.at[iface]; !known && len(l.at) >= lastSeenIfaceCap {
		return
	}
	l.at[iface] = now
}

// Snapshot returns a copy of the last-seen time per interface. Interfaces that
// have never produced a NetFlow record are absent rather than zero — "never seen
// since start" and "seen, then stopped" are different states and a zero time would
// collapse them into one.
func (l *LastSeen) Snapshot() map[string]time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()

	out := make(map[string]time.Time, len(l.at))
	for iface, t := range l.at {
		out[iface] = t
	}
	return out
}
