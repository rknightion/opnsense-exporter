// Package fetchshare is the shared-result seam between the exporter's two
// independent consumers of the OPNsense API: the metrics collectors, which poll on
// their data-volatility tier, and the syslog enrichment refresher, which keeps its
// own label tables on its own TTLs (#248).
//
// The two were fetching twelve of the same endpoints on overlapping cadences
// (#571). Every request costs the firewall two configd RPCs and two audit lines,
// independent of the endpoint and of what it returns (#535), so the duplication was
// ~10.9k requests and ~21.7k audit lines a day for data that had already been
// decoded moments earlier in the same process.
//
// # This is NOT a response cache
//
// The distinction is the whole design, and was decided explicitly (Rob,
// 2026-07-31): a per-endpoint freshness window inside the API client would be a
// body cache on live lease data by another name, and this package deliberately is
// not that.
//
//   - Nothing here ever serves a Fetch* call. Every Fetch* still goes to the box,
//     every time. Collector poll cadence and every exported metric are untouched.
//   - Publication is a side effect of a fetch that was going to happen anyway. The
//     seam only records what was decoded.
//   - Reading is EXPLICIT and opt-in per call site: a consumer names the key and
//     the maximum age it is willing to accept, and gets nothing back if no
//     sufficiently fresh result exists. There is no ambient behaviour to reason
//     about at a call site that does not mention this package.
//
// A consumer that gets nothing back does what it did before — fetches. That is what
// keeps a disabled collector, a failing poll, or a plugin-absent endpoint working
// exactly as it did, with no special case anywhere.
//
// # Freshness is the caller's decision, not the store's
//
// There is deliberately no TTL configured per key. A stored entry never expires on
// its own; Fresh takes maxAge from the caller, because how stale is too stale is a
// property of what the reader is doing with it, not of the endpoint. Two consumers
// of the same key may reasonably disagree.
//
// A nil *Store is valid and permanently empty — every method is nil-safe — so a
// client or refresher built without one simply never publishes and never reads.
package fetchshare

import (
	"sync"
	"time"
)

// Key names one published result. It is the API endpoint name (the key in the
// client's endpoint table) wherever a result maps 1:1 onto an endpoint, so the
// seam, the response cache, the request self-metrics and the contract manifest all
// talk about the same thing under the same name.
//
// Where one endpoint is decoded into more than one shape, the key must name the
// SHAPE rather than the endpoint — an entry is retrieved by type assertion, so two
// producers publishing different Go types under one key would make every read a
// coin flip. There is no such case today; interfaceStatistics is the near miss
// (the collector's InterfaceStatistics and the refresher's kernel-index map come
// from the same route) and is deliberately not published for that reason.
type Key string

// The published keys. Each is produced by exactly one Fetch* method and consumed by
// the enrichment refresher (#571).
const (
	KeyArpTable           Key = "arp"
	KeyNDPTable           Key = "ndpTable"
	KeyKeaLeases4         Key = "keaLeases4"
	KeyKeaLeases6         Key = "keaLeases6"
	KeyDnsmasqLeases      Key = "dnsmasqLeases"
	KeyDHCPv4Leases       Key = "dhcpv4"
	KeyDHCPv6Leases       Key = "dhcpv6Leases"
	KeyInterfacesOverview Key = "interfacesOverview"
	KeyInterfaces         Key = "interfaces"
	KeyIPsecPhase1        Key = "ipsecPhase1"
	KeyOpenVPNInstances   Key = "openVPNInstances"
)

// Store holds the most recent decoded result per key, with the time it was
// recorded. It is safe for concurrent use; the zero value is not usable — call New.
type Store struct {
	now func() time.Time

	mu      sync.RWMutex
	entries map[Key]entry
}

type entry struct {
	value any
	at    time.Time
}

// New returns an empty Store.
func New() *Store {
	return &Store{now: time.Now, entries: make(map[Key]entry)}
}

// Publish records v as the latest decoded result for key, replacing any previous
// one. v must not be mutated afterwards: readers get the same value, not a copy,
// exactly as the API client's Fetch* methods already hand each caller a freshly
// decoded value it owns.
//
// Publishing a zero value is meaningful and must not be special-cased: an empty
// lease table from a box with no leases, or from a plugin-absent 404 folded into
// success, is a real answer. Suppressing it would leave the key permanently
// unpublished and send every reader to the API forever.
func (s *Store) Publish(key Key, v any) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[key] = entry{value: v, at: s.now()}
}

// age returns how long ago key was published.
func (s *Store) age(key Key) (any, time.Duration, bool) {
	if s == nil {
		return nil, 0, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[key]
	if !ok {
		return nil, 0, false
	}
	return e.value, s.now().Sub(e.at), true
}

// Fresh returns the published result for key when one exists, was published less
// than maxAge ago, and is of type T.
//
// A type mismatch returns false rather than panicking: it means two producers are
// publishing different shapes under one key, and the reader's job is to fall back
// to fetching, not to take the process down. (TestKeysHaveOneProducer is what
// stops that happening in the first place.)
//
// A non-positive maxAge always misses, so a caller can disable seam reads by
// passing 0 without a branch at the call site.
func Fresh[T any](s *Store, key Key, maxAge time.Duration) (T, bool) {
	var zero T
	if s == nil || maxAge <= 0 {
		return zero, false
	}
	v, age, ok := s.age(key)
	if !ok || age >= maxAge {
		return zero, false
	}
	typed, ok := v.(T)
	if !ok {
		return zero, false
	}
	return typed, true
}

// Snapshot returns the age of every published key, for diagnostics. The values
// themselves are deliberately not exposed: this is for answering "is the seam
// feeding the refresher?", not for reading data out of band.
func (s *Store) Snapshot() map[Key]time.Duration {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := s.now()
	out := make(map[Key]time.Duration, len(s.entries))
	for k, e := range s.entries {
		out[k] = now.Sub(e.at)
	}
	return out
}
