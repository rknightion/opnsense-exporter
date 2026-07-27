// Package enrich turns the opaque identifiers in an OPNsense log line — a rule
// id, a kernel device name, a bare IP address — into something a human can read,
// using data the exporter already fetches from the OPNsense API.
//
// The hot path here is a LOG LINE, not a scrape: at burst it runs thousands of
// times a second on the receiver goroutine. Every lookup is therefore served from
// an immutable Snapshot published through an atomic pointer — reads take no locks
// and never allocate. A background Refresher rebuilds snapshots on a TTL (and on
// demand, see NoteMiss) and swaps them in.
package enrich

import (
	"net/netip"
	"sync/atomic"
	"time"
)

// Snapshot is an immutable, point-in-time view of every enrichment table.
//
// A Snapshot is NEVER mutated after it is published via Cache.Store. Rebuilds
// clone it and replace only the table they own, so unchanged maps are shared
// between snapshots for free.
type Snapshot struct {
	RuleLabels  map[string]string    // filterlog rid -> rule description
	IfaceNames  map[string]string    // "vtnet0" -> "LAN"
	Hostnames   map[string]string    // "10.0.0.6" -> "robs-laptop"
	MACs        map[string]string    // "10.0.0.6" -> "aa:bb:cc:dd:ee:ff"
	LocalNets   []netip.Prefix       // every subnet configured on the firewall
	SelfIPs     map[netip.Addr]bool  // addresses the firewall itself holds
	LastRefresh map[string]time.Time // per TABLE: "rules" | "interfaces" | "leases" | "tunnels"

	// Ifaces is every interface the box reports, with its identity and topology.
	// It is METADATA ONLY: internal/flow joins it onto IfaceOrder by device name.
	// Its own order carries no meaning and must not be read as one — doing exactly
	// that is what mislabelled 93% of NetFlow byte volume for months (#361).
	Ifaces []IfaceInfo

	// IfaceOrder is the box's interface devices in `ifinfo` order: element i is
	// ifIndex i+1. THIS is the NetFlow enumeration, and the only thing that
	// decides an index.
	//
	// OPNsense derives the same list twice — src/etc/rc.d/netflow counts it to
	// name the netgraph hook `ifaceN`, and its own flowd reporting
	// (scripts/netflow/lib/parse.py) counts it again to read those names back.
	//
	// It is built from api/diagnostics/interface/get_interface_config, whose key
	// order is ATTACH order rather than `ifinfo` order, corrected with the kernel
	// indices in IfaceStatedIndex — see reconstructIfinfoOrder (#363). The two
	// orders agree until an interface is recreated, and diverge silently after.
	//
	// Empty means the fetch has never succeeded. It must NOT be treated as "no
	// interfaces": a map built from an empty ordering resolves nothing, so
	// consumers keep their previous map instead of publishing one built from it.
	IfaceOrder []string

	// IfaceStatedIndex is the ifIndex the API states per device, from
	// api/diagnostics/traffic/interface. It is a CROSS-CHECK on IfaceOrder and
	// never a substitute: the stated value is a per-interface property the kernel
	// assigns, while the netflow hook number is a position in a list, and the two
	// are equal only while the index space has no gaps. A permanent removal
	// shifts every position above it while the stated indices stay put; a
	// destroy-and-recreate does not (verified live 2026-07-24). A disagreement
	// is therefore the signal that the enumeration has really moved.
	IfaceStatedIndex map[string]uint32

	// Tunnels maps an IPsec connection UUID to its description. charon logs the
	// tunnel as a bare UUID ("<5e891b0c-...|8> sending DPD request"), which is
	// unreadable without the API — and the exporter is the one component that has it.
	Tunnels map[string]string
	// VPNInstances maps an OpenVPN instance UUID to its description. OpenVPN names
	// the instance only in a management socket path (instance-<uuid>.sock).
	VPNInstances map[string]string
}

// IfaceInfo is one interface's identity and topology, as the OPNsense API
// reports it. It is a projection of opnsense.InterfaceOverview: the enrichment
// snapshot must not leak the API package's types onto the hot path, and only
// these fields are needed to derive interface topology.
//
// It is part of an immutable Snapshot — neither the struct nor Addrs may be
// mutated after publication.
type IfaceInfo struct {
	Device     string       // kernel name: "ixl0", "ixl0_vlan50", "pppoe0"
	Name       string       // OPNsense description: "LAN", "IOT"; may be empty
	Identifier string       // config identifier: "lan", "wan", "opt3"; empty when unassigned
	VlanTag    string       // 802.1q tag; empty for a non-VLAN interface
	VlanParent string       // parent device for a VLAN child; empty otherwise
	Addrs      []netip.Addr // every configured address, Unmap()ed
	// Prefixes is every configured SUBNET on this interface, masked to its network
	// address. Kept PER INTERFACE, unlike Snapshot.LocalNets which merges every
	// interface's subnets into one flat list: the flat form answers "is this address
	// local", which is all Scope needs, but it cannot answer "WHICH interface owns this
	// address" — and that is the question the NetFlow repair stage needs in order to
	// attribute a trunk-captured record to the VLAN child the traffic actually belongs
	// to (#465). doRefreshIfaces used to compute this and throw it away.
	Prefixes []netip.Prefix
	IsWAN    bool // see isWANIface in refresh.go for the heuristic and its limits
}

// IsVLAN reports whether this interface is an 802.1q child of another.
func (i IfaceInfo) IsVLAN() bool { return i.VlanTag != "" || i.VlanParent != "" }

// emptySnapshot backs a cold Cache: every lookup misses, nothing panics.
var emptySnapshot = &Snapshot{}

// RuleLabel resolves a filterlog rid to its rule description. An empty
// description is reported as a miss — a blank label is no better than none.
func (s *Snapshot) RuleLabel(rid string) (string, bool) {
	v, ok := s.RuleLabels[rid]
	return v, ok && v != ""
}

// InterfaceName resolves a kernel device ("vtnet0") to its OPNsense description
// ("LAN").
func (s *Snapshot) InterfaceName(dev string) (string, bool) {
	v, ok := s.IfaceNames[dev]
	return v, ok && v != ""
}

// Tunnel resolves an IPsec connection UUID to its configured description.
func (s *Snapshot) Tunnel(uuid string) (string, bool) {
	v, ok := s.Tunnels[uuid]
	return v, ok && v != ""
}

// VPNInstance resolves an OpenVPN instance UUID to its configured description.
func (s *Snapshot) VPNInstance(uuid string) (string, bool) {
	v, ok := s.VPNInstances[uuid]
	return v, ok && v != ""
}

// Hostname resolves an IP to a DHCP/ARP-known hostname.
func (s *Snapshot) Hostname(ip string) (string, bool) {
	v, ok := s.Hostnames[ip]
	return v, ok && v != ""
}

// MAC resolves an IP to its link-layer address.
func (s *Snapshot) MAC(ip string) (string, bool) {
	v, ok := s.MACs[ip]
	return v, ok && v != ""
}

// Scope classifies an address relative to the firewall:
//
//	"self"   the firewall itself holds this address
//	"local"  the address sits inside one of the firewall's configured subnets
//	"remote" anything else routable
//	""       not an IP address at all
//
// SelfIPs is keyed by netip.Addr rather than string on purpose: one IPv6 address
// has many textual forms (2001:db8::0001, 2001:db8::1, ::1 …) and a string key
// would silently miss most of them.
func (s *Snapshot) Scope(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	addr = addr.Unmap()

	// Without the box's own addresses and subnets we do not know the topology, and
	// "remote" would be a confident LIE rather than an absence — every LAN address
	// on a cold or failed snapshot would be labelled as though it came from the
	// internet. Say nothing instead.
	if len(s.SelfIPs) == 0 && len(s.LocalNets) == 0 {
		return ""
	}

	if s.SelfIPs[addr] {
		return "self"
	}
	for _, p := range s.LocalNets {
		if p.Contains(addr) {
			return "local"
		}
	}
	return "remote"
}

// clone shallow-copies the snapshot. Callers hold buildMu. Sharing the unchanged
// maps with the previous snapshot is safe precisely because snapshots are never
// mutated after Store; LastRefresh is copied because every rebuild writes to it.
func (s *Snapshot) clone() *Snapshot {
	next := &Snapshot{
		RuleLabels: s.RuleLabels,
		IfaceNames: s.IfaceNames,
		Hostnames:  s.Hostnames,
		MACs:       s.MACs,
		LocalNets:  s.LocalNets,
		SelfIPs:    s.SelfIPs,
		Ifaces:     s.Ifaces,

		// EVERY field must be carried here. A field omitted is not a partial
		// clone, it is a field that silently reverts to zero the next time any
		// OTHER table refreshes — which is minutes, so it never survives to be
		// noticed in a test that only exercises its own refresh.
		// TestSnapshotCloneCarriesEveryField enforces this by reflection.
		IfaceOrder:       s.IfaceOrder,
		IfaceStatedIndex: s.IfaceStatedIndex,

		Tunnels:      s.Tunnels,
		VPNInstances: s.VPNInstances,
		LastRefresh:  make(map[string]time.Time, len(s.LastRefresh)+1),
	}
	for k, v := range s.LastRefresh {
		next.LastRefresh[k] = v
	}
	return next
}

// Cache publishes the current Snapshot. Load is lock-free and allocation-free —
// it is called once per enriched log line, on the receiver goroutine — and it
// NEVER returns nil: a cold cache serves an empty snapshot that misses every
// lookup rather than panicking the reader.
type Cache struct {
	p atomic.Pointer[Snapshot]
}

// NewCache returns a cache seeded with an empty snapshot, so a read before the
// first refresh misses cleanly instead of nil-panicking.
func NewCache() *Cache {
	c := &Cache{}
	c.p.Store(emptySnapshot)
	return c
}

// Load returns the current snapshot. Lock-free; never nil.
func (c *Cache) Load() *Snapshot {
	if s := c.p.Load(); s != nil {
		return s
	}
	return emptySnapshot
}

// Store publishes s. s must never be mutated after this call.
func (c *Cache) Store(s *Snapshot) {
	if s == nil {
		s = emptySnapshot
	}
	c.p.Store(s)
}
