package flow

import (
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
)

// LocalOriginName is the interface Name reported for ifIndex 0.
//
// ng_netflow uses ifIndex 0 for traffic the firewall ITSELF sourced — it never
// entered through a netgraph hook — so 0 means "locally originated", not
// "unknown". Modelling it explicitly is what stops the box's own traffic from
// being counted as an unmapped lookup and losing its label.
const LocalOriginName = "locally-originated"

// vlanInfix is the OPNsense VLAN device-name convention: "<parent>_vlan<tag>".
const vlanInfix = "_vlan"

// IfMap resolves a NetFlow ifIndex to an interface.
//
// # Why this is hard
//
// The ifIndex in an OPNsense NetFlow record is NEITHER an OS index NOR an SNMP
// index. src/etc/rc.d/netflow attaches each interface with
//
//	ngctl mkpeer $interface: netflow lower iface$ifIndex
//
// where ifIndex is a 1-BASED COUNTER over `ifinfo` output across ALL interfaces.
// Nothing about it is stable: adding or removing any interface renumbers every
// interface after it, silently remapping historical series.
//
// # Why this is a best effort
//
// The map is derived by replaying that same enumeration over the interface list
// the OPNsense API returns, in API order. The API is NOT GUARANTEED to reproduce
// ifinfo's ordering — in particular it may omit unassigned kernel interfaces,
// which would shift every index from that point on. So:
//
//   - An operator override wins OUTRIGHT for any index it names.
//   - An index with no entry yields the ZERO Iface — an empty name, never a
//     guessed one. A wrong interface label is worse than a missing one, because a
//     missing one is visibly missing while a wrong one silently poisons a query.
//   - Every unmapped lookup is counted, and every override that disagrees with the
//     derivation is counted, so the disagreement is observable rather than silent.
//
// # Concurrency
//
// An IfMap is immutable after construction and is REBUILT AND SWAPPED, never
// mutated, so any number of readers may use one concurrently with no locking.
// UnmappedLookups is the single exception and is an atomic counter. Lookups
// allocate nothing: they are map reads returning values.
type IfMap struct {
	byIndex map[uint32]Iface
	wanAddr map[netip.Addr]Iface
	wanDev  map[string]bool
	parents map[string]string

	built      time.Time
	overridden int
	conflicts  int

	unmapped atomic.Uint64
}

// IfMapStats is a point-in-time view of an IfMap, for metrics and the operator
// console. Copying it copies the counter's value, not the counter.
type IfMapStats struct {
	// Entries is the number of ifIndex entries, INCLUDING the synthetic ifIndex 0.
	Entries int
	// Overridden is how many entries came from the operator override.
	Overridden int
	// Conflicts is how many of those overrides DISAGREED with what the derived
	// enumeration produced for the same index (including an index the derivation
	// never produced at all). A non-zero value means the API's interface list does
	// not reproduce ifinfo order — the failure mode this map cannot detect on its
	// own — and is the signal worth alerting on.
	Conflicts int
	// UnmappedLookups is how many lookups found nothing and returned the zero Iface.
	UnmappedLookups uint64
}

// BuildIfMap replays the netflow(8) interface enumeration over ifaces — which MUST
// be in the order the OPNsense API returned them — assigning ifIndex 1 to the
// first, 2 to the second and so on, then lets override replace any index outright.
//
// An override value may name a known device ("igb0") or a known interface name
// ("WAN2"), in which case the index resolves to that whole interface; anything else
// is taken verbatim as the interface's name, because an operator asserting a label
// we cannot corroborate is still an assertion, not a guess of ours. A blank value
// states nothing and is ignored.
//
// built stamps the map for Age; pass the time the underlying snapshot was fetched.
func BuildIfMap(ifaces []enrich.IfaceInfo, override map[uint32]string, built time.Time) *IfMap {
	m := &IfMap{
		byIndex: make(map[uint32]Iface, len(ifaces)+1+len(override)),
		wanAddr: make(map[netip.Addr]Iface),
		wanDev:  make(map[string]bool),
		parents: make(map[string]string),
		built:   built,
	}

	// ifIndex 0 is not part of the enumeration: it is the firewall itself.
	m.byIndex[0] = Iface{Name: LocalOriginName}

	byDevice := make(map[string]Iface, len(ifaces))
	byName := make(map[string]Iface, len(ifaces))

	for i, info := range ifaces {
		// The counter advances for EVERY row, mapped or not: a row we cannot name
		// still occupied a slot in the box's own enumeration, and skipping it would
		// shift every index after it.
		idx := uint32(i + 1) //nolint:gosec // bounded by len(ifaces); an interface count cannot overflow uint32
		iface := Iface{Device: info.Device, Name: info.Name, Index: idx}

		if parent := parentOfIface(info); parent != "" {
			m.parents[info.Device] = parent
		}
		if info.Device == "" {
			continue
		}
		m.byIndex[idx] = iface
		byDevice[info.Device] = iface
		if info.Name != "" {
			if _, dup := byName[info.Name]; !dup {
				byName[info.Name] = iface
			}
		}
		if info.IsWAN {
			m.wanDev[info.Device] = true
			for _, a := range info.Addrs {
				a = a.Unmap()
				if !a.IsValid() {
					continue
				}
				if _, dup := m.wanAddr[a]; !dup {
					m.wanAddr[a] = iface
				}
			}
		}
	}

	for idx, raw := range override {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue // states nothing; leave the derivation alone
		}
		resolved, ok := byDevice[value]
		if !ok {
			resolved, ok = byName[value]
		}
		if !ok {
			// Not an interface we know. Honour the operator's label verbatim; leave
			// Device empty rather than inventing one.
			resolved = Iface{Name: value}
		}
		resolved.Index = idx

		prev, existed := m.byIndex[idx]
		if !existed || prev.Device != resolved.Device || prev.Name != resolved.Name {
			m.conflicts++
		}
		m.byIndex[idx] = resolved
		m.overridden++
	}

	return m
}

// parentOfIface resolves a VLAN child's parent device, preferring what the API
// stated and falling back to the "<parent>_vlan<tag>" device-name convention only
// when the API said nothing. The fallback exists because the nested "vlan" object
// is not present on every release/row shape, while the device name always is.
func parentOfIface(info enrich.IfaceInfo) string {
	if info.VlanParent != "" {
		return info.VlanParent
	}
	return parseVLANParent(info.Device)
}

// parseVLANParent splits "ixl0_vlan50" into "ixl0". It requires a non-empty parent
// and an all-digit tag so an interface merely CONTAINING the substring is not
// mistaken for a VLAN child. LastIndex handles stacked QinQ names
// ("ixl0_vlan100_vlan200" -> "ixl0_vlan100").
func parseVLANParent(device string) string {
	i := strings.LastIndex(device, vlanInfix)
	if i <= 0 {
		return ""
	}
	tag := device[i+len(vlanInfix):]
	if tag == "" {
		return ""
	}
	for _, c := range tag {
		if c < '0' || c > '9' {
			return ""
		}
	}
	return device[:i]
}

// Iface resolves a NetFlow ifIndex.
//
// An index with no entry yields the ZERO Iface — empty device, empty name, so
// Label() is "" — and is counted in UnmappedLookups. It NEVER returns a guess.
// Safe on a nil receiver (the pipeline holds no map until the first build) and
// allocation-free, because it is called once per flow record.
func (m *IfMap) Iface(idx uint32) Iface {
	if m == nil {
		return Iface{}
	}
	if iface, ok := m.byIndex[idx]; ok {
		return iface
	}
	m.unmapped.Add(1)
	return Iface{}
}

// WANFor reports which WAN interface holds addr, if any. Addresses are Unmapped
// first: ::ffff:203.0.113.9 and 203.0.113.9 are the same host but netip compares
// them as different Addrs, so without this the v4-mapped form would always miss —
// the same reasoning as enrich.Snapshot.Scope and Record.CanonicalTuple.
//
// Only interfaces enrich flagged IsWAN are candidates, and that flag is a
// heuristic (see enrich.isWANIface): a miss is normal, and callers must treat a
// miss as "unknown", never as "not the firewall's".
func (m *IfMap) WANFor(addr netip.Addr) (Iface, bool) {
	if m == nil {
		return Iface{}, false
	}
	addr = addr.Unmap()
	if !addr.IsValid() {
		return Iface{}, false
	}
	iface, ok := m.wanAddr[addr]
	return iface, ok
}

// IsWAN reports whether a device is one the box treats as internet-facing.
//
// This exists for the direction rule. WANFor can only classify a record whose
// source IS a WAN address — the POST-NAT copy — but the ordinary pre-NAT record
// leaves a LAN address on a WAN interface and matches no WAN address at all. That
// is the majority of WAN traffic, and without this it reads as direction="unknown".
//
// It inherits the heuristic nature of enrich.IfaceInfo.IsWAN: a true is a strong
// hint, not ground truth. An unknown device is false — never a guess.
func (m *IfMap) IsWAN(device string) bool {
	if m == nil || device == "" {
		return false
	}
	return m.wanDev[device]
}

// ParentOf resolves a VLAN child device to its parent device. It answers only for
// devices present in the interface list the map was built from; an unknown device
// misses rather than being name-parsed on the fly, so the map's answers stay a
// function of its inputs alone.
func (m *IfMap) ParentOf(device string) (string, bool) {
	if m == nil || device == "" {
		return "", false
	}
	p, ok := m.parents[device]
	return p, ok && p != ""
}

// Age reports how stale the map is. It returns 0 for an unstamped map and clamps a
// backwards clock to 0 rather than reporting a negative age.
func (m *IfMap) Age(now time.Time) time.Duration {
	if m == nil || m.built.IsZero() {
		return 0
	}
	d := now.Sub(m.built)
	if d < 0 {
		return 0
	}
	return d
}

// Stats returns a snapshot of the map's shape and its miss counter.
func (m *IfMap) Stats() IfMapStats {
	if m == nil {
		return IfMapStats{}
	}
	return IfMapStats{
		Entries:         len(m.byIndex),
		Overridden:      m.overridden,
		Conflicts:       m.conflicts,
		UnmappedLookups: m.unmapped.Load(),
	}
}
