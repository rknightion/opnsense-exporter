package flow

import (
	"net/netip"
	"sort"
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
// # Where the enumeration comes from, and where it must not come from
//
// The ordering is the box's own `ifinfo` device list, fetched from
// api/diagnostics/interface/get_interface_config, whose JSON key order
// reproduces it exactly. Nothing else decides an index.
//
// It used to be derived by counting the rows of the interface OVERVIEW endpoint,
// which is a different list: on the reference box it returns 15 rows where the
// kernel has 16, because it omits pfsync0. Every index from 10 up came out one
// too low, and 93% of measured byte volume was attributed to the wrong interface
// for months (#361). So interface METADATA — names, addresses, WAN flags, VLAN
// parents — is joined onto the ordering BY DEVICE NAME, never by position, and a
// device the metadata does not know still occupies its slot.
//
// The rest of the contract:
//
//   - An operator override wins OUTRIGHT for any index it names.
//   - An index with no entry yields the ZERO Iface — an empty name, never a
//     guessed one. A wrong interface label is worse than a missing one, because a
//     missing one is visibly missing while a wrong one silently poisons a query.
//   - Every unmapped lookup is counted, every override that disagrees with the
//     derivation is counted, and every disagreement between the derived position
//     and the index the API states is counted, so a wrong map is observable
//     rather than silent.
//
// # Concurrency
//
// An IfMap is immutable after construction and is REBUILT AND SWAPPED, never
// mutated, so any number of readers may use one concurrently with no locking.
// The unmapped-lookup counter is the single exception; see IfMapCounters for why
// it does not live here. Lookups allocate nothing: they are map reads returning
// values.
type IfMap struct {
	byIndex map[uint32]Iface
	wanAddr map[netip.Addr]Iface
	wanDev  map[string]bool
	parents map[string]string
	// trunks is the inverse of parents: every device that at least one VLAN child
	// names as its parent. Derived rather than stored per row, because a child may
	// name a parent the interface list itself never contained.
	trunks map[string]bool

	// stated is the ifIndex the API states per device, and overriddenIdx is the
	// set of indices the operator pinned. Both exist for Entries — the operator
	// console has to show WHERE an entry came from, because this bug survived
	// entirely on nothing ever displaying the mapping.
	stated        map[string]uint32
	overriddenIdx map[uint32]bool

	built         time.Time
	overridden    int
	conflicts     int
	disagreements int
	unlisted      int

	// ownCounters backs a map nobody attached shared counters to — tests, and the
	// cold-start path before a Processor exists.
	ownCounters IfMapCounters
	counters    *IfMapCounters
}

// IfMapCounters holds the counters whose lifetime must OUTLIVE any one IfMap.
//
// This type exists because of a real, shipped bug. UnmappedLookups is the alarm
// for "the enumeration moved and indices no longer resolve" — the entire class of
// fault this map can suffer — and it lived as an atomic.Uint64 field on the IfMap
// itself. main rebuilds the map every 60 seconds and swaps it in, so the counter
// went back to zero every minute and a Prometheus counter that only ever counts
// to a handful before resetting is indistinguishable from one that never fires.
// It read 0 on a box where 0.9% of byte volume was landing on an index with no
// entry (#361).
//
// The Processor owns one of these for the life of the process and attaches it to
// every map it publishes.
type IfMapCounters struct {
	unmapped atomic.Uint64
}

// AttachCounters points the map at counters that survive a rebuild. It must be
// called BEFORE the map is published to readers — Processor.SetIfMap does it — so
// that it happens-before any concurrent lookup.
func (m *IfMap) AttachCounters(c *IfMapCounters) {
	if m == nil || c == nil {
		return
	}
	m.counters = c
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
	// never produced at all). A non-zero value means the ordering source does not
	// reproduce ifinfo order and is the signal worth alerting on.
	Conflicts int
	// StatedIndexDisagreements is how many devices the API states an ifIndex for
	// that differs from the position the ordering put them at. It is the guard on
	// an ordering carried by JSON key order: agreement is silent, disagreement
	// means something was destroyed and recreated and the enumeration has moved.
	StatedIndexDisagreements int
	// UnlistedDevices is how many devices the metadata knows that the ordering
	// does not contain. A device with no slot can never be resolved from an
	// ifIndex, so this is the ordering source going stale or wrong.
	UnlistedDevices int
	// UnmappedLookups is how many lookups found nothing and returned the zero Iface.
	UnmappedLookups uint64
}

// IfaceEntry is one resolved ifIndex entry, for the operator console.
//
// Rendering the map is part of the fix rather than a convenience: the off-by-one
// in #361 mislabelled 93% of byte volume for months, and it survived that long
// because the only way to see the mapping was to decode a raw packet capture.
type IfaceEntry struct {
	Index      uint32
	Device     string
	Name       string
	Overridden bool
	// Stated is the ifIndex the API states for this device, 0 when it states
	// none. Disagrees is Stated being non-zero and not equal to Index.
	Stated    uint32
	Disagrees bool
}

// IfMapInput is everything BuildIfMap needs. It is a struct rather than a
// parameter list because Order and Ifaces are two different lists from two
// different endpoints that are easy to transpose, and transposing them is
// precisely the bug this replaced.
type IfMapInput struct {
	// Order is the box's interface devices in ifinfo order: element i is ifIndex
	// i+1. This is THE enumeration. Empty means the fetch has not succeeded yet,
	// and nothing is derived — callers must keep their previous map rather than
	// publishing one built from nothing.
	Order []string
	// Ifaces carries interface metadata, joined onto Order BY DEVICE NAME. Its own
	// order is never read; a row for a device absent from Order still contributes
	// its VLAN parent and WAN addresses, and is counted in UnlistedDevices.
	Ifaces []enrich.IfaceInfo
	// Stated is device -> the ifIndex the API states for it. A cross-check only:
	// it is a per-interface property the kernel assigns, while the netflow hook
	// number is a POSITION in a list, and the two are equal ONLY while the index
	// space has no gaps.
	//
	// Remove an interface permanently and every device above it shifts down a
	// position while its kernel index stays put, so the position rc.d/netflow
	// counts stops matching the number the kernel reports. The position is what
	// names the hook and therefore what arrives in the records, so the position
	// wins and this only ever raises the alarm.
	//
	// A destroy-and-recreate does NOT do this, verified live on 2026-07-24 by
	// bouncing a PPPoE WAN: the interface reclaims the lowest free index, which
	// is its own while nothing else has taken it, and lands back in its old
	// slot. Do not "simplify" the derivation to read Stated instead — it agrees
	// right up until the one case that matters.
	Stated map[string]uint32
	// Override is the operator's --flow.netflow.ifindex-map, which wins outright.
	Override map[uint32]string
	// Built stamps the map for Age; pass the time the underlying data was fetched.
	Built time.Time
}

// BuildIfMap replays the netflow(8) interface enumeration over in.Order,
// assigning ifIndex 1 to the first device, 2 to the second and so on, joins
// in.Ifaces onto it by device name, then lets in.Override replace any index
// outright.
//
// An override value may name a known device ("igb0") or a known interface name
// ("WAN2"), in which case the index resolves to that whole interface; anything else
// is taken verbatim as the interface's name, because an operator asserting a label
// we cannot corroborate is still an assertion, not a guess of ours. A blank value
// states nothing and is ignored.
func BuildIfMap(in IfMapInput) *IfMap {
	m := &IfMap{
		byIndex:       make(map[uint32]Iface, len(in.Order)+1+len(in.Override)),
		wanAddr:       make(map[netip.Addr]Iface),
		wanDev:        make(map[string]bool),
		parents:       make(map[string]string),
		trunks:        make(map[string]bool),
		stated:        in.Stated,
		overriddenIdx: make(map[uint32]bool, len(in.Override)),
		built:         in.Built,
	}
	m.counters = &m.ownCounters

	// ifIndex 0 is not part of the enumeration: it is the firewall itself.
	m.byIndex[0] = Iface{Name: LocalOriginName}

	// Metadata first, keyed by device. Every row contributes its topology whether
	// or not the ordering lists it — a VLAN child's parent and a WAN's addresses
	// are facts about the interface, not about its slot.
	meta := make(map[string]enrich.IfaceInfo, len(in.Ifaces))
	byName := make(map[string]Iface, len(in.Ifaces))
	for _, info := range in.Ifaces {
		if parent := parentOfIface(info); parent != "" {
			m.parents[info.Device] = parent
			m.trunks[parent] = true
		}
		if info.Device == "" {
			continue
		}
		meta[info.Device] = info
		if info.IsWAN {
			m.wanDev[info.Device] = true
		}
	}

	byDevice := make(map[string]Iface, len(in.Order))
	listed := make(map[string]bool, len(in.Order))

	for i, device := range in.Order {
		// The counter advances for EVERY device, known to the metadata or not: a
		// device the metadata omits still occupied a slot in the box's own
		// enumeration, and skipping it shifts every index after it. That is
		// exactly what pfsync0 did in #361.
		idx := uint32(i + 1) //nolint:gosec // bounded by len(in.Order); an interface count cannot overflow uint32
		if device == "" {
			continue
		}
		listed[device] = true
		if stated, ok := in.Stated[device]; ok && stated != 0 && stated != idx {
			m.disagreements++
		}

		info := meta[device]
		iface := Iface{Device: device, Name: info.Name, Index: idx}
		m.byIndex[idx] = iface
		byDevice[device] = iface
		if info.Name != "" {
			if _, dup := byName[info.Name]; !dup {
				byName[info.Name] = iface
			}
		}
		for _, a := range info.Addrs {
			if !info.IsWAN {
				break
			}
			a = a.Unmap()
			if !a.IsValid() {
				continue
			}
			if _, dup := m.wanAddr[a]; !dup {
				m.wanAddr[a] = iface
			}
		}
	}

	// A device the metadata knows but the ordering does not can never be reached
	// from an ifIndex. That is the ordering source being stale or wrong, which is
	// the failure this map cannot otherwise detect, so it is counted.
	for device := range meta {
		if !listed[device] {
			m.unlisted++
		}
	}

	for idx, raw := range in.Override {
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
		m.overriddenIdx[idx] = true
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
	m.counters.unmapped.Add(1)
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

// HasVLANChildren reports whether device is a trunk — a device at least one VLAN
// child names as its parent.
//
// This is the question ParentOf cannot answer, because a trunk is precisely the
// device that is nobody's child. The VLAN/parent de-duplication needs it to decide
// whether a record naming this device could still be beaten by a more specific copy
// on one of its children (#357): if it could not, the record emits immediately and
// is never held.
func (m *IfMap) HasVLANChildren(device string) bool {
	if m == nil || device == "" {
		return false
	}
	return m.trunks[device]
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
		Entries:                  len(m.byIndex),
		Overridden:               m.overridden,
		Conflicts:                m.conflicts,
		StatedIndexDisagreements: m.disagreements,
		UnlistedDevices:          m.unlisted,
		UnmappedLookups:          m.counters.unmapped.Load(),
	}
}

// Entries renders the whole resolved map, sorted by index, for the operator
// console. It allocates, so it is a page-render path and never a lookup path.
func (m *IfMap) Entries() []IfaceEntry {
	if m == nil {
		return nil
	}
	out := make([]IfaceEntry, 0, len(m.byIndex))
	for idx, iface := range m.byIndex {
		e := IfaceEntry{
			Index:      idx,
			Device:     iface.Device,
			Name:       iface.Name,
			Overridden: m.overriddenIdx[idx],
		}
		if stated, ok := m.stated[iface.Device]; ok && stated != 0 {
			e.Stated = stated
			e.Disagrees = stated != idx
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}

// BuiltAt reports when the map's underlying data was fetched. Zero for an
// unstamped map.
func (m *IfMap) BuiltAt() time.Time {
	if m == nil {
		return time.Time{}
	}
	return m.built
}
