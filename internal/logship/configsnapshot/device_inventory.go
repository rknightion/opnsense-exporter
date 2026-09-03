package configsnapshot

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

const deviceInventoryFamily = "device_inventory"

// DeviceInventoryRecord is the deliberately small, allow-listed projection
// shipped for one network device. It contains no upstream configuration map;
// configuration-bearing families must continue to redact through
// opnsense.SensitiveConfigKey before they leave the firewall.
//
// Empty values are retained rather than omitted. ARP/NDP/DHCP and LLDP expose
// different portions of this identity, and stable field presence makes the
// record useful to Loki's JSON stage when one source has no value for a field.
type DeviceInventoryRecord struct {
	MAC       string   `json:"mac"`
	IPs       []string `json:"ips"`
	Hostname  string   `json:"hostname"`
	Interface string   `json:"interface"`
	FirstSeen string   `json:"first_seen"`
	LastSeen  string   `json:"last_seen"`
	Vendor    string   `json:"vendor"`
	// NewDevice is true only on the first snapshot observed by this provider for
	// this entity. The dashboard uses it for the "new device on network"
	// annotation; it is a body field because configsnapshot.Entity has no
	// provider-defined attribute hook.
	NewDevice bool `json:"new_device"`
}

// MarshalJSON keeps the family on the repository-wide sensitive-key contract.
// The record is an allow-listed projection rather than an upstream configuration
// map, but every shipped key still passes through SensitiveConfigKey so a future
// vocabulary expansion cannot leave this family behind.
func (r DeviceInventoryRecord) MarshalJSON() ([]byte, error) {
	fields := map[string]any{
		"mac":        r.MAC,
		"ips":        r.IPs,
		"hostname":   r.Hostname,
		"interface":  r.Interface,
		"first_seen": r.FirstSeen,
		"last_seen":  r.LastSeen,
		"vendor":     r.Vendor,
		"new_device": r.NewDevice,
	}
	for key := range fields {
		if opnsense.SensitiveConfigKey(key) {
			delete(fields, key)
		}
	}
	return json.Marshal(fields)
}

// snapshotCanonicalValue excludes the first-observation marker from the
// family's content hash. new_device is an emission-time event hint, not part of
// the device's persistent identity; including its true-to-false transition in
// the hash would force an otherwise unchanged inventory to emit a second
// change batch on the next poll.
func (r DeviceInventoryRecord) snapshotCanonicalValue() any {
	r.NewDevice = false
	return r
}

// DeviceInventoryObservation is the normalized input to the fusion core. One
// observation normally represents one row from ARP, NDP or a DHCP lease. The
// Identity field is reserved for sources without a MAC/IP join key, such as an
// LLDP neighbor whose chassis does not report a MAC identifier. LLDP rows that
// do report a chassis MAC use both the MAC and their stable chassis identity.
//
// FirstSeen and LastSeen are accepted only in RFC3339 form. A source that does
// not expose timestamps leaves them empty; the provider does not invent times
// for a row merely because it was polled.
type DeviceInventoryObservation struct {
	Source    string
	Identity  string
	MAC       string
	IP        string
	Hostname  string
	Interface string
	FirstSeen string
	LastSeen  string
	Vendor    string
}

// deviceInventoryFetcher supplies normalized observations to the provider.
// Keeping the fetch contract separate from fusion means the identity rules
// can be tested without a firewall and keeps API-source projection details out
// of the configstate framework.
type deviceInventoryFetcher interface {
	FetchDeviceInventory(context.Context) ([]DeviceInventoryObservation, error)
}

type deviceInventoryProvider struct {
	fetcher deviceInventoryFetcher

	mu   sync.Mutex
	seen map[string]struct{}
	// pending contains identities observed by the current source poll. It is
	// promoted to seen only through CommitSnapshot, after every sibling provider
	// and every record body has succeeded.
	pending map[string]struct{}
}

func newDeviceInventoryProvider(client *opnsense.Client) *deviceInventoryProvider {
	return newDeviceInventoryProviderWithFetcher(opnsenseDeviceInventoryFetcher{client: client})
}

func newDeviceInventoryProviderWithFetcher(fetcher deviceInventoryFetcher) *deviceInventoryProvider {
	return &deviceInventoryProvider{fetcher: fetcher, seen: make(map[string]struct{})}
}

func (*deviceInventoryProvider) Family() string { return deviceInventoryFamily }

func (p *deviceInventoryProvider) Snapshot(ctx context.Context) ([]Entity, error) {
	if p == nil || p.fetcher == nil {
		return nil, errors.New("device inventory provider has no fetcher")
	}
	observations, err := p.fetcher.FetchDeviceInventory(ctx)
	if err != nil {
		return nil, err
	}

	fused := fuseDeviceInventory(observations)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.seen == nil {
		p.seen = make(map[string]struct{})
	}

	entities := make([]Entity, 0, len(fused))
	pending := make(map[string]struct{}, len(fused))
	for _, device := range fused {
		_, known := p.seen[device.ID]
		pending[device.ID] = struct{}{}
		value := device.Record
		value.NewDevice = !known
		entities = append(entities, Entity{ID: device.ID, Value: value})
	}
	p.pending = pending
	return entities, nil
}

func (p *deviceInventoryProvider) CommitSnapshot() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.seen == nil {
		p.seen = make(map[string]struct{})
	}
	for id := range p.pending {
		p.seen[id] = struct{}{}
	}
	p.pending = nil
}

type fusedDevice struct {
	ID     string
	Record DeviceInventoryRecord

	mac        string
	ips        map[string]struct{}
	identities map[string]struct{}
	interfaces map[string]struct{}
	hostname   preferredString
	vendor     preferredString
	firstSeen  time.Time
	lastSeen   time.Time
	haveFirst  bool
	haveLast   bool
}

type preferredString struct {
	value    string
	priority int
}

func (v *preferredString) set(value string, priority int) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	if v.value == "" || priority < v.priority ||
		(priority == v.priority && value < v.value) {
		v.value = value
		v.priority = priority
	}
}

type normalizedObservation struct {
	source        string
	identity      string
	mac           string
	ip            string
	hostname      string
	interfaceName string
	firstSeen     time.Time
	lastSeen      time.Time
	haveFirst     bool
	haveLast      bool
	vendor        string
}

func normalizeObservation(observation DeviceInventoryObservation) (normalizedObservation, bool) {
	n := normalizedObservation{
		source:        strings.ToLower(strings.TrimSpace(observation.Source)),
		identity:      normalizeIdentity(observation.Identity),
		mac:           normalizeMAC(observation.MAC),
		ip:            normalizeIP(observation.IP),
		hostname:      strings.TrimSpace(observation.Hostname),
		interfaceName: strings.TrimSpace(observation.Interface),
		vendor:        strings.TrimSpace(observation.Vendor),
	}
	if first, ok := parseInventoryTimestamp(observation.FirstSeen); ok {
		n.firstSeen, n.haveFirst = first, true
	}
	if last, ok := parseInventoryTimestamp(observation.LastSeen); ok {
		n.lastSeen, n.haveLast = last, true
	}
	if n.mac == "" && n.ip == "" && n.identity == "" {
		return normalizedObservation{}, false
	}
	return n, true
}

func normalizeIdentity(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeMAC(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	mac, err := net.ParseMAC(value)
	if err != nil || len(mac) != 6 {
		return ""
	}
	return strings.ToLower(mac.String())
}

func normalizeIP(value string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return ""
	}
	return addr.Unmap().WithZone("").String()
}

func parseInventoryTimestamp(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

func sourcePriority(source string) int {
	switch source {
	case "arp":
		return 10
	case "ndp":
		return 20
	case "kea4", "kea6", "dnsmasq", "dhcpv4", "dhcpv6":
		return 30
	case "hostdiscovery":
		return 40
	case "lldp":
		return 50
	default:
		return 100
	}
}

type deviceBuilder struct {
	devices  []*fusedDevice
	mac      map[string]int
	ip       map[string]map[int]struct{}
	identity map[string]int
}

func newDeviceBuilder() *deviceBuilder {
	return &deviceBuilder{
		mac:      make(map[string]int),
		ip:       make(map[string]map[int]struct{}),
		identity: make(map[string]int),
	}
}

func (b *deviceBuilder) add(observation normalizedObservation) {
	matches := b.matches(observation)
	index := -1
	if len(matches) > 0 {
		index = matches[0]
		for _, other := range matches[1:] {
			if other != index {
				index = b.merge(index, other)
			}
		}
	}
	if index < 0 {
		index = len(b.devices)
		b.devices = append(b.devices, &fusedDevice{
			ips:        make(map[string]struct{}),
			identities: make(map[string]struct{}),
			interfaces: make(map[string]struct{}),
		})
	}
	b.absorb(index, observation)
	b.reindex()
}

func (b *deviceBuilder) matches(observation normalizedObservation) []int {
	if observation.mac != "" {
		if index, ok := b.mac[observation.mac]; ok {
			matches := []int{index}
			// A row first observed without a MAC can be upgraded when a later
			// source supplies one for the same IP. The MAC match is stronger
			// than the IP match, so only MAC-less candidates are absorbed here.
			for _, candidate := range b.ipCandidates(observation.ip) {
				if candidate != index && b.devices[candidate].mac == "" {
					matches = append(matches, candidate)
				}
			}
			return matches
		}
	}

	if observation.identity != "" {
		if index, ok := b.identity[observation.identity]; ok {
			candidate := b.devices[index]
			// A reused/ambiguous LLDP chassis name must not collapse two
			// devices whose MACs disagree. An identity-only row can still
			// upgrade a MAC-less candidate, but a concrete conflict is kept
			// separate and may be joined below only by an unambiguous IP.
			if observation.mac == "" || candidate.mac == "" || candidate.mac == observation.mac {
				return []int{index}
			}
		}
	}

	if observation.ip != "" {
		candidates := b.ipCandidates(observation.ip)
		// An IP-only observation is safe to join only when that IP identifies
		// one current record. If two MAC-bearing devices claim a stale/shared
		// IP, guessing would collapse distinct devices.
		if len(candidates) == 1 {
			candidate := b.devices[candidates[0]]
			if observation.mac == "" || candidate.mac == "" || candidate.mac == observation.mac {
				return candidates
			}
		}
	}
	return nil
}

func (b *deviceBuilder) ipCandidates(ip string) []int {
	set := b.ip[ip]
	if len(set) == 0 {
		return nil
	}
	indices := make([]int, 0, len(set))
	for index := range set {
		if index >= 0 && index < len(b.devices) && b.devices[index] != nil {
			indices = append(indices, index)
		}
	}
	sort.Ints(indices)
	return indices
}

func (b *deviceBuilder) merge(first, second int) int {
	if first == second {
		return first
	}
	if second < first {
		first, second = second, first
	}
	right := b.devices[second]
	if right == nil {
		return first
	}
	left := b.devices[first]
	if left.mac == "" {
		left.mac = right.mac
	}
	for ip := range right.ips {
		left.ips[ip] = struct{}{}
	}
	for identity := range right.identities {
		left.identities[identity] = struct{}{}
	}
	for iface := range right.interfaces {
		left.interfaces[iface] = struct{}{}
	}
	left.hostname = choosePreferred(left.hostname, right.hostname)
	left.vendor = choosePreferred(left.vendor, right.vendor)
	if right.haveFirst && (!left.haveFirst || right.firstSeen.Before(left.firstSeen)) {
		left.firstSeen, left.haveFirst = right.firstSeen, true
	}
	if right.haveLast && (!left.haveLast || right.lastSeen.After(left.lastSeen)) {
		left.lastSeen, left.haveLast = right.lastSeen, true
	}
	b.devices[second] = nil
	b.reindex()
	return first
}

func choosePreferred(left, right preferredString) preferredString {
	if left.value == "" {
		return right
	}
	if right.value == "" {
		return left
	}
	if right.priority < left.priority ||
		(right.priority == left.priority && right.value < left.value) {
		return right
	}
	return left
}

func (b *deviceBuilder) absorb(index int, observation normalizedObservation) {
	device := b.devices[index]
	if observation.mac != "" && device.mac == "" {
		device.mac = observation.mac
	}
	if observation.ip != "" {
		device.ips[observation.ip] = struct{}{}
	}
	if observation.identity != "" {
		device.identities[observation.identity] = struct{}{}
	}
	if observation.interfaceName != "" {
		device.interfaces[observation.interfaceName] = struct{}{}
	}
	priority := sourcePriority(observation.source)
	device.hostname.set(observation.hostname, priority)
	device.vendor.set(observation.vendor, priority)
	if observation.haveFirst && (!device.haveFirst || observation.firstSeen.Before(device.firstSeen)) {
		device.firstSeen, device.haveFirst = observation.firstSeen, true
	}
	if observation.haveLast && (!device.haveLast || observation.lastSeen.After(device.lastSeen)) {
		device.lastSeen, device.haveLast = observation.lastSeen, true
	}
}

func (b *deviceBuilder) reindex() {
	b.mac = make(map[string]int)
	b.ip = make(map[string]map[int]struct{})
	b.identity = make(map[string]int)
	for index, device := range b.devices {
		if device == nil {
			continue
		}
		if device.mac != "" {
			b.mac[device.mac] = index
		}
		for ip := range device.ips {
			if b.ip[ip] == nil {
				b.ip[ip] = make(map[int]struct{})
			}
			b.ip[ip][index] = struct{}{}
		}
		for identity := range device.identities {
			b.identity[identity] = index
		}
	}
}

func (b *deviceBuilder) result() []fusedDevice {
	result := make([]fusedDevice, 0, len(b.devices))
	for _, device := range b.devices {
		if device == nil {
			continue
		}
		ips := make([]string, 0, len(device.ips))
		for ip := range device.ips {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		interfaces := make([]string, 0, len(device.interfaces))
		for iface := range device.interfaces {
			interfaces = append(interfaces, iface)
		}
		sort.Slice(interfaces, func(i, j int) bool {
			if interfaces[i] == "unknown" {
				return false
			}
			if interfaces[j] == "unknown" {
				return true
			}
			return interfaces[i] < interfaces[j]
		})

		id := ""
		switch {
		case device.mac != "":
			id = "mac:" + device.mac
		case len(ips) > 0:
			id = "ip:" + ips[0]
		case len(device.identities) > 0:
			identities := make([]string, 0, len(device.identities))
			for identity := range device.identities {
				identities = append(identities, identity)
			}
			sort.Strings(identities)
			id = "identity:" + identities[0]
		}
		if id == "" {
			continue
		}

		iface := ""
		if len(interfaces) > 0 {
			iface = interfaces[0]
		}
		firstSeen, lastSeen := "", ""
		if device.haveFirst {
			firstSeen = device.firstSeen.UTC().Format(time.RFC3339Nano)
		}
		if device.haveLast {
			lastSeen = device.lastSeen.UTC().Format(time.RFC3339Nano)
		}
		result = append(result, fusedDevice{
			ID: id,
			Record: DeviceInventoryRecord{
				MAC:       device.mac,
				IPs:       ips,
				Hostname:  device.hostname.value,
				Interface: iface,
				FirstSeen: firstSeen,
				LastSeen:  lastSeen,
				Vendor:    device.vendor.value,
			},
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func fuseDeviceInventory(observations []DeviceInventoryObservation) []fusedDevice {
	builder := newDeviceBuilder()
	for _, observation := range observations {
		normalized, ok := normalizeObservation(observation)
		if ok {
			builder.add(normalized)
		}
	}
	return builder.result()
}

// opnsenseDeviceInventoryFetcher adapts the existing normalized OPNsense API
// results. The endpoint methods are intentionally called through WithContext
// so cancellation has the same behavior as the firewall config provider.
type opnsenseDeviceInventoryFetcher struct {
	client *opnsense.Client
}

func (f opnsenseDeviceInventoryFetcher) FetchDeviceInventory(ctx context.Context) ([]DeviceInventoryObservation, error) {
	if f.client == nil {
		return nil, errors.New("device inventory fetcher has no OPNsense client")
	}
	return collectDeviceInventory(opnsenseDeviceInventoryAPI{client: f.client.WithContext(ctx)})
}

type deviceInventoryAPI interface {
	FetchArpTable() (opnsense.ArpTable, *opnsense.APICallError)
	FetchNDPTable() (opnsense.NDPTable, *opnsense.APICallError)
	FetchKeaLeases4() (opnsense.KeaLeases, *opnsense.APICallError)
	FetchKeaLeases6() (opnsense.KeaLeases, *opnsense.APICallError)
	FetchDnsmasqLeases() (opnsense.DnsmasqLeases, *opnsense.APICallError)
	FetchDHCPv4Leases() (opnsense.DHCPv4Leases, *opnsense.APICallError)
	FetchDHCPv6Leases() (opnsense.DHCPv6Leases, *opnsense.APICallError)
	FetchHostDiscovery() (opnsense.HostDiscoveryInventory, *opnsense.APICallError)
	FetchLLDPNeighbors() (opnsense.LLDPNeighbors, *opnsense.APICallError)
}

type opnsenseDeviceInventoryAPI struct{ client *opnsense.Client }

func (a opnsenseDeviceInventoryAPI) FetchArpTable() (opnsense.ArpTable, *opnsense.APICallError) {
	return a.client.FetchArpTable()
}
func (a opnsenseDeviceInventoryAPI) FetchNDPTable() (opnsense.NDPTable, *opnsense.APICallError) {
	return a.client.FetchNDPTable()
}
func (a opnsenseDeviceInventoryAPI) FetchKeaLeases4() (opnsense.KeaLeases, *opnsense.APICallError) {
	return a.client.FetchKeaLeases4()
}
func (a opnsenseDeviceInventoryAPI) FetchKeaLeases6() (opnsense.KeaLeases, *opnsense.APICallError) {
	return a.client.FetchKeaLeases6()
}
func (a opnsenseDeviceInventoryAPI) FetchDnsmasqLeases() (opnsense.DnsmasqLeases, *opnsense.APICallError) {
	return a.client.FetchDnsmasqLeases()
}
func (a opnsenseDeviceInventoryAPI) FetchDHCPv4Leases() (opnsense.DHCPv4Leases, *opnsense.APICallError) {
	return a.client.FetchDHCPv4Leases()
}
func (a opnsenseDeviceInventoryAPI) FetchDHCPv6Leases() (opnsense.DHCPv6Leases, *opnsense.APICallError) {
	return a.client.FetchDHCPv6Leases()
}
func (a opnsenseDeviceInventoryAPI) FetchHostDiscovery() (opnsense.HostDiscoveryInventory, *opnsense.APICallError) {
	return a.client.FetchHostDiscovery()
}
func (a opnsenseDeviceInventoryAPI) FetchLLDPNeighbors() (opnsense.LLDPNeighbors, *opnsense.APICallError) {
	return a.client.FetchLLDPNeighbors()
}

func collectDeviceInventory(api deviceInventoryAPI) ([]DeviceInventoryObservation, error) {
	if api == nil {
		return nil, errors.New("device inventory API is nil")
	}
	var observations []DeviceInventoryObservation

	arps, err := api.FetchArpTable()
	if err != nil {
		return nil, err
	}
	for _, row := range arps.Arp {
		observations = append(observations, DeviceInventoryObservation{
			Source: "arp", MAC: row.Mac, IP: row.IP, Hostname: row.Hostname,
			Interface: firstNonEmptyInventory(row.IntfDescription, row.Device), Vendor: row.Manufacturer,
		})
	}

	ndp, err := api.FetchNDPTable()
	if err != nil {
		return nil, err
	}
	for _, row := range ndp.Entries {
		observations = append(observations, DeviceInventoryObservation{
			Source: "ndp", MAC: row.Mac, IP: row.IP,
			Interface: firstNonEmptyInventory(row.IntfDescription, row.Device), Vendor: row.Manufacturer,
		})
	}

	kea4, err := api.FetchKeaLeases4()
	if err != nil {
		if !isOptionalInventory404(err) {
			return nil, err
		}
	} else {
		for _, row := range kea4.Leases {
			observations = append(observations, DeviceInventoryObservation{
				Source: "kea4", MAC: row.HWAddr, IP: row.Address, Hostname: row.Hostname,
				Interface: row.IfDescr, Vendor: row.Vendor,
			})
		}
	}

	kea6, err := api.FetchKeaLeases6()
	if err != nil {
		if !isOptionalInventory404(err) {
			return nil, err
		}
	} else {
		for _, row := range kea6.Leases {
			observations = append(observations, DeviceInventoryObservation{
				Source: "kea6", MAC: row.HWAddr, IP: row.Address, Hostname: row.Hostname,
				Interface: row.IfDescr, Vendor: row.Vendor,
			})
		}
	}

	dnsmasq, err := api.FetchDnsmasqLeases()
	if err != nil {
		if !isOptionalInventory404(err) {
			return nil, err
		}
	} else {
		for _, row := range dnsmasq.Leases {
			observations = append(observations, DeviceInventoryObservation{
				Source: "dnsmasq", MAC: row.HWAddr, IP: row.Address, Hostname: row.Hostname,
				Interface: row.IfDescr, Vendor: row.Vendor,
			})
		}
	}

	dhcp4, err := api.FetchDHCPv4Leases()
	if err != nil {
		if !isOptionalInventory404(err) {
			return nil, err
		}
	} else if dhcp4.Present {
		for _, row := range dhcp4.Leases {
			observations = append(observations, DeviceInventoryObservation{
				Source: "dhcpv4", MAC: row.MAC, IP: row.Address, Hostname: row.Hostname,
				Interface: row.IfDescr,
			})
		}
	}

	dhcp6, err := api.FetchDHCPv6Leases()
	if err != nil {
		if !isOptionalInventory404(err) {
			return nil, err
		}
	} else {
		for _, row := range dhcp6.Leases {
			observations = append(observations, DeviceInventoryObservation{
				Source: "dhcpv6", MAC: row.MAC, IP: row.Address,
				Interface: row.IfDescr,
			})
		}
	}

	// Hostdiscovery is the only current source with persistent first/last-seen
	// timestamps. Its aggregate Groups remain metric-only; the per-host Hosts
	// projection is an allow-listed, non-label view for this bounded family.
	hostdiscovery, err := api.FetchHostDiscovery()
	if err != nil && !isOptionalInventory404(err) {
		return nil, err
	}
	for _, row := range hostdiscovery.Hosts {
		observations = append(observations, DeviceInventoryObservation{
			Source: "hostdiscovery", MAC: row.MAC, IP: row.IP,
			Interface: row.Interface, FirstSeen: row.FirstSeen,
			LastSeen: row.LastSeen, Vendor: row.Vendor,
		})
	}

	lldp, err := api.FetchLLDPNeighbors()
	if err != nil {
		if !isOptionalInventory404(err) {
			return nil, err
		}
	} else {
		for _, row := range lldp.Neighbors {
			identity := lldpIdentity(row)
			if len(row.MgmtIPs) == 0 {
				observations = append(observations, DeviceInventoryObservation{
					Source: "lldp", Identity: identity, MAC: row.ChassisMAC,
					Hostname: row.ChassisName, Interface: row.Interface,
				})
				continue
			}
			for _, ip := range row.MgmtIPs {
				observations = append(observations, DeviceInventoryObservation{
					Source: "lldp", Identity: identity, MAC: row.ChassisMAC,
					IP: ip, Hostname: row.ChassisName, Interface: row.Interface,
				})
			}
		}
	}

	return observations, nil
}

func firstNonEmptyInventory(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func isOptionalInventory404(err *opnsense.APICallError) bool {
	return err != nil && err.StatusCode == http.StatusNotFound
}

func lldpIdentity(neighbor opnsense.LLDPNeighbor) string {
	if mac := normalizeMAC(neighbor.ChassisMAC); mac != "" {
		return "lldp:mac:" + mac
	}
	name := strings.ToLower(strings.TrimSpace(neighbor.ChassisName))
	if name != "" {
		return "lldp:name:" + name
	}
	return "lldp:interface:" + strings.ToLower(strings.TrimSpace(neighbor.Interface)) +
		":port:" + strings.ToLower(strings.TrimSpace(neighbor.PortID)) +
		":description:" + strings.ToLower(strings.TrimSpace(neighbor.PortDescr))
}

var _ Provider = (*deviceInventoryProvider)(nil)
