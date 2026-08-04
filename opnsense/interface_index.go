package opnsense

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// The kernel interface index, read from netstat.
//
// # Why this endpoint and not a nicer one
//
// NetFlow's ifIndex is a POSITION in the device list `/usr/local/sbin/ifinfo`
// prints, and that list is the kernel's ifmib table walked by row number — the row
// number IS the kernel index (`ifinfo.c`: `for (i = 1; i <= maxifno; i++)`,
// `continue` on ENOENT). So reproducing the enumeration means knowing every
// device's kernel index and ranking by it.
//
// Nothing models that as a field. The endpoints that look like they should do not
// have it: get_interface_config has no index at all, and interfaces_info omits
// pfsync0 outright (`parseIfInfo()` carries a hardcoded skip for it), which is
// disqualifying because pfsync0 sits in the MIDDLE of the index space.
//
// api/diagnostics/interface/get_interface_statistics is `netstat -i -n -W -b -d
// --libxo json`, and netstat renders each interface's AF_LINK row with its network
// column set to the literal "<Link#N>" — N being sdl_index, the kernel index
// (usr.bin/netstat/if.c). It is the only API route to the index for EVERY device,
// including the unassigned ports and pseudo-devices (#364).
//
// # Why this is not cached
//
// The payload is packet and byte counters. Caching it would freeze them, and the
// per-endpoint cache contract in this package permits only wholly slow-moving
// bodies for exactly that reason.

// linkNetwork matches netstat's AF_LINK network column and captures the kernel
// index. Every other row in the response is a per-ADDRESS row whose network is a
// prefix ("10.0.0.0/24", "fe80::%ixl0/64") — three times as many of them as real
// interfaces — so this pattern is the filter, not a convenience.
var linkNetwork = regexp.MustCompile(`^<Link#(\d+)>$`)

// interfaceStatisticsResponse is the shape of get_interface_statistics: an object
// keyed by a DISPLAY string ("[LAN] (ixl0) / 98:b7:85:21:af:f2") that is not
// stable enough to key on, so the device comes from the row's own name field.
type interfaceStatisticsResponse struct {
	Statistics map[string]interfaceStatisticsRow `json:"statistics"`
}

type interfaceStatisticsRow struct {
	Name    string `json:"name"`
	Network string `json:"network"`
	Address string `json:"address"`

	ReceivedPackets float64 `json:"received-packets"`
	ReceivedBytes   float64 `json:"received-bytes"`
	SentPackets     float64 `json:"sent-packets"`
	SentBytes       float64 `json:"sent-bytes"`

	// DroppedPackets is IFCOUNTER_OQDROPS. libxo emits the key twice in this
	// payload and PHP's json_decode is last-wins, which is why the value lands
	// on oqdrops rather than the input-side counter; verified against raw
	// netstat on a dev box (tailscale0 oqdrops=8, API reported 8). It is
	// present ONLY on the AF_LINK row, so a pointer distinguishes "the box did
	// not report it" from a genuine zero.
	//
	// There is no equivalent INPUT-drop counter anywhere in this payload: the
	// only drop key on the wire is this one, and it lands on the OUTPUT side
	// per the libxo/PHP quirk above. #642 confirmed this on a live capture
	// where netstat's own Idrop column (3081 on ixl2) has no counterpart here
	// at all (dropped-packets reads 0 for the same interface at the same
	// time). Do not repurpose this field as an input-drop counter for a
	// gap-filled device — there is nothing to source that from.
	DroppedPackets *float64 `json:"dropped-packets"`

	// InputErrors/OutputErrors/Collisions are IFCOUNTER_IERRORS
	// ("received-errors"), IFCOUNTER_OERRORS ("send-errors") and
	// IFCOUNTER_COLLISIONS ("collisions"). Like DroppedPackets above, they
	// are present ONLY on the AF_LINK row, so a pointer distinguishes "the
	// box did not report it" from a genuine zero (#642).
	InputErrors  *float64 `json:"received-errors"`
	OutputErrors *float64 `json:"send-errors"`
	Collisions   *float64 `json:"collisions"`
}

// packetCountImplausible reports whether a packet count is physically
// impossible given the byte count reported on the SAME row: fewer than 20
// bytes per packet is below the minimum Ethernet frame, so no genuine packet
// count can produce it. It only applies when packets > 0 — an idle device
// legitimately reports 0 packets against 0 bytes, and dividing by a zero
// packet count must never suppress that (#642).
//
// This widens the implausible-value guard beyond parseQueueDropCounter's
// int32-wrap check (opnsense/interfaces.go), which does not catch this case.
// Prod ixl2 reports received-packets = 281,475,478,389,769
// (0x100001de95031 — exactly 2^48 plus a plausible count: the low bits
// increment correctly with real traffic, bit 48 is simply stuck high)
// against received-bytes = 393,185,547,668, ~0.0014 bytes/packet. A
// magnitude ceiling is deliberately NOT used: 2^48 is theoretically
// reachable on a fast enough link over a long enough uptime, so a bare
// threshold would eventually reject a real count. The bytes/packet
// cross-check does not have that failure mode.
func packetCountImplausible(packets, bytes float64) bool {
	if packets <= 0 {
		return false
	}
	return bytes/packets < 20
}

// InterfaceFamilyTraffic is one device's traffic for one address family,
// summed over every address of that family the device holds.
type InterfaceFamilyTraffic struct {
	Device string
	Family string // "ipv4" or "ipv6"

	ReceivedPackets, ReceivedBytes float64
	SentPackets, SentBytes         float64
}

// InterfaceLinkStats holds the per-device counters that only the AF_LINK row
// carries: the original OutputQueueDrops, plus (#642) the full gap-fill
// counter set used for devices api/diagnostics/traffic/interface
// (FetchInterfaces) does not cover. That endpoint is OPNsense's own
// restriction to interfaces with a config identifier, so a purely physical,
// unassigned port — e.g. ixl2, the SFP+ NIC underneath a PPPoE WAN — has no
// counters there at all, even though this endpoint's AF_LINK row carries a
// full set for it same as for any assigned device.
//
// This struct carries the raw parsed values for EVERY device the response
// returns (#642 point 3: uniform rule, no physical-vs-pseudo classification
// here). It is the CALLER's job — the collector, which alone holds both this
// fetch and FetchInterfaces's — to decide, per device, whether to use this
// gap-fill data or the traffic endpoint's own counters, and NEVER both: two
// independent sources for one counter would drift and make any rate() over
// the combined series meaningless. See interfacesCollector.Update's
// trafficCoveredDevices for that join, and
// TestInterfacesCollector_StatisticsGapFill_NoDoubleSource for the
// regression guard.
type InterfaceLinkStats struct {
	Device string

	OutputQueueDrops        float64
	OutputQueueDropsPresent bool

	// ReceivedBytes/SentBytes are read unconditionally: nothing on the
	// reference box has ever shown these implausible, unlike the packet
	// counters below.
	ReceivedBytes float64
	SentBytes     float64

	// ReceivedPackets/SentPackets are independently presence-gated by
	// packetCountImplausible against their own row's paired byte count: a
	// device can have a corrupt received-packets figure and a perfectly
	// good sent-packets figure in the same row (ixl2, live), so each
	// direction is checked on its own rather than gating the whole row on
	// one bad field.
	ReceivedPackets        float64
	ReceivedPacketsPresent bool
	SentPackets            float64
	SentPacketsPresent     bool

	InputErrors         float64
	InputErrorsPresent  bool
	OutputErrors        float64
	OutputErrorsPresent bool
	Collisions          float64
	CollisionsPresent   bool
}

// InterfaceStatistics is the parsed get_interface_statistics payload beyond the
// kernel index: the per-address-family traffic split and the per-device link
// counters.
type InterfaceStatistics struct {
	Families []InterfaceFamilyTraffic
	Links    []InterfaceLinkStats
}

// addressFamily classifies a per-address row. The row's own address is used
// rather than the network prefix because both are equally reliable and the
// address is always populated. Callers MUST have excluded AF_LINK rows first:
// their address is a MAC, which contains colons and would classify as IPv6.
func addressFamily(address string) string {
	if strings.Contains(address, ":") {
		return "ipv6"
	}
	return "ipv4"
}

// FetchInterfaceStatistics returns the per-address-family traffic split and the
// per-device link counters from get_interface_statistics.
//
// # What the family split does and does not measure
//
// The per-address counters count traffic addressed to or sourced from THIS box's
// own addresses. Forwarded transit traffic is not attributed to any local
// address, so on a router the family rows sum to a small fraction of the device
// total: on the reference box ixl0's AF_LINK row read 419,866,764 received
// packets while its four address rows summed to 24.5M, about 6%. Read this as
// "which family is the box itself talking", not as a split of everything the
// interface forwards.
//
// # Why a separate call from FetchInterfaceIndexes
//
// The index lookup feeds log enrichment on its own refresh cadence and its
// contract (an empty result is a hard error) is deliberately stricter than this
// one's. Keeping them separate leaves that path untouched.
func (c *Client) FetchInterfaceStatistics() (InterfaceStatistics, *APICallError) {
	var data InterfaceStatistics

	url, ok := c.endpoints["interfaceStatistics"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "interfaceStatistics",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var resp interfaceStatisticsResponse
	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	families := make(map[string]*InterfaceFamilyTraffic)
	links := make(map[string]*InterfaceLinkStats)

	for _, row := range resp.Statistics {
		if row.Name == "" {
			continue
		}
		if linkNetwork.MatchString(row.Network) {
			l, exists := links[row.Name]
			if !exists {
				l = &InterfaceLinkStats{Device: row.Name}
				links[row.Name] = l
			}
			if row.DroppedPackets != nil {
				l.OutputQueueDrops = *row.DroppedPackets
				l.OutputQueueDropsPresent = true
			}
			if row.InputErrors != nil {
				l.InputErrors = *row.InputErrors
				l.InputErrorsPresent = true
			}
			if row.OutputErrors != nil {
				l.OutputErrors = *row.OutputErrors
				l.OutputErrorsPresent = true
			}
			if row.Collisions != nil {
				l.Collisions = *row.Collisions
				l.CollisionsPresent = true
			}
			l.ReceivedBytes = row.ReceivedBytes
			l.SentBytes = row.SentBytes
			if !packetCountImplausible(row.ReceivedPackets, row.ReceivedBytes) {
				l.ReceivedPackets = row.ReceivedPackets
				l.ReceivedPacketsPresent = true
			}
			if !packetCountImplausible(row.SentPackets, row.SentBytes) {
				l.SentPackets = row.SentPackets
				l.SentPacketsPresent = true
			}
			continue
		}

		fam := addressFamily(row.Address)
		key := row.Name + "\x00" + fam
		f, exists := families[key]
		if !exists {
			f = &InterfaceFamilyTraffic{Device: row.Name, Family: fam}
			families[key] = f
		}
		f.ReceivedPackets += row.ReceivedPackets
		f.ReceivedBytes += row.ReceivedBytes
		f.SentPackets += row.SentPackets
		f.SentBytes += row.SentBytes
	}

	data.Families = make([]InterfaceFamilyTraffic, 0, len(families))
	for _, f := range families {
		data.Families = append(data.Families, *f)
	}
	sort.Slice(data.Families, func(i, j int) bool {
		if data.Families[i].Device != data.Families[j].Device {
			return data.Families[i].Device < data.Families[j].Device
		}
		return data.Families[i].Family < data.Families[j].Family
	})

	data.Links = make([]InterfaceLinkStats, 0, len(links))
	for _, l := range links {
		data.Links = append(data.Links, *l)
	}
	sort.Slice(data.Links, func(i, j int) bool { return data.Links[i].Device < data.Links[j].Device })

	return data, nil
}

// FetchInterfaceIndexes returns each device's kernel interface index.
//
// The result is NOT the NetFlow ifIndex. NetFlow's index is the device's RANK once
// every device is ordered by these values, and rank equals index only while the
// index space is dense — a permanently removed interface leaves a gap, past which
// they diverge. Ranking is the caller's job precisely so that distinction stays
// visible.
//
// An empty result is an error rather than an empty map: every failure mode of this
// parse (a libxo format change, a renamed column) looks like "no interfaces have an
// index", and silently returning that would let a caller derive an enumeration from
// nothing.
func (c *Client) FetchInterfaceIndexes() (map[string]uint32, *APICallError) {
	url, ok := c.endpoints["interfaceStatistics"]
	if !ok {
		return nil, &APICallError{
			Endpoint:   "interfaceStatistics",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var resp interfaceStatisticsResponse
	if err := c.do("GET", url, nil, &resp); err != nil {
		return nil, err
	}

	indexes := make(map[string]uint32, len(resp.Statistics))
	for _, row := range resp.Statistics {
		m := linkNetwork.FindStringSubmatch(row.Network)
		if m == nil || row.Name == "" {
			continue // a per-address row, or a row shape we do not model
		}
		var idx uint32
		if _, err := fmt.Sscanf(m[1], "%d", &idx); err != nil || idx == 0 {
			continue // index 0 is not a kernel index; ifmib rows start at 1
		}
		// A device appearing twice with DIFFERENT indices means the response is
		// internally inconsistent and nothing derived from it can be trusted.
		if prev, dup := indexes[row.Name]; dup && prev != idx {
			return nil, &APICallError{
				Endpoint:   string(url),
				Message:    fmt.Sprintf("device %q reported with two kernel indexes (%d and %d)", row.Name, prev, idx),
				StatusCode: 0,
			}
		}
		indexes[row.Name] = idx
	}

	if len(indexes) == 0 {
		return nil, &APICallError{
			Endpoint:   string(url),
			Message:    "no interface carried a <Link#N> row; the netstat response shape has changed",
			StatusCode: 0,
		}
	}
	return indexes, nil
}
