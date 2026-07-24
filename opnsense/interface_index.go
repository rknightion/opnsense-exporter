package opnsense

import (
	"fmt"
	"regexp"
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
