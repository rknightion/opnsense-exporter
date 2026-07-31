package opnsense

import (
	"strings"
	"time"
)

type FirewallPFStat struct {
	InterfaceName string `json:"interface,omitempty"` // We will populate this field with the key of the map
	References    int    `json:"references"`

	// Skipped is derived from the map key, not a wire field: pfctl appends a
	// literal " (skip)" suffix to any device with pf "skip on interface" enabled.
	// The suffix is stripped out of InterfaceName so toggling the pf option does
	// not rename the series (#105), but the state itself is real information —
	// pf is not filtering that interface at all — so it is carried here rather
	// than discarded (#542). No json tag: the API never sends this key, and
	// tagging it would add a phantom path to the reflected golden schema.
	Skipped bool `json:"-"`

	// ClearedRaw is the wire value of pf's own "counters reset at" timestamp for
	// this interface — the `Cleared:` line of `pfctl -vvsInterfaces` (the same
	// instant `pfctl -z`/a filter reload zeroes every pass/block counter below).
	// OPNsense's configd script passes it through as a NAIVE (no timezone marker
	// at all, not even an abbreviation) ISO-8601 string:
	//   datetime.datetime.strptime(line, "%b %d %H:%M:%S %Y").isoformat()
	// (opnsense/core src/opnsense/scripts/filter/pfstatistics.py, pfctl_interfaces()
	// — verified against upstream source 2026-07-31, since a wire-format guess here
	// would be exactly the kind of unverified assumption #284 warns against).
	// Never read this field directly: ClearedUnixSeconds below is the presence-gated,
	// parsed form the collector actually emits.
	ClearedRaw flexString `json:"cleared"`

	// ClearedTimestamp/HasClearedTimestamp are computed from ClearedRaw by
	// FetchPFStatsByInterface via ClearedUnixSeconds. HasClearedTimestamp is
	// false for an absent/empty value or one that fails to parse — the
	// collector must skip the metric rather than emit epoch 0, which would
	// misreport a healthy interface's counter history as reset at 1970 (mirrors
	// GeoIPStatus.HasLastUpdateTimestamp in firewall_geoip.go). No json tag:
	// these are derived, not wire fields.
	ClearedTimestamp    float64 `json:"-"`
	HasClearedTimestamp bool    `json:"-"`

	// int64 so large byte/packet counters (>2^31) unmarshal correctly on 32-bit
	// source builds instead of failing the whole fetch (#103).
	In4PassPackets   int64 `json:"in4_pass_packets"`
	In4BlockPackets  int64 `json:"in4_block_packets"`
	Out4PassPackets  int64 `json:"out4_pass_packets"`
	Out4BlockPackets int64 `json:"out4_block_packets"`

	In6PassPackets   int64 `json:"in6_pass_packets"`
	In6BlockPackets  int64 `json:"in6_block_packets"`
	Out6PassPackets  int64 `json:"out6_pass_packets"`
	Out6BlockPackets int64 `json:"out6_block_packets"`

	In4PassBytes   int64 `json:"in4_pass_bytes"`
	In4BlockBytes  int64 `json:"in4_block_bytes"`
	Out4PassBytes  int64 `json:"out4_pass_bytes"`
	Out4BlockBytes int64 `json:"out4_block_bytes"`

	In6PassBytes   int64 `json:"in6_pass_bytes"`
	In6BlockBytes  int64 `json:"in6_block_bytes"`
	Out6PassBytes  int64 `json:"out6_pass_bytes"`
	Out6BlockBytes int64 `json:"out6_block_bytes"`
}

// firewallPFStatsResponse is the struct returned by the OPNsense API
// when requesting the firewwall statistics by interface. The response is weird json
// that have the interface name as key and the FirewallPFStats struct as value
type firewallPFStatsResponse struct {
	Interface map[string]FirewallPFStat `json:"interfaces"`
}

type FirewallPFStats struct {
	Interfaces []FirewallPFStat
}

func (c *Client) FetchPFStatsByInterface() (FirewallPFStats, *APICallError) {
	var resp firewallPFStatsResponse
	var data FirewallPFStats

	url, ok := c.endpoints["pfStatisticsByInterface"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "pfStatisticsByInterface",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	err := c.do("GET", url, nil, &resp)
	if err != nil {
		return data, err
	}

	for k, v := range resp.Interface {
		// The pfctl-derived interfaces map mixes real devices with the "all"
		// aggregate row and pf interface-group rows (enc, lo, pflog, pfsync, tun,
		// vlan, and custom groups like "zenvpngroup"), and appends a literal
		// " (skip)" suffix to any device with pf "skip on interface" enabled.
		// Strip the mutable skip suffix (so toggling it doesn't rename the series)
		// and keep only real network devices, so the interface label is stable and
		// a naive sum can't double-count aggregate/group rows against members (#105).
		name := stripPFSkipSuffix(k)
		if !isPFDeviceName(name) {
			continue
		}
		v.InterfaceName = name
		v.Skipped = name != k
		if ts, ok := v.ClearedUnixSeconds(); ok {
			v.ClearedTimestamp = ts
			v.HasClearedTimestamp = true
		}
		data.Interfaces = append(data.Interfaces, v)
	}
	return data, nil
}

// pfClearedTimestampLayout is the Go reference-time layout matching
// pfstatistics.py's `datetime.datetime.strptime(line, "%b %d %H:%M:%S %Y").isoformat()`
// output: whole seconds only (the strptime format string has no %f), and — unlike
// the abbreviation-only timestamps handled in system_resources.go — NO timezone
// marker whatsoever, because Python's datetime.isoformat() omits the offset
// entirely for a naive (tzinfo-less) datetime.
const pfClearedTimestampLayout = "2006-01-02T15:04:05"

// ClearedUnixSeconds parses ClearedRaw (pf's own per-interface "counters reset
// at" timestamp) into Unix seconds. ok is false for an empty/absent value or a
// shape that fails to parse — the caller must skip the metric rather than
// fabricate epoch 0, which would misreport a healthy interface's counter
// history as reset at 1970.
//
// pfctl formats "Cleared:" from the box's local wall clock (ctime()-style,
// see pfctl(8)/pf source), and the isoformat() pass-through above carries no
// offset at all — not even an abbreviation like the "BST"/"GMT" strings
// system_resources.go already has to correct for. There is therefore no
// offset to recover from the string itself, so — mirroring
// parseGeoIPTimestamp in firewall_geoip.go, which faces the identical
// ambiguity for geoip.py's naive timestamps — this decodes deterministically
// as UTC. The result can be off by the firewall's real UTC offset; that is
// acceptable here because the metric's job is "did a reset happen" (a step
// change, or a value newer than a rate() window), not a to-the-minute clock.
func (v FirewallPFStat) ClearedUnixSeconds() (float64, bool) {
	s := strings.TrimSpace(v.ClearedRaw.String())
	if s == "" {
		return 0, false
	}
	t, err := time.ParseInLocation(pfClearedTimestampLayout, s, time.UTC)
	if err != nil {
		return 0, false
	}
	return float64(t.Unix()), true
}

// stripPFSkipSuffix removes the literal " (skip)" that pfctl appends to a device
// name when "skip on interface" is enabled, so the interface label does not
// change when that pf option is toggled (#105).
func stripPFSkipSuffix(name string) string {
	return strings.TrimSuffix(name, " (skip)")
}

// isPFDeviceName reports whether a pfctl interfaces-map key names a real network
// device rather than the "all" aggregate or a pf interface group. FreeBSD network
// interfaces are always "<driver><unit>" and end in a digit (igb0, lo0, pppoe0,
// tailscale0, vlan sub-interfaces, …); the "all" row and pf groups (enc, lo,
// pflog, pfsync, tun, vlan, custom groups) are bare names with no unit number.
func isPFDeviceName(name string) bool {
	if name == "" {
		return false
	}
	last := name[len(name)-1]
	return last >= '0' && last <= '9'
}

type firewallStatEntry struct {
	Label string `json:"label"`
	Value int    `json:"value"`
}

type FirewallInterfaceHit struct {
	Label string
	Value int
}

func (c *Client) FetchFirewallStats() ([]FirewallInterfaceHit, *APICallError) {
	var resp []firewallStatEntry

	url, ok := c.endpoints["firewallStats"]
	if !ok {
		return nil, &APICallError{
			Endpoint:   "firewallStats",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return nil, err
	}

	hits := make([]FirewallInterfaceHit, len(resp))
	for i, entry := range resp {
		hits[i] = FirewallInterfaceHit(entry)
	}
	return hits, nil
}
