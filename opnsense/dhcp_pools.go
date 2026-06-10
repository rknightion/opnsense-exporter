package opnsense

import (
	"math"
	"math/big"
	"net"
	"strings"
)

// ipRangeSize returns the number of addresses in the inclusive range
// [start, end]. ok is false when either address fails to parse or the range
// is inverted. Works for IPv4 and IPv6 (big.Int over the 16-byte form;
// returned as float64 since the result feeds a Prometheus gauge).
func ipRangeSize(start, end string) (float64, bool) {
	s := net.ParseIP(strings.TrimSpace(start))
	e := net.ParseIP(strings.TrimSpace(end))
	if s == nil || e == nil {
		return 0, false
	}
	si := new(big.Int).SetBytes(s.To16())
	ei := new(big.Int).SetBytes(e.To16())
	diff := new(big.Int).Sub(ei, si)
	if diff.Sign() < 0 {
		return 0, false
	}
	diff.Add(diff, big.NewInt(1))
	f, _ := new(big.Float).SetInt(diff).Float64()
	return f, true
}

// poolSpecSize returns the total number of addresses covered by a Kea pool
// specification. Entries are split on newlines AND commas — the multi-pool
// separator is unverified (the live box only has single pools), so both are
// accepted defensively. Each entry is either an inclusive range
// "start - end" (spaces optional) or a CIDR prefix "addr/len". CIDR is
// accepted because Kea allows prefix pool specs. Unparseable non-empty
// entries contribute 0 and are warn-logged so misparses are visible instead
// of silently shrinking the pool size.
//
// Client method (not a free function) purely for access to c.log.
func (c *Client) poolSpecSize(pools string) float64 {
	var total float64
	entries := strings.FieldsFunc(pools, func(r rune) bool {
		return r == '\n' || r == ','
	})
	for _, line := range entries {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "/") {
			_, ipnet, err := net.ParseCIDR(line)
			if err != nil {
				c.log.Warn("kea: unparseable CIDR pool entry; contributing 0", "entry", line, "err", err)
				continue
			}
			ones, bits := ipnet.Mask.Size()
			total += math.Pow(2, float64(bits-ones))
			continue
		}
		parts := strings.SplitN(line, "-", 2)
		if len(parts) != 2 {
			c.log.Warn("kea: unparseable pool entry (no range separator); contributing 0", "entry", line)
			continue
		}
		n, ok := ipRangeSize(parts[0], parts[1])
		if !ok {
			c.log.Warn("kea: unparseable or inverted pool range; contributing 0", "entry", line)
			continue
		}
		total += n
	}
	return total
}
