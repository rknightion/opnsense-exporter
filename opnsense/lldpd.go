package opnsense

import (
	"net/http"
	"regexp"
	"strings"
)

// lldpdNeighborResponse mirrors the JSON envelope returned by
// api/lldpd/service/neighbor: a single "response" field carrying the raw text
// output of `lldpcli show neighbors` — the os-lldpd plugin's configd action
// shells out to lldpcli without `-f json`, so this is free text, not
// structured JSON (verified against a live OPNsense 26.1 box; see #216).
type lldpdNeighborResponse struct {
	Response string `json:"response"`
}

// LLDPNeighbor is one parsed neighbor block from `lldpcli show neighbors`.
// The fields used as metric labels are kept alongside the chassis MAC and
// management addresses, which are safe for bounded device-inventory records
// but remain excluded from metric labels. SysDescr, Capability, TTL, RID and
// Time stay deliberately unmodelled (#216).
type LLDPNeighbor struct {
	// Interface is the local interface device name (e.g. "ixl0"), taken from
	// the "Interface:" line before the first comma. The line also carries an
	// optional "alias: <description>" token — optional because some releases/
	// interfaces omit it entirely (#216) — which is not captured since it is
	// not used as a label.
	Interface string
	// ChassisName is the remote neighbor's SysName (e.g. the neighboring
	// switch's hostname).
	ChassisName string
	// PortID is the remote neighbor's PortID exactly as reported by lldpcli,
	// including its type prefix (e.g. "ifname ixl0", "local Port 1").
	PortID string
	// PortDescr is the remote neighbor's PortDescr.
	PortDescr string
	// ChassisMAC is the remote chassis MAC when lldpcli reports a MAC chassis
	// identifier. It is used to join LLDP with ARP/NDP and hostdiscovery; it is
	// never emitted as a metric label by the LLDP collector.
	ChassisMAC string
	// MgmtIPs contains every management address reported by the neighbor. LLDP
	// can emit more than one MgmtIP line (for example IPv4 and IPv6), so this is
	// a slice rather than a single last-write-wins value. It is not a metric
	// label.
	MgmtIPs []string
}

// LLDPNeighbors holds the aggregated result of FetchLLDPNeighbors.
type LLDPNeighbors struct {
	Present   bool // false when the os-lldpd plugin is not installed (HTTP 404)
	Neighbors []LLDPNeighbor
}

var (
	// lldpSeparatorRegex matches the "----...----" divider lines lldpcli prints
	// before the header, between neighbor blocks, and after the last one.
	lldpSeparatorRegex = regexp.MustCompile(`^-{5,}$`)

	// lldpInterfaceRegex captures the local interface device name from a line
	// like "Interface:    ixl0, alias: LAN (lan), via: LLDP, RID: 1, Time: ...".
	// The alias token (and everything after it) is optional and not captured:
	// the device name always appears first, immediately before the first comma.
	lldpInterfaceRegex = regexp.MustCompile(`^Interface:\s*(\S+?)\s*,`)
)

// FetchLLDPNeighbors calls the lldpd neighbor endpoint and parses the raw
// lldpcli text response into a slice of neighbor structs.
//
// If the os-lldpd plugin is not installed the endpoint returns HTTP 404
// (verified against a live OPNsense 26.1 box). That is treated as "feature
// absent" — empty data with no error — mirroring FetchACMECertificates.
//
// The payload is free-text lldpcli output, not a versioned structured API, so
// the parser is deliberately lenient: a block it cannot make sense of is
// skipped (with a warning log), never failing the whole fetch.
func (c *Client) FetchLLDPNeighbors() (LLDPNeighbors, *APICallError) {
	var resp lldpdNeighborResponse
	var data LLDPNeighbors

	url, ok := c.endpoints["lldpdNeighbors"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "lldpdNeighbors",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil
		}
		return data, err
	}

	data.Present = true
	data.Neighbors = c.parseLLDPNeighbors(resp.Response)

	return data, nil
}

// parseLLDPNeighbors splits lldpcli's `show neighbors` text output into
// per-neighbor blocks — delimited by "----" separator lines — and parses each
// block independently. A block that yields no usable Interface: line is
// skipped with a warning; every other field simply defaults to empty string
// when absent, so a partial/malformed block never fails the parse outright.
func (c *Client) parseLLDPNeighbors(text string) []LLDPNeighbor {
	var neighbors []LLDPNeighbor
	var block []string

	flush := func() {
		if len(block) == 0 {
			return
		}
		if n, ok := parseLLDPBlock(block); ok {
			neighbors = append(neighbors, n)
		} else {
			c.log.Warn("lldpd: skipping unparseable neighbor block (no Interface: line found)",
				"lines", len(block))
		}
		block = nil
	}

	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
			continue
		case lldpSeparatorRegex.MatchString(trimmed):
			flush()
		case trimmed == "LLDP neighbors:":
			// Header line, printed once right after the first separator.
			continue
		default:
			block = append(block, trimmed)
		}
	}
	flush()

	return neighbors
}

// parseLLDPBlock parses the already-trimmed lines of a single neighbor block
// (separator lines removed). ok is false when no Interface: line was found,
// meaning the block was not a real neighbor entry.
func parseLLDPBlock(lines []string) (LLDPNeighbor, bool) {
	var n LLDPNeighbor
	found := false

	for _, line := range lines {
		if matches := lldpInterfaceRegex.FindStringSubmatch(line); matches != nil {
			n.Interface = matches[1]
			found = true
			continue
		}

		key, value, ok := splitLLDPField(line)
		if !ok {
			continue
		}
		switch key {
		case "ChassisID":
			// lldpcli's MAC form is "mac <address>". Other chassis-id
			// forms (local, chassis-component, ...) are intentionally not
			// guessed into a MAC.
			if strings.HasPrefix(strings.ToLower(value), "mac ") {
				n.ChassisMAC = strings.TrimSpace(value[len("mac "):])
			}
		case "SysName":
			n.ChassisName = value
		case "MgmtIP":
			n.MgmtIPs = append(n.MgmtIPs, value)
		case "PortID":
			n.PortID = value
		case "PortDescr":
			n.PortDescr = value
		}
	}

	return n, found
}

// splitLLDPField splits a "Key:    value" line (arbitrary whitespace around
// the colon) into its key and value. Header-only lines with nothing after the
// colon (e.g. "Chassis:", "Port:") return ok=false so callers skip them.
func splitLLDPField(line string) (key, value string, ok bool) {
	idx := strings.Index(line, ":")
	if idx < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:idx])
	value = strings.TrimSpace(line[idx+1:])
	if value == "" {
		return "", "", false
	}
	return key, value, true
}
