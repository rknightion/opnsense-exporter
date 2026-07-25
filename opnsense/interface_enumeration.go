package opnsense

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// interfaceConfigEntry is one device's entry in
// api/diagnostics/interface/get_interface_config. The endpoint serves a
// top-level JSON object keyed by device name, so this is the value type, not
// the response type.
//
// It exists for the schema registry and the live-box canary only: the
// enumeration fetch below deliberately never decodes into it (see
// FetchInterfaceEnumeration for why). The field set mirrors
// legacy_interfaces_details() in OPNsense core's src/etc/inc/interfaces.lib.inc,
// which is the same producer that feeds interfaces_info — hence the shared
// interfaceAddressRaw address element type.
type interfaceConfigEntry struct {
	Device string `json:"device"`

	Flags        []string `json:"flags"`
	Capabilities []string `json:"capabilities"`
	Options      []string `json:"options"`

	// ND6 is the nd6 options block, and it is an OBJECT wrapping the flag list,
	// not the bare list this originally modelled: legacy_interfaces_details()
	// builds it as ["flags" => explode(",", ...)] — identical on master,
	// stable/26.7, stable/26.1 and stable/25.7, so no release has ever served
	// the flat shape (#371). Absent entirely on rows ifconfig prints no "nd6
	// options=" line for (pflog0, pfsync0).
	ND6 interfaceND6 `json:"nd6"`

	MACAddr   string `json:"macaddr"`
	MACAddrHW string `json:"macaddr_hw"`

	// Configured addresses, in the same CIDR-carrying shape interfaces_info
	// uses ("ipaddr": "10.0.0.114/24"); an interface with no address of a
	// family omits the key entirely.
	IPv4 []interfaceAddressRaw `json:"ipv4"`
	IPv6 []interfaceAddressRaw `json:"ipv6"`

	SupportedMedia []string `json:"supported_media"`
	Media          string   `json:"media"`
	MediaRaw       string   `json:"media_raw"`
	Status         string   `json:"status"`
	IsPhysical     bool     `json:"is_physical"`

	// MTU is json.Number rather than string: 26.7 retyped a batch of counters
	// from quoted strings to bare JSON numbers, and json.Number decodes both,
	// so the canary accepts either shape instead of reporting a representation
	// change as drift.
	MTU json.Number `json:"mtu"`

	// SFP is the transceiver block, a plain string map because OPNsense emits
	// dynamic per-lane DOM keys ("lane_1_rx_power", ...) alongside the fixed
	// identity keys; flexStringMap additionally tolerates the PHP-side empty
	// map serialized as [].
	SFP flexStringMap `json:"sfp"`
}

// interfaceND6 is one device's nd6(4) options, as ifconfig prints them and
// legacy_interfaces_details() wraps them.
type interfaceND6 struct {
	Flags []string `json:"flags"`
}

// interfaceConfigResponse is the top-level shape of get_interface_config: an
// object keyed by device name. It describes SHAPE for the schema registry and
// the live canary. It is NOT how the fetch decodes the payload — a Go map
// cannot carry key order, and key order is the entire point of this endpoint.
type interfaceConfigResponse map[string]interfaceConfigEntry

// FetchInterfaceEnumeration returns the box's interface devices in ifinfo
// order: element i is ifIndex i+1.
//
// Why this endpoint, and why the order is load-bearing (#361): OPNsense's
// NetFlow ifIndex is not an identifier the kernel stores anywhere. It is a
// 1-based POSITION over the device list printed by /usr/local/sbin/ifinfo, and
// two independent upstream implementations agree on that — the netgraph hook
// names in /usr/local/etc/rc.d/netflow come from a shell counter over that
// list, and /usr/local/opnsense/scripts/netflow/lib/parse.py resolves an index
// with enumerate(re.findall(r"Interface ([^ ]+)", out), start=1). So the only
// way to translate a flow record's ifIndex back to a device is to reproduce
// that list, in that order.
//
// api/interfaces/overview/interfaces_info is the wrong source and was the
// original bug: it omits pfsync0 (15 rows where the kernel has 16 on the
// reference box), which shifts every index from 10 upward by one and mislabels
// the large majority of flow volume. get_interface_config returns all 16
// devices in exactly ifinfo/`ifconfig -l` order, pfsync0 included.
//
// THE DECODE IS DELIBERATELY HAND-ROLLED. json.Unmarshal into a
// map[string]interfaceConfigEntry destroys the ordering: Go maps are unordered
// and range order is deliberately randomised, so a map-based version compiles,
// returns every device, and produces a different wrong answer on every process
// start — a silent, non-deterministic mislabelling with no error anywhere. The
// body is therefore read as raw JSON and walked with a json.Decoder, taking
// keys in wire order and discarding each value wholesale.
func (c *Client) FetchInterfaceEnumeration() ([]string, *APICallError) {
	url, ok := c.endpoints["interfaceConfig"]
	if !ok {
		return nil, &APICallError{
			Endpoint:   "interfaceConfig",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var raw json.RawMessage
	if err := c.do("GET", url, nil, &raw); err != nil {
		return nil, err
	}

	devices, perr := parseInterfaceEnumeration(raw)
	if perr != nil {
		return nil, &APICallError{
			Endpoint:   string(url),
			Message:    perr.Error(),
			StatusCode: 0,
		}
	}
	return devices, nil
}

// parseInterfaceEnumeration walks a get_interface_config body and returns its
// top-level keys in wire order.
//
// Every failure mode here returns an error instead of a partial list on
// purpose. A short or reordered enumeration does not look broken downstream —
// it looks like a perfectly plausible device list that labels flow records with
// the wrong interface. An absent enumeration is recoverable (the collector
// emits nothing); a confidently wrong one is not.
func parseInterfaceEnumeration(raw json.RawMessage) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))

	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to read interface config body: %w", err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, fmt.Errorf("interface config body is not a JSON object (got %v)", tok)
	}

	var devices []string
	seen := make(map[string]struct{})

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("failed to read interface config key: %w", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			// Unreachable for well-formed JSON (object keys are always
			// strings); guarded rather than type-asserted so a decoder change
			// can never panic a scrape.
			return nil, fmt.Errorf("interface config key is not a string (got %v)", keyTok)
		}

		// The value is read and thrown away — but it MUST be read, or the
		// decoder's next Token() would return a token from inside the value
		// instead of the next device key. Decoding into json.RawMessage
		// consumes an arbitrarily nested value in one step without caring what
		// shape it is (object, null, anything a future release adds).
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return nil, fmt.Errorf("failed to read interface config value for %q: %w", key, err)
		}

		// A zero-length key cannot be a real device: ifinfo prints a name for
		// every line it emits. Giving it a slot would insert a phantom index
		// and shift every real device after it, which is the exact failure this
		// endpoint was adopted to fix — so drop it rather than count it.
		if key == "" {
			continue
		}

		// A repeated key means the list no longer maps 1:1 onto ifinfo
		// positions. Counting the device twice would silently shift everything
		// after it, and picking one occurrence would be a guess about which
		// slot is real, so report instead.
		if _, dup := seen[key]; dup {
			return nil, fmt.Errorf("duplicate device %q in interface config: enumeration cannot be trusted", key)
		}
		seen[key] = struct{}{}
		devices = append(devices, key)
	}

	// Consume the closing brace so a truncated body (which leaves the stream
	// mid-object) is reported rather than silently yielding a short list.
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("failed to read end of interface config body: %w", err)
	}

	return devices, nil
}
