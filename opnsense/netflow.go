package opnsense

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// --- Private response structs for JSON unmarshaling ---

type netflowIsEnabledResponse struct {
	Netflow int `json:"netflow"`
	Local   int `json:"local"`
}

type netflowStatusResponse struct {
	Status     string `json:"status"`
	Collectors string `json:"collectors"`
}

type netflowCacheEntry struct {
	Pkts           int    `json:"Pkts"`
	Interface      string `json:"if"`
	SrcIPAddresses int    `json:"SrcIPaddresses"`
	DstIPAddresses int    `json:"DstIPaddresses"`
}

// netflowCacheEntryMap decodes the whole api/diagnostics/netflow/cacheStats
// body. PHP builds it as an associative array keyed by netgraph node name, so
// json_encode renders it as a JSON object ({...}) when the cache holds
// anything but as an empty JSON array ([]) when it does not — a box that has
// just started capturing, or one carrying no traffic. A plain map field cannot
// unmarshal "[]", which failed the whole fetch and killed the collector rather
// than reporting an empty cache (#499). Captured live on OPNsense 27.1.a_40.
//
// Same PHP empty-map-vs-empty-array shape as firewallRuleStatMap, and treated
// the same way: a NON-empty array is an error, not something to absorb. Cache
// entries are always keyed by node name (netflow_igb0, ksocket_netflow_igb0),
// never by sequential index, so upstream has no encoding path that produces a
// populated array here — one would be genuine drift and must surface as such.
type netflowCacheEntryMap map[string]netflowCacheEntry

// UnmarshalJSON implements json.Unmarshaler.
func (m *netflowCacheEntryMap) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		*m = nil
		return nil
	}
	if trimmed[0] == '[' {
		var arr []json.RawMessage
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return fmt.Errorf("netflowCacheEntryMap array: %w", err)
		}
		if len(arr) > 0 {
			return fmt.Errorf("netflowCacheEntryMap: unexpected non-empty array with %d elements", len(arr))
		}
		*m = nil
		return nil
	}
	var raw map[string]netflowCacheEntry
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return fmt.Errorf("netflowCacheEntryMap object: %w", err)
	}
	*m = raw
	return nil
}

// netflowSelectOption is one entry of an OPNsense "field with options" map. The
// key is the interface IDENT (opt7, lan); value is the descriptive name (AAISP),
// which is what every flow metric carries as its interface label.
type netflowSelectOption struct {
	Value    string  `json:"value"`
	Selected flexInt `json:"selected"`
}

// netflowGetConfigResponse decodes api/diagnostics/netflow/getconfig, which is
// $mdlNetflow->getNodes() - the stored Netflow model straight out of config.xml,
// with no live state in it at all.
//
// The serialization is NOT uniform, and a struct that assumes it is will not
// decode this: InterfaceField and OptionField members (interfaces, egress_only,
// version, targets) come back as {value,selected} option-dict maps, while
// collect.enable is a BooleanField and comes back as a BARE STRING. The two
// timeouts are strings rather than JSON numbers. Verified against a live
// OPNsense 26.7.1 on 2026-07-24.
//
// egress_only, version, targets and collect are deliberately not modelled: only
// the capture set and the timeouts are consumed.
type netflowGetConfigResponse struct {
	Netflow struct {
		Capture struct {
			Interfaces map[string]netflowSelectOption `json:"interfaces"`
		} `json:"capture"`
		ActiveTimeout   flexInt `json:"activeTimeout"`
		InactiveTimeout flexInt `json:"inactiveTimeout"`
	} `json:"netflow"`
}

// --- Public return structs ---

// NetflowCaptureConfig is the box's configured NetFlow capture set: which
// interfaces it has been told to capture on, and the flow timeouts it applies.
//
// It answers "what SHOULD be exporting", which is the half of the picture no
// counter can supply - an interface producing nothing is indistinguishable from
// an idle one unless you know it was supposed to be producing something.
type NetflowCaptureConfig struct {
	// Interfaces maps the DESCRIPTIVE interface name (AAISP, LAN) to whether it is
	// selected for capture. Keyed by descriptive name rather than by ident because
	// the descriptive name is the interface label on every flow metric, so this is
	// the only key the two can be joined on.
	Interfaces map[string]bool
	// ActiveTimeout is how long a long-running flow may sit in the cache before
	// ng_netflow exports it anyway; InactiveTimeout is how long an idle flow waits.
	// Both are the box's own configured values, exported so an operator derives a
	// "this interface has gone quiet" threshold from them instead of guessing.
	ActiveTimeout   time.Duration
	InactiveTimeout time.Duration
}

// NetflowEnabled holds the enabled state of netflow services.
type NetflowEnabled struct {
	Netflow bool
	Local   bool
}

// NetflowStatus holds the current netflow service status.
type NetflowStatus struct {
	Active     bool
	Collectors int
}

// NetflowCacheStats holds per-interface netflow cache statistics.
type NetflowCacheStats struct {
	Interface      string
	Packets        int
	SrcIPAddresses int
	DstIPAddresses int
}

// FetchNetflowIsEnabled retrieves the netflow enabled status from OPNsense.
func (c *Client) FetchNetflowIsEnabled() (NetflowEnabled, *APICallError) {
	var resp netflowIsEnabledResponse
	var data NetflowEnabled

	url, ok := c.endpoints["netflowIsEnabled"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "netflowIsEnabled",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	data.Netflow = resp.Netflow == 1
	data.Local = resp.Local == 1

	return data, nil
}

// FetchNetflowStatus retrieves the netflow service status from OPNsense.
func (c *Client) FetchNetflowStatus() (NetflowStatus, *APICallError) {
	var resp netflowStatusResponse
	var data NetflowStatus

	url, ok := c.endpoints["netflowStatus"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "netflowStatus",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	data.Active = resp.Status == "active"
	if n, parseErr := strconv.Atoi(resp.Collectors); parseErr == nil {
		data.Collectors = n
	}

	return data, nil
}

// FetchNetflowCacheStats retrieves netflow cache statistics from OPNsense.
// Only entries with the "netflow_" prefix are returned; "ksocket_" entries
// (export sockets with typically zero values) are filtered out.
func (c *Client) FetchNetflowCacheStats() ([]NetflowCacheStats, *APICallError) {
	var resp netflowCacheEntryMap
	var data []NetflowCacheStats

	url, ok := c.endpoints["netflowCacheStats"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "netflowCacheStats",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	for key, entry := range resp {
		if !strings.HasPrefix(key, "netflow_") {
			continue
		}
		data = append(data, NetflowCacheStats{
			Interface:      entry.Interface,
			Packets:        entry.Pkts,
			SrcIPAddresses: entry.SrcIPAddresses,
			DstIPAddresses: entry.DstIPAddresses,
		})
	}

	return data, nil
}

// FetchNetflowCaptureConfig retrieves the configured NetFlow capture set.
//
// The endpoint is core Diagnostics, not plugin-gated, and answers 200 even on a
// box where netflow was never configured - the InterfaceField enumerates every
// interface regardless, all with selected=0. That is a legitimate answer meaning
// "nothing is expected to export", so it is returned as such rather than treated
// as an error or as an absent feature.
func (c *Client) FetchNetflowCaptureConfig() (NetflowCaptureConfig, *APICallError) {
	var resp netflowGetConfigResponse
	data := NetflowCaptureConfig{Interfaces: map[string]bool{}}

	url, ok := c.endpoints["netflowGetConfig"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "netflowGetConfig",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	for _, opt := range resp.Netflow.Capture.Interfaces {
		// An entry with no descriptive name cannot be joined to anything, so it is
		// skipped rather than emitted under an empty label.
		if opt.Value == "" {
			continue
		}
		data.Interfaces[opt.Value] = opt.Selected.Int() == 1
	}
	data.ActiveTimeout = time.Duration(resp.Netflow.ActiveTimeout.Int()) * time.Second
	data.InactiveTimeout = time.Duration(resp.Netflow.InactiveTimeout.Int()) * time.Second

	return data, nil
}
