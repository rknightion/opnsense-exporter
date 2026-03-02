package opnsense

import (
	"strconv"
	"strings"
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

// --- Public return structs ---

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
	var resp map[string]netflowCacheEntry
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
