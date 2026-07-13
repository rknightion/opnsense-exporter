package opnsense

import (
	"net/http"
	"time"
)

// hostDiscoveryRow mirrors one row of api/hostdiscovery/service/search's
// response: one row per (interface, MAC, IP) tuple the core hostwatch daemon
// has ever seen (or, when hostwatch is disabled, one row per live ARP/NDP
// entry -- see Source below). Verified against a live OPNsense 26.7 devel box
// with hostwatch enabled and disabled (#223).
type hostDiscoveryRow struct {
	// Source is "discovery" when the hostwatch daemon is enabled -- backed by
	// a persistent sqlite inventory that survives reboots and cache expiry,
	// unlike the live arp/ndp tables the arp_table/ndp collectors scrape -- or
	// "arp-ndp" when it is disabled, a fallback that reads the live ARP/NDP
	// tables directly and therefore duplicates arp_table/ndp. FirstSeen and
	// LastSeen are empty strings (not omitted, not null) in "arp-ndp" mode
	// since that path has no persistent history to report.
	Source           string  `json:"source"`
	InterfaceName    string  `json:"interface_name"`
	EtherAddress     string  `json:"ether_address"`
	IPAddress        string  `json:"ip_address"`
	OrganizationName *string `json:"organization_name"`
	FirstSeen        string  `json:"first_seen"`
	LastSeen         string  `json:"last_seen"`
}

// hostDiscoverySearchResponse is the search-grid envelope api/hostdiscovery/service/search
// returns; Total/RowCount/Current are decoded for schema fidelity but unused --
// the endpoint returns every known host in a single page (verified live, #223).
type hostDiscoverySearchResponse struct {
	Total    int                `json:"total"`
	RowCount int                `json:"rowCount"`
	Current  int                `json:"current"`
	Rows     []hostDiscoveryRow `json:"rows"`
}

// HostDiscoveryGroup is the aggregated host count for one interface+source
// pair. This is deliberately the finest grain exposed: per-host MAC/IP/hostname
// labels would be unbounded cardinality (#223), so only bounded
// interface x source groups are counted. Source is folded in (rather than
// dropped) so the "arp-ndp" fallback rows -- which duplicate the arp_table/ndp
// collectors -- are visible as their own series rather than silently merged
// into the "discovery" counts or dropped outright.
type HostDiscoveryGroup struct {
	Interface string
	Source    string
	// Hosts is the total number of host entries in this interface+source group.
	Hosts int
	// RecentHosts is the subset of Hosts whose last_seen falls within
	// hostDiscoveryRecentWindow of the fetch time. Rows with an empty or
	// unparseable LastSeen (always true for "arp-ndp" rows) never count as
	// recent, since there is no timestamp to judge recency from.
	RecentHosts int
}

// HostDiscoveryInventory holds the aggregated result of FetchHostDiscovery.
type HostDiscoveryInventory struct {
	Groups []HostDiscoveryGroup
}

// hostDiscoveryRecentWindow is the client-side recency threshold behind the
// opnsense_hostdiscovery_hosts_recent gauge (#223).
const hostDiscoveryRecentWindow = 15 * time.Minute

// FetchHostDiscovery calls the core hostwatch inventory endpoint
// (api/hostdiscovery/service/search) and aggregates its rows into per
// interface+source host counts.
//
// This is a CORE OPNsense endpoint (Interfaces > Host discovery, added to
// OPNsense in 2025), not a plugin -- so, per CLAUDE.md's PluginGatedEndpoints
// rule, it is deliberately NOT added there. A 404 here is still treated as
// "feature absent" (empty data, nil error) the same way FetchACMECertificates
// treats a missing plugin, as defensive handling for firewalls older than the
// exporter's support window (current + previous stable), but it is never
// negative-cached: PluginGatedEndpoints exists for plugin installs, which can
// toggle at runtime, whereas an OPNsense version cannot.
//
// Never emits per-host series: ether_address/ip_address (and the free-text
// organization_name OUI vendor) are unbounded cardinality and are decoded
// only for schema fidelity, never surfaced as labels or otherwise used.
func (c *Client) FetchHostDiscovery() (HostDiscoveryInventory, *APICallError) {
	var resp hostDiscoverySearchResponse
	var data HostDiscoveryInventory

	path, ok := c.endpoints["hostdiscoverySearch"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "hostdiscoverySearch",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", path, nil, &resp); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil
		}
		return data, err
	}

	type groupKey struct {
		iface  string
		source string
	}
	index := map[groupKey]int{}
	now := time.Now()

	for _, row := range resp.Rows {
		k := groupKey{row.InterfaceName, row.Source}
		i, ok := index[k]
		if !ok {
			data.Groups = append(data.Groups, HostDiscoveryGroup{
				Interface: row.InterfaceName,
				Source:    row.Source,
			})
			i = len(data.Groups) - 1
			index[k] = i
		}
		data.Groups[i].Hosts++

		if row.LastSeen == "" {
			continue
		}
		ts, perr := time.Parse(time.RFC3339, row.LastSeen)
		if perr != nil {
			continue
		}
		if now.Sub(ts) <= hostDiscoveryRecentWindow {
			data.Groups[i].RecentHosts++
		}
	}

	return data, nil
}
