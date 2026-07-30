package opnsense

import (
	"net/http"
	"strings"
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
	// Manufacturer is the OUI vendor lookup of the MAC (organization_name),
	// canonicalized via organizationLabel: a small bounded set, matching the
	// `manufacturer` label #534 already ships on arp_table/ndp. A null
	// organization_name (an OUI the box could not resolve, e.g. a
	// randomized-MAC device) becomes the "unknown" sentinel rather than an
	// empty label.
	Manufacturer string
	// Hosts is the total number of host entries in this interface+source+manufacturer group.
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

// organizationLabel resolves a hostDiscoveryRow's organization_name to the
// `manufacturer` label value: a nil pointer (JSON null -- an OUI the box
// could not resolve) or an empty/whitespace-only string both collapse to the
// "unknown" sentinel, matching the convention used across the codebase
// (canonicalizeFirmwareCheckState, keaLeaseStateLabel, etc.) so this label is
// never emitted empty.
func organizationLabel(name *string) string {
	if name == nil {
		return "unknown"
	}
	trimmed := strings.TrimSpace(*name)
	if trimmed == "" {
		return "unknown"
	}
	return trimmed
}

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
// Never emits per-host series: ether_address and ip_address are one value per
// host, so they are decoded for schema fidelity and never surfaced as labels.
//
// organization_name is NOT in that category, and an earlier version of this
// comment was wrong to lump it in as "unbounded cardinality". It is the OUI
// vendor of the MAC — a small bounded set that #534 already ships as a
// `manufacturer` label on arp_table/ndp — and the global series budget is 100k
// against roughly 4.6k in use. It is exported here (#557) as an additional
// grouping dimension on the aggregate hosts/hosts_recent series, via
// organizationLabel().
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
		iface        string
		source       string
		manufacturer string
	}
	index := map[groupKey]int{}
	now := time.Now()

	for _, row := range resp.Rows {
		manufacturer := organizationLabel(row.OrganizationName)
		k := groupKey{row.InterfaceName, row.Source, manufacturer}
		i, ok := index[k]
		if !ok {
			data.Groups = append(data.Groups, HostDiscoveryGroup{
				Interface:    row.InterfaceName,
				Source:       row.Source,
				Manufacturer: manufacturer,
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
