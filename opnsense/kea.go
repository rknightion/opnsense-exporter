package opnsense

import (
	"github.com/rknightion/opnsense-exporter/internal/fetchshare"
	"math"
	"net"
	"strings"
)

// keaLeaseStats mirrors the top-level `stats` object OPNsense computes over
// the FULL lease population before the bootgrid search endpoint pages the
// `rows` array — so, unlike a count derived from `rows`, it is never
// truncated by the page size. Confirmed live on OPNsense 26.7 and 26.1.11
// (issue #208 dev-box comment, captured 2026-07-13): shape
// stats:{active,inactive,total}, all JSON numbers. "active" is lease state 0;
// "inactive" is every non-zero state combined (declined + expired-reclaimed
// are not split out here — only the per-row `state` field distinguishes
// them; see keaLeaseStateLabel). The 3-way active/declined/expired-reclaimed
// split (opnsense_kea_dhcp{4,6}_leases_by_state) still comes from the
// per-row `state` field, since that is the only source for it. This block
// is ALSO exported directly (#557) as opnsense_kea_dhcp{4,6}_lease_pool_stats:
// it is Kea's own accounting computed over the full lease population before
// the bootgrid search paginates `rows`, so unlike a row-derived count it is
// authoritative and never truncated by the page size.
type keaLeaseStats struct {
	Active   flexInt `json:"active"`
	Inactive flexInt `json:"inactive"`
	Total    flexInt `json:"total"`
}

// keaLeaseRow mirrors one row of api/kea/leases{4,6}/search. `type` and
// `state` come straight from Kea's own lease4-get-all/lease6-get-all
// response via get_kea_leases.py: `type` is only meaningful for DHCPv6
// (Kea's IA_NA/IA_PD lease-type enum stringified; DHCPv4 leases carry
// type:"" since Kea has no lease-type concept there), and `state` is Kea's
// raw lease-state integer (0=default/active, 1=declined,
// 2=expired-reclaimed). Unverified against a live box with non-zero leases
// at the time of writing (issue #208: dev box had 0 leases) — kept
// tolerant/parse-only per the issue body.
// 2=expired-reclaimed). CONFIRMED on a real DHCPv4 lease (dev-box capture,
// 2026-07-13, issue #208: captures/kea/leases4_search_with_data.json) —
// type:"" and state:0 (JSON number) on a live active lease, plus the
// top-level `stats`/`interfaces` siblings (see keaLeaseResponse). Still
// unverified: a live DHCPv6 lease row showing the actual "IA_NA"/"IA_PD"
// string values — the dev box's only IPv6-capable-client attempt hit a
// host/LXC-level IPv6 kernel gap, so kept tolerant/parse-only for `type` on
// v6 per the issue body.
type keaLeaseRow struct {
	Address    string     `json:"address"`
	HWAddr     string     `json:"hwaddr"`
	Hostname   string     `json:"hostname"`
	Expire     flexInt    `json:"expire"`
	IfDescr    string     `json:"if_descr"`
	IsReserved flexBool   `json:"is_reserved"`
	Type       flexString `json:"type"`
	State      flexInt    `json:"state"`
	// MacInfo is PHP-side enrichment (LeasesController.php): an offline IEEE
	// OUI lookup of the first three hwaddr octets against the OPNsense
	// macdb, run identically for both endpoints. It is a vendor-NAME string
	// ("Apple, Inc."), empty whenever the OUI is unknown (common with MAC
	// randomisation) — not derivable from hwaddr without shipping that DB.
	MacInfo string `json:"mac_info"`
	// ClientID is Kea's own raw `client-id` lease field
	// (get_kea_leases.py:151, `lease.get("client-id", "")`) — genuine DHCPv4
	// option 61. Kea's lease6-get-all response carries no "client-id" key at
	// all (DHCPv6 identifies clients by DUID instead), so on v6 rows this is
	// permanently "" — confirmed against upstream source, not just untested.
	ClientID string `json:"client_id"`
	// ValidLifetime is Kea's `valid-lft` (granted lease duration in
	// seconds), populated identically for both endpoints. It is NOT
	// derivable from the already-modeled Expire: Expire = cltt + valid-lft
	// and cltt is never exposed, so the sum cannot be reversed.
	ValidLifetime flexInt `json:"valid_lifetime"`
	// PrefixLen is the delegated prefix's block size for a DHCPv6 IA_PD
	// (prefix-delegation) lease -- e.g. 56 for a /56 delegation. Meaningful
	// ONLY on keaLeases6: get_kea_leases.py's shared row-builder emits this
	// key unconditionally on both v4 and v6, but Kea's lease4-get-all has no
	// prefix-length concept at all, so on v4 rows this is permanently the
	// script's hardcoded default (128) rather than real data (#584,
	// confirmed against exemptions.json's keaLeases4 note). Callers must
	// never surface it as a v4 label -- see keaCollector.emitLeaseMetrics's
	// includePrefixLen switch.
	PrefixLen flexInt `json:"prefix_len"`
}

type keaLeaseResponse struct {
	Total      int           `json:"total"`
	RowCount   int           `json:"rowCount"`
	Current    int           `json:"current"`
	Rows       []keaLeaseRow `json:"rows"`
	Stats      keaLeaseStats `json:"stats"`
	Interfaces flexStringMap `json:"interfaces"`
}

type KeaLease struct {
	Address    string
	HWAddr     string
	Hostname   string
	IsReserved bool
	Expire     int
	IfDescr    string
	Type       string // v6: "IA_NA" or "IA_PD"; v4 rows carry no type ("")
	State      int    // 0=active, 1=declined, 2=expired-reclaimed (Kea's own enum)
	// Vendor is the decoded mac_info OUI vendor-name lookup, populated on
	// both v4 and v6 leases; empty whenever the OUI is unknown.
	Vendor string
	// ClientID is the raw DHCPv4 option 61 client identifier. Always empty
	// on v6 leases (Kea's lease6 records carry no client-id field) — callers
	// must not surface it as a v6 label.
	ClientID string
	// ValidLifetime is Kea's valid-lft in seconds, populated on both v4 and
	// v6 leases.
	ValidLifetime int
	// PrefixLen is the IA_PD delegated prefix's block size; only meaningful
	// when this lease came from FetchKeaLeases6 (see keaLeaseRow.PrefixLen).
	PrefixLen int
}

type KeaLeases struct {
	Leases            []KeaLease
	TotalLeases       int
	ReservedCount     int
	DynamicCount      int
	LeasesByInterface map[string]int
	// LeasesByState buckets leases by keaLeaseStateLabel (active/declined/
	// expired-reclaimed/unknown) — at most 4 keys.
	LeasesByState map[string]int
	// LeasesByType buckets DHCPv6 leases by keaLeaseTypeLabel (IA_NA/IA_PD/
	// unknown). Rows with an empty `type` (always true for DHCPv4) are
	// excluded, so this stays empty for FetchKeaLeases4.
	LeasesByType map[string]int
	// StatsActive / StatsInactive / StatsTotal are Kea's OWN pool accounting
	// (the response's top-level `stats` object, computed over the full lease
	// population before bootgrid pages `rows`), NOT re-derived from the
	// decoded rows -- the two answer different questions and neither
	// replaces the other (#557). Zero-valued when the box sends no `stats`
	// object at all.
	StatsActive   int
	StatsInactive int
	StatsTotal    int
}

// keaLeaseStateLabel maps Kea's raw lease-state integer to the bounded label
// set for opnsense_kea_dhcp{4,6}_leases_by_state. Kea currently defines only
// 0/1/2; anything else maps to "unknown" defensively.
func keaLeaseStateLabel(state int) string {
	switch state {
	case 0:
		return "active"
	case 1:
		return "declined"
	case 2:
		return "expired-reclaimed"
	default:
		return "unknown"
	}
}

// keaLeaseTypeLabel maps Kea's raw DHCPv6 lease-type string to the bounded
// label set for opnsense_kea_dhcp6_leases_by_type. Anything other than the
// two Kea-defined values maps to "unknown" defensively.
func keaLeaseTypeLabel(t string) string {
	switch t {
	case "IA_NA", "IA_PD":
		return t
	default:
		return "unknown"
	}
}

func (c *Client) fetchKeaLeases(endpointName EndpointName) (KeaLeases, *APICallError) {
	var resp keaLeaseResponse
	var data KeaLeases

	url, ok := c.endpoints[endpointName]
	if !ok {
		return data, &APICallError{
			Endpoint:   string(endpointName),
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	data.TotalLeases = resp.Total
	data.LeasesByInterface = make(map[string]int)
	data.LeasesByState = make(map[string]int)
	data.LeasesByType = make(map[string]int)
	data.StatsActive = resp.Stats.Active.Int()
	data.StatsInactive = resp.Stats.Inactive.Int()
	data.StatsTotal = resp.Stats.Total.Int()

	for _, row := range resp.Rows {
		reserved := row.IsReserved.Bool()
		typ := row.Type.String()
		state := row.State.Int()

		lease := KeaLease{
			Address:       row.Address,
			HWAddr:        row.HWAddr,
			Hostname:      row.Hostname,
			IsReserved:    reserved,
			Expire:        row.Expire.Int(),
			IfDescr:       row.IfDescr,
			Type:          typ,
			State:         state,
			Vendor:        row.MacInfo,
			ClientID:      row.ClientID,
			ValidLifetime: row.ValidLifetime.Int(),
			PrefixLen:     row.PrefixLen.Int(),
		}

		data.Leases = append(data.Leases, lease)
		data.LeasesByInterface[row.IfDescr]++
		data.LeasesByState[keaLeaseStateLabel(state)]++
		if typ != "" {
			data.LeasesByType[keaLeaseTypeLabel(typ)]++
		}

		if reserved {
			data.ReservedCount++
		} else {
			data.DynamicCount++
		}
	}

	// Keyed by the endpoint this helper was called for, so v4 and v6 land under
	// their own keys rather than overwriting one another.
	c.publishResult(fetchshare.Key(endpointName), data)
	return data, nil
}

func (c *Client) FetchKeaLeases4() (KeaLeases, *APICallError) {
	return c.fetchKeaLeases("keaLeases4")
}

func (c *Client) FetchKeaLeases6() (KeaLeases, *APICallError) {
	return c.fetchKeaLeases("keaLeases6")
}

// keaSubnetRow mirrors api/kea/dhcpv4|dhcpv6/searchSubnet bootgrid rows.
// %interface carries the display name (e.g. "MGMT") that matches the
// if_descr labels used by the lease metrics, enabling PromQL joins. uuid
// identifies the subnet record and is used to join PD pool rows (whose own
// "subnet" field is a ModelRelationField UUID reference, not a CIDR) back to
// their subnet's CIDR.
type keaSubnetRow struct {
	UUID      string `json:"uuid"`
	Subnet    string `json:"subnet"`
	Pools     string `json:"pools"`
	Interface string `json:"%interface"`
}

type keaSubnetResponse struct {
	Rows []keaSubnetRow `json:"rows"`
}

// KeaSubnet is one configured Kea subnet with its computed pool size.
type KeaSubnet struct {
	UUID      string
	Subnet    string
	Interface string
	PoolSize  float64
}

func (c *Client) fetchKeaSubnets(endpointName EndpointName) ([]KeaSubnet, *APICallError) {
	var resp keaSubnetResponse

	url, ok := c.endpoints[endpointName]
	if !ok {
		return nil, &APICallError{
			Endpoint:   string(endpointName),
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}
	if err := c.do("GET", url, nil, &resp); err != nil {
		return nil, err
	}

	subnets := make([]KeaSubnet, 0, len(resp.Rows))
	for _, row := range resp.Rows {
		subnets = append(subnets, KeaSubnet{
			UUID:      row.UUID,
			Subnet:    row.Subnet,
			Interface: row.Interface,
			PoolSize:  c.poolSpecSize(row.Pools),
		})
	}
	return subnets, nil
}

// FetchKeaSubnets4 returns the configured Kea DHCPv4 subnets.
func (c *Client) FetchKeaSubnets4() ([]KeaSubnet, *APICallError) {
	return c.fetchKeaSubnets("keaSubnets4")
}

// FetchKeaSubnets6 returns the configured Kea DHCPv6 subnets.
func (c *Client) FetchKeaSubnets6() ([]KeaSubnet, *APICallError) {
	return c.fetchKeaSubnets("keaSubnets6")
}

// keaPdPoolRow mirrors one row of api/kea/dhcpv6/searchPdPool
// (OPNsense\Kea\KeaDhcpv6, pd_pools.pd_pool — source-verified against
// KeaDhcpv6.xml + Dhcpv6Controller::searchPdPoolAction). "subnet" is a
// ModelRelationField: its raw JSON value is the UUID of the parent subnet6
// record (display="interface,subnet"), NOT a CIDR — resolve it against
// FetchKeaSubnets6's UUID field. "%subnet" is OPNsense's own bootgrid-rendered
// "<if-key> <cidr>" description string (the generic UIModelGrid
// %fieldname-when-differs-from-value convention, same one that produces
// keaSubnets4/6's "%interface"); it is kept only as a fallback for when the
// UUID join misses (e.g. a stale reference). Unverified against a live PD
// pool row (issue #208: dev box had none configured at time of writing) —
// derived from OPNsense core source, kept tolerant.
// "<interface-description> <cidr>" description string (the generic
// UIModelGrid %fieldname-when-differs-from-value convention, same one that
// produces keaSubnets4/6's "%interface"); it is kept only as a fallback for
// when the UUID join misses (e.g. a stale reference).
//
// CONFIRMED via a real PD pool added on the dev box (2026-07-13, issue #208:
// captures/kea/dhcpv6_search_pd_pool.json) — subnet is the parent subnet6's
// uuid, %subnet is "TESTLAN fd09:172:16:9::/64" (interface description +
// CIDR, space-separated, matching a real subnet6 row's own uuid), and
// prefix_len/delegated_len arrived as JSON STRINGS ("56"/"62") on this box —
// flexInt already tolerates that. No live IA_PD lease row was captured
// (host/LXC-level IPv6 kernel gap on the only available test client), so the
// lease-side `type` field stays unverified for the actual "IA_NA"/"IA_PD"
// wire values; the PD pool CONFIG row shape here is fully confirmed.
type keaPdPoolRow struct {
	SubnetUUID    string     `json:"subnet"`
	SubnetDisplay flexString `json:"%subnet"`
	Prefix        string     `json:"prefix"`
	PrefixLen     flexInt    `json:"prefix_len"`
	DelegatedLen  flexInt    `json:"delegated_len"`
}

type keaPdPoolResponse struct {
	Rows []keaPdPoolRow `json:"rows"`
}

// KeaPdPool is one configured DHCPv6 prefix-delegation pool with its computed
// delegable-prefix capacity.
type KeaPdPool struct {
	SubnetUUID    string
	SubnetDisplay string
	Prefix        string
	Capacity      float64
}

// FetchKeaPdPools returns the configured Kea DHCPv6 prefix-delegation pools.
// Core Kea configuration data (never plugin-gated): searchPdPool is served
// whenever the Kea DHCPv6 controller exists, whether or not PD is in use —
// an empty rows array is "no PD pools configured", not "feature absent".
func (c *Client) FetchKeaPdPools() ([]KeaPdPool, *APICallError) {
	var resp keaPdPoolResponse

	url, ok := c.endpoints["keaPdPools6"]
	if !ok {
		return nil, &APICallError{
			Endpoint:   "keaPdPools6",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}
	if err := c.do("GET", url, nil, &resp); err != nil {
		return nil, err
	}

	pools := make([]KeaPdPool, 0, len(resp.Rows))
	for _, row := range resp.Rows {
		pools = append(pools, KeaPdPool{
			SubnetUUID:    row.SubnetUUID,
			SubnetDisplay: row.SubnetDisplay.String(),
			Prefix:        row.Prefix,
			Capacity:      c.pdPoolCapacity(row.PrefixLen.Int(), row.DelegatedLen.Int()),
		})
	}
	return pools, nil
}

// pdPoolCapacity returns the number of prefixes a PD pool can delegate:
// 2^(delegated_len - prefix_len). Invalid lengths (a delegated length
// shorter than the pool's own prefix, or either length outside the 0-128
// IPv6 bit range) contribute 0 and are warn-logged rather than failing the
// scrape.
func (c *Client) pdPoolCapacity(prefixLen, delegatedLen int) float64 {
	if prefixLen < 0 || prefixLen > 128 || delegatedLen < prefixLen || delegatedLen > 128 {
		c.log.Warn("kea: invalid pd pool prefix lengths; contributing 0",
			"prefix_len", prefixLen, "delegated_len", delegatedLen)
		return 0
	}
	return math.Pow(2, float64(delegatedLen-prefixLen))
}

// KeaPoolUsedBySubnet returns, for each configured Kea subnet, the count of
// leases whose address falls inside that subnet's CIDR — a client-side join,
// since Kea lease records carry no subnet reference of their own. DHCPv6
// IA_PD leases (delegated prefixes, not host addresses) are excluded: their
// pool consumption is tracked separately via the PD pool metrics. Every
// configured subnet gets a zero-filled entry even with no matching leases, so
// dhcp{4,6}_pool_used always has a series to divide dhcp{4,6}_pool_size by.
// Subnets with an unparseable CIDR, and leases with an unparseable address,
// are skipped defensively — never expected from a well-formed OPNsense
// config.
func KeaPoolUsedBySubnet(leases []KeaLease, subnets []KeaSubnet) map[string]int {
	used := make(map[string]int, len(subnets))

	type parsedSubnet struct {
		key string
		net *net.IPNet
	}
	parsed := make([]parsedSubnet, 0, len(subnets))
	for _, s := range subnets {
		used[s.Subnet] = 0
		_, ipnet, err := net.ParseCIDR(strings.TrimSpace(s.Subnet))
		if err != nil {
			continue
		}
		parsed = append(parsed, parsedSubnet{key: s.Subnet, net: ipnet})
	}

	for _, l := range leases {
		if l.Type == "IA_PD" {
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(l.Address))
		if ip == nil {
			continue
		}
		for _, ps := range parsed {
			if ps.net.Contains(ip) {
				used[ps.key]++
				break
			}
		}
	}

	return used
}
