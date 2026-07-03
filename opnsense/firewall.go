package opnsense

type FirewallPFStat struct {
	InterfaceName string `json:"interface,omitempty"` // We will populate this field with the key of the map
	References    int    `json:"references"`

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
		v.InterfaceName = k
		data.Interfaces = append(data.Interfaces, v)
	}
	return data, nil
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
