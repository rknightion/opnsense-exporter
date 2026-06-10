package opnsense

// aliasTableSizeResponse mirrors api/firewall/alias/get_table_size.
// Shape confirmed against a live OPNsense 26.1 box: one call returns the
// global used/limit AND per-table entry counts plus pf eval/block/pass
// packet+byte counters — so the N+1 firewall/alias_util/aliases fanout is
// unnecessary and deliberately not implemented. The "updated" field is a
// timezone-less local timestamp and is intentionally ignored.
type aliasTableDetail struct {
	Count       float64 `json:"count"`
	EvalNomatch float64 `json:"eval_nomatch"`
	EvalMatch   float64 `json:"eval_match"`
	InBlockP    float64 `json:"in_block_p"`
	InBlockB    float64 `json:"in_block_b"`
	InPassP     float64 `json:"in_pass_p"`
	InPassB     float64 `json:"in_pass_b"`
	OutBlockP   float64 `json:"out_block_p"`
	OutBlockB   float64 `json:"out_block_b"`
	OutPassP    float64 `json:"out_pass_p"`
	OutPassB    float64 `json:"out_pass_b"`
}

type aliasTableSizeResponse struct {
	Status  string                      `json:"status"`
	Size    float64                     `json:"size"`
	Used    float64                     `json:"used"`
	Details map[string]aliasTableDetail `json:"details"`
}

// AliasTable is one pf alias table with its pf counters.
type AliasTable struct {
	Name        string
	Entries     float64
	EvalMatch   float64
	EvalNomatch float64
	InBlockP    float64
	InBlockB    float64
	InPassP     float64
	InPassB     float64
	OutBlockP   float64
	OutBlockB   float64
	OutPassP    float64
	OutPassB    float64
}

// AliasTables holds the result of FetchAliasTables.
type AliasTables struct {
	Tables []AliasTable
	Used   float64
	Limit  float64
}

// FetchAliasTables returns pf alias table sizes and counters from
// api/firewall/alias/get_table_size. A single call returns the global
// used/limit totals AND per-table entry counts plus pf eval/block/pass
// packet+byte counters. Internal __* tables are included — they are real
// pf tables (bogons, sshlockout, virusprot) and are bounded.
func (c *Client) FetchAliasTables() (AliasTables, *APICallError) {
	var resp aliasTableSizeResponse
	var data AliasTables

	url, ok := c.endpoints["aliasTableSize"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "aliasTableSize",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	data.Used = resp.Used
	data.Limit = resp.Size
	for name, d := range resp.Details {
		data.Tables = append(data.Tables, AliasTable{
			Name:        name,
			Entries:     d.Count,
			EvalMatch:   d.EvalMatch,
			EvalNomatch: d.EvalNomatch,
			InBlockP:    d.InBlockP,
			InBlockB:    d.InBlockB,
			InPassP:     d.InPassP,
			InPassB:     d.InPassB,
			OutBlockP:   d.OutBlockP,
			OutBlockB:   d.OutBlockB,
			OutPassP:    d.OutPassP,
			OutPassB:    d.OutPassB,
		})
	}
	return data, nil
}
