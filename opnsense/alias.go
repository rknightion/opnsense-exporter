package opnsense

// aliasTableSizeResponse mirrors api/firewall/alias/get_table_size.
// Shape confirmed against a live OPNsense 26.1 box: one call returns the
// global used/limit AND per-table entry counts plus pf eval/block/pass
// packet+byte counters — so the N+1 firewall/alias_util/aliases fanout is
// unnecessary and deliberately not implemented.
type aliasTableDetail struct {
	Count float64 `json:"count"`
	// Updated is the table's last-refresh time (#583). Earlier revisions of this
	// file said it was "intentionally ignored" because it is a timezone-less
	// local timestamp; that reason no longer holds — parseGeoIPTimestamp
	// (firewall_geoip.go) already resolves this exact naive-ISO-8601 shape, and
	// a URL/DNS alias that silently stopped refreshing is a security control
	// failing open with a table still full of stale rows, which no other metric
	// can see.
	//
	// Producer (core src/opnsense/scripts/filter/pftablecount.py:69-82,
	// identical on stable/26.1 and stable/26.7):
	//
	//	table_updated = None
	//	if os.path.isfile("/var/db/aliastables/<table>.txt"):
	//	    table_updated = datetime.fromtimestamp(os.path.getmtime(f)).isoformat()
	//	result['details'][table]['updated'] = table_updated
	//
	// Two consequences the decode has to respect. The key is set on EVERY table,
	// so it is never "missing" — but it is JSON **null** for every table with no
	// persisted file, which is most of them (a static host/network alias has no
	// refresh cycle at all). And the value is the FILE MTIME rendered by
	// datetime.isoformat() with no UTC offset, so it carries microseconds and is
	// ambiguous by the box's zone offset; parseGeoIPTimestamp pins it to UTC to
	// stay deterministic, which is fine for an age-since-refresh reading but
	// means the absolute epoch can be off by that offset.
	//
	// flexString decodes null to "", which parseGeoIPTimestamp already treats as
	// "unknown" — so null, absent and unparseable all converge on one answer.
	Updated     flexString `json:"updated"`
	EvalNomatch float64    `json:"eval_nomatch"`
	EvalMatch   float64    `json:"eval_match"`
	InBlockP    float64    `json:"in_block_p"`
	InBlockB    float64    `json:"in_block_b"`
	InPassP     float64    `json:"in_pass_p"`
	InPassB     float64    `json:"in_pass_b"`
	OutBlockP   float64    `json:"out_block_p"`
	OutBlockB   float64    `json:"out_block_b"`
	OutPassP    float64    `json:"out_pass_p"`
	OutPassB    float64    `json:"out_pass_b"`
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
	// UpdatedTimestamp is when this table's persisted content was last written,
	// in Unix seconds (#583). HasUpdated is false for a table with no persisted
	// file (static aliases — the common case), for a null/absent value, and for
	// a value that failed to parse; the collector must then emit nothing rather
	// than epoch 0, which would make every static table read as 56 years stale.
	UpdatedTimestamp float64
	HasUpdated       bool
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
		updated, hasUpdated := parseGeoIPTimestamp(d.Updated.String())
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

			UpdatedTimestamp: updated,
			HasUpdated:       hasUpdated,
		})
	}
	return data, nil
}
