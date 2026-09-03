package opnsense

import (
	"net/url"
	"sort"
	"strings"
)

// pfTopSearchResponse is the bootgrid envelope returned by
// api/diagnostics/firewall/query_pf_top. The endpoint's payload is generated
// from the pftop script and is wrapped by searchRecordsetBase, so callers see
// rows rather than the script's internal details array.
type pfTopSearchResponse struct {
	Rows     []pfTopStateRow `json:"rows"`
	Total    int             `json:"total"`
	RowCount int             `json:"rowCount"`
	Current  int             `json:"current"`
}

type pfTopStateRow struct {
	Proto   string `json:"proto"`
	Dir     string `json:"dir"`
	SrcAddr string `json:"src_addr"`
	SrcPort string `json:"src_port"`
	DstAddr string `json:"dst_addr"`
	DstPort string `json:"dst_port"`
	GwAddr  string `json:"gw_addr"`
	GwPort  string `json:"gw_port"`
	State   string `json:"state"`
	Age     int64  `json:"age"`
	Expire  int64  `json:"expire"`
	Packets int64  `json:"pkts"`
	Bytes   int64  `json:"bytes"`
	Average int64  `json:"avg"`
	Rule    string `json:"rule"`
	// Presentation metadata conditionally added by queryPfTopAction when the
	// rule has a matching label. It stays in the schema but never becomes a
	// metric label.
	Label       string `json:"label"`
	Description string `json:"descr"`
}

// PFTopState is one row from OPNsense's pfTop diagnostic view. State rows are
// deliberately kept as the endpoint returned them; duplicate folding and
// ranking belong to the collector, where the complete current snapshot is
// available.
type PFTopState struct {
	Proto   string
	Dir     string
	SrcAddr string
	SrcPort string
	DstAddr string
	DstPort string
	GwAddr  string
	GwPort  string
	State   string
	Packets int64
	Bytes   int64
	Rule    string
}

// PFTop is one successful pfTop response.
type PFTop struct {
	States []PFTopState
}

// fetchPFTopPayload asks the bootgrid endpoint for the complete current result
// set. Ranking and the N=100 bound are intentionally local to the collector.
const fetchPFTopPayload = bootgridAllRows + "&searchPhrase="

// FetchPFTop retrieves the current pfTop state rows from OPNsense.
func (c *Client) FetchPFTop() (PFTop, *APICallError) {
	var resp pfTopSearchResponse
	var data PFTop

	path, ok := c.endpoints["pfTop"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "pfTop",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	form := url.Values{
		"current":      {"1"},
		"rowCount":     {"-1"},
		"searchPhrase": {""},
	}
	if err := c.doForm(path, form, &resp); err != nil {
		return data, err
	}

	data.States = make([]PFTopState, 0, len(resp.Rows))
	for _, row := range resp.Rows {
		data.States = append(data.States, PFTopState{
			Proto:   row.Proto,
			Dir:     row.Dir,
			SrcAddr: row.SrcAddr,
			SrcPort: row.SrcPort,
			DstAddr: row.DstAddr,
			DstPort: row.DstPort,
			GwAddr:  row.GwAddr,
			GwPort:  row.GwPort,
			State:   row.State,
			Packets: row.Packets,
			Bytes:   row.Bytes,
			Rule:    row.Rule,
		})
	}
	return data, nil
}

// trafficTopRecordRow is one record in an iftop sample. The collector consumes
// only the rate fields and deliberately ignores cumulative and presentation
// fields that the API also returns.
type trafficTopDetailRow struct {
	Address         string   `json:"address"`
	Rate            string   `json:"rate"`
	RateBits        int64    `json:"rate_bits"`
	Cumulative      string   `json:"cumulative"`
	CumulativeBytes int64    `json:"cumulative_bytes"`
	Tags            []string `json:"tags"`
}

type trafficTopRecordRow struct {
	Address            string                `json:"address"`
	RateIn             string                `json:"rate_in"`
	RateOut            string                `json:"rate_out"`
	Rate               string                `json:"rate"`
	RateBitsIn         int64                 `json:"rate_bits_in"`
	RateBitsOut        int64                 `json:"rate_bits_out"`
	RateBits           int64                 `json:"rate_bits"`
	CumulativeIn       string                `json:"cumulative_in"`
	CumulativeOut      string                `json:"cumulative_out"`
	Cumulative         string                `json:"cumulative"`
	CumulativeBytesIn  int64                 `json:"cumulative_bytes_in"`
	CumulativeBytesOut int64                 `json:"cumulative_bytes_out"`
	CumulativeBytes    int64                 `json:"cumulative_bytes"`
	Tags               []string              `json:"tags"`
	ReverseName        string                `json:"rname"`
	Details            []trafficTopDetailRow `json:"details"`
}

type trafficTopInterfaceRow struct {
	Status  string                `json:"status"`
	Records []trafficTopRecordRow `json:"records"`
}

// TrafficTopRecord is one host aggregate in a two-second iftop sample.
type TrafficTopRecord struct {
	Address     string
	RateBitsIn  int64
	RateBitsOut int64
	RateBits    int64
}

// TrafficTopInterface is one interface's sample. A timeout is represented by
// Status="timeout" and is excluded by the collector rather than converted to
// a synthetic zero.
type TrafficTopInterface struct {
	Status  string
	Records []TrafficTopRecord
}

// TrafficTop is the successful response keyed by the OPNsense configuration
// identifier supplied in the request path.
type TrafficTop struct {
	Interfaces map[string]TrafficTopInterface
}

// FetchTrafficTop retrieves one iftop sample for the supplied interface
// identifiers. The identifiers are canonicalized here as well as by the
// collector, so direct callers cannot accidentally issue duplicate or unstable
// requests. Empty input is a successful empty snapshot and makes no request.
func (c *Client) FetchTrafficTop(identifiers []string) (TrafficTop, *APICallError) {
	data := TrafficTop{Interfaces: map[string]TrafficTopInterface{}}

	ids := make([]string, 0, len(identifiers))
	seen := make(map[string]struct{}, len(identifiers))
	for _, identifier := range identifiers {
		identifier = strings.TrimSpace(identifier)
		if identifier == "" {
			continue
		}
		if _, ok := seen[identifier]; ok {
			continue
		}
		seen[identifier] = struct{}{}
		ids = append(ids, identifier)
	}
	if len(ids) == 0 {
		return data, nil
	}
	sort.Strings(ids)

	basePath, ok := c.endpoints["trafficTop"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "trafficTop",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}
	// OPNsense's route takes a comma-separated list in one path segment. Escape
	// each identifier, not the joined string, so commas remain separators while
	// an unexpected reserved character cannot escape the route segment.
	escaped := make([]string, len(ids))
	for i, identifier := range ids {
		escaped[i] = url.PathEscape(identifier)
	}
	path := EndpointPath(string(basePath) + "/" + strings.Join(escaped, ","))

	var resp map[string]trafficTopInterfaceRow
	if err := c.do("GET", path, nil, &resp); err != nil {
		return data, err
	}
	for identifier, row := range resp {
		entry := TrafficTopInterface{Status: row.Status, Records: make([]TrafficTopRecord, 0, len(row.Records))}
		for _, record := range row.Records {
			entry.Records = append(entry.Records, TrafficTopRecord{
				Address:     record.Address,
				RateBitsIn:  record.RateBitsIn,
				RateBitsOut: record.RateBitsOut,
				RateBits:    record.RateBits,
			})
		}
		data.Interfaces[identifier] = entry
	}
	return data, nil
}
