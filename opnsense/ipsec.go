package opnsense

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

type ipsecSearchResponse struct {
	Rows []struct {
		Phase1desc  string `json:"phase1desc"`
		Connected   bool   `json:"connected"`
		IkeId       string `json:"ikeid"`
		Name        string `json:"name"`
		InstallTime string `json:"install-time"`
		// int64 so large byte/packet counters (>2^31) unmarshal correctly on
		// 32-bit source builds instead of failing the whole fetch (#103).
		BytesIn    int64 `json:"bytes-in"`
		BytesOut   int64 `json:"bytes-out"`
		PacketsIn  int64 `json:"packets-in"`
		PacketsOut int64 `json:"packets-out"`
	} `json:"rows"`
	RowCount int `json:"rowCount"`
	Total    int `json:"total"`
	Current  int `json:"current"`
}

type ipsecPhase2 struct {
	Phase2desc  string
	Name        string
	InstallTime int
	RekeyTime   int
	LifeTime    int
	// int64 so large byte/packet counters (>2^31) survive on 32-bit builds (#103).
	BytesIn    int64
	BytesOut   int64
	PacketsIn  int64
	PacketsOut int64
}

type ipsecPhase2SearchResponse struct {
	Rows []struct {
		Phase2desc  string `json:"phase2desc"`
		Name        string `json:"name"`
		InstallTime string `json:"install-time"`
		RekeyTime   string `json:"rekey-time"`
		LifeTime    string `json:"life-time"`
		BytesIn     string `json:"bytes-in"`
		BytesOut    string `json:"bytes-out"`
		PacketsIn   string `json:"packets-in"`
		PacketsOut  string `json:"packets-out"`
	} `json:"rows"`
}

type IPsec struct {
	Phase1desc  string
	Connected   int
	IkeId       string
	Name        string
	InstallTime int
	// int64 so large byte/packet counters (>2^31) survive on 32-bit builds (#103).
	BytesIn    int64
	BytesOut   int64
	PacketsIn  int64
	PacketsOut int64
	Phase2     []ipsecPhase2
}

type IPsecPhase1 struct {
	Rows []IPsec
}

func (c *Client) FetchIPsecPhase2(ikeId string) (ipsecPhase2SearchResponse, *APICallError) {
	var resp ipsecPhase2SearchResponse

	url, ok := c.endpoints["ipsecPhase2"]

	if !ok {
		return resp, &APICallError{
			Endpoint:   "ipsecPhase2",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	body := map[string]string{"id": ikeId}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return resp, &APICallError{
			Endpoint:   "ipsecPhase2",
			Message:    "failed to marshal body",
			StatusCode: 0,
		}
	}

	if err := c.do("POST", url, strings.NewReader(string(bodyBytes)), &resp); err != nil {
		return resp, err
	}

	return resp, nil
}

func (c *Client) FetchIPsecPhase1() (IPsecPhase1, *APICallError) {
	var resp ipsecSearchResponse
	var data IPsecPhase1

	url, ok := c.endpoints["ipsecPhase1"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "ipsecPhase1",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	for _, v := range resp.Rows {

		installTime, err := strconv.Atoi(v.InstallTime)
		if err != nil {
			installTime = 0
		}

		phase2Rows := []ipsecPhase2{}
		phase2, err2 := c.FetchIPsecPhase2(v.IkeId)
		if err2 != nil {
			c.log.Error("failed to fetch ipsec phase2", "error", err2)
		} else {
			for _, v2 := range phase2.Rows {
				p2InstallTime, err := strconv.Atoi(v2.InstallTime)
				if err != nil {
					p2InstallTime = 0
				}
				rekeyTime, err := strconv.Atoi(v2.RekeyTime)
				if err != nil {
					rekeyTime = 0
				}
				lifeTime, err := strconv.Atoi(v2.LifeTime)
				if err != nil {
					lifeTime = 0
				}
				// safeAtoi (int64) so large byte/packet counters are preserved
				// rather than silently zeroed via int overflow on 32-bit (#103).
				bytesIn := safeAtoi(v2.BytesIn)
				bytesOut := safeAtoi(v2.BytesOut)
				packetsIn := safeAtoi(v2.PacketsIn)
				packetsOut := safeAtoi(v2.PacketsOut)
				phase2Rows = append(phase2Rows, ipsecPhase2{
					Phase2desc:  v2.Phase2desc,
					Name:        v2.Name,
					InstallTime: p2InstallTime,
					RekeyTime:   rekeyTime,
					LifeTime:    lifeTime,
					BytesIn:     bytesIn,
					BytesOut:    bytesOut,
					PacketsIn:   packetsIn,
					PacketsOut:  packetsOut,
				})
			}
		}
		data.Rows = append(data.Rows, IPsec{
			Phase1desc:  v.Phase1desc,
			IkeId:       v.IkeId,
			Name:        v.Name,
			InstallTime: installTime,
			BytesIn:     v.BytesIn,
			BytesOut:    v.BytesOut,
			PacketsIn:   v.PacketsIn,
			PacketsOut:  v.PacketsOut,
			Connected:   parseBoolToInt(v.Connected),
			Phase2:      phase2Rows,
		})
	}

	return data, nil
}

// ipsecPoolRow mirrors one entry in the api/ipsec/leases/pools `pools` object
// map. Numbers are real JSON integers (Python ujson), not strings.
//
// VERIFICATION: endpoint is OPNsense core (LeasesController.php::poolsAction +
// scripts/ipsec/list_leases.py). Live-verification against the real box is
// encouraged; the populated fixture is derived from the controller source.
type ipsecPoolRow struct {
	Name    string  `json:"name"`
	Net     string  `json:"net"`
	Online  float64 `json:"online"`
	Offline float64 `json:"offline"`
	Size    float64 `json:"size"`
}

// IPsecPool is the normalised per-pool data.
type IPsecPool struct {
	Name    string
	Net     string
	Online  float64
	Offline float64
	Size    float64
}

// IPsecPools holds all configured mode-cfg pools returned by FetchIPsecPools.
type IPsecPools struct {
	Pools []IPsecPool // sorted by Name
}

// ipsecPoolsResponse captures the top-level api/ipsec/leases/pools object.
// The `pools` field is a JSON array when unconfigured but an object map when
// pools exist — use json.RawMessage and try both.
type ipsecPoolsResponse struct {
	Pools json.RawMessage `json:"pools"`
}

// FetchIPsecPools fetches IPsec mode-cfg pool utilisation data.
//
// When no pools are configured, the API returns `{"pools": []}` (an array);
// when pools exist, `pools` is an object map keyed by pool name. A 404 is
// treated as "feature absent" — empty data, no error.
func (c *Client) FetchIPsecPools() (IPsecPools, *APICallError) {
	var data IPsecPools

	url, ok := c.endpoints["ipsecPools"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "ipsecPools",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var resp ipsecPoolsResponse
	if err := c.do("GET", url, nil, &resp); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil // defensive: feature absent
		}
		return data, err
	}

	// pools is an array when unconfigured, an object map when populated.
	// Try to unmarshal as a map; on failure (e.g. empty array) return empty.
	var poolMap map[string]ipsecPoolRow
	if err := json.Unmarshal(resp.Pools, &poolMap); err != nil || len(poolMap) == 0 {
		return data, nil
	}

	for _, row := range poolMap {
		data.Pools = append(data.Pools, IPsecPool(row))
	}
	sort.Slice(data.Pools, func(i, j int) bool {
		return data.Pools[i].Name < data.Pools[j].Name
	})

	return data, nil
}
