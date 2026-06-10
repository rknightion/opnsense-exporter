package opnsense

import (
	"net/http"
	"time"
)

// qfeedsStatsResponse mirrors api/qfeeds/settings/stats (os-q-feeds-connector).
// Shape confirmed against a live OPNsense 26.1 box running plugin 1.6:
// numbers arrive as JSON numbers, timestamps as RFC3339 strings, licensed as bool.
type qfeedsStatsResponse struct {
	Feeds []struct {
		Name             string  `json:"name"`
		TotalEntries     float64 `json:"total_entries"`
		PacketsBlocked   float64 `json:"packets_blocked"`
		BytesBlocked     float64 `json:"bytes_blocked"`
		AddressesBlocked float64 `json:"addresses_blocked"`
		UpdatedAt        string  `json:"updated_at"`
		NextUpdate       string  `json:"next_update"`
		Licensed         bool    `json:"licensed"`
	} `json:"feeds"`
	Totals struct {
		Entries          float64 `json:"entries"`
		AddressesBlocked float64 `json:"addresses_blocked"`
		PacketsBlocked   float64 `json:"packets_blocked"`
		BytesBlocked     float64 `json:"bytes_blocked"`
	} `json:"totals"`
	License struct {
		Name       string `json:"name"`
		ExpiryDate string `json:"expiry_date"`
	} `json:"license"`
}

// QFeedsFeed is one normalised Q-Feeds feed.
type QFeedsFeed struct {
	Name              string
	Entries           float64
	PacketsBlocked    float64
	BytesBlocked      float64
	AddressesBlocked  float64
	LastUpdateSeconds float64
	HasLastUpdate     bool
	NextUpdateSeconds float64
	HasNextUpdate     bool
}

// QFeedsStats holds the aggregated result of FetchQFeedsStats.
type QFeedsStats struct {
	Present               bool // false when the plugin is not installed (HTTP 404)
	Feeds                 []QFeedsFeed
	TotalEntries          float64
	TotalPacketsBlocked   float64
	TotalBytesBlocked     float64
	TotalAddressesBlocked float64
	LicenseName           string
	LicenseExpirySeconds  float64
	HasLicenseExpiry      bool
}

// parseRFC3339Unix parses an RFC3339 timestamp to unix seconds; ok=false on
// empty or unparseable input.
func parseRFC3339Unix(s string) (float64, bool) {
	if s == "" {
		return 0, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return 0, false
	}
	return float64(t.Unix()), true
}

// FetchQFeedsStats calls the Q-Feeds stats endpoint. A 404 means the
// os-q-feeds-connector plugin is absent: zero-value data (Present=false) and
// nil error, mirroring FetchACMECertificates/FetchDynDNSAccounts.
func (c *Client) FetchQFeedsStats() (QFeedsStats, *APICallError) {
	var resp qfeedsStatsResponse
	var data QFeedsStats

	url, ok := c.endpoints["qfeedsStats"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "qfeedsStats",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil
		}
		return data, err
	}

	data.Present = true
	data.TotalEntries = resp.Totals.Entries
	data.TotalPacketsBlocked = resp.Totals.PacketsBlocked
	data.TotalBytesBlocked = resp.Totals.BytesBlocked
	data.TotalAddressesBlocked = resp.Totals.AddressesBlocked
	data.LicenseName = resp.License.Name
	data.LicenseExpirySeconds, data.HasLicenseExpiry = parseRFC3339Unix(resp.License.ExpiryDate)

	for _, f := range resp.Feeds {
		feed := QFeedsFeed{
			Name:             f.Name,
			Entries:          f.TotalEntries,
			PacketsBlocked:   f.PacketsBlocked,
			BytesBlocked:     f.BytesBlocked,
			AddressesBlocked: f.AddressesBlocked,
		}
		feed.LastUpdateSeconds, feed.HasLastUpdate = parseRFC3339Unix(f.UpdatedAt)
		feed.NextUpdateSeconds, feed.HasNextUpdate = parseRFC3339Unix(f.NextUpdate)
		data.Feeds = append(data.Feeds, feed)
	}
	return data, nil
}
