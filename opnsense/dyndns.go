package opnsense

import (
	"net/http"
	"time"
)

// dyndnsAccountRow mirrors the JSON fields returned by the ddclient plugin
// api/dyndns/accounts/searchItem bootgrid endpoint.
//
// Field names confirmed from a live OPNsense 26.1 box running os-ddclient.
// The %service and %interface fields are display-name variants and are not
// captured here — service and interface raw values are used for labels.
//
// NOTE: rows also include "password" and "%password" — these are intentionally
// omitted to prevent credential exposure in metric labels.
type dyndnsAccountRow struct {
	UUID         string     `json:"uuid"`
	Enabled      flexString `json:"enabled"`
	Service      flexString `json:"service"`
	Hostnames    flexString `json:"hostnames"`
	Zone         flexString `json:"zone"`
	Interface    flexString `json:"interface"`
	Description  flexString `json:"description"`
	CurrentIP    flexString `json:"current_ip"`
	CurrentMtime flexString `json:"current_mtime"`
}

type dyndnsAccountSearchResponse struct {
	Total    int                `json:"total"`
	RowCount int                `json:"rowCount"`
	Current  int                `json:"current"`
	Rows     []dyndnsAccountRow `json:"rows"`
}

// DynDNSAccount is the normalised representation of one DynDNS account.
type DynDNSAccount struct {
	UUID              string
	Enabled           bool
	Service           string
	Hostnames         string
	Zone              string
	Interface         string
	Description       string
	CurrentIP         string
	LastUpdateSeconds float64 // Unix seconds; 0 means never updated / parse failed
	HasLastUpdate     bool    // true when current_mtime was non-empty and parsed
}

// DynDNSAccounts holds the aggregated result of FetchDynDNSAccounts.
type DynDNSAccounts struct {
	Present  bool // false when the os-ddclient plugin is not installed (HTTP 404)
	Accounts []DynDNSAccount
	Total    int
}

// FetchDynDNSAccounts calls the ddclient accounts search endpoint and returns
// aggregated account data.
//
// If the os-ddclient plugin is not installed the endpoint returns HTTP 404
// (verified against a live OPNsense 26.1 box). That is treated as "feature
// absent" — empty data with no error — so boxes without the plugin do not log
// errors or increment endpoint counters on every scrape.
func (c *Client) FetchDynDNSAccounts() (DynDNSAccounts, *APICallError) {
	var resp dyndnsAccountSearchResponse
	var data DynDNSAccounts

	url, ok := c.endpoints["dyndnsAccounts"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "dyndnsAccounts",
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
	data.Total = resp.Total

	for _, row := range resp.Rows {
		acct := DynDNSAccount{
			UUID:        row.UUID,
			Enabled:     parseStringToBool(row.Enabled.String()),
			Service:     row.Service.String(),
			Hostnames:   row.Hostnames.String(),
			Zone:        row.Zone.String(),
			Interface:   row.Interface.String(),
			Description: row.Description.String(),
			CurrentIP:   row.CurrentIP.String(),
		}

		if mtime := row.CurrentMtime.String(); mtime != "" {
			if t, err := time.Parse(time.RFC3339, mtime); err == nil {
				acct.LastUpdateSeconds = float64(t.Unix())
				acct.HasLastUpdate = true
			} else {
				c.log.Debug("dyndns: failed to parse current_mtime",
					"mtime", mtime,
					"err", err,
				)
			}
		}

		data.Accounts = append(data.Accounts, acct)
	}

	return data, nil
}
