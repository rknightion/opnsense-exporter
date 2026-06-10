package opnsense

// syslogStatRow mirrors api/syslog/service/stats bootgrid rows.
// Field names confirmed against a live OPNsense 26.1 box: capitalised keys,
// Number arrives as a string.
type syslogStatRow struct {
	Description    string `json:"Description"`
	SourceName     string `json:"SourceName"`
	SourceID       string `json:"SourceId"`
	SourceInstance string `json:"SourceInstance"`
	State          string `json:"State"`
	Type           string `json:"Type"`
	Number         string `json:"Number"`
}

type syslogStatsResponse struct {
	Total    int             `json:"total"`
	RowCount int             `json:"rowCount"`
	Current  int             `json:"current"`
	Rows     []syslogStatRow `json:"rows"`
}

// SyslogStat is one normalised syslog-ng statistic.
type SyslogStat struct {
	SourceName     string
	SourceID       string
	SourceInstance string
	Type           string
	Value          float64
}

// SyslogStats holds the result of FetchSyslogStats.
type SyslogStats struct {
	Stats []SyslogStat
	Total int
}

// FetchSyslogStats returns the syslog-ng statistics grid. Rows of Type
// "stamp" (unix timestamp of the stats epoch, not a statistic) are skipped.
func (c *Client) FetchSyslogStats() (SyslogStats, *APICallError) {
	var resp syslogStatsResponse
	var data SyslogStats

	url, ok := c.endpoints["syslogStats"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "syslogStats",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	data.Total = resp.Total
	for _, row := range resp.Rows {
		if row.Type == "stamp" {
			continue
		}
		data.Stats = append(data.Stats, SyslogStat{
			SourceName:     row.SourceName,
			SourceID:       row.SourceID,
			SourceInstance: row.SourceInstance,
			Type:           row.Type,
			Value:          safeParseFloat(row.Number),
		})
	}
	return data, nil
}
