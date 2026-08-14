package opnsense

// configBackupItem mirrors one entry of the api/core/backup/backups/this
// bootgrid response — the on-box history of automatic config backups written
// by OPNsense's own BackupController (globbed from /conf/backup/config-*.xml).
//
// Field shapes confirmed against a live OPNsense 26.7 box (2026-07-13):
//   - time     is an epoch-seconds value with a fractional component; observed
//     on the wire as a quoted decimal string ("1783886416.55"). flexString
//     tolerates either that or a bare JSON number, so a future release that
//     switches representation (per the AGENTS.md "absorb" triage) does not
//     need a struct change.
//   - filesize is a JSON int on the wire; flexString is still used so a
//     string-typed filesize on some release doesn't break decoding.
type configBackupItem struct {
	Time     flexString `json:"time"`
	Filesize flexString `json:"filesize"`
}

// configBackupResponse is the top-level api/core/backup/backups/this payload.
type configBackupResponse struct {
	Items []configBackupItem `json:"items"`
}

// ConfigBackupHistory is the normalised config-backup freshness summary: is the
// firewall's own config actually being backed up, and how stale is the newest
// copy. No per-backup metrics are derived — descriptions/usernames can carry
// hostnames or admin identity, so only the aggregate counts/timestamp are
// surfaced.
type ConfigBackupHistory struct {
	// Count is the number of backups OPNsense currently retains (bounded by
	// the box's retention setting; observed as high as 100 on a live box).
	Count int
	// LastTimestamp is the Unix-seconds time of the newest backup, or 0 if
	// Count is 0.
	LastTimestamp float64
	// LastSizeBytes is the file size of the newest backup, or 0 if Count is 0.
	LastSizeBytes float64
}

// FetchConfigBackupHistory retrieves the on-box config backup history and
// summarises it into freshness/count/size signals. This is a core endpoint —
// it is never plugin-gated and never answers 404.
func (c *Client) FetchConfigBackupHistory() (ConfigBackupHistory, *APICallError) {
	var resp configBackupResponse
	var data ConfigBackupHistory

	path, ok := c.endpoints["backupHistory"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "backupHistory",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", path, nil, &resp); err != nil {
		return data, err
	}

	data.Count = len(resp.Items)
	if data.Count == 0 {
		return data, nil
	}

	// OPNsense's BackupController documents items[] as newest-first, but the
	// newest entry is derived explicitly by max(time) rather than trusting
	// index 0, so a reordered or paginated response can't silently misreport
	// the newest backup.
	newestIdx := 0
	newestTime := safeParseFloat(resp.Items[0].Time.String())
	for i := 1; i < len(resp.Items); i++ {
		t := safeParseFloat(resp.Items[i].Time.String())
		if t > newestTime {
			newestTime = t
			newestIdx = i
		}
	}

	data.LastTimestamp = newestTime
	data.LastSizeBytes = safeParseFloat(resp.Items[newestIdx].Filesize.String())

	return data, nil
}
