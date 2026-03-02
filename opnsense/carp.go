package opnsense

// carpVIPRow is the raw JSON row returned by the CARP VIP status API.
type carpVIPRow struct {
	Interface string `json:"interface"`
	VHID      string `json:"vhid"`
	Advbase   string `json:"advbase"`
	Advskew   string `json:"advskew"`
	Status    string `json:"status"`
	StatusTxt string `json:"status_txt"`
	VIP       string `json:"vip"`
	Subnet    string `json:"subnet"`
}

// carpInfo holds global CARP status fields from the API response.
type carpInfo struct {
	Demotion        string `json:"demotion"`
	Allow           string `json:"allow"`
	MaintenanceMode bool   `json:"maintenancemode"`
}

// carpStatusResponse is the top-level JSON structure for the CARP status API.
type carpStatusResponse struct {
	Rows []carpVIPRow `json:"rows"`
	Carp carpInfo     `json:"carp"`
}

// CARPStatus holds the parsed CARP/VIP status data.
type CARPStatus struct {
	VIPs            []CARPVIP
	Demotion        int
	Allow           bool
	MaintenanceMode bool
}

// CARPVIP represents a single parsed CARP Virtual IP.
type CARPVIP struct {
	Interface string
	VHID      string
	VIP       string
	Status    int
	Advbase   int
	Advskew   int
}

// parseCARPStatus converts a CARP status string to an integer.
// MASTER=1, BACKUP=0, INIT=2, unknown=-1.
func parseCARPStatus(status string) int {
	switch status {
	case "MASTER":
		return 1
	case "BACKUP":
		return 0
	case "INIT":
		return 2
	default:
		return -1
	}
}

// FetchCARPStatus retrieves the CARP/VIP status from the OPNsense API.
func (c *Client) FetchCARPStatus() (CARPStatus, *APICallError) {
	var resp carpStatusResponse
	var data CARPStatus

	url, ok := c.endpoints["carpStatus"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "carpStatus",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	data.Demotion = safeAtoi(resp.Carp.Demotion)
	data.Allow = parseStringToBool(resp.Carp.Allow)
	data.MaintenanceMode = resp.Carp.MaintenanceMode

	for _, row := range resp.Rows {
		vip := CARPVIP{
			Interface: row.Interface,
			VHID:      row.VHID,
			VIP:       row.VIP,
			Status:    parseCARPStatus(row.Status),
			Advbase:   safeAtoi(row.Advbase),
			Advskew:   safeAtoi(row.Advskew),
		}
		data.VIPs = append(data.VIPs, vip)
	}

	return data, nil
}
