package opnsense

// carpVIPRow is the raw JSON row returned by the CARP VIP status API
// (get_vip_status). On OPNsense 26.1 the row has no "vip" key — the VIP address
// is carried in "subnet" (getVipStatusAction sets 'subnet' => $subnet['ipaddr']).
type carpVIPRow struct {
	Interface string `json:"interface"`
	VHID      string `json:"vhid"`
	Advbase   string `json:"advbase"`
	Advskew   string `json:"advskew"`
	Status    string `json:"status"`
	StatusTxt string `json:"status_txt"`
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
	Demotion        int64
	Allow           bool
	MaintenanceMode bool
}

// CARPVIP represents a single parsed CARP Virtual IP.
type CARPVIP struct {
	Interface string
	VHID      string
	VIP       string
	Status    int
	Advbase   int64
	Advskew   int64
}

// parseCARPStatus converts a CARP status string to an integer.
// MASTER=1, BACKUP=0, INIT=2, DISABLED=3, unknown=-1.
//
// DISABLED earns its own value rather than falling through to unknown (#503).
// getVipStatusAction builds its rows in two passes: the first walks the live
// ifconfig carp blocks, which is where MASTER/BACKUP/INIT come from, and the
// second stamps DISABLED on every configured VIP the first pass did not find -
// a VIP an admin disabled, or one whose interface is down. Both are routine.
//
// Folding that into -1 was wrong in two directions at once. It reported normal
// config as a parse failure, and because the VIP-fault alert pages on anything
// outside [0,1] it paged someone five minutes after they disabled a VIP. It also
// hid real parse failures behind routine config, which is what -1 is for.
func parseCARPStatus(status string) int {
	switch status {
	case "MASTER":
		return 1
	case "BACKUP":
		return 0
	case "INIT":
		return 2
	case "DISABLED":
		return 3
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
			// The VIP address is in the API's "subnet" field on 26.1 (there is
			// no "vip" key). Using subnet also keeps the (interface, vhid, vip)
			// label tuple unique when a vhid carries multiple addresses (#166).
			VIP:     row.Subnet,
			Status:  parseCARPStatus(row.Status),
			Advbase: safeAtoi(row.Advbase),
			Advskew: safeAtoi(row.Advskew),
		}
		data.VIPs = append(data.VIPs, vip)
	}

	return data, nil
}
