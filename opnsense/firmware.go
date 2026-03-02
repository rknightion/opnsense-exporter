package opnsense

import "time"

type firmwareStatusResponse struct {
	LastCheck      string `json:"last_check"`
	NeedsReboot    string `json:"needs_reboot"`
	OsVersion      string `json:"os_version"`
	ProductID      string `json:"product_id"`
	ProductVersion string `json:"product_version"`
	ProductAbi     string `json:"product_abi"`
	NewPackages    []struct {
		Name       string `json:"name"`
		Repository string `json:"repository"`
		Version    string `json:"version"`
	} `json:"new_packages"`
	UpgradePackages []struct {
		Name           string `json:"name"`
		Repository     string `json:"repository"`
		CurrentVersion string `json:"current_version"`
		NewVersion     string `json:"new_version"`
		Size           string `json:"size,omitempty"`
	} `json:"upgrade_packages"`
	Product struct {
		ProductCheck struct {
			UpgradeNeedsReboot string `json:"upgrade_needs_reboot"`
		} `json:"product_check"`
	} `json:"product"`
	Status string `json:"status"`
}

type FirmwareStatus struct {
	LastCheck          string
	NeedsReboot        bool
	NewPackages        int
	OsVersion          string
	ProductABI         string
	ProductId          string
	ProductVersion     string
	UpgradePackages    int
	UpgradeNeedsReboot bool
	LastCheckTimestamp float64
}

func NewFirmwareStatus() FirmwareStatus {
	return FirmwareStatus{
		LastCheck:          "undefined",
		NeedsReboot:        false,
		NewPackages:        0,
		OsVersion:          "undefined",
		ProductABI:         "undefined",
		ProductId:          "undefined",
		ProductVersion:     "undefined",
		UpgradePackages:    0,
		UpgradeNeedsReboot: false,
		LastCheckTimestamp: 0,
	}
}

func parseLastCheckTimestamp(raw string) float64 {
	if raw == "" || raw == "undefined" {
		return 0
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err == nil {
		return float64(t.Unix())
	}
	t, err = time.Parse("2006-01-02T15:04:05", raw)
	if err == nil {
		return float64(t.UTC().Unix())
	}
	return 0
}

func (c *Client) FetchFirmwareStatus() (FirmwareStatus, *APICallError) {
	var resp firmwareStatusResponse
	data := NewFirmwareStatus()

	url, ok := c.endpoints["firmware"]

	if !ok {
		return data, &APICallError{
			Endpoint:   "firmware",
			Message:    "Missing endpoint 'firmwareStatus'",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	if resp.Status != "none" {
		data.OsVersion = resp.OsVersion
		data.ProductABI = resp.ProductAbi
		data.ProductId = resp.ProductID
		data.ProductVersion = resp.ProductVersion
		data.LastCheck = resp.LastCheck
		data.NeedsReboot = resp.NeedsReboot == "1"
		data.UpgradeNeedsReboot = resp.Product.ProductCheck.UpgradeNeedsReboot == "1"
		data.LastCheckTimestamp = parseLastCheckTimestamp(resp.LastCheck)
		data.NewPackages = len(resp.NewPackages)
		data.UpgradePackages = len(resp.UpgradePackages)
	}
	return data, nil
}
