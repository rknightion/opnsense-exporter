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
	// DowngradePackages / ReinstallPackages are state-dependent supersets that
	// appear once a firmware check has run (#237): packages available to downgrade
	// (shape mirrors upgrade_packages: current_version/new_version) and packages
	// available to reinstall (shape mirrors new_packages: a single version field).
	// Only counts are exported — see FirmwareStatus.DowngradePackages/ReinstallPackages.
	DowngradePackages []struct {
		Name           string `json:"name"`
		Repository     string `json:"repository"`
		CurrentVersion string `json:"current_version"`
		NewVersion     string `json:"new_version"`
	} `json:"downgrade_packages"`
	ReinstallPackages []struct {
		Name       string `json:"name"`
		Repository string `json:"repository"`
		Version    string `json:"version"`
	} `json:"reinstall_packages"`
	Product struct {
		ProductCheck struct {
			UpgradeNeedsReboot string `json:"upgrade_needs_reboot"`
		} `json:"product_check"`
	} `json:"product"`
	Status string `json:"status"`
}

type FirmwareStatus struct {
	LastCheck             string
	NeedsReboot           bool
	NewPackages           int
	OsVersion             string
	ProductABI            string
	ProductId             string
	ProductVersion        string
	UpgradePackages       int
	UpgradeNeedsReboot    bool
	LastCheckTimestamp    float64
	UpgradePackageDetails []FirmwarePackageUpgrade
	// DowngradePackages / ReinstallPackages (#237): counts only, siblings of
	// NewPackages/UpgradePackages. Populated only once a firmware check has run
	// since boot, same as the rest of this state-dependent envelope.
	DowngradePackages int
	ReinstallPackages int
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
	// OPNsense 25.x+ emits e.g. "Tue Jun  9 10:13:17 BST 2026" (time.UnixDate).
	// ParseInLocation with UTC keeps the result deterministic regardless of
	// the host's timezone (plain time.Parse resolves abbreviations like "BST"
	// against the local zone). Zone abbreviations therefore parse with a zero
	// offset, so the value can be off by the box's zone offset — acceptable
	// for a last-check age.
	t, err = time.ParseInLocation(time.UnixDate, raw, time.UTC)
	if err == nil {
		return float64(t.Unix())
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

	// OPNsense >= 25.x no longer flips the status field; a populated
	// last_check is the signal that an update check has run and the rest of
	// the payload is meaningful (upstream PR #101 / issue #100).
	if resp.LastCheck != "" {
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
		data.DowngradePackages = len(resp.DowngradePackages)
		data.ReinstallPackages = len(resp.ReinstallPackages)
		for _, p := range resp.UpgradePackages {
			data.UpgradePackageDetails = append(data.UpgradePackageDetails, FirmwarePackageUpgrade{
				Name:           p.Name,
				CurrentVersion: p.CurrentVersion,
				NewVersion:     p.NewVersion,
			})
		}
	}
	return data, nil
}

// FirmwarePackageUpgrade describes one package with a pending upgrade, from
// the firmware status "upgrade_packages" list.
type FirmwarePackageUpgrade struct {
	Name           string
	CurrentVersion string
	NewVersion     string
}

type firmwareInfoResponse struct {
	ProductID      string `json:"product_id"`
	ProductVersion string `json:"product_version"`
	Plugin         []struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Installed string `json:"installed"`
	} `json:"plugin"`
}

// FirmwarePlugin is one installed OPNsense plugin (os-*) from core/firmware/info.
type FirmwarePlugin struct {
	Name    string
	Version string
}

// FirmwareInfo is the parsed subset of api/core/firmware/info the exporter
// uses: product identity plus installed plugins.
type FirmwareInfo struct {
	ProductID        string
	ProductVersion   string
	InstalledPlugins []FirmwarePlugin
}

// FetchFirmwareInfo fetches api/core/firmware/info and returns the product
// identity plus the list of installed plugins. The 900+ entry "package"
// catalogue in the response is deliberately not decoded — only the plugin
// list (~100 entries, ~15 installed on a typical box) is used, filtered to
// installed == "1", to keep metric cardinality bounded.
func (c *Client) FetchFirmwareInfo() (FirmwareInfo, *APICallError) {
	var resp firmwareInfoResponse
	var data FirmwareInfo

	url, ok := c.endpoints["firmwareInfo"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "firmwareInfo",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	data.ProductID = resp.ProductID
	data.ProductVersion = resp.ProductVersion
	for _, p := range resp.Plugin {
		if p.Installed != "1" {
			continue
		}
		data.InstalledPlugins = append(data.InstalledPlugins, FirmwarePlugin{
			Name:    p.Name,
			Version: p.Version,
		})
	}
	return data, nil
}
