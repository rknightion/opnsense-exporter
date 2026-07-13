package opnsense

import (
	"net/http"
	"strings"
)

// dmidecodeSystemInfo mirrors the "system" section of the os-dmidecode
// plugin's api/dmidecode/service/get response. The plugin's ServiceController
// (sysutils/dmidecode/src/opnsense/mvc/app/controllers/OPNsense/Dmidecode/Api/ServiceController.php
// in opnsense/plugins) runs `dmidecode -q -t system`, greps it down to these
// five keys and ini-parses the result — so any of them may be empty (or read
// "Not Specified"/"To be filled by O.E.M." — dmidecode's own placeholders for
// unset firmware fields, seen verbatim on the QEMU dev box).
type dmidecodeSystemInfo struct {
	Manufacturer string `json:"Manufacturer"`
	ProductName  string `json:"Product Name"`
	Version      string `json:"Version"`
	SerialNumber string `json:"Serial Number"`
	Family       string `json:"Family"`
}

// dmidecodeBiosInfo mirrors the "bios" section of the same response, from
// `dmidecode -q -t bios` filtered to Vendor/Version/Release Date.
type dmidecodeBiosInfo struct {
	Vendor      string `json:"Vendor"`
	Version     string `json:"Version"`
	ReleaseDate string `json:"Release Date"`
}

// dmidecodeServiceGetResponse is the full api/dmidecode/service/get payload.
// Confirmed shape (dev box, 2026-07-13, QEMU DMI):
//
//	{"status":"ok","system":{"Manufacturer":"QEMU","Product Name":"Standard PC (i440FX + PIIX, 1996)",
//	 "Version":"pc-i440fx-11.0","Serial Number":"Not Specified","Family":"Not Specified"},
//	 "bios":{"Vendor":"SeaBIOS","Version":"rel-1.17.0-...","Release Date":"04/01/2014"}}
type dmidecodeServiceGetResponse struct {
	Status string              `json:"status"`
	System dmidecodeSystemInfo `json:"system"`
	BIOS   dmidecodeBiosInfo   `json:"bios"`
}

// DMIInfo is the normalised representation of one firewall's DMI/BIOS
// identity, as reported by the os-dmidecode plugin.
type DMIInfo struct {
	// Present is false when the os-dmidecode plugin is not installed (HTTP 404).
	Present      bool
	Manufacturer string
	Product      string
	Version      string
	Serial       string
	Family       string
	BIOSVendor   string
	BIOSVersion  string
	BIOSRelease  string
}

// FetchDMIInfo calls the os-dmidecode plugin's service/get endpoint and
// returns the box's DMI system/BIOS identity.
//
// If the os-dmidecode plugin is not installed the endpoint returns HTTP 404
// (this repo's convention for every plugin-gated endpoint — mirroring
// FetchACMECertificates); that is treated as "feature absent" so boxes
// without the plugin do not log errors or increment endpoint counters on
// every scrape.
func (c *Client) FetchDMIInfo() (DMIInfo, *APICallError) {
	var resp dmidecodeServiceGetResponse
	var data DMIInfo

	url, ok := c.endpoints["dmidecodeInfo"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "dmidecodeInfo",
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
	data.Manufacturer = resp.System.Manufacturer
	data.Product = resp.System.ProductName
	data.Version = resp.System.Version
	data.Serial = resp.System.SerialNumber
	data.Family = resp.System.Family
	data.BIOSVendor = resp.BIOS.Vendor
	data.BIOSVersion = resp.BIOS.Version
	data.BIOSRelease = resp.BIOS.ReleaseDate

	return data, nil
}

// dechwPowerStatusResponse mirrors api/dechw/info/power_status, served by the
// os-dec-hw plugin's InfoController::powerStatusAction (sysutils/dec-hw in
// opnsense/plugins):
//
//	public function powerStatusAction()
//	{
//	    $result = ["status" => "failed"];
//	    $status = parse_ini_string((new Backend())->configdRun('dechw power'));
//	    if (!empty($status)) {
//	        $result["status"] = "OK";
//	        $result = array_merge($result, $status);
//	    }
//	    return $result;
//	}
//
// The `dechw power` configd action reads the Deciso DEC-series appliance's
// GPIO power-supply-presence lines via gpioctl. On any box without that GPIO
// device — every non-Deciso firewall, and this repo's QEMU dev/test box,
// confirmed live 2026-07-13 — configdRun returns empty output, so the
// controller answers plain {"status":"failed"} with NO pwr1/pwr2 keys at all.
// Only real Deciso hardware ever answers {"status":"OK","pwr1":"...","pwr2":"..."}.
// This is a three-state situation, not a two-state one:
//  1. os-dec-hw not installed at all       -> HTTP 404 (handled like any other
//     plugin-gated endpoint: "feature absent", no PSU series).
//  2. os-dec-hw installed, no GPIO hardware -> HTTP 200 {"status":"failed"}
//     (feature present, hardware absent: still no PSU series).
//  3. os-dec-hw installed on real Deciso hw -> HTTP 200 {"status":"OK",...}
//     (PSU series emitted).
//
// pwr1/pwr2 use *flexBool (pointers) rather than plain flexBool so a firewall
// model that only reports one PSU doesn't get a fabricated "PSU 2 = failed"
// series for a key that was never in the response — nil means the key was
// absent, matching the widget's own fixed ['pwr1','pwr2'] iteration
// (sysutils/dec-hw .../www/js/widgets/DecHW.js), which treats '1' as powered
// (blue) and anything else as unpowered (red).
type dechwPowerStatusResponse struct {
	Status string    `json:"status"`
	PWR1   *flexBool `json:"pwr1"`
	PWR2   *flexBool `json:"pwr2"`
}

// PSUStatus is the normalised representation of the Deciso DEC-series
// dual-PSU GPIO status, as reported by the os-dec-hw plugin.
type PSUStatus struct {
	// Present is true only when the plugin is installed AND reports live GPIO
	// hardware (status == "OK"). It is false both when the plugin is absent
	// (404) and when it is installed but the box has no GPIO power hardware
	// ({"status":"failed"}) — see the three-state doc comment above.
	Present bool
	// PSU1/PSU2 are nil when the corresponding key was absent from an "OK"
	// response; otherwise true = powered, false = not powered.
	PSU1 *bool
	PSU2 *bool
}

// FetchDechwPowerStatus calls the os-dec-hw plugin's power-status endpoint
// and returns the Deciso dual-PSU GPIO state.
//
// A 404 (plugin not installed) is treated as "feature absent", mirroring
// every other plugin-gated Fetch* method. A 200 with {"status":"failed"} is
// NOT an error and NOT a 404 — it means the plugin is installed but this box
// has no GPIO power hardware to report (the overwhelming majority of
// os-dec-hw installs, since the plugin doesn't gate on appliance model) — so
// it is likewise treated as "no PSU data", just via a different signal.
func (c *Client) FetchDechwPowerStatus() (PSUStatus, *APICallError) {
	var resp dechwPowerStatusResponse
	var data PSUStatus

	url, ok := c.endpoints["dechwPowerStatus"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "dechwPowerStatus",
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

	if !strings.EqualFold(resp.Status, "OK") {
		// Plugin installed, no GPIO hardware detected (typically {"status":"failed"}).
		return data, nil
	}

	data.Present = true
	if resp.PWR1 != nil {
		v := resp.PWR1.Bool()
		data.PSU1 = &v
	}
	if resp.PWR2 != nil {
		v := resp.PWR2.Bool()
		data.PSU2 = &v
	}

	return data, nil
}
