package opnsense

import (
	"net/http"
	"net/url"
)

// smartListResponse is the JSON structure returned by api/smart/service/list.
// The devices array contains bare device names (e.g. "ada0", "nvme0") with no /dev/ prefix.
type smartListResponse struct {
	Devices []string `json:"devices"`
}

// smartInfoResponse is the JSON structure returned by api/smart/service/info.
// When the device is valid and smartctl succeeds, Output is populated.
// When device validation fails the endpoint returns {"message":"..."} with no output field.
type smartInfoResponse struct {
	Output *smartInfoOutput `json:"output"`
}

// smartInfoOutput mirrors the stable fields from a smartctl -a -j JSON response.
// All fields are pointers because they may be absent for some drive types.
type smartInfoOutput struct {
	ModelName          *string             `json:"model_name"`
	SerialNumber       *string             `json:"serial_number"`
	SmartStatus        *smartStatus        `json:"smart_status"`
	Temperature        *smartTemp          `json:"temperature"`
	PowerOnTime        *smartPowerOnTime   `json:"power_on_time"`
	AtaSmartAttributes *smartAtaAttributes `json:"ata_smart_attributes"`
	NVMeHealth         *smartNVMeHealthLog `json:"nvme_smart_health_information_log"`

	// RotationRate is ATA IDENTIFY word 217 (ataprint.cpp:725): 0 explicitly
	// means solid-state, any other value is the platter's RPM. A pointer so a
	// present-but-zero SSD reading (0, true) never collapses into the same
	// nil an omitted field produces (#577, mirrors the AttachOrStatResetUptime
	// presence-gating rule in interfaces.go) — reporting 0 for a drive that
	// simply didn't send this field would misclassify it as SSD.
	RotationRate *float64 `json:"rotation_rate"`

	// SpareAvailable and EnduranceUsed are smartctl's own NORMALIZED wear
	// percentages, derived by regex-matching vendor-specific attribute names
	// (Spare_Blocks/Reallocated_Sector_Count family; SSD_Life_Left/
	// Wear_Leveling family). Not reconstructible from the generic
	// per-attribute dump without reimplementing that matching — hence tracked
	// as their own fields rather than left to attribute_raw. Absent on drives
	// smartctl cannot normalize (most HDDs, some SSD vendors), so both stay
	// pointers (#577).
	SpareAvailable *smartWearPercent `json:"spare_available"`
	EnduranceUsed  *smartWearPercent `json:"endurance_used"`
}

// smartWearPercent is the object smartctl wraps each normalized wear
// percentage in. EVERY emission site in smartmontools writes an object keyed
// by current_percent — ataprint.cpp:1206 and :1217 (guessed from the SATA
// attribute table), ataprint.cpp:1825 (Device Statistics page 7, which
// overrides the guess) and nvmeprint.cpp:505 and :511 — so a bare number is a
// shape upstream cannot produce, and modelling one was #615.
//
// That mismodelling did not merely blank two gauges: json.Unmarshal failed on
// the whole smartInfo body, which sent FetchSMARTDevices down its per-device
// error path and cost every per-device SMART metric on the only box in the
// fleet with a real disk. Silently, at Debug level, with collector_success=1.
//
// ThresholdPercent is emitted for spare_available only — unconditionally by
// the NVMe path, and by the SATA path when 0 < threshold < 50. No emitter
// writes it for endurance_used; the field is shared here because the wrapper
// object is the same shape, not as a claim that endurance carries a threshold.
// Nothing exports it yet (#615 keeps the metric surface unchanged); it is a
// candidate gauge, not part of that fix.
type smartWearPercent struct {
	CurrentPercent   *float64 `json:"current_percent"`
	ThresholdPercent *float64 `json:"threshold_percent"`
}

// smartAtaAttributes mirrors the smartctl -a -j SATA attribute table.
type smartAtaAttributes struct {
	Table []smartAtaAttribute `json:"table"`
}

type smartAtaAttribute struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Value  int64  `json:"value"`
	Worst  int64  `json:"worst"`
	Thresh int64  `json:"thresh"`
	Raw    struct {
		Value float64 `json:"value"`
	} `json:"raw"`

	// WhenFailed is smartctl's own attribute-level failed marker
	// (ataprint.cpp:1334): "now", "past", or "" for an attribute that has
	// never crossed its threshold. Always emitted per attribute row (not
	// conditional), so a plain string is enough — no presence-gating needed
	// here, unlike RotationRate above.
	WhenFailed string `json:"when_failed"`
}

// smartNVMeHealthLog mirrors the smartctl -a -j NVMe health information log.
// Pointers: absent fields stay nil and emit no metric.
type smartNVMeHealthLog struct {
	AvailableSpare   *float64 `json:"available_spare"`
	PercentageUsed   *float64 `json:"percentage_used"`
	MediaErrors      *float64 `json:"media_errors"`
	UnsafeShutdowns  *float64 `json:"unsafe_shutdowns"`
	DataUnitsRead    *float64 `json:"data_units_read"`
	DataUnitsWritten *float64 `json:"data_units_written"`
}

type smartStatus struct {
	Passed bool `json:"passed"`
}

type smartTemp struct {
	Current *float64 `json:"current"`
}

type smartPowerOnTime struct {
	Hours *float64 `json:"hours"`
}

// SMARTAttribute is one row of a SATA drive's SMART attribute table.
type SMARTAttribute struct {
	ID        int64
	Value     int64
	Worst     int64
	Threshold int64
	Name      string
	// Raw is the raw attribute value; float64 because values like
	// Total_LBAs_Written exceed int32 (and float64 precision is ample).
	Raw float64
	// WhenFailed is "now", "past", or "" (never failed). See smartAtaAttribute
	// for why this is a plain string rather than presence-gated (#577).
	WhenFailed string
}

// SMARTNVMe holds the NVMe health information log fields we export.
type SMARTNVMe struct {
	AvailableSpare, PercentageUsed, MediaErrors,
	UnsafeShutdowns, DataUnitsRead, DataUnitsWritten *float64
}

// SMARTDevice is the normalised representation of one disk's SMART data.
type SMARTDevice struct {
	// Device is the bare device name (e.g. "ada0", "nvme0").
	Device string

	// Model is the drive model name. Empty string if absent.
	Model string

	// Serial is the drive serial number. Empty string if absent.
	Serial string

	// Health is nil when the SMART status was not available.
	Health *bool

	// Temperature is nil when temperature data was not available.
	Temperature *float64

	// PowerOnHours is nil when power-on time was not available.
	PowerOnHours *float64

	// Attributes is the SATA SMART attribute table (empty for NVMe drives).
	Attributes []SMARTAttribute

	// NVMe is the NVMe health log (nil for SATA drives).
	NVMe *SMARTNVMe

	// RotationRate is nil when the drive didn't report ATA IDENTIFY word 217
	// at all. 0 is a real, meaningful reading (SSD), not an absence (#577).
	RotationRate *float64

	// SpareAvailable and EnduranceUsed are smartctl's normalized SSD wear
	// percentages. Nil when smartctl couldn't derive them for this drive
	// (#577).
	SpareAvailable *float64
	EnduranceUsed  *float64
}

// SMARTDevices holds the aggregated result of FetchSMARTDevices.
type SMARTDevices struct {
	// Present is false when the os-smart plugin is not installed (list endpoint
	// 404s). The collector gates all emission on this so it stays silent on
	// boxes without the plugin.
	Present bool

	// Devices is the list of parsed devices. Only devices whose info call
	// succeeded and returned an output block are fully populated; others
	// may have nil pointer fields.
	Devices []SMARTDevice

	// DeviceCount is the count of device names returned by the list endpoint,
	// regardless of whether their info calls succeeded.
	DeviceCount int

	// InfoFailures counts devices whose info call produced nothing usable —
	// a transport error, a non-2xx, or a body that was not JSON at all. Those
	// devices are reported by name only.
	//
	// InfoPartialDecodes counts devices whose info body was valid JSON that
	// disagreed with our schema on at least one field. Those devices ARE kept,
	// carrying every field that did decode; only the mismatched ones are
	// missing.
	//
	// Both are exported so the collector can surface them. #615 was invisible
	// for as long as it was precisely because the per-device failure path was
	// a Debug log and nothing else, while the collector went on reporting
	// success — so shape drift on this endpoint must never again be silent.
	InfoFailures       int
	InfoPartialDecodes int
}

// FetchSMARTDevices calls the os-smart plugin API to enumerate disks and
// fetch per-disk SMART data. It returns an error only when the list endpoint
// itself fails (e.g. plugin not installed → 404). Individual disk info
// failures are logged at debug level and result in a device entry with nil
// optional fields; they do not abort the whole fetch.
func (c *Client) FetchSMARTDevices() (SMARTDevices, *APICallError) {
	var data SMARTDevices

	listURL, ok := c.endpoints["smartList"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "smartList",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	infoURL, ok := c.endpoints["smartInfo"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "smartInfo",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	// Step 1: list devices via empty form POST. The os-smart plugin requires
	// POST for every action: a GET returns HTTP 200 with
	// {"message":"Unable to run list action"} and no devices (verified against
	// os-smart 2.4 plugin source and a live 26.1 box) — do not "simplify" this
	// to a GET.
	var listResp smartListResponse
	if err := c.doForm(listURL, url.Values{}, &listResp); err != nil {
		// os-smart plugin not installed → endpoint 404s. Treat as "feature
		// absent" (empty data with Present=false, no error) so the collector,
		// which is enabled by default, stays quiet on boxes without the plugin.
		if err.StatusCode == http.StatusNotFound {
			return data, nil
		}
		return data, err
	}

	data.Present = true
	data.DeviceCount = len(listResp.Devices)

	// Step 2: fetch info for each device.
	for _, deviceName := range listResp.Devices {
		form := url.Values{}
		form.Set("device", deviceName)
		form.Set("type", "a")
		form.Set("json", "1")

		var infoResp smartInfoResponse
		if err := c.doForm(infoURL, form, &infoResp); err != nil {
			// A shape disagreement on one field must not cost the device its
			// health, temperature, power-on hours and whole attribute table
			// (#615). encoding/json has already written every field it
			// understood, so keep what decoded and count the drift instead.
			if err.PartialDecode && infoResp.Output != nil {
				c.log.Warn("smart info payload disagreed with our schema; keeping the fields that did decode",
					"component", "opnsense-client",
					"device", deviceName,
					"err", err.Error())
				data.InfoPartialDecodes++
			} else {
				c.log.Warn("smart info call failed for device; reporting it by name only",
					"component", "opnsense-client",
					"device", deviceName,
					"err", err.Error())
				data.InfoFailures++
				data.Devices = append(data.Devices, SMARTDevice{Device: deviceName})
				continue
			}
		}

		dev := SMARTDevice{Device: deviceName}

		if out := infoResp.Output; out != nil {
			if out.ModelName != nil {
				dev.Model = *out.ModelName
			}
			if out.SerialNumber != nil {
				dev.Serial = *out.SerialNumber
			}
			if out.SmartStatus != nil {
				passed := out.SmartStatus.Passed
				dev.Health = &passed
			}
			if out.Temperature != nil && out.Temperature.Current != nil {
				temp := *out.Temperature.Current
				dev.Temperature = &temp
			}
			if out.PowerOnTime != nil && out.PowerOnTime.Hours != nil {
				hours := *out.PowerOnTime.Hours
				dev.PowerOnHours = &hours
			}
			if out.AtaSmartAttributes != nil {
				for _, a := range out.AtaSmartAttributes.Table {
					dev.Attributes = append(dev.Attributes, SMARTAttribute{
						ID:         a.ID,
						Name:       a.Name,
						Value:      a.Value,
						Worst:      a.Worst,
						Threshold:  a.Thresh,
						Raw:        a.Raw.Value,
						WhenFailed: a.WhenFailed,
					})
				}
			}
			if out.RotationRate != nil {
				rpm := *out.RotationRate
				dev.RotationRate = &rpm
			}
			if out.SpareAvailable != nil && out.SpareAvailable.CurrentPercent != nil {
				spare := *out.SpareAvailable.CurrentPercent
				dev.SpareAvailable = &spare
			}
			if out.EnduranceUsed != nil && out.EnduranceUsed.CurrentPercent != nil {
				endurance := *out.EnduranceUsed.CurrentPercent
				dev.EnduranceUsed = &endurance
			}
			if n := out.NVMeHealth; n != nil {
				dev.NVMe = &SMARTNVMe{
					AvailableSpare:   n.AvailableSpare,
					PercentageUsed:   n.PercentageUsed,
					MediaErrors:      n.MediaErrors,
					UnsafeShutdowns:  n.UnsafeShutdowns,
					DataUnitsRead:    n.DataUnitsRead,
					DataUnitsWritten: n.DataUnitsWritten,
				}
			}
		}

		data.Devices = append(data.Devices, dev)
	}

	return data, nil
}
