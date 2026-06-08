package opnsense

import "net/url"

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
	ModelName    *string           `json:"model_name"`
	SerialNumber *string           `json:"serial_number"`
	SmartStatus  *smartStatus      `json:"smart_status"`
	Temperature  *smartTemp        `json:"temperature"`
	PowerOnTime  *smartPowerOnTime `json:"power_on_time"`
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
}

// SMARTDevices holds the aggregated result of FetchSMARTDevices.
type SMARTDevices struct {
	// Devices is the list of parsed devices. Only devices whose info call
	// succeeded and returned an output block are fully populated; others
	// may have nil pointer fields.
	Devices []SMARTDevice

	// DeviceCount is the count of device names returned by the list endpoint,
	// regardless of whether their info calls succeeded.
	DeviceCount int
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

	// Step 1: list devices via empty form POST.
	var listResp smartListResponse
	if err := c.doForm(listURL, url.Values{}, &listResp); err != nil {
		return data, err
	}

	data.DeviceCount = len(listResp.Devices)

	// Step 2: fetch info for each device.
	for _, deviceName := range listResp.Devices {
		form := url.Values{}
		form.Set("device", deviceName)
		form.Set("type", "a")
		form.Set("json", "1")

		var infoResp smartInfoResponse
		if err := c.doForm(infoURL, form, &infoResp); err != nil {
			c.log.Debug("smart info call failed for device; skipping",
				"component", "opnsense-client",
				"device", deviceName,
				"err", err.Error())
			data.Devices = append(data.Devices, SMARTDevice{Device: deviceName})
			continue
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
		}

		data.Devices = append(data.Devices, dev)
	}

	return data, nil
}
