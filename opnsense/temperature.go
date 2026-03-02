package opnsense

type temperatureReading struct {
	Device         string `json:"device"`
	DeviceSeq      int    `json:"device_seq"`
	Temperature    string `json:"temperature"`
	TypeTranslated string `json:"type_translated"`
	Type           string `json:"type"`
}

type TemperatureReading struct {
	Device    string
	DeviceSeq int
	Type      string
	Celsius   float64
}

func (c *Client) FetchTemperatures() ([]TemperatureReading, *APICallError) {
	var resp []temperatureReading

	url, ok := c.endpoints["systemTemperature"]
	if !ok {
		return nil, &APICallError{
			Endpoint:   "systemTemperature",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return nil, err
	}

	readings := make([]TemperatureReading, 0, len(resp))
	for _, r := range resp {
		readings = append(readings, TemperatureReading{
			Device:    r.Device,
			DeviceSeq: r.DeviceSeq,
			Type:      r.Type,
			Celsius:   safeParseFloat(r.Temperature),
		})
	}

	return readings, nil
}
