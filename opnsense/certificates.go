package opnsense

type certificateRow struct {
	UUID       string `json:"uuid"`
	Descr      string `json:"descr"`
	CommonName string `json:"commonname"`
	ValidFrom  string `json:"valid_from"`
	ValidTo    string `json:"valid_to"`
	InUse      string `json:"in_use"`
	CertType   string `json:"%cert_type"`
}

type certificateSearchResponse struct {
	Total int              `json:"total"`
	Rows  []certificateRow `json:"rows"`
}

type Certificate struct {
	Description string
	CommonName  string
	CertType    string
	InUse       string
	ValidFrom   float64
	ValidTo     float64
}

type CertificateStatus struct {
	Certificates []Certificate
	Total        int
}

func (c *Client) FetchCertificates() (CertificateStatus, *APICallError) {
	var resp certificateSearchResponse
	var data CertificateStatus

	url, ok := c.endpoints["certificates"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "certificates",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	data.Total = resp.Total

	for _, row := range resp.Rows {
		cert := Certificate{
			Description: row.Descr,
			CommonName:  row.CommonName,
			CertType:    row.CertType,
			InUse:       row.InUse,
			ValidFrom:   safeParseFloat(row.ValidFrom),
			ValidTo:     safeParseFloat(row.ValidTo),
		}

		data.Certificates = append(data.Certificates, cert)
	}

	return data, nil
}
