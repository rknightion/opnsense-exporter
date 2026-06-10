package opnsense

// caRow mirrors api/trust/ca/search bootgrid rows.
//
// SECURITY: rows also contain crt/prv/crt_payload/prv_payload — the CA
// certificate AND PRIVATE KEY. They are deliberately not captured here so key
// material never enters exporter memory beyond the transient response buffer,
// and the client's sensitive-field redaction covers "prv" for the error path.
type caRow struct {
	UUID       string `json:"uuid"`
	Descr      string `json:"descr"`
	CommonName string `json:"commonname"`
	ValidFrom  string `json:"valid_from"`
	ValidTo    string `json:"valid_to"`
}

type caSearchResponse struct {
	Rows []caRow `json:"rows"`
}

// CACertificate is one certificate authority's validity window.
type CACertificate struct {
	Description string
	CommonName  string
	ValidFrom   float64
	ValidTo     float64
}

// CACertificates holds the result of FetchCACertificates.
type CACertificates struct {
	CAs   []CACertificate
	Total int
}

// FetchCACertificates returns the certificate authorities known to the trust
// store with their validity timestamps (unix seconds, arriving as strings —
// same encoding as leaf certificates).
func (c *Client) FetchCACertificates() (CACertificates, *APICallError) {
	var resp caSearchResponse
	var data CACertificates

	url, ok := c.endpoints["caCertificates"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "caCertificates",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	data.Total = len(resp.Rows)
	for _, row := range resp.Rows {
		data.CAs = append(data.CAs, CACertificate{
			Description: row.Descr,
			CommonName:  row.CommonName,
			ValidFrom:   safeParseFloat(row.ValidFrom),
			ValidTo:     safeParseFloat(row.ValidTo),
		})
	}
	return data, nil
}

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
