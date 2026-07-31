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
	// Refcount is how many OTHER config nodes reference this CA (#583).
	// Upstream computes it in Trust/FieldTypes/CAsField.php:112-118 as
	// count(xpath("//*[text() = '<refid>']")) - 1 — the -1 drops the CA's own
	// refid node — and assigns it with an explicit (string) cast, so the wire
	// value is a string-encoded integer on both releases in the support window
	// (stable/26.1 and stable/26.7 are byte-identical here). flexInt covers the
	// string form and a future bare-number form without a code change.
	//
	// POINTER on purpose: upstream sets the field unconditionally, so nil means
	// the key genuinely was not there (an older/other generation), which is a
	// different fact from "referenced by nothing". Only the second is safe to
	// alert on, so the collector must emit no series for nil rather than a 0.
	Refcount *flexInt `json:"refcount"`
}

type caSearchResponse struct {
	Rows []caRow `json:"rows"`
}

// CACertificate is one certificate authority's validity window.
type CACertificate struct {
	Description  string
	CommonName   string
	ValidFrom    float64
	HasValidFrom bool
	ValidTo      float64
	HasValidTo   bool
	// References is upstream's refcount: how many other config nodes use this
	// CA (#583). It is what separates "a CA 20 days from expiry that 50 things
	// depend on" (an outage in three weeks) from "a CA 20 days from expiry that
	// nothing uses" (dead config) — the validity window alone cannot tell them
	// apart. HasReferences is false when the key was absent; never treat the
	// zero value as a real refcount of 0.
	References    float64
	HasReferences bool
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
		validFrom, hasFrom := safeParseFloatOK(row.ValidFrom)
		validTo, hasTo := safeParseFloatOK(row.ValidTo)
		ca := CACertificate{
			Description:  row.Descr,
			CommonName:   row.CommonName,
			ValidFrom:    validFrom,
			HasValidFrom: hasFrom,
			ValidTo:      validTo,
			HasValidTo:   hasTo,
		}
		if row.Refcount != nil {
			ca.References = float64(row.Refcount.Int())
			ca.HasReferences = true
		}
		data.CAs = append(data.CAs, ca)
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
	Description  string
	CommonName   string
	CertType     string
	InUse        string
	ValidFrom    float64
	HasValidFrom bool
	ValidTo      float64
	HasValidTo   bool
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
		// A pending CSR (crt empty, csr populated) or an unparseable cert blob
		// leaves valid_from/valid_to as empty strings — track whether they parsed
		// so the collector can skip the expiry metric rather than emit epoch 0,
		// which reads as "expired since 1970" (#167).
		validFrom, hasFrom := safeParseFloatOK(row.ValidFrom)
		validTo, hasTo := safeParseFloatOK(row.ValidTo)
		cert := Certificate{
			Description:  row.Descr,
			CommonName:   row.CommonName,
			CertType:     row.CertType,
			InUse:        row.InUse,
			ValidFrom:    validFrom,
			HasValidFrom: hasFrom,
			ValidTo:      validTo,
			HasValidTo:   hasTo,
		}

		data.Certificates = append(data.Certificates, cert)
	}

	return data, nil
}
