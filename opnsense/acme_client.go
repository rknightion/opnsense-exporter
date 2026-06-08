package opnsense

import "net/http"

// acmeCertificateRow mirrors the JSON fields returned by the ACME client plugin
// api/acmeclient/certificates/search bootgrid endpoint.
//
// Field names confirmed from:
// https://raw.githubusercontent.com/opnsense/plugins/master/security/acme-client/src/opnsense/mvc/app/models/OPNsense/AcmeClient/AcmeClient.xml
// https://raw.githubusercontent.com/opnsense/plugins/master/security/acme-client/src/opnsense/mvc/app/views/OPNsense/AcmeClient/certificates.volt
//
// The model defines:
//   - enabled      BooleanField  (default 1)  — "0" or "1"
//   - name         TextField                  — common name / primary domain
//   - description  TextField                  — human-readable description
//   - altNames     CSVListField               — SAN list (comma-separated string or [])
//   - lastUpdate   IntegerField               — Unix timestamp of last issue/renewal
//   - statusCode   IntegerField  (default 100) — numeric ACME operation status
//   - statusLastUpdate IntegerField           — Unix timestamp of last ACME run
//
// The PHP serializer may return integer fields as numbers or empty arrays ([]) when
// never set, so flexString is used throughout for resilience.
type acmeCertificateRow struct {
	UUID             string     `json:"uuid"`
	Enabled          flexString `json:"enabled"`
	Name             flexString `json:"name"`
	Description      flexString `json:"description"`
	AltNames         flexString `json:"altNames"`
	LastUpdate       flexString `json:"lastUpdate"`
	StatusCode       flexString `json:"statusCode"`
	StatusLastUpdate flexString `json:"statusLastUpdate"`
}

type acmeCertificateSearchResponse struct {
	Total    int                  `json:"total"`
	RowCount int                  `json:"rowCount"`
	Current  int                  `json:"current"`
	Rows     []acmeCertificateRow `json:"rows"`
}

// ACMECertificate is the normalised representation of one ACME-managed certificate.
type ACMECertificate struct {
	Name             string
	Description      string
	AltNames         string
	Enabled          bool
	LastUpdate       float64 // Unix seconds; 0 means never updated
	StatusCode       float64 // numeric ACME status code (100 = default/unknown)
	StatusLastUpdate float64 // Unix seconds; 0 means never run
}

// ACMECertificates holds the aggregated result of FetchACMECertificates.
type ACMECertificates struct {
	Certificates []ACMECertificate
	Total        int
}

// FetchACMECertificates calls the ACME client certificates search endpoint and
// returns aggregated certificate data.
//
// If the os-acme-client plugin is not installed the endpoint returns HTTP 404
// (verified against a live OPNsense 26.1 box). That is treated as "feature
// absent" — empty data with no error — so boxes without the plugin do not log
// errors or increment endpoint counters on every scrape.
func (c *Client) FetchACMECertificates() (ACMECertificates, *APICallError) {
	var resp acmeCertificateSearchResponse
	var data ACMECertificates

	url, ok := c.endpoints["acmeCertificates"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "acmeCertificates",
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

	data.Total = resp.Total

	for _, row := range resp.Rows {
		cert := ACMECertificate{
			Name:             row.Name.String(),
			Description:      row.Description.String(),
			AltNames:         row.AltNames.String(),
			Enabled:          parseStringToBool(row.Enabled.String()),
			LastUpdate:       safeParseFloat(row.LastUpdate.String()),
			StatusCode:       safeParseFloat(row.StatusCode.String()),
			StatusLastUpdate: safeParseFloat(row.StatusLastUpdate.String()),
		}
		data.Certificates = append(data.Certificates, cert)
	}

	return data, nil
}
