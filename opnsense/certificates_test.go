package opnsense

import (
	"math"
	"net/http"
	"testing"
)

func TestFetchCertificates_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"total": 3,
			"rows": [
				{
					"uuid": "abc-123",
					"descr": "Web Server Cert",
					"commonname": "fw.example.com",
					"valid_from": "1704067200",
					"valid_to": "1735689600",
					"in_use": "webgui",
					"%cert_type": "server"
				},
				{
					"uuid": "def-456",
					"descr": "CA Certificate",
					"commonname": "Internal CA",
					"valid_from": "1672531200",
					"valid_to": "1767225600",
					"in_use": "",
					"%cert_type": "ca"
				},
				{
					"uuid": "ghi-789",
					"descr": "Expired Cert",
					"commonname": "old.example.com",
					"valid_from": "",
					"valid_to": "",
					"in_use": "",
					"%cert_type": "server"
				}
			]
		}`))
	})
	defer server.Close()

	data, err := client.FetchCertificates()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.Total != 3 {
		t.Errorf("expected Total=3, got %d", data.Total)
	}
	if len(data.Certificates) != 3 {
		t.Fatalf("expected 3 certificates, got %d", len(data.Certificates))
	}

	// First cert
	c1 := data.Certificates[0]
	if c1.Description != "Web Server Cert" {
		t.Errorf("expected description 'Web Server Cert', got %q", c1.Description)
	}
	if c1.CommonName != "fw.example.com" {
		t.Errorf("expected common name 'fw.example.com', got %q", c1.CommonName)
	}
	if c1.ValidFrom != 1704067200.0 {
		t.Errorf("expected ValidFrom=1704067200, got %f", c1.ValidFrom)
	}
	if c1.ValidTo != 1735689600.0 {
		t.Errorf("expected ValidTo=1735689600, got %f", c1.ValidTo)
	}
	if c1.InUse != "webgui" {
		t.Errorf("expected InUse='webgui', got %q", c1.InUse)
	}
	if c1.CertType != "server" {
		t.Errorf("expected CertType='server', got %q", c1.CertType)
	}

	// Third cert: empty valid_from/valid_to (a pending CSR / unparseable blob)
	// must be flagged as absent, distinct from a genuine epoch 0 (#167).
	c3 := data.Certificates[2]
	if c3.HasValidFrom {
		t.Error("expected HasValidFrom=false for empty valid_from")
	}
	if c3.HasValidTo {
		t.Error("expected HasValidTo=false for empty valid_to")
	}
	// A populated cert must still report HasValidFrom/HasValidTo=true.
	if !c1.HasValidFrom || !c1.HasValidTo {
		t.Error("expected populated cert to have HasValidFrom/HasValidTo=true")
	}
}

func TestFetchCertificates_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchCertificates()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

func TestFetchCACertificates_Success(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/trust/ca/search", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"rows": [
				{
					"uuid": "02030146-47b3-4ecb-8eae-c45b218161c8",
					"refid": "61f055d56326f",
					"descr": "OPNsense-CA",
					"commonname": "OPNsense-CA",
					"serial": "2",
					"refcount": "1",
					"valid_from": "1643140565",
					"valid_to": "1958500565",
					"crt": "IGNORED",
					"prv": "MUST-NEVER-BE-PARSED",
					"crt_payload": "IGNORED",
					"prv_payload": "MUST-NEVER-BE-PARSED"
				}
			],
			"rowCount": 1,
			"total": 1,
			"current": 1
		}`))
	})

	data, err := client.FetchCACertificates()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.Total != 1 {
		t.Errorf("expected Total=1, got %d", data.Total)
	}
	if len(data.CAs) != 1 {
		t.Fatalf("expected 1 CA, got %d", len(data.CAs))
	}
	ca := data.CAs[0]
	if ca.Description != "OPNsense-CA" || ca.CommonName != "OPNsense-CA" {
		t.Errorf("unexpected CA names: %+v", ca)
	}
	if ca.ValidFrom != 1643140565 || ca.ValidTo != 1958500565 {
		t.Errorf("unexpected CA validity: %+v", ca)
	}
}

// TestFetchCertificates_NonFiniteValidTo is the #323 regression test for the
// sibling that matters most: certificates.go uses safeParseFloatOK precisely
// to distinguish an absent valid_to (a pending CSR) from a real one, and the
// collector gates cert_valid_to_seconds on the ok flag. strconv.ParseFloat
// accepts "NaN" without an error, so a NaN was reported as present, emitted as
// a gauge, and every `cert_valid_to_seconds - time() < 30d` expiry alert
// silently stopped firing for that certificate.
func TestFetchCertificates_NonFiniteValidTo(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 1,
			"rows": [
				{
					"uuid": "nan-1",
					"descr": "Broken Cert",
					"commonname": "broken.example.com",
					"valid_from": "Inf",
					"valid_to": "NaN",
					"in_use": "",
					"%cert_type": "server"
				}
			]
		}`))
	})
	defer server.Close()

	data, err := client.FetchCertificates()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(data.Certificates))
	}
	c := data.Certificates[0]
	if c.HasValidTo {
		t.Errorf("expected HasValidTo=false for a NaN valid_to, got true (value=%v)", c.ValidTo)
	}
	if c.HasValidFrom {
		t.Errorf("expected HasValidFrom=false for an Inf valid_from, got true (value=%v)", c.ValidFrom)
	}
	if math.IsNaN(c.ValidTo) || math.IsInf(c.ValidTo, 0) {
		t.Errorf("ValidTo is non-finite: %v", c.ValidTo)
	}
	if math.IsNaN(c.ValidFrom) || math.IsInf(c.ValidFrom, 0) {
		t.Errorf("ValidFrom is non-finite: %v", c.ValidFrom)
	}
}

// TestFetchCACertificates_NonFiniteValidTo covers the CA half of the same
// path (ca_valid_to_seconds).
func TestFetchCACertificates_NonFiniteValidTo(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{
					"descr": "Broken CA",
					"commonname": "Broken CA",
					"valid_from": "1672531200",
					"valid_to": "NaN"
				}
			]
		}`))
	})
	defer server.Close()

	data, err := client.FetchCACertificates()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.CAs) != 1 {
		t.Fatalf("expected 1 CA, got %d", len(data.CAs))
	}
	ca := data.CAs[0]
	if ca.HasValidTo {
		t.Errorf("expected HasValidTo=false for a NaN valid_to, got true (value=%v)", ca.ValidTo)
	}
	if !ca.HasValidFrom || ca.ValidFrom != 1672531200 {
		t.Errorf("expected the finite valid_from to still parse, got (%v, %v)", ca.ValidFrom, ca.HasValidFrom)
	}
}
