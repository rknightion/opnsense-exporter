package opnsense

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// dropJSONKey removes one top-level key from a JSON object literal, so a
// "complete real SA" fixture can be minted once and then holed one key at a
// time. Re-encoding rather than string surgery keeps the fixture valid whatever
// the key's position or value type.
func dropJSONKey(t *testing.T, obj, key string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(obj), &m); err != nil {
		t.Fatalf("fixture is not valid JSON: %v", err)
	}
	if _, ok := m[key]; !ok {
		t.Fatalf("fixture does not carry %q, so dropping it proves nothing", key)
	}
	delete(m, key)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("re-encode fixture: %v", err)
	}
	return string(out)
}

// ipsecSadSchema returns the real reflected ipsecSad schema, so these tests
// exercise the field set the canary actually validates rather than a
// hand-written stand-in that could drift from ipsecSadRow.
func ipsecSadSchema(t *testing.T) EndpointSchema {
	t.Helper()
	all, err := AllEndpointSchemas()
	if err != nil {
		t.Fatalf("AllEndpointSchemas: %v", err)
	}
	for _, s := range all {
		if s.Endpoint == "ipsecSad" {
			return s
		}
	}
	t.Fatal("ipsecSad not in the schema registry")
	return EndpointSchema{}
}

// The six counters #578 exports. They must never be exempted, and must stay
// enforced whenever a real SA is present (#618).
var ipsecSadCounterPaths = []string{
	"rows[].allocated",
	"rows[].allocated_hard",
	"rows[].allocated_soft",
	"rows[].bytes_current",
	"rows[].bytes_hard",
	"rows[].bytes_soft",
}

// TestIsIPsecSADPlaceholderRow pins the discriminator the client and the probe
// share. A real SA always carries both; the placeholder carries neither.
func TestIsIPsecSADPlaceholderRow(t *testing.T) {
	cases := []struct {
		name        string
		spi, satype string
		want        bool
	}{
		{"real SA", "c6524517", "esp", false},
		{"placeholder, both null", "", "", true},
		{"spi only", "c6524517", "", true},
		{"satype only", "", "esp", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsIPsecSADPlaceholderRow(tc.spi, tc.satype); got != tc.want {
				t.Errorf("IsIPsecSADPlaceholderRow(%q, %q) = %v, want %v", tc.spi, tc.satype, got, tc.want)
			}
		})
	}
}

// TestValidateIPsecSADEmptySADB is the regression this exists for: on a box with
// no security associations, the probe must report the endpoint as zero rows and
// find nothing missing, rather than reading setkey's "No SAD entries." sentence
// as an SA that has lost eleven fields.
func TestValidateIPsecSADEmptySADB(t *testing.T) {
	res, err := ValidateResponseSchema(ipsecSadSchema(t), []byte(ipsecSadEmptyFixture), SchemaExemption{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Missing) != 0 {
		t.Errorf("empty SADB must produce no Missing findings, got %v", res.Missing)
	}
	if len(res.Mismatches) != 0 {
		t.Errorf("empty SADB must produce no Mismatches, got %v", res.Mismatches)
	}
	// Every rows[] path should read Unverified — there is nothing to check, which
	// is a different and honest answer from "the key is gone".
	for _, p := range ipsecSadCounterPaths {
		if !contains(res.Unverified, p) {
			t.Errorf("expected %s to be Unverified on an empty SADB, got Unverified=%v", p, res.Unverified)
		}
	}
}

// TestValidateIPsecSADRealRowStillChecked is the other half of the acceptance
// bar. Dropping the placeholder must not become a way of dropping enforcement:
// a payload holding one real SA alongside a placeholder still validates the
// real one, and a real SA MISSING a counter is still reported.
func TestValidateIPsecSADRealRowStillChecked(t *testing.T) {
	// NAT-traversed on purpose: rows[].nat is the one field legitimately absent
	// on a non-NAT-T SA and carries a base-scope missingOK for it. Including it
	// lets these cases run with NO exemption at all, which is a stronger claim —
	// the six counters are shown enforced on their own merit, not because an
	// exemption happened to be quiet.
	const realRow = `{"src":"10.0.0.1","dst":"10.0.0.2","satype":"esp","spi":"c6524517",` +
		`"reqid":1,"state":"mature","nat":"4500",` +
		`"addtime_diff":42,"addtime_hard":3600,"addtime_soft":3000,` +
		`"ikeid":"1","phase1desc":"p1","phase2desc":"p2",` +
		`"bytes_current":"1024","bytes_hard":"0","bytes_soft":"0",` +
		`"allocated":"7","allocated_hard":"0","allocated_soft":"0"}`
	const placeholderRow = `{"src":"No","dst":"SAD","satype":null,"spi":null,"nat":"ntries",` +
		`"id":"x","ikeid":null,"phase1desc":null,"phase2desc":null}`

	t.Run("complete real row plus placeholder is clean", func(t *testing.T) {
		raw := `{"total":2,"rowCount":2,"current":1,"rows":[` + realRow + `,` + placeholderRow + `]}`
		res, err := ValidateResponseSchema(ipsecSadSchema(t), []byte(raw), SchemaExemption{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(res.Missing) != 0 {
			t.Errorf("a complete SA must produce no Missing findings, got %v", res.Missing)
		}
		for _, p := range ipsecSadCounterPaths {
			if contains(res.Unverified, p) {
				t.Errorf("%s must be genuinely CHECKED when a real SA is present, not Unverified", p)
			}
		}
	})

	// One case per counter: strip it from the real row and confirm the probe
	// still catches it. A single combined case would pass even if the walker
	// stopped at the first absent key.
	for _, path := range ipsecSadCounterPaths {
		key := strings.TrimPrefix(path, "rows[].")
		t.Run("real row missing "+key+" is still reported", func(t *testing.T) {
			stripped := dropJSONKey(t, realRow, key)
			raw := `{"total":2,"rowCount":2,"current":1,"rows":[` + stripped + `,` + placeholderRow + `]}`
			res, err := ValidateResponseSchema(ipsecSadSchema(t), []byte(raw), SchemaExemption{})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !contains(res.Missing, path) {
				t.Errorf("dropping %s from a real SA must be reported as Missing, got Missing=%v", path, res.Missing)
			}
		})
	}
}

// TestIPsecSADHasNoPlaceholderExemption guards the ledger against the fix being
// undone by an exemption. These six paths back exported metrics, so a missingOK
// on any of them — at base scope or any profile — blinds the canary to real
// drift on a consumed field, which is exactly what #618 removed.
func TestIPsecSADHasNoPlaceholderExemption(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "schemas", "exemptions.json"))
	if err != nil {
		t.Fatalf("read exemptions.json: %v", err)
	}
	var ledger map[string]SchemaExemption
	if err := json.Unmarshal(raw, &ledger); err != nil {
		t.Fatalf("parse exemptions.json: %v", err)
	}
	ex, ok := ledger["ipsecSad"]
	if !ok {
		return
	}
	scopes := map[string][]string{"base": ex.MissingOK}
	for name, p := range ex.Profiles {
		scopes[name] = p.MissingOK
	}
	for scope, paths := range scopes {
		for _, got := range paths {
			for _, banned := range ipsecSadCounterPaths {
				if got == banned {
					t.Errorf("%s scope exempts %s: it backs opnsense_ipsec_sa_* and must stay enforced (#618); "+
						"an empty SADB is handled by normalizeIPsecSADPayload, not by an exemption", scope, banned)
				}
			}
		}
	}
}

func contains(hay []string, needle string) bool {
	return slices.Contains(hay, needle)
}
