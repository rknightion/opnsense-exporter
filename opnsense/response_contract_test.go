package opnsense

import (
	"os"
	"path/filepath"
	"testing"
)

// TestResponseContracts validates every captured fixture for every registered
// response contract: top-level keys stay within the known set (a new key is a
// drift signal), and the semantic validator passes (the consumed data decodes
// into usable values). This catches payload-shape drift at an UNCHANGED endpoint
// — the class the endpoint-manifest canary (cmd/apicontract) cannot see, because
// the path and HTTP verb are identical (e.g. OPNsense 26.1 moving per-subsystem
// health into a top-level "subsystems" map). Refresh fixtures from a real/beta
// box with `make capture` to catch a new OPNsense release early.
func TestResponseContracts(t *testing.T) {
	contracts := ResponseContracts()
	if len(contracts) == 0 {
		t.Fatal("no response contracts registered")
	}
	for _, contract := range contracts {
		t.Run(string(contract.Endpoint), func(t *testing.T) {
			fixtures, err := contract.Fixtures()
			if err != nil {
				t.Fatalf("resolve fixtures: %v", err)
			}
			if len(fixtures) == 0 {
				t.Fatalf("contract %s has no fixtures (globs %v) — capture at least one real response",
					contract.Endpoint, contract.FixtureGlobs)
			}
			for _, f := range fixtures {
				t.Run(filepath.Base(f), func(t *testing.T) {
					raw, err := os.ReadFile(f)
					if err != nil {
						t.Fatalf("read %s: %v", f, err)
					}
					unknown, err := contract.UnknownTopLevelKeys(raw)
					if err != nil {
						t.Fatalf("parse top-level: %v", err)
					}
					if len(unknown) > 0 {
						t.Errorf("unexpected top-level key(s) %v — OPNsense may have added/moved data the exporter does not model; "+
							"after confirming it is consumed, add it to the struct and KnownTopLevelKeys", unknown)
					}
					if contract.Validate != nil {
						if err := contract.Validate(raw); err != nil {
							t.Errorf("response contract failed: %v", err)
						}
					}
				})
			}
		})
	}
}

func TestUnknownTopLevelKeys(t *testing.T) {
	c := ResponseContract{KnownTopLevelKeys: []string{"metadata", "subsystems"}}

	// Known keys (any case) → no drift.
	if got, err := c.UnknownTopLevelKeys([]byte(`{"metadata":{},"Subsystems":[]}`)); err != nil || len(got) != 0 {
		t.Errorf("known keys: got %v err %v, want none", got, err)
	}
	// A new top-level key → flagged (this is how 26.1's "subsystems" first appeared).
	got, err := c.UnknownTopLevelKeys([]byte(`{"metadata":{},"brand_new_field":1}`))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(got) != 1 || got[0] != "brand_new_field" {
		t.Errorf("got %v, want [brand_new_field]", got)
	}
}

func TestValidateHealthResponse_DriftDetection(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{"healthy 26.1", `{"metadata":{"system":{"status":"OK"}},"subsystems":[]}`, false},
		{"degraded 26.1 consumed", `{"metadata":{"system":{"status":"ERROR"}},"subsystems":{"crashreporter":{"status":"ERROR","statusCode":-1}}}`, false},
		{"numeric metadata status", `{"metadata":{"System":{"status":2}}}`, false},
		// Drift: a future/unknown overall status enum that would silently resolve to 0.
		{"unrecognized status enum", `{"metadata":{"system":{"status":"MELTDOWN"}}}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateHealthResponse([]byte(tc.raw))
			if (err != nil) != tc.wantErr {
				t.Errorf("validateHealthResponse() err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
