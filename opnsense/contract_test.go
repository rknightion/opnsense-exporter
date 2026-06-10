package opnsense

import "testing"

func TestContractManifestCoversAllEndpoints(t *testing.T) {
	manifest := ContractManifest()
	endpoints := defaultEndpoints()
	if len(manifest) != len(endpoints) {
		t.Fatalf("manifest has %d entries, endpoints has %d", len(manifest), len(endpoints))
	}
	for name, path := range endpoints {
		ec, ok := manifest[name]
		if !ok {
			t.Errorf("endpoint %q missing from manifest", name)
			continue
		}
		if ec.Path != path {
			t.Errorf("endpoint %q: manifest path %q != endpoints path %q", name, ec.Path, path)
		}
		if ec.Method != "GET" && ec.Method != "POST" {
			t.Errorf("endpoint %q: invalid method %q", name, ec.Method)
		}
	}
}

func TestPostEndpointsAreKnownAndCounted(t *testing.T) {
	endpoints := defaultEndpoints()
	for name := range postEndpoints {
		if _, ok := endpoints[name]; !ok {
			t.Errorf("postEndpoints contains unknown endpoint %q", name)
		}
	}
	if len(postEndpoints) != 14 {
		t.Errorf("expected 14 POST endpoints, got %d", len(postEndpoints))
	}
	manifest := ContractManifest()
	postCount := 0
	for _, ec := range manifest {
		if ec.Method == "POST" {
			postCount++
		}
	}
	if postCount != 14 {
		t.Errorf("expected 14 POST entries in manifest, got %d", postCount)
	}
}
