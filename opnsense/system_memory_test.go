package opnsense

import (
	"net/http"
	"testing"
)

// zoneByName is a test helper: KernelMemoryStatistics.Zones is a sorted slice, not a
// map, because the collector iterates it in a stable order.
func zoneByName(t *testing.T, s KernelMemoryStatistics, name string) KernelMemoryZone {
	t.Helper()
	for _, z := range s.Zones {
		if z.Name == name {
			return z
		}
	}
	t.Fatalf("zone %q not found in %d zones", name, len(s.Zones))
	return KernelMemoryZone{}
}

func mallocByName(t *testing.T, s KernelMemoryStatistics, name string) KernelMemoryMallocType {
	t.Helper()
	for _, m := range s.MallocTypes {
		if m.Name == name {
			return m
		}
	}
	t.Fatalf("malloc type %q not found in %d types", name, len(s.MallocTypes))
	return KernelMemoryMallocType{}
}

// systemMemoryFixture is a trimmed capture of api/diagnostics/system/memory taken
// from the live prod firewall (OPNsense 26.1) on 2026-07-30. Every row is verbatim
// from that capture with ONE deliberate edit: "256 Bucket" has sleep raised from 0
// to 3, because no zone on any of the three boxes had a non-zero sleep at capture
// time and the sleep path still needs coverage. That is a synthetic value, not a
// synthetic shape — sleep is a plain UMA counter on every row. Everything else,
// including the 144270 fail, is what the box actually reported.
//
// The fixture deliberately keeps the four shapes the parser has to survive:
//
//   - "pf state keys": limit == 0 while used == 16275, which is the live proof that
//     limit 0 means "no ceiling configured", not "ceiling of zero".
//   - "256 Bucket": a genuinely non-zero fail counter.
//   - "vm pgcache" x2 and "NetFlow IPv4 cache" x3: UMA reports one ROW PER NUMA
//     DOMAIN / per ng_netflow instance under a single zone name, so zone names are
//     NOT unique on the wire and must be merged or Prometheus rejects the scrape.
//   - "buffer arena-40" x2: duplicate rows whose item size DIFFERS (4096 vs 40960),
//     so the merge cannot assume the duplicates are identical.
const systemMemoryFixture = `{
  "__version": "2",
  "vmstat": {
    "malloc-statistics": {
      "memory": [
        {"type": "CAM periph", "in-use": 6, "memory-use": 1408, "requests": 1545, "size": [16, 32, 64, 128, 256, 512, 32768]},
        {"type": "dummynet", "in-use": 4, "memory-use": 1280, "requests": 124554, "size": [128, 256, 384, 512]},
        {"type": "dummynet", "in-use": 3, "memory-use": 2560, "requests": 3, "size": [512, 1024]},
        {"type": "pf_temp", "in-use": 0, "memory-use": 0, "requests": 11, "size": [16]}
      ]
    },
    "memory-zone-statistics": {
      "zone": [
        {"name": "pf states", "size": 328, "limit": 3258600, "used": 12780, "free": 10590, "requests": 41293921, "fail": 0, "sleep": 0, "xdomain": 0},
        {"name": "pf state keys", "size": 88, "limit": 0, "used": 16275, "free": 10727, "requests": 41314018, "fail": 0, "sleep": 0, "xdomain": 0},
        {"name": "256 Bucket", "size": 2072, "limit": 0, "used": 1281, "free": 141, "requests": 89163726, "fail": 144270, "sleep": 3, "xdomain": 0},
        {"name": "mbuf", "size": 256, "limit": 13041195, "used": 56806, "free": 5685, "requests": 1613640853, "fail": 0, "sleep": 0, "xdomain": 0},
        {"name": "vm pgcache", "size": 4096, "limit": 0, "used": 819065, "free": 2020, "requests": 1981217291, "fail": 8858, "sleep": 0, "xdomain": 0},
        {"name": "vm pgcache", "size": 4096, "limit": 0, "used": 2170293, "free": 3620, "requests": 398186153, "fail": 268, "sleep": 0, "xdomain": 0},
        {"name": "NetFlow IPv4 cache", "size": 88, "limit": 1048576, "used": 0, "free": 0, "requests": 0, "fail": 0, "sleep": 0, "xdomain": 0},
        {"name": "NetFlow IPv4 cache", "size": 88, "limit": 1048576, "used": 174, "free": 3890, "requests": 110164, "fail": 0, "sleep": 0, "xdomain": 1},
        {"name": "NetFlow IPv4 cache", "size": 88, "limit": 1048576, "used": 482, "free": 4862, "requests": 1386337, "fail": 0, "sleep": 0, "xdomain": 2},
        {"name": "buffer arena-40", "size": 4096, "limit": 0, "used": 0, "free": 0, "requests": 0, "fail": 0, "sleep": 0, "xdomain": 0},
        {"name": "buffer arena-40", "size": 40960, "limit": 0, "used": 0, "free": 0, "requests": 0, "fail": 0, "sleep": 0, "xdomain": 0}
      ]
    }
  }
}`

func TestFetchKernelMemory(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/diagnostics/system/memory" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(systemMemoryFixture))
	})
	defer server.Close()

	stats, err := client.FetchKernelMemory()
	if err != nil {
		t.Fatalf("FetchKernelMemory returned error: %v", err)
	}

	// 11 rows collapse to 7 distinct zone names.
	if got, want := len(stats.Zones), 7; got != want {
		t.Errorf("zone count = %d, want %d", got, want)
	}
	// 4 rows collapse to 3 distinct malloc types.
	if got, want := len(stats.MallocTypes), 3; got != want {
		t.Errorf("malloc type count = %d, want %d", got, want)
	}

	t.Run("scalar zone fields decode", func(t *testing.T) {
		z := zoneByName(t, stats, "pf states")
		if z.ItemSizeBytes != 328 || z.Limit != 3258600 || z.Used != 12780 ||
			z.Free != 10590 || z.Requests != 41293921 || z.Failures != 0 ||
			z.Sleeps != 0 || z.XDomain != 0 || z.Rows != 1 {
			t.Errorf("pf states = %+v", z)
		}
	})

	t.Run("limit 0 with used > 0 is preserved verbatim", func(t *testing.T) {
		z := zoneByName(t, stats, "pf state keys")
		if z.Limit != 0 {
			t.Errorf("pf state keys Limit = %d, want 0 (no ceiling configured)", z.Limit)
		}
		if z.Used != 16275 {
			t.Errorf("pf state keys Used = %d, want 16275", z.Used)
		}
	})

	t.Run("non-zero fail and sleep survive", func(t *testing.T) {
		z := zoneByName(t, stats, "256 Bucket")
		if z.Failures != 144270 || z.Sleeps != 3 {
			t.Errorf("256 Bucket fail/sleep = %d/%d, want 144270/3", z.Failures, z.Sleeps)
		}
	})

	t.Run("duplicate zone rows are summed", func(t *testing.T) {
		z := zoneByName(t, stats, "vm pgcache")
		if z.Rows != 2 {
			t.Errorf("vm pgcache Rows = %d, want 2", z.Rows)
		}
		if z.Used != 819065+2170293 {
			t.Errorf("vm pgcache Used = %d, want %d", z.Used, 819065+2170293)
		}
		if z.Free != 2020+3620 {
			t.Errorf("vm pgcache Free = %d, want %d", z.Free, 2020+3620)
		}
		if z.Requests != 1981217291+398186153 {
			t.Errorf("vm pgcache Requests = %d, want %d", z.Requests, 1981217291+398186153)
		}
		if z.Failures != 8858+268 {
			t.Errorf("vm pgcache Failures = %d, want %d", z.Failures, 8858+268)
		}

		nf := zoneByName(t, stats, "NetFlow IPv4 cache")
		if nf.Rows != 3 {
			t.Errorf("NetFlow IPv4 cache Rows = %d, want 3", nf.Rows)
		}
		if nf.Used != 174+482 {
			t.Errorf("NetFlow IPv4 cache Used = %d, want %d", nf.Used, 174+482)
		}
		if nf.Limit != 3*1048576 {
			t.Errorf("NetFlow IPv4 cache Limit = %d, want %d (per-row ceilings sum)", nf.Limit, 3*1048576)
		}
		if nf.XDomain != 3 {
			t.Errorf("NetFlow IPv4 cache XDomain = %d, want 3", nf.XDomain)
		}
	})

	t.Run("duplicate rows with differing item size take the largest", func(t *testing.T) {
		z := zoneByName(t, stats, "buffer arena-40")
		if z.ItemSizeBytes != 40960 {
			t.Errorf("buffer arena-40 ItemSizeBytes = %d, want 40960", z.ItemSizeBytes)
		}
	})

	t.Run("zone failures are summed across every row", func(t *testing.T) {
		want := int64(144270 + 8858 + 268)
		if stats.ZoneFailuresTotal != want {
			t.Errorf("ZoneFailuresTotal = %d, want %d", stats.ZoneFailuresTotal, want)
		}
	})

	t.Run("malloc fields decode and duplicates are summed", func(t *testing.T) {
		m := mallocByName(t, stats, "CAM periph")
		if m.InUse != 6 || m.Bytes != 1408 || m.Requests != 1545 || m.Rows != 1 {
			t.Errorf("CAM periph = %+v", m)
		}
		d := mallocByName(t, stats, "dummynet")
		if d.Rows != 2 || d.InUse != 7 || d.Bytes != 1280+2560 || d.Requests != 124554+3 {
			t.Errorf("dummynet = %+v", d)
		}
	})

	t.Run("zones and malloc types are name-sorted", func(t *testing.T) {
		for i := 1; i < len(stats.Zones); i++ {
			if stats.Zones[i-1].Name > stats.Zones[i].Name {
				t.Fatalf("zones not sorted: %q before %q", stats.Zones[i-1].Name, stats.Zones[i].Name)
			}
		}
		for i := 1; i < len(stats.MallocTypes); i++ {
			if stats.MallocTypes[i-1].Name > stats.MallocTypes[i].Name {
				t.Fatalf("malloc types not sorted: %q before %q", stats.MallocTypes[i-1].Name, stats.MallocTypes[i].Name)
			}
		}
	})
}

// TestFetchKernelMemory_Empty covers memoryAction's own early return: it emits a bare
// `[]` when configd hands back nothing parseable. That must decode to an empty result
// and no error, so a box in that state goes silent rather than failing the scrape.
func TestFetchKernelMemory_Empty(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"empty array from memoryAction", `[]`},
		{"empty object", `{}`},
		{"wrapper present but both sections empty", `{"__version":"2","vmstat":{"malloc-statistics":{"memory":[]},"memory-zone-statistics":{"zone":[]}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			})
			defer server.Close()

			stats, err := client.FetchKernelMemory()
			if err != nil {
				t.Fatalf("FetchKernelMemory returned error: %v", err)
			}
			if len(stats.Zones) != 0 || len(stats.MallocTypes) != 0 || stats.ZoneFailuresTotal != 0 {
				t.Errorf("expected empty statistics, got %+v", stats)
			}
		})
	}
}

// TestFetchKernelMemory_StringNumbers pins the KindNumeric tolerance the canary
// triage calls "absorb": a counter arriving as a JSON string must still decode.
func TestFetchKernelMemory_StringNumbers(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"__version":"2","vmstat":{
			"malloc-statistics":{"memory":[{"type":"solaris","in-use":"12","memory-use":"3400","requests":"99"}]},
			"memory-zone-statistics":{"zone":[{"name":"socket","size":"1032","limit":"1042770","used":"462","free":"3350","requests":"9","fail":"7","sleep":"1","xdomain":"0"}]}}}`))
	})
	defer server.Close()

	stats, err := client.FetchKernelMemory()
	if err != nil {
		t.Fatalf("FetchKernelMemory returned error: %v", err)
	}
	z := zoneByName(t, stats, "socket")
	if z.Limit != 1042770 || z.Used != 462 || z.Failures != 7 || z.Sleeps != 1 || z.ItemSizeBytes != 1032 {
		t.Errorf("socket zone = %+v", z)
	}
	if stats.ZoneFailuresTotal != 7 {
		t.Errorf("ZoneFailuresTotal = %d, want 7", stats.ZoneFailuresTotal)
	}
	m := mallocByName(t, stats, "solaris")
	if m.InUse != 12 || m.Bytes != 3400 || m.Requests != 99 {
		t.Errorf("solaris malloc = %+v", m)
	}
}

func TestFetchKernelMemory_EndpointMissing(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(systemMemoryFixture))
	})
	defer server.Close()

	delete(client.endpoints, "systemMemory")
	if _, err := client.FetchKernelMemory(); err == nil {
		t.Fatal("expected an error when the systemMemory endpoint is not registered")
	}
}
