package opnsense

import (
	"net/http"
	"testing"
)

// The two ARC header shapes below are REAL CAPTURES, taken 2026-07-30:
//   - ZFS: the production firewall (OPNsense 26.7.1_1), `top -aHSTn -d2`.
//   - UFS: testbed VM 102 (OPNsense 27.1.a), same command.
//
// The UFS shape is the one that matters and it is NOT what #551 assumed. The issue
// predicted a UFS box would emit no `ARC:` header at all. It emits the header with
// nothing after it — `"ARC: "` — so "no ARC line" is the wrong absence test and a
// naive parser would read a bare prefix as a box with zero-sized everything.
const (
	arcHeaderZFS         = "ARC: 7818M Total, 3034M MFU, 4222M MRU, 22M Anon, 46M Header, 483M Other"
	arcHeaderZFSCompress = "     6772M Compressed, 11G Uncompressed, 1.70:1 Ratio"
	arcHeaderUFS         = "ARC: "
)

func TestFetchActivity_ARCComposition(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"headers":[
			"911 threads:   13 running, 864 sleeping, 34 waiting",
			"Mem: 5249M Active, 3393M Inact, 5446M Laundry, 13G Wired, 372K Buf, 3900M Free",
			"` + arcHeaderZFS + `",
			"` + arcHeaderZFSCompress + `",
			"Swap: 10G Total, 433M Used, 9807M Free, 4% Inuse"
		],"details":[]}`))
	})
	defer server.Close()

	data, err := client.FetchActivity()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.ARC.Present {
		t.Fatal("ARC.Present should be true on a ZFS box")
	}

	const mb, gb = 1024 * 1024, 1024 * 1024 * 1024
	for _, tc := range []struct {
		name string
		got  float64
		want float64
	}{
		{"MFU", data.ARC.MFUBytes, 3034 * mb},
		{"MRU", data.ARC.MRUBytes, 4222 * mb},
		{"Anon", data.ARC.AnonBytes, 22 * mb},
		{"Header", data.ARC.HeaderBytes, 46 * mb},
		{"Other", data.ARC.OtherBytes, 483 * mb},
		{"Compressed", data.ARC.CompressedBytes, 6772 * mb},
		{"Uncompressed", data.ARC.UncompressedBytes, 11 * gb},
	} {
		if tc.got != tc.want {
			t.Errorf("ARC.%s = %v, want %v", tc.name, tc.got, tc.want)
		}
	}
	if !data.ARC.HasCompression {
		t.Error("HasCompression should be true when the continuation line parsed")
	}
}

// TestFetchActivity_ARCAbsentOnUFS is the load-bearing case. A UFS box has no ARC,
// and every component must read ABSENT rather than zero — a zero would render as a
// real 0-byte ARC on every panel and would be indistinguishable from a ZFS box whose
// cache is genuinely empty.
func TestFetchActivity_ARCAbsentOnUFS(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header string
	}{
		{"empty ARC header, as a real UFS box emits it", arcHeaderUFS},
		{"no ARC header at all", ""},
		{"ARC header with unparseable contents", "ARC: wat"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"headers":["911 threads:   13 running, 864 sleeping, 34 waiting"`
			if tc.header != "" {
				body += `,"` + tc.header + `"`
			}
			body += `],"details":[]}`

			server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Write([]byte(body))
			})
			defer server.Close()

			data, err := client.FetchActivity()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if data.ARC.Present {
				t.Errorf("ARC.Present must be false, got composition %+v", data.ARC)
			}
			// Thread parsing must be unaffected: a missing ARC is not an error.
			if data.ThreadsTotal != 911 {
				t.Errorf("ThreadsTotal = %d, want 911", data.ThreadsTotal)
			}
		})
	}
}

// TestFetchActivity_ARCWithoutCompressionLine covers the composition line arriving
// without its continuation. Composition is still usable; compression is not, and must
// not be published as zero.
func TestFetchActivity_ARCWithoutCompressionLine(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"headers":["` + arcHeaderZFS + `"],"details":[]}`))
	})
	defer server.Close()

	data, err := client.FetchActivity()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.ARC.Present {
		t.Fatal("composition should still parse without the continuation line")
	}
	if data.ARC.HasCompression {
		t.Error("HasCompression must be false when the continuation line is absent")
	}
}

func TestParseTopSize(t *testing.T) {
	for _, tc := range []struct {
		in     string
		want   float64
		wantOK bool
	}{
		{"483M", 483 * 1024 * 1024, true},
		{"11G", 11 * 1024 * 1024 * 1024, true},
		{"372K", 372 * 1024, true},
		{"1024B", 1024, true},
		// top drops the suffix entirely for a plain byte count.
		{"512", 512, true},
		{"1.5G", 1.5 * 1024 * 1024 * 1024, true},
		{"", 0, false},
		{"wat", 0, false},
		{"12X", 0, false},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, ok := parseTopSize(tc.in)
			if ok != tc.wantOK {
				t.Fatalf("parseTopSize(%q) ok = %v, want %v", tc.in, ok, tc.wantOK)
			}
			if ok && got != tc.want {
				t.Errorf("parseTopSize(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
