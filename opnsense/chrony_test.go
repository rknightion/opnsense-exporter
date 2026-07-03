package opnsense

import (
	"net/http"
	"testing"
)

// chronyTrackingFixture is the raw chronyc tracking output as returned by the
// OPNsense API in {"response": "..."} envelope.
const chronyTrackingFixture = `Reference ID    : C0A80001 (ntp1.example.net)
Stratum         : 3
Ref time (UTC)  : Tue Jun 09 08:00:00 2026
System time     : 0.000123456 seconds slow of NTP time
Last offset     : -0.000012345 seconds
RMS offset      : 0.000098765 seconds
Frequency       : 12.345 ppm fast
Residual freq   : -0.001 ppm
Skew            : 0.123 ppm
Root delay      : 0.012345678 seconds
Root dispersion : 0.001234567 seconds
Update interval : 64.5 seconds
Leap status     : Normal`

const chronySourcesFixture = `MS Name/IP address         Stratum Poll Reach LastRx Last sample
===============================================================================
^* ntp1.example.net              2   6   377    34   +123us[ +145us] +/-   12ms
^+ ntp2.example.net              2   6   377    35   -250us[ -251us] +/-   15ms
^? 203.0.113.5                   0   8     0     -     +0ns[   +0ns] +/-    0ns`

const chronySourceStatsFixture = `Name/IP Address            NP  NR  Span  Frequency  Freq Skew  Offset  Std Dev
==============================================================================
ntp1.example.net           25  12  19m     -0.002      0.060   -45us    113us
ntp2.example.net           20  10  17m     +0.010      0.080  +120us    220us`

// wrapChronyResponse wraps raw chronyc text in the API envelope.
func wrapChronyResponse(raw string) string {
	return `{"response":"` + escapeForJSON(raw) + `"}`
}

// escapeForJSON escapes a string for use as a JSON string value.
func escapeForJSON(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			b = append(b, '\\', '"')
		case '\\':
			b = append(b, '\\', '\\')
		case '\n':
			b = append(b, '\\', 'n')
		case '\r':
			b = append(b, '\\', 'r')
		case '\t':
			b = append(b, '\\', 't')
		default:
			b = append(b, c)
		}
	}
	return string(b)
}

// --- parseChronyDuration ---

func TestParseChronyDuration(t *testing.T) {
	cases := []struct {
		in     string
		want   float64
		wantOK bool
	}{
		{"+123us", 123e-6, true},
		{"-45ns", -45e-9, true},
		{"12ms", 12e-3, true},
		{"1.5s", 1.5, true},
		{"-0.000012345s", -0.000012345, true},
		{"+0ns", 0, true},
		{"-", 0, false},
		{"", 0, false},
		{"ppm", 0, false},
	}
	for _, tc := range cases {
		got, ok := parseChronyDuration(tc.in)
		if ok != tc.wantOK {
			t.Errorf("parseChronyDuration(%q) ok=%v want %v", tc.in, ok, tc.wantOK)
			continue
		}
		if ok && absFloat(got-tc.want) > 1e-15 {
			t.Errorf("parseChronyDuration(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func absFloat(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

// --- parseChronyTracking ---

func TestParseChronyTracking(t *testing.T) {
	tr := parseChronyTracking(chronyTrackingFixture)

	if !tr.Valid {
		t.Fatal("expected Valid=true for full tracking output")
	}
	if tr.ReferenceID != "C0A80001" {
		t.Errorf("ReferenceID=%q, want C0A80001", tr.ReferenceID)
	}
	if tr.ReferenceName != "ntp1.example.net" {
		t.Errorf("ReferenceName=%q, want ntp1.example.net", tr.ReferenceName)
	}
	if tr.Stratum != 3 {
		t.Errorf("Stratum=%v, want 3", tr.Stratum)
	}
	// "slow" means negative offset
	if absFloat(tr.SystemTimeOffsetSeconds-(-0.000123456)) > 1e-12 {
		t.Errorf("SystemTimeOffsetSeconds=%v, want -0.000123456", tr.SystemTimeOffsetSeconds)
	}
	if absFloat(tr.FrequencyPPM-12.345) > 1e-6 {
		t.Errorf("FrequencyPPM=%v, want 12.345", tr.FrequencyPPM)
	}
	if absFloat(tr.ResidualFrequencyPPM-(-0.001)) > 1e-9 {
		t.Errorf("ResidualFrequencyPPM=%v, want -0.001", tr.ResidualFrequencyPPM)
	}
	if tr.LeapStatusValue != 0 {
		t.Errorf("LeapStatusValue=%v, want 0 (Normal)", tr.LeapStatusValue)
	}
	if tr.LeapStatus != "Normal" {
		t.Errorf("LeapStatus=%q, want Normal", tr.LeapStatus)
	}
}

func TestParseChronyTracking_Empty(t *testing.T) {
	tr := parseChronyTracking("")
	if tr.Valid {
		t.Error("expected Valid=false for empty input")
	}
	if tr.LeapStatusValue != 3 {
		t.Errorf("LeapStatusValue=%v, want 3 (not synchronised) for empty", tr.LeapStatusValue)
	}
}

func TestParseChronyTracking_ErrorText(t *testing.T) {
	// When chronyd is stopped, configd returns an error string like
	// "chronyd is not running".
	tr := parseChronyTracking("chronyd is not running")
	if tr.Valid {
		t.Error("expected Valid=false for error text (no Reference ID)")
	}
}

// --- parseChronySources ---

func TestParseChronySources(t *testing.T) {
	sources := parseChronySources(chronySourcesFixture)

	if len(sources) != 3 {
		t.Fatalf("expected 3 sources, got %d", len(sources))
	}

	// ntp1: ^* — server mode, selected
	s0 := sources[0]
	if s0.Mode != "^" {
		t.Errorf("sources[0].Mode=%q, want ^", s0.Mode)
	}
	if s0.State != "*" {
		t.Errorf("sources[0].State=%q, want *", s0.State)
	}
	if s0.Name != "ntp1.example.net" {
		t.Errorf("sources[0].Name=%q, want ntp1.example.net", s0.Name)
	}
	if s0.Reachability != 255 {
		t.Errorf("sources[0].Reachability=%v, want 255 (octal 377)", s0.Reachability)
	}
	if !s0.HasLastRx || absFloat(s0.LastRxSeconds-34) > 1e-9 {
		t.Errorf("sources[0] LastRx: HasLastRx=%v LastRxSeconds=%v, want true/34", s0.HasLastRx, s0.LastRxSeconds)
	}
	if !s0.HasOffset || absFloat(s0.OffsetSeconds-123e-6) > 1e-12 {
		t.Errorf("sources[0] Offset: HasOffset=%v OffsetSeconds=%v, want true/123e-6", s0.HasOffset, s0.OffsetSeconds)
	}

	// ntp2: ^+ — server mode, acceptable
	s1 := sources[1]
	if s1.Mode != "^" || s1.State != "+" {
		t.Errorf("sources[1] Mode/State=%q/%q, want ^/+", s1.Mode, s1.State)
	}
	if !s1.HasOffset || absFloat(s1.OffsetSeconds-(-250e-6)) > 1e-12 {
		t.Errorf("sources[1] Offset: %v, want -250e-6", s1.OffsetSeconds)
	}

	// 203.0.113.5: ^? — not reachable, LastRx="-"
	s2 := sources[2]
	if s2.State != "?" {
		t.Errorf("sources[2].State=%q, want ?", s2.State)
	}
	if s2.HasLastRx {
		t.Errorf("sources[2] should have HasLastRx=false (LastRx was '-')")
	}
	if s2.Reachability != 0 {
		t.Errorf("sources[2].Reachability=%v, want 0", s2.Reachability)
	}
}

func TestParseChronySources_Refclock(t *testing.T) {
	// Refclock line: mode char '#', state char '*'
	raw := `MS Name/IP address         Stratum Poll Reach LastRx Last sample
===============================================================================
#* GPS0                          0   4   377    11   -479ns[ -621ns] +/-   134ns`

	sources := parseChronySources(raw)
	if len(sources) != 1 {
		t.Fatalf("expected 1 source, got %d", len(sources))
	}
	s := sources[0]
	if s.Mode != "#" {
		t.Errorf("Mode=%q, want #", s.Mode)
	}
	if s.State != "*" {
		t.Errorf("State=%q, want *", s.State)
	}
	if s.Name != "GPS0" {
		t.Errorf("Name=%q, want GPS0", s.Name)
	}
	if s.Reachability != 255 {
		t.Errorf("Reachability=%v, want 255 (octal 377)", s.Reachability)
	}
}

// --- parseChronySourceStats ---

func TestParseChronySourceStats(t *testing.T) {
	stats := parseChronySourceStats(chronySourceStatsFixture)

	if len(stats) != 2 {
		t.Fatalf("expected 2 sourcestats rows, got %d", len(stats))
	}

	st0 := stats[0]
	if st0.Name != "ntp1.example.net" {
		t.Errorf("stats[0].Name=%q, want ntp1.example.net", st0.Name)
	}
	if st0.Samples != 25 {
		t.Errorf("stats[0].Samples=%v, want 25", st0.Samples)
	}
	if !st0.HasStdDev || absFloat(st0.StdDevSeconds-113e-6) > 1e-12 {
		t.Errorf("stats[0] StdDev: HasStdDev=%v StdDevSeconds=%v, want true/113e-6", st0.HasStdDev, st0.StdDevSeconds)
	}

	st1 := stats[1]
	if st1.Name != "ntp2.example.net" {
		t.Errorf("stats[1].Name=%q, want ntp2.example.net", st1.Name)
	}
	if !st1.HasStdDev || absFloat(st1.StdDevSeconds-220e-6) > 1e-12 {
		t.Errorf("stats[1] StdDev: HasStdDev=%v StdDevSeconds=%v, want true/220e-6", st1.HasStdDev, st1.StdDevSeconds)
	}
}

// --- FetchChronyStatus ---

func TestFetchChronyStatus_Normal(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/chrony/service/chronytracking", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(wrapChronyResponse(chronyTrackingFixture)))
	})
	mux.HandleFunc("/api/chrony/service/chronysources", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(wrapChronyResponse(chronySourcesFixture)))
	})
	mux.HandleFunc("/api/chrony/service/chronysourcestats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(wrapChronyResponse(chronySourceStatsFixture)))
	})

	data, err := client.FetchChronyStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true")
	}
	if !data.Tracking.Valid {
		t.Error("expected Tracking.Valid=true")
	}
	if data.Tracking.Stratum != 3 {
		t.Errorf("Tracking.Stratum=%v, want 3", data.Tracking.Stratum)
	}
	if len(data.Sources) != 3 {
		t.Errorf("expected 3 sources, got %d", len(data.Sources))
	}
	if len(data.SourceStats) != 2 {
		t.Errorf("expected 2 sourcestats, got %d", len(data.SourceStats))
	}
}

// TestFetchChronyStatus_SubFetchFailure guards #163: a non-404 error from the
// sources (or sourcestats) sub-endpoint must be distinguishable from a genuine
// zero-sources response — HasSources/HasSourceStats stay false — rather than
// silently yielding empty slices with no signal.
func TestFetchChronyStatus_SubFetchFailure(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/chrony/service/chronytracking", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(wrapChronyResponse(chronyTrackingFixture)))
	})
	// Sources transiently fails (500); sourcestats succeeds.
	mux.HandleFunc("/api/chrony/service/chronysources", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	mux.HandleFunc("/api/chrony/service/chronysourcestats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(wrapChronyResponse(chronySourceStatsFixture)))
	})

	data, err := client.FetchChronyStatus()
	if err != nil {
		t.Fatalf("expected nil error (sub-fetch failure is tolerated), got %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true")
	}
	if data.HasSources {
		t.Error("expected HasSources=false when the sources sub-fetch fails")
	}
	if !data.HasSourceStats {
		t.Error("expected HasSourceStats=true when sourcestats succeeds")
	}
}

func TestFetchChronyStatus_ChronydStopped(t *testing.T) {
	// When chronyd is stopped, the configd script returns error text.
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	errorResp := `{"response":"chronyd is not running"}`
	mux.HandleFunc("/api/chrony/service/chronytracking", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(errorResp))
	})
	mux.HandleFunc("/api/chrony/service/chronysources", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(errorResp))
	})
	mux.HandleFunc("/api/chrony/service/chronysourcestats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(errorResp))
	})

	data, err := client.FetchChronyStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Error("expected Present=true (plugin installed, service stopped)")
	}
	if data.Tracking.Valid {
		t.Error("expected Tracking.Valid=false for error-text response")
	}
	if len(data.Sources) != 0 {
		t.Errorf("expected 0 sources for error-text response, got %d", len(data.Sources))
	}
}

func TestFetchChronyStatus_404(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer server.Close()

	data, err := client.FetchChronyStatus()
	if err != nil {
		t.Fatalf("expected nil error on 404 (plugin absent), got: %v", err)
	}
	if data.Present {
		t.Error("expected Present=false on 404")
	}
}
