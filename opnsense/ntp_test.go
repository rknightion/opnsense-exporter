package opnsense

import (
	"net/http"
	"testing"
)

func TestFetchNTPStatus_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"rows": [
				{
					"status": "*",
					"server": "0.pool.ntp.org",
					"refid": ".GPS.",
					"stratum": "1",
					"type": "u",
					"when": "32",
					"poll": "64",
					"reach": "377",
					"delay": "1.234",
					"offset": "0.567",
					"jitter": "0.123"
				},
				{
					"status": "+",
					"server": "1.pool.ntp.org",
					"refid": ".PPS.",
					"stratum": "2",
					"type": "u",
					"when": "-",
					"poll": "128",
					"reach": "17",
					"delay": "5.678",
					"offset": "-1.234",
					"jitter": "0.456"
				},
				{
					"status": " ",
					"server": "2.pool.ntp.org",
					"refid": ".INIT.",
					"stratum": "16",
					"type": "u",
					"when": "0",
					"poll": "64",
					"reach": "",
					"delay": "0",
					"offset": "0",
					"jitter": "0"
				}
			]
		}`))
	})
	defer server.Close()

	data, err := client.FetchNTPStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(data.Peers) != 3 {
		t.Fatalf("expected 3 peers, got %d", len(data.Peers))
	}

	// First peer: normal values
	p1 := data.Peers[0]
	if p1.Status != "*" {
		t.Errorf("expected status '*', got %q", p1.Status)
	}
	if p1.Server != "0.pool.ntp.org" {
		t.Errorf("expected server '0.pool.ntp.org', got %q", p1.Server)
	}
	if p1.RefID != ".GPS." {
		t.Errorf("expected refid '.GPS.', got %q", p1.RefID)
	}
	if p1.Stratum != 1 {
		t.Errorf("expected Stratum=1, got %d", p1.Stratum)
	}
	if p1.WhenSeconds != 32 {
		t.Errorf("expected WhenSeconds=32, got %f", p1.WhenSeconds)
	}
	if p1.PollSeconds != 64 {
		t.Errorf("expected PollSeconds=64, got %f", p1.PollSeconds)
	}
	// "377" octal = 255 decimal
	if p1.Reach != 255 {
		t.Errorf("expected Reach=255 (377 octal), got %d", p1.Reach)
	}
	if p1.DelayMillis != 1.234 {
		t.Errorf("expected DelayMillis=1.234, got %f", p1.DelayMillis)
	}
	if p1.OffsetMillis != 0.567 {
		t.Errorf("expected OffsetMillis=0.567, got %f", p1.OffsetMillis)
	}
	if p1.JitterMillis != 0.123 {
		t.Errorf("expected JitterMillis=0.123, got %f", p1.JitterMillis)
	}

	// Second peer: when="-" should be 0
	p2 := data.Peers[1]
	if p2.WhenSeconds != 0 {
		t.Errorf("expected WhenSeconds=0 for when='-', got %f", p2.WhenSeconds)
	}
	// "17" octal = 15 decimal
	if p2.Reach != 15 {
		t.Errorf("expected Reach=15 (17 octal), got %d", p2.Reach)
	}

	// Third peer: empty reach should be 0
	p3 := data.Peers[2]
	if p3.Reach != 0 {
		t.Errorf("expected Reach=0 for empty reach, got %d", p3.Reach)
	}
	if p3.Stratum != 16 {
		t.Errorf("expected Stratum=16, got %d", p3.Stratum)
	}
}

// TestFetchNTPStatus_SuffixedWhenPoll guards #89: once an interval exceeds ~2048s
// ntpq's prettyinterval renders when/poll as unit-suffixed strings ("34m", "12h",
// "3d"). These must parse to seconds, not silently coerce to 0 (which reads as
// "responded just now" during the exact outage the metric exists to detect).
func TestFetchNTPStatus_SuffixedWhenPoll(t *testing.T) {
	cases := []struct {
		when string
		poll string
		want float64
	}{
		{"34m", "34m", 2040},
		{"12h", "12h", 43200},
		{"3d", "3d", 259200},
	}
	for _, tc := range cases {
		t.Run(tc.when, func(t *testing.T) {
			server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`{"rows":[{"status":"*","server":"s","refid":".GPS.","stratum":"1","type":"u","when":"` + tc.when + `","poll":"` + tc.poll + `","reach":"377","delay":"1","offset":"0","jitter":"0"}]}`))
			})
			defer server.Close()

			data, err := client.FetchNTPStatus()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			p := data.Peers[0]
			if p.WhenSeconds != tc.want || !p.WhenValid {
				t.Errorf("when %q: got (%v, valid=%v), want (%v, true)", tc.when, p.WhenSeconds, p.WhenValid, tc.want)
			}
			if p.PollSeconds != tc.want || !p.PollValid {
				t.Errorf("poll %q: got (%v, valid=%v), want (%v, true)", tc.poll, p.PollSeconds, p.PollValid, tc.want)
			}
		})
	}
}

// TestFetchNTPStatus_UnknownWhenNotZero guards #89: an unknown when ("-" or
// garbage) must be flagged invalid, not reported as a real 0 ("responded now").
func TestFetchNTPStatus_UnknownWhenNotZero(t *testing.T) {
	for _, when := range []string{"-", "garbage"} {
		server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"rows":[{"status":"*","server":"s","refid":".GPS.","stratum":"1","type":"u","when":"` + when + `","poll":"64","reach":"377","delay":"1","offset":"0","jitter":"0"}]}`))
		})
		data, err := client.FetchNTPStatus()
		server.Close()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if data.Peers[0].WhenValid {
			t.Errorf("when %q: expected WhenValid=false (unknown must be distinguishable from 0), got valid", when)
		}
	}
}

func TestFetchNTPStatus_OctalReachParsing(t *testing.T) {
	tests := []struct {
		name     string
		reach    string
		expected int
	}{
		{"Full reach 377", "377", 255},
		{"Half reach 17", "17", 15},
		{"One reach 1", "1", 1},
		{"Zero reach 0", "0", 0},
		{"Invalid reach", "xyz", 0},
		{"Empty reach", "", 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
				// Raw JSON literal mirroring a real /api/ntp/service/status peer row, so
				// a wrong json tag or field type in ntpStatusResponse/ntpPeerRow is caught
				// rather than round-tripped away (#155). Live shape: all peer fields are
				// strings (reach is an octal string parsed by the client).
				w.Write([]byte(`{"rows":[{"status":"*","server":"ntp.test","refid":".GPS.","stratum":"1","type":"u","when":"10","poll":"64","reach":"` + tc.reach + `","delay":"0","offset":"0","jitter":"0"}]}`))
			})
			defer server.Close()

			data, err := client.FetchNTPStatus()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if data.Peers[0].Reach != tc.expected {
				t.Errorf("reach %q: expected %d, got %d", tc.reach, tc.expected, data.Peers[0].Reach)
			}
		})
	}
}

func TestFetchNTPStatus_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchNTPStatus()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

// TestFetchNTPGPSStatus_NoRefclock covers the real shape captured live from the
// 26.7-devel test box (no GPS hardware attached): the configd script's PHP
// empty array `$result['gps'] = []` encodes as a JSON array, not an object.
func TestFetchNTPGPSStatus_NoRefclock(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{"ntpq_servers":[{"status":"*","server":"ntp.test","refid":".PPS.","stratum":"1","type":"u","when":"10","poll":"64","reach":"377","delay":"0","offset":"0","jitter":"0"}],"gps":[]}`))
	})
	defer server.Close()

	data, err := client.FetchNTPGPSStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.Present {
		t.Errorf("expected Present=false when gps is an empty array (no refclock), got %+v", data)
	}
}

// TestFetchNTPGPSStatus_GPGGA covers the populated shape derived from
// ntpd_status.php's $GPGGA branch: 'ok' is the raw NMEA quality-indicator
// digit (a string, not a JSON bool) and 'sat' is the satellite count string.
// lat/lon are deliberately not modelled (privacy, per #224) even though the
// script emits them.
func TestFetchNTPGPSStatus_GPGGA(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ntpq_servers":[],"gps":{"sentence":"$GPGGA","ok":"1","alt":"12.3","alt_unit":"M","sat":"08","lat":37.5,"lon":-122.1}}`))
	})
	defer server.Close()

	data, err := client.FetchNTPGPSStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true for a populated gps object")
	}
	if !data.OK {
		t.Errorf("expected OK=true for quality indicator \"1\", got false")
	}
	if !data.SatellitesValid || data.Satellites != 8 {
		t.Errorf("expected Satellites=8 (valid), got %d (valid=%v)", data.Satellites, data.SatellitesValid)
	}
}

// TestFetchNTPGPSStatus_GPRMCNoFix covers the $GPRMC branch, where 'ok' is a
// genuine JSON boolean (PHP `($vars[2] ?? ”) === 'A'`) rather than a string,
// and asserts a "no fix" (false) is preserved rather than defaulting true.
func TestFetchNTPGPSStatus_GPRMCNoFix(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ntpq_servers":[],"gps":{"sentence":"$GPRMC","ok":false}}`))
	})
	defer server.Close()

	data, err := client.FetchNTPGPSStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true")
	}
	if data.OK {
		t.Error("expected OK=false for a JSON false 'ok' value")
	}
	if data.SatellitesValid {
		t.Errorf("expected SatellitesValid=false ($GPRMC never carries 'sat'), got Satellites=%d", data.Satellites)
	}
}

func TestFetchNTPGPSStatus_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchNTPGPSStatus()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}
