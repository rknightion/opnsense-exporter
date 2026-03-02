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
				resp := ntpStatusResponse{
					Rows: []ntpPeerRow{
						{
							Status:  "*",
							Server:  "ntp.test",
							RefID:   ".GPS.",
							Stratum: "1",
							Type:    "u",
							When:    "10",
							Poll:    "64",
							Reach:   tc.reach,
							Delay:   "0",
							Offset:  "0",
							Jitter:  "0",
						},
					},
				}
				w.Write(mustMarshal(t, resp))
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
