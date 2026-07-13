package opnsense

import (
	"net/http"
	"testing"
)

// torCircuitsPartialBootstrapFixture is a trimmed-down, sanitised version of a
// real dev-box capture (2026-07-13, captures/tor/circuits.json): a Tor whose
// bootstrap is stuck mid-way, so every circuit is an ONEHOP/internal circuit.
// The "hosts" arrays intentionally reproduce the real column-shift artefact
// (BUILD_FLAGS=... landing as bogus pseudo-relay entries) to prove the fetch
// never reads "hosts" at all.
const torCircuitsPartialBootstrapFixture = `{"response":{
	"4":{"status":"EXTENDED","hosts":[{"host":"BUILD_FLAGS=ONEHOP_TUNNEL","nickname":null},{"host":"IS_INTERNAL","nickname":null},{"host":"NEED_CAPACITY","nickname":null}],"flags":{"PURPOSE":["GENERAL"],"TIME_CREATED":["2026-07-13T17:24:49.653025"]}},
	"5":{"status":"EXTENDED","hosts":[{"host":"BUILD_FLAGS=ONEHOP_TUNNEL","nickname":null},{"host":"IS_INTERNAL","nickname":null},{"host":"NEED_CAPACITY","nickname":null}],"flags":{"PURPOSE":["GENERAL"],"TIME_CREATED":["2026-07-13T17:24:49.653175"]}},
	"11":{"status":"BUILT","hosts":[{"host":"$9433B42F5282DFA0B4D3065D34E65FE13680B98A","nickname":"KhanKrumCloud2"}],"flags":{"BUILD_FLAGS":["ONEHOP_TUNNEL","IS_INTERNAL","NEED_CAPACITY"],"PURPOSE":["GENERAL"],"TIME_CREATED":["2026-07-13T17:24:49.653294"]}},
	"20":{"status":"BUILT","hosts":[{"host":"$B765AA8B1B31AAF09B203B7176772B955734CEE8","nickname":"Durst"}],"flags":{"BUILD_FLAGS":["ONEHOP_TUNNEL","IS_INTERNAL","NEED_CAPACITY"],"PURPOSE":["GENERAL"],"TIME_CREATED":["2026-07-13T17:24:49.653459"]}}
}}`

// torCircuitsHSVanguardsFixture reproduces the second dev-box probe capture:
// a single HS_VANGUARDS-purpose circuit whose "status" field itself is
// corrupted (the real live capture had a comma-joined multi-relay path stuffed
// into "status" by the same column-shift class of bug). status is therefore
// NOT a recognised CircStatus value and must land in the "other" bucket.
const torCircuitsHSVanguardsFixture = `{"response":{
	"0":{"status":"$B765AA8B1B31AAF09B203B7176772B955734CEE8~Durst,$09F9CD95B472256DFDFF666A0CFD82A3F3CE3514~chinachinachina","hosts":[{"host":"BUILD_FLAGS=IS_INTERNAL","nickname":null},{"host":"NEED_CAPACITY","nickname":null}],"flags":{"PURPOSE":["HS_VANGUARDS"],"TIME_CREATED":["2026-07-13T17:48:04.391019"]}}
}}`

// torCircuitsFullyBootstrappedFixture is source-derived (torspec
// control-spec.txt §4.1.1 CircStatus/Purpose grammar): a healthy Tor with
// fully extended 3-hop GENERAL circuits and one unrecognised status value to
// exercise the vocabulary fallback.
const torCircuitsFullyBootstrappedFixture = `{"response":{
	"1":{"status":"BUILT","hosts":[{"host":"$AAA","nickname":"relay1"},{"host":"$BBB","nickname":"relay2"},{"host":"$CCC","nickname":"relay3"}],"flags":{"BUILD_FLAGS":["NEED_CAPACITY"],"PURPOSE":["GENERAL"],"TIME_CREATED":["2026-07-13T18:00:00.000000"]}},
	"2":{"status":"BUILT","hosts":[{"host":"$DDD","nickname":"relay4"}],"flags":{"PURPOSE":["GENERAL"],"TIME_CREATED":["2026-07-13T18:00:01.000000"]}},
	"3":{"status":"FAILED","hosts":[],"flags":{"PURPOSE":["TESTING"],"TIME_CREATED":["2026-07-13T18:00:02.000000"]}},
	"4":{"status":"SOME_FUTURE_STATUS","hosts":[],"flags":{"PURPOSE":["SOME_FUTURE_PURPOSE"],"TIME_CREATED":["2026-07-13T18:00:03.000000"]}}
}}`

// torStreamsMisalignedFixture is the real dev-box capture (2026-07-13,
// captures/tor/streams.json) verbatim: a Tor stuck mid-bootstrap producing
// only NEW streams, with the parser landmine from a real payload where a
// stream row's fields landed in the wrong keys (e.g.
// {"stream_id":"NEW","stream_status":"0",...}). Kept as a permanent regression
// fixture per the issue's explicit instruction.
const torStreamsMisalignedFixture = `{"response":[
	{"stream_id":"95","stream_status":"NEW","circuit_id":"0","destination_host":"194.164.197.45.$49D2288C36ED78FF07C17A0B2F5673DBC1DF3164.exit","destination_port":"443"},
	{"stream_id":"97","stream_status":"NEW","circuit_id":"0","destination_host":"192.42.116.32.$DA7EFCD6C466B1F4CC7F63C3206DDE1EC0F447A6.exit","destination_port":"443"},
	{"stream_id":"99","stream_status":"NEW","circuit_id":"0","destination_host":"136.243.147.89.$07D8ECD7305722EE37FA0A408BC0D2034B9BE07A.exit","destination_port":"9100"},
	{"stream_id":"NEW","stream_status":"0","circuit_id":"109.73.65.37.$6007EF215FA156F200B634CC83BD76BB2D563DAA.exit:9001","destination_host":null,"destination_port":null},
	{"stream_id":"0","stream_status":"89.47.51.189.$00588E8ED6B571AE3D4F002300793406DD7A62B6.exit:443","circuit_id":"NEW","destination_host":null,"destination_port":null},
	{"stream_id":"188.165.136.211.$22B914891BFD03971AEF2D54C3129F1C4F61B2FF.exit:8081","stream_status":"NEW","circuit_id":"0","destination_host":"148.251.83.53.$94F5629AE5F2DC409CD44668176597FF48296BA1.exit","destination_port":"8443"},
	{"stream_id":"NEW","stream_status":"0","circuit_id":"83.228.196.41.$0DBDDF93345A9D1368FA64BDFA495562D0505DC5.exit:443","destination_host":null,"destination_port":null},
	{"stream_id":"0","stream_status":"94.130.142.182.$50B7C4F6C18A3E5FC1D4E2ECE6B7B316B29FB26C.exit:8443","circuit_id":"NEW","destination_host":null,"destination_port":null},
	{"stream_id":"135.125.89.25.$872108C52C52CC10217A351C883E991AEDF7C470.exit:443","stream_status":"NEW","circuit_id":"0","destination_host":"5.9.14.30.$D245932673168094C492D5155F64699E251703E9.exit","destination_port":"993"},
	{"stream_id":"NEW","stream_status":"0","circuit_id":"192.42.116.77.$0625BCA64F30EC2E1AC1C5021E651074257C2908.exit:443","destination_host":null,"destination_port":null},
	{"stream_id":"0","stream_status":"192.121.108.118.$A02AB2C40AB744F451CCCE38781D8E05676CC15E.exit:9001","circuit_id":"NEW","destination_host":null,"destination_port":null},
	{"stream_id":"192.42.116.44.$A5C5ADC6CE9B52BE860D2572FF48569DC9E24C60.exit:443","stream_status":"NEW","circuit_id":"0","destination_host":"194.13.83.131.$35F5A0B2F017FD09F7EBF33A565A53D8EB2C9272.exit","destination_port":"9001"}
]}`

// torStreamsFullyBootstrappedFixture is source-derived (torspec
// control-spec.txt §4.1.2/§3.9 StreamStatus grammar): a healthy Tor with
// SUCCEEDED streams and one unrecognised status to exercise the fallback.
const torStreamsFullyBootstrappedFixture = `{"response":[
	{"stream_id":"1","stream_status":"SUCCEEDED","circuit_id":"1","destination_host":"example.com","destination_port":"443"},
	{"stream_id":"2","stream_status":"SUCCEEDED","circuit_id":"1","destination_host":"example.org","destination_port":"443"},
	{"stream_id":"3","stream_status":"NEW","circuit_id":"2","destination_host":"example.net","destination_port":"80"},
	{"stream_id":"4","stream_status":"SOME_FUTURE_STATUS","circuit_id":"2","destination_host":"example.io","destination_port":"80"}
]}`

func TestFetchTorCircuits_PartialBootstrap(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(torCircuitsPartialBootstrapFixture))
	})
	defer server.Close()

	data, err := client.FetchTorCircuits()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present || !data.Up {
		t.Fatalf("expected Present=true, Up=true, got Present=%v Up=%v", data.Present, data.Up)
	}
	if data.ByStatus["EXTENDED"] != 2 {
		t.Errorf("EXTENDED: want 2, got %d", data.ByStatus["EXTENDED"])
	}
	if data.ByStatus["BUILT"] != 2 {
		t.Errorf("BUILT: want 2, got %d", data.ByStatus["BUILT"])
	}
	if data.ByStatus["other"] != 0 {
		t.Errorf("other: want 0, got %d", data.ByStatus["other"])
	}
	// All 4 circuits carry PURPOSE=GENERAL despite the hosts[]/BUILD_FLAGS
	// column-shift bug — proves status/purpose parsing is unaffected by it.
	if data.ByPurpose["GENERAL"] != 4 {
		t.Errorf("GENERAL purpose: want 4, got %d", data.ByPurpose["GENERAL"])
	}
}

func TestFetchTorCircuits_CorruptedStatusFallsBackToOther(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(torCircuitsHSVanguardsFixture))
	})
	defer server.Close()

	data, err := client.FetchTorCircuits()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Up {
		t.Fatal("expected Up=true")
	}
	// The comma-joined relay path landed in "status" — not a recognised
	// CircStatus value, so it must be bucketed as "other", never emitted
	// verbatim (it contains relay identity strings).
	if data.ByStatus["other"] != 1 {
		t.Errorf("other: want 1, got %d (full map: %v)", data.ByStatus["other"], data.ByStatus)
	}
	for status := range data.ByStatus {
		if status != "other" {
			t.Errorf("unexpected raw status label leaked through: %q", status)
		}
	}
	if data.ByPurpose["HS_VANGUARDS"] != 1 {
		t.Errorf("HS_VANGUARDS: want 1, got %d", data.ByPurpose["HS_VANGUARDS"])
	}
}

func TestFetchTorCircuits_FullyBootstrapped(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(torCircuitsFullyBootstrappedFixture))
	})
	defer server.Close()

	data, err := client.FetchTorCircuits()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.ByStatus["BUILT"] != 2 {
		t.Errorf("BUILT: want 2, got %d", data.ByStatus["BUILT"])
	}
	if data.ByStatus["FAILED"] != 1 {
		t.Errorf("FAILED: want 1, got %d", data.ByStatus["FAILED"])
	}
	if data.ByStatus["other"] != 1 {
		t.Errorf("other: want 1, got %d", data.ByStatus["other"])
	}
	if data.ByPurpose["GENERAL"] != 2 {
		t.Errorf("GENERAL: want 2, got %d", data.ByPurpose["GENERAL"])
	}
	if data.ByPurpose["TESTING"] != 1 {
		t.Errorf("TESTING: want 1, got %d", data.ByPurpose["TESTING"])
	}
	if data.ByPurpose["other"] != 1 {
		t.Errorf("purpose other: want 1, got %d", data.ByPurpose["other"])
	}
}

func TestFetchTorCircuits_ControlPortNotUp_ResponseNull(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"response": null}`))
	})
	defer server.Close()

	data, err := client.FetchTorCircuits()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Error("expected Present=true (plugin installed, control port unreachable)")
	}
	if data.Up {
		t.Error("expected Up=false when response is null")
	}
	if len(data.ByStatus) != 0 || len(data.ByPurpose) != 0 {
		t.Errorf("expected no counts when control port is down, got %v / %v", data.ByStatus, data.ByPurpose)
	}
}

func TestFetchTorCircuits_ControlPortNotUp_ConfigError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"response": {"error": "no control port found"}}`))
	})
	defer server.Close()

	data, err := client.FetchTorCircuits()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Error("expected Present=true")
	}
	if data.Up {
		t.Error("expected Up=false when response carries the config-error shape")
	}
}

func TestFetchTorCircuits_404IsAbsent(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer server.Close()

	data, err := client.FetchTorCircuits()
	if err != nil {
		t.Fatalf("expected nil error on 404 (plugin absent), got: %v", err)
	}
	if data.Present {
		t.Error("expected Present=false on 404")
	}
}

func TestFetchTorStreams_MisalignedRealCapture(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(torStreamsMisalignedFixture))
	})
	defer server.Close()

	data, err := client.FetchTorStreams()
	if err != nil {
		t.Fatalf("unexpected error (decoder must never crash on misaligned rows): %v", err)
	}
	if !data.Present || !data.Up {
		t.Fatalf("expected Present=true, Up=true, got Present=%v Up=%v", data.Present, data.Up)
	}

	// 6 rows have a well-formed "NEW" in the stream_status position; the other
	// 6 are the shifted rows where "0" or a relay-descriptor string landed in
	// stream_status instead — those must fall into "other", never surface the
	// raw garbage (a relay/exit descriptor) as a label value.
	if data.ByStatus["NEW"] != 6 {
		t.Errorf("NEW: want 6, got %d (full map: %v)", data.ByStatus["NEW"], data.ByStatus)
	}
	if data.ByStatus["other"] != 6 {
		t.Errorf("other: want 6, got %d (full map: %v)", data.ByStatus["other"], data.ByStatus)
	}
	for status := range data.ByStatus {
		if status != "NEW" && status != "other" {
			t.Errorf("unexpected raw status label leaked through: %q", status)
		}
	}
}

func TestFetchTorStreams_FullyBootstrapped(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(torStreamsFullyBootstrappedFixture))
	})
	defer server.Close()

	data, err := client.FetchTorStreams()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.ByStatus["SUCCEEDED"] != 2 {
		t.Errorf("SUCCEEDED: want 2, got %d", data.ByStatus["SUCCEEDED"])
	}
	if data.ByStatus["NEW"] != 1 {
		t.Errorf("NEW: want 1, got %d", data.ByStatus["NEW"])
	}
	if data.ByStatus["other"] != 1 {
		t.Errorf("other: want 1, got %d", data.ByStatus["other"])
	}
}

func TestFetchTorStreams_ControlPortNotUp_ResponseNull(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"response": null}`))
	})
	defer server.Close()

	data, err := client.FetchTorStreams()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Error("expected Present=true")
	}
	if data.Up {
		t.Error("expected Up=false when response is null")
	}
}

func TestFetchTorStreams_EmptyIsUp(t *testing.T) {
	// A genuinely idle-but-healthy Tor answers {"response": []} — must be
	// distinguished from {"response": null} (control port down).
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"response": []}`))
	})
	defer server.Close()

	data, err := client.FetchTorStreams()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Up {
		t.Error("expected Up=true for an empty-but-valid response")
	}
	if len(data.ByStatus) != 0 {
		t.Errorf("expected no stream counts, got %v", data.ByStatus)
	}
}

func TestFetchTorStreams_404IsAbsent(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer server.Close()

	data, err := client.FetchTorStreams()
	if err != nil {
		t.Fatalf("expected nil error on 404 (plugin absent), got: %v", err)
	}
	if data.Present {
		t.Error("expected Present=false on 404")
	}
}

func TestFetchTorHiddenServices_None(t *testing.T) {
	// PHP's json_encode(array()) emits [] for zero configured hidden services.
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"response": []}`))
	})
	defer server.Close()

	data, err := client.FetchTorHiddenServices()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Error("expected Present=true")
	}
	if len(data.HostnameAvailable) != 0 {
		t.Errorf("expected no hidden services, got %v", data.HostnameAvailable)
	}
}

func TestFetchTorHiddenServices_MixedAvailability(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"response": {"myservice": "abcdefghijklmnop.onion", "pending": "not available"}}`))
	})
	defer server.Close()

	data, err := client.FetchTorHiddenServices()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Error("expected Present=true")
	}
	if !data.HostnameAvailable["myservice"] {
		t.Error("expected myservice hostname to be available")
	}
	if data.HostnameAvailable["pending"] {
		t.Error("expected pending hostname to be unavailable")
	}
}

func TestFetchTorHiddenServices_404IsAbsent(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer server.Close()

	data, err := client.FetchTorHiddenServices()
	if err != nil {
		t.Fatalf("expected nil error on 404 (plugin absent), got: %v", err)
	}
	if data.Present {
		t.Error("expected Present=false on 404")
	}
}
