package opnsense

import (
	"net/http"
	"testing"
)

func TestFetchNetisrStatistics_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"netisr": {
				"protocol": [
					{"name": "ip", "protocol": 1, "queue-limit": 256, "policy": "flow"},
					{"name": "arp", "protocol": 2, "queue-limit": 512, "policy": "source"}
				],
				"workstream": [
					{
						"work": [
							{
								"workstream": 0, "cpu": 0, "name": "ip",
								"length": 5, "watermark": 10,
								"dispatched": 100, "hybrid-dispatched": 10,
								"queue-drops": 1, "queued": 50, "handled": 99
							},
							{
								"workstream": 0, "cpu": 0, "name": "arp",
								"length": 2, "watermark": 4,
								"dispatched": 30, "hybrid-dispatched": 3,
								"queue-drops": 0, "queued": 15, "handled": 30
							}
						]
					},
					{
						"work": [
							{
								"workstream": 1, "cpu": 1, "name": "ip",
								"length": 3, "watermark": 12,
								"dispatched": 200, "hybrid-dispatched": 20,
								"queue-drops": 2, "queued": 80, "handled": 198
							},
							{
								"workstream": 1, "cpu": 1, "name": "arp",
								"length": 1, "watermark": 3,
								"dispatched": 20, "hybrid-dispatched": 2,
								"queue-drops": 1, "queued": 10, "handled": 19
							}
						]
					}
				]
			}
		}`))
	})
	defer server.Close()

	data, err := client.FetchNetisrStatistics()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(data) != 2 {
		t.Fatalf("expected 2 protocols, got %d", len(data))
	}

	// Check ip: sums across 2 workstreams
	ip := data["ip"]
	if ip.Dispatched != 300 {
		t.Errorf("ip.Dispatched = %d; want 300", ip.Dispatched)
	}
	if ip.HybridDispatched != 30 {
		t.Errorf("ip.HybridDispatched = %d; want 30", ip.HybridDispatched)
	}
	if ip.QueueDrops != 3 {
		t.Errorf("ip.QueueDrops = %d; want 3", ip.QueueDrops)
	}
	if ip.Queued != 130 {
		t.Errorf("ip.Queued = %d; want 130", ip.Queued)
	}
	if ip.Handled != 297 {
		t.Errorf("ip.Handled = %d; want 297", ip.Handled)
	}
	// max length: max(5, 3) = 5
	if ip.Length != 5 {
		t.Errorf("ip.Length = %d; want 5", ip.Length)
	}
	// max watermark: max(10, 12) = 12
	if ip.Watermark != 12 {
		t.Errorf("ip.Watermark = %d; want 12", ip.Watermark)
	}
	// queue-limit from protocol array
	if ip.QueueLimit != 256 {
		t.Errorf("ip.QueueLimit = %d; want 256", ip.QueueLimit)
	}

	// Check arp
	arp := data["arp"]
	if arp.Dispatched != 50 {
		t.Errorf("arp.Dispatched = %d; want 50", arp.Dispatched)
	}
	if arp.HybridDispatched != 5 {
		t.Errorf("arp.HybridDispatched = %d; want 5", arp.HybridDispatched)
	}
	if arp.QueueDrops != 1 {
		t.Errorf("arp.QueueDrops = %d; want 1", arp.QueueDrops)
	}
	if arp.Queued != 25 {
		t.Errorf("arp.Queued = %d; want 25", arp.Queued)
	}
	if arp.Handled != 49 {
		t.Errorf("arp.Handled = %d; want 49", arp.Handled)
	}
	// max length: max(2, 1) = 2
	if arp.Length != 2 {
		t.Errorf("arp.Length = %d; want 2", arp.Length)
	}
	// max watermark: max(4, 3) = 4
	if arp.Watermark != 4 {
		t.Errorf("arp.Watermark = %d; want 4", arp.Watermark)
	}
	if arp.QueueLimit != 512 {
		t.Errorf("arp.QueueLimit = %d; want 512", arp.QueueLimit)
	}
}

func TestFetchNetisrStatistics_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchNetisrStatistics()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

func TestFetchSocketStatistics_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"tcp4/[10.0.0.1:80-10.0.0.2:1234]": {},
			"tcp4/[10.0.0.1:443-10.0.0.3:5678]": {},
			"udp4/[10.0.0.1:53-*:*]": {},
			"unix/[/var/run/log.sock]": {},
			"unix/[/var/run/devd.sock]": {}
		}`))
	})
	defer server.Close()

	data, err := client.FetchSocketStatistics()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.ByType["tcp4"] != 2 {
		t.Errorf("tcp4 count = %d; want 2", data.ByType["tcp4"])
	}
	if data.ByType["udp4"] != 1 {
		t.Errorf("udp4 count = %d; want 1", data.ByType["udp4"])
	}
	if data.ByType["unix"] != 2 {
		t.Errorf("unix count = %d; want 2", data.ByType["unix"])
	}
	if data.UnixTotal != 2 {
		t.Errorf("UnixTotal = %d; want 2", data.UnixTotal)
	}
}

func TestFetchSocketStatistics_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchSocketStatistics()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

func TestFetchRouteStatistics_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`[
			{"proto": "IPv4"},
			{"proto": "IPv4"},
			{"proto": "IPv4"},
			{"proto": "IPv6"},
			{"proto": "IPv6"}
		]`))
	})
	defer server.Close()

	data, err := client.FetchRouteStatistics()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.ByProto["IPv4"] != 3 {
		t.Errorf("IPv4 count = %d; want 3", data.ByProto["IPv4"])
	}
	if data.ByProto["IPv6"] != 2 {
		t.Errorf("IPv6 count = %d; want 2", data.ByProto["IPv6"])
	}
}

func TestFetchRouteStatistics_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchRouteStatistics()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}
