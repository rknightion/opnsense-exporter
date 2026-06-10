package opnsense

import (
	"net/http"
	"testing"
)

// monitRunningFixture is derived from core Monit/Api/StatusController.php +
// monit 5.x _status?format=xml schema as serialised by PHP simplexml_load_string
// + json_encode. Unvalidated against a live box with monit running.
const monitRunningFixture = `{
  "result": "ok",
  "status": {
    "@attributes": {"id": "abc123", "incarnation": "1700000000", "version": "5.33.0"},
    "server": {"uptime": "3600", "poll": "120", "startdelay": "0",
               "localhostname": "fw1", "controlfile": "/usr/local/etc/monitrc"},
    "platform": {"name": "FreeBSD", "release": "14.1", "cpu": "4", "memory": "8388608"},
    "service": [
      {"@attributes": {"type": "5"}, "name": "$HOST", "collected_sec": "1700000060",
       "status": "0", "status_hint": "0", "monitor": "1", "monitormode": "0",
       "onreboot": "0", "pendingaction": "0"},
      {"@attributes": {"type": "3"}, "name": "nginx", "collected_sec": "1700000060",
       "status": "512", "status_hint": "0", "monitor": "1", "monitormode": "0",
       "onreboot": "0", "pendingaction": "0"}
    ]
  }
}`

// monitDownFixture is the live-validated shape returned by api/monit/status/get/xml
// on OPNsense 26.1 when monit is installed but not running (validated 2026-06-09).
// The exact wording of the message is preserved here so the fixture matches the box.
const monitDownFixture = `{"result": "failed",
 "status": "\nEither the file /var/run/monit.sock does not exists or it is not a unix socket.\nPlease check if the Monit service is running.\n\nIf you have started Monit recently, wait for StartDelay seconds and refresh this page."}`

// monitSingleServiceFixture exercises the simplexml single-child-as-object quirk:
// when there is exactly one service, it is serialised as a JSON object, not an array.
const monitSingleServiceFixture = `{
  "result": "ok",
  "status": {
    "service": {"@attributes": {"type": "5"}, "name": "$HOST",
                "status": "0", "monitor": "1", "monitormode": "0",
                "pendingaction": "0"}
  }
}`

func TestFetchMonitStatus_Running(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/monit/status/get/xml", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(monitRunningFixture))
	})

	data, err := client.FetchMonitStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.StatusOK {
		t.Fatal("expected StatusOK=true for running monit")
	}
	if len(data.Checks) != 2 {
		t.Fatalf("expected 2 checks, got %d", len(data.Checks))
	}

	// Find checks by name.
	checks := map[string]MonitCheck{}
	for _, c := range data.Checks {
		checks[c.Name] = c
	}

	host, ok := checks["$HOST"]
	if !ok {
		t.Fatal("expected $HOST check")
	}
	if host.Type != "system" {
		t.Errorf("expected $HOST type=system, got %q", host.Type)
	}
	if host.StatusOK != 1 {
		t.Errorf("expected $HOST StatusOK=1, got %v", host.StatusOK)
	}
	if host.Monitored != 1 {
		t.Errorf("expected $HOST Monitored=1, got %v", host.Monitored)
	}

	nginx, ok := checks["nginx"]
	if !ok {
		t.Fatal("expected nginx check")
	}
	if nginx.Type != "process" {
		t.Errorf("expected nginx type=process, got %q", nginx.Type)
	}
	if nginx.StatusOK != 0 {
		t.Errorf("expected nginx StatusOK=0 (status=512), got %v", nginx.StatusOK)
	}
	if nginx.Monitored != 1 {
		t.Errorf("expected nginx Monitored=1, got %v", nginx.Monitored)
	}
}

func TestFetchMonitStatus_SingleServiceObject(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/monit/status/get/xml", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(monitSingleServiceFixture))
	})

	data, err := client.FetchMonitStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.StatusOK {
		t.Fatal("expected StatusOK=true")
	}
	if len(data.Checks) != 1 {
		t.Fatalf("expected 1 check (single object, not array), got %d", len(data.Checks))
	}
	c := data.Checks[0]
	if c.Name != "$HOST" {
		t.Errorf("expected name=$HOST, got %q", c.Name)
	}
	if c.Type != "system" {
		t.Errorf("expected type=system, got %q", c.Type)
	}
	if c.StatusOK != 1 {
		t.Errorf("expected StatusOK=1, got %v", c.StatusOK)
	}
}

func TestFetchMonitStatus_Down(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/monit/status/get/xml", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(monitDownFixture))
	})

	data, err := client.FetchMonitStatus()
	if err != nil {
		t.Fatalf("expected nil error when monit is down, got: %v", err)
	}
	if data.StatusOK {
		t.Error("expected StatusOK=false when result=failed")
	}
	if len(data.Checks) != 0 {
		t.Errorf("expected 0 checks when monit is down, got %d", len(data.Checks))
	}
}

func TestFetchMonitStatus_404(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer server.Close()

	data, err := client.FetchMonitStatus()
	if err != nil {
		t.Fatalf("expected nil error on 404 (feature absent), got: %v", err)
	}
	if data.StatusOK {
		t.Error("expected StatusOK=false on 404")
	}
	if len(data.Checks) != 0 {
		t.Errorf("expected 0 checks on 404, got %d", len(data.Checks))
	}
}
