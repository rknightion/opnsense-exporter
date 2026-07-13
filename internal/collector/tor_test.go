package collector

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/common/promslog"
)

const torCircuitsFixture = `{"response":{
	"1":{"status":"BUILT","hosts":[{"host":"$AAA","nickname":"relay1"}],"flags":{"PURPOSE":["GENERAL"]}},
	"2":{"status":"EXTENDED","hosts":[],"flags":{"PURPOSE":["GENERAL"]}},
	"3":{"status":"BUILT","hosts":[{"host":"$BBB","nickname":"relay2"}],"flags":{"PURPOSE":["HS_VANGUARDS"]}}
}}`

const torStreamsFixture = `{"response":[
	{"stream_id":"1","stream_status":"NEW","circuit_id":"1","destination_host":"example.com","destination_port":"443"},
	{"stream_id":"2","stream_status":"SUCCEEDED","circuit_id":"1","destination_host":"example.org","destination_port":"443"}
]}`

// torStreamsMisalignedCollectorFixture reproduces the real dev-box column-shift
// row alongside well-formed rows, at the collector layer, to prove the garbage
// value never surfaces as a "status" label on the emitted metric.
const torStreamsMisalignedCollectorFixture = `{"response":[
	{"stream_id":"95","stream_status":"NEW","circuit_id":"0","destination_host":"1.2.3.4.$AAA.exit","destination_port":"443"},
	{"stream_id":"NEW","stream_status":"0","circuit_id":"5.6.7.8.$BBB.exit:9001","destination_host":null,"destination_port":null}
]}`

const torHiddenServicesFixture = `{"response": {"myservice": "abcdefghijklmnop.onion", "pending": "not available"}}`

func torCollectorMux(t *testing.T) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tor/service/circuits", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(torCircuitsFixture))
	})
	mux.HandleFunc("/api/tor/service/streams", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(torStreamsFixture))
	})
	mux.HandleFunc("/api/tor/service/get_hidden_services", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(torHiddenServicesFixture))
	})
	return mux
}

func TestTorCollector_Update_Normal(t *testing.T) {
	server := httptest.NewServer(torCollectorMux(t))
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &torCollector{subsystem: TorSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	assertNoDuplicateSeries(t, metrics)

	// control_port_up(1) + circuits{BUILT=2,EXTENDED=1}(2) +
	// circuits_by_purpose{GENERAL=2,HS_VANGUARDS=1}(2) +
	// streams{NEW=1,SUCCEEDED=1}(2) + hidden_services(1) +
	// hidden_service_hostname_available{myservice,pending}(2)
	expected := 1 + 2 + 2 + 2 + 1 + 2
	if len(metrics) != expected {
		t.Errorf("expected %d metrics, got %d", expected, len(metrics))
	}

	var gotControlPortUp bool
	circuitStatusSeen := map[string]float64{}
	purposeSeen := map[string]float64{}
	streamStatusSeen := map[string]float64{}
	var hiddenServicesCount float64
	hostnameAvailable := map[string]float64{}

	for _, m := range metrics {
		labels := getMetricLabels(m)
		val := getMetricValue(m)
		switch {
		case hasFqName(m, "opnsense_tor_control_port_up"):
			gotControlPortUp = true
			if val != 1 {
				t.Errorf("control_port_up: want 1, got %v", val)
			}
		case hasFqName(m, "opnsense_tor_circuits"):
			circuitStatusSeen[labels["status"]] = val
		case hasFqName(m, "opnsense_tor_circuits_by_purpose"):
			purposeSeen[labels["purpose"]] = val
		case hasFqName(m, "opnsense_tor_streams"):
			streamStatusSeen[labels["status"]] = val
		case hasFqName(m, "opnsense_tor_hidden_services"):
			hiddenServicesCount = val
		case hasFqName(m, "opnsense_tor_hidden_service_hostname_available"):
			hostnameAvailable[labels["service"]] = val
		}
	}

	if !gotControlPortUp {
		t.Error("expected control_port_up metric")
	}
	if circuitStatusSeen["BUILT"] != 2 {
		t.Errorf("circuits{status=BUILT}: want 2, got %v", circuitStatusSeen["BUILT"])
	}
	if circuitStatusSeen["EXTENDED"] != 1 {
		t.Errorf("circuits{status=EXTENDED}: want 1, got %v", circuitStatusSeen["EXTENDED"])
	}
	if purposeSeen["GENERAL"] != 2 {
		t.Errorf("circuits_by_purpose{purpose=GENERAL}: want 2, got %v", purposeSeen["GENERAL"])
	}
	if purposeSeen["HS_VANGUARDS"] != 1 {
		t.Errorf("circuits_by_purpose{purpose=HS_VANGUARDS}: want 1, got %v", purposeSeen["HS_VANGUARDS"])
	}
	if streamStatusSeen["NEW"] != 1 || streamStatusSeen["SUCCEEDED"] != 1 {
		t.Errorf("streams: want NEW=1 SUCCEEDED=1, got %v", streamStatusSeen)
	}
	if hiddenServicesCount != 2 {
		t.Errorf("hidden_services: want 2, got %v", hiddenServicesCount)
	}
	if hostnameAvailable["myservice"] != 1 {
		t.Errorf("hidden_service_hostname_available{service=myservice}: want 1, got %v", hostnameAvailable["myservice"])
	}
	if hostnameAvailable["pending"] != 0 {
		t.Errorf("hidden_service_hostname_available{service=pending}: want 0, got %v", hostnameAvailable["pending"])
	}
}

func TestTorCollector_Update_MisalignedStreamRowNeverLeaksLabel(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tor/service/circuits", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response":{}}`))
	})
	mux.HandleFunc("/api/tor/service/streams", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(torStreamsMisalignedCollectorFixture))
	})
	mux.HandleFunc("/api/tor/service/get_hidden_services", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response":[]}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &torCollector{subsystem: TorSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	assertNoDuplicateSeries(t, metrics)

	for _, m := range metrics {
		if !hasFqName(m, "opnsense_tor_streams") {
			continue
		}
		status := getMetricLabels(m)["status"]
		if status != "NEW" && status != "other" {
			t.Errorf("garbage stream_status value leaked as a label: %q", status)
		}
	}
}

func TestTorCollector_Update_PluginAbsent(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &torCollector{subsystem: TorSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics when plugin absent, got %d", len(metrics))
	}
}

func TestTorCollector_Update_ControlPortDown(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tor/service/circuits", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response": null}`))
	})
	mux.HandleFunc("/api/tor/service/streams", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response": null}`))
	})
	mux.HandleFunc("/api/tor/service/get_hidden_services", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response": []}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &torCollector{subsystem: TorSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Only control_port_up(=0) and hidden_services(=0) are expected: no
	// circuits/streams/purpose series when the control port is down.
	expected := 2
	if len(metrics) != expected {
		t.Errorf("expected %d metrics, got %d", expected, len(metrics))
	}
	for _, m := range metrics {
		if hasFqName(m, "opnsense_tor_control_port_up") && getMetricValue(m) != 0 {
			t.Error("expected control_port_up=0")
		}
	}
}

func TestTorCollector_Name(t *testing.T) {
	c := &torCollector{subsystem: TorSubsystem}
	if c.Name() != TorSubsystem {
		t.Errorf("expected %s, got %s", TorSubsystem, c.Name())
	}
}
