package collector

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/common/promslog"
)

func TestGatewayGroupsCollector_Update(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/routing/group_settings/search", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
      "total":1,"rowCount":1,"current":1,
      "rows":[{
        "uuid":"group-a","name":"WAN_FAILOVER","item":"WAN_GW","item2":"LTE_GW",
        "item3":"","item4":"","item5":"","trigger":"down","poolopts":"","descr":"failover",
        "gateways":{
          "1":[{"name":"WAN_GW","address":"10.0.0.1","status":"none","loss":"0.0 %","delay":"1.2 ms","stddev":"0.3 ms","monitor":"192.0.2.53","status_translated":"Online","label":"success"}],
          "2":[{"name":"LTE_GW","address":"10.0.0.3","status":"down","loss":"~","delay":"~","stddev":"~","monitor":"~","status_translated":"Offline","label":"danger"}],
          "3":[],"4":[],"5":[]
        }
      }]
    }`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)
	client.Endpoints()["gatewayGroups"] = "api/routing/group_settings/search"
	c := &gatewayGroupsCollector{subsystem: GatewayGroupsSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	assertNoDuplicateSeries(t, metrics)
	if len(metrics) != 2 {
		t.Fatalf("metrics = %d, want 2 membership series", len(metrics))
	}
	for _, metric := range metrics {
		if !hasFqName(metric, "opnsense_gateway_groups_member") {
			t.Errorf("unexpected metric descriptor: %s", metric.Desc())
		}
		labels := getMetricLabels(metric)
		if getMetricValue(metric) != 1 {
			t.Errorf("membership value = %v, want 1", getMetricValue(metric))
		}
		if labels["group"] != "WAN_FAILOVER" || labels["name"] == "" || labels["address"] == "" {
			t.Errorf("unexpected membership labels: %+v", labels)
		}
		switch labels["name"] {
		case "WAN_GW":
			if labels["address"] != "192.0.2.53" || labels["gateway_address"] != "10.0.0.1" {
				t.Errorf("active gateway join labels = %+v, want monitor address plus configured gateway address", labels)
			}
		case "LTE_GW":
			if labels["address"] != "~" || labels["gateway_address"] != "10.0.0.3" {
				t.Errorf("disabled gateway join labels = %+v, want '~' monitor sentinel plus configured gateway address", labels)
			}
		}
		if labels["opnsense_instance"] != "test" {
			t.Errorf("instance label = %q, want test", labels["opnsense_instance"])
		}
	}
}

func TestGatewayGroupsCollector_FeatureAbsent(t *testing.T) {
	server := httptest.NewServer(http.NewServeMux())
	defer server.Close()

	client := newCollectorTestClient(t, server)
	client.Endpoints()["gatewayGroups"] = "api/routing/group_settings/search"
	c := &gatewayGroupsCollector{subsystem: GatewayGroupsSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 0 {
		t.Fatalf("metrics = %d, want 0 when endpoint is absent", len(metrics))
	}
}
