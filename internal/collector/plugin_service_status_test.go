package collector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
)

// These are the agent-family plugins whose only collector surface is the
// standard service/status response. The route spellings are taken from each
// plugin's released ACL/view source, not inferred from the package directory.
var pluginServiceStatusTestCases = []struct {
	name      string
	subsystem string
	path      string
	new       func() CollectorInstance
}{
	{
		name:      "collectd",
		subsystem: CollectdSubsystem,
		path:      "/api/collectd/service/status",
		new: func() CollectorInstance {
			return &collectdCollector{pluginServiceStatusCollector: pluginServiceStatusCollector{
				subsystem: CollectdSubsystem, endpoint: "collectdServiceStatus",
			}}
		},
	},
	{
		name:      "telegraf",
		subsystem: TelegrafSubsystem,
		path:      "/api/telegraf/service/status",
		new: func() CollectorInstance {
			return &telegrafCollector{pluginServiceStatusCollector: pluginServiceStatusCollector{
				subsystem: TelegrafSubsystem, endpoint: "telegrafServiceStatus",
			}}
		},
	},
	{
		name:      "netdata",
		subsystem: NetdataSubsystem,
		path:      "/api/netdata/service/status",
		new: func() CollectorInstance {
			return &netdataCollector{pluginServiceStatusCollector: pluginServiceStatusCollector{
				subsystem: NetdataSubsystem, endpoint: "netdataServiceStatus",
			}}
		},
	},
	{
		name:      "nrpe",
		subsystem: NRPESubsystem,
		path:      "/api/nrpe/service/status",
		new: func() CollectorInstance {
			return &nrpeCollector{pluginServiceStatusCollector: pluginServiceStatusCollector{
				subsystem: NRPESubsystem, endpoint: "nrpeServiceStatus",
			}}
		},
	},
	{
		name:      "zabbix-agent",
		subsystem: ZabbixAgentSubsystem,
		path:      "/api/zabbixagent/service/status",
		new: func() CollectorInstance {
			return &zabbixAgentCollector{pluginServiceStatusCollector: pluginServiceStatusCollector{
				subsystem: ZabbixAgentSubsystem, endpoint: "zabbixAgentServiceStatus",
			}}
		},
	},
	{
		name:      "zabbix-proxy",
		subsystem: ZabbixProxySubsystem,
		path:      "/api/zabbixproxy/service/status",
		new: func() CollectorInstance {
			return &zabbixProxyCollector{pluginServiceStatusCollector: pluginServiceStatusCollector{
				subsystem: ZabbixProxySubsystem, endpoint: "zabbixProxyServiceStatus",
			}}
		},
	},
	{
		name:      "net-snmp",
		subsystem: NetSNMPSubsystem,
		path:      "/api/netsnmp/service/status",
		new: func() CollectorInstance {
			return &netSNMPCollector{pluginServiceStatusCollector: pluginServiceStatusCollector{
				subsystem: NetSNMPSubsystem, endpoint: "netSnmpServiceStatus",
			}}
		},
	},
	{
		name:      "wazuh-agent",
		subsystem: WazuhAgentSubsystem,
		path:      "/api/wazuh_agent/service/status",
		new: func() CollectorInstance {
			return &wazuhAgentCollector{pluginServiceStatusCollector: pluginServiceStatusCollector{
				subsystem: WazuhAgentSubsystem, endpoint: "wazuhAgentServiceStatus",
			}}
		},
	},
	{
		name:      "beats",
		subsystem: BeatsSubsystem,
		path:      "/api/beats/service/status",
		new: func() CollectorInstance {
			return &beatsCollector{pluginServiceStatusCollector: pluginServiceStatusCollector{
				subsystem: BeatsSubsystem, endpoint: "beatsServiceStatus",
			}}
		},
	},
	{
		name:      "munin-node",
		subsystem: MuninNodeSubsystem,
		path:      "/api/muninnode/service/status",
		new: func() CollectorInstance {
			return &muninNodeCollector{pluginServiceStatusCollector: pluginServiceStatusCollector{
				subsystem: MuninNodeSubsystem, endpoint: "muninNodeServiceStatus",
			}}
		},
	},
	{
		name:      "node-exporter",
		subsystem: NodeExporterSubsystem,
		path:      "/api/nodeexporter/service/status",
		new: func() CollectorInstance {
			return &nodeExporterCollector{pluginServiceStatusCollector: pluginServiceStatusCollector{
				subsystem: NodeExporterSubsystem, endpoint: "nodeExporterServiceStatus",
			}}
		},
	},
	{
		name:      "puppet-agent",
		subsystem: PuppetAgentSubsystem,
		path:      "/api/puppetagent/service/status",
		new: func() CollectorInstance {
			return &puppetAgentCollector{pluginServiceStatusCollector: pluginServiceStatusCollector{
				subsystem: PuppetAgentSubsystem, endpoint: "puppetAgentServiceStatus",
			}}
		},
	},
	{
		name:      "qemu-guest-agent",
		subsystem: QemuGuestAgentSubsystem,
		path:      "/api/qemuguestagent/service/status",
		new: func() CollectorInstance {
			return &qemuGuestAgentCollector{pluginServiceStatusCollector: pluginServiceStatusCollector{
				subsystem: QemuGuestAgentSubsystem, endpoint: "qemuGuestAgentServiceStatus",
			}}
		},
	},
}

func TestPluginServiceStatusCollectorsHaveUniqueNames(t *testing.T) {
	seen := make(map[string]string, len(pluginServiceStatusTestCases))
	for _, tc := range pluginServiceStatusTestCases {
		t.Run(tc.name, func(t *testing.T) {
			collector := tc.new()
			if got := collector.Name(); got != tc.subsystem {
				t.Errorf("Name() = %q, want %q", got, tc.subsystem)
			}
			if previous, ok := seen[collector.Name()]; ok {
				t.Errorf("subsystem %q is shared by %s and %s", collector.Name(), previous, tc.name)
			}
			seen[collector.Name()] = tc.name
		})
	}
}

// The standard ApiMutableServiceControllerBase returns these four status
// values. collectd and telegraf implement equivalent custom status actions;
// their non-running values must follow the same zero mapping.
func TestPluginServiceStatusCollectorsMapRunningState(t *testing.T) {
	statuses := []struct {
		name string
		body string
		want float64
	}{
		{name: "running", body: `{"status":"running"}`, want: 1},
		{name: "stopped", body: `{"status":"stopped"}`, want: 0},
		{name: "disabled", body: `{"status":"disabled"}`, want: 0},
		{name: "unknown", body: `{"status":"unknown"}`, want: 0},
		// collectd and telegraf's released custom actions misspell this fallback;
		// it is still a non-running status and must map to zero.
		{name: "unknown-legacy-spelling", body: `{"status":"unkown"}`, want: 0}, //nolint:misspell // Upstream wire value.
	}

	for _, status := range statuses {
		for _, tc := range pluginServiceStatusTestCases {
			t.Run(tc.name+"/"+status.name, func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != tc.path {
						t.Errorf("request path = %q, want %q", r.URL.Path, tc.path)
						http.NotFound(w, r)
						return
					}
					_, _ = w.Write([]byte(status.body))
				}))
				defer server.Close()

				collector := tc.new()
				collector.Register(namespace, "test-instance", promslog.NewNopLogger())
				metrics := collectMetrics(t, collector, newCollectorTestClient(t, server))
				if len(metrics) != 1 {
					t.Fatalf("got %d metrics, want 1", len(metrics))
				}
				wantName := "opnsense_" + tc.subsystem + "_service_running"
				if !hasFqName(metrics[0], wantName) {
					t.Fatalf("metric = %s, want %s", metrics[0].Desc(), wantName)
				}
				if got := getMetricValue(metrics[0]); got != status.want {
					t.Errorf("value = %v, want %v", got, status.want)
				}
				if labels := getMetricLabels(metrics[0]); labels[instanceLabelName] != "test-instance" {
					t.Errorf("%s label = %q, want %q", instanceLabelName, labels[instanceLabelName], "test-instance")
				}
			})
		}
	}
}

func TestPluginServiceStatusCollectorsStaySilentWhenAbsent(t *testing.T) {
	for _, tc := range pluginServiceStatusTestCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tc.path {
					t.Errorf("request path = %q, want %q", r.URL.Path, tc.path)
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			defer server.Close()

			collector := tc.new()
			collector.Register(namespace, "test-instance", promslog.NewNopLogger())
			metrics := collectMetrics(t, collector, newCollectorTestClient(t, server))
			if len(metrics) != 0 {
				t.Fatalf("got %d metrics for a 404, want 0", len(metrics))
			}
		})
	}
}

func TestPluginServiceStatusCollectorsPropagateNon404Errors(t *testing.T) {
	for _, tc := range pluginServiceStatusTestCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tc.path {
					t.Errorf("request path = %q, want %q", r.URL.Path, tc.path)
				}
				http.Error(w, "upstream failure", http.StatusInternalServerError)
			}))
			defer server.Close()

			collector := tc.new()
			collector.Register(namespace, "test-instance", promslog.NewNopLogger())
			ch := make(chan prometheus.Metric)
			var metrics []prometheus.Metric
			done := make(chan struct{})
			go func() {
				defer close(done)
				for metric := range ch {
					metrics = append(metrics, metric)
				}
			}()
			err := collector.Update(context.Background(), newCollectorTestClient(t, server), ch)
			close(ch)
			<-done
			if err == nil {
				t.Fatal("Update returned nil for HTTP 500")
			}
			if len(metrics) != 0 {
				t.Fatalf("got %d metrics for HTTP 500, want 0", len(metrics))
			}
			if err.StatusCode != http.StatusInternalServerError {
				t.Errorf("error status = %d, want %d", err.StatusCode, http.StatusInternalServerError)
			}
		})
	}
}
