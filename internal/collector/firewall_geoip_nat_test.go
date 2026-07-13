package collector

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/common/promslog"
)

// registerFirewallCoreHandlers wires the three endpoints the base
// firewallCollector.Update always calls, so GeoIP/NAT-focused tests don't
// need to restate them.
func registerFirewallCoreHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/api/diagnostics/firewall/pf_statistics/interfaces", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"interfaces":{}}`))
	})
	mux.HandleFunc("/api/diagnostics/firewall/pf_states/1", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"current":"1","limit":"2"}`))
	})
	mux.HandleFunc("/api/diagnostics/firewall/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
	})
}

// TestFirewallCollector_GeoIP_NeverConfigured covers the "never touched
// GeoIP" shape (#221): usages/addresses/files all 0, timestamp null. The
// last_update_timestamp_seconds gauge must be entirely ABSENT (never emitted
// as epoch 0), matching the certificate expiry HasValidFrom/HasValidTo
// convention.
func TestFirewallCollector_GeoIP_NeverConfigured(t *testing.T) {
	mux := http.NewServeMux()
	registerFirewallCoreHandlers(mux)
	mux.HandleFunc("/api/firewall/alias/get_geo_i_p", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"alias":{"geoip":{"url":"","usages":0,"address_count":0,"file_count":0,"timestamp":null,"locations_filename":null,"address_sources":{"IPv4":null,"IPv6":null}}}}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)
	c := &firewallCollector{subsystem: FirewallSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	var sawUsages, sawAddresses, sawFiles, sawTimestamp bool
	for _, m := range metrics {
		switch {
		case hasFqName(m, "opnsense_firewall_geoip_alias_usages"):
			sawUsages = true
			if getMetricValue(m) != 0 {
				t.Errorf("expected geoip_alias_usages=0, got %v", getMetricValue(m))
			}
		case hasFqName(m, "opnsense_firewall_geoip_addresses"):
			sawAddresses = true
			if getMetricValue(m) != 0 {
				t.Errorf("expected geoip_addresses=0, got %v", getMetricValue(m))
			}
		case hasFqName(m, "opnsense_firewall_geoip_files"):
			sawFiles = true
			if getMetricValue(m) != 0 {
				t.Errorf("expected geoip_files=0, got %v", getMetricValue(m))
			}
		case hasFqName(m, "opnsense_firewall_geoip_last_update_timestamp_seconds"):
			sawTimestamp = true
		}
	}
	if !sawUsages || !sawAddresses || !sawFiles {
		t.Errorf("expected geoip_alias_usages/addresses/files to always be emitted (usages=%v addresses=%v files=%v)",
			sawUsages, sawAddresses, sawFiles)
	}
	if sawTimestamp {
		t.Error("expected geoip_last_update_timestamp_seconds to be ABSENT for a null timestamp (never emit epoch 0)")
	}
}

// TestFirewallCollector_GeoIP_Downloaded covers the populated shape: a real
// timestamp and non-zero address/file counts.
func TestFirewallCollector_GeoIP_Downloaded(t *testing.T) {
	mux := http.NewServeMux()
	registerFirewallCoreHandlers(mux)
	mux.HandleFunc("/api/firewall/alias/get_geo_i_p", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"alias":{"geoip":{"url":"https://download.maxmind.com/geoip/databases/GeoLite2-Country-CSV/download?suffix=zip&license_key=SECRETKEY123","usages":2,"address_count":123456,"file_count":250,"timestamp":"2026-07-01T12:34:56","locations_filename":"GeoLite2-Country-Locations-en.csv","address_sources":{"IPv4":"blocks-ipv4.csv","IPv6":"blocks-ipv6.csv"}}}}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)
	c := &firewallCollector{subsystem: FirewallSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	var sawTimestamp bool
	for _, m := range metrics {
		switch {
		case hasFqName(m, "opnsense_firewall_geoip_alias_usages"):
			if getMetricValue(m) != 2 {
				t.Errorf("expected geoip_alias_usages=2, got %v", getMetricValue(m))
			}
		case hasFqName(m, "opnsense_firewall_geoip_addresses"):
			if getMetricValue(m) != 123456 {
				t.Errorf("expected geoip_addresses=123456, got %v", getMetricValue(m))
			}
		case hasFqName(m, "opnsense_firewall_geoip_files"):
			if getMetricValue(m) != 250 {
				t.Errorf("expected geoip_files=250, got %v", getMetricValue(m))
			}
		case hasFqName(m, "opnsense_firewall_geoip_last_update_timestamp_seconds"):
			sawTimestamp = true
			const wantUnix = 1782909296 // 2026-07-01T12:34:56 UTC
			if getMetricValue(m) != wantUnix {
				t.Errorf("expected geoip_last_update_timestamp_seconds=%d, got %v", wantUnix, getMetricValue(m))
			}
		}
	}
	if !sawTimestamp {
		t.Error("expected geoip_last_update_timestamp_seconds to be emitted for a populated timestamp")
	}
}

// TestFirewallCollector_GeoIP_FetchErrorIsNonFatal covers the case where the
// GeoIP endpoint itself fails (e.g. transient error): the rest of the
// firewall collector's metrics must still be emitted, and Update must not
// return an error for this — mirroring the existing FetchFirewallStats
// tolerance in the same collector.
func TestFirewallCollector_GeoIP_FetchErrorIsNonFatal(t *testing.T) {
	mux := http.NewServeMux()
	registerFirewallCoreHandlers(mux)
	mux.HandleFunc("/api/firewall/alias/get_geo_i_p", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)
	c := &firewallCollector{subsystem: FirewallSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	// collectMetrics itself fails the test if Update returns an error.
	metrics := collectMetrics(t, c, client)

	for _, m := range metrics {
		if hasFqName(m, "opnsense_firewall_geoip_alias_usages") ||
			hasFqName(m, "opnsense_firewall_geoip_addresses") ||
			hasFqName(m, "opnsense_firewall_geoip_files") ||
			hasFqName(m, "opnsense_firewall_geoip_last_update_timestamp_seconds") {
			t.Errorf("expected no GeoIP metrics on fetch failure, got %s", m.Desc().String())
		}
	}
}

// TestFirewallCollector_NATCounts_DisabledByDefault confirms the opt-in NAT
// rule inventory metric is absent unless SetNATCountsEnabled(true) is called
// — no NAT endpoints are even registered on the mux, so a fetch attempt would
// 404 and fail the test via collectMetrics's error check if it were wrongly
// attempted by default.
func TestFirewallCollector_NATCounts_DisabledByDefault(t *testing.T) {
	mux := http.NewServeMux()
	registerFirewallCoreHandlers(mux)
	mux.HandleFunc("/api/firewall/alias/get_geo_i_p", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"alias":{"geoip":{"url":"","usages":0,"address_count":0,"file_count":0,"timestamp":null,"locations_filename":null,"address_sources":{"IPv4":null,"IPv6":null}}}}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)
	c := &firewallCollector{subsystem: FirewallSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	for _, m := range metrics {
		if hasFqName(m, "opnsense_firewall_nat_rules") {
			t.Errorf("expected no nat_rules metric when NAT counts are disabled, got %s", m.Desc().String())
		}
	}
}

// TestFirewallCollector_NATCounts_Enabled covers all four NAT rule types once
// enabled, including the d_nat inverted "disabled" field encoding.
func TestFirewallCollector_NATCounts_Enabled(t *testing.T) {
	mux := http.NewServeMux()
	registerFirewallCoreHandlers(mux)
	mux.HandleFunc("/api/firewall/alias/get_geo_i_p", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"alias":{"geoip":{"url":"","usages":0,"address_count":0,"file_count":0,"timestamp":null,"locations_filename":null,"address_sources":{"IPv4":null,"IPv6":null}}}}`))
	})
	mux.HandleFunc("/api/firewall/source_nat/search_rule", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[{"uuid":"a","enabled":"1"},{"uuid":"b","enabled":"0"}],"rowCount":1,"total":1,"current":1}`))
	})
	mux.HandleFunc("/api/firewall/d_nat/search_rule", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[{"uuid":"c","disabled":"0"},{"uuid":"d","disabled":"1"}],"rowCount":1,"total":1,"current":1}`))
	})
	mux.HandleFunc("/api/firewall/one_to_one/search_rule", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[{"uuid":"e","enabled":"1"}],"rowCount":1,"total":1,"current":1}`))
	})
	mux.HandleFunc("/api/firewall/npt/search_rule", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[],"rowCount":0,"total":0,"current":1}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)
	c := &firewallCollector{subsystem: FirewallSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	c.SetNATCountsEnabled(true)

	metrics := collectMetrics(t, c, client)

	type key struct{ typ, enabled string }
	got := map[key]float64{}
	for _, m := range metrics {
		if !hasFqName(m, "opnsense_firewall_nat_rules") {
			continue
		}
		labels := getMetricLabels(m)
		got[key{labels["type"], labels["enabled"]}] = getMetricValue(m)
	}

	want := map[key]float64{
		{"source_nat", "true"}: 1, {"source_nat", "false"}: 1,
		{"d_nat", "true"}: 1, {"d_nat", "false"}: 1,
		{"one_to_one", "true"}: 1, {"one_to_one", "false"}: 0,
		{"npt", "true"}: 0, {"npt", "false"}: 0,
	}
	for k, wantVal := range want {
		gotVal, ok := got[k]
		if !ok {
			t.Errorf("missing nat_rules series for type=%s enabled=%s", k.typ, k.enabled)
			continue
		}
		if gotVal != wantVal {
			t.Errorf("nat_rules type=%s enabled=%s: expected %v, got %v", k.typ, k.enabled, wantVal, gotVal)
		}
	}
}
