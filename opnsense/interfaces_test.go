package opnsense

import (
	"net/http"
	"testing"
)

// TestParseSFPRXPower covers the combined-string DOM rx_power reading.
// FreeBSD's ifconfig(8) (sbin/ifconfig/sfp.c) formats it as
// "RX power: %.2f mW (%.2f dBm)" — mW leading, dBm parenthesized — verified
// against upstream source 2026-07-25 and against a live OPNsense box
// (sfp.lane_1_rx_power = "0.48 mW (-3.16 dBm)" on ixl0). Each unit is located
// by its own label rather than by position, so order variation and a
// malformed component in either half are tolerated independently.
func TestParseSFPRXPower(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		wantMW    float64
		wantMWOK  bool
		wantDBM   float64
		wantDBMOK bool
	}{
		{
			name:      "live capture (issue #456, ixl0)",
			value:     "0.48 mW (-3.16 dBm)",
			wantMW:    0.48,
			wantMWOK:  true,
			wantDBM:   -3.16,
			wantDBMOK: true,
		},
		{
			name:      "whitespace variation (extra spaces and tabs)",
			value:     "  0.48\tmW\t(  -3.16\tdBm  )",
			wantMW:    0.48,
			wantMWOK:  true,
			wantDBM:   -3.16,
			wantDBMOK: true,
		},
		{
			name:      "reversed order still parses (dBm leading, mW parenthesized)",
			value:     "-2.32 dBm (0.59 mW)",
			wantMW:    0.59,
			wantMWOK:  true,
			wantDBM:   -2.32,
			wantDBMOK: true,
		},
		{
			name:      "positive dBm",
			value:     "1.2 mW (0.79 dBm)",
			wantMW:    1.2,
			wantMWOK:  true,
			wantDBM:   0.79,
			wantDBMOK: true,
		},
		{
			name:      "dBm component malformed, mW still parses",
			value:     "0.48 mW (bogus dBm)",
			wantMW:    0.48,
			wantMWOK:  true,
			wantDBMOK: false,
		},
		{
			name:      "mW component malformed, dBm still parses",
			value:     "bogus mW (-3.16 dBm)",
			wantMWOK:  false,
			wantDBM:   -3.16,
			wantDBMOK: true,
		},
		{
			name:      "completely malformed value",
			value:     "not available",
			wantMWOK:  false,
			wantDBMOK: false,
		},
		{
			name:      "empty string",
			value:     "",
			wantMWOK:  false,
			wantDBMOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw, mwOK, dbm, dbmOK := parseSFPRXPower(tt.value)
			if mwOK != tt.wantMWOK {
				t.Errorf("mwOK = %v, want %v", mwOK, tt.wantMWOK)
			}
			if mwOK && mw != tt.wantMW {
				t.Errorf("mw = %v, want %v", mw, tt.wantMW)
			}
			if dbmOK != tt.wantDBMOK {
				t.Errorf("dbmOK = %v, want %v", dbmOK, tt.wantDBMOK)
			}
			if dbmOK && dbm != tt.wantDBM {
				t.Errorf("dbm = %v, want %v", dbm, tt.wantDBM)
			}
		})
	}
}

func TestFetchInterfaces_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"interfaces": {
				"igb0": {
					"device": "igb0",
					"driver": "igb",
					"index": "1",
					"flags": "0x8843",
					"promiscuous listeners": "0",
					"send queue length": "5",
					"send queue max length": "50",
					"send queue drops": "0",
					"type": "Ethernet",
					"address length": "6",
					"header length": "14",
					"link state": "2",
					"vhid": "0",
					"datalen": "152",
					"mtu": "1500",
					"metric": "0",
					"line rate": "1000000000 bit/s",
					"packets received": "123456",
					"packets transmitted": "654321",
					"bytes received": "98765432",
					"bytes transmitted": "87654321",
					"output errors": "2",
					"input errors": "1",
					"collisions": "0",
					"multicasts received": "500",
					"multicasts transmitted": "300",
					"input queue drops": "3",
					"packets for unknown protocol": "10",
					"HW offload capabilities": "RXCSUM,TXCSUM",
					"uptime at attach or stat reset": "123456",
					"name": "WAN"
				},
				"igb1": {
					"device": "igb1",
					"driver": "igb",
					"index": "2",
					"flags": "0x8843",
					"promiscuous listeners": "0",
					"send queue length": "2",
					"send queue max length": "100",
					"send queue drops": "1",
					"type": "Ethernet",
					"address length": "6",
					"header length": "14",
					"link state": "link state is down",
					"vhid": "0",
					"datalen": "152",
					"mtu": "9000",
					"metric": "0",
					"line rate": " 500 bit/s ",
					"packets received": "0",
					"packets transmitted": "0",
					"bytes received": "0",
					"bytes transmitted": "0",
					"output errors": "0",
					"input errors": "0",
					"collisions": "0",
					"multicasts received": "0",
					"multicasts transmitted": "0",
					"input queue drops": "0",
					"packets for unknown protocol": "0",
					"HW offload capabilities": "",
					"uptime at attach or stat reset": "0",
					"name": "LAN"
				}
			}
		}`))
	})
	defer server.Close()

	data, err := client.FetchInterfaces()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(data.Interfaces) != 2 {
		t.Fatalf("expected 2 interfaces, got %d", len(data.Interfaces))
	}

	// Find the WAN interface (map iteration order is not guaranteed)
	var wan, lan *Interface
	for i := range data.Interfaces {
		switch data.Interfaces[i].Name {
		case "WAN":
			wan = &data.Interfaces[i]
		case "LAN":
			lan = &data.Interfaces[i]
		}
	}

	if wan == nil {
		t.Fatal("WAN interface not found")
	}
	if lan == nil {
		t.Fatal("LAN interface not found")
	}

	// WAN checks
	if wan.Device != "igb0" {
		t.Errorf("expected device 'igb0', got %q", wan.Device)
	}
	if wan.MTU != 1500 {
		t.Errorf("expected MTU=1500, got %d", wan.MTU)
	}
	if wan.PacketsReceived != 123456 {
		t.Errorf("expected PacketsReceived=123456, got %d", wan.PacketsReceived)
	}
	if wan.BytesTransmitted != 87654321 {
		t.Errorf("expected BytesTransmitted=87654321, got %d", wan.BytesTransmitted)
	}
	if wan.InputErrors != 1 {
		t.Errorf("expected InputErrors=1, got %d", wan.InputErrors)
	}
	if wan.OutputErrors != 2 {
		t.Errorf("expected OutputErrors=2, got %d", wan.OutputErrors)
	}
	if wan.LinkState != 1 {
		t.Errorf("expected LinkState=1 (up), got %d", wan.LinkState)
	}
	if wan.LineRate != 1000000000 {
		t.Errorf("expected LineRate=1000000000, got %d", wan.LineRate)
	}
	if wan.SendQueueLength != 5 {
		t.Errorf("expected SendQueueLength=5, got %d", wan.SendQueueLength)
	}
	if wan.SendQueueMaxLength != 50 {
		t.Errorf("expected SendQueueMaxLength=50, got %d", wan.SendQueueMaxLength)
	}
	if wan.InputQueueDrops != 3 {
		t.Errorf("expected InputQueueDrops=3, got %d", wan.InputQueueDrops)
	}
	if wan.Driver != "igb" {
		t.Errorf("expected Driver=igb, got %q", wan.Driver)
	}
	if wan.HWOffloadCapabilities != "RXCSUM,TXCSUM" {
		t.Errorf("expected HWOffloadCapabilities=RXCSUM,TXCSUM, got %q", wan.HWOffloadCapabilities)
	}

	// LAN checks
	if lan.LinkState != 0 {
		t.Errorf("expected LinkState=0 (down), got %d", lan.LinkState)
	}
	if lan.MTU != 9000 {
		t.Errorf("expected MTU=9000, got %d", lan.MTU)
	}
	if lan.LineRate != 500 {
		t.Errorf("expected LineRate=500, got %d", lan.LineRate)
	}
	if lan.Driver != "igb" {
		t.Errorf("expected Driver=igb, got %q", lan.Driver)
	}
	if lan.HWOffloadCapabilities != "" {
		t.Errorf("expected HWOffloadCapabilities='', got %q", lan.HWOffloadCapabilities)
	}
}

// TestNormalizeHWOffloadCapabilities covers the sort-and-dedupe normalization
// applied to the raw "HW offload capabilities" comma list. The wire value is
// already comma-separated but its ordering is not documented as stable, so a
// naive pass-through would let the box's own reordering churn the label value
// on unrelated polls; sorting makes the series stable across polls that
// report the same capability set in a different order.
func TestNormalizeHWOffloadCapabilities(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty", input: "", want: ""},
		{name: "already sorted", input: "RXCSUM,TXCSUM", want: "RXCSUM,TXCSUM"},
		{name: "out of order", input: "TXCSUM,RXCSUM", want: "RXCSUM,TXCSUM"},
		{name: "extra whitespace", input: "TXCSUM, RXCSUM ,  TSO4", want: "RXCSUM,TSO4,TXCSUM"},
		{name: "duplicate entries collapsed", input: "TXCSUM,TXCSUM,RXCSUM", want: "RXCSUM,TXCSUM"},
		{name: "trailing comma / empty tokens dropped", input: "RXCSUM,TXCSUM,", want: "RXCSUM,TXCSUM"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeHWOffloadCapabilities(tt.input)
			if got != tt.want {
				t.Errorf("normalizeHWOffloadCapabilities(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestFetchInterfaces_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchInterfaces()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

// TestFetchInterfaces_LinkStateTriState guards #86: the kernel link state is
// tri-state ("2"=up, "1"=down, "0"=unknown). "0" (unknown, reported for PPPoE
// and other carrier-less pseudo-devices) must NOT be collapsed to the same value
// as a genuine "1" (down), or healthy PPPoE WANs read as permanently down.
func TestFetchInterfaces_LinkStateTriState(t *testing.T) {
	cases := []struct {
		name      string
		linkState string
		want      int
	}{
		{"up numeric", "2", LinkStateUp},
		{"down numeric", "1", LinkStateDown},
		{"unknown numeric", "0", LinkStateUnknown},
		{"up legacy string", "link state is up", LinkStateUp},
		{"down legacy string", "link state is down", LinkStateDown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`{"interfaces":{"x0":{"device":"x0","name":"X0","type":"Ethernet","link state":"` + tc.linkState + `","mtu":"1500","bytes received":"0","bytes transmitted":"0","packets received":"0","packets transmitted":"0","multicasts received":"0","multicasts transmitted":"0","input errors":"0","output errors":"0","collisions":"0","send queue length":"0","send queue max length":"0","send queue drops":"0","input queue drops":"0"}}}`))
			})
			defer server.Close()

			data, err := client.FetchInterfaces()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(data.Interfaces) != 1 {
				t.Fatalf("expected 1 interface, got %d", len(data.Interfaces))
			}
			if got := data.Interfaces[0].LinkState; got != tc.want {
				t.Errorf("link state %q: got %d, want %d", tc.linkState, got, tc.want)
			}
		})
	}
}

// TestFetchInterfaces_LineRateValid guards #644: line rate is a kernel
// placeholder (not a real negotiated rate) on carrier-less pseudo-devices,
// which the kernel reports with LinkStateUnknown ("0" on the wire). Real
// captured values: pppoe0 reads exactly 64000 (ng_pppoe's static baudrate,
// not the underlying WAN's actual ~1Gbit/s FTTP rate); tailscale0/zen0 read
// 0. Both must be suppressed (LineRateValid=false). A genuinely-down
// Ethernet NIC (LinkStateDown, not Unknown) must NOT be suppressed — its
// line rate is real data even if link is currently down.
func TestFetchInterfaces_LineRateValid(t *testing.T) {
	cases := []struct {
		name      string
		linkState string // wire value
		lineRate  string
		wantValid bool
	}{
		{"pppoe0 live capture: unknown link state, 64000 placeholder", "0", "64000 bit/s", false},
		{"tailscale0-shaped: unknown link state, 0 placeholder", "0", "0 bit/s", false},
		{"zen0-shaped: unknown link state, 0 placeholder", "0", "0 bit/s", false},
		{"ethernet up: real negotiated rate kept", "2", "1000000000 bit/s", true},
		{"ethernet genuinely down: not unknown, rate kept", "1", "1000000000 bit/s", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`{"interfaces":{"x0":{"device":"x0","name":"X0","type":"Ethernet","link state":"` + tc.linkState + `","line rate":"` + tc.lineRate + `","mtu":"1500"}}}`))
			})
			defer server.Close()

			data, err := client.FetchInterfaces()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(data.Interfaces) != 1 {
				t.Fatalf("expected 1 interface, got %d", len(data.Interfaces))
			}
			if got := data.Interfaces[0].LineRateValid; got != tc.wantValid {
				t.Errorf("LineRateValid = %v, want %v (linkState=%q lineRate=%q)", got, tc.wantValid, tc.linkState, tc.lineRate)
			}
		})
	}
}

// TestFetchInterfaces_TolerantFieldParsing guards #102: one malformed/missing
// counter field on a single interface must degrade only that metric to 0, not
// abort the whole fetch and blank every interface's metrics for the scrape.
func TestFetchInterfaces_TolerantFieldParsing(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		// igb0 is fully valid; newtun0 has an empty "send queue max length".
		w.Write([]byte(`{"interfaces":{
			"igb0":{"device":"igb0","name":"LAN","type":"Ethernet","link state":"2","mtu":"1500","bytes received":"100","bytes transmitted":"200","packets received":"10","packets transmitted":"20","multicasts received":"0","multicasts transmitted":"0","input errors":"0","output errors":"0","collisions":"0","send queue length":"0","send queue max length":"50","send queue drops":"0","input queue drops":"0"},
			"newtun0":{"device":"newtun0","name":"TUN","type":"Tunnel","link state":"0","mtu":"1400","bytes received":"5","bytes transmitted":"6","packets received":"1","packets transmitted":"2","multicasts received":"0","multicasts transmitted":"0","input errors":"0","output errors":"0","collisions":"0","send queue length":"0","send queue max length":"","send queue drops":"0","input queue drops":"0"}
		}}`))
	})
	defer server.Close()

	data, err := client.FetchInterfaces()
	if err != nil {
		t.Fatalf("expected nil error (one bad field must not abort the fetch), got: %v", err)
	}
	if len(data.Interfaces) != 2 {
		t.Fatalf("expected 2 interfaces present despite one bad field, got %d", len(data.Interfaces))
	}
	for _, iface := range data.Interfaces {
		switch iface.Device {
		case "igb0":
			if iface.BytesReceived != 100 || iface.SendQueueMaxLength != 50 {
				t.Errorf("igb0 valid fields mis-parsed: %+v", iface)
			}
		case "newtun0":
			if iface.SendQueueMaxLength != 0 {
				t.Errorf("newtun0 malformed field should default to 0, got %d", iface.SendQueueMaxLength)
			}
			if iface.BytesReceived != 5 {
				t.Errorf("newtun0 other fields must still parse, got BytesReceived=%d", iface.BytesReceived)
			}
		}
	}
}

// TestFetchInterfaces_MalformedJSON guards #102's scope: a genuine decode failure
// still returns an error (the fix narrows error scope to per-field parsing only).
func TestFetchInterfaces_MalformedJSON(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{not valid json`))
	})
	defer server.Close()

	if _, err := client.FetchInterfaces(); err == nil {
		t.Fatal("expected a non-nil error for malformed JSON")
	}
}

func TestFetchInterfaces_EmptyInterfaces(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"interfaces": {}}`))
	})
	defer server.Close()

	data, err := client.FetchInterfaces()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Interfaces) != 0 {
		t.Errorf("expected 0 interfaces, got %d", len(data.Interfaces))
	}
}

func TestFetchInterfacesOverview_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"total": 3, "rowCount": 3, "current": 1,
			"rows": [
				{
					"device": "ixl0",
					"identifier": "lan",
					"description": "LAN",
					"status": "up",
					"flags": ["up", "broadcast", "running", "multicast"],
					"media": "10Gbase-SR <full-duplex>",
					"media_raw": "Ethernet autoselect (10Gbase-SR <full-duplex>)",
					"link_type": "static",
					"vlan_tag": null,
					"is_physical": true,
					"enabled": true,
					"mtu": "1500"
				},
				{
					"device": "ixl1",
					"identifier": "",
					"description": "Unassigned Interface",
					"status": "no carrier",
					"flags": ["broadcast", "simplex", "multicast"],
					"media": "Ethernet autoselect",
					"is_physical": true,
					"mtu": "1500"
				},
				{
					"device": "ixl0_vlan100",
					"identifier": "opt3",
					"description": "MGMT",
					"status": "up",
					"flags": ["up", "broadcast", "running", "multicast"],
					"media": "10Gbase-SR <full-duplex>",
					"link_type": "static",
					"vlan_tag": "100",
					"vlan": {"tag": "100", "proto": "802.1q", "pcp": "7", "parent": "ixl0"},
					"is_physical": false,
					"mtu": "1500"
				}
			]
		}`))
	})
	defer server.Close()

	data, err := client.FetchInterfacesOverview()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Interfaces) != 3 {
		t.Fatalf("expected 3 interfaces, got %d", len(data.Interfaces))
	}

	lan := data.Interfaces[0]
	if lan.Device != "ixl0" || lan.Identifier != "lan" || lan.Description != "LAN" {
		t.Errorf("unexpected lan identity: %+v", lan)
	}
	if !lan.AdminUp {
		t.Error("expected lan AdminUp=true (flags contain 'up')")
	}
	if lan.Status != "up" || lan.Media != "10Gbase-SR <full-duplex>" || lan.LinkType != "static" {
		t.Errorf("unexpected lan fields: %+v", lan)
	}
	if lan.VlanTag != "" || lan.VlanParent != "" {
		t.Errorf("expected empty vlan fields for lan, got %+v", lan)
	}
	if !lan.Physical {
		t.Error("expected lan Physical=true")
	}
	// #584: Enabled is the config-level "administratively disabled" flag,
	// distinct from AdminUp (derived from the ifconfig UP flag). This
	// fixture's lan row carries the raw "enabled": true.
	if !lan.Enabled {
		t.Error("expected lan Enabled=true")
	}

	unassigned := data.Interfaces[1]
	if unassigned.AdminUp {
		t.Error("expected unassigned AdminUp=false (no 'up' flag)")
	}
	if unassigned.Status != "no carrier" {
		t.Errorf("expected status 'no carrier', got %q", unassigned.Status)
	}
	// This fixture row omits "enabled" entirely; Go's zero value (false) is
	// the conservative default. OverviewController's parseIfInfo always sets
	// this key (!empty($config['enable'])), so an omission should never
	// happen live -- this pins the decode behaviour if it ever does.
	if unassigned.Enabled {
		t.Error("expected unassigned Enabled=false (key absent from fixture)")
	}

	vlan := data.Interfaces[2]
	if vlan.VlanTag != "100" || vlan.VlanParent != "ixl0" {
		t.Errorf("expected vlan tag=100 parent=ixl0, got %+v", vlan)
	}
	if vlan.Physical {
		t.Error("expected vlan Physical=false")
	}
}

// TestFetchInterfacesOverview_EnabledIndependentOfAdminUp guards #584: Enabled
// (the config-level admin-enabled flag, OverviewController's parseIfInfo:
// `!empty($config['enable'])`) is genuinely independent of AdminUp (derived
// from the ifconfig "up" flag) -- an interface can be link-up while
// administratively disabled in config (e.g. a stale ifconfig read before the
// disable takes effect) or vice versa, and the exporter must decode both
// without deriving either from the other.
func TestFetchInterfacesOverview_EnabledIndependentOfAdminUp(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 1, "rowCount": 1, "current": 1,
			"rows": [
				{
					"device": "ixl2",
					"identifier": "opt5",
					"description": "DMZ",
					"status": "up",
					"flags": ["up", "broadcast", "running", "multicast"],
					"is_physical": true,
					"enabled": false
				}
			]
		}`))
	})
	defer server.Close()

	data, err := client.FetchInterfacesOverview()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Interfaces) != 1 {
		t.Fatalf("expected 1 interface, got %d", len(data.Interfaces))
	}
	iface := data.Interfaces[0]
	if !iface.AdminUp {
		t.Error("expected AdminUp=true (flags contain 'up')")
	}
	if iface.Enabled {
		t.Error("expected Enabled=false (\"enabled\": false in the fixture) -- must not be derived from AdminUp")
	}
}

func TestFetchInterfacesOverview_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchInterfacesOverview()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

// TestFetchInterfacesOverview_SFPCopperNoDOM mirrors a real prod OPNsense 26.1
// box (2026-07-13 capture): two ixl(4) ports each carry a UBNT UF-RJ45-1G
// copper RJ45 SFP. Copper modules populate identity fields only — no
// temperature/voltage/lane_*_rx_power/lane_*_tx_bias — and the box has no
// LAGG or bridge interfaces at all. DOM series must degrade to absent, never
// zero (#214).
func TestFetchInterfacesOverview_SFPCopperNoDOM(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 1, "rowCount": 1, "current": 1,
			"rows": [
				{
					"device": "ixl0",
					"identifier": "wan",
					"description": "WAN",
					"status": "up",
					"flags": ["up", "broadcast", "running", "multicast"],
					"media": "SFP/SFP+/SFP28 1000BASE-T <full-duplex>",
					"link_type": "static",
					"vlan_tag": null,
					"is_physical": true,
					"sfp": {
						"plugged": "SFP/SFP+/SFP28 1000BASE-T (Unknown)",
						"vendor": "UBNT",
						"part_number": " UF-RJ45-1G",
						"serial_number": "X00000000001",
						"manufacturing_date": "2021-04-07"
					}
				}
			]
		}`))
	})
	defer server.Close()

	data, err := client.FetchInterfacesOverview()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(data.Laggs) != 0 || len(data.LaggPorts) != 0 || len(data.BridgeMembers) != 0 {
		t.Errorf("expected no lagg/bridge data, got laggs=%d laggPorts=%d bridgeMembers=%d",
			len(data.Laggs), len(data.LaggPorts), len(data.BridgeMembers))
	}

	if len(data.SFPModules) != 1 {
		t.Fatalf("expected 1 SFP module, got %d", len(data.SFPModules))
	}
	sfp := data.SFPModules[0]
	if sfp.Device != "ixl0" {
		t.Errorf("expected device ixl0, got %q", sfp.Device)
	}
	if sfp.Vendor != "UBNT" {
		t.Errorf("expected vendor UBNT, got %q", sfp.Vendor)
	}
	// PN comes off the wire with a leading space (interfaces.lib.inc's PN:(.*)
	// capture has no \s+ before the value) — the parser must trim it.
	if sfp.PartNumber != "UF-RJ45-1G" {
		t.Errorf("expected trimmed part number UF-RJ45-1G, got %q", sfp.PartNumber)
	}
	if sfp.SerialNumber != "X00000000001" {
		t.Errorf("expected serial X00000000001, got %q", sfp.SerialNumber)
	}
	if sfp.ManufacturingDate != "2021-04-07" {
		t.Errorf("expected manufacturing date 2021-04-07, got %q", sfp.ManufacturingDate)
	}

	// The whole point of the copper-RJ45 case: DOM must be absent, never 0.
	if sfp.TemperaturePresent {
		t.Errorf("expected TemperaturePresent=false for a copper SFP, got value %v", sfp.TemperatureC)
	}
	if sfp.VoltagePresent {
		t.Errorf("expected VoltagePresent=false for a copper SFP, got value %v", sfp.VoltageV)
	}
	if len(sfp.Lanes) != 0 {
		t.Errorf("expected no DOM lanes for a copper SFP, got %+v", sfp.Lanes)
	}
	// #456: neither rx_power series (mW or dBm) exists for a copper module,
	// since there are no lanes at all to carry RXPowerMWPresent/RXPowerPresent.
}

// TestFetchInterfacesOverview_SFPOpticalWithDOM is source-derived: OPNsense
// core's legacy_interfaces_details() (interfaces.lib.inc lines 401-424)
// parses `ifconfig -Lmv`'s "module temperature: X C voltage: Y Volts" and
// "lane N: RX power: A TX bias: B" lines verbatim, including their unit
// suffixes, into the sfp map. This models a DOM-capable optical transceiver
// (e.g. an Intel ixl/ix or Chelsio NIC) with two lanes.
//
// CORRECTED 2026-07-25 (#456): the rx_power fixture below previously read
// "-2.32 dBm (0.59 mW)" — dBm leading, mW parenthesized. That ordering was
// WRONG; it was never captured from a real box. FreeBSD's ifconfig(8)
// (sbin/ifconfig/sfp.c) formats it "RX power: %.2f mW (%.2f dBm)" — mW
// always leads, dBm is always parenthesized — confirmed against upstream
// ifconfig source and a live OPNsense box (sfp.lane_1_rx_power =
// "0.48 mW (-3.16 dBm)" on ixl0). The wrong order let the old leading-float
// parser accidentally read the right number for the wrong reason: it always
// took the first token, which happened to be dBm in this fixture but is mW
// on every real box, so the shipped exporter published the mW value under
// the "_dbm" metric name. See parseSFPRXPower, which now locates each unit
// by its own label instead of by position.
func TestFetchInterfacesOverview_SFPOpticalWithDOM(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 1, "rowCount": 1, "current": 1,
			"rows": [
				{
					"device": "ix0",
					"identifier": "opt1",
					"description": "SFP1",
					"status": "up",
					"flags": ["up", "broadcast", "running", "multicast"],
					"media": "10Gbase-SR <full-duplex>",
					"link_type": "static",
					"vlan_tag": null,
					"is_physical": true,
					"sfp": {
						"plugged": "SFP+ 10GBASE-SR",
						"vendor": "FS",
						"part_number": "SFP-10GSR-85",
						"serial_number": "G2129012345",
						"manufacturing_date": "2021-01-01",
						"temperature": "32.79 C",
						"voltage": "3.30 ",
						"lane_1_rx_power": "0.59 mW (-2.32 dBm)",
						"lane_1_tx_bias": "6.02 mA",
						"lane_2_rx_power": "0.56 mW (-2.55 dBm)",
						"lane_2_tx_bias": "6.10 mA"
					}
				}
			]
		}`))
	})
	defer server.Close()

	data, err := client.FetchInterfacesOverview()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.SFPModules) != 1 {
		t.Fatalf("expected 1 SFP module, got %d", len(data.SFPModules))
	}
	sfp := data.SFPModules[0]

	if !sfp.TemperaturePresent {
		t.Fatal("expected TemperaturePresent=true")
	}
	if sfp.TemperatureC != 32.79 {
		t.Errorf("expected temperature 32.79, got %v", sfp.TemperatureC)
	}
	if !sfp.VoltagePresent {
		t.Fatal("expected VoltagePresent=true")
	}
	if sfp.VoltageV != 3.30 {
		t.Errorf("expected voltage 3.30, got %v", sfp.VoltageV)
	}

	if len(sfp.Lanes) != 2 {
		t.Fatalf("expected 2 DOM lanes, got %d: %+v", len(sfp.Lanes), sfp.Lanes)
	}
	byLane := map[string]SFPLane{}
	for _, l := range sfp.Lanes {
		byLane[l.Lane] = l
	}
	l1, ok := byLane["1"]
	if !ok {
		t.Fatalf("expected lane 1, got %+v", sfp.Lanes)
	}
	if !l1.RXPowerPresent || l1.RXPowerDBM != -2.32 {
		t.Errorf("expected lane 1 rx power -2.32 dBm (present), got %+v", l1)
	}
	if !l1.RXPowerMWPresent || l1.RXPowerMW != 0.59 {
		t.Errorf("expected lane 1 rx power 0.59 mW (present), got %+v", l1)
	}
	if !l1.TXBiasPresent || l1.TXBiasMA != 6.02 {
		t.Errorf("expected lane 1 tx bias 6.02 (present), got %+v", l1)
	}
	l2, ok := byLane["2"]
	if !ok {
		t.Fatalf("expected lane 2, got %+v", sfp.Lanes)
	}
	if !l2.RXPowerPresent || l2.RXPowerDBM != -2.55 {
		t.Errorf("expected lane 2 rx power -2.55 dBm (present), got %+v", l2)
	}
	if !l2.RXPowerMWPresent || l2.RXPowerMW != 0.56 {
		t.Errorf("expected lane 2 rx power 0.56 mW (present), got %+v", l2)
	}
	if !l2.TXBiasPresent || l2.TXBiasMA != 6.10 {
		t.Errorf("expected lane 2 tx bias 6.10 (present), got %+v", l2)
	}
}

// TestFetchInterfacesOverview_SFPRXPowerPartial covers #456's tolerance
// requirement at the fetch layer (not just the parser unit test): when one
// component of a lane's rx_power reading is malformed, exactly the
// independently-parseable component's Present flag is set — never a
// zero-substitution on the broken half, and never suppressing the good half.
func TestFetchInterfacesOverview_SFPRXPowerPartial(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 1, "rowCount": 1, "current": 1,
			"rows": [
				{
					"device": "ix0",
					"identifier": "opt1",
					"description": "SFP1",
					"status": "up",
					"flags": ["up", "broadcast", "running", "multicast"],
					"media": "10Gbase-SR <full-duplex>",
					"link_type": "static",
					"vlan_tag": null,
					"is_physical": true,
					"sfp": {
						"plugged": "SFP+ 10GBASE-SR",
						"vendor": "FS",
						"part_number": "SFP-10GSR-85",
						"serial_number": "G2129012345",
						"manufacturing_date": "2021-01-01",
						"lane_1_rx_power": "0.48 mW (N/A)",
						"lane_2_rx_power": "N/A (-3.16 dBm)",
						"lane_3_rx_power": "totally unparseable"
					}
				}
			]
		}`))
	})
	defer server.Close()

	data, err := client.FetchInterfacesOverview()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.SFPModules) != 1 {
		t.Fatalf("expected 1 SFP module, got %d", len(data.SFPModules))
	}
	byLane := map[string]SFPLane{}
	for _, l := range data.SFPModules[0].Lanes {
		byLane[l.Lane] = l
	}

	l1, ok := byLane["1"]
	if !ok {
		t.Fatalf("expected lane 1, got %+v", data.SFPModules[0].Lanes)
	}
	if !l1.RXPowerMWPresent || l1.RXPowerMW != 0.48 {
		t.Errorf("lane 1: expected mW=0.48 present, got %+v", l1)
	}
	if l1.RXPowerPresent {
		t.Errorf("lane 1: expected dBm absent (malformed), got %+v", l1)
	}

	l2, ok := byLane["2"]
	if !ok {
		t.Fatalf("expected lane 2, got %+v", data.SFPModules[0].Lanes)
	}
	if l2.RXPowerMWPresent {
		t.Errorf("lane 2: expected mW absent (malformed), got %+v", l2)
	}
	if !l2.RXPowerPresent || l2.RXPowerDBM != -3.16 {
		t.Errorf("lane 2: expected dBm=-3.16 present, got %+v", l2)
	}

	l3, ok := byLane["3"]
	if !ok {
		t.Fatalf("expected lane 3, got %+v", data.SFPModules[0].Lanes)
	}
	if l3.RXPowerMWPresent || l3.RXPowerPresent {
		t.Errorf("lane 3: expected both mW and dBm absent for a completely malformed reading, got %+v", l3)
	}
}

// TestFetchInterfacesOverview_LaggLACPWithMembers is source-derived from
// interfaces.lib.inc lines 431-464: an LACP lagg reports laggproto+lagghash,
// a "lagg statistics:" block (active ports/flapping), and a laggport map
// whose per-member "state=" clause is LACP-only (collecting/distributing).
func TestFetchInterfacesOverview_LaggLACPWithMembers(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 1, "rowCount": 1, "current": 1,
			"rows": [
				{
					"device": "lagg0",
					"identifier": "lan",
					"description": "LAN",
					"status": "up",
					"flags": ["up", "broadcast", "running", "multicast"],
					"media": "Ethernet autoselect",
					"link_type": "static",
					"vlan_tag": null,
					"is_physical": true,
					"laggproto": "lacp",
					"lagghash": "l2,l3,l4",
					"laggstatistics": {
						"active ports": "2",
						"flapping": "0"
					},
					"laggport": {
						"ix0": {
							"flags": ["active"],
							"state": ["active", "collecting", "distributing"]
						},
						"ix1": {
							"flags": ["active"],
							"state": ["active", "collecting", "distributing"]
						}
					}
				}
			]
		}`))
	})
	defer server.Close()

	data, err := client.FetchInterfacesOverview()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(data.Laggs) != 1 {
		t.Fatalf("expected 1 lagg, got %d", len(data.Laggs))
	}
	lagg := data.Laggs[0]
	if lagg.Device != "lagg0" || lagg.Protocol != "lacp" || lagg.Hash != "l2,l3,l4" {
		t.Errorf("unexpected lagg info: %+v", lagg)
	}
	if !lagg.StatsPresent {
		t.Fatal("expected StatsPresent=true")
	}
	if lagg.ActivePorts != 2 || lagg.Flapping != 0 {
		t.Errorf("expected active_ports=2 flapping=0, got %+v", lagg)
	}

	if len(data.LaggPorts) != 2 {
		t.Fatalf("expected 2 lagg ports, got %d", len(data.LaggPorts))
	}
	for _, p := range data.LaggPorts {
		if p.Lagg != "lagg0" {
			t.Errorf("expected owning lagg lagg0, got %q", p.Lagg)
		}
		if !p.Active {
			t.Errorf("expected port %q active=true", p.Port)
		}
		if !p.StatePresent {
			t.Errorf("expected port %q StatePresent=true", p.Port)
		}
		if !p.Collecting || !p.Distributing {
			t.Errorf("expected port %q collecting+distributing=true, got %+v", p.Port, p)
		}
	}
}

// TestFetchInterfacesOverview_LaggFailoverNoLACPState is source-derived:
// non-LACP protocols (failover, loadbalance, ...) never carry a laggport
// "state=" clause (interfaces.lib.inc line 455-456's second alternation has
// no state group), and failover in particular carries no lagghash. The
// standby port's "active" flag is absent.
func TestFetchInterfacesOverview_LaggFailoverNoLACPState(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 1, "rowCount": 1, "current": 1,
			"rows": [
				{
					"device": "lagg0",
					"identifier": "lan",
					"description": "LAN",
					"status": "up",
					"flags": ["up", "broadcast", "running", "multicast"],
					"media": "Ethernet autoselect",
					"link_type": "static",
					"vlan_tag": null,
					"is_physical": true,
					"laggproto": "failover",
					"laggport": {
						"ix0": {"flags": ["active"]},
						"ix1": {"flags": []}
					}
				}
			]
		}`))
	})
	defer server.Close()

	data, err := client.FetchInterfacesOverview()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(data.Laggs) != 1 {
		t.Fatalf("expected 1 lagg, got %d", len(data.Laggs))
	}
	lagg := data.Laggs[0]
	if lagg.Protocol != "failover" || lagg.Hash != "" {
		t.Errorf("expected failover protocol with empty hash, got %+v", lagg)
	}
	if lagg.StatsPresent {
		t.Errorf("expected StatsPresent=false (no laggstatistics block), got %+v", lagg)
	}

	if len(data.LaggPorts) != 2 {
		t.Fatalf("expected 2 lagg ports, got %d", len(data.LaggPorts))
	}
	var active, standby *LaggPort
	for i := range data.LaggPorts {
		p := &data.LaggPorts[i]
		if p.Port == "ix0" {
			active = p
		}
		if p.Port == "ix1" {
			standby = p
		}
	}
	if active == nil || !active.Active {
		t.Fatalf("expected ix0 active=true, got %+v", active)
	}
	if active.StatePresent {
		t.Error("expected StatePresent=false for a failover lagg (no LACP state)")
	}
	if standby == nil || standby.Active {
		t.Fatalf("expected ix1 active=false, got %+v", standby)
	}
}

// TestFetchInterfacesOverview_BridgeWithMembers is source-derived from
// interfaces.lib.inc lines 505-511: a bridge(4) interface's "members" map
// keys by member device name.
func TestFetchInterfacesOverview_BridgeWithMembers(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 1, "rowCount": 1, "current": 1,
			"rows": [
				{
					"device": "bridge0",
					"identifier": "opt5",
					"description": "GUESTBRIDGE",
					"status": "up",
					"flags": ["up", "broadcast", "running", "multicast"],
					"media": "Ethernet autoselect",
					"link_type": "static",
					"vlan_tag": null,
					"is_physical": false,
					"members": {
						"ix2": {"flags": ["learning", "discover", "autoedge", "autoptp"]},
						"ix3": {"flags": ["learning", "discover", "autoedge", "autoptp"]}
					}
				}
			]
		}`))
	})
	defer server.Close()

	data, err := client.FetchInterfacesOverview()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(data.BridgeMembers) != 2 {
		t.Fatalf("expected 2 bridge members, got %d", len(data.BridgeMembers))
	}
	for _, m := range data.BridgeMembers {
		if m.Bridge != "bridge0" {
			t.Errorf("expected owning bridge bridge0, got %q", m.Bridge)
		}
	}
	if data.BridgeMembers[0].Member != "ix2" || data.BridgeMembers[1].Member != "ix3" {
		t.Errorf("expected sorted members ix2, ix3, got %+v", data.BridgeMembers)
	}
}

// TestFetchInterfacesOverview_Addresses covers #248: interfaces_info carries the
// interface's configured addresses ("ipv4"/"ipv6" arrays of {"ipaddr": "<cidr>"}),
// which log enrichment needs to classify a packet's scope (self/local/remote).
// A row with no address keys at all must yield empty slices, never an error.
func TestFetchInterfacesOverview_Addresses(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 3, "rowCount": 3, "current": 1,
			"rows": [
				{
					"device": "vtnet0",
					"identifier": "lan",
					"description": "LAN",
					"status": "up",
					"flags": ["up", "broadcast", "running", "multicast"],
					"is_physical": true,
					"addr4": "10.0.0.114/24",
					"addr6": "fd6b:1111:2222:3333::/64",
					"ipv4": [{"ipaddr": "10.0.0.114/24"}],
					"ipv6": [
						{"ipaddr": "fd6b:1111:2222:3333::d512/64"},
						{"ipaddr": "fe80::1a2b:3cff:fe4d:5e6f/64", "link-local": true}
					]
				},
				{
					"device": "vtnet1",
					"identifier": "",
					"description": "Unassigned Interface",
					"status": "no carrier",
					"is_physical": true
				},
				{
					"device": "vtnet2",
					"identifier": "opt1",
					"description": "DMZ",
					"status": "up",
					"is_physical": true,
					"ipv4": null,
					"ipv6": []
				}
			]
		}`))
	})
	defer server.Close()

	data, err := client.FetchInterfacesOverview()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Interfaces) != 3 {
		t.Fatalf("expected 3 interfaces, got %d", len(data.Interfaces))
	}

	lan := data.Interfaces[0]
	if len(lan.IPv4) != 1 || lan.IPv4[0] != "10.0.0.114/24" {
		t.Errorf("expected lan IPv4 [10.0.0.114/24], got %v", lan.IPv4)
	}
	if len(lan.IPv6) != 2 ||
		lan.IPv6[0] != "fd6b:1111:2222:3333::d512/64" ||
		lan.IPv6[1] != "fe80::1a2b:3cff:fe4d:5e6f/64" {
		t.Errorf("expected both lan IPv6 CIDRs (incl. link-local), got %v", lan.IPv6)
	}

	// Missing keys entirely: empty, not an error.
	unassigned := data.Interfaces[1]
	if len(unassigned.IPv4) != 0 || len(unassigned.IPv6) != 0 {
		t.Errorf("expected no addresses on unassigned iface, got %v / %v", unassigned.IPv4, unassigned.IPv6)
	}

	// Explicit null / empty array: also empty, not an error.
	dmz := data.Interfaces[2]
	if len(dmz.IPv4) != 0 || len(dmz.IPv6) != 0 {
		t.Errorf("expected no addresses on dmz iface, got %v / %v", dmz.IPv4, dmz.IPv6)
	}
}

// TestFetchInterfaces_UnknownProtocolPackets guards #375: "packets for unknown
// protocol" is a plain tolerant counter (safeAtoi, 0 on missing/malformed),
// consistent with every other counter on this struct (#102).
func TestFetchInterfaces_UnknownProtocolPackets(t *testing.T) {
	cases := []struct {
		name  string
		field string
		want  int64
	}{
		{"non-zero", `"packets for unknown protocol":"13852362",`, 13852362},
		{"zero", `"packets for unknown protocol":"0",`, 0},
		{"missing", ``, 0},
		{"malformed", `"packets for unknown protocol":"not-a-number",`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Write([]byte(`{"interfaces":{"x0":{"device":"x0","name":"X0","type":"Ethernet","link state":"2",` + tc.field + `"mtu":"1500"}}}`))
			})
			defer server.Close()

			data, err := client.FetchInterfaces()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(data.Interfaces) != 1 {
				t.Fatalf("expected 1 interface, got %d", len(data.Interfaces))
			}
			if got := data.Interfaces[0].UnknownProtocolPackets; got != tc.want {
				t.Errorf("unknown protocol packets %q: got %d, want %d", tc.field, got, tc.want)
			}
		})
	}
}

// TestFetchInterfaces_AttachOrStatResetMarker guards #375's deliberate parsing
// asymmetry against every other counter on this struct: the "uptime at attach
// or stat reset" marker is a system-uptime *reading*, not a counter, so
// missing/malformed data must never be reported as a fabricated boot-time
// zero. A genuine wire "0" must stay representable as valid-with-value-0.
func TestFetchInterfaces_AttachOrStatResetMarker(t *testing.T) {
	cases := []struct {
		name      string
		field     string
		wantValid bool
		wantValue int64
	}{
		{"non-zero", `"uptime at attach or stat reset":"18",`, true, 18},
		{"genuine zero", `"uptime at attach or stat reset":"0",`, true, 0},
		{"missing", ``, false, 0},
		{"malformed", `"uptime at attach or stat reset":"not-a-number",`, false, 0},
		{"empty string", `"uptime at attach or stat reset":"",`, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Write([]byte(`{"interfaces":{"x0":{"device":"x0","name":"X0","type":"Ethernet","link state":"2",` + tc.field + `"mtu":"1500"}}}`))
			})
			defer server.Close()

			data, err := client.FetchInterfaces()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(data.Interfaces) != 1 {
				t.Fatalf("expected 1 interface, got %d", len(data.Interfaces))
			}
			iface := data.Interfaces[0]
			if iface.AttachOrStatResetValid != tc.wantValid {
				t.Errorf("marker %q: got valid=%v, want %v", tc.field, iface.AttachOrStatResetValid, tc.wantValid)
			}
			if iface.AttachOrStatResetUptime != tc.wantValue {
				t.Errorf("marker %q: got value=%d, want %d", tc.field, iface.AttachOrStatResetUptime, tc.wantValue)
			}
		})
	}
}

// TestFetchInterfaces_AttachOrStatResetMarkerChange guards the interface-
// recreation case that motivated this issue (#361): a marker that jumps
// between fetches (e.g. after a PPPoE bounce) must be reflected verbatim on
// the next fetch, not carried over or smoothed from a previous snapshot.
// FetchInterfaces rebuilds the slice from scratch on every call, so this also
// guards against accidentally introducing cross-call state.
func TestFetchInterfaces_AttachOrStatResetMarkerChange(t *testing.T) {
	marker := `"1"`
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"interfaces":{"x0":{"device":"x0","name":"X0","type":"Ethernet","link state":"2","uptime at attach or stat reset":` + marker + `,"mtu":"1500"}}}`))
	})
	defer server.Close()

	data, err := client.FetchInterfaces()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := data.Interfaces[0].AttachOrStatResetUptime; got != 1 {
		t.Fatalf("expected initial marker=1, got %d", got)
	}

	// Simulate the box recreating the interface: the marker jumps to the new
	// system uptime at recreation time (#361's live pppoe0 evidence: marker
	// 200603 against a system uptime around 200640).
	marker = `"200603"`
	data, err = client.FetchInterfaces()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Interfaces[0].AttachOrStatResetValid {
		t.Fatal("expected marker still valid after recreation")
	}
	if got := data.Interfaces[0].AttachOrStatResetUptime; got != 200603 {
		t.Errorf("expected marker to reflect recreation value 200603, got %d", got)
	}
}

// TestFetchInterfaces_StatedIndex covers the kernel's own per-interface index
// (the "index" key of api/diagnostics/traffic/interface). It is a cross-check
// for the positional NetFlow enumeration, never a substitute for it (#361), so
// it must be surfaced — and it must parse as tolerantly as every other counter
// on the struct: a missing or non-numeric value degrades to 0 for that one
// interface, it does not fail the fetch.
func TestFetchInterfaces_StatedIndex(t *testing.T) {
	cases := []struct {
		name  string
		index string
		want  int
	}{
		{"numeric", `"index":"7",`, 7},
		{"missing", ``, 0},
		{"garbage", `"index":"not-a-number",`, 0},
		{"empty", `"index":"",`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Write([]byte(`{"interfaces":{"x0":{"device":"x0","name":"X0","type":"Ethernet",` + tc.index + `"link state":"2","mtu":"1500"}}}`))
			})
			defer server.Close()

			data, err := client.FetchInterfaces()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(data.Interfaces) != 1 {
				t.Fatalf("expected 1 interface, got %d", len(data.Interfaces))
			}
			if got := data.Interfaces[0].Index; got != tc.want {
				t.Errorf("index %q: got %d, want %d", tc.index, got, tc.want)
			}
		})
	}
}

// TestFetchInterfaces_QueueDropsRejectWrapped32 pins #548. Prod ixl1 reports
// `input queue drops = 4294958080`, which is 2^32 - 9216: a small negative that
// has wrapped through an unsigned 32-bit field somewhere below us, in the driver
// or the netstat plumbing. Published verbatim as a counter it reads as 4.29
// billion drops on a healthy interface, and any rate() spanning the wrap — or a
// later move back toward zero, which looks like a counter reset — is nonsense.
//
// So an implausible value is treated as ABSENT rather than as data. A fabricated
// 0 would be worse than nothing: it claims the interface reported no drops.
//
// The tolerant safeAtoi convention (#102: 0 on a missing or non-numeric field)
// is deliberately kept for the missing/malformed cases, matching every other
// counter on this struct. Only the implausible-value case is rejected.
func TestFetchInterfaces_QueueDropsRejectWrapped32(t *testing.T) {
	cases := []struct {
		name      string
		value     string
		wantValid bool
		wantValue int64
	}{
		{"prod ixl1 wrapped negative", "4294958080", false, 0},
		{"exactly 2^31, the smallest wrap", "2147483648", false, 0},
		{"2^32-1, all ones", "4294967295", false, 0},
		{"already negative on the wire", "-9216", false, 0},
		{"plausible large count", "2147483647", true, 2147483647},
		{"ordinary count", "9216", true, 9216},
		{"genuine zero", "0", true, 0},
		{"missing", "", true, 0},
		{"malformed", "not-a-number", true, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			field := ""
			if tc.value != "" {
				field = `"input queue drops":"` + tc.value + `","send queue drops":"` + tc.value + `",`
			}
			server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Write([]byte(`{"interfaces":{"x0":{"device":"x0","name":"X0","type":"Ethernet","link state":"2",` + field + `"mtu":"1500"}}}`))
			})
			defer server.Close()

			data, err := client.FetchInterfaces()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(data.Interfaces) != 1 {
				t.Fatalf("expected 1 interface, got %d", len(data.Interfaces))
			}
			got := data.Interfaces[0]
			if got.InputQueueDropsValid != tc.wantValid || got.InputQueueDrops != tc.wantValue {
				t.Errorf("input queue drops %q: got (%d, valid=%v), want (%d, valid=%v)",
					tc.value, got.InputQueueDrops, got.InputQueueDropsValid, tc.wantValue, tc.wantValid)
			}
			if got.SendQueueDropsValid != tc.wantValid || got.SendQueueDrops != tc.wantValue {
				t.Errorf("send queue drops %q: got (%d, valid=%v), want (%d, valid=%v)",
					tc.value, got.SendQueueDrops, got.SendQueueDropsValid, tc.wantValue, tc.wantValid)
			}
		})
	}
}
