package opnsense

import (
	"net/http"
	"reflect"
	"testing"
)

// referenceInterfaceConfigBody is a trimmed capture of
// api/diagnostics/interface/get_interface_config from the reference box: the
// real 16 devices in the real order the kernel prints them. Values are cut down
// to what the parser must tolerate — the parser reads keys only, never values.
//
// The key order here IS the fixture. It is deliberately NOT alphabetical, not
// grouped by driver, and not sorted by any property of the key itself, so no
// accidental re-sorting inside the parser can reproduce it.
const referenceInterfaceConfigBody = `{
	"ixl0": {"device": "ixl0", "status": "up", "flags": ["up", "broadcast"], "mtu": "1500"},
	"ixl1": {"device": "ixl1", "status": "no carrier", "flags": ["up"], "mtu": "1500"},
	"ixl2": {"device": "ixl2", "status": "up", "flags": ["up"], "mtu": "1500"},
	"ixl3": {"device": "ixl3", "status": "no carrier", "flags": [], "mtu": "1500"},
	"igb0": {"device": "igb0", "status": "up", "flags": ["up"], "mtu": "1500"},
	"igb1": {"device": "igb1", "status": "no carrier", "flags": [], "mtu": "1500"},
	"lo0": {"device": "lo0", "status": "active", "flags": ["up", "loopback"], "mtu": "16384"},
	"enc0": {"device": "enc0", "status": "active", "flags": ["up"], "mtu": "1536"},
	"pflog0": {"device": "pflog0", "status": "active", "flags": ["up"], "mtu": "33160"},
	"pfsync0": {"device": "pfsync0", "status": "active", "flags": ["up"], "mtu": "1500"},
	"ixl0_vlan100": {"device": "ixl0_vlan100", "status": "up", "flags": ["up"], "mtu": "1500"},
	"ixl0_vlan25": {"device": "ixl0_vlan25", "status": "up", "flags": ["up"], "mtu": "1500"},
	"ixl0_vlan50": {"device": "ixl0_vlan50", "status": "up", "flags": ["up"], "mtu": "1500"},
	"zen0": {"device": "zen0", "status": "active", "flags": ["up"], "mtu": "1500"},
	"pppoe0": {"device": "pppoe0", "status": "up", "flags": ["up", "pointopoint"], "mtu": "1492"},
	"tailscale0": {"device": "tailscale0", "status": "active", "flags": ["up"], "mtu": "1280"}
}`

// referenceInterfaceOrder is the ifinfo order of the fixture above: element i
// is ifIndex i+1. pfsync0 sits at slot 10 — the device that
// api/interfaces/overview/interfaces_info omits, which is precisely why the
// enumeration is derived from get_interface_config instead (#361).
var referenceInterfaceOrder = []string{
	"ixl0", "ixl1", "ixl2", "ixl3", "igb0", "igb1", "lo0", "enc0",
	"pflog0", "pfsync0", "ixl0_vlan100", "ixl0_vlan25", "ixl0_vlan50",
	"zen0", "pppoe0", "tailscale0",
}

// TestFetchInterfaceEnumeration_PreservesKeyOrder is the regression guard
// against the single mistake that silently destroys this feature: decoding the
// response into a map[string]T.
//
// The NetFlow ifIndex is a 1-based POSITION over the device list, carried by
// nothing but the JSON object's key order. Go maps are unordered and their
// range order is deliberately randomised per iteration, so a map-based
// implementation still compiles, still returns all 16 devices, and still passes
// any test that only checks membership or length — it just mislabels flow
// records with a different wrong answer on every process start.
//
// This test is therefore built to be deterministic rather than lucky: with 16
// keys there are 16! (~2e13) orderings, so the probability that a randomised
// map range reproduces the input order is ~5e-14 per run. A map[string]T
// implementation fails this test on effectively every execution.
func TestFetchInterfaceEnumeration_PreservesKeyOrder(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(referenceInterfaceConfigBody))
	})
	defer server.Close()

	devices, err := client.FetchInterfaceEnumeration()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !reflect.DeepEqual(devices, referenceInterfaceOrder) {
		t.Fatalf("device order not preserved\n got: %v\nwant: %v", devices, referenceInterfaceOrder)
	}
}

// TestFetchInterfaceEnumeration_OrderStableAcrossCalls repeats the fetch so a
// map-based implementation cannot pass by winning one coin flip: Go re-seeds
// map iteration on every range, so twenty consecutive identical answers from a
// map are impossible in practice.
func TestFetchInterfaceEnumeration_OrderStableAcrossCalls(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(referenceInterfaceConfigBody))
	})
	defer server.Close()

	for i := 0; i < 20; i++ {
		devices, err := client.FetchInterfaceEnumeration()
		if err != nil {
			t.Fatalf("call %d: expected no error, got: %v", i, err)
		}
		if !reflect.DeepEqual(devices, referenceInterfaceOrder) {
			t.Fatalf("call %d: device order not preserved\n got: %v\nwant: %v", i, devices, referenceInterfaceOrder)
		}
	}
}

// TestFetchInterfaceEnumeration_EmptyValueObjectKeepsSlot pins that the slot
// belongs to the KEY, not to the value: a device whose config object the box
// could not populate must still consume its ifIndex, or every device after it
// shifts down one and the mislabelling this endpoint was adopted to fix comes
// straight back.
func TestFetchInterfaceEnumeration_EmptyValueObjectKeepsSlot(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"igb0": {}, "igb1": {"device": "igb1"}, "lo0": {}}`))
	})
	defer server.Close()

	devices, err := client.FetchInterfaceEnumeration()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	want := []string{"igb0", "igb1", "lo0"}
	if !reflect.DeepEqual(devices, want) {
		t.Fatalf("got %v, want %v", devices, want)
	}
}

// TestFetchInterfaceEnumeration_NullValueKeepsSlot covers the same rule for an
// explicit null value, which encoding/json would happily skip if the value were
// decoded into a typed struct and the result filtered on emptiness.
func TestFetchInterfaceEnumeration_NullValueKeepsSlot(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"igb0": null, "igb1": {"device": "igb1"}}`))
	})
	defer server.Close()

	devices, err := client.FetchInterfaceEnumeration()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	want := []string{"igb0", "igb1"}
	if !reflect.DeepEqual(devices, want) {
		t.Fatalf("got %v, want %v", devices, want)
	}
}

func TestFetchInterfaceEnumeration_EmptyObject(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{}`))
	})
	defer server.Close()

	devices, err := client.FetchInterfaceEnumeration()
	if err != nil {
		t.Fatalf("expected no error for an empty object, got: %v", err)
	}
	if len(devices) != 0 {
		t.Fatalf("expected no devices, got %v", devices)
	}
}

// TestFetchInterfaceEnumeration_EmptyKeySkipped pins that a zero-length key is
// dropped rather than allocated a slot. ifinfo cannot print a nameless device,
// so an empty key is malformed input; handing it an ifIndex would insert a
// phantom slot and shift every real device after it.
func TestFetchInterfaceEnumeration_EmptyKeySkipped(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"igb0": {}, "": {}, "igb1": {}}`))
	})
	defer server.Close()

	devices, err := client.FetchInterfaceEnumeration()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	want := []string{"igb0", "igb1"}
	if !reflect.DeepEqual(devices, want) {
		t.Fatalf("got %v, want %v", devices, want)
	}
}

// TestFetchInterfaceEnumeration_NotAnObject rejects a body that is not a JSON
// object. A JSON array would decode without complaint into a []string of
// something, and an error body would silently yield zero devices; both must be
// reported so the collector emits nothing rather than a confidently wrong
// index map.
func TestFetchInterfaceEnumeration_NotAnObject(t *testing.T) {
	for name, body := range map[string]string{
		"array":  `["igb0", "igb1"]`,
		"string": `"igb0"`,
		"number": `42`,
		"null":   `null`,
	} {
		t.Run(name, func(t *testing.T) {
			server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Write([]byte(body))
			})
			defer server.Close()

			devices, err := client.FetchInterfaceEnumeration()
			if err == nil {
				t.Fatalf("expected an error for a non-object body, got devices %v", devices)
			}
			if devices != nil {
				t.Errorf("expected no devices alongside the error, got %v", devices)
			}
		})
	}
}

// TestFetchInterfaceEnumeration_DuplicateKey rejects a repeated device key
// rather than counting the slot twice. Two entries for one device means the
// list no longer maps 1:1 onto ifinfo positions, so every later index is
// suspect — reporting that is strictly better than shipping a plausible but
// shifted enumeration.
func TestFetchInterfaceEnumeration_DuplicateKey(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"igb0": {}, "igb1": {}, "igb0": {}}`))
	})
	defer server.Close()

	devices, err := client.FetchInterfaceEnumeration()
	if err == nil {
		t.Fatalf("expected an error for a duplicate device key, got devices %v", devices)
	}
	if devices != nil {
		t.Errorf("expected no devices alongside the error, got %v", devices)
	}
}

func TestFetchInterfaceEnumeration_MissingEndpoint(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{}`))
	})
	defer server.Close()

	delete(client.endpoints, "interfaceConfig")

	if _, err := client.FetchInterfaceEnumeration(); err == nil {
		t.Fatal("expected an error when the endpoint is not registered")
	}
}

func TestFetchInterfaceEnumeration_HTTPError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer server.Close()

	if _, err := client.FetchInterfaceEnumeration(); err == nil {
		t.Fatal("expected an error on HTTP 500")
	}
}
