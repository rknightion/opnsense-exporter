package opnsense

import (
	"net/http"
	"testing"
)

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
					"link state": "link state is up",
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
