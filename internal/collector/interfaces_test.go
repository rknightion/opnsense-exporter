package collector

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/common/promslog"
)

func TestInterfacesCollector_Update(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"interfaces": {
				"igb0": {
					"device": "igb0",
					"driver": "igb",
					"index": "1",
					"flags": "0x8843",
					"promiscuous listeners": "0",
					"send queue length": "0",
					"send queue max length": "50",
					"send queue drops": "0",
					"type": "Ethernet",
					"address length": "6",
					"header length": "14",
					"link state": "up",
					"vhid": "",
					"datalen": "176",
					"mtu": "1500",
					"metric": "0",
					"line rate": "1000000000",
					"packets received": "123456",
					"packets transmitted": "654321",
					"bytes received": "1000000",
					"bytes transmitted": "2000000",
					"output errors": "0",
					"input errors": "1",
					"collisions": "0",
					"multicasts received": "100",
					"multicasts transmitted": "50",
					"input queue drops": "0",
					"packets for unknown protocol": "0",
					"HW offload capabilities": "",
					"uptime at attach or stat reset": "",
					"name": "LAN"
				}
			}
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &interfacesCollector{subsystem: InterfacesSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 16 metrics per interface (mtu, bytesReceived, bytesTransmitted, multicastsReceived,
	// multicastsTransmitted, inputErrors, outputErrors, collisions, receivedPackets,
	// transmittedPackets, sendQueueLength, sendQueueMaxLength, sendQueueDrops,
	// inputQueueDrops, linkState, lineRate)
	expectedCount := 16
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

func TestInterfacesCollector_Update_MultipleInterfaces(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"interfaces": {
				"igb0": {
					"device": "igb0",
					"driver": "igb",
					"index": "1",
					"flags": "0x8843",
					"promiscuous listeners": "0",
					"send queue length": "0",
					"send queue max length": "50",
					"send queue drops": "0",
					"type": "Ethernet",
					"address length": "6",
					"header length": "14",
					"link state": "up",
					"vhid": "",
					"datalen": "176",
					"mtu": "1500",
					"metric": "0",
					"line rate": "1000000000",
					"packets received": "100",
					"packets transmitted": "200",
					"bytes received": "1000",
					"bytes transmitted": "2000",
					"output errors": "0",
					"input errors": "0",
					"collisions": "0",
					"multicasts received": "10",
					"multicasts transmitted": "5",
					"input queue drops": "0",
					"packets for unknown protocol": "0",
					"HW offload capabilities": "",
					"uptime at attach or stat reset": "",
					"name": "LAN"
				},
				"igb1": {
					"device": "igb1",
					"driver": "igb",
					"index": "2",
					"flags": "0x8843",
					"promiscuous listeners": "0",
					"send queue length": "0",
					"send queue max length": "50",
					"send queue drops": "0",
					"type": "Ethernet",
					"address length": "6",
					"header length": "14",
					"link state": "down",
					"vhid": "",
					"datalen": "176",
					"mtu": "1500",
					"metric": "0",
					"line rate": "0",
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
					"uptime at attach or stat reset": "",
					"name": "WAN"
				}
			}
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &interfacesCollector{subsystem: InterfacesSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 16 metrics per interface * 2 interfaces = 32
	expectedCount := 32
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

func TestInterfacesCollector_Name(t *testing.T) {
	c := &interfacesCollector{subsystem: InterfacesSubsystem}
	if c.Name() != InterfacesSubsystem {
		t.Errorf("expected %s, got %s", InterfacesSubsystem, c.Name())
	}
}
