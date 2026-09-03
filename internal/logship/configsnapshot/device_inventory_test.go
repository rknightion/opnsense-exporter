package configsnapshot

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"

	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

// These are normalized values returned by the current opnsense package models,
// not invented wire payloads. Hostdiscovery and LLDP rows exercise the bounded
// non-metric projections retained alongside their aggregate/metric views.
func TestFuseDeviceInventoryMergesAllIdentityFields(t *testing.T) {
	observations := []DeviceInventoryObservation{
		{
			Source: "dhcpv4", MAC: "AA-BB-CC-DD-EE-01", IP: "192.0.2.10",
			Hostname: "dhcp-name", Interface: "LAN", Vendor: "DHCP vendor",
			FirstSeen: "2026-09-01T10:00:00+01:00",
		},
		{
			Source: "arp", MAC: "aa:bb:cc:dd:ee:01", IP: "192.0.2.10",
			Hostname: "arp-name", Interface: "ix0", Vendor: "ARP vendor",
			LastSeen: "2026-09-01T12:00:00Z",
		},
		{
			Source: "ndp", MAC: "AA:BB:CC:DD:EE:01", IP: "2001:db8::10%ix0",
			Interface: "LAN", Vendor: "NDP vendor",
		},
		{
			Source: "hostdiscovery", MAC: "aa:bb:cc:dd:ee:01", IP: "192.0.2.10",
			FirstSeen: "2026-08-31T23:00:00Z",
			LastSeen:  "2026-09-01T13:00:00Z",
		},
		{
			Source: "dhcpv6", IP: "2001:db8::11", Interface: "LAN",
		},
		{
			Source: "arp", MAC: "aa:bb:cc:dd:ee:01", IP: "2001:db8::11",
		},
		// LLDP observations can use a chassis identity without a host MAC.
		{
			Source: "lldp", Identity: "lldp:name:core-switch", Hostname: "Core-Switch", Interface: "ix0",
		},
		{
			Source: "lldp", Identity: "LLDP:NAME:CORE-SWITCH", Hostname: "core-switch", Interface: "ix1",
		},
	}

	got := fuseDeviceInventory(observations)
	if len(got) != 2 {
		t.Fatalf("fuseDeviceInventory returned %d devices, want 2: %+v", len(got), got)
	}

	var host, neighbor *fusedDevice
	for i := range got {
		switch got[i].ID {
		case "mac:aa:bb:cc:dd:ee:01":
			host = &got[i]
		case "identity:lldp:name:core-switch":
			neighbor = &got[i]
		}
	}
	if host == nil || neighbor == nil {
		t.Fatalf("fused IDs = %v, want MAC and LLDP identities", []string{got[0].ID, got[1].ID})
	}

	wantHost := DeviceInventoryRecord{
		MAC:       "aa:bb:cc:dd:ee:01",
		IPs:       []string{"192.0.2.10", "2001:db8::10", "2001:db8::11"},
		Hostname:  "arp-name", // live ARP wins over DHCP at the stated priority
		Interface: "LAN",      // stable lexical choice among the observed names
		FirstSeen: "2026-08-31T23:00:00Z",
		LastSeen:  "2026-09-01T13:00:00Z",
		Vendor:    "ARP vendor", // ARP/NDP OUI data wins over DHCP metadata
	}
	if !reflect.DeepEqual(host.Record, wantHost) {
		t.Errorf("fused host = %+v, want %+v", host.Record, wantHost)
	}

	wantNeighbor := DeviceInventoryRecord{
		IPs:       []string{},
		Hostname:  "Core-Switch",
		Interface: "ix0",
	}
	if !reflect.DeepEqual(neighbor.Record, wantNeighbor) {
		t.Errorf("fused LLDP neighbor = %+v, want %+v", neighbor.Record, wantNeighbor)
	}
}

func TestFuseDeviceInventoryDoesNotCollapseConflictingMACsOnOneIP(t *testing.T) {
	got := fuseDeviceInventory([]DeviceInventoryObservation{
		{Source: "arp", MAC: "aa:bb:cc:dd:ee:01", IP: "192.0.2.50"},
		{Source: "ndp", MAC: "aa:bb:cc:dd:ee:02", IP: "192.0.2.50"},
		// With two MAC-bearing candidates, an IP-only row is ambiguous and is
		// retained as its own identity rather than assigned to either device.
		{Source: "dhcpv6", IP: "192.0.2.50"},
	})
	if len(got) != 3 {
		t.Fatalf("fuseDeviceInventory returned %d devices, want 3 for conflicting MACs: %+v", len(got), got)
	}
}

func TestFuseDeviceInventoryDoesNotCollapseConflictingMACsOnOneIdentity(t *testing.T) {
	got := fuseDeviceInventory([]DeviceInventoryObservation{
		{Source: "lldp", Identity: "chassis:shared-name", MAC: "aa:bb:cc:dd:ee:01"},
		{Source: "lldp", Identity: "chassis:shared-name", MAC: "aa:bb:cc:dd:ee:02"},
	})
	if len(got) != 2 {
		t.Fatalf("fuseDeviceInventory returned %d devices, want 2 for conflicting identity MACs: %+v", len(got), got)
	}
}

type fakeDeviceInventoryFetcher struct {
	observations []DeviceInventoryObservation
	err          error
}

func (f *fakeDeviceInventoryFetcher) FetchDeviceInventory(ctx context.Context) ([]DeviceInventoryObservation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return f.observations, f.err
}

func TestDeviceInventoryProviderMarksOnlyFirstObservationAsNew(t *testing.T) {
	fetcher := &fakeDeviceInventoryFetcher{observations: []DeviceInventoryObservation{{
		Source: "arp", MAC: "aa:bb:cc:dd:ee:01", IP: "192.0.2.10",
	}}}
	provider := newDeviceInventoryProviderWithFetcher(fetcher)

	first, err := provider.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("first Snapshot: %v", err)
	}
	provider.CommitSnapshot()
	second, err := provider.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("second Snapshot: %v", err)
	}
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("snapshot sizes = %d and %d, want one entity each", len(first), len(second))
	}
	firstRecord := first[0].Value.(DeviceInventoryRecord)
	secondRecord := second[0].Value.(DeviceInventoryRecord)
	if !firstRecord.NewDevice {
		t.Error("first observation did not carry new_device=true")
	}
	if secondRecord.NewDevice {
		t.Error("unchanged known observation carried new_device=true")
	}
}

func TestDeviceInventoryProviderDoesNotAdvanceSeenAfterFailure(t *testing.T) {
	fetcher := &fakeDeviceInventoryFetcher{err: errors.New("firewall unavailable")}
	provider := newDeviceInventoryProviderWithFetcher(fetcher)
	if _, err := provider.Snapshot(context.Background()); err == nil {
		t.Fatal("Snapshot succeeded despite fetcher failure")
	}

	fetcher.err = nil
	fetcher.observations = []DeviceInventoryObservation{{Source: "arp", MAC: "aa:bb:cc:dd:ee:01", IP: "192.0.2.10"}}
	entities, err := provider.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("successful Snapshot after failure: %v", err)
	}
	if len(entities) != 1 || !entities[0].Value.(DeviceInventoryRecord).NewDevice {
		t.Fatalf("post-failure snapshot = %+v, want one new device", entities)
	}
}

func TestDeviceInventoryProviderHonorsCancellation(t *testing.T) {
	fetcher := &fakeDeviceInventoryFetcher{observations: []DeviceInventoryObservation{{
		Source: "arp", MAC: "aa:bb:cc:dd:ee:01", IP: "192.0.2.10",
	}}}
	provider := newDeviceInventoryProviderWithFetcher(fetcher)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := provider.Snapshot(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Snapshot error = %v, want context.Canceled", err)
	}
}

type fakeDeviceInventoryAPI struct {
	arp      opnsense.ArpTable
	arpErr   *opnsense.APICallError
	ndp      opnsense.NDPTable
	ndpErr   *opnsense.APICallError
	kea4     opnsense.KeaLeases
	kea4Err  *opnsense.APICallError
	kea6     opnsense.KeaLeases
	kea6Err  *opnsense.APICallError
	dnsmasq  opnsense.DnsmasqLeases
	dnsErr   *opnsense.APICallError
	dhcp4    opnsense.DHCPv4Leases
	dhcp4Err *opnsense.APICallError
	dhcp6    opnsense.DHCPv6Leases
	dhcp6Err *opnsense.APICallError
	host     opnsense.HostDiscoveryInventory
	hostErr  *opnsense.APICallError
	lldp     opnsense.LLDPNeighbors
	lldpErr  *opnsense.APICallError
}

func (f *fakeDeviceInventoryAPI) FetchArpTable() (opnsense.ArpTable, *opnsense.APICallError) {
	return f.arp, f.arpErr
}
func (f *fakeDeviceInventoryAPI) FetchNDPTable() (opnsense.NDPTable, *opnsense.APICallError) {
	return f.ndp, f.ndpErr
}
func (f *fakeDeviceInventoryAPI) FetchKeaLeases4() (opnsense.KeaLeases, *opnsense.APICallError) {
	return f.kea4, f.kea4Err
}
func (f *fakeDeviceInventoryAPI) FetchKeaLeases6() (opnsense.KeaLeases, *opnsense.APICallError) {
	return f.kea6, f.kea6Err
}
func (f *fakeDeviceInventoryAPI) FetchDnsmasqLeases() (opnsense.DnsmasqLeases, *opnsense.APICallError) {
	return f.dnsmasq, f.dnsErr
}
func (f *fakeDeviceInventoryAPI) FetchDHCPv4Leases() (opnsense.DHCPv4Leases, *opnsense.APICallError) {
	return f.dhcp4, f.dhcp4Err
}
func (f *fakeDeviceInventoryAPI) FetchDHCPv6Leases() (opnsense.DHCPv6Leases, *opnsense.APICallError) {
	return f.dhcp6, f.dhcp6Err
}
func (f *fakeDeviceInventoryAPI) FetchHostDiscovery() (opnsense.HostDiscoveryInventory, *opnsense.APICallError) {
	return f.host, f.hostErr
}
func (f *fakeDeviceInventoryAPI) FetchLLDPNeighbors() (opnsense.LLDPNeighbors, *opnsense.APICallError) {
	return f.lldp, f.lldpErr
}

func TestCollectDeviceInventoryMapsCurrentNormalizedSources(t *testing.T) {
	api := &fakeDeviceInventoryAPI{
		arp: opnsense.ArpTable{Arp: []opnsense.Arp{{
			Mac: "aa:bb:cc:dd:ee:01", IP: "192.0.2.10", Hostname: "arp-name",
			Device: "ix0", IntfDescription: "LAN", Manufacturer: "ARP vendor",
		}}},
		ndp: opnsense.NDPTable{Entries: []opnsense.NDPEntry{{
			Mac: "aa:bb:cc:dd:ee:01", IP: "2001:db8::10", Device: "ix0",
			IntfDescription: "LAN", Manufacturer: "ARP vendor",
		}}},
		kea4: opnsense.KeaLeases{Leases: []opnsense.KeaLease{{
			HWAddr: "aa:bb:cc:dd:ee:01", Address: "192.0.2.10", Hostname: "kea-name",
			IfDescr: "LAN", Vendor: "Kea vendor",
		}}},
		kea6: opnsense.KeaLeases{},
		dnsmasq: opnsense.DnsmasqLeases{Leases: []opnsense.DnsmasqLease{{
			HWAddr: "aa:bb:cc:dd:ee:01", Address: "192.0.2.10", Hostname: "dnsmasq-name",
			IfDescr: "LAN", Vendor: "dnsmasq vendor",
		}}},
		dhcp4: opnsense.DHCPv4Leases{Present: true, Leases: []opnsense.DHCPv4Lease{{
			MAC: "aa:bb:cc:dd:ee:01", Address: "192.0.2.10", Hostname: "isc4-name", IfDescr: "LAN",
		}}},
		dhcp6: opnsense.DHCPv6Leases{Leases: []opnsense.DHCPv6Lease{{
			MAC: "aa:bb:cc:dd:ee:01", Address: "2001:db8::10", IfDescr: "LAN",
		}}},
		host: opnsense.HostDiscoveryInventory{
			Groups: []opnsense.HostDiscoveryGroup{{
				Interface: "LAN", Source: "discovery", Manufacturer: "ARP vendor", Hosts: 1,
			}},
			Hosts: []opnsense.HostDiscoveryHost{{
				Source: "discovery", Interface: "LAN", MAC: "aa:bb:cc:dd:ee:01",
				IP: "192.0.2.10", Vendor: "ARP vendor",
				FirstSeen: "2026-08-31T23:00:00Z", LastSeen: "2026-09-01T13:00:00Z",
			}},
		},
		lldp: opnsense.LLDPNeighbors{Present: true, Neighbors: []opnsense.LLDPNeighbor{{
			Interface: "ix0", ChassisName: "core-switch", ChassisMAC: "aa:bb:cc:dd:ee:02",
			MgmtIPs: []string{"192.0.2.20"}, PortID: "local Port 1",
		}}},
	}

	observations, err := collectDeviceInventory(api)
	if err != nil {
		t.Fatalf("collectDeviceInventory: %v", err)
	}
	counts := make(map[string]int)
	for _, observation := range observations {
		counts[observation.Source]++
	}
	for _, source := range []string{"arp", "ndp", "kea4", "kea6", "dnsmasq", "dhcpv4", "dhcpv6", "hostdiscovery", "lldp"} {
		if counts[source] == 0 && source != "kea6" {
			t.Errorf("source %q produced no observation; counts=%v", source, counts)
		}
	}
	var lldpObservation DeviceInventoryObservation
	for _, observation := range observations {
		if observation.Source == "lldp" {
			lldpObservation = observation
		}
	}
	if lldpObservation.Identity != "lldp:mac:aa:bb:cc:dd:ee:02" ||
		lldpObservation.MAC != "aa:bb:cc:dd:ee:02" ||
		lldpObservation.IP != "192.0.2.20" ||
		lldpObservation.Hostname != "core-switch" {
		t.Errorf("LLDP observation = %+v, want stable chassis identity", lldpObservation)
	}
}

func TestCollectDeviceInventoryToleratesOptionalBackend404s(t *testing.T) {
	api := &fakeDeviceInventoryAPI{
		kea4Err:  &opnsense.APICallError{Endpoint: "keaLeases4", StatusCode: http.StatusNotFound},
		kea6Err:  &opnsense.APICallError{Endpoint: "keaLeases6", StatusCode: http.StatusNotFound},
		dnsErr:   &opnsense.APICallError{Endpoint: "dnsmasqLeases", StatusCode: http.StatusNotFound},
		dhcp4Err: &opnsense.APICallError{Endpoint: "dhcpv4", StatusCode: http.StatusNotFound},
		dhcp6Err: &opnsense.APICallError{Endpoint: "dhcpv6", StatusCode: http.StatusNotFound},
		arp:      opnsense.ArpTable{Arp: []opnsense.Arp{{Mac: "aa:bb:cc:dd:ee:01", IP: "192.0.2.10"}}},
	}
	if _, err := collectDeviceInventory(api); err != nil {
		t.Fatalf("collectDeviceInventory returned an optional 404: %v", err)
	}
}

func TestCollectDeviceInventoryPropagatesCoreFailure(t *testing.T) {
	api := &fakeDeviceInventoryAPI{
		arpErr: &opnsense.APICallError{Endpoint: "arp", StatusCode: http.StatusInternalServerError},
	}
	if _, err := collectDeviceInventory(api); err == nil {
		t.Fatal("collectDeviceInventory swallowed core ARP failure")
	}
}
