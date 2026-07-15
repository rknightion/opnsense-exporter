package syslog

import (
	"testing"

	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
)

// Real UUIDs and names from a live OPNsense 26.7 box: the UUID charon logs is the
// `ikeid` from ipsec/sessions/search_phase1, and the UUID in OpenVPN's socket path
// is the `uuid` from openvpn/instances/search.
func tunnelSnap() *enrich.Snapshot {
	return &enrich.Snapshot{
		Tunnels:      map[string]string{"5e891b0c-ca13-4e38-a7c0-a2aa891c30b4": "test ipsec conn"},
		VPNInstances: map[string]string{"6f86d5cd-44f2-47ea-a882-f8773b65c190": "test server"},
	}
}

func TestEnrichTunnels_IPsec(t *testing.T) {
	env := Envelope{
		Program: "charon",
		Message: "10[IKE] <5e891b0c-ca13-4e38-a7c0-a2aa891c30b4|8> sending DPD request",
	}
	rec := BuildRecord(env, tunnelSnap(), nil)
	if got := rec.Attributes["ipsec.connection"]; got != "test ipsec conn" {
		t.Errorf("ipsec.connection = %q, want %q", got, "test ipsec conn")
	}
	if rec.Attributes["opnsense.subsystem"] != "ipsec" {
		t.Errorf("subsystem = %q", rec.Attributes["opnsense.subsystem"])
	}
}

func TestEnrichTunnels_OpenVPNInstance(t *testing.T) {
	env := Envelope{
		Program: "openvpn_server1",
		Message: "MANAGEMENT: Client connected from /var/etc/openvpn/instance-6f86d5cd-44f2-47ea-a882-f8773b65c190.sock",
	}
	rec := BuildRecord(env, tunnelSnap(), nil)
	if got := rec.Attributes["openvpn.instance"]; got != "test server" {
		t.Errorf("openvpn.instance = %q, want %q", got, "test server")
	}
	if rec.Attributes["opnsense.subsystem"] != "vpn" {
		t.Errorf("subsystem = %q, want vpn", rec.Attributes["opnsense.subsystem"])
	}
}

// configd stamps its RPC lines with a task UUID. That is NOT a tunnel, and we must
// not invent an ipsec.connection attribute for it.
func TestEnrichTunnels_UnrelatedUUIDIsNotClaimed(t *testing.T) {
	env := Envelope{
		Program: "configd.py",
		Message: "[1d319fef-0428-4250-9cb8-fdd9c4148887] request suricata rule metadata",
	}
	rec := BuildRecord(env, tunnelSnap(), nil)
	if _, claimed := rec.Attributes["ipsec.connection"]; claimed {
		t.Error("a configd task UUID was claimed as an IPsec tunnel")
	}
	if _, claimed := rec.Attributes["openvpn.instance"]; claimed {
		t.Error("a configd task UUID was claimed as an OpenVPN instance")
	}
}

// A tunnel that has since been deleted resolves to nothing — and must not produce a
// half-populated attribute set.
func TestEnrichTunnels_UnknownUUIDIsLeftAlone(t *testing.T) {
	env := Envelope{Program: "charon", Message: "<11111111-2222-3333-4444-555555555555|1> sending DPD request"}
	rec := BuildRecord(env, tunnelSnap(), nil)
	if _, ok := rec.Attributes["ipsec.connection_id"]; ok {
		t.Error("an unresolvable UUID must not be emitted")
	}
}

func TestEnrichTunnels_NilSnapshotIsSafe(t *testing.T) {
	env := Envelope{Program: "charon", Message: "<5e891b0c-ca13-4e38-a7c0-a2aa891c30b4|8> sending DPD request"}
	if rec := BuildRecord(env, nil, nil); rec.Body != env.Message {
		t.Errorf("body = %q, want the message verbatim", rec.Body)
	}
}
