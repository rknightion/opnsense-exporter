package flow

import "testing"

// #606: the raw kernel device must never reach the metric label for an interface the
// box HAS a description for. On the reference box that produced interface="ixl0"
// beside interface="LAN", and interface="ixl0_vlan50" beside interface="IOT" — one
// interface split across two series, so every `sum by (interface)` under-reported
// both.
func TestIfaceLabel_UnresolvedYieldsTheSentinelNotTheDevice(t *testing.T) {
	i := Iface{Device: "ixl0", Unresolved: true}
	if got := i.Label(); got != UnresolvedInterfaceLabel {
		t.Fatalf("Label() = %q, want %q", got, UnresolvedInterfaceLabel)
	}
}

// The mark is only ever set when the interface table could not be consulted. Once a
// description resolves it is cleared, and the label is the description as before.
func TestIfaceLabel_ResolvedNameWinsOverTheSentinel(t *testing.T) {
	i := Iface{Device: "ixl0", Name: "LAN"}
	if got := i.Label(); got != "LAN" {
		t.Fatalf("Label() = %q, want LAN", got)
	}
}

// A device the box genuinely has NO description for is a different case and keeps its
// old behaviour: the raw device is then the best true label there is, and calling it
// "unresolved" would hide a real interface behind a bucket.
func TestIfaceLabel_UnmarkedDeviceStillFallsBackToTheDevice(t *testing.T) {
	i := Iface{Device: "ixl0"}
	if got := i.Label(); got != "ixl0" {
		t.Fatalf("Label() = %q, want ixl0", got)
	}
}

// The sentinel is a named value, not "": an empty label is ABSENT to Prometheus, so
// the bytes would vanish from `sum by (interface)` rather than showing up as a bucket
// an operator can see and watch drain after a restart.
func TestUnresolvedInterfaceLabel_IsNotEmpty(t *testing.T) {
	if UnresolvedInterfaceLabel == "" {
		t.Fatal("UnresolvedInterfaceLabel is empty; the bytes would disappear from the metric entirely")
	}
}
