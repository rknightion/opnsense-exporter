package syslog

import (
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// gaugeValue reads a single gauge sample out of reg, reporting whether the series
// exists at all. The existence half matters as much as the value: the slot gauges are
// published ONLY for a transport that is actually listening, so "absent" and "zero"
// are different answers here. (prometheus/testutil is not vendored.)
func gaugeValue(t *testing.T, reg *prometheus.Registry, name, transport string) (float64, bool) {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "transport" && lp.GetValue() == transport {
					return m.GetGauge().GetValue(), true
				}
			}
		}
	}
	return 0, false
}

// awaitGauge polls until the gauge reaches want. A slot is released on the serving
// goroutine after the peer's read fails, so there is no synchronisation point a test
// can join.
func awaitGauge(t *testing.T, reg *prometheus.Registry, name, transport string, want float64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var last float64
	var seen bool
	for time.Now().Before(deadline) {
		got, ok := gaugeValue(t, reg, name, transport)
		if ok && got == want {
			return
		}
		last, seen = got, ok
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s{transport=%q}: want %v, last saw %v (present=%v)", name, transport, want, last, seen)
}

// TestListenerPublishesSlotLimitForConfiguredTransportsOnly is the headroom half of
// #592 item 4. Before this, connection pressure was observable only once
// Reject("conn_limit") fired — a wall-hit counter, which tells an operator they have
// already run out rather than that they are about to.
//
// The limit is published per CONFIGURED transport and not for an unconfigured one:
// tcpSem and tlsSem are allocated unconditionally in NewListener, so publishing off
// their capacity alone would advertise a TLS budget on a listener with no TLS socket.
// Same rule as the pipeline's sourceNames split — a series that can never move claims
// we are watching something we are not.
func TestListenerPublishesSlotLimitForConfiguredTransportsOnly(t *testing.T) {
	reg := prometheus.NewRegistry()
	c := newCollector()
	startListener(t, Config{TCPAddr: "127.0.0.1:0", MaxConns: 7, Registerer: reg}, c.handle, nil)

	got, ok := gaugeValue(t, reg, connSlotsLimitName, "tcp")
	if !ok {
		t.Fatalf("%s{transport=\"tcp\"} not published for a listener with a TCP socket", connSlotsLimitName)
	}
	if got != 7 {
		t.Errorf("%s{transport=\"tcp\"} = %v, want 7 (MaxConns)", connSlotsLimitName, got)
	}
	if _, ok := gaugeValue(t, reg, connSlotsLimitName, "tls"); ok {
		t.Errorf("%s{transport=\"tls\"} published for a listener with no TLS socket", connSlotsLimitName)
	}
	if _, ok := gaugeValue(t, reg, connSlotsInUseName, "tls"); ok {
		t.Errorf("%s{transport=\"tls\"} published for a listener with no TLS socket", connSlotsInUseName)
	}
}

// TestListenerSlotsInUseSeededToZero: the in-use gauge must exist at zero before the
// first connection rather than springing into existence on it. An absent series is
// indistinguishable from a dead exporter at query time — the failure #280 fixed for
// the counters, and the reason a headroom panel needs a real zero to divide by.
func TestListenerSlotsInUseSeededToZero(t *testing.T) {
	reg := prometheus.NewRegistry()
	c := newCollector()
	startListener(t, Config{TCPAddr: "127.0.0.1:0", MaxConns: 4, Registerer: reg}, c.handle, nil)

	got, ok := gaugeValue(t, reg, connSlotsInUseName, "tcp")
	if !ok {
		t.Fatalf("%s{transport=\"tcp\"} absent before the first connection", connSlotsInUseName)
	}
	if got != 0 {
		t.Errorf("%s{transport=\"tcp\"} = %v at rest, want 0", connSlotsInUseName, got)
	}
}

// TestListenerSlotsInUseTracksOccupancy proves the gauge moves in BOTH directions. The
// release half is the one worth testing: a slot leaked on close shows up as permanent
// phantom pressure and eventually reads as a full listener that is serving nobody.
func TestListenerSlotsInUseTracksOccupancy(t *testing.T) {
	reg := prometheus.NewRegistry()
	c := newCollector()
	l := startListener(t, Config{TCPAddr: "127.0.0.1:0", MaxConns: 4, Registerer: reg}, c.handle, nil)

	conn, err := net.Dial("tcp", l.TCPAddr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := conn.Write([]byte("<134>one\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	c.await(t, 3*time.Second) // the connection is established and being served
	awaitGauge(t, reg, connSlotsInUseName, "tcp", 1)

	_ = conn.Close()
	awaitGauge(t, reg, connSlotsInUseName, "tcp", 0)
}

// TestListenerNilRegistererIsANoOp: an exporter run with self-metrics off hands the
// pipeline a nil Registerer, and every other receiver metric treats that as a silent
// opt-out rather than a panic. The slot gauges must do the same, or turning
// self-metrics off would take the syslog receiver down with it.
func TestListenerNilRegistererIsANoOp(t *testing.T) {
	c := newCollector()
	l := startListener(t, Config{TCPAddr: "127.0.0.1:0", MaxConns: 2, Registerer: nil}, c.handle, nil)

	conn, err := net.Dial("tcp", l.TCPAddr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("<134>one\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	c.await(t, 3*time.Second) // must serve normally with nothing to report to
}
