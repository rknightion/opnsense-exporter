package zenarmor

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/internal/logship"
)

// selfDoc builds a conn document describing a connection from src to dst:dstPort —
// the shape Zenarmor emits when it observes our own ingest. dst is deliberately a
// parameter: the point of several tests below is that it is NEVER consulted.
func selfDoc(src, dst string, dstPort int) string {
	return fmt.Sprintf(`{"start_time":1784224295000,"transport_proto":"TCP","interface":"ixl0",`+
		`"ip_src_saddr":%q,"ip_src_port":54321,"ip_dst_saddr":%q,"ip_dst_port":%d,`+
		`"is_blocked":0,"app_name":"Elasticsearch","app_category":"Database",`+
		`"device":{"id":"98b78521aff2","name":"opnsense"}}`, src, dst, dstPort)
}

func TestListenPortOf(t *testing.T) {
	tests := []struct {
		addr string
		want int
	}{
		{":9200", 9200},
		{"0.0.0.0:9200", 9200},
		{"10.0.0.5:9200", 9200},
		{"[::]:9200", 9200},
		{"", 0},
		{"nonsense", 0},
		{":notaport", 0},
	}
	for _, tc := range tests {
		if got := listenPortOf(tc.addr); got != tc.want {
			t.Errorf("listenPortOf(%q) = %d, want %d", tc.addr, got, tc.want)
		}
	}
}

func TestIsSelfTraffic(t *testing.T) {
	peer := netip.MustParseAddr("10.0.0.254") // the firewall, streaming to us

	tests := []struct {
		name  string
		attrs map[string]string
		peer  netip.Addr
		port  int
		want  bool
	}{
		{
			// The real thing: the firewall POSTing a bulk to our listener, as
			// Zenarmor observed it on the wire.
			name:  "our own ingest connection",
			attrs: map[string]string{"ip_src_saddr": "10.0.0.254", "ip_dst_saddr": "10.0.0.5", "ip_dst_port": "9200"},
			peer:  peer, port: 9200, want: true,
		},
		{
			// THE CONTAINER CASE. The record's destination is the HOST's LAN
			// address (10.0.0.5) because that is what the firewall connected to;
			// the exporter inside the container is 172.17.0.2 and has no idea
			// 10.0.0.5 exists. A filter comparing destination ADDRESSES would
			// never fire here, which is the whole reason this one does not.
			name:  "container: dst is the host address, not ours",
			attrs: map[string]string{"ip_src_saddr": "10.0.0.254", "ip_dst_saddr": "10.0.0.5", "ip_dst_port": "9200"},
			peer:  peer, port: 9200, want: true,
		},
		{
			// Same, published on a host port that differs from the container's.
			// We match the port we actually bound, so a record addressed to the
			// published port is not ours.
			name:  "different port is not ours",
			attrs: map[string]string{"ip_src_saddr": "10.0.0.254", "ip_dst_saddr": "10.0.0.5", "ip_dst_port": "9300"},
			peer:  peer, port: 9200, want: false,
		},
		{
			// A LAN client talking to some other Elasticsearch. Right port, wrong
			// source: this is real traffic and must survive.
			name:  "another host talking to some elasticsearch",
			attrs: map[string]string{"ip_src_saddr": "10.0.50.144", "ip_dst_saddr": "10.0.0.99", "ip_dst_port": "9200"},
			peer:  peer, port: 9200, want: false,
		},
		{
			// The firewall's own ordinary traffic. Right source, wrong port.
			name:  "peer's other traffic",
			attrs: map[string]string{"ip_src_saddr": "10.0.0.254", "ip_dst_saddr": "8.8.8.8", "ip_dst_port": "53"},
			peer:  peer, port: 9200, want: false,
		},
		{
			name:  "no destination port recorded",
			attrs: map[string]string{"ip_src_saddr": "10.0.0.254", "ip_dst_saddr": "10.0.0.5"},
			peer:  peer, port: 9200, want: false,
		},
		{
			name:  "no source address recorded",
			attrs: map[string]string{"ip_dst_saddr": "10.0.0.5", "ip_dst_port": "9200"},
			peer:  peer, port: 9200, want: false,
		},
		{
			name:  "unparseable source address",
			attrs: map[string]string{"ip_src_saddr": "not-an-ip", "ip_dst_port": "9200"},
			peer:  peer, port: 9200, want: false,
		},
		{
			// An unknown listen port disables the filter rather than guessing.
			name:  "zero listen port never matches",
			attrs: map[string]string{"ip_src_saddr": "10.0.0.254", "ip_dst_port": "9200"},
			peer:  peer, port: 0, want: false,
		},
		{
			name:  "invalid peer never matches",
			attrs: map[string]string{"ip_src_saddr": "10.0.0.254", "ip_dst_port": "9200"},
			peer:  netip.Addr{}, port: 9200, want: false,
		},
		{
			// IPv6, and the peer arrives as a 4-in-6 mapped address (::ffff:10.0.0.254)
			// while the record spells it plainly. Unmap must happen or every record
			// from a dual-stack listener escapes the filter.
			name:  "ipv4-mapped peer still matches",
			attrs: map[string]string{"ip_src_saddr": "10.0.0.254", "ip_dst_port": "9200"},
			peer:  netip.MustParseAddr("::ffff:10.0.0.254"), port: 9200, want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSelfTraffic(tc.attrs, tc.peer, []int{tc.port}); got != tc.want {
				t.Errorf("isSelfTraffic() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestIsSelfTrafficMultiPort covers #299 at the unit level: with several ports bound, a
// record matches on ANY of them, and a zero in the set is ignored rather than treated as
// a wildcard.
func TestIsSelfTrafficMultiPort(t *testing.T) {
	peer := netip.MustParseAddr("10.0.0.254")
	withPort := func(p string) map[string]string {
		return map[string]string{
			"ip_src_saddr": "10.0.0.254",
			"ip_dst_saddr": "10.0.0.5",
			"ip_dst_port":  p,
		}
	}

	tests := []struct {
		name  string
		attrs map[string]string
		ports []int
		want  bool
	}{
		{"matches first of several", withPort("5514"), []int{5514, 6514}, true},
		{"matches second of several", withPort("6514"), []int{5514, 6514}, true},
		{"matches none of several", withPort("9999"), []int{5514, 6514}, false},
		{"empty set disables", withPort("6514"), nil, false},
		{"zero in set is not a wildcard", withPort("6514"), []int{0}, false},
		{"real port beside a zero still matches", withPort("6514"), []int{0, 6514}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSelfTraffic(tc.attrs, peer, tc.ports); got != tc.want {
				t.Errorf("isSelfTraffic(ports=%v) = %v, want %v", tc.ports, got, tc.want)
			}
		})
	}
}

// End to end through handleDoc, which is where the three behaviours that matter meet:
// the record must not ship, must not reach the derived counters, and must still be
// visible as a reject.
func TestSourceDropsSelfTraffic(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink := &captureSink{}
	s, err := newSource(
		logship.Deps{Registerer: reg, MetricSink: sink},
		Config{Addr: "127.0.0.1:0", DropSelfTraffic: true},
	)
	if err != nil {
		t.Fatalf("newSource: %v", err)
	}
	t.Cleanup(func() { _ = s.ln.Close() })

	var shipped []logship.Record
	s.emit = func(r logship.Record) { shipped = append(shipped, r) }

	peer := netip.MustParseAddr("10.0.0.254")
	// dst is 10.0.0.5 — the HOST's address, which this process does not have and
	// cannot enumerate. If the filter ever starts comparing destination addresses,
	// this test fails, which is exactly what it is for.
	doc := selfDoc("10.0.0.254", "10.0.0.5", s.listenPorts[0])
	s.handleDoc("zenarmor_0000000000_abc_conn_write", []byte(doc), peer)

	if len(shipped) != 0 {
		t.Errorf("shipped %d records, want 0 — self-traffic must not reach the pipeline", len(shipped))
	}
	if len(sink.got) != 0 {
		t.Errorf("derived %d observations, want 0 — our own ingest is not the operator's traffic", len(sink.got))
	}
	if n := rejectCount(t, reg, "self_traffic"); n != 1 {
		t.Errorf("self_traffic reject count = %v, want 1 — the drop must be visible, not silent", n)
	}
}

// The escape hatch has to actually work: with the flag off the record ships and
// counts like any other.
func TestSourceKeepsSelfTrafficWhenDisabled(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink := &captureSink{}
	s, err := newSource(
		logship.Deps{Registerer: reg, MetricSink: sink},
		Config{Addr: "127.0.0.1:0", DropSelfTraffic: false},
	)
	if err != nil {
		t.Fatalf("newSource: %v", err)
	}
	t.Cleanup(func() { _ = s.ln.Close() })

	var shipped []logship.Record
	s.emit = func(r logship.Record) { shipped = append(shipped, r) }

	peer := netip.MustParseAddr("10.0.0.254")
	doc := selfDoc("10.0.0.254", "10.0.0.5", s.listenPorts[0])
	s.handleDoc("zenarmor_0000000000_abc_conn_write", []byte(doc), peer)

	if len(shipped) != 1 {
		t.Errorf("shipped %d records, want 1 — the flag is off", len(shipped))
	}
	if len(sink.got) != 1 {
		t.Errorf("derived %d observations, want 1 — the flag is off", len(sink.got))
	}
	if n := rejectCount(t, reg, "self_traffic"); n != 0 {
		t.Errorf("self_traffic reject count = %v, want 0", n)
	}
}

// Ordinary traffic from the same peer must survive with the filter ON. The firewall
// is a real source of real traffic; only the connection to OUR port is ours.
func TestSourceKeepsPeersOtherTraffic(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink := &captureSink{}
	s, err := newSource(
		logship.Deps{Registerer: reg, MetricSink: sink},
		Config{Addr: "127.0.0.1:0", DropSelfTraffic: true},
	)
	if err != nil {
		t.Fatalf("newSource: %v", err)
	}
	t.Cleanup(func() { _ = s.ln.Close() })

	var shipped []logship.Record
	s.emit = func(r logship.Record) { shipped = append(shipped, r) }

	peer := netip.MustParseAddr("10.0.0.254")
	// Same sender, a port that is not ours: the firewall resolving DNS.
	doc := selfDoc("10.0.0.254", "8.8.8.8", 53)
	s.handleDoc("zenarmor_0000000000_abc_conn_write", []byte(doc), peer)

	if len(shipped) != 1 {
		t.Errorf("shipped %d records, want 1 — the peer's own traffic is not self-traffic", len(shipped))
	}
	if n := rejectCount(t, reg, "self_traffic"); n != 0 {
		t.Errorf("self_traffic reject count = %v, want 0", n)
	}
}
