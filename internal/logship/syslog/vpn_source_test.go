package syslog

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/internal/logship"
	"github.com/rknightion/opnsense2otel/v4/internal/logship/enrich"
	"github.com/rknightion/opnsense2otel/v4/internal/options"
)

// The sanitized RFC5424 templates retained for #406, rendered with the real
// facility/severity each was captured at. These are the ONLY eight lines this
// feature is allowed to have grammar for: four charon, four openvpn_server40.
const (
	lineCharonAuthFailed  = `<30>1 2026-07-27T12:00:00Z fixture-firewall charon 1 - - 00[ENC] <` + charonIkeID + `|1> generating IKE_AUTH response 1 [ N(AUTH_FAILED) ]`
	lineCharonEstablished = `<30>1 2026-07-27T12:00:00Z fixture-firewall charon 1 - - 00[IKE] <` + charonIkeID + `|1> IKE_SA ` + charonIkeID + `[1] established between 192.0.2.1[fixture-local-id]...192.0.2.2[fixture-remote-id]`
	lineCharonLiveness    = `<30>1 2026-07-27T12:00:00Z fixture-firewall charon 1 - - 00[IKE] <` + charonIkeID + `|1> giving up after 5 retransmits`
	lineCharonTerminated  = `<30>1 2026-07-27T12:00:00Z fixture-firewall charon 1 - - 00[IKE] <` + charonIkeID + `|1> IKE_SA deleted`

	lineOpenVPNEstablished = `<29>1 2026-07-27T12:00:00Z fixture-firewall openvpn_server40 1 - - udp4:192.0.2.2:11940 [fixture-user] Peer Connection Initiated with [AF_INET]192.0.2.2:11940`
	lineOpenVPNAuthFailed  = `<29>1 2026-07-27T12:00:00Z fixture-firewall openvpn_server40 1 - - udp4:192.0.2.2:11940 SENT CONTROL [UNDEF]: 'AUTH_FAILED' (status=1)`
	lineOpenVPNCertFailed  = `<27>1 2026-07-27T12:00:00Z fixture-firewall openvpn_server40 1 - - udp4:192.0.2.2:11940 VERIFY ERROR: depth=0, error=self-signed certificate: CN=fixture-untrusted, serial=1111111111111111`
	lineOpenVPNTerminated  = `<29>1 2026-07-27T12:00:00Z fixture-firewall openvpn_server40 1 - - fixture-user/udp4:192.0.2.2:11940 SIGUSR1[soft,ping-restart] received, client-instance restarting`
)

// vpnSnap resolves both ids the #255 enrichment knows about: the charon ikeid and
// the OpenVPN instance uuid, each to the name configured on the firewall.
func vpnSnap() *enrich.Snapshot {
	return &enrich.Snapshot{
		Tunnels:      map[string]string{charonIkeID: "TESTLAN to LXC105"},
		VPNInstances: map[string]string{"6f86d5cd-44f2-47ea-a882-f8773b65c190": "TESTLAN roadwarrior"},
	}
}

func newVPNSource(t *testing.T, snap *enrich.Snapshot) (*source, *fakeSink, *[]logship.Record) {
	t.Helper()
	cache := enrich.NewCache()
	if snap != nil {
		cache.Store(snap)
	}
	sink := &fakeSink{}
	s := newSource(&options.SyslogConfig{}, logship.Deps{
		Registerer: prometheus.NewRegistry(),
		Cache:      cache,
		MetricSink: sink,
	})
	emitted := &[]logship.Record{}
	s.emit = func(record logship.Record) { *emitted = append(*emitted, record) }
	return s, sink, emitted
}

// THE #406 connection-label finding, pinned end to end. addCommon calls
// enrichTunnels OUTSIDE its enrichBody guard (generic.go), so tunnel resolution
// still runs for a record a PARSER produced — parsers only lose the body-scan
// address/interface enrichment, not the tunnel lookup. Since every captured charon
// line carries the ikeid, the connection label really does populate for IPsec.
func TestSourceVPNIPsecConnectionLabelResolvesForParsedRecords(t *testing.T) {
	s, sink, emitted := newVPNSource(t, vpnSnap())

	for _, line := range []string{lineCharonEstablished, lineCharonTerminated, lineCharonAuthFailed, lineCharonLiveness} {
		s.handle([]byte(line), netip.MustParseAddr("192.0.2.1"))
	}

	want := [][]string{
		{"ipsec", "established", "success", "TESTLAN to LXC105"},
		{"ipsec", "terminated", "success", "TESTLAN to LXC105"},
		{"ipsec", "authentication_failed", "failure", "TESTLAN to LXC105"},
		{"ipsec", "liveness_failed", "failure", "TESTLAN to LXC105"},
	}
	if len(sink.calls) != len(want) {
		t.Fatalf("sink calls = %+v, want %d vpn observations", sink.calls, len(want))
	}
	for i, args := range want {
		if sink.calls[i].method != "vpn" {
			t.Fatalf("call %d method = %q, want vpn", i, sink.calls[i].method)
		}
		assertArgs(t, sink.calls[i].args, args)
	}
	if len(*emitted) != len(want) {
		t.Fatalf("emitted records = %d, want %d", len(*emitted), len(want))
	}
}

// A charon line whose ikeid is not in the inventory — a tunnel deleted since the
// last refresh, or a cold cache — still counts, with an EMPTY connection. The raw
// UUID must not be substituted for the name it failed to resolve.
func TestSourceVPNIPsecUnresolvedConnectionIsEmptyNotAUUID(t *testing.T) {
	s, sink, _ := newVPNSource(t, &enrich.Snapshot{})

	s.handle([]byte(lineCharonEstablished), netip.MustParseAddr("192.0.2.1"))

	if len(sink.calls) != 1 {
		t.Fatalf("sink calls = %+v, want one vpn observation", sink.calls)
	}
	assertArgs(t, sink.calls[0].args, []string{"ipsec", "established", "success", ""})
}

// The OpenVPN half of the same finding, and it is a NEGATIVE result worth pinning:
// none of the four captured OpenVPN templates contains the instance UUID (it
// appears only on the MANAGEMENT socket-path line, which is not one of them), so
// enrichTunnels has nothing to resolve and the connection label is structurally
// EMPTY for these events. It is not wired around: the alternative would be
// inventing a mapping from the program-name suffix (openvpn_server40 → "40") to a
// configured instance, and the exporter's instance inventory carries no such
// numeric key.
func TestSourceVPNOpenVPNConnectionLabelIsStructurallyEmpty(t *testing.T) {
	s, sink, emitted := newVPNSource(t, vpnSnap())

	for _, line := range []string{lineOpenVPNEstablished, lineOpenVPNTerminated, lineOpenVPNAuthFailed, lineOpenVPNCertFailed} {
		s.handle([]byte(line), netip.MustParseAddr("192.0.2.1"))
	}

	want := [][]string{
		{"openvpn", "established", "success", ""},
		{"openvpn", "terminated", "success", ""},
		{"openvpn", "authentication_failed", "failure", ""},
		{"openvpn", "certificate_failed", "failure", ""},
	}
	if len(sink.calls) != len(want) {
		t.Fatalf("sink calls = %+v, want %d vpn observations", sink.calls, len(want))
	}
	for i, args := range want {
		assertArgs(t, sink.calls[i].args, args)
	}
	if len(*emitted) != len(want) {
		t.Fatalf("emitted records = %d, want %d", len(*emitted), len(want))
	}
}

// A captured OpenVPN line that DOES carry the instance uuid resolves like any other
// enriched line — proof that the empty label above is a property of the captured
// lifecycle grammar and not a broken lookup.
func TestSourceVPNOpenVPNInstanceStillResolvesOnLinesThatCarryTheUUID(t *testing.T) {
	s, _, emitted := newVPNSource(t, vpnSnap())

	s.handle([]byte(`<29>1 2026-07-27T12:00:00Z fixture-firewall openvpn_server40 1 - - MANAGEMENT: Client connected from /var/etc/openvpn/instance-6f86d5cd-44f2-47ea-a882-f8773b65c190.sock`), netip.MustParseAddr("192.0.2.1"))

	if len(*emitted) != 1 {
		t.Fatalf("emitted records = %d, want 1", len(*emitted))
	}
	if got := (*emitted)[0].Attributes["openvpn.instance"]; got != "TESTLAN roadwarrior" {
		t.Errorf("openvpn.instance = %q, want the configured name", got)
	}
}

// THE privacy gate at the metric boundary. Every forbidden value present in the
// eight captured lines is asserted absent from every label value handed to the
// sink. The record BODY still carries them — that is deliberate and unchanged from
// before this parser existed — but a metric label is forever and global.
func TestSourceVPNMetricLabelsCarryNoIdentityFromAnyCapturedLine(t *testing.T) {
	forbidden := []string{
		"fixture-user",      // OpenVPN username
		"fixture-untrusted", // certificate CN
		"1111111111111111",  // certificate serial
		"fixture-local-id",  // IKE local identity
		"fixture-remote-id", // IKE remote identity
		"192.0.2.1",         // local tunnel address
		"192.0.2.2",         // remote peer address
		"11940",             // remote peer port
		charonIkeID,         // raw IKE_SA / connection UUID
		"fixture-firewall",  // sender hostname
		"self-signed",       // daemon error text
		"AUTH_FAILED",       // daemon wire token
		"VERIFY ERROR",      // daemon wire token
		"SIGUSR1",           // daemon wire token
		"IKE_SA",            // daemon wire token
		"ping-restart",      // daemon wire token
	}

	s, sink, emitted := newVPNSource(t, vpnSnap())
	for _, line := range []string{
		lineCharonAuthFailed, lineCharonEstablished, lineCharonLiveness, lineCharonTerminated,
		lineOpenVPNEstablished, lineOpenVPNAuthFailed, lineOpenVPNCertFailed, lineOpenVPNTerminated,
	} {
		s.handle([]byte(line), netip.MustParseAddr("192.0.2.1"))
	}

	if len(sink.calls) != 8 {
		t.Fatalf("sink calls = %d, want 8 vpn observations", len(sink.calls))
	}
	for _, call := range sink.calls {
		if call.method != "vpn" {
			t.Fatalf("method = %q, want vpn", call.method)
		}
		for _, arg := range call.args {
			for _, bad := range forbidden {
				if strings.Contains(arg, bad) {
					t.Errorf("metric label value %q carries forbidden value %q", arg, bad)
				}
			}
		}
	}

	// The parser also must not have minted a new identity-bearing ATTRIBUTE.
	//
	// Two pre-existing ENRICHMENT mechanisms are exempt, and only those: the #255
	// tunnel ids (the value the connection name was resolved FROM) and the #250
	// generic peer.* body scan. Both shipped on charon/openvpn lines long before this
	// parser existed, and the body-enrichment opt-in deliberately keeps the second one
	// running. What is being asserted here is that THIS PARSER extracted nothing —
	// the metric-label half above stays absolute either way.
	for _, record := range *emitted {
		for key, value := range record.Attributes {
			if key == "ipsec.connection_id" || key == "openvpn.instance_id" ||
				strings.HasPrefix(key, "peer.") || key == "interface" || key == "interface.name" {
				continue
			}
			for _, bad := range forbidden {
				if bad == "fixture-firewall" && key == "host" {
					continue // the syslog envelope's own hostname, on every record since #258
				}
				if strings.Contains(value, bad) {
					t.Errorf("attribute %q=%q carries forbidden value %q", key, value, bad)
				}
			}
		}
	}
}

// vpnEnrichSnap resolves both the tunnel id AND the peer addresses on the captured
// charon line, so a test can see whether generic body enrichment ran.
func vpnEnrichSnap() *enrich.Snapshot {
	return &enrich.Snapshot{
		Tunnels:      map[string]string{charonIkeID: "TESTLAN to LXC105"},
		VPNInstances: map[string]string{"6f86d5cd-44f2-47ea-a882-f8773b65c190": "TESTLAN roadwarrior"},
		Hostnames:    map[string]string{"192.0.2.2": "fixture-peer"},
		MACs:         map[string]string{"192.0.2.2": "02:00:00:00:00:02"},
		LocalNets:    []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
		SelfIPs:      map[netip.Addr]bool{netip.MustParseAddr("192.0.2.1"): true},
	}
}

// Q4: A VPN-parsed record MUST keep the generic body scan. addCommon suppresses it
// for parsed records because a parser that already emitted its own positional
// addresses (filterlog's src.*/dst.*) would otherwise emit them a second time under
// peer.* — and our two VPN parsers emit NO addresses at all, so that rationale does
// not apply to them. Suppressing it would silently break any existing Loki query on
// peer.* for charon/openvpn lines the moment these parsers start matching.
func TestSourceVPNParsedRecordsKeepGenericBodyEnrichment(t *testing.T) {
	s, _, emitted := newVPNSource(t, vpnEnrichSnap())

	s.handle([]byte(lineCharonEstablished), netip.MustParseAddr("192.0.2.1"))

	if len(*emitted) != 1 {
		t.Fatalf("emitted records = %d, want 1", len(*emitted))
	}
	rec := (*emitted)[0]
	// Structured as a VPN event AND body-enriched: both, not either.
	assertAttr(t, rec, "vpn.event", "established")
	assertAttr(t, rec, "ipsec.connection", "TESTLAN to LXC105")
	if rec.Attributes["peer.ip"] == "" {
		t.Fatalf("a parsed charon record lost peer.* body enrichment: %+v", rec.Attributes)
	}
	// The captured established line names BOTH endpoints, local first, so the generic
	// scan numbers them in that order: peer.* is the firewall's own address (scope
	// self), peer.2.* is the remote peer it resolved.
	assertAttr(t, rec, "peer.ip", "192.0.2.1")
	assertAttr(t, rec, "peer.scope", "self")
	assertAttr(t, rec, "peer.2.ip", "192.0.2.2")
	assertAttr(t, rec, "peer.2.hostname", "fixture-peer")
	assertAttr(t, rec, "peer.2.mac", "02:00:00:00:00:02")

	// An OpenVPN lifecycle line is the same deal.
	s.handle([]byte(lineOpenVPNEstablished), netip.MustParseAddr("192.0.2.1"))
	if len(*emitted) != 2 {
		t.Fatalf("emitted records = %d, want 2", len(*emitted))
	}
	if got := (*emitted)[1].Attributes["peer.hostname"]; got != "fixture-peer" {
		t.Errorf("a parsed openvpn record lost peer.* body enrichment: %+v", (*emitted)[1].Attributes)
	}
}

// Q4, the other half: the opt-in must stay NARROW. filterlog owns its addresses
// positionally, so it must NOT gain peer.* — that double-emit hazard is the entire
// reason enrichBody defaults to false for parsed records, and this is the guard
// against "fixing" the default instead of opting in.
func TestFilterlogParsedRecordsStillSuppressBodyEnrichment(t *testing.T) {
	rec := BuildRecord(testEnvelope(realIPv4TCPLine), testSnapshot(t), func(string) {})

	if rec.Attributes["src.ip"] == "" {
		t.Fatalf("filterlog record lost its positional addresses: %+v", rec.Attributes)
	}
	for key := range rec.Attributes {
		if strings.HasPrefix(key, "peer.") {
			t.Errorf("filterlog double-emitted its addresses under %q — enrichBody must stay off for it", key)
		}
	}
}

// Sampling must never be able to drop a VPN lifecycle line: these are low-volume
// security/operational events and the raw line is where the identity detail lives.
func TestSourceVPNLinesSurviveSampling(t *testing.T) {
	cache := enrich.NewCache()
	cache.Store(vpnSnap())
	s := newSource(&options.SyslogConfig{Sample: true, SampledAttr: true}, logship.Deps{
		Registerer: prometheus.NewRegistry(),
		Cache:      cache,
		MetricSink: &fakeSink{},
	})
	var emitted []logship.Record
	s.emit = func(record logship.Record) { emitted = append(emitted, record) }

	lines := []string{
		lineCharonAuthFailed, lineCharonEstablished, lineCharonLiveness, lineCharonTerminated,
		lineOpenVPNEstablished, lineOpenVPNAuthFailed, lineOpenVPNCertFailed, lineOpenVPNTerminated,
	}
	for _, line := range lines {
		s.handle([]byte(line), netip.MustParseAddr("192.0.2.1"))
	}
	if len(emitted) != len(lines) {
		t.Fatalf("emitted records = %d, want all %d retained under sampling", len(emitted), len(lines))
	}
	for _, record := range emitted {
		if record.Attributes["sampled"] != "true" {
			t.Errorf("counted line was not stamped sampled=true: %+v", record.Attributes)
		}
	}
}

// An unmatched charon or openvpn line ships generically and is NOT counted. This is
// the whole shape of the #406 narrowing: version-new and stable-release grammar,
// which was never captured, keeps flowing as a log record.
func TestSourceVPNUnmatchedLinesShipGenericAndUncounted(t *testing.T) {
	s, sink, emitted := newVPNSource(t, vpnSnap())

	lines := []string{
		`<30>1 2026-07-27T12:00:00Z fixture-firewall charon 1 - - 14[IKE] <` + charonIkeID + `|1> CHILD_SA fixture-child{1} established with SPIs c0ffee01_i deadbeef_o`,
		`<29>1 2026-07-27T12:00:00Z fixture-firewall openvpn_server40 1 - - fixture-user/udp4:192.0.2.2:11940 SIGUSR1[soft,tls-error] received, client-instance restarting`,
		`<29>1 2026-07-27T12:00:00Z fixture-firewall openvpn_server40 1 - - udp4:192.0.2.2:11940 SIGTERM[soft,delayed-exit] received, client-instance exiting`,
		`<27>1 2026-07-27T12:00:00Z fixture-firewall openvpn_server40 1 - - udp4:192.0.2.2:11940 TLS Error: TLS handshake failed`,
		`<29>1 2026-07-27T12:00:00Z fixture-firewall openvpn_server40 1 - - fixture-user/udp4:192.0.2.2:11940 Inactivity timeout (--ping-restart), restarting`,
	}
	for _, line := range lines {
		s.handle([]byte(line), netip.MustParseAddr("192.0.2.1"))
	}

	if len(sink.calls) != 0 {
		t.Fatalf("sink calls = %+v, want none for uncaptured grammar", sink.calls)
	}
	if len(*emitted) != len(lines) {
		t.Fatalf("emitted records = %d, want all %d shipped generically", len(*emitted), len(lines))
	}
	for i, record := range *emitted {
		if _, structured := record.Attributes[attrVPNEvent]; structured {
			t.Errorf("record %d was structured as a vpn event: %+v", i, record.Attributes)
		}
		if !strings.Contains(record.Body, "restart") && !strings.Contains(record.Body, "CHILD_SA") &&
			!strings.Contains(record.Body, "exiting") && !strings.Contains(record.Body, "TLS Error") {
			t.Errorf("record %d body was not shipped verbatim: %q", i, record.Body)
		}
	}
}
