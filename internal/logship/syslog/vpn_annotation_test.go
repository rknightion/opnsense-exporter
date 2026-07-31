package syslog

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rknightion/opnsense-exporter/internal/logship"
)

// The dashboard's "Tunnel lifecycle" annotation layer (grafana/annotations.py) is a
// LogQL query, and #591 found it querying an attribute almost nothing set: it filters
// `opnsense_subsystem=~"vpn|ipsec" | vpn_event=~"established|terminated"`, and until
// #596 only charon and openvpn ever wrote vpn.event. A perfect query against data
// that does not exist reads as "no tunnel flaps" rather than as "no parser".
//
// So this test evaluates the LAYER'S OWN FILTERS, read out of annotations.py at test
// time, against records built through the real dispatch path (buildRecord, which is
// what stamps opnsense.subsystem). It fails if a parser stops matching the layer AND
// if the layer's query is edited in a way that stops matching the parsers — the two
// sides cannot drift apart silently in either direction, which is the failure #591
// documented.
func TestTunnelLifecycleAnnotationMatchesEveryVPNLifecycleParser(t *testing.T) {
	subsystemRe, eventRe := tunnelLifecycleLayerFilters(t)

	// BOTH ends of the vocabulary for every lifecycle parser, each a shape confirmed
	// against upstream source or a capture in that parser's own file. Both ends matter:
	// with establishments only, narrowing the layer's filter to one of the two values
	// would still pass. A parser registered for vpn.event with no entry here is the gap
	// this test exists to close, so keep it in step.
	cases := []struct {
		program string
		event   string
		message string
	}{
		{
			program: "charon",
			event:   "established",
			message: `14[IKE] <` + charonIkeID + `|1> IKE_SA ` + charonIkeID +
				`[1] established between 192.0.2.1[fixture-local-id]...192.0.2.2[fixture-remote-id]`,
		},
		{
			program: "charon",
			event:   "terminated",
			message: `07[IKE] <` + charonIkeID + `|1> IKE_SA deleted`,
		},
		{
			program: "openvpn_server40",
			event:   "established",
			message: `udp4:192.0.2.9:1194 [fixture-user] Peer Connection Initiated with [AF_INET]192.0.2.9:1194`,
		},
		{
			program: "openvpn_server40",
			event:   "terminated",
			message: `fixture-user/udp4:192.0.2.9:1194 SIGUSR1[soft,ping-restart] received, client-instance restarting`,
		},
		{
			program: "wireguard",
			event:   "established",
			message: `wireguard instance fixture-site-to-site (wg1) started`,
		},
		{
			program: "wireguard",
			event:   "terminated",
			message: `wireguard instance fixture-site-to-site (wg1) stopped`,
		},
		{
			program: "tailscaled",
			event:   "established",
			message: `Switching ipn state Starting -> Running (WantRunning=true, nm=true)`,
		},
		{
			program: "tailscaled",
			event:   "terminated",
			message: `Switching ipn state Running -> Stopped (WantRunning=false, nm=true)`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.program+"/"+tc.event, func(t *testing.T) {
			env := Envelope{Program: tc.program, Message: tc.message, Facility: 4, Severity: 6}
			rec, parsed := buildRecord(env, nil, nil)
			if !parsed {
				t.Fatalf("%s: buildRecord fell through to a generic record", tc.program)
			}

			subsystem := rec.Attributes[logship.AttrSubsystem]
			if !subsystemRe.MatchString(subsystem) {
				t.Errorf("%s: opnsense_subsystem = %q, which the layer's %s does not select",
					tc.program, subsystem, subsystemRe)
			}
			event := rec.Attributes[attrVPNEvent]
			if !eventRe.MatchString(event) {
				t.Errorf("%s: vpn_event = %q, which the layer's %s does not select",
					tc.program, event, eventRe)
			}
			// Matching the layer is not enough on its own: both values are in the filter, so
			// a parser that mapped an establishment onto `terminated` would still be selected
			// and would put the marker on the wrong end of the tunnel's traffic series.
			if event != tc.event {
				t.Errorf("%s: vpn_event = %q, want %q", tc.program, event, tc.event)
			}
		})
	}
}

// tunnelLifecycleLayerFilters reads the Tunnel lifecycle layer's two label filters
// out of grafana/annotations.py and compiles them the way LogQL evaluates a label
// filter: `=~` is FULLY ANCHORED, so `vpn` must not be matched by a value that
// merely contains it.
//
// It fails loudly rather than skipping if the layer or either filter cannot be
// found. A test that silently passes when it can no longer locate what it checks is
// worse than no test — the query would then be free to drift back to the #591 state.
func tunnelLifecycleLayerFilters(t *testing.T) (subsystem, event *regexp.Regexp) {
	t.Helper()

	path := filepath.Join("..", "..", "..", "grafana", "annotations.py")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	const marker = `name="Tunnel lifecycle"`
	start := strings.Index(string(src), marker)
	if start < 0 {
		t.Fatalf("%s no longer contains %s; the annotation layer was renamed or removed, "+
			"so this test can no longer prove the parsers match it", path, marker)
	}
	layer := string(src)[start:]
	if end := strings.Index(layer, "\n    Annotation("); end > 0 {
		layer = layer[:end]
	}

	// The subsystem filter is written inside a python triple-quoted string whose closing
	// quote is escaped, hence the trailing \\" in the pattern.
	subsystemFilter := regexp.MustCompile(`opnsense_subsystem=~"([^"\\]+)\\"`).FindStringSubmatch(layer)
	if subsystemFilter == nil {
		t.Fatalf("no opnsense_subsystem=~ filter found in the Tunnel lifecycle layer of %s", path)
	}
	eventFilter := regexp.MustCompile(`vpn_event=~"([^"]+)"`).FindStringSubmatch(layer)
	if eventFilter == nil {
		t.Fatalf("no vpn_event=~ filter found in the Tunnel lifecycle layer of %s", path)
	}

	return regexp.MustCompile(`^(?:` + subsystemFilter[1] + `)$`),
		regexp.MustCompile(`^(?:` + eventFilter[1] + `)$`)
}
