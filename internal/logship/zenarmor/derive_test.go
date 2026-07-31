package zenarmor

import (
	"reflect"
	"strings"
	"testing"

	"github.com/rknightion/opnsense2otel/v4/internal/logship"
)

// captureSink records the observations handed to it. Only ObserveZenarmor is
// exercised here; the rest satisfy the interface.
type captureSink struct {
	got     []logship.ZenarmorObservation
	devices [][3]string
	reject  bool
}

func (s *captureSink) ObserveZenarmorDevice(name, category, iface string) bool {
	s.devices = append(s.devices, [3]string{name, category, iface})
	return !s.reject
}

func (s *captureSink) ObserveZenarmor(o logship.ZenarmorObservation) bool {
	s.got = append(s.got, o)
	return !s.reject
}

func (s *captureSink) ObserveFirewall(_, _, _, _, _ string) bool { return true }
func (s *captureSink) ObserveHAProxy(_, _, _, _, _ string) bool  { return true }
func (s *captureSink) ObserveSSHD(_, _, _ string) bool           { return true }
func (s *captureSink) ObserveDHCP(_, _, _ string) bool           { return true }
func (s *captureSink) ObserveAudit(_, _ string) bool             { return true }
func (s *captureSink) ObserveIDS(_, _, _, _ string) bool         { return true }
func (s *captureSink) ObserveGateway(_, _ string) bool           { return true }
func (s *captureSink) ObserveRADIUS(_, _, _ string) bool         { return true }
func (s *captureSink) ObserveVPN(_, _, _, _ string) bool         { return true }
func (s *captureSink) ObserveCARP(_, _, _, _, _ string) bool     { return true }
func (s *captureSink) ObserveUPnP(_, _, _ string) bool           { return true }

// The syslog-only families (#536 netmap/ARP, #541 dhclient, #546 dhcp6c and the
// kea-dhcp6 allocation failures). Zenarmor never emits them; these exist so this
// stub still satisfies logship.MetricSink.
func (s *captureSink) ObserveNetmapRingFull(_ string) bool                { return true }
func (s *captureSink) ObserveARPMove(_ string) bool                       { return true }
func (s *captureSink) ObserveDHCPClient(_, _ string) bool                 { return true }
func (s *captureSink) ObserveDHCPClientScript(_, _ string) bool           { return true }
func (s *captureSink) ObserveDHCPClientLease(_ string, _, _ float64) bool { return true }
func (s *captureSink) ObserveDHCP6CMessage(_, _, _ string) bool           { return true }
func (s *captureSink) ObserveDHCP6CEvent(_, _, _ string) bool             { return true }
func (s *captureSink) ObserveDHCP6AllocFail(_ string) bool                { return true }

func (s *captureSink) ObserveDHCP6CPrefix(_, _ string, _, _, _ float64) bool { return true }

func (s *captureSink) ObserveDHCP6CAddress(_ string, _, _, _ float64) bool { return true }
func (s *captureSink) ClearDHCP6CAddress(_ string) bool                    { return true }

var _ logship.MetricSink = (*captureSink)(nil)

func TestObserveDerivedPropagatesSinkAcceptance(t *testing.T) {
	accepted := &captureSink{}
	if !observeDerived(accepted, "flow", map[string]string{}) {
		t.Fatal("accepted observation reported false")
	}

	rejected := &captureSink{reject: true}
	if observeDerived(rejected, "flow", map[string]string{}) {
		t.Fatal("rejected observation reported true")
	}
}

func (s *captureSink) only(t *testing.T) logship.ZenarmorObservation {
	t.Helper()
	if len(s.got) != 1 {
		t.Fatalf("got %d observations, want 1", len(s.got))
	}
	return s.got[0]
}

func TestObserveDerivedPerFamily(t *testing.T) {
	cases := []struct {
		name   string
		family string
		attrs  map[string]string
		want   logship.ZenarmorObservation
	}{
		{
			name:   "flow takes app_category",
			family: "flow",
			attrs: map[string]string{
				logship.AttrAction: logship.ActionBlock,
				attrAppCategory:    "File Transfer",
				attrInterfaceName:  "LAN",
			},
			want: logship.ZenarmorObservation{
				Family: "flow", Action: "block", Category: "File Transfer", Interface: "LAN",
			},
		},
		{
			name:   "dns takes domain_category and rcode",
			family: "dns",
			attrs: map[string]string{
				logship.AttrAction: logship.ActionPass,
				attrDomainCategory: "Technology and Computer",
				attrRCode:          "0",
				attrInterfaceName:  "LAN",
			},
			want: logship.ZenarmorObservation{
				Family: "dns", Action: "pass", Category: "Technology and Computer",
				Interface: "LAN", RCode: "0",
			},
		},
		{
			name:   "tls takes domain_category but no rcode",
			family: "tls",
			attrs: map[string]string{
				logship.AttrAction: logship.ActionPass,
				attrDomainCategory: "Uncategorized",
				attrInterfaceName:  "VLAN50",
			},
			want: logship.ZenarmorObservation{
				Family: "tls", Action: "pass", Category: "Uncategorized", Interface: "VLAN50",
			},
		},
		{
			name:   "web buckets the status",
			family: "web",
			attrs: map[string]string{
				logship.AttrAction: logship.ActionPass,
				attrHTTPStatus:     "404",
				attrInterfaceName:  "LAN",
			},
			want: logship.ZenarmorObservation{
				Family: "web", Action: "pass", Interface: "LAN", StatusClass: "4xx",
			},
		},
		{
			name:   "ids takes alert category and severity",
			family: "ids",
			attrs: map[string]string{
				logship.AttrAction: logship.ActionBlock,
				attrAlertCategory:  "Attempted Administrator Privilege Gain",
				attrAlertSeverity:  "1",
				attrInterfaceName:  "WAN",
			},
			want: logship.ZenarmorObservation{
				Family: "ids", Action: "block", Interface: "WAN",
				Category: "Attempted Administrator Privilege Gain", Severity: "1",
			},
		},
		{
			name:   "voip carries only the shared dimensions",
			family: "voip",
			attrs: map[string]string{
				logship.AttrAction: logship.ActionPass,
				attrInterfaceName:  "LAN",
			},
			want: logship.ZenarmorObservation{Family: "voip", Action: "pass", Interface: "LAN"},
		},
		{
			name:   "the raw device stands in when enrichment did not resolve a name",
			family: "flow",
			attrs: map[string]string{
				logship.AttrAction: logship.ActionPass,
				attrInterfaceDev:   "ixl0",
			},
			want: logship.ZenarmorObservation{Family: "flow", Action: "pass", Interface: "ixl0"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &captureSink{}
			observeDerived(s, c.family, c.attrs)
			if got := s.only(t); !reflect.DeepEqual(got, c.want) {
				t.Errorf("observation =\n %+v\nwant\n %+v", got, c.want)
			}
		})
	}
}

// The end-to-end wiring that the frozen key consts exist to protect: a key written by
// parse.go under one spelling and read by derive.go under another yields a silently
// empty label, with nothing failing anywhere. So derive from a REAL parsed document
// rather than a hand-built attribute map.
func TestObserveDerivedFromRealDocuments(t *testing.T) {
	cases := []struct {
		family string
		doc    string
		want   logship.ZenarmorObservation
	}{
		{
			family: "flow", doc: connDoc,
			want: logship.ZenarmorObservation{
				Family: "flow", Action: "pass", Category: "Network Management", Interface: "ixl0",
			},
		},
		{
			family: "dns", doc: dnsAnsweredDoc,
			want: logship.ZenarmorObservation{
				Family: "dns", Action: "pass", Category: "Technology and Computer",
				Interface: "ixl0", RCode: "0",
			},
		},
		{
			family: "tls", doc: tlsDoc,
			want: logship.ZenarmorObservation{
				Family: "tls", Action: "pass", Category: "Uncategorized", Interface: "ixl0",
			},
		},
		{
			family: "web", doc: httpDoc,
			want: logship.ZenarmorObservation{
				Family: "web", Action: "pass", Interface: "ixl0", StatusClass: "2xx",
			},
		},
		{
			family: "ids", doc: alertDoc,
			want: logship.ZenarmorObservation{
				Family: "ids", Action: "block", Interface: "ixl0",
				Category: "Attempted Administrator Privilege Gain", Severity: "1",
			},
		},
	}
	for _, c := range cases {
		t.Run(c.family, func(t *testing.T) {
			rec, ok := buildRecord(c.family, []byte(c.doc), nil)
			if !ok {
				t.Fatal("buildRecord returned !ok")
			}
			s := &captureSink{}
			observeDerived(s, c.family, rec.Attributes)
			if got := s.only(t); !reflect.DeepEqual(got, c.want) {
				t.Errorf("observation =\n %+v\nwant\n %+v", got, c.want)
			}
		})
	}
}

// THE cardinality guard. Zenarmor is the highest-cardinality data this exporter
// touches, and every per-flow field sits in the same attribute map as the bounded
// ones. If anyone ever routes one into a counter label, this fails.
func TestObserveDerivedNeverPassesUnboundedLabels(t *testing.T) {
	// Every unbounded value below is present in the attributes, under the key parse.go
	// really writes it to, taken from the real captured documents.
	unbounded := map[string]string{
		"app_name":            "BitTorrent",
		"ip_src_saddr":        "10.0.0.114",
		"ip_dst_saddr":        "61.145.136.88",
		"ip_src_port":         "55309",
		"ip_dst_port":         "6001",
		"src_hostname":        "10.0.0.114",
		"dst_hostname":        "www.tinionet.net",
		"src_hwaddr":          "bc2411c1d512",
		"ja3":                 "d4532a81f32dbfb55a549c648cddc3da",
		"community_id":        "1:tecORBpGbqEAiZw4rUmpJB5C6yM=",
		"conn_uuid":           "418a309b-1b40-42b0-b39e-03726055ff8c",
		"server_name":         "www.tinionet.net",
		"query":               "time.windows.com",
		"uri":                 "/inform",
		"user_agent":          "ESP32 HTTP Client/1.0",
		"host":                "10.0.0.11",
		"device.name":         "opnsense-devel",
		"alertinfo.signature": "ET EXPLOIT Possible CVE-2021-44228",
	}
	bounded := map[string]string{
		logship.AttrAction: logship.ActionBlock,
		attrAppCategory:    "File Transfer",
		attrDomainCategory: "Technology and Computer",
		attrAlertCategory:  "Attempted Administrator Privilege Gain",
		attrAlertSeverity:  "1",
		attrRCode:          "0",
		attrHTTPStatus:     "404",
		attrInterfaceName:  "LAN",
	}

	attrs := make(map[string]string, len(unbounded)+len(bounded))
	for k, v := range unbounded {
		attrs[k] = v
	}
	for k, v := range bounded {
		attrs[k] = v
	}

	for _, family := range []string{"flow", "dns", "tls", "web", "ids", "voip", "somethingnew"} {
		s := &captureSink{}
		observeDerived(s, family, attrs)
		o := s.only(t)

		// Reflect over the observation so a NEW field added to ZenarmorObservation is
		// covered automatically rather than needing this test updated.
		v := reflect.ValueOf(o)
		for i := 0; i < v.NumField(); i++ {
			got := v.Field(i).String()
			fieldName := v.Type().Field(i).Name
			for key, bad := range unbounded {
				if got == bad {
					t.Errorf("family %q: unbounded value %q (from attribute %q) reached counter label %s",
						family, bad, key, fieldName)
				}
			}
		}
	}
}

// A parse failure still gets counted, under its family, so sum(rate(zenarmor_total))
// stays equal to the document rate instead of quietly under-reporting.
func TestObserveDerivedCountsUnparsedRecords(t *testing.T) {
	rec, parsed := parseDoc("flow", []byte(`garbage`), nil)
	if parsed {
		t.Fatal("fixture should not parse")
	}
	s := &captureSink{}
	observeDerived(s, "flow", rec.Attributes) // nil attributes
	if got := s.only(t); got != (logship.ZenarmorObservation{Family: "flow"}) {
		t.Errorf("observation = %+v, want only the family set", got)
	}
}

func TestObserveDerivedNilSinkIsSafe(t *testing.T) {
	observeDerived(nil, "flow", map[string]string{})
}

func TestStatusClass(t *testing.T) {
	cases := map[string]string{
		"200": "2xx", "204": "2xx", "301": "3xx", "404": "4xx", "500": "5xx",
		"100": "1xx",
		// Out of range or unparseable must yield "" rather than invent a bucket.
		"": "", "99": "", "600": "", "abc": "", "-1": "", "OK": "",
	}
	for in, want := range cases {
		if got := statusClass(in); got != want {
			t.Errorf("statusClass(%q) = %q, want %q", in, got, want)
		}
	}
}

// Cheap belt-and-braces on the taxonomy assumption: a category is a bounded label, so
// it must never look like a hostname, a URL or an IP.
func TestCategoryValuesLookBounded(t *testing.T) {
	for _, doc := range []string{connDoc, dnsAnsweredDoc, tlsDoc, httpDoc} {
		for _, family := range []string{"flow", "dns", "tls", "web"} {
			rec, _ := buildRecord(family, []byte(doc), nil)
			s := &captureSink{}
			observeDerived(s, family, rec.Attributes)
			cat := s.only(t).Category
			if strings.ContainsAny(cat, "/:") {
				t.Errorf("family %q category %q looks like a URL or address, not a taxonomy value", family, cat)
			}
		}
	}
}

// --- #474: the bounded device inventory -------------------------------------

// The inventory is fed from the SAME parsed record as the counter, but through its
// own sink method, so device_name never reaches the counter's label tuple.
func TestObserveDerived_FeedsTheDeviceInventory(t *testing.T) {
	sink := &captureSink{}
	attrs := map[string]string{
		"device.name":     "robs-laptop",
		"device.category": "laptop",
		attrInterfaceName: "IOT",
	}
	observeDerived(sink, "flow", attrs)

	want := [][3]string{{"robs-laptop", "laptop", "IOT"}}
	if !reflect.DeepEqual(sink.devices, want) {
		t.Fatalf("devices = %v, want %v", sink.devices, want)
	}
	// And it must not have leaked into the counter's tuple.
	for _, o := range sink.got {
		if strings.Contains(o.Category, "robs-laptop") || o.Interface == "robs-laptop" {
			t.Fatalf("device name leaked into the counter observation: %+v", o)
		}
	}
}

// A record with no device attributed is not a device. Observing it would mint a
// permanent empty-named series that reads as a real device on the picker.
func TestObserveDerived_SkipsRecordsWithNoDevice(t *testing.T) {
	sink := &captureSink{}
	observeDerived(sink, "dns", map[string]string{attrRCode: "0"})
	if len(sink.devices) != 0 {
		t.Fatalf("devices = %v, want none for a record carrying no device", sink.devices)
	}
}

// An unenriched record still names its device, so it still belongs in the inventory —
// the interface just falls back to the kernel device until enrichment resolves it.
//
// This fallback is only safe because the inventory is keyed on the device NAME, with
// the interface as a value (#476). It used to be part of the key, which forked one
// device into two rows — `jules/ixl0` and `jules/LAN` — with the stale one sitting out
// its full 24h TTL. Now the later sighting overwrites the earlier one.
//
// Skipping unenriched records instead would be worse: if the enrichment snapshot never
// loaded, the inventory would stay empty and the picker would silently show nothing.
func TestObserveDerived_DeviceInventoryFallsBackToTheRawDevice(t *testing.T) {
	sink := &captureSink{}
	observeDerived(sink, "flow", map[string]string{
		"device.name":    "printer-1",
		attrInterfaceDev: "ixl0",
	})
	want := [][3]string{{"printer-1", "", "ixl0"}}
	if !reflect.DeepEqual(sink.devices, want) {
		t.Fatalf("devices = %v, want %v — unenriched records still belong in the inventory", sink.devices, want)
	}
}
