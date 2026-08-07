package logship

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/internal/logship/enrich"
	"github.com/rknightion/opnsense2otel/v4/internal/options"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

// --- fixtures ---------------------------------------------------------------

// unboundRow builds one search_queries row as the raw map the fake server
// encodes, mirroring the live-box payload shape captured against a real
// OPNsense 26.7-devel box (#233): uuid is always null there.
func unboundRow(tm int64, client, domain, typ, action, source string) map[string]any {
	return map[string]any{
		"uuid": nil, "time": tm, "client": client, "family": "ip4", "type": typ,
		"domain": domain, "action": action, "source": source, "blocklist": "",
		"rcode": "NOERROR", "resolve_time_ms": 0, "dnssec_status": "Unchecked",
		"ttl": 300, "policy": "", "status": 1,
	}
}

// newUnboundTestServer serves one page of rows per call, in the order given
// (tests supply pages already in the time-DESC order the real API returns).
func newUnboundTestServer(t *testing.T, pages ...[]map[string]any) (*httptest.Server, *opnsense.Client) {
	t.Helper()
	call := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rows []map[string]any
		if call < len(pages) {
			rows = pages[call]
		}
		call++
		if rows == nil {
			rows = []map[string]any{}
		}
		resp := map[string]any{"total": 1000, "rowCount": len(rows), "current": 1, "rows": rows}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(server.Close)

	cfg := options.OPNSenseConfig{
		Protocol: "http", Host: strings.TrimPrefix(server.URL, "http://"),
		APIKey: "k", APISecret: "s",
	}
	client, err := opnsense.NewClient(cfg, "test", slog.Default())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return server, &client
}

func newTestUnboundSource(client *opnsense.Client) *unboundSource {
	return &unboundSource{client: client, log: slog.Default()}
}

// --- tests -------------------------------------------------------------------

func TestUnboundSource_NameAndMinInterval(t *testing.T) {
	s := newTestUnboundSource(nil)
	if s.Name() != "unbound" {
		t.Fatalf("Name() = %q, want unbound", s.Name())
	}
	if s.MinInterval() != 15*time.Second {
		t.Fatalf("MinInterval() = %s, want 15s", s.MinInterval())
	}
}

func TestNewUnboundSource_DisabledByDefault(t *testing.T) {
	src, err := newUnboundSource(Deps{})
	if err != nil {
		t.Fatalf("newUnboundSource: %v", err)
	}
	if src != nil {
		t.Fatal("expected newUnboundSource to report disabled (nil, nil) when --logs.unbound.enabled defaults false")
	}
}

func TestUnboundSource_FirstPollSeedsWithoutEmitting(t *testing.T) {
	page1 := []map[string]any{
		unboundRow(100, "10.0.0.1", "a.example.", "A", "Pass", "Cache"),
		unboundRow(100, "10.0.0.2", "b.example.", "A", "Pass", "Cache"),
		unboundRow(90, "10.0.0.1", "c.example.", "A", "Pass", "Recursion"),
	}
	_, client := newUnboundTestServer(t, page1)
	s := newTestUnboundSource(client)

	records, err := s.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("cold-start poll should seed the cursor without emitting; got %d records", len(records))
	}

	data, ok := s.SaveState()
	if !ok {
		t.Fatal("expected SaveState to have something to persist after the first poll")
	}
	var st unboundState
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatalf("unmarshal state: %v", err)
	}
	if st.LastTime != 100 {
		t.Fatalf("LastTime = %d, want 100", st.LastTime)
	}
	if len(st.Seen) != 2 {
		t.Fatalf("expected 2 fingerprints seeded at the boundary time, got %d", len(st.Seen))
	}
}

func TestUnboundSource_IncrementalDedupAcrossPolls(t *testing.T) {
	page1 := []map[string]any{
		unboundRow(100, "10.0.0.1", "a.example.", "A", "Pass", "Cache"),
		unboundRow(100, "10.0.0.2", "b.example.", "A", "Pass", "Cache"),
	}
	// Second poll: the two t=100 rows repeat (already seen) plus two genuinely
	// new rows at t=103 and t=105, all in time-DESC order like the real API.
	page2 := []map[string]any{
		unboundRow(105, "10.0.0.3", "e.example.", "A", "Pass", "Recursion"),
		unboundRow(103, "10.0.0.4", "d.example.", "A", "Block", "Local"),
		unboundRow(100, "10.0.0.1", "a.example.", "A", "Pass", "Cache"),
		unboundRow(100, "10.0.0.2", "b.example.", "A", "Pass", "Cache"),
	}
	_, client := newUnboundTestServer(t, page1, page2)
	s := newTestUnboundSource(client)

	if _, err := s.Poll(context.Background()); err != nil {
		t.Fatalf("first Poll: %v", err)
	}

	records, err := s.Poll(context.Background())
	if err != nil {
		t.Fatalf("second Poll: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected exactly the 2 new rows, got %d: %+v", len(records), records)
	}
	// Emission order must be oldest-first.
	if records[0].Attributes["domain"] != "d.example." {
		t.Fatalf("records[0] domain = %q, want d.example. (t=103 before t=105)", records[0].Attributes["domain"])
	}
	if records[1].Attributes["domain"] != "e.example." {
		t.Fatalf("records[1] domain = %q, want e.example.", records[1].Attributes["domain"])
	}
	if records[0].Timestamp.Unix() != 103 || records[1].Timestamp.Unix() != 105 {
		t.Fatalf("unexpected timestamps: %v, %v", records[0].Timestamp, records[1].Timestamp)
	}
	if records[0].Severity != SeverityWarn {
		t.Fatalf("expected Block action to carry SeverityWarn, got %v", records[0].Severity)
	}
	if records[1].Severity != SeverityInfo {
		t.Fatalf("expected Pass action to carry SeverityInfo, got %v", records[1].Severity)
	}
}

func TestUnboundSource_ReservedSourceKeyIsNeverForged(t *testing.T) {
	page := []map[string]any{unboundRow(100, "10.0.0.1", "a.example.", "A", "Pass", "Cache")}
	_, client := newUnboundTestServer(t, page)
	s := newTestUnboundSource(client)
	if _, err := s.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	// Force a second, warm poll so records are actually emitted.
	page2 := []map[string]any{
		unboundRow(101, "10.0.0.1", "z.example.", "A", "Pass", "Cache"),
		unboundRow(100, "10.0.0.1", "a.example.", "A", "Pass", "Cache"),
	}
	_, client2 := newUnboundTestServer(t, page2)
	s.client = client2
	records, err := s.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 new record, got %d", len(records))
	}
	if _, ok := records[0].Attributes["source"]; ok {
		t.Fatal("unbound's own 'source' field must not be attributed under the pipeline-reserved 'source' key")
	}
	if records[0].Attributes["query_source"] != "Cache" {
		t.Fatalf("query_source = %q, want Cache", records[0].Attributes["query_source"])
	}
}

func TestUnboundSource_WindowOverflowRecordsPossibleGap(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetrics(reg, queueBounds{capacity: 10, length: func() float64 { return 0 }}, sourceNames{})

	page1 := []map[string]any{unboundRow(100, "10.0.0.1", "a.example.", "A", "Pass", "Cache")}
	_, client := newUnboundTestServer(t, page1)
	s := newTestUnboundSource(client)
	if _, err := s.Poll(context.Background()); err != nil {
		t.Fatalf("first Poll: %v", err)
	}

	// Simulate a busy resolver: the whole next page is newer than the previous
	// cursor (t=100), so there is no continuity at all — a full window overflow.
	page2 := []map[string]any{
		unboundRow(160, "10.0.0.9", "new1.example.", "A", "Pass", "Cache"),
		unboundRow(150, "10.0.0.9", "new2.example.", "A", "Pass", "Cache"),
	}
	_, client2 := newUnboundTestServer(t, page2)
	s.client = client2

	records, err := s.Poll(context.Background())
	if err != nil {
		t.Fatalf("second Poll: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected both visible rows to still be emitted despite the gap, got %d", len(records))
	}
	if got := counterValue(t, m.possibleGap.WithLabelValues("unbound")); got != 1 {
		t.Fatalf("logs_possible_gap_total{source=unbound} = %v, want 1", got)
	}
}

func TestUnboundSource_NoContinuityGapNotDoubleCountedOnNormalPoll(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetrics(reg, queueBounds{capacity: 10, length: func() float64 { return 0 }}, sourceNames{})

	page1 := []map[string]any{unboundRow(100, "c", "a.example.", "A", "Pass", "Cache")}
	_, client := newUnboundTestServer(t, page1)
	s := newTestUnboundSource(client)
	if _, err := s.Poll(context.Background()); err != nil {
		t.Fatalf("first Poll: %v", err)
	}

	// Normal continuity: the new page's oldest row equals the previous cursor.
	page2 := []map[string]any{
		unboundRow(105, "c", "b.example.", "A", "Pass", "Cache"),
		unboundRow(100, "c", "a.example.", "A", "Pass", "Cache"),
	}
	_, client2 := newUnboundTestServer(t, page2)
	s.client = client2
	if _, err := s.Poll(context.Background()); err != nil {
		t.Fatalf("second Poll: %v", err)
	}

	if got := counterValue(t, m.possibleGap.WithLabelValues("unbound")); got != 0 {
		t.Fatalf("logs_possible_gap_total{source=unbound} = %v, want 0 on a continuous poll", got)
	}
}

func TestUnboundSource_EmptyPollIsNoOp(t *testing.T) {
	_, client := newUnboundTestServer(t, []map[string]any{})
	s := newTestUnboundSource(client)

	records, err := s.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if records != nil {
		t.Fatalf("expected nil records on an empty page, got %v", records)
	}
	if _, ok := s.SaveState(); ok {
		t.Fatal("expected nothing to persist when no row has ever been observed")
	}
}

func TestUnboundSource_StateRoundTrip(t *testing.T) {
	page1 := []map[string]any{
		unboundRow(100, "c", "a.example.", "A", "Pass", "Cache"),
		unboundRow(100, "c", "b.example.", "AAAA", "Pass", "Cache"),
	}
	_, client := newUnboundTestServer(t, page1)
	base := newTestUnboundSource(client)
	if _, err := base.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	data, ok := base.SaveState()
	if !ok {
		t.Fatal("expected saved state")
	}

	// A fresh source restores from the persisted blob and must not re-emit the
	// rows it already saw before restart.
	restored := newTestUnboundSource(nil)
	restored.LoadState(data)

	page2 := []map[string]any{
		unboundRow(110, "c", "new.example.", "A", "Pass", "Cache"),
		unboundRow(100, "c", "a.example.", "A", "Pass", "Cache"),
		unboundRow(100, "c", "b.example.", "AAAA", "Pass", "Cache"),
	}
	_, client2 := newUnboundTestServer(t, page2)
	restored.client = client2

	records, err := restored.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll after restore: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected only the genuinely new row after restore, got %d: %+v", len(records), records)
	}
	if records[0].Attributes["domain"] != "new.example." {
		t.Fatalf("unexpected record after restore: %+v", records[0])
	}
}

func TestUnboundSource_LoadStateIgnoresCorruptData(t *testing.T) {
	s := newTestUnboundSource(nil)
	s.LoadState([]byte("not json"))
	if _, ok := s.SaveState(); ok {
		t.Fatal("corrupt LoadState input must not seed a cursor")
	}
}

func TestRowFingerprint_PrefersUUIDWhenPresent(t *testing.T) {
	withUUID := opnsense.UnboundSearchQueryRow{}
	if err := json.Unmarshal([]byte(`{"uuid":"abc-1","time":1}`), &withUUID); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if fp := rowFingerprint(withUUID); fp != "abc-1" {
		t.Fatalf("rowFingerprint = %q, want abc-1", fp)
	}
}

func TestRowFingerprint_FallsBackToContentWhenUUIDNull(t *testing.T) {
	row := opnsense.UnboundSearchQueryRow{}
	if err := json.Unmarshal([]byte(`{"uuid":null,"time":5,"client":"c","domain":"d.","type":"A","action":"Pass","source":"Cache","rcode":"NOERROR","resolve_time_ms":3}`), &row); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	fp1 := rowFingerprint(row)
	fp2 := rowFingerprint(row)
	if fp1 == "" || fp1 != fp2 {
		t.Fatalf("expected a stable non-empty fingerprint, got %q / %q", fp1, fp2)
	}

	other := row
	other.Domain = "different."
	if rowFingerprint(other) == fp1 {
		t.Fatal("expected a different domain to change the fingerprint")
	}
}

// The resolver's Capitalised verb maps onto the normalised opnsense.action while
// the raw one survives — Drop vs Block is a real distinction and stays queryable.
func TestUnboundRecord_SetsAttrAction(t *testing.T) {
	for _, tc := range []struct{ action, want string }{
		{"Pass", ActionPass},
		{"Block", ActionBlock},
		{"Drop", ActionBlock},
	} {
		var row opnsense.UnboundSearchQueryRow
		body := `{"time":1,"client":"10.0.0.6","domain":"x.test.","type":"A","action":"` + tc.action + `","source":"Cache","rcode":"NOERROR"}`
		if err := json.Unmarshal([]byte(body), &row); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		rec := unboundRecord(row, nil)
		if got := rec.Attributes[AttrAction]; got != tc.want {
			t.Errorf("action %q -> opnsense.action %q, want %q", tc.action, got, tc.want)
		}
		if got := rec.Attributes["action"]; got != tc.action {
			t.Errorf("raw action = %q, want %q (the Drop/Block distinction must survive)", got, tc.action)
		}
	}
}

func TestUnboundRecord_UnknownActionLeavesAttrActionUnset(t *testing.T) {
	var row opnsense.UnboundSearchQueryRow
	if err := json.Unmarshal([]byte(`{"time":1,"action":"Reshuffled"}`), &row); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if v, present := unboundRecord(row, nil).Attributes[AttrAction]; present {
		t.Errorf("opnsense.action = %q for an unknown verb; must be absent", v)
	}
}

// unboundRowRecord builds a Record from one raw client value, the only field these
// tests vary.
func unboundRowRecord(t *testing.T, client string, snap *enrich.Snapshot) Record {
	t.Helper()
	var row opnsense.UnboundSearchQueryRow
	body, err := json.Marshal(map[string]any{
		"time": 1, "client": client, "domain": "x.test.", "type": "A",
		"action": "Pass", "source": "Cache", "rcode": "NOERROR",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := json.Unmarshal(body, &row); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return unboundRecord(row, snap)
}

// The contract from #660: whatever the resolver's own client table put in the
// `client` column is carried by dns.client_label, which never claims to be an
// address; src.ip is set ONLY when that value already parses as an IP, so a
// consumer filtering on src.ip can never match a hostname. Values are the real
// ones observed in a live 1000-row page.
func TestUnboundRecord_ClientLabelAndSrcIP(t *testing.T) {
	for _, tc := range []struct {
		name      string
		client    string
		wantLabel string // "" means the attribute must be absent
		wantIP    string // "" means src.ip must be absent
	}{
		{"fqdn with a PTR", "camden.rob-knight.net", "camden.rob-knight.net", ""},
		{"bare ipv4, no PTR", "10.0.0.5", "10.0.0.5", "10.0.0.5"},
		{"bare ipv6 literal", "2001:8b0:1f05::105b", "2001:8b0:1f05::105b", "2001:8b0:1f05::105b"},
		{"non-fqdn name", "poly-office", "poly-office", ""},
		{"localhost", "localhost", "localhost", ""},
		{"empty", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attrs := unboundRowRecord(t, tc.client, nil).Attributes

			got, present := attrs[unboundClientLabelAttr]
			switch {
			case tc.wantLabel == "" && present:
				t.Errorf("%s = %q; an empty client must set no label attribute at all", unboundClientLabelAttr, got)
			case tc.wantLabel != "" && got != tc.wantLabel:
				t.Errorf("%s = %q, want %q", unboundClientLabelAttr, got, tc.wantLabel)
			}

			gotIP, hasIP := attrs["src.ip"]
			switch {
			case tc.wantIP == "" && hasIP:
				t.Errorf("src.ip = %q for client %q; src.ip must be a real address or absent, never a hostname", gotIP, tc.client)
			case tc.wantIP != "" && gotIP != tc.wantIP:
				t.Errorf("src.ip = %q, want %q", gotIP, tc.wantIP)
			}

			if _, stale := attrs["client"]; stale {
				t.Error(`the mixed-type "client" attribute must be gone, not shipped alongside its replacement`)
			}
		})
	}
}

// Enrichment is keyed on the parsed address, exactly like every other lane — and
// is therefore a no-op on the majority of rows, whose client value is a name.
func TestUnboundRecord_EnrichesOnlyAParsedIP(t *testing.T) {
	snap := &enrich.Snapshot{
		Hostnames: map[string]string{"10.0.0.5": "camden", "camden.rob-knight.net": "SHOULD-NOT-RESOLVE"},
		MACs:      map[string]string{"10.0.0.5": "aa:bb:cc:dd:ee:ff"},
		LocalNets: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		SelfIPs:   map[netip.Addr]bool{netip.MustParseAddr("10.0.0.254"): true},
	}

	t.Run("client without a PTR is enriched from our own tables", func(t *testing.T) {
		attrs := unboundRowRecord(t, "10.0.0.5", snap).Attributes
		for k, want := range map[string]string{
			"src.ip": "10.0.0.5", "src.hostname": "camden",
			"src.mac": "aa:bb:cc:dd:ee:ff", "src.scope": "local",
		} {
			if attrs[k] != want {
				t.Errorf("%s = %q, want %q", k, attrs[k], want)
			}
		}
	})

	t.Run("client with a PTR gets no src.* at all", func(t *testing.T) {
		attrs := unboundRowRecord(t, "camden.rob-knight.net", snap).Attributes
		for _, k := range []string{"src.ip", "src.hostname", "src.mac", "src.scope"} {
			if v, ok := attrs[k]; ok {
				t.Errorf("%s = %q; a hostname-shaped client value must never be enriched as an address", k, v)
			}
		}
	})
}
