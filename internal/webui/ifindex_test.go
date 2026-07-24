package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ifIndexDeps returns console deps whose IfIndexMap closure yields rep. A nil
// closure is the "flow lane is off" case and is set by the caller, not here.
func ifIndexDeps(rep IfIndexReport) Deps {
	d := testDeps()
	d.IfIndexMap = func() IfIndexReport { return rep }
	return d
}

// sampleIfIndexReport is a deliberately UNSORTED report carrying one of each
// interesting row shape: a plain derived row, an override that agrees with the
// derivation, an override the box contradicts, and a label-only override with no
// kernel device. Handing it out unsorted is the point — the console's whole job
// on this tab is to be read straight down against `ifinfo` output, which only
// works if the rows come out in index order regardless of map iteration order.
func sampleIfIndexReport() IfIndexReport {
	return IfIndexReport{
		Rows: []IfIndexRow{
			{Index: 11, Device: "pppoe0", Name: "AAISP", Source: "override", Stated: 10, Disagrees: true},
			{Index: 2, Device: "ixl1", Name: "LAN", Source: "derived"},
			{Index: 7, Name: "GUEST", Source: "override"},
			{Index: 1, Device: "ixl0", Name: "WAN", Source: "derived", Stated: 1},
		},
		Built:         time.Now(),
		Entries:       4,
		Overridden:    2,
		Conflicts:     1,
		Disagreements: 1,
		Unmapped:      37,
	}
}

// TestHandler_IfIndexJSON_404WhenFlowLaneOff pins the disabled case. With no
// flow lane there is no resolved map to eyeball, so the endpoint must 404 rather
// than serve an empty report that reads like "the map is empty" — the same
// distinction devices.go draws for its kill switch. The catch-all "/" route
// would otherwise answer this path with the console HTML at 200, so a 404 here
// is also proof the route registered at all.
func TestHandler_IfIndexJSON_404WhenFlowLaneOff(t *testing.T) {
	d := testDeps()
	d.IfIndexMap = nil
	srv := NewServer(d)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/ifindex.json", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("ifindex JSON with no flow lane want 404, got %d", rec.Code)
	}
}

// TestHandler_IfIndexRouteSelfRegistered asserts the route is wired by this
// file's own init() — Handler() builds a fresh mux from the registrar list, so
// serving JSON (not the catch-all's HTML) proves registration happened without
// any central edit.
func TestHandler_IfIndexRouteSelfRegistered(t *testing.T) {
	srv := NewServer(ifIndexDeps(sampleIfIndexReport()))

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/ifindex.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("ifindex JSON want 200, got %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Fatalf("content-type want json (got %q) — the request fell through to the / page handler", got)
	}
}

// TestHandler_IfIndexJSON_RowsSortedByIndex is the reason this page exists: the
// table has to line up row-for-row with `ifinfo` output, so the rows must leave
// the handler in ascending index order whatever order the flow lane hands them
// over in.
func TestHandler_IfIndexJSON_RowsSortedByIndex(t *testing.T) {
	cases := []struct {
		name string
		in   []IfIndexRow
		want []uint32
	}{
		{"unsorted", []IfIndexRow{{Index: 11}, {Index: 2}, {Index: 7}, {Index: 1}}, []uint32{1, 2, 7, 11}},
		{"already sorted", []IfIndexRow{{Index: 0}, {Index: 1}, {Index: 2}}, []uint32{0, 1, 2}},
		{"reversed", []IfIndexRow{{Index: 3}, {Index: 2}, {Index: 1}}, []uint32{1, 2, 3}},
		// Index 10+ is exactly where the production bug lived: a lexical sort puts
		// 10 before 2, which is the ordering that made the off-by-one invisible.
		{"numeric not lexical", []IfIndexRow{{Index: 10}, {Index: 2}, {Index: 1}}, []uint32{1, 2, 10}},
		{"empty", nil, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := NewServer(ifIndexDeps(IfIndexReport{Rows: tc.in}))
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/ifindex.json", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("want 200, got %d", rec.Code)
			}
			var rep IfIndexReport
			if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if len(rep.Rows) != len(tc.want) {
				t.Fatalf("row count = %d, want %d (%+v)", len(rep.Rows), len(tc.want), rep.Rows)
			}
			for i, want := range tc.want {
				if rep.Rows[i].Index != want {
					t.Fatalf("row %d index = %d, want %d (rows %+v)", i, rep.Rows[i].Index, want, rep.Rows)
				}
			}
		})
	}
}

// TestIfIndexReport_DoesNotReorderTheSource asserts the sort works on a copy.
// The closure hands back the flow lane's own view of the map; reordering that
// slice in place would mutate live state from a read-only console handler, and
// under concurrent scrapes that is a data race, not a cosmetic problem.
func TestIfIndexReport_DoesNotReorderTheSource(t *testing.T) {
	src := []IfIndexRow{{Index: 11}, {Index: 2}, {Index: 7}, {Index: 1}}
	d := testDeps()
	d.IfIndexMap = func() IfIndexReport { return IfIndexReport{Rows: src} }
	srv := NewServer(d)

	rep := srv.ifIndexReport()
	if rep.Rows[0].Index != 1 {
		t.Fatalf("returned rows not sorted: %+v", rep.Rows)
	}
	for i, want := range []uint32{11, 2, 7, 1} {
		if src[i].Index != want {
			t.Fatalf("source slice was reordered at %d: got %d, want %d (%+v)", i, src[i].Index, want, src)
		}
	}
}

// TestHandler_IfIndexJSON_RendersEveryRowAndCounters asserts the whole report
// survives the round trip: every row, its resolved fields, and the health
// counters the page's summary reads.
func TestHandler_IfIndexJSON_RendersEveryRowAndCounters(t *testing.T) {
	srv := NewServer(ifIndexDeps(sampleIfIndexReport()))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/ifindex.json", nil))

	var rep IfIndexReport
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(rep.Rows) != 4 {
		t.Fatalf("want 4 rows, got %d: %+v", len(rep.Rows), rep.Rows)
	}
	byIndex := map[uint32]IfIndexRow{}
	for _, r := range rep.Rows {
		byIndex[r.Index] = r
	}
	if got := byIndex[1]; got.Device != "ixl0" || got.Name != "WAN" || got.Source != "derived" || got.Stated != 1 || got.Disagrees {
		t.Errorf("derived row 1 round-tripped wrong: %+v", got)
	}
	if got := byIndex[11]; got.Source != "override" || got.Stated != 10 || !got.Disagrees {
		t.Errorf("disagreeing override row 11 round-tripped wrong: %+v", got)
	}
	if got := byIndex[7]; got.Device != "" || got.Name != "GUEST" || got.Source != "override" {
		t.Errorf("label-only override row 7 round-tripped wrong: %+v", got)
	}
	if rep.Entries != 4 || rep.Overridden != 2 || rep.Conflicts != 1 || rep.Disagreements != 1 || rep.Unmapped != 37 {
		t.Errorf("counters round-tripped wrong: %+v", rep)
	}
	if rep.Built.IsZero() {
		t.Errorf("Built timestamp lost in the round trip")
	}
}

// TestHandler_IfIndexJSON_ShapeIsStable pins the wire keys. The page rebuilds
// its table from this JSON by field name, so a silent rename would empty the
// table rather than fail anything — the exact class of invisible breakage this
// whole page exists to catch.
func TestHandler_IfIndexJSON_ShapeIsStable(t *testing.T) {
	srv := NewServer(ifIndexDeps(sampleIfIndexReport()))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/ifindex.json", nil))

	var top map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &top); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, key := range []string{"Rows", "Built", "Entries", "Overridden", "Conflicts", "Disagreements", "Unmapped"} {
		if _, ok := top[key]; !ok {
			t.Errorf("ifindex.json missing top-level key %q", key)
		}
	}
	var rows []map[string]json.RawMessage
	if err := json.Unmarshal(top["Rows"], &rows); err != nil {
		t.Fatalf("decode Rows: %v", err)
	}
	if len(rows) == 0 {
		t.Fatalf("no rows to check")
	}
	for _, key := range []string{"Index", "Device", "Name", "Source", "Stated", "Disagrees"} {
		if _, ok := rows[0][key]; !ok {
			t.Errorf("ifindex.json row missing key %q", key)
		}
	}
}

// TestRenderPage_IfIndexTab asserts the console carries the tab, its table body,
// the lazy loader, and the sentence explaining what an ifIndex actually is. That
// last one is not decoration: an operator cannot check this table against
// anything without being told it is a 1-based position over `ifinfo` output.
func TestRenderPage_IfIndexTab(t *testing.T) {
	srv := NewServer(ifIndexDeps(sampleIfIndexReport()))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("page want 200, got %d", rec.Code)
	}
	out := rec.Body.String()
	for _, want := range []string{
		`data-tab="ifindex"`,
		`data-target="ifindex"`,
		`id="ifxBody"`,
		"function loadIfIndex",
		"/api/ifindex.json",
		"ifinfo",
		"iface",
		"renumber",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("console page missing %q", want)
		}
	}
}

// TestRenderPage_IfIndexMarksDisagreementAndOverride asserts the page can tell
// the two interesting row states apart visually. A disagreeing row is the whole
// point of the tab — it is what months of mislabelled byte volume looked like —
// so it must not render as just another row of numbers.
func TestRenderPage_IfIndexMarksDisagreementAndOverride(t *testing.T) {
	srv := NewServer(ifIndexDeps(sampleIfIndexReport()))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	out := rec.Body.String()

	for _, want := range []string{
		// The row classes and the CSS that tints them.
		"tr.ifx-disagrees>td", "tr.ifx-override>td",
		// The JS that applies them from the row's own fields.
		"ifx-disagrees", "ifx-override",
		// The at-a-glance badge on a contradicted row.
		"disagrees",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("console page missing disagreement/override marking %q", want)
		}
	}
}
