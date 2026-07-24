package webui

import (
	"net/http"
	"sort"
	"time"
)

// IfIndexRow is one resolved ifIndex entry.
type IfIndexRow struct {
	Index     uint32 // the NetFlow ifIndex
	Device    string // kernel device: "ixl0", "pppoe0"; empty if the override named only a label
	Name      string // OPNsense description: "LAN", "AAISP"; may be empty
	Source    string // "derived" | "override"
	Stated    uint32 // index the API states for this device; 0 when the API states none
	Disagrees bool   // Stated is non-zero and differs from Index
}

// IfIndexReport is the whole resolved map plus its health counters.
type IfIndexReport struct {
	Rows          []IfIndexRow
	Built         time.Time
	Entries       int
	Overridden    int
	Conflicts     int
	Disagreements int
	Unmapped      uint64
}

// init registers the ifIndex page area's routes. See server.go's extension docs
// for the pattern every page area follows.
func init() { registerRoutes((*Server).registerIfIndex) }

// registerIfIndex mounts the resolved-ifIndex-map JSON endpoint.
//
// # Why this page exists at all
//
// A NetFlow ifIndex is a 1-based position over `ifinfo` output that OPNsense
// turns into a netgraph hook name; the exporter can only DERIVE the mapping by
// replaying that enumeration over the interface list the API returns, and the
// API is not obliged to reproduce ifinfo's ordering. That derivation was
// silently wrong in production for months — off by one from index 10 up, which
// mislabelled 93% of byte volume — and it survived precisely because nothing in
// the product ever SHOWED the mapping. The only way to see it was to decode a
// raw packet capture. This endpoint closes that hole: it makes the resolved map
// eyeballable against the firewall's own `ifinfo` output.
//
// # Why it is not on the poll
//
// The tab loads this endpoint lazily on tab-open, like Devices — but for the
// opposite reason. Devices is lazy because its fetch reaches the firewall; this
// one is lazy only because the map changes about as often as an operator adds an
// interface, so re-fetching it every few seconds would be pure noise. It is a
// cheap in-memory read of already-resolved state: it never gathers the live
// registry and never touches the firewall.
func (s *Server) registerIfIndex(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/ifindex.json", s.handleIfIndexJSON)
}

// handleIfIndexJSON serves the resolved map, or 404s when there is no flow lane
// to have resolved one. The 404 is deliberate: an empty 200 would read as "the
// map resolved to nothing", which is a very different operational statement from
// "NetFlow is switched off". devices.go 404s its disabled kill switch for the
// same reason.
func (s *Server) handleIfIndexJSON(w http.ResponseWriter, r *http.Request) {
	if s.deps.IfIndexMap == nil {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, s.ifIndexReport())
}

// ifIndexReport reads the resolved map through the Deps closure and returns it
// with the rows in ascending index order.
func (s *Server) ifIndexReport() IfIndexReport {
	rep := s.deps.IfIndexMap()
	rep.Rows = sortedIfIndexRows(rep.Rows)
	return rep
}

// sortedIfIndexRows returns a COPY of rows ordered by ascending Index.
//
// The copy is not defensive tidiness. The closure hands back the flow lane's own
// view of a map that is rebuilt and swapped under live readers, so sorting the
// returned slice in place would have a read-only console handler mutating shared
// state — a data race, not a cosmetic one.
//
// The ordering is what makes the table usable: it is meant to be read straight
// down against `ifinfo` output, line for line. Note the sort is numeric, not
// lexical — a lexical order puts 10 before 2, and index 10 is exactly where the
// production off-by-one began, so a string sort would scatter the divergence
// across the table instead of parking it at the first row that differs.
func sortedIfIndexRows(rows []IfIndexRow) []IfIndexRow {
	if len(rows) == 0 {
		return nil
	}
	out := make([]IfIndexRow, len(rows))
	copy(out, rows)
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}
