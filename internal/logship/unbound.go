package logship

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rknightion/opnsense2otel/v4/internal/logship/enrich"
	"github.com/rknightion/opnsense2otel/v4/internal/options"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

// unboundSourceName is the Name()/`source` attribute value for this lane.
const unboundSourceName = "unbound"

// unboundClientLabelAttr carries the `client` column exactly as the resolver's own
// client table produced it — a hostname when OPNsense had a PTR/lease name for the
// querier, a bare IP when it did not, `localhost`, or nothing at all (#660).
//
// It is deliberately NOT called src.ip or any other address key. The firewall
// destroys the raw client address before serialisation — `stats.py handle_details()`
// collapses hostname over client with np.where and then drops the `hostname` and
// `ipaddr` columns, on BOTH SQL branches — so this value is not one type and never
// can be from this endpoint. Naming it a *label* is the honest description: it is
// whatever identity string the resolver applied, and it is the only field on this
// lane stable enough to group a panel on.
//
// Consequence, and it is not fixable here: this lane cannot be joined to NetFlow or
// Zenarmor flow records by IP on most rows. The syslog per-query route (#659) logs
// the raw client address and never substitutes; use it when IP correlation matters.
const unboundClientLabelAttr = "dns.client_label"

func init() {
	RegisterSource(newUnboundSource)
}

// newUnboundSource builds the unbound per-query DNS log source, or reports it
// disabled (nil, nil) when --logs.unbound.enabled is not set.
func newUnboundSource(deps Deps) (Source, error) {
	if !options.LogsUnboundEnabled() {
		return nil, nil
	}
	return &unboundSource{client: deps.Client, log: deps.Logger, cache: deps.Cache}, nil
}

// unboundSource ships Unbound's per-query DNS log
// (api/unbound/overview/search_queries) to Loki: a pi-hole-style record per
// query with block/policy enrichment unavailable anywhere else in OPNsense's
// API surface.
//
// ACCEPTED-LOSS DESIGN (#233): without a client filter, the backing DuckDB
// query only ever returns the newest 1000 rows across the WHOLE resolver
// (opnsense.FetchUnboundSearchQueries / UnboundSearchQueriesRowCap) — there is
// no true cursor. This source reconstructs a best-effort cursor from the
// row's own `time` (unix seconds) plus a content fingerprint for same-second
// dedup (uuid is documented but observed always null on a live box, so it is
// used only when present). On a resolver busy enough that more than ~1000
// queries land between two polls, the oldest rows in the new page will all be
// newer than the previous cursor — a full discontinuity — which is detected
// and counted via logs_possible_gap_total{source="unbound"} rather than
// silently presented as a complete stream.
type unboundSource struct {
	client *opnsense.Client
	log    *slog.Logger
	// cache is the shared enrichment snapshot, used only on the minority of rows
	// whose client value is already an address (see unboundClientLabelAttr). May be
	// nil in tests; a nil cache simply enriches nothing.
	cache *enrich.Cache

	mu sync.Mutex
	// lastTime is the newest row `time` value processed by the previous Poll
	// (unix seconds). Zero means "never polled" (cold start).
	lastTime int64
	// seenAtLastTime dedupes rows sharing exactly lastTime across polls (the API
	// has one-second resolution, and duplicate seconds are common past ~1 qps).
	seenAtLastTime map[string]struct{}
}

func (s *unboundSource) Name() string { return unboundSourceName }

// MinInterval raises the poll floor to 15s (#233): each call spawns
// python+pandas+DuckDB on the box (~1s CPU).
func (s *unboundSource) MinInterval() time.Duration { return options.LogsUnboundMinInterval() }

// ReportsGaps marks unbound as a bounded-window source, so the pipeline
// pre-initialises logs_possible_gap_total{source="unbound"} to zero (#280). It is
// the only implementer: api/unbound/overview/search_queries exposes just the newest
// 1000 rows resolver-wide, so a busy resolver can push older rows out of the window
// between polls. Poll detects that and calls recordPossibleGap below.
func (s *unboundSource) ReportsGaps() {}

// Poll fetches the newest query rows and returns the ones not yet shipped,
// oldest first. The very first poll (cold start, no persisted state) seeds the
// cursor without emitting anything — mirroring the pipeline's own restart
// convention ("resume from now") so a restart never dumps up to 1000 rows of
// arbitrarily-old history as if it just happened.
func (s *unboundSource) Poll(ctx context.Context) ([]Record, error) {
	rows, err := s.client.WithContext(ctx).FetchUnboundSearchQueries()
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}

	lastTime, seenAtLastTime := s.snapshotCursor()
	coldStart := lastTime == 0

	// rows are time DESC (newest first), per FetchUnboundSearchQueries.
	newest := int64(rows[0].Time.Int())
	oldest := int64(rows[len(rows)-1].Time.Int())

	if !coldStart && oldest > lastTime {
		// The entire returned page is newer than our last cursor: whatever rows
		// existed between lastTime and oldest were pushed out of the backend's
		// 1000-row window before we ever fetched them. Count it, don't hide it.
		recordPossibleGap(unboundSourceName)
	}

	var records []Record
	if !coldStart {
		kept := make([]opnsense.UnboundSearchQueryRow, 0, len(rows))
		for _, row := range rows {
			t := int64(row.Time.Int())
			switch {
			case t > lastTime:
				kept = append(kept, row)
			case t == lastTime:
				if _, seen := seenAtLastTime[rowFingerprint(row)]; !seen {
					kept = append(kept, row)
				}
			}
		}
		// kept preserves the page's time-DESC order; reverse it so records are
		// emitted oldest first.
		snap := s.snapshot()
		records = make([]Record, 0, len(kept))
		for i := len(kept) - 1; i >= 0; i-- {
			records = append(records, unboundRecord(kept[i], snap))
		}
	}

	// Re-seed the cursor and the same-second dedup ring from the FULL page (not
	// just kept rows) so an already-seen boundary row is still remembered next
	// poll.
	nextSeen := make(map[string]struct{})
	for _, row := range rows {
		if int64(row.Time.Int()) == newest {
			nextSeen[rowFingerprint(row)] = struct{}{}
		}
	}
	s.updateCursor(newest, nextSeen)

	return records, nil
}

// snapshot returns the current enrichment snapshot, or nil when no cache was wired
// (tests, and any future caller that builds the source directly).
func (s *unboundSource) snapshot() *enrich.Snapshot {
	if s.cache == nil {
		return nil
	}
	return s.cache.Load()
}

func (s *unboundSource) snapshotCursor() (int64, map[string]struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastTime, s.seenAtLastTime
}

func (s *unboundSource) updateCursor(lastTime int64, seen map[string]struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastTime = lastTime
	s.seenAtLastTime = seen
}

// unboundState is the persisted cursor blob (StatefulSource).
type unboundState struct {
	LastTime int64    `json:"last_time"`
	Seen     []string `json:"seen,omitempty"`
}

// LoadState restores the cursor from a previously persisted blob. Malformed
// data is ignored (resume from now), matching the pipeline's documented
// best-effort resume semantics.
func (s *unboundSource) LoadState(data []byte) {
	var st unboundState
	if err := json.Unmarshal(data, &st); err != nil {
		return
	}
	seen := make(map[string]struct{}, len(st.Seen))
	for _, fp := range st.Seen {
		seen[fp] = struct{}{}
	}
	s.updateCursor(st.LastTime, seen)
}

// SaveState returns the current cursor for persistence, or ok=false before the
// first successful poll (nothing to persist yet).
func (s *unboundSource) SaveState() ([]byte, bool) {
	lastTime, seenMap := s.snapshotCursor()
	if lastTime == 0 {
		return nil, false
	}
	seen := make([]string, 0, len(seenMap))
	for fp := range seenMap {
		seen = append(seen, fp)
	}
	sort.Strings(seen) // deterministic encoding
	data, err := json.Marshal(unboundState{LastTime: lastTime, Seen: seen})
	if err != nil {
		return nil, false
	}
	return data, true
}

// rowFingerprint returns a stable per-row identity used for same-second dedup
// across polls. The documented uuid field is preferred when non-empty, but
// Unbound is observed to leave it null in practice (verified against a live
// OPNsense 26.7-devel box, #233), so a composite of the row's own fields is
// used as a fallback. A bit-identical duplicate query (same
// client/domain/type/action/source/rcode/resolve time in the same second) can
// collide and be deduped away; that is an accepted, documented trade-off, not
// a correctness bug — see the source's doc comment.
func rowFingerprint(row opnsense.UnboundSearchQueryRow) string {
	if u := row.UUID.String(); u != "" {
		return u
	}
	return strings.Join([]string{
		strconv.FormatInt(int64(row.Time.Int()), 10),
		row.Client.String(), row.Domain.String(), row.Type.String(),
		row.Action.String(), row.Source.String(), row.RCode.String(),
		strconv.Itoa(row.ResolveTimeMs.Int()),
	}, "|")
}

// unboundLogLine is the compact JSON Record.Body for one query — full row
// fidelity, independent of the (smaller) structured-metadata attribute set
// below.
type unboundLogLine struct {
	Time          int64  `json:"time"`
	Client        string `json:"client"`
	Family        string `json:"family,omitempty"`
	Type          string `json:"type"`
	Domain        string `json:"domain"`
	Action        string `json:"action"`
	Source        string `json:"source"`
	Blocklist     string `json:"blocklist,omitempty"`
	RCode         string `json:"rcode"`
	ResolveTimeMs int64  `json:"resolve_time_ms,omitempty"`
	DNSSECStatus  string `json:"dnssec_status,omitempty"`
	TTL           int64  `json:"ttl,omitempty"`
	Policy        string `json:"policy,omitempty"`
}

// unboundRecord converts one API row into a shippable Record.
//
// Attribute key note: Unbound's own "source" field (Recursion/Local/Local-data
// /Cache — where the answer came from) is deliberately mapped to the
// "query_source" attribute, NOT "source" — the pipeline reserves the "source"
// attribute key for its own `source` stamp (this lane's Name(), "unbound") and
// strips any Record.Attributes entry under that key before shipping (see
// record.go's sanitizeAttributes). Using "source" here would silently lose
// Unbound's resolution-source data on every record.
// Client note (#660): the upstream `client` column is mixed-type by construction,
// so it ships as unboundClientLabelAttr rather than a bare `client`, and src.ip is
// set only when that value already parses as an address — see the const's comment.
func unboundRecord(row opnsense.UnboundSearchQueryRow, snap *enrich.Snapshot) Record {
	line := unboundLogLine{
		Time:          int64(row.Time.Int()),
		Client:        row.Client.String(),
		Family:        row.Family.String(),
		Type:          row.Type.String(),
		Domain:        row.Domain.String(),
		Action:        row.Action.String(),
		Source:        row.Source.String(),
		Blocklist:     row.Blocklist.String(),
		RCode:         row.RCode.String(),
		ResolveTimeMs: int64(row.ResolveTimeMs.Int()),
		DNSSECStatus:  row.DNSSECStatus.String(),
		TTL:           int64(row.TTL.Int()),
		Policy:        row.Policy.String(),
	}
	body, err := json.Marshal(line)
	if err != nil {
		body = []byte(`{"error":"unbound log line encode failure"}`)
	}

	attrs := map[string]string{
		"domain":        row.Domain.String(),
		"qtype":         row.Type.String(),
		"action":        row.Action.String(),
		"query_source":  row.Source.String(),
		"rcode":         row.RCode.String(),
		"blocklist":     row.Blocklist.String(),
		"dnssec_status": row.DNSSECStatus.String(),
	}
	// Normalised, promotable disposition. The resolver's own Capitalised verb
	// (Pass/Block/Drop) stays in `action` above — Drop vs Block is a real
	// distinction here, and it survives as structured metadata.
	if a := MapUnboundAction(row.Action.String()); a != "" {
		attrs[AttrAction] = a
	}
	setUnboundClient(attrs, snap, row.Client.String())

	return Record{
		Timestamp:  time.Unix(int64(row.Time.Int()), 0).UTC(),
		Body:       string(body),
		Attributes: attrs,
		Severity:   unboundSeverity(row.Action.String()),
	}
}

// setUnboundClient writes the client attributes for one row.
//
// Three cases, and the middle one is the whole point of #660:
//
//   - empty (22 rows in a live 1000-row page) — nothing is set at all, rather than
//     an empty label a consumer would have to filter out by hand.
//   - a name (`camden.rob-knight.net`, `poly-office`, `localhost` — ~97% of rows) —
//     the label only. No reverse-mapping back to an address: measured against our own
//     ARP/lease tables it covered 35% of traffic, missed the single biggest client
//     entirely, and was 4-way ambiguous on the second biggest, so it would produce an
//     authoritative-looking field that is silently wrong (#660 decision comment).
//   - an address — the label AND src.ip, plus hostname/MAC/scope from our own
//     enrichment, exactly like every other lane.
//
// The guarantee: src.ip is a real address or absent. It is never a hostname.
func setUnboundClient(attrs map[string]string, snap *enrich.Snapshot, client string) {
	client = strings.TrimSpace(client)
	if client == "" {
		return
	}
	attrs[unboundClientLabelAttr] = client

	if net.ParseIP(client) == nil {
		return
	}
	attrs["src.ip"] = client
	if snap == nil {
		return
	}
	// A miss is the normal case here (a device that has never held a lease), so it
	// is silent and never signals a stale snapshot — same contract as the syslog
	// lanes' client enrichment.
	if host, ok := snap.Hostname(client); ok {
		attrs["src.hostname"] = host
	}
	if mac, ok := snap.MAC(client); ok {
		attrs["src.mac"] = mac
	}
	if scope := snap.Scope(client); scope != "" {
		attrs["src.scope"] = scope
	}
}

// unboundSeverity flags blocked/dropped queries as warnings so they stand out
// in Loki without any extra query filter; everything else is informational.
func unboundSeverity(action string) Severity {
	switch action {
	case "Block", "Drop":
		return SeverityWarn
	default:
		return SeverityInfo
	}
}
