package webui

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rknightion/opnsense-exporter/opnsense"
)

// init registers the devices page area's routes. See server.go's extension docs
// for the pattern every page area follows.
func init() { registerRoutes((*Server).registerDevices) }

// registerDevices mounts the connected-devices JSON endpoint. Devices are a tab
// on the single console page that loads THIS endpoint lazily on tab-open — never
// on the auto-refresh poll — because the fetch is a live firewall read (ARP/DHCP
// only, never the metric collectors, so it does not trigger a scrape). The read
// is bounded by a route-local short-TTL cache, single-flight and a deadline; see
// devicesCache below for why those bounds are not optional.
func (s *Server) registerDevices(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/devices.json", s.handleDevicesJSON)
}

func (s *Server) handleDevicesJSON(w http.ResponseWriter, r *http.Request) {
	if s.deps.DisableDevices {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, s.devicesReport(r.Context()))
}

// devicesView is the render envelope for the devices page: the report plus an
// error string when the fetch failed (rendered as an inline callout rather than
// a hard error, so a transient API blip doesn't take the page down).
type devicesView struct {
	Report DeviceReport
	Error  string
}

// Bounds on the device fetch. /api/devices.json is the console's only route
// that reaches the firewall, it is unauthenticated in a default deployment
// (--web.config.file auth is opt-in), and one miss costs THREE sequential live
// OPNsense calls on the SAME shared client the poll scheduler uses — which has a
// single process-wide semaphore (--opnsense.max-concurrent-requests, default
// 16). Unbounded, a burst on this one route competes directly with real metric
// polling, so it is capped three ways: a short TTL, single-flight, and a
// deadline.
const (
	// devicesCacheTTL is how long a successful report is served without
	// re-fetching. ARP entries and DHCP leases turn over on the order of minutes,
	// so a few seconds of staleness is invisible on the tab while still absorbing
	// a refresh-mashing operator or a scripted poll.
	//
	// This is deliberately NOT the client's own response cache
	// (opnsense/cache.go): that cache's contract permits only wholly slow-moving
	// GET bodies and explicitly excludes anything carrying live status, which is
	// exactly what ARP/DHCP lease state is. The window here is local to this
	// route and short enough that no metric series can be frozen by it — no
	// collector reads it.
	devicesCacheTTL = 8 * time.Second

	// devicesFetchTimeout caps one upstream fetch. FetchDevices makes three
	// sequential calls, each with the client's own 15s timeout and up to three
	// retries, so an unresponsive firewall could otherwise hold the request — and
	// its slot on the shared client semaphore — for minutes.
	devicesFetchTimeout = 20 * time.Second
)

// devicesCaches holds one devicesCache per Server. It is keyed off the Server
// rather than stored as a Server field so the devices route owns its caching
// policy end to end, and so tests get natural per-Server isolation. There is
// exactly one Server per process, so the map holds one entry in practice.
var devicesCaches sync.Map // *Server -> *devicesCache

func (s *Server) devicesCache() *devicesCache {
	if v, ok := devicesCaches.Load(s); ok {
		return v.(*devicesCache)
	}
	v, _ := devicesCaches.LoadOrStore(s, &devicesCache{ttl: devicesCacheTTL, timeout: devicesFetchTimeout})
	return v.(*devicesCache)
}

// devicesCache is a short-TTL cache of the last SUCCESSFUL device report with
// single-flight on misses. It is local to this route by design (see the const
// block) and holds no reference to the API client.
type devicesCache struct {
	ttl     time.Duration
	timeout time.Duration

	mu       sync.Mutex
	report   devicesView
	at       time.Time
	inflight *devicesFetch
}

// devicesFetch is one in-flight upstream fetch that concurrent misses join.
// view is written before done is closed, so the close/receive pair publishes it.
type devicesFetch struct {
	done chan struct{}
	view devicesView
}

// get returns a cached report when one is fresh, otherwise joins (or starts) the
// single in-flight fetch. The caller's ctx only bounds how long IT waits — the
// fetch itself runs on its own bounded context so one client disconnecting does
// not cancel the result every other waiter is about to receive.
func (c *devicesCache) get(ctx context.Context, fetch func(context.Context) devicesView) devicesView {
	c.mu.Lock()
	if !c.at.IsZero() && time.Since(c.at) < c.ttl {
		v := c.report
		c.mu.Unlock()
		return v
	}
	f := c.inflight
	if f == nil {
		f = &devicesFetch{done: make(chan struct{})}
		c.inflight = f
		go c.run(f, fetch)
	}
	c.mu.Unlock()

	select {
	case <-f.done:
		return f.view
	case <-ctx.Done():
		return devicesView{Error: ctx.Err().Error()}
	}
}

// run performs the one upstream fetch under the route deadline, publishes the
// result to the cache (successes only — caching a failure would pin an error
// callout on the tab for the whole TTL after a transient blip) and then releases
// the waiters. The cache is updated BEFORE done is closed so a request arriving
// at that instant sees the fresh entry rather than starting a second fetch.
func (c *devicesCache) run(f *devicesFetch, fetch func(context.Context) devicesView) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	v := fetch(ctx)

	c.mu.Lock()
	if c.inflight == f {
		c.inflight = nil
	}
	if v.Error == "" {
		c.report, c.at = v, time.Now()
	}
	c.mu.Unlock()

	f.view = v
	close(f.done)
}

// devicesReport serves the report from the route-local cache, collapsing
// concurrent misses into one upstream fetch. Any error is folded into the view
// so the template always renders (empty table + a callout on failure).
func (s *Server) devicesReport(ctx context.Context) devicesView {
	if s.deps.Devices == nil {
		return devicesView{}
	}
	return s.devicesCache().get(ctx, s.fetchDevices)
}

// fetchDevices is the uncached upstream read, wrapped into the view envelope.
func (s *Server) fetchDevices(ctx context.Context) devicesView {
	rep, err := s.deps.Devices(ctx)
	if err != nil {
		return devicesView{Report: rep, Error: err.Error()}
	}
	return devicesView{Report: rep}
}

// FetchDevices reads the ARP table plus the DHCPv4/DHCPv6 leases from the
// firewall and merges them into a single connected-devices report. Each
// FetchArpTable/FetchDHCPv4Leases/FetchDHCPv6Leases call returns a typed
// *opnsense.APICallError; each is guarded inside its own nil-check so a nil
// *APICallError never becomes a non-nil error interface.
func FetchDevices(ctx context.Context, c *opnsense.Client) (DeviceReport, error) {
	cc := c.WithContext(ctx)
	arp, apiErr := cc.FetchArpTable()
	if apiErr != nil {
		return DeviceReport{}, apiErr
	}
	d4, apiErr := cc.FetchDHCPv4Leases()
	if apiErr != nil {
		return DeviceReport{}, apiErr
	}
	d6, apiErr := cc.FetchDHCPv6Leases()
	if apiErr != nil {
		return DeviceReport{}, apiErr
	}
	return DeviceReport{Devices: mergeDevices(arp, d4, d6), Generated: time.Now()}, nil
}

// mergeDevices folds the ARP table and the DHCPv4/DHCPv6 leases into one row
// per device, deduped by IP+MAC. ARP is applied first (it carries the lease
// expiry); a DHCP lease for the same IP+MAC merges in, and a non-empty DHCP
// hostname wins over ARP's. The manufacturer is resolved from the MAC OUI.
// Rows are sorted by IP then MAC for a stable render.
func mergeDevices(arp opnsense.ArpTable, d4 opnsense.DHCPv4Leases, d6 opnsense.DHCPv6Leases) []DeviceRow {
	idx := make(map[string]int)
	var rows []DeviceRow

	key := func(ip, mac string) string {
		return strings.ToUpper(strings.TrimSpace(ip) + "|" + strings.TrimSpace(mac))
	}

	// upsert merges r into an existing row (same IP+MAC) or appends it. fromDHCP
	// marks a DHCP-sourced hostname, which is preferred over an ARP one.
	upsert := func(r DeviceRow, fromDHCP bool) {
		if r.IP == "" && r.MAC == "" {
			return
		}
		k := key(r.IP, r.MAC)
		if i, ok := idx[k]; ok {
			ex := &rows[i]
			if r.Hostname != "" && (fromDHCP || ex.Hostname == "") {
				ex.Hostname = r.Hostname
			}
			if ex.Interface == "" {
				ex.Interface = r.Interface
			}
			if ex.Expiry == "" {
				ex.Expiry = r.Expiry
			}
			if ex.Manufacturer == "" {
				ex.Manufacturer = r.Manufacturer
			}
			return
		}
		idx[k] = len(rows)
		rows = append(rows, r)
	}

	for _, a := range arp.Arp {
		upsert(DeviceRow{
			IP:           a.IP,
			MAC:          a.Mac,
			Hostname:     a.Hostname,
			Interface:    a.IntfDescription,
			Expiry:       formatExpiry(a.Expires),
			Manufacturer: LookupOUI(a.Mac),
			Source:       "arp",
		}, false)
	}

	for _, l := range d4.Leases {
		upsert(DeviceRow{
			IP:           l.Address,
			MAC:          l.MAC,
			Hostname:     l.Hostname,
			Interface:    l.IfDescr,
			Manufacturer: LookupOUI(l.MAC),
			Source:       "dhcp4",
		}, true)
	}

	for _, l := range d6.Leases {
		// DHCPv6 leases carry no hostname (DUID replaces it upstream).
		upsert(DeviceRow{
			IP:           l.Address,
			MAC:          l.MAC,
			Interface:    l.IfDescr,
			Manufacturer: LookupOUI(l.MAC),
			Source:       "dhcp6",
		}, true)
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].IP != rows[j].IP {
			return rows[i].IP < rows[j].IP
		}
		return rows[i].MAC < rows[j].MAC
	})
	return rows
}

// formatExpiry renders an ARP lease-expiry epoch as a UTC RFC3339 timestamp. A
// zero/negative epoch (permanent or unset) renders as an empty string.
func formatExpiry(epoch int) string {
	if epoch <= 0 {
		return ""
	}
	return time.Unix(int64(epoch), 0).UTC().Format(time.RFC3339)
}
