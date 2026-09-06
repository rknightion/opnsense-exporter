package enrich

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rknightion/opnsense2otel/v5/internal/fetchshare"
	"github.com/rknightion/opnsense2otel/v5/internal/geoip"
	"github.com/rknightion/opnsense2otel/v5/opnsense"
)

// Refresh intervals. Rules and leases move on human timescales (an admin edits a
// rule, a laptop takes a lease); interfaces and their addresses almost never do.
const (
	rulesTTL  = 60 * time.Second
	ifacesTTL = 5 * time.Minute
	leasesTTL = 60 * time.Second
	// Tunnel and VPN-instance names change only when an admin edits the config, so
	// this is the slowest table. It is also the cheapest: both endpoints are already
	// fetched by the metrics collectors.
	tunnelsTTL = 10 * time.Minute

	// ifaceOrderTTL is the base rate for re-reading the box's interface
	// enumeration. It changes only when an interface is created or destroyed, so
	// polling it at the metadata rate would be waste — but a wrong enumeration
	// mislabels everything, so the base rate is backed by two triggers (an
	// interface the ordering does not contain, and an unresolvable ifIndex)
	// rather than left to run for a full period on its own.
	ifaceOrderTTL = time.Hour

	// missInterval rate-limits miss-triggered refreshes. Without it, a flood of
	// unknown rids (a rule was just deleted; a scanner is hammering the WAN) would
	// turn every log line into an API call.
	missInterval = 30 * time.Second

	// orderReqInterval rate-limits enumeration re-fetches triggered by an
	// unresolvable ifIndex. That trigger is reachable from the UNAUTHENTICATED
	// NetFlow socket, so without a bound a sender could mint indices and turn
	// each one into an API call against the firewall.
	orderReqInterval = time.Minute

	// warnInterval rate-limits refresh-failure logging, so a firewall that is down
	// does not also flood our own log.
	warnInterval = 5 * time.Minute
)

// Refresher keeps a Cache populated from the OPNsense API. It owns three tables:
//
//	"rules"       filterlog rid -> rule description
//	"interfaces"  device -> name, plus the firewall's own addresses and subnets
//	"leases"      IP -> hostname / MAC (ARP, NDP and every DHCP backend)
//
// Every rebuild is a load->build->store read-modify-write, so all of them
// serialise behind buildMu: the atomic pointer makes the SWAP safe, not the RMW.
// Two refreshers racing without it would silently lose one another's table.
type Refresher struct {
	client *opnsense.Client
	cache  *Cache
	m      *Metrics
	log    *slog.Logger

	// seam is the shared-result store the metrics collectors publish their decoded
	// results to (#571). Eleven of this refresher's inputs are endpoints a collector
	// already polls, and re-fetching them cost 10,872 requests and 21,744 audit lines
	// a day. nil is valid and means every input is fetched, exactly as before.
	//
	// FRESHNESS, stated rather than assumed. An input read from the seam is up to its
	// table's TTL old at the moment the table is rebuilt, so worst-case enrichment
	// staleness rises from one TTL to two (leases: 60s to 120s; typical ~90s rather
	// than ~30s). That is a freshness change within a stated bound, not a data or
	// fidelity loss: these tables map an identifier to a LABEL — rid to rule
	// description, IP to hostname/MAC, UUID to tunnel name — so the cost of a stale
	// entry is a log line carrying the previous label, or none, for one extra cycle.
	// No metric moves, no record is dropped, and NoteMiss remains the correctness
	// backstop for the case that actually matters (an identifier never seen before),
	// unchanged: the rule table it guards is not seam-backed at all, because no
	// collector fetches firewallRuleIDs.
	seam *fetchshare.Store

	now func() time.Time

	// buildMu serialises every load->build->store. Held across the API call, which
	// is fine: refreshes are minutes apart and never on the hot path.
	buildMu sync.Mutex

	// mu guards the miss rate-limiter only. It is a SEPARATE lock from buildMu:
	// NoteMiss runs on the receiver goroutine and must never wait behind an
	// in-flight HTTPS refresh.
	mu       sync.Mutex
	lastMiss time.Time
	lastWarn map[string]time.Time

	missInterval time.Duration
	missCh       chan struct{}

	// orderCh carries "the enumeration may have moved, re-fetch it" from the two
	// places that can notice: an interface appearing that the ordering does not
	// contain, and an ifIndex arriving that the map cannot resolve. Buffered(1)
	// like missCh, so a burst coalesces into one pending refresh.
	orderCh      chan struct{}
	lastOrderReq time.Time

	rulesTTL      time.Duration
	ifacesTTL     time.Duration
	leasesTTL     time.Duration
	tunnelsTTL    time.Duration
	ifaceOrderTTL time.Duration

	refreshRules      func() error
	refreshIfaces     func() error
	refreshLeases     func() error
	refreshTunnels    func() error
	refreshIfaceOrder func() error
}

// WithResultSeam makes the refresher source an input from store when a metrics
// collector has already decoded it recently enough, instead of fetching it again
// (#571). Call before Run. A refresher with no seam fetches everything, as it did
// before the seam existed.
func (r *Refresher) WithResultSeam(store *fetchshare.Store) *Refresher {
	r.seam = store
	return r
}

// NewRefresher wires a Refresher to the API client and the cache it publishes to.
func NewRefresher(c *opnsense.Client, cache *Cache, m *Metrics, log *slog.Logger) *Refresher {
	r := &Refresher{
		client:       c,
		cache:        cache,
		m:            m,
		log:          log,
		now:          time.Now,
		lastWarn:     make(map[string]time.Time),
		missInterval: missInterval,
		missCh:       make(chan struct{}, 1), // buffered(1): misses coalesce
		orderCh:      make(chan struct{}, 1),
		rulesTTL:     rulesTTL,
		ifacesTTL:    ifacesTTL,
		leasesTTL:    leasesTTL,
		tunnelsTTL:   tunnelsTTL,

		ifaceOrderTTL: ifaceOrderTTL,
	}
	r.refreshRules = r.doRefreshRules
	r.refreshIfaces = r.doRefreshIfaces
	r.refreshLeases = r.doRefreshLeases
	r.refreshTunnels = r.doRefreshTunnels
	r.refreshIfaceOrder = r.doRefreshIfaceOrder
	return r
}

// NoteIfIndexUnresolved reports that a NetFlow record named an ifIndex the map
// could not resolve.
//
// That is direct evidence the enumeration moved — an interface was created or
// destroyed and every index above it shifted — so it is worth re-fetching well
// before the hourly tick. It is called from the flow pipeline, so like NoteMiss
// it must never block and never perform I/O: the NetFlow socket is
// UNAUTHENTICATED, and a synchronous API call per unresolvable index would let
// anything that can reach port 2055 drive the firewall's API load.
func (r *Refresher) NoteIfIndexUnresolved() {
	r.mu.Lock()
	now := r.now()
	if !r.lastOrderReq.IsZero() && now.Sub(r.lastOrderReq) < orderReqInterval {
		r.mu.Unlock()
		return
	}
	r.lastOrderReq = now
	r.mu.Unlock()

	select {
	case r.orderCh <- struct{}{}:
	default: // a re-fetch is already pending
	}
}

// noteOrderStale signals a re-fetch without the rate limit, for the callers that
// are already bounded by their own refresh interval.
func (r *Refresher) noteOrderStale() {
	if r.orderCh == nil {
		return
	}
	select {
	case r.orderCh <- struct{}{}:
	default:
	}
}

// NoteMiss reports a lookup miss for table.
//
// It is called ON THE RECEIVER GOROUTINE — the one draining the UDP socket — and
// must therefore NEVER block and NEVER perform I/O: a synchronous API call here
// stops the read loop, the kernel socket buffer overflows and datagrams are lost
// SILENTLY. So: count the miss, rate-limit, then do a non-blocking send on a
// size-1 buffered channel that Run drains. A flood of misses coalesces into a
// single pending refresh, at most one per missInterval.
func (r *Refresher) NoteMiss(table string) {
	r.m.Misses.WithLabelValues(table).Inc()

	r.mu.Lock()
	now := r.now()
	if !r.lastMiss.IsZero() && now.Sub(r.lastMiss) < r.missInterval {
		r.mu.Unlock()
		return
	}
	r.lastMiss = now
	r.mu.Unlock()

	select {
	case r.missCh <- struct{}{}:
	default: // a refresh is already pending; nothing to do
	}
}

// Run refreshes every table once, then keeps them fresh until ctx is cancelled:
// on each table's TTL ticker, and on the miss signal from NoteMiss. It blocks.
func (r *Refresher) Run(ctx context.Context) {
	// The enumeration goes first: the interfaces refresh compares against it to
	// decide whether the device set has outgrown the ordering, and doing that
	// against an empty ordering would signal on every device.
	r.tick("ifaceorder", r.refreshIfaceOrder)
	r.tick("rules", r.refreshRules)
	r.tick("interfaces", r.refreshIfaces)
	r.tick("leases", r.refreshLeases)
	r.tick("tunnels", r.refreshTunnels)

	ifaceOrderT := time.NewTicker(r.ifaceOrderTTL)
	defer ifaceOrderT.Stop()
	rulesT := time.NewTicker(r.rulesTTL)
	defer rulesT.Stop()
	ifacesT := time.NewTicker(r.ifacesTTL)
	defer ifacesT.Stop()
	leasesT := time.NewTicker(r.leasesTTL)
	defer leasesT.Stop()
	tunnelsT := time.NewTicker(r.tunnelsTTL)
	defer tunnelsT.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-rulesT.C:
			r.tick("rules", r.refreshRules)
		case <-ifacesT.C:
			r.tick("interfaces", r.refreshIfaces)
		case <-leasesT.C:
			r.tick("leases", r.refreshLeases)
		case <-tunnelsT.C:
			r.tick("tunnels", r.refreshTunnels)
		case <-ifaceOrderT.C:
			r.tick("ifaceorder", r.refreshIfaceOrder)
		case <-r.orderCh:
			// Something saw evidence the enumeration moved. Only that one table is
			// refreshed: it is the only one a shifted enumeration invalidates, and
			// this path is reachable from an unauthenticated socket.
			r.tick("ifaceorder", r.refreshIfaceOrder)
		case <-r.missCh:
			// A miss means the log named something we have never seen. Any of the
			// three tables could be the stale one, and this is rate-limited to once
			// per missInterval, so refresh them all.
			r.tick("rules", r.refreshRules)
			r.tick("interfaces", r.refreshIfaces)
			r.tick("leases", r.refreshLeases)
		}
	}
}

// tick runs one table rebuild under buildMu. On failure it counts the error,
// warns (rate-limited) and LEAVES THE CACHE UNTOUCHED: stale enrichment beats
// none, and enrichment must never drop a record.
func (r *Refresher) tick(table string, fn func() error) {
	if fn == nil {
		return // table not wired (only reachable in tests); never panic the pipeline
	}
	r.buildMu.Lock()
	defer r.buildMu.Unlock()

	if err := fn(); err != nil {
		r.m.RefreshErrors.WithLabelValues(table).Inc()
		r.warn(table, err)
		return
	}
	r.m.LastRefresh.WithLabelValues(table).Set(float64(r.now().Unix()))
}

// warn logs a refresh failure at most once per warnInterval per table.
func (r *Refresher) warn(table string, err error) {
	if r.log == nil {
		return
	}
	now := r.now()
	last, ok := r.lastWarn[table]
	if ok && now.Sub(last) < warnInterval {
		return
	}
	if r.lastWarn == nil {
		r.lastWarn = make(map[string]time.Time)
	}
	r.lastWarn[table] = now
	r.log.Warn("log enrichment refresh failed; keeping previous snapshot",
		"table", table, "err", err)
}

// update clones the current snapshot, lets mutate replace the one table being
// rebuilt, stamps the table's refresh time and publishes the result. Callers hold
// buildMu (tick does). Snapshots are never mutated after Store, so the tables
// mutate does not touch are shared with the previous snapshot for free.
func (r *Refresher) update(table string, mutate func(s *Snapshot)) {
	next := r.cache.Load().clone()
	mutate(next)
	next.LastRefresh[table] = r.now()
	r.cache.Store(next)
}

// doRefreshRules rebuilds rid -> rule description.
//
// diagnostics/firewall/list_rule_ids is the only endpoint that resolves BOTH
// user-authored rules (dashed UUIDs) and the auto/system rules whose rid is an
// undashed content hash (anti-lockout, default-deny, bogons) — the latter are the
// majority of rids in a real filterlog.
func (r *Refresher) doRefreshRules() error {
	ids, err := r.client.FetchFirewallRuleIDs()
	if err != nil {
		return err
	}
	labels := make(map[string]string, len(ids))
	for _, id := range ids {
		if id.ID == "" {
			continue
		}
		labels[id.ID] = id.Descr
	}
	r.update("rules", func(s *Snapshot) { s.RuleLabels = labels })
	return nil
}

// doRefreshIfaces rebuilds device -> name plus the firewall's own addresses
// (SelfIPs) and configured subnets (LocalNets), which together drive Scope — and
// the ordered Ifaces table internal/flow derives the NetFlow ifIndex map from.
func (r *Refresher) doRefreshIfaces() error {
	// The fast-tier interfaces collector polls this endpoint every 15s, so the seam
	// almost always has one far fresher than this table's 5m TTL (#571).
	ov, err := seamOr(r, fetchshare.KeyInterfacesOverview, r.ifacesTTL, r.client.FetchInterfacesOverview)
	if err != nil {
		return err
	}

	names := make(map[string]string, len(ov.Interfaces))
	selfIPs := make(map[netip.Addr]bool)
	seenNet := make(map[netip.Prefix]bool)
	var localNets []netip.Prefix
	ifaces := make([]IfaceInfo, 0, len(ov.Interfaces))

	for _, iface := range ov.Interfaces {
		if iface.Device != "" && iface.Description != "" {
			names[iface.Device] = iface.Description
		}
		info := IfaceInfo{
			Device:     iface.Device,
			Name:       iface.Description,
			Identifier: iface.Identifier,
			VlanTag:    iface.VlanTag,
			VlanParent: iface.VlanParent,
		}
		for _, cidr := range append(append([]string{}, iface.IPv4...), iface.IPv6...) {
			addr, pfx, perr := parseAddrPrefix(cidr)
			if perr != nil {
				continue
			}
			selfIPs[addr] = true
			info.Addrs = append(info.Addrs, addr)
			// pfx is already masked by parseAddrPrefix, so it is the SUBNET rather than
			// the held address with a length — which matters because Prefix.Contains
			// returns false for an unmasked prefix, and every per-interface subnet test
			// would silently miss. Deduped per interface: two addresses on one subnet
			// (a v4 address and a second alias, or an interface holding both ends of a
			// /31) must not enter the list twice.
			if !containsPrefix(info.Prefixes, pfx) {
				info.Prefixes = append(info.Prefixes, pfx)
			}
			if !seenNet[pfx] {
				seenNet[pfx] = true
				localNets = append(localNets, pfx)
			}
		}
		info.IsWAN = isWANIface(info)
		// EVERY row is appended, including a nameless or address-less one. This is
		// metadata, joined onto IfaceOrder by device NAME — the row's position here
		// means nothing, and reading it as the ifIndex enumeration is the bug this
		// endpoint was retired from (#361): it omits pfsync0, so counting its rows
		// put every index from 10 up one too low.
		ifaces = append(ifaces, info)
	}

	r.update("interfaces", func(s *Snapshot) {
		s.IfaceNames = names
		s.SelfIPs = selfIPs
		s.LocalNets = localNets
		s.Ifaces = ifaces
	})

	// An interface the enumeration does not contain can never be resolved from an
	// ifIndex, so its appearance means the enumeration has moved. Signal a
	// re-fetch rather than wait out the rest of the hour with a stale ordering.
	// Skipped entirely before the first successful enumeration fetch, when every
	// device would look new.
	if snap := r.cache.Load(); len(snap.IfaceOrder) > 0 {
		listed := make(map[string]bool, len(snap.IfaceOrder))
		for _, dev := range snap.IfaceOrder {
			listed[dev] = true
		}
		for _, info := range ifaces {
			if info.Device != "" && !listed[info.Device] {
				r.noteOrderStale()
				break
			}
		}
	}
	return nil
}

// doRefreshIfaceOrder reads the box's interface enumeration — the list NetFlow's
// ifIndex is a 1-based position over — and the index the API states per device,
// which cross-checks it.
//
// The two are deliberately not equal partners. The ordering is authoritative and
// its absence is a hard failure; the stated indices are a guard, and losing them
// must not cost us a good ordering. It must also not silently BLANK the guard,
// because an empty guard reads as "nothing disagrees" when the truth is "nothing
// was checked" — so a failed stated fetch carries the previous values forward.
func (r *Refresher) doRefreshIfaceOrder() error {
	indexes, err := r.client.FetchInterfaceIndexes()
	if err != nil {
		return err
	}

	// The enumeration endpoint is fetched only for its device COUNT. Its key order
	// is attach order and is not usable as the enumeration (#363, #364) — but two
	// independent sources agreeing on how many interfaces exist is a cheap check
	// that neither is missing one, and a missing device shifts every rank above it.
	count := 0
	if devices, cerr := r.client.FetchInterfaceEnumeration(); cerr == nil {
		count = len(devices)
	}

	order, rerr := rankByKernelIndex(indexes, count)
	if rerr != nil {
		return rerr
	}

	// The stated indices stay a SEPARATE, independent cross-check, from a different
	// producer (`ifinfo` via PHP, against netstat via libxo above). Under a dense
	// index space the rank must equal the stated index for every configured device,
	// so a divergence is direct evidence of a gap. They must never become an input
	// to the derivation — that is what makes the comparison meaningful.
	//
	// Losing them must not cost us a good ordering, and must not silently BLANK the
	// guard either: an empty guard reads as "nothing disagrees" when the truth is
	// "nothing was checked". So a failed fetch carries the previous values forward.
	stated := r.cache.Load().IfaceStatedIndex
	if ifaces, ferr := seamOr(r, fetchshare.KeyInterfaces, r.ifaceOrderTTL, r.client.FetchInterfaces); ferr == nil {
		fresh := make(map[string]uint32, len(ifaces.Interfaces))
		for _, iface := range ifaces.Interfaces {
			if iface.Device == "" || iface.Index <= 0 {
				continue
			}
			fresh[iface.Device] = uint32(iface.Index) //nolint:gosec // an interface index is small and positive
		}
		if len(fresh) > 0 {
			stated = fresh
		}
	}

	r.update("ifaceorder", func(s *Snapshot) {
		s.IfaceOrder = order
		s.IfaceStatedIndex = stated
	})
	return nil
}

// isWANIface decides whether an interface faces the internet.
//
// The obvious test — "it holds an address outside every LocalNets prefix" — is
// CIRCULAR: LocalNets is built from these very addresses, so every configured
// address is inside it by construction and the test can never fire. So the
// decision comes from what the API actually states: OPNsense's own config
// identifier, plus whether the interface holds a globally-routable address.
//
//	not a VLAN child, AND
//	Identifier is "wan" or "optN" (never "lan"; never empty/unassigned), AND
//	at least one configured address is globally routable
//
// Known failure modes, both deliberate:
//
//   - FALSE NEGATIVE: a WAN behind ISP CPE double-NAT, holding only an RFC1918
//     address, is not detected. Nothing in the payload distinguishes it from a LAN.
//     (A CGNAT 100.64/10 WAN IS detected — CGNAT is not RFC1918.)
//   - FALSE POSITIVE: a non-VLAN optN interface carrying a routed public subnet
//     (a physical DMZ port) reads as a WAN. Excluding VLAN children removes the
//     common case of that — a tagged DMZ — at the cost of missing the rare
//     VLAN-tagged WAN handoff.
//
// The consumer of this must therefore treat IsWAN as a hint, never as ground
// truth: a wrong interface attribution is worse than an absent one.
func isWANIface(i IfaceInfo) bool {
	if i.IsVLAN() || !isWANIdentifier(i.Identifier) {
		return false
	}
	for _, a := range i.Addrs {
		if isGloballyRoutable(a) {
			return true
		}
	}
	return false
}

// isWANIdentifier reports whether an OPNsense config identifier is one a WAN can
// use. OPNsense assigns "lan", "wan", then "opt1".."optN"; a second WAN is an optN,
// so optN has to be accepted, and "lan" and the empty (unassigned) identifier are
// the only ones that can be ruled out.
func isWANIdentifier(id string) bool {
	id = strings.ToLower(strings.TrimSpace(id))
	if id == "wan" {
		return true
	}
	rest, ok := strings.CutPrefix(id, "opt")
	if !ok || rest == "" {
		return false
	}
	for _, c := range rest {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// isGloballyRoutable reports whether an address could plausibly be reached from
// the internet: not loopback, not link-local, not multicast, not unspecified and
// not RFC1918/ULA private. Carrier-grade NAT space (100.64.0.0/10) is NOT excluded
// — it is what many ISPs hand a WAN, and netip does not classify it as private.
//
// The implementation moved to internal/geoip (#520) so the GeoIP enrichment path and
// this one share a single classifier rather than drifting apart; it could not move
// the other way, because this package imports internal/options and options needs
// geoip. geoip.Enrichable is the geo-side variant and differs ONLY in excluding
// CGNAT, for a reason documented there.
func isGloballyRoutable(a netip.Addr) bool {
	return geoip.IsGloballyRoutable(a)
}

// doRefreshLeases rebuilds IP -> hostname and IP -> MAC from every source the box
// has: the ARP and NDP caches (always present) plus each DHCP backend. A backend
// answering 404 is simply NOT INSTALLED — that is empty data, not an error
// (mirroring FetchACMECertificates). Only a real failure fails the table.
func (r *Refresher) doRefreshLeases() error {
	hostnames := make(map[string]string)
	macs := make(map[string]string)

	// set records a hostname/MAC for ip. Earlier sources win: ARP and NDP are the
	// live L2 truth, a DHCP lease may be stale or handed to a device long gone.
	set := func(ip, hostname, mac string) {
		if ip == "" {
			return
		}
		if hostname != "" {
			if _, ok := hostnames[ip]; !ok {
				hostnames[ip] = hostname
			}
		}
		if mac != "" {
			if _, ok := macs[ip]; !ok {
				macs[ip] = mac
			}
		}
	}

	// Every source below is also polled by a metrics collector on the medium (60s)
	// tier, so each is read from the shared-result seam when one has published
	// recently enough and fetched only when it has not (#571). This is the largest
	// single duplication the 2026-07-31 audit found: six collectors and this
	// refresher were asking the box for the same six lease tables every minute.
	//
	// ARP and NDP are core: a failure there is a real failure.
	arp, arpErr := seamOr(r, fetchshare.KeyArpTable, r.leasesTTL, r.client.FetchArpTable)
	if arpErr != nil {
		return arpErr
	}
	for _, a := range arp.Arp {
		set(a.IP, a.Hostname, a.Mac)
	}

	ndp, ndpErr := seamOr(r, fetchshare.KeyNDPTable, r.leasesTTL, r.client.FetchNDPTable)
	if ndpErr != nil {
		return ndpErr
	}
	for _, n := range ndp.Entries {
		set(n.IP, "", n.Mac)
	}

	kea4, kea4Err := seamOr(r, fetchshare.KeyKeaLeases4, r.leasesTTL, r.client.FetchKeaLeases4)
	if err := skipAbsent(kea4Err); err != nil {
		return err
	}
	for _, l := range kea4.Leases {
		set(l.Address, l.Hostname, l.HWAddr)
	}

	kea6, kea6Err := seamOr(r, fetchshare.KeyKeaLeases6, r.leasesTTL, r.client.FetchKeaLeases6)
	if err := skipAbsent(kea6Err); err != nil {
		return err
	}
	for _, l := range kea6.Leases {
		set(l.Address, l.Hostname, l.HWAddr)
	}

	dnsmasq, dnsmasqErr := seamOr(r, fetchshare.KeyDnsmasqLeases, r.leasesTTL, r.client.FetchDnsmasqLeases)
	if err := skipAbsent(dnsmasqErr); err != nil {
		return err
	}
	for _, l := range dnsmasq.Leases {
		set(l.Address, l.Hostname, l.HWAddr)
	}

	// The legacy ISC backends already fold 404 into "absent" themselves.
	v4, v4Err := seamOr(r, fetchshare.KeyDHCPv4Leases, r.leasesTTL, r.client.FetchDHCPv4Leases)
	if err := skipAbsent(v4Err); err != nil {
		return err
	}
	for _, l := range v4.Leases {
		set(l.Address, l.Hostname, l.MAC)
	}

	v6, v6Err := seamOr(r, fetchshare.KeyDHCPv6Leases, r.leasesTTL, r.client.FetchDHCPv6Leases)
	if err := skipAbsent(v6Err); err != nil {
		return err
	}
	for _, l := range v6.Leases {
		set(l.Address, "", l.MAC)
	}

	r.update("leases", func(s *Snapshot) {
		s.Hostnames = hostnames
		s.MACs = macs
	})
	return nil
}

// skipAbsent folds a 404 — "this plugin is not installed" — into success with
// empty data. It returns an error interface (not *APICallError) so the caller can
// compare it against nil safely.
func skipAbsent(err *opnsense.APICallError) error {
	if err == nil {
		return nil
	}
	if err.StatusCode == http.StatusNotFound {
		return nil
	}
	return err
}

// containsPrefix reports whether prefixes already holds p. A linear scan, because an
// interface holds a handful of addresses at most and a map here would cost more than
// it saves.
func containsPrefix(prefixes []netip.Prefix, p netip.Prefix) bool {
	for _, existing := range prefixes {
		if existing == p {
			return true
		}
	}
	return false
}

// parseAddrPrefix splits an interface CIDR ("10.0.0.114/24") into the address the
// firewall holds and the masked network it sits on ("10.0.0.0/24").
func parseAddrPrefix(cidr string) (netip.Addr, netip.Prefix, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return netip.Addr{}, netip.Prefix{}, err
	}
	return p.Addr().Unmap(), p.Masked(), nil
}

// doRefreshTunnels rebuilds the IPsec-connection and OpenVPN-instance UUID tables.
//
// charon and OpenVPN both log an opaque UUID and nothing else — "<5e891b0c-…|8>
// sending DPD request", "instance-6f86d5cd-….sock". Nobody can read that. Both
// endpoints are ALREADY fetched by the metrics collectors, so resolving the UUID to
// its configured description costs no extra API call.
//
// That last sentence was FALSE from the day it was written until #571: both
// endpoints were indeed already fetched by the collectors, and this function then
// went and fetched them again anyway — 432 duplicate requests a day. The seam is
// what finally makes the claim true. Note the ipsec saving is larger than one
// request per tick: FetchIPsecPhase1 fans out to a phase2 search PER TUNNEL, and a
// seam hit skips the whole fan-out.
//
// Verified against a live OPNsense 26.7 box: the UUID charon logs is exactly the
// `ikeid` that ipsec/sessions/search_phase1 returns alongside `phase1desc`, and the
// UUID in OpenVPN's socket path is exactly the `uuid` from openvpn/instances/search.
//
// A box running neither is the normal case: an empty table is not an error, and a
// failure here must never stop the other tables (each refresher is ticked
// independently and a failure leaves the previous snapshot in place).
func (r *Refresher) doRefreshTunnels() error {
	tunnels := map[string]string{}
	p1, err := seamOr(r, fetchshare.KeyIPsecPhase1, r.tunnelsTTL, r.client.FetchIPsecPhase1)
	if e := skipAbsent(err); e != nil {
		return e
	}
	if err == nil {
		for _, row := range p1.Rows {
			if row.IkeId == "" {
				continue
			}
			// Fall back to the connection's own name when it has no description, so a
			// nameless tunnel still resolves to something rather than nothing.
			desc := row.Phase1desc
			if desc == "" {
				desc = row.Name
			}
			tunnels[row.IkeId] = desc
		}
	}

	instances := map[string]string{}
	ov, verr := seamOr(r, fetchshare.KeyOpenVPNInstances, r.tunnelsTTL, r.client.FetchOpenVPNInstances)
	if e := skipAbsent(verr); e != nil {
		return e
	}
	if verr == nil {
		for _, row := range ov.Rows {
			if row.UUID == "" {
				continue
			}
			instances[row.UUID] = row.Description
		}
	}

	r.update("tunnels", func(s *Snapshot) {
		s.Tunnels = tunnels
		s.VPNInstances = instances
	})
	return nil
}

// rankByKernelIndex turns per-device kernel indexes into the enumeration NetFlow
// positions over: devices sorted by kernel index, ifIndex = 1-based RANK.
//
// RANK, not the index itself. `ifinfo` walks the kernel's ifmib table by row
// number and skips absent rows, so its POSITION is the rank over live indexes,
// and rc.d/netflow counts that position to name the netgraph hook. Rank equals
// index only while the index space is dense; a permanently removed interface
// leaves a gap, past which the two diverge. Keeping the distinction explicit is
// what stops this being "simplified" into using the index directly (#364).
//
// This replaced a heuristic that back-filled devices with no known index into the
// free slots in attach order. It was exact on the box it was built against and
// unsound in general: it assumed only configured interfaces are ever destroyed and
// recreated, and pfsync0 alone disproves that — it churns on pfsync.configure, it
// is absent from every endpoint that carries an index except this one, and it sits
// in the MIDDLE of the index space, so misplacing it shifts everything above.
//
// count is the device count from the enumeration endpoint, used as a cross-check:
// two independent sources must agree on how many interfaces exist, or one of them
// is missing a device and neither can be trusted to order.
func rankByKernelIndex(indexes map[string]uint32, count int) ([]string, error) {
	if len(indexes) == 0 {
		return nil, errors.New("enrich: no interface kernel indexes to rank")
	}
	if count > 0 && len(indexes) != count {
		return nil, fmt.Errorf(
			"enrich: %d devices carry a kernel index but the enumeration lists %d; "+
				"one source is missing a device", len(indexes), count)
	}

	seen := make(map[uint32]string, len(indexes))
	devices := make([]string, 0, len(indexes))
	for device, idx := range indexes {
		if prev, dup := seen[idx]; dup {
			return nil, fmt.Errorf("enrich: %q and %q both hold kernel index %d", prev, device, idx)
		}
		seen[idx] = device
		devices = append(devices, device)
	}
	sort.Slice(devices, func(i, j int) bool { return indexes[devices[i]] < indexes[devices[j]] })
	return devices, nil
}
