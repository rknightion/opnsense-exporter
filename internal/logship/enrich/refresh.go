package enrich

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/rknightion/opnsense-exporter/opnsense"
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

	// missInterval rate-limits miss-triggered refreshes. Without it, a flood of
	// unknown rids (a rule was just deleted; a scanner is hammering the WAN) would
	// turn every log line into an API call.
	missInterval = 30 * time.Second

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

	rulesTTL   time.Duration
	ifacesTTL  time.Duration
	leasesTTL  time.Duration
	tunnelsTTL time.Duration

	refreshRules   func() error
	refreshIfaces  func() error
	refreshLeases  func() error
	refreshTunnels func() error
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
		rulesTTL:     rulesTTL,
		ifacesTTL:    ifacesTTL,
		leasesTTL:    leasesTTL,
		tunnelsTTL:   tunnelsTTL,
	}
	r.refreshRules = r.doRefreshRules
	r.refreshIfaces = r.doRefreshIfaces
	r.refreshLeases = r.doRefreshLeases
	r.refreshTunnels = r.doRefreshTunnels
	return r
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
	r.tick("rules", r.refreshRules)
	r.tick("interfaces", r.refreshIfaces)
	r.tick("leases", r.refreshLeases)
	r.tick("tunnels", r.refreshTunnels)

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
	ov, err := r.client.FetchInterfacesOverview()
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
			if !seenNet[pfx] {
				seenNet[pfx] = true
				localNets = append(localNets, pfx)
			}
		}
		info.IsWAN = isWANIface(info)
		// EVERY row is appended, including a nameless or address-less one: ifIndex is
		// a positional counter over this same enumeration, so skipping a row here
		// would shift every later index by one.
		ifaces = append(ifaces, info)
	}

	r.update("interfaces", func(s *Snapshot) {
		s.IfaceNames = names
		s.SelfIPs = selfIPs
		s.LocalNets = localNets
		s.Ifaces = ifaces
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
func isGloballyRoutable(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() {
		return false
	}
	return !a.IsLoopback() && !a.IsUnspecified() && !a.IsPrivate() &&
		!a.IsLinkLocalUnicast() && !a.IsLinkLocalMulticast() &&
		!a.IsInterfaceLocalMulticast() && !a.IsMulticast()
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

	// ARP and NDP are core: a failure there is a real failure.
	arp, arpErr := r.client.FetchArpTable()
	if arpErr != nil {
		return arpErr
	}
	for _, a := range arp.Arp {
		set(a.IP, a.Hostname, a.Mac)
	}

	ndp, ndpErr := r.client.FetchNDPTable()
	if ndpErr != nil {
		return ndpErr
	}
	for _, n := range ndp.Entries {
		set(n.IP, "", n.Mac)
	}

	kea4, kea4Err := r.client.FetchKeaLeases4()
	if err := skipAbsent(kea4Err); err != nil {
		return err
	}
	for _, l := range kea4.Leases {
		set(l.Address, l.Hostname, l.HWAddr)
	}

	kea6, kea6Err := r.client.FetchKeaLeases6()
	if err := skipAbsent(kea6Err); err != nil {
		return err
	}
	for _, l := range kea6.Leases {
		set(l.Address, l.Hostname, l.HWAddr)
	}

	dnsmasq, dnsmasqErr := r.client.FetchDnsmasqLeases()
	if err := skipAbsent(dnsmasqErr); err != nil {
		return err
	}
	for _, l := range dnsmasq.Leases {
		set(l.Address, l.Hostname, l.HWAddr)
	}

	// The legacy ISC backends already fold 404 into "absent" themselves.
	v4, v4Err := r.client.FetchDHCPv4Leases()
	if err := skipAbsent(v4Err); err != nil {
		return err
	}
	for _, l := range v4.Leases {
		set(l.Address, l.Hostname, l.MAC)
	}

	v6, v6Err := r.client.FetchDHCPv6Leases()
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
// Verified against a live OPNsense 26.7 box: the UUID charon logs is exactly the
// `ikeid` that ipsec/sessions/search_phase1 returns alongside `phase1desc`, and the
// UUID in OpenVPN's socket path is exactly the `uuid` from openvpn/instances/search.
//
// A box running neither is the normal case: an empty table is not an error, and a
// failure here must never stop the other tables (each refresher is ticked
// independently and a failure leaves the previous snapshot in place).
func (r *Refresher) doRefreshTunnels() error {
	tunnels := map[string]string{}
	p1, err := r.client.FetchIPsecPhase1()
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
	ov, verr := r.client.FetchOpenVPNInstances()
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
