package syslog

import (
	"strings"

	"github.com/rknightion/opnsense2otel/v4/internal/logship"
	"github.com/rknightion/opnsense2otel/v4/internal/logship/enrich"
)

// filterlog CSV layout. The common header is nine fields, then an IP-version
// specific body, then a protocol tail.
//
//	header (9): rulenr, subrulenr, anchorname, rid, interface, reason, action, dir, ipversion
//	IPv4  (+11): tos, ecn, ttl, id, offset, ipflags, protonum, protoname, length, src, dst
//	IPv6   (+8): class, flow, hoplimit, protoname, protonum, length, src, dst
//
// IPv6 puts protoname BEFORE protonum and IPv4 is the reverse — that inversion
// is the easiest bug in this parser, and TestParseFilterlog_IPv6ICMP_ProtoOrderInversion
// guards it.
//
// The TCP tail has NINE fields: srcport, dstport, datalen, tcpflags, seq, ack,
// window, urg, options. OPNsense's own read_log.py names only eight
// (…,seq,ack,urp,tcpopts), which mislabels the window as the urgent pointer and
// silently drops the options; filterlog's description.txt is the ground truth
// and we follow it.
const (
	fRulenr = iota
	fSubrulenr
	fAnchorname
	fRid
	fInterface
	fReason
	fAction
	fDir
	fIPVersion
	filterlogHeaderLen
)

func init() {
	// filterlog resolves its own positional src/dst addresses, so BuildRecord does
	// not re-scan its body for peer.* addresses.
	RegisterParser(parseFilterlog, "filterlog")
}

// parseFilterlog turns a filterlog CSV payload into an enriched Record. It
// returns ok=false for a row it cannot make sense of (too short, unknown IP
// version) so the caller can fall back to a generic record — a malformed line is
// degraded, never dropped and never a panic. Enrichment is best-effort: a nil or
// cold snapshot yields an unenriched (but complete) record.
func parseFilterlog(env Envelope, snap *enrich.Snapshot, miss func(table string)) (logship.Record, bool) {
	f := strings.Split(env.Message, ",")
	if len(f) < filterlogHeaderLen {
		return logship.Record{}, false
	}

	var (
		protoNum  string
		protoName string
		src, dst  string
		tail      []string
	)
	switch f[fIPVersion] {
	case "4":
		// tos, ecn, ttl, id, offset, ipflags, protonum, protoname, length, src, dst
		const ipv4BodyLen = 11
		if len(f) < filterlogHeaderLen+ipv4BodyLen {
			return logship.Record{}, false
		}
		protoNum = f[filterlogHeaderLen+6]
		protoName = f[filterlogHeaderLen+7]
		src = f[filterlogHeaderLen+9]
		dst = f[filterlogHeaderLen+10]
		tail = f[filterlogHeaderLen+ipv4BodyLen:]
	case "6":
		// class, flow, hoplimit, protoname, protonum, length, src, dst
		const ipv6BodyLen = 8
		if len(f) < filterlogHeaderLen+ipv6BodyLen {
			return logship.Record{}, false
		}
		protoName = f[filterlogHeaderLen+3] // protoname FIRST on IPv6
		protoNum = f[filterlogHeaderLen+4]
		src = f[filterlogHeaderLen+6]
		dst = f[filterlogHeaderLen+7]
		tail = f[filterlogHeaderLen+ipv6BodyLen:]
	default:
		return logship.Record{}, false
	}

	action := f[fAction]
	dir := f[fDir]
	iface := f[fInterface]

	attrs := make(map[string]string, 24)
	set := func(k, v string) {
		if v != "" {
			attrs[k] = v
		}
	}

	set("action", action)
	// The normalised, promotable twin of `action`. set() skips empty values, so an
	// unrecognised verb (a NAT/rdr line — `action` is a raw wire passthrough) leaves
	// the label unset rather than being guessed into a security verdict. The raw
	// `action` above stays put: sample.go and derive.go both read it.
	set(logship.AttrAction, logship.MapFilterlogAction(action))
	set("direction", dir)
	set("interface", iface)
	set("ip.version", f[fIPVersion])
	set("network.type", networkType(f[fIPVersion])) // semconv Stable: ipv4/ipv6 alongside ip.version
	set("protocol", protoName)
	// semconv Stable network.transport, but only for real transports — icmp/carp/etc.
	// are not transports, so `protocol` stays the superset that carries them.
	set("network.transport", networkTransport(protoName))
	set("src.ip", src)
	set("dst.ip", dst)

	// Rule identity. rid=="0" means "no rule id — identify by rulenr/subrulenr"
	// (NAT and floating matches); it is NOT a cache miss, so we neither look it
	// up nor signal a miss.
	rid := f[fRid]
	switch rid {
	case "", "0":
		set("rule.ref", ruleRef(f[fRulenr], f[fSubrulenr]))
	default:
		set("rule.id", rid)
		if descr, ok := ruleLabel(snap, rid); ok {
			set("rule.description", descr)
		} else if miss != nil {
			miss("rules")
		}
	}

	var srcPort, dstPort string
	switch protoNum {
	case "6": // TCP — nine fields
		names := []string{"src.port", "dst.port", "", "tcp.flags", "tcp.seq", "tcp.ack", "tcp.window", "tcp.urg", "tcp.options"}
		for i, name := range names {
			if i >= len(tail) || name == "" {
				continue
			}
			set(name, tail[i])
		}
		srcPort, dstPort = at(tail, 0), at(tail, 1)
	case "17": // UDP — srcport, dstport, datalen
		srcPort, dstPort = at(tail, 0), at(tail, 1)
		set("src.port", srcPort)
		set("dst.port", dstPort)
	case "112": // CARP — type, ttl, vhid, version, advskew, advbase (not modelled as attributes)
	default:
		// ICMP and everything else: filterlog has no field spec, so keep the
		// trailing CSV verbatim rather than inventing labels for it.
		set("icmp_extra", strings.Join(tail, ","))
	}

	// Best-effort enrichment. An unknown IP is normal (every WAN address is
	// unknown), so hostname/MAC/scope lookups NEVER signal a miss — only the
	// rules table does.
	if name, ok := ifaceName(snap, iface); ok {
		set("interface.name", name)
	}
	enrichEndpoint(set, snap, "src", src, srcPort, protoName)
	enrichEndpoint(set, snap, "dst", dst, dstPort, protoName)
	// GeoIP (#528): filterlog is one of the three lanes where a remote peer is the
	// SUBJECT of the line, not an incidental mention -- unlike unbound or DHCP, which
	// never get this. geoAttrs is itself a no-op unless a GeoIP source has been
	// configured (--geoip.enabled plus --logs.syslog.geoip), so this costs nothing on
	// a deployment that has not opted in.
	geoAttrs(set, "src", src)
	geoAttrs(set, "dst", dst)

	sev := logship.SeverityInfo
	if action == "block" {
		sev = logship.SeverityWarn
	}

	return logship.Record{
		Timestamp:  env.Timestamp,
		Body:       renderFilterlogBody(action, dir, attrs["interface.name"], iface, src, dst, srcPort, dstPort, protoName),
		Attributes: attrs,
		Severity:   sev,
	}, true
}

// enrichEndpoint adds the hostname/MAC/scope/service attributes for one side of
// the flow. Every lookup is optional and a miss is silent.
func enrichEndpoint(set func(k, v string), snap *enrich.Snapshot, side, ip, port, proto string) {
	if ip == "" {
		return
	}
	if snap != nil {
		if host, ok := snap.Hostname(ip); ok {
			set(side+".hostname", host)
		}
		if mac, ok := snap.MAC(ip); ok {
			set(side+".mac", mac)
		}
		set(side+".scope", snap.Scope(ip))
	}
	if port != "" {
		if svc, ok := enrich.ServiceName(port, proto); ok {
			set(side+".service", svc)
		}
	}
}

func ruleLabel(snap *enrich.Snapshot, rid string) (string, bool) {
	if snap == nil {
		return "", false
	}
	return snap.RuleLabel(rid)
}

func ifaceName(snap *enrich.Snapshot, dev string) (string, bool) {
	if snap == nil || dev == "" {
		return "", false
	}
	return snap.InterfaceName(dev)
}

// ruleRef renders the rulenr/subrulenr identity used when a line carries no rule
// id (rid=="0"), e.g. "rule #16.115".
func ruleRef(rulenr, subrulenr string) string {
	if rulenr == "" {
		return ""
	}
	if subrulenr == "" {
		return "rule #" + rulenr
	}
	return "rule #" + rulenr + "." + subrulenr
}

// networkType maps a filterlog IP-version field ("4"/"6") to the semconv
// `network.type` value. Empty for anything else, so set() drops it.
func networkType(ipVersion string) string {
	switch ipVersion {
	case "4":
		return "ipv4"
	case "6":
		return "ipv6"
	default:
		return ""
	}
}

// networkTransport maps a protocol name to the semconv `network.transport` value,
// but ONLY for L4 transports. icmp/carp/esp/etc. are not transports and return "",
// so set() drops them (they remain available under our superset `protocol` key).
func networkTransport(proto string) string {
	switch proto {
	case "tcp", "udp":
		return proto
	default:
		return ""
	}
}

func at(s []string, i int) string {
	if i < 0 || i >= len(s) {
		return ""
	}
	return s[i]
}

// renderFilterlogBody produces the human-readable line, e.g.
// "block in on LAN: 10.0.0.6:57920 -> 10.0.0.114:22 (tcp)".
func renderFilterlogBody(action, dir, ifName, ifDev, src, dst, srcPort, dstPort, proto string) string {
	var b strings.Builder
	b.WriteString(action)
	if dir != "" {
		b.WriteString(" " + dir)
	}
	name := ifName
	if name == "" {
		name = ifDev
	}
	if name != "" {
		b.WriteString(" on " + name)
	}
	b.WriteString(": ")
	b.WriteString(endpoint(src, srcPort))
	b.WriteString(" -> ")
	b.WriteString(endpoint(dst, dstPort))
	if proto != "" {
		b.WriteString(" (" + proto + ")")
	}
	return b.String()
}

func endpoint(ip, port string) string {
	if port == "" {
		return ip
	}
	return ip + ":" + port
}
