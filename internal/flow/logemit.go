package flow

import (
	"strconv"
	"strings"
)

// LogAttributes renders a flow record as the structured-metadata map shipped on its
// OTLP log record. Everything here is Loki structured metadata, NEVER a label: IPs,
// ports, hostnames, application names, domains and connection ids all live here, where
// they are filterable but cannot become index cardinality — the same rule the rollup
// enforces for metrics (rollup.go) and logmetrics.go enforces for the log lanes.
//
// This lives in package flow, returning a plain map, so the flow record stays the one
// source of truth for its own schema and can be tested without importing logship (which
// imports flow, so flow must not import it back). The flowlog lane wraps this into a
// logship.Record.
//
// Keys are only set when they carry information: an absent key is cheaper than an empty
// value and reads correctly in Loki, which distinguishes "no attribute" from "".
func (r Record) LogAttributes() map[string]string {
	a := make(map[string]string, 24)

	if r.SrcAddr.IsValid() {
		a["src.ip"] = r.SrcAddr.String()
	}
	if r.DstAddr.IsValid() {
		a["dst.ip"] = r.DstAddr.String()
	}
	if r.SrcPort != 0 {
		a["src.port"] = strconv.Itoa(int(r.SrcPort))
	}
	if r.DstPort != 0 {
		a["dst.port"] = strconv.Itoa(int(r.DstPort))
	}
	if t := transportName(r.Proto); t != "other" || r.Proto != 0 {
		a["net.transport"] = t
	}
	a["flow.proto"] = strconv.Itoa(int(r.Proto))
	if r.CommunityID != "" {
		a["flow.community_id"] = r.CommunityID
	}
	if d := r.Direction.String(); d != "unknown" {
		a["flow.direction"] = d
	}
	if lbl := interfaceLabel(r); lbl != "" {
		a["flow.interface"] = lbl
	}
	if r.In.Label() != "" {
		a["flow.in_interface"] = r.In.Label()
	}
	if r.Out.Label() != "" {
		a["flow.out_interface"] = r.Out.Label()
	}
	if r.VLANID != "" {
		a["flow.vlan"] = r.VLANID
	}
	if v := r.Verdict.String(); v != "" {
		a["flow.action"] = v
	}
	// The egress correction is recorded per record, not only as a counter, so a single
	// flow can be shown to have been repaired — the counter says how often, this says
	// which one.
	if r.Out.Corrected {
		a["flow.egress_corrected"] = "true"
	}
	// Same reasoning for the VLAN-child attribution (#465): the interface on this record
	// is one the exporter deduced from the address's subnet, not one ng_netflow reported,
	// and an operator comparing it against a switch port needs to know that.
	if r.Repairs.VLANSubnetAttributed {
		a["flow.vlan_subnet_attributed"] = "true"
	}
	if r.Fragments > 1 {
		a["flow.fragments"] = strconv.Itoa(r.Fragments)
	}

	if r.L7.AppName != "" {
		a["app.name"] = r.L7.AppName
	}
	if r.L7.AppProto != "" {
		a["app.proto"] = r.L7.AppProto
	}
	if r.L7.AppCategory != "" {
		a["app.category"] = r.L7.AppCategory
	}
	if r.L7.DomainCat != "" {
		a["app.domain_category"] = r.L7.DomainCat
	}

	if r.Enrich.SrcHostname != "" {
		a["src.hostname"] = r.Enrich.SrcHostname
	}
	if r.Enrich.DstHostname != "" {
		a["dst.hostname"] = r.Enrich.DstHostname
	}
	if r.Enrich.SrcScope != "" {
		a["src.scope"] = r.Enrich.SrcScope
	}
	if r.Enrich.DstScope != "" {
		a["dst.scope"] = r.Enrich.DstScope
	}
	if r.Enrich.DstService != "" {
		a["dst.service"] = r.Enrich.DstService
	}
	if r.Enrich.DstDomain != "" {
		a["dst.domain"] = r.Enrich.DstDomain
	}

	geoAttrs(a, "src", r.Geo.Src)
	geoAttrs(a, "dst", r.Geo.Dst)

	// Both sources' counters travel together and are NEVER summed (#346 decision 3):
	// they measure at different points and their disagreement is itself the signal.
	if r.NF.Present {
		a["flow.nf.bytes"] = strconv.FormatUint(r.NF.Bytes(), 10)
		a["flow.nf.packets"] = strconv.FormatUint(r.NF.Packets(), 10)
	}
	if r.Zen.Present {
		a["flow.zen.bytes"] = strconv.FormatUint(r.Zen.Bytes(), 10)
		a["flow.zen.packets"] = strconv.FormatUint(r.Zen.Packets(), 10)
	}
	return a
}

// geoAttrs renders one endpoint's geolocation under the given prefix ("src"/"dst").
//
// Everything here is a LOG ATTRIBUTE and must stay one. Per the deployment's Loki
// setup, only RESOURCE attributes are ever promoted to index labels, and country must
// not become one — it is a ~250-value dimension on a stream that already has enough.
// ASN and city are not usefully bounded at all and exist only here.
//
// The two *_source keys are the provenance attributes #520 makes mandatory. They are
// emitted whenever the field they describe is set, including when only one database
// could possibly have answered: a reader must never have to infer which one it was
// from whether Zenarmor happens to be installed.
func geoAttrs(a map[string]string, prefix string, g GeoEndpoint) {
	if g.Empty() {
		return
	}
	if g.Country != "" {
		a[prefix+".geo.country"] = g.Country
		a[prefix+".geo.country_source"] = g.CountrySource
	}
	if g.Continent != "" {
		a[prefix+".geo.continent"] = g.Continent
	}
	if g.City != "" {
		a[prefix+".geo.city"] = g.City
	}
	if g.Region != "" {
		a[prefix+".geo.region"] = g.Region
	}
	if g.City != "" || g.Region != "" {
		a[prefix+".geo.city_source"] = g.CitySource
	}
	if g.ASN != 0 {
		a[prefix+".geo.asn"] = "AS" + strconv.FormatUint(uint64(g.ASN), 10)
	}
	if g.ASOrg != "" {
		a[prefix+".geo.as_org"] = g.ASOrg
	}
	// Zenarmor's country is retained, but only where it actually says something our
	// answer does not. Re-emitting an identical value on every record would be pure
	// per-line cost for no information; a DISAGREEMENT is the interesting case, and
	// the one the disagreement counter is a rate for.
	if g.ZenCountry != "" && g.ZenCountry != g.Country {
		a[prefix+".geo.zen_country"] = g.ZenCountry
	}
}

// LogBody is a compact, human-readable one-line summary of the flow, used as the OTLP
// log body. The structured attributes carry the queryable detail; the body is for a
// human scanning the stream.
func (r Record) LogBody() string {
	var b strings.Builder
	b.WriteString(endpoint(r.SrcAddr.String(), r.SrcPort))
	b.WriteString(" -> ")
	b.WriteString(endpoint(r.DstAddr.String(), r.DstPort))
	b.WriteByte(' ')
	b.WriteString(transportName(r.Proto))
	if r.L7.AppName != "" {
		b.WriteByte(' ')
		b.WriteString(r.L7.AppName)
	}
	if v := r.Verdict.String(); v != "" {
		b.WriteByte(' ')
		b.WriteString(v)
	}
	return b.String()
}

// LogSeverityBlocked reports whether the flow was blocked, so the lane can raise the
// OTLP severity for a dropped flow without this package importing logship's Severity.
func (r Record) LogSeverityBlocked() bool { return r.Verdict == VerdictBlock }

func endpoint(ip string, port uint16) string {
	if port == 0 {
		return ip
	}
	return ip + ":" + strconv.Itoa(int(port))
}
