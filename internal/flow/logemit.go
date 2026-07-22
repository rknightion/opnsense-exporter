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
