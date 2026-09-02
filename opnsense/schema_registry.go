package opnsense

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// envelopeDescent registers an endpoint whose Fetch* two-stage-decodes a
// json.RawMessage field, rather than a bare zero value (#459).
//
// A schemaRegistry entry is normally the exact struct a Fetch* method
// unmarshals the wire response into. Several FRR/Tor endpoints instead decode
// {"response": ...} into an envelope whose sole modelled field is
// `Response json.RawMessage` — the client re-unmarshals that raw payload into
// a second, more specific Go type afterwards (to tolerate a `[]`/`null`
// fallback the box sends when the underlying daemon is disabled or
// unreachable). Registering the bare envelope reflects only as far as
// Response: json.RawMessage implements json.Unmarshaler, so walkType stops at
// KindAny and every path beneath "response" — including fields that back real
// exported metrics — is permanently invisible to the live canary, whatever the
// box actually reports (the OSPFv3 case this issue is named for).
//
// envelopeDescent names that second stage explicitly instead: Envelope is the
// outer struct actually unmarshaled off the wire (so its own shape and any
// sibling fields still derive normally), Field is the RawMessage field's JSON
// key (its schema path), and Inner is the zero value of the type its payload
// is unmarshaled into downstream. The derived schema then carries Field's real
// inner paths in place of the single KindAny stop. The two-stage decode in the
// client is completely untouched — this only changes what the schema
// DESCRIBES, exactly as the issue scopes it.
//
// Field is not restricted to a json.RawMessage, nor to a top-level key (#589).
// Any path where the walker stops at KindAny on a CONTAINER is the same bug:
// a custom-unmarshaling map alias (healthCheck's subsystemMap,
// firewallRuleStats' firewallRuleStatMap, ospfoverview's frrOSPFAreaMap) hides
// its element's fields exactly as a RawMessage hides its payload, and a Field
// may be dotted ("bpf-statistics.bpf-entry") to name a nested one.
// TestRegisteredTypesDeclareSecondDecodeStage enumerates every such stop from
// the registry and fails on any that is neither descended here nor ledgered as
// deliberate, so this cannot quietly reopen.
//
// Two shapes compose, and both fall out of the one recursive walk in
// descentShape:
//
//   - Inner may itself be an envelopeDescent — a payload that hides a second
//     stage inside the first. quaggaOspfOverview is `response` (RawMessage) ->
//     frrOSPFOverviewBody, whose own `areas` is a custom-unmarshaling map;
//     monitStatus is three deep (status -> service -> port).
//   - Envelope may itself be an envelopeDescent — SIBLING descents, for an
//     envelope carrying more than one opaque container.
//     unboundQueryStatsTotals has both `top` and `top_blocked`.
//
// Not every opaque container is safe to unwrap, and there are two distinct
// reasons, which must not be conflated:
//
//   - No nameable shape at all. hasyncVersion's `response` is an object, a
//     bare boolean or null depending on HA configuration; quaggaOspfInterface
//     wraps interfaces in `{"interfaces": {...}}` on FRR>=8 but returns the flat
//     map directly on older FRR and only the wrapped shape has ever been
//     confirmed live. These are left as bare envelopes and documented in
//     testdata/schemas/coverage.json rather than guessing a shape.
//   - A nameable shape behind a container whose own JSON TYPE varies —
//     see Heterogeneous.
type envelopeDescent struct {
	Envelope any
	Field    string
	Inner    any

	// Heterogeneous keeps Field's OWN kind at KindAny while still describing
	// and verifying everything beneath it.
	//
	// Some containers are not one JSON type. haproxyCounters is an array whose
	// complete rows are objects but whose incomplete CSV lines survive as raw
	// arrays (queryStats.php only array_combine()s an entry when
	// `count($a) > 1`, so the trailing blank socket line arrives as `[null]`);
	// monitStatus' `status` is the parsed XML object when monit answers and a
	// plain error STRING when it does not; its `service` is an array for 2+
	// checks and a bare object for exactly one (the SimpleXML repeated-child
	// quirk). Pinning a kind on any of those manufactures a permanent Mismatch
	// the box can never clear — the opposite of what the canary is for.
	//
	// Leaving the container KindAny costs exactly one thing: `opaque()` in
	// schema_validate.go stops the reverse unknown-key walk there, so new
	// upstream fields beneath it are not reported as opportunities. It costs
	// NOTHING on the drift side — evaluateFieldPath resolves each described
	// child path independently of its parent's kind, so every consumed field
	// beneath is still type-checked, and a shape the schema does not match
	// simply reports Unverified instead of a false Mismatch. That trade is why
	// this is preferable to leaving the whole subtree undescribed.
	Heterogeneous bool
}

// prefixSchemaPath re-anchors a schema path derived relative to Inner's own
// root (e.g. "areas.*.numberOfAreaScopedLsa", or "[]" for a slice Inner) under
// envelopeDescent.Field, matching schema.go's joinPath convention: "[]"
// attaches directly ("response[]"), a map/struct segment joins with a dot
// ("response.areas").
func prefixSchemaPath(field, path string) string {
	if path == "" {
		return field
	}
	if strings.HasPrefix(path, "[]") {
		return field + path
	}
	return field + "." + path
}

// descentElement wraps a descent Inner that describes ONE ELEMENT of a JSON
// array rather than the whole payload. Go cannot express "slice of
// envelopeDescent-of-T" as a value, so an array whose element type itself hides
// a further decode stage needs this marker: monitStatus' `service` is a list of
// checks, and each check's `port` is another SimpleXML array-or-object. Without
// it the only expressible shapes are "array of a plain Go type" (Inner []T) and
// "one descended object", neither of which fits.
//
// descentShape re-anchors the element's whole shape under "[]", exactly as
// walkType does for a real slice.
type descentElement struct{ Elem any }

// descentShape resolves a descent target to its top-level kind and its field
// paths RELATIVE to its own root. A plain value reflects directly; an
// envelopeDescent merges its Envelope's shape with its Inner's, re-anchored
// under Field. Both sides recurse, which is what makes nested descents
// (Inner is a descent) and sibling descents (Envelope is a descent) work
// without a second mechanism.
func descentShape(target any) (FieldKind, []SchemaField) {
	if de, ok := target.(descentElement); ok {
		elemKind, elemFields := descentShape(de.Elem)
		out := make([]SchemaField, 0, len(elemFields)+1)
		out = append(out, SchemaField{Path: "[]", Kind: elemKind})
		for _, f := range elemFields {
			out = append(out, SchemaField{Path: prefixSchemaPath("[]", f.Path), Kind: f.Kind})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
		return KindArray, out
	}

	ed, ok := target.(envelopeDescent)
	if !ok {
		return schemaForType(reflect.TypeOf(target))
	}

	envKind, envFields := descentShape(ed.Envelope)
	innerKind, innerFields := descentShape(ed.Inner)

	fieldMap := make(map[string]FieldKind, len(envFields)+len(innerFields)+1)
	for _, f := range envFields {
		if f.Path == ed.Field {
			continue // replaced below by the descended shape
		}
		fieldMap[f.Path] = f.Kind
	}
	if ed.Heterogeneous {
		// The container's own JSON type varies with box state; only what is
		// beneath it is stable. See the Heterogeneous doc comment.
		fieldMap[ed.Field] = KindAny
	} else {
		fieldMap[ed.Field] = innerKind
	}
	for _, f := range innerFields {
		fieldMap[prefixSchemaPath(ed.Field, f.Path)] = f.Kind
	}

	fields := make([]SchemaField, 0, len(fieldMap))
	for p, k := range fieldMap {
		fields = append(fields, SchemaField{Path: p, Kind: k})
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].Path < fields[j].Path })
	return envKind, fields
}

// rootEnvelopeType is the reflect.Type of the outermost real Go value behind a
// registry entry, unwrapping any number of sibling descents. It exists only for
// the "is the top level a struct?" test below.
func rootEnvelopeType(target any) reflect.Type {
	for {
		switch v := target.(type) {
		case envelopeDescent:
			target = v.Envelope
		case descentElement:
			// Unreachable via the only caller (a descentElement root derives
			// KindArray, which fails the KindObject guard before this is
			// consulted), but unwrapped anyway so the answer is never the
			// marker struct's own reflect.Type.
			target = v.Elem
		default:
			return derefType(reflect.TypeOf(target))
		}
	}
}

// derefType strips pointer indirection, matching walkType.
func derefType(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

// envelopeDescentSchemaFor derives the schema for an envelopeDescent registry
// entry: the envelope's own top-level shape (Method/Path/TopLevelKind/
// KnownTopLevelKeys come from it unchanged), with each descended Field's
// KindAny stop replaced by the shape beneath it, re-anchored under that Field.
func envelopeDescentSchemaFor(name EndpointName, ed envelopeDescent) (EndpointSchema, error) {
	ec, ok := ContractManifest()[name]
	if !ok {
		return EndpointSchema{}, fmt.Errorf("endpoint %q is not in the client manifest", name)
	}

	kind, fields := descentShape(ed)

	s := EndpointSchema{
		Endpoint:     string(name),
		Method:       ec.Method,
		Path:         string(ec.Path),
		TopLevelKind: kind,
		Fields:       fields,
	}
	// Mirrors endpointSchemaFor: only a struct top level has a fixed key set
	// worth checking. A descended Field contributes a top-level key exactly
	// when the field itself is one (a dotted or "[]" Field names something
	// deeper, and everything re-anchored beneath a Field always carries a "."
	// or "[" so it can never be mistaken for one).
	if kind == KindObject && rootEnvelopeType(ed).Kind() == reflect.Struct {
		for _, f := range fields {
			if !strings.ContainsAny(f.Path, ".*[") {
				s.KnownTopLevelKeys = append(s.KnownTopLevelKeys, f.Path)
			}
		}
		sort.Strings(s.KnownTopLevelKeys)
	}
	return s, nil
}

// schemaRegistry maps every manifest endpoint to a zero value of the struct
// its Fetch* call site decodes the response into — or, for an endpoint whose
// Fetch* two-stage-decodes a json.RawMessage field, an envelopeDescent naming
// both stages (#459). The schema walker (schema.go) reflects over these to
// derive the structure-only golden schemas in testdata/schemas/.
// TestSchemaRegistryComplete pins this map to defaultEndpoints(), so adding an
// endpoint without a registry entry (or an explicit exemption) fails CI.
var schemaRegistry = map[EndpointName]any{
	"acmeCertificates":     acmeCertificateSearchResponse{},
	"aliasTableSize":       aliasTableSizeResponse{},
	"apcupsdServiceStatus": serviceStatusResponse{},
	"apcupsdUpsStatus":     apcupsdUpsStatusResponse{},
	"arp":                  arpSearchResponse{},
	"authAPIKeys":          authAPIKeySearchResponse{},
	"authGroups":           authGroupSearchResponse{},
	"authUsers":            authUserSearchResponse{},
	"backupHistory":        configBackupResponse{},
	"backupDiff":           configBackupDiffResponse{},
	// bpf-entry is a json.RawMessage because decodeBPFEntries also accepts a
	// bare object, but the array is the only shape the wire can actually take:
	// configd's `interface show bpf` is `netstat -B --libxo json`, and FreeBSD's
	// usr.bin/netstat/bpf.c emits the entries with xo_open_list("bpf-entry") +
	// xo_open_instance, which libxo renders as a JSON array for one instance as
	// much as for ten. So this is a plain descent, not a Heterogeneous one — the
	// single-object branch in the client is defensive, not a live shape (#589).
	"bpfStatistics": envelopeDescent{
		Envelope: bpfStatisticsResponse{},
		Field:    "bpf-statistics.bpf-entry",
		Inner:    []bpfEntry{},
	},
	"caCertificates":             caSearchResponse{},
	"captivePortalServiceStatus": serviceStatusResponse{},
	"captivePortalSessions":      captivePortalSessionSearch{},
	"captivePortalZones":         captivePortalZoneMap{},
	"carpStatus":                 carpStatusResponse{},
	"certificates":               certificateSearchResponse{},
	"chronyServiceStatus":        serviceStatusResponse{},
	"chronySources":              chronyResponseEnvelope{},
	"chronySourceStats":          chronyResponseEnvelope{},
	"chronyTracking":             chronyResponseEnvelope{},
	"clamavVersion":              clamavVersionResponse{},
	"cpuType":                    []string{},
	"cronJobs":                   cronSearchResponse{},
	// All ten CrowdSec bootgrid searches share crowdsecSearchEnvelope, whose
	// `rows` is a json.RawMessage the client re-unmarshals into a DIFFERENT row
	// type per endpoint — so the envelope is shared but the descent is not, and
	// registering the bare envelope hid every consumed row field on all ten
	// (#589). `rows` is always a JSON array: searchRecordsetBase slices a PHP
	// list, so an empty result is `[]` and the children just go Unverified.
	"crowdsecAlerts": envelopeDescent{
		Envelope: crowdsecSearchEnvelope{},
		Field:    "rows",
		Inner:    []crowdsecAlertRow{},
	},
	"crowdsecBouncers": envelopeDescent{
		Envelope: crowdsecSearchEnvelope{},
		Field:    "rows",
		Inner:    []crowdsecBouncerRow{},
	},
	"crowdsecDecisions": envelopeDescent{
		Envelope: crowdsecSearchEnvelope{},
		Field:    "rows",
		Inner:    []crowdsecDecisionRow{},
	},
	"crowdsecMachines": envelopeDescent{
		Envelope: crowdsecSearchEnvelope{},
		Field:    "rows",
		Inner:    []crowdsecMachineRow{},
	},
	"crowdsecServiceStatus": serviceStatusResponse{},
	"dechwPowerStatus":      dechwPowerStatusResponse{},
	// The six hub-component searches are byte-identical upstream — every
	// controller builds name/status/local_version/local_path/description — so
	// they all descend into the same row type.
	"crowdsecCollections": envelopeDescent{
		Envelope: crowdsecSearchEnvelope{},
		Field:    "rows",
		Inner:    []crowdsecHubItemRow{},
	},
	"crowdsecScenarios": envelopeDescent{
		Envelope: crowdsecSearchEnvelope{},
		Field:    "rows",
		Inner:    []crowdsecHubItemRow{},
	},
	"crowdsecParsers": envelopeDescent{
		Envelope: crowdsecSearchEnvelope{},
		Field:    "rows",
		Inner:    []crowdsecHubItemRow{},
	},
	"crowdsecPostoverflows": envelopeDescent{
		Envelope: crowdsecSearchEnvelope{},
		Field:    "rows",
		Inner:    []crowdsecHubItemRow{},
	},
	"crowdsecAppsecConfigs": envelopeDescent{
		Envelope: crowdsecSearchEnvelope{},
		Field:    "rows",
		Inner:    []crowdsecHubItemRow{},
	},
	"crowdsecAppsecRules": envelopeDescent{
		Envelope: crowdsecSearchEnvelope{},
		Field:    "rows",
		Inner:    []crowdsecHubItemRow{},
	},
	"dhcpv4":               dhcpv4LeaseResponse{},
	"dhcpv6Leases":         dhcpv6LeaseResponse{},
	"dhcpv6Prefixes":       dhcpv6PrefixResponse{},
	"dmidecodeInfo":        dmidecodeServiceGetResponse{},
	"dnsmasqLeases":        dnsmasqLeaseResponse{},
	"dnsmasqRanges":        dnsmasqRangeResponse{},
	"dnsmasqServiceStatus": serviceStatusResponse{},
	"dyndnsAccounts":       dyndnsAccountSearchResponse{},
	"dyndnsServiceStatus":  serviceStatusResponse{},
	"firewallRuleIDs":      firewallRuleIDsResponse{},
	"firewallRules":        firewallRuleSearchResponse{},
	// `stats` is firewallRuleStatMap, a custom-unmarshaling map — the walker
	// stops on it exactly as it stops on a json.RawMessage, so the five counters
	// behind every rule UUID were invisible (#589). Pinning it to object is safe
	// because the only non-object shape upstream can produce is the EMPTY array
	// (a PHP assoc array with nothing in it), which the validator already reads
	// as "empty, not drift"; firewallRuleStatMap rejects a populated array
	// outright for the same reason.
	"firewallRuleStats": envelopeDescent{
		Envelope: firewallRuleStatsResponse{},
		Field:    "stats",
		Inner:    map[string]firewallRuleStat{},
	},
	"firewallStats":  []firewallStatEntry{},
	"firmware":       firmwareStatusResponse{},
	"firmwareInfo":   firmwareInfoResponse{},
	"gatewaysStatus": gatewayConfigurationResponse{},
	// The counters payload is a heterogeneous array by construction, so the
	// element kind stays KindAny while the 38 consumed CSV columns beneath it
	// are described and checked (#589). queryStats.php's showStat() only
	// array_combine()s a line into an object when `count($a) > 1`, so the blank
	// trailing line the admin socket always emits survives as a raw PHP list and
	// json_encodes to a nested ARRAY alongside the object rows — which is why
	// haproxy.go skips undecodable elements rather than erroring. Pinning "[]"
	// to object would report that filler element as drift on every single run.
	"haproxyCounters": envelopeDescent{
		Envelope:      []json.RawMessage{},
		Field:         "[]",
		Inner:         haproxyStatRow{},
		Heterogeneous: true,
	},
	"haproxyInfo":          map[string]flexString{},
	"haproxyServiceStatus": serviceStatusResponse{},
	"hasyncServices":       hasyncServicesBootgrid{},
	// hasyncVersion is deliberately NOT registered as an envelopeDescent (#459):
	// its Response field is genuinely polymorphic on the wire — an object when
	// HA is configured and the peer answers, but a bare JSON boolean (`false`)
	// on the overwhelming majority of installs (single-node, HA unconfigured)
	// and JSON null on some error paths (see hasyncVersionResponse's doc
	// comment). Reflecting through it as an object would misdescribe the common
	// case, not just widen an unverified path; see the coverage.json note on
	// this endpoint.
	"hasyncVersion": hasyncVersionResponse{},
	// The TOP-LEVEL `subsystems` map — NOT `metadata.subsystems`, which upstream
	// initialises to [] and never assigns (re-verified against
	// SystemController::statusAction on master while doing #589; see the #284
	// note on HealthCheckResponse). subsystemMap's custom UnmarshalJSON stopped
	// the walker, hiding message/status/statusCode, all three of which
	// SystemStatus::collectStatus() always emits. The array-tolerant shape is
	// the EMPTY-array quirk, which the validator reads as "empty, not drift".
	"healthCheck": envelopeDescent{
		Envelope: HealthCheckResponse{},
		Field:    "subsystems",
		Inner:    map[string]HealthCheckSubsystem{},
	},
	"hostdiscoverySearch":     hostDiscoverySearchResponse{},
	"idsStatus":               serviceStatusResponse{},
	"idsAlertLogs":            []idsAlertLogEntry{},
	"idsQueryAlerts":          idsAlertsResponse{},
	"idsSettings":             idsSettingsResponse{},
	"idsRulesets":             idsRulesetsResponse{},
	"idsSearchInstalledRules": idsInstalledRulesResponse{},
	"interfaces":              interfaceResponse{},
	"interfaceConfig":         interfaceConfigResponse{},
	"interfaceStatistics":     interfaceStatisticsResponse{},
	"interfacesOverview":      interfacesOverviewResponse{},
	"lldpdNeighbors":          lldpdNeighborResponse{},
	"ipsecPhase1":             ipsecSearchResponse{},
	"ipsecPhase2":             ipsecPhase2SearchResponse{},
	// `pools` is object-or-EMPTY-array and nothing else: poolsAction returns
	// `['pools' => []]` when the script found nothing, otherwise list_leases.py's
	// dict keyed by pool name (name/net/online/offline/size — exactly what
	// ipsecPoolRow models). The empty-array form is already read as "empty, not
	// drift", so pinning it to object is safe (#589).
	"ipsecPools": envelopeDescent{
		Envelope: ipsecPoolsResponse{},
		Field:    "pools",
		Inner:    map[string]ipsecPoolRow{},
	},
	"ipsecSad":           ipsecSadResponse{},
	"ipsecSpd":           ipsecSpdResponse{},
	"ipsecLegacyStatus":  ipsecLegacyStatusResponse{},
	"ipsecServiceStatus": serviceStatusResponse{},
	"keaLeases4":         keaLeaseResponse{},
	"keaLeases6":         keaLeaseResponse{},
	"keaPdPools6":        keaPdPoolResponse{},
	"keaServiceStatus":   serviceStatusResponse{},
	"keaSubnets4":        keaSubnetResponse{},
	"keaSubnets6":        keaSubnetResponse{},
	"memoryStatistics":   mbufResponse{},
	"monitServiceStatus": serviceStatusResponse{},
	// Three nested descents, all Heterogeneous, because every hop changes JSON
	// type with box state rather than with release (#589):
	//
	//   status  — the parsed XML object when result=="ok", a plain error STRING
	//             when monit is stopped or its httpd is unreachable.
	//   service — an array for 2+ checks, a bare object for exactly one, absent
	//             for none (the SimpleXML repeated-child quirk decodeXMLNodes
	//             exists for).
	//   port    — same quirk again, per host check.
	//
	// Describing the array form and leaving the containers KindAny means a
	// multi-check box (the normal case, and the only one where the ~20 consumed
	// fields exist to drift) is fully verified, while a single-check or
	// monit-stopped box reports those paths Unverified instead of a Mismatch it
	// could never clear. That is the whole reason this is not simply left opaque
	// like hasyncVersion: here there IS one nameable shape, it just is not the
	// only one the container takes.
	"monitStatus": envelopeDescent{
		Envelope:      monitStatusEnvelope{},
		Field:         "status",
		Heterogeneous: true,
		Inner: envelopeDescent{
			Envelope:      monitStatusBody{},
			Field:         "service",
			Heterogeneous: true,
			Inner: descentElement{Elem: envelopeDescent{
				Envelope:      monitServiceXML{},
				Field:         "port",
				Heterogeneous: true,
				Inner:         descentElement{Elem: monitPortXML{}},
			}},
		},
	},
	"ndpTable":             []ndpEntry{},
	"netbirdServiceStatus": serviceStatusResponse{},
	"netbirdStatus":        netbirdStatusObject{},
	// The plain map, not the tolerant netflowCacheEntryMap the client actually
	// decodes into (#499): the tolerant alias carries a custom UnmarshalJSON, so
	// walkType would stop at KindAny and every consumed field (*.Pkts, *.if,
	// *.SrcIPaddresses, *.DstIPaddresses) would go permanently invisible to the
	// live canary. The two have the same underlying type, so this describes the
	// populated shape exactly; the empty-cache "[]" form is handled by the
	// validator's PHP-empty-object rule rather than by widening the schema.
	"netflowCacheStats":       map[string]netflowCacheEntry{},
	"netflowGetConfig":        netflowGetConfigResponse{},
	"netflowIsEnabled":        netflowIsEnabledResponse{},
	"netflowStatus":           netflowStatusResponse{},
	"netisrStatistics":        netisrResponse{},
	"nginxServiceStatus":      serviceStatusResponse{},
	"nginxVts":                nginxVtsResponse{},
	"ntpStatus":               ntpStatusResponse{},
	"nutServiceStatus":        serviceStatusResponse{},
	"nutUpsStatus":            nutUpsStatusResponse{},
	"openVPNInstances":        openVPNSearchResponse{},
	"openVPNSessions":         openVPNSearchSessionsResponse{},
	"firewallStates":          firewallStatesResponse{},
	"pfStates":                pfStatesResponse{},
	"pfStatisticsByInterface": firewallPFStatsResponse{},
	"pfStatsInfo":             pfStatsInfoResponse{},
	"pfStatsMemory":           pfStatsMemoryResponse{},
	"pfStatsTimeouts":         pfStatsTimeoutsResponse{},
	"pfsyncNodes":             pfsyncNodesResponse{},
	"protocolStatistics":      protocolStatisticsResponse{},
	"qfeedsStats":             qfeedsStatsResponse{},
	"quaggaBfdCounters": envelopeDescent{
		Envelope: frrBFDCountersEnvelope{},
		Field:    "response",
		Inner:    map[string]frrBFDCounterEntry{},
	},
	"quaggaBfdNeighbors": envelopeDescent{
		Envelope: frrBFDNeighborsEnvelope{},
		Field:    "response",
		Inner:    map[string]frrBFDNeighborEntry{},
	},
	"quaggaBgpSummary": envelopeDescent{
		Envelope: frrBGPSummaryEnvelope{},
		Field:    "response",
		Inner:    frrBGPSummaryResponseBody{},
	},
	"quaggaOspfNeighbors": frrOSPFNeighborSearch{},
	// Two stages, not one (#589): #459 descended `response`, but the body's own
	// `areas` is frrOSPFAreaMap, a custom-unmarshaling map, so the walker stopped
	// again one level down and the four per-area counters backing
	// opnsense_frr_ospf_area_* stayed invisible. The map is object-or-EMPTY-array
	// (the PHP quirk frrOSPFAreaMap absorbs), so pinning it to object is safe.
	"quaggaOspfOverview": envelopeDescent{
		Envelope: frrOSPFOverviewEnvelope{},
		Field:    "response",
		Inner: envelopeDescent{
			Envelope: frrOSPFOverviewBody{},
			Field:    "areas",
			Inner:    map[string]frrOSPFAreaData{},
		},
	},
	"quaggaServiceStatus":           serviceStatusResponse{},
	"routingTable":                  []routeEntry{},
	"services":                      servicesSearchResponse{},
	"smartInfo":                     smartInfoResponse{},
	"smartList":                     smartListResponse{},
	"snapshotsIsSupported":          snapshotsSupportedResponse{},
	"snapshotsSearch":               bootEnvironmentSearchResponse{},
	"captivePortalVoucherProviders": []string{},
	"captivePortalVoucherGroups":    []string{},
	"captivePortalVouchers":         []captivePortalVoucherRow{},
	"relaydStatusSum":               relaydStatusSumResponse{},
	"haproxyTables":                 []haproxyTableRow{},
	"ntpGPS":                        ntpGPSResponse{},
	"siproxdRegistrations":          siproxdRegistrationsResponse{},
	"nginxBans":                     nginxBanSearchResponse{},
	"firewallGeoIP":                 geoIPAliasResponse{},
	"natSourceNATRules":             natSearchRuleResponse{},
	"natOneToOneRules":              natSearchRuleResponse{},
	"natNPTRules":                   natSearchRuleResponse{},
	"natDNATRules":                  natSearchRuleResponseDNAT{},
	"quaggaBgpNeighbors": envelopeDescent{
		Envelope: frrBGPNeighborsEnvelope{},
		Field:    "response",
		Inner:    map[string]frrBGPNeighborEntry{},
	},
	"quaggaGeneralRoute4": frrGeneralRouteSearch{},
	"quaggaGeneralRoute6": frrGeneralRouteSearch{},
	"quaggaOspfDatabase": envelopeDescent{
		Envelope: frrOSPFDatabaseEnvelope{},
		Field:    "response",
		Inner:    frrOSPFDatabaseBody{},
	},
	// quaggaOspfInterface is deliberately NOT unwrapped (#459): FRR>=8 wraps
	// per-interface data in {"interfaces": {...}}, but older FRR returns the
	// flat per-interface map directly at the top level (frr.go's
	// FetchFRROSPFInterfaces decodes both), and only the wrapped shape has ever
	// been confirmed live. Picking either shape as canonical would either
	// misdescribe the other or invent an untested claim; see the coverage.json
	// note on this endpoint for the accepted-blind-spot reasoning and the prune
	// trigger.
	"quaggaOspfInterface":  frrOSPFInterfaceEnvelope{},
	"quaggaOspfRoute":      frrOSPFRouteSearch{},
	"quaggaOspfv3Database": frrOSPFv3DatabaseSearch{},
	"quaggaOspfv3Interface": envelopeDescent{
		Envelope: frrOSPFv3InterfaceEnvelope{},
		Field:    "response",
		Inner:    map[string]frrOSPFv3InterfaceEntry{},
	},
	"quaggaOspfv3Overview": envelopeDescent{
		Envelope: frrOSPFv3OverviewEnvelope{},
		Field:    "response",
		Inner:    frrOSPFv3OverviewBody{},
	},
	"quaggaOspfv3Route": frrOSPFv3RouteSearch{},
	"socketStatistics": struct {
		Statistics map[string]json.RawMessage `json:"statistics"`
	}{},
	"syslogStats":            syslogStatsResponse{},
	"syslogServiceStatus":    serviceStatusResponse{},
	"systemActivity":         activityResponse{},
	"systemDisk":             systemDiskResponse{},
	"systemInformation":      systemInformationResponse{},
	"systemMbuf":             mbufResponse{},
	"systemMemory":           systemMemoryResponse{},
	"systemResources":        systemResourcesResponse{},
	"systemSwap":             systemSwapResponse{},
	"systemTemperature":      []temperatureReading{},
	"systemTime":             systemTimeResponse{},
	"tailscaleServiceStatus": serviceStatusResponse{},
	"tailscaleStatus":        tailscaleStatusResponse{},
	"torCircuits": envelopeDescent{
		Envelope: torCircuitsEnvelope{},
		Field:    "response",
		Inner:    map[string]torCircuitRaw{},
	},
	"torStreams": envelopeDescent{
		Envelope: torStreamsEnvelope{},
		Field:    "response",
		Inner:    []torStreamRaw{},
	},
	"torHiddenServices":       torHiddenServicesResponse{},
	"trafficShaperStatistics": trafficShaperStatsResponse{},
	// The plain map, not the array-tolerant unboundPoliciesResponse the client
	// decodes into — same treatment as netflowCacheStats below, and for the same
	// reason: the alias's custom UnmarshalJSON stops the walker, hiding the
	// per-policy `enabled` flag. The two have the same underlying type, so this
	// describes the populated shape exactly, and the empty-"[]" form is handled
	// by the validator's PHP-empty-object rule (#589).
	"unboundBlocklistPolicies": map[string]unboundPolicyEntry{},
	"unboundDNSStatus":         unboundDNSStatusResponse{},
	"unboundInfra":             unboundInfraResponse{},
	"unboundServiceStatus":     serviceStatusResponse{},
	"unboundQueryStatsEnabled": unboundIsEnabledResponse{},
	// Two SIBLING descents in one envelope (#589): `top` and `top_blocked` are
	// both unboundTopDomains, a custom-unmarshaling map that hid each entry's
	// `total`. Nesting the envelope inside a second descent is how sibling
	// containers are expressed — see the envelopeDescent doc comment. Both are
	// object-or-empty-array, so pinning them to object is safe, and the map keys
	// (domain names) normalise to "*" so no identity can reach the golden.
	"unboundQueryStatsTotals": envelopeDescent{
		Envelope: envelopeDescent{
			Envelope: unboundOverviewTotalsResponse{},
			Field:    "top",
			Inner:    map[string]unboundTopDomainEntry{},
		},
		Field: "top_blocked",
		Inner: map[string]unboundTopDomainEntry{},
	},
	"unboundLocalZones":      unboundLocalZonesResponse{},
	"unboundLocalData":       unboundLocalDataResponse{},
	"unboundInsecureDomains": unboundInsecureDomainsResponse{},
	"unboundSearchQueries":   unboundSearchQueriesResponse{},
	"vnstatInterfaceList":    vnstatInterfaceListResponse{},
	"vnstatGetJsonData":      vnstatJSONResponse{},
	"wireguardClients":       wireguardClientsResponse{},
	"wireguardServiceStatus": serviceStatusResponse{},
}

// schemaExemptEndpoints lists endpoints that deliberately have no schema, with
// the reason why.
var schemaExemptEndpoints = map[EndpointName]string{
	// version/get passes cscli's raw multi-line text output straight through —
	// it is not JSON at all, so no structural schema applies. FetchCrowdSecStatus
	// parses it tolerantly (parseCrowdSecVersion); the live canary has no
	// coverage for this endpoint (#205).
	// A never-ending text/event-stream of SSE frames, not a JSON document — there is
	// no response body to derive a structure from, and holding it open is exactly
	// what the live-box schema canary must not do. The frame payload's shape is
	// pinned by internal/cpustream's parser tests instead (#559).
	"cpuUsageStream":  "SSE stream (text/event-stream), not a JSON document — no structural schema applies",
	"crowdsecVersion": "raw multi-line cscli version text, not JSON — no structural schema applies",
}

// SchemaExemptions returns the endpoints excluded from schema derivation and
// the reasons, for the drift report.
func SchemaExemptions() map[EndpointName]string {
	out := make(map[EndpointName]string, len(schemaExemptEndpoints))
	for k, v := range schemaExemptEndpoints {
		out[k] = v
	}
	return out
}

// AllEndpointSchemas derives the structure-only schema of every registered
// endpoint, sorted by endpoint name.
func AllEndpointSchemas() ([]EndpointSchema, error) {
	names := make([]string, 0, len(schemaRegistry))
	for name := range schemaRegistry {
		names = append(names, string(name))
	}
	sort.Strings(names)

	out := make([]EndpointSchema, 0, len(names))
	for _, name := range names {
		s, err := schemaForRegistryEntry(EndpointName(name), schemaRegistry[EndpointName(name)])
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// schemaForRegistryEntry derives one endpoint's schema from its registry
// value. A plain value derives normally (schema.go's endpointSchemaFor); an
// envelopeDescent value derives by reflecting through its RawMessage field
// (#459) — see envelopeDescentSchemaFor.
func schemaForRegistryEntry(name EndpointName, target any) (EndpointSchema, error) {
	if ed, ok := target.(envelopeDescent); ok {
		return envelopeDescentSchemaFor(name, ed)
	}
	return endpointSchemaFor(name, target)
}
