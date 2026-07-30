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
// Not every Response json.RawMessage envelope in the codebase is safe to
// unwrap this way: one is genuinely polymorphic on the wire (hasyncVersion's
// `response` is an object, a bare boolean or null depending on HA
// configuration) and one is genuinely ambiguous in shape (quaggaOspfInterface
// wraps interfaces in `{"interfaces": {...}}` on FRR>=8 but returns the flat
// map directly on older FRR, and only the wrapped shape has ever been
// confirmed live) — both are left as bare envelopes and documented instead in
// testdata/schemas/coverage.json rather than guessing a shape.
type envelopeDescent struct {
	Envelope any
	Field    string
	Inner    any
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

// envelopeDescentSchemaFor derives the schema for an envelopeDescent registry
// entry: the envelope's own top-level shape (Method/Path/TopLevelKind/
// KnownTopLevelKeys come from it unchanged), with Field's KindAny stop
// replaced by Inner's fully-reflected shape, re-anchored under Field.
func envelopeDescentSchemaFor(name EndpointName, ed envelopeDescent) (EndpointSchema, error) {
	ec, ok := ContractManifest()[name]
	if !ok {
		return EndpointSchema{}, fmt.Errorf("endpoint %q is not in the client manifest", name)
	}

	envKind, envFields := schemaForType(reflect.TypeOf(ed.Envelope))
	innerKind, innerFields := schemaForType(reflect.TypeOf(ed.Inner))

	fieldMap := make(map[string]FieldKind, len(envFields)+len(innerFields)+1)
	var topKeys []string
	for _, f := range envFields {
		if f.Path == ed.Field {
			continue // replaced below by the descended shape
		}
		fieldMap[f.Path] = f.Kind
		if !strings.ContainsAny(f.Path, ".*[") {
			topKeys = append(topKeys, f.Path)
		}
	}
	fieldMap[ed.Field] = innerKind
	for _, f := range innerFields {
		fieldMap[prefixSchemaPath(ed.Field, f.Path)] = f.Kind
	}
	if !strings.ContainsAny(ed.Field, ".*[") {
		topKeys = append(topKeys, ed.Field)
	}

	fields := make([]SchemaField, 0, len(fieldMap))
	for p, k := range fieldMap {
		fields = append(fields, SchemaField{Path: p, Kind: k})
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].Path < fields[j].Path })
	sort.Strings(topKeys)

	s := EndpointSchema{
		Endpoint:     string(name),
		Method:       ec.Method,
		Path:         string(ec.Path),
		TopLevelKind: envKind,
		Fields:       fields,
	}
	// Mirrors endpointSchemaFor: only a struct top level has a fixed key set
	// worth checking. Every envelopeDescent's Envelope is such a struct today
	// (a single-field {"response": ...} wrapper), but guard the condition
	// exactly the same way in case that ever changes.
	base := reflect.TypeOf(ed.Envelope)
	for base.Kind() == reflect.Pointer {
		base = base.Elem()
	}
	if envKind == KindObject && base.Kind() == reflect.Struct {
		s.KnownTopLevelKeys = topKeys
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
	"acmeCertificates":           acmeCertificateSearchResponse{},
	"aliasTableSize":             aliasTableSizeResponse{},
	"apcupsdServiceStatus":       serviceStatusResponse{},
	"apcupsdUpsStatus":           apcupsdUpsStatusResponse{},
	"arp":                        arpSearchResponse{},
	"authAPIKeys":                authAPIKeySearchResponse{},
	"authGroups":                 authGroupSearchResponse{},
	"authUsers":                  authUserSearchResponse{},
	"backupHistory":              configBackupResponse{},
	"bpfStatistics":              bpfStatisticsResponse{},
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
	"crowdsecAlerts":             crowdsecSearchEnvelope{},
	"crowdsecBouncers":           crowdsecSearchEnvelope{},
	"crowdsecDecisions":          crowdsecSearchEnvelope{},
	"crowdsecMachines":           crowdsecSearchEnvelope{},
	"crowdsecServiceStatus":      serviceStatusResponse{},
	"dechwPowerStatus":           dechwPowerStatusResponse{},
	"crowdsecCollections":        crowdsecSearchEnvelope{},
	"crowdsecScenarios":          crowdsecSearchEnvelope{},
	"crowdsecParsers":            crowdsecSearchEnvelope{},
	"crowdsecPostoverflows":      crowdsecSearchEnvelope{},
	"crowdsecAppsecConfigs":      crowdsecSearchEnvelope{},
	"crowdsecAppsecRules":        crowdsecSearchEnvelope{},
	"dhcpv4":                     dhcpv4LeaseResponse{},
	"dhcpv6Leases":               dhcpv6LeaseResponse{},
	"dhcpv6Prefixes":             dhcpv6PrefixResponse{},
	"dmidecodeInfo":              dmidecodeServiceGetResponse{},
	"dnsmasqLeases":              dnsmasqLeaseResponse{},
	"dnsmasqRanges":              dnsmasqRangeResponse{},
	"dnsmasqServiceStatus":       serviceStatusResponse{},
	"dyndnsAccounts":             dyndnsAccountSearchResponse{},
	"dyndnsServiceStatus":        serviceStatusResponse{},
	"firewallRuleIDs":            firewallRuleIDsResponse{},
	"firewallRules":              firewallRuleSearchResponse{},
	"firewallRuleStats":          firewallRuleStatsResponse{},
	"firewallStats":              []firewallStatEntry{},
	"firmware":                   firmwareStatusResponse{},
	"firmwareInfo":               firmwareInfoResponse{},
	"gatewaysStatus":             gatewayConfigurationResponse{},
	"haproxyCounters":            []json.RawMessage{},
	"haproxyInfo":                map[string]flexString{},
	"haproxyServiceStatus":       serviceStatusResponse{},
	"hasyncServices":             hasyncServicesBootgrid{},
	// hasyncVersion is deliberately NOT registered as an envelopeDescent (#459):
	// its Response field is genuinely polymorphic on the wire — an object when
	// HA is configured and the peer answers, but a bare JSON boolean (`false`)
	// on the overwhelming majority of installs (single-node, HA unconfigured)
	// and JSON null on some error paths (see hasyncVersionResponse's doc
	// comment). Reflecting through it as an object would misdescribe the common
	// case, not just widen an unverified path; see the coverage.json note on
	// this endpoint.
	"hasyncVersion":           hasyncVersionResponse{},
	"healthCheck":             HealthCheckResponse{},
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
	"ipsecPools":              ipsecPoolsResponse{},
	"ipsecSad":                ipsecSadResponse{},
	"ipsecSpd":                ipsecSpdResponse{},
	"ipsecLegacyStatus":       ipsecLegacyStatusResponse{},
	"ipsecServiceStatus":      serviceStatusResponse{},
	"keaLeases4":              keaLeaseResponse{},
	"keaLeases6":              keaLeaseResponse{},
	"keaPdPools6":             keaPdPoolResponse{},
	"keaServiceStatus":        serviceStatusResponse{},
	"keaSubnets4":             keaSubnetResponse{},
	"keaSubnets6":             keaSubnetResponse{},
	"memoryStatistics":        mbufResponse{},
	"monitServiceStatus":      serviceStatusResponse{},
	"monitStatus":             monitStatusEnvelope{},
	"ndpTable":                []ndpEntry{},
	"netbirdServiceStatus":    serviceStatusResponse{},
	"netbirdStatus":           netbirdStatusObject{},
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
	"quaggaOspfOverview": envelopeDescent{
		Envelope: frrOSPFOverviewEnvelope{},
		Field:    "response",
		Inner:    frrOSPFOverviewBody{},
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
	"torHiddenServices":        torHiddenServicesResponse{},
	"trafficShaperStatistics":  trafficShaperStatsResponse{},
	"unboundBlocklistPolicies": unboundPoliciesResponse{},
	"unboundDNSStatus":         unboundDNSStatusResponse{},
	"unboundInfra":             unboundInfraResponse{},
	"unboundServiceStatus":     serviceStatusResponse{},
	"unboundQueryStatsEnabled": unboundIsEnabledResponse{},
	"unboundQueryStatsTotals":  unboundOverviewTotalsResponse{},
	"unboundLocalZones":        unboundLocalZonesResponse{},
	"unboundLocalData":         unboundLocalDataResponse{},
	"unboundInsecureDomains":   unboundInsecureDomainsResponse{},
	"unboundSearchQueries":     unboundSearchQueriesResponse{},
	"vnstatInterfaceList":      vnstatInterfaceListResponse{},
	"vnstatGetJsonData":        vnstatJSONResponse{},
	"wireguardClients":         wireguardClientsResponse{},
	"wireguardServiceStatus":   serviceStatusResponse{},
}

// schemaExemptEndpoints lists endpoints that deliberately have no schema, with
// the reason why.
var schemaExemptEndpoints = map[EndpointName]string{
	// version/get passes cscli's raw multi-line text output straight through —
	// it is not JSON at all, so no structural schema applies. FetchCrowdSecStatus
	// parses it tolerantly (parseCrowdSecVersion); the live canary has no
	// coverage for this endpoint (#205).
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
