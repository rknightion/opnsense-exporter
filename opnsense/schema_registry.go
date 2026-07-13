package opnsense

import (
	"encoding/json"
	"sort"
)

// schemaRegistry maps every manifest endpoint to a zero value of the struct
// its Fetch* call site decodes the response into. The schema walker
// (schema.go) reflects over these to derive the structure-only golden schemas
// in testdata/schemas/. TestSchemaRegistryComplete pins this map to
// defaultEndpoints(), so adding an endpoint without a registry entry (or an
// explicit exemption) fails CI.
var schemaRegistry = map[EndpointName]any{
	"acmeCertificates":           acmeCertificateSearchResponse{},
	"aliasTableSize":             aliasTableSizeResponse{},
	"apcupsdServiceStatus":       serviceStatusResponse{},
	"apcupsdUpsStatus":           apcupsdUpsStatusResponse{},
	"arp":                        arpSearchResponse{},
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
	"dhcpv4":                     dhcpv4LeaseResponse{},
	"dhcpv6Leases":               dhcpv6LeaseResponse{},
	"dhcpv6Prefixes":             dhcpv6PrefixResponse{},
	"dnsmasqLeases":              dnsmasqLeaseResponse{},
	"dnsmasqRanges":              dnsmasqRangeResponse{},
	"dnsmasqServiceStatus":       serviceStatusResponse{},
	"dyndnsAccounts":             dyndnsAccountSearchResponse{},
	"dyndnsServiceStatus":        serviceStatusResponse{},
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
	"hasyncVersion":              hasyncVersionResponse{},
	"healthCheck":                HealthCheckResponse{},
	"idsStatus":                  serviceStatusResponse{},
	"idsAlertLogs":               []idsAlertLogEntry{},
	"idsQueryAlerts":             idsAlertsResponse{},
	"idsSettings":                idsSettingsResponse{},
	"idsRulesets":                idsRulesetsResponse{},
	"idsSearchInstalledRules":    idsInstalledRulesResponse{},
	"interfaces":                 interfaceResponse{},
	"interfacesOverview":         interfacesOverviewResponse{},
	"ipsecPhase1":                ipsecSearchResponse{},
	"ipsecPhase2":                ipsecPhase2SearchResponse{},
	"ipsecPools":                 ipsecPoolsResponse{},
	"ipsecServiceStatus":         serviceStatusResponse{},
	"keaLeases4":                 keaLeaseResponse{},
	"keaLeases6":                 keaLeaseResponse{},
	"keaPdPools6":                keaPdPoolResponse{},
	"keaServiceStatus":           serviceStatusResponse{},
	"keaSubnets4":                keaSubnetResponse{},
	"keaSubnets6":                keaSubnetResponse{},
	"memoryStatistics":           mbufResponse{},
	"monitServiceStatus":         serviceStatusResponse{},
	"monitStatus":                monitStatusEnvelope{},
	"ndpTable":                   []ndpEntry{},
	"netflowCacheStats":          map[string]netflowCacheEntry{},
	"netflowIsEnabled":           netflowIsEnabledResponse{},
	"netflowStatus":              netflowStatusResponse{},
	"netisrStatistics":           netisrResponse{},
	"nginxServiceStatus":         serviceStatusResponse{},
	"nginxVts":                   nginxVtsResponse{},
	"ntpStatus":                  ntpStatusResponse{},
	"nutServiceStatus":           serviceStatusResponse{},
	"nutUpsStatus":               nutUpsStatusResponse{},
	"openVPNInstances":           openVPNSearchResponse{},
	"openVPNSessions":            openVPNSearchSessionsResponse{},
	"pfStates":                   pfStatesResponse{},
	"pfStatisticsByInterface":    firewallPFStatsResponse{},
	"pfStatsInfo":                pfStatsInfoResponse{},
	"pfStatsMemory":              pfStatsMemoryResponse{},
	"pfStatsTimeouts":            pfStatsTimeoutsResponse{},
	"pfsyncNodes":                pfsyncNodesResponse{},
	"protocolStatistics":         protocolStatisticsResponse{},
	"qfeedsStats":                qfeedsStatsResponse{},
	"quaggaBfdCounters":          frrBFDNeighborsEnvelope{},
	"quaggaBfdNeighbors":         frrBFDNeighborsEnvelope{},
	"quaggaBgpSummary":           frrBGPSummaryEnvelope{},
	"quaggaOspfNeighbors":        frrOSPFNeighborSearch{},
	"quaggaOspfOverview":         frrOSPFOverviewEnvelope{},
	"quaggaServiceStatus":        serviceStatusResponse{},
	"routingTable":               []routeEntry{},
	"services":                   servicesSearchResponse{},
	"smartInfo":                  smartInfoResponse{},
	"smartList":                  smartListResponse{},
	"snapshotsIsSupported":       snapshotsSupportedResponse{},
	"snapshotsSearch":            bootEnvironmentSearchResponse{},
	"socketStatistics": struct {
		Statistics map[string]json.RawMessage `json:"statistics"`
	}{},
	"syslogStats":              syslogStatsResponse{},
	"syslogServiceStatus":      serviceStatusResponse{},
	"systemActivity":           activityResponse{},
	"systemDisk":               systemDiskResponse{},
	"systemInformation":        systemInformationResponse{},
	"systemMbuf":               mbufResponse{},
	"systemResources":          systemResourcesResponse{},
	"systemSwap":               systemSwapResponse{},
	"systemTemperature":        []temperatureReading{},
	"systemTime":               systemTimeResponse{},
	"tailscaleServiceStatus":   serviceStatusResponse{},
	"tailscaleStatus":          tailscaleStatusResponse{},
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
	"wireguardClients":         wireguardClientsResponse{},
	"wireguardServiceStatus":   serviceStatusResponse{},
}

// schemaExemptEndpoints lists endpoints that deliberately have no schema, with
// the reason why. Currently every endpoint has a decodable response struct.
var schemaExemptEndpoints = map[EndpointName]string{}

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
		s, err := endpointSchemaFor(EndpointName(name), schemaRegistry[EndpointName(name)])
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}
