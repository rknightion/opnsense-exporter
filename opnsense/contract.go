package opnsense

// EndpointContract pairs an endpoint's path with the HTTP method the exporter
// uses to call it. Used by cmd/apicontract to diff against OPNsense source.
type EndpointContract struct {
	Path   EndpointPath
	Method string // "GET" or "POST"
}

// postEndpoints lists every endpoint the exporter calls with POST (via
// c.do("POST", ...) or c.doForm(...)). Everything else is GET.
//
// This map is no longer hand-regenerated: TestPostEndpointsMatchCallSites derives the
// POST endpoint set from the package source (AST) and fails CI if this map drifts from
// the actual call sites — a new POST Fetch* missing here, or a stale entry whose site is
// GET. Add the key here (and bump the golden count in contract_test.go) when you add a
// POST endpoint; the test tells you exactly which key is missing/stale (#145).
var postEndpoints = map[EndpointName]struct{}{
	"arp":                     {},
	"captivePortalSessions":   {},
	"cronJobs":                {},
	"crowdsecAlerts":          {},
	"crowdsecDecisions":       {},
	"crowdsecBouncers":        {},
	"crowdsecMachines":        {},
	"crowdsecCollections":     {},
	"crowdsecScenarios":       {},
	"crowdsecParsers":         {},
	"crowdsecPostoverflows":   {},
	"crowdsecAppsecConfigs":   {},
	"crowdsecAppsecRules":     {},
	"firewallRules":           {},
	"quaggaOspfNeighbors":     {},
	"hasyncServices":          {},
	"ipsecPhase2":             {},
	"openVPNInstances":        {},
	"smartList":               {},
	"smartInfo":               {},
	"idsQueryAlerts":          {},
	"idsSearchInstalledRules": {},
	"unboundSearchQueries":    {},
}

// ContractManifest returns the endpoint name→{path, method} contract derived
// from defaultEndpoints(). Paths therefore always match the live client.
func ContractManifest() map[EndpointName]EndpointContract {
	endpoints := defaultEndpoints()
	manifest := make(map[EndpointName]EndpointContract, len(endpoints))
	for name, path := range endpoints {
		method := "GET"
		if _, ok := postEndpoints[name]; ok {
			method = "POST"
		}
		manifest[name] = EndpointContract{Path: path, Method: method}
	}
	return manifest
}
