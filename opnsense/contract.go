package opnsense

// EndpointContract pairs an endpoint's path with the HTTP method the exporter
// uses to call it. Used by cmd/apicontract to diff against OPNsense source.
type EndpointContract struct {
	Path   EndpointPath
	Method string // "GET" or "POST"
}

// postEndpoints lists every endpoint the exporter calls with POST (via
// c.do("POST", ...) or c.doForm(...)). Everything else is GET. Regenerate with:
//
//	grep -rnE 'c\.doForm\(|c\.do\("POST"' opnsense/*.go | grep -v _test.go
//
// then map each call site back to its c.endpoints["..."] key.
var postEndpoints = map[EndpointName]struct{}{
	"arp":                   {},
	"captivePortalSessions": {},
	"cronJobs":              {},
	"crowdsecAlerts":        {},
	"crowdsecDecisions":     {},
	"crowdsecBouncers":      {},
	"crowdsecMachines":      {},
	"firewallRules":         {},
	"quaggaOspfNeighbors":   {},
	"hasyncServices":        {},
	"ipsecPhase2":           {},
	"openVPNInstances":      {},
	"smartList":             {},
	"smartInfo":             {},
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
