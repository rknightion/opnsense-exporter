package opnsense

// CaptureRequest describes how to probe a POST endpoint with the same request
// the client sends, so the live schema canary (cmd/apidrift) exercises the
// exact code path the exporter uses. Parameterized requests carry a %s
// placeholder resolved at probe time (a device name, an IKE connection id).
type CaptureRequest struct {
	ContentType   string
	Body          string
	Parameterized bool
}

const (
	jsonContentType = "application/json"
	formContentType = "application/x-www-form-urlencoded"
)

// bootgridAllRows is the standard bootgrid form body requesting every row.
const bootgridAllRows = "current=1&rowCount=-1"

// captureRequests mirrors the bodies of every POST call site in this package.
// TestCaptureRequestsCoverPostEndpoints pins it to postEndpoints, which is
// itself AST-pinned to the actual call sites.
var captureRequests = map[EndpointName]CaptureRequest{
	"arp":                   {ContentType: jsonContentType, Body: fetchArpPayload},
	"cronJobs":              {ContentType: jsonContentType, Body: fetchCronPayload},
	"firewallRules":         {ContentType: jsonContentType, Body: fetchFirewallRulesPayload},
	"openVPNInstances":      {ContentType: jsonContentType, Body: fetchOpenVPNPayload},
	"captivePortalSessions": {ContentType: formContentType, Body: bootgridAllRows},
	"crowdsecAlerts":        {ContentType: formContentType, Body: bootgridAllRows},
	"crowdsecDecisions":     {ContentType: formContentType, Body: bootgridAllRows},
	"crowdsecBouncers":      {ContentType: formContentType, Body: bootgridAllRows},
	"crowdsecMachines":      {ContentType: formContentType, Body: bootgridAllRows},
	"quaggaOspfNeighbors":   {ContentType: formContentType, Body: bootgridAllRows},
	"hasyncServices":        {ContentType: formContentType, Body: bootgridAllRows},
	"smartList":             {ContentType: formContentType, Body: ""},
	"smartInfo":             {ContentType: formContentType, Body: "device=%s&type=a&json=1", Parameterized: true},
	"ipsecPhase2":           {ContentType: jsonContentType, Body: `{"id":"%s"}`, Parameterized: true},
	// IDS: query_alerts reads up to idsAlertRowCap newest eve rows; searchInstalledRules
	// reads a single row purely for the envelope total (count-only).
	"idsQueryAlerts":          {ContentType: formContentType, Body: "current=1&rowCount=500"},
	"idsSearchInstalledRules": {ContentType: formContentType, Body: "current=1&rowCount=1"},
}

// CaptureRequestFor returns the capture request for a POST endpoint. GET
// endpoints return false — they are probed with a plain GET.
func CaptureRequestFor(name EndpointName) (CaptureRequest, bool) {
	req, ok := captureRequests[name]
	return req, ok
}
