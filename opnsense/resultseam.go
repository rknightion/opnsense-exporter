package opnsense

import (
	"github.com/rknightion/opnsense2otel/v4/internal/fetchshare"
)

// SetResultSeam makes this client publish the decoded result of the Fetch* methods
// listed in seamPublishedKeys to store, so a second consumer in the same process
// can read one instead of asking the firewall for it again (#571).
//
// It changes nothing about what this client fetches. Every Fetch* still performs
// its request, every metric is built from a live decode, and no Fetch* is ever
// served from the seam. The only effect is that the result is also recorded.
//
// Must be called before the client is cloned per scrape (WithContext), like the
// response cache: clones share the seam pointer, but only one that already exists.
func (c *Client) SetResultSeam(store *fetchshare.Store) {
	c.results = store
}

// publishResult records v under key, if a seam is wired. Nil-safe both ways: a
// client with no seam, and a nil seam, are both permanent no-ops.
//
// Called at the RETURN of a Fetch*, on the success path only. A failed fetch must
// not publish: the seam's contract is "this is what the box said", and publishing a
// partial or zero-valued failure would hand a reader an authoritative-looking empty
// table. A 404 that a Fetch* has already folded into "feature absent, empty data,
// nil error" is a success and is published — the empty table is the correct answer
// for that box, and withholding it would send every reader to the API forever.
func (c *Client) publishResult(key fetchshare.Key, v any) {
	if c == nil || c.results == nil {
		return
	}
	c.results.Publish(key, v)
}

// seamPublishedKeys is the set of keys this package publishes, paired with the
// Fetch* method that produces each. Hand-maintained, and asserted against the
// package source by TestSeamPublishedKeysMatchCallSites: the seam retrieves an
// entry by TYPE ASSERTION, so two Fetch* methods publishing different Go shapes
// under one key would silently turn every read into a coin flip. Naming the
// producer is what makes that reviewable.
//
// The list is deliberately short. An endpoint belongs here only when a SECOND
// consumer in this process already fetches it independently — the seam exists to
// remove duplicate requests, not to become an ambient result cache. Publishing an
// endpoint nobody else reads costs a map write per poll and buys nothing.
var seamPublishedKeys = map[fetchshare.Key]string{
	fetchshare.KeyArpTable:           "FetchArpTable",
	fetchshare.KeyNDPTable:           "FetchNDPTable",
	fetchshare.KeyKeaLeases4:         "FetchKeaLeases4",
	fetchshare.KeyKeaLeases6:         "FetchKeaLeases6",
	fetchshare.KeyDnsmasqLeases:      "FetchDnsmasqLeases",
	fetchshare.KeyDHCPv4Leases:       "FetchDHCPv4Leases",
	fetchshare.KeyDHCPv6Leases:       "FetchDHCPv6Leases",
	fetchshare.KeyInterfacesOverview: "FetchInterfacesOverview",
	fetchshare.KeyInterfaces:         "FetchInterfaces",
	fetchshare.KeyIPsecPhase1:        "FetchIPsecPhase1",
	fetchshare.KeyOpenVPNInstances:   "FetchOpenVPNInstances",
	// KeySystemInformation (#640): the second consumer is FetchFirmwareStatus,
	// not the enrichment refresher — it reads the FreeBSD version so the
	// firmware collector's os_version label doesn't need its own duplicate
	// systemInformation request. Published from fetchSystemInfo (the unexported
	// helper FetchSystemResources fans out to), not from FetchSystemResources
	// itself.
	fetchshare.KeySystemInformation: "fetchSystemInfo",
}

// Endpoints reached by a second consumer that are deliberately NOT published,
// recorded so the omissions read as decisions rather than oversights (#571):
//
//   - interfaceStatistics. Fetched by the interfaces collector via
//     FetchInterfaceStatistics and by the enrichment refresher via
//     FetchInterfaceIndexes — the SAME route decoded into two different exported
//     shapes. The collector's normalised InterfaceStatistics discards the
//     "<Link#N>" network string the kernel-index parse is entirely built around
//     (interface_index.go's linkNetwork), so the refresher cannot be served from
//     it, and publishing the unexported response type would put an internal shape
//     on a cross-package seam. The refresher reads it hourly: 24 requests a day,
//     against the ~10.8k the published keys remove.
//   - interfaceConfig. Fetched only by the refresher (FetchInterfaceEnumeration).
//     No collector fetches it, so there is no duplicate to remove.
//   - firewallRuleIDs. Same: the refresher is its only consumer, which is why it
//     carries a short body TTL of its own instead (#248).
