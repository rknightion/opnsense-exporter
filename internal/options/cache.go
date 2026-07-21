package options

import (
	"time"

	"github.com/alecthomas/kingpin/v2"
)

// DefaultCacheTTL and DefaultFirmwareCacheTTL are the flag defaults, exported so the
// invariant they carry is testable from the collector package (#338): a body TTL only
// ever pays for itself when it is LONGER than the poll interval of the collector that
// fetches the endpoint. The poll scheduler clamps every interval to at most
// collector.IntervalCeil (15m), so both defaults sit above the slowest possible poll
// and still elide real calls — see TestBodyCacheDefaultsOutliveThePollCeiling.
const (
	DefaultCacheTTL         = time.Hour
	DefaultFirmwareCacheTTL = 12 * time.Hour
)

var (
	firmwareCacheTTL = kingpin.Flag(
		"exporter.firmware-cache-ttl",
		"How long to cache firmware API responses (status and, when enabled, package details). The firmware data OPNsense serves is the stored result of the box's own update check, which it refreshes roughly daily, so re-fetching it on every poll only costs firewall CPU. Set to 0 to fetch on every poll.",
	).Envar("OPNSENSE_EXPORTER_FIRMWARE_CACHE_TTL").Default(DefaultFirmwareCacheTTL.String()).Duration()

	cacheTTL = kingpin.Flag(
		"exporter.cache-ttl",
		"How long to cache responses from slow-moving API endpoints (system/CPU identity, certificate inventory, Unbound DNS blocklist policy config) and to remember that a plugin-gated endpoint is absent (its 404). This data changes only on an admin action — a config edit, a certificate renewal, a plugin install — so re-fetching it on every poll only costs firewall CPU. Set it above the collector poll interval or it can never serve a hit. The cost is staleness: a newly installed plugin, or a cert change, can take up to this long to show up. Set to 0 to fetch everything on every poll. Live data (counters, rates, service run-state) is never cached regardless of this setting.",
	).Envar("OPNSENSE_EXPORTER_CACHE_TTL").Default(DefaultCacheTTL.String()).Duration()
)

// ruleIDsCacheTTL bounds how long the firewall rule-id map may be served from
// the client response cache. Short by design: it exists to absorb a burst of
// unknown-rid lookups, not to hold the map for the whole *cacheTTL window.
const ruleIDsCacheTTL = time.Minute

// EndpointCacheTTLs maps an OPNsense API endpoint name to how long a successful
// GET response for it may be served from cache instead of re-fetched. Only
// endpoints whose payload is wholly slow-moving belong here: anything carrying a
// counter, rate or live status must be fetched on every poll.
//
// This body cache is NOT made redundant by the internal poll scheduler (#338).
// The two memoize different things at different layers: the poll snapshot caches
// the metrics the SERVING path replays (so a scrape costs no API call), while this
// caches API bodies for the POLL path (so a poll costs no API call). A collector
// polling on the cold 15m tier still asks the box four times an hour; with the 1h
// default it asks once, and the 12h firmware TTL removes 47 of every 48 calls.
// Dropping it would hand every elided call straight back to the firewall. It also
// dedupes endpoints shared by collectors on different tiers, which the snapshot —
// keyed per collector, not per endpoint — cannot do.
type EndpointCacheTTLs map[string]time.Duration

// CacheTTLs returns the per-endpoint response-cache TTLs for successful responses.
// Endpoints absent from the map — which is all of them but these — are never cached.
func CacheTTLs() EndpointCacheTTLs {
	ttls := EndpointCacheTTLs{}

	// Both firmware endpoints are gated by the same daily-ish check on the box:
	// "firmware" (api/core/firmware/status) reads the stored result of that check,
	// and "firmwareInfo" (api/core/firmware/info) lists installed plugins, which
	// change only on a package install. One TTL therefore governs both.
	if *firmwareCacheTTL > 0 {
		ttls["firmware"] = *firmwareCacheTTL
		ttls["firmwareInfo"] = *firmwareCacheTTL
	}

	if *cacheTTL > 0 {
		// Machine identity: the CPU model is fixed until the hardware changes, and the
		// OPNsense/FreeBSD versions change only on an upgrade.
		ttls["cpuType"] = *cacheTTL
		ttls["systemInformation"] = *cacheTTL

		// DMI/BIOS identity (os-dmidecode plugin): manufacturer/product/serial and BIOS
		// vendor/version/release date only change when the hardware itself changes, so
		// this is a prime response-cache candidate. Deliberately NOT the dechw PSU status
		// endpoint alongside it: that payload is live GPIO hardware state and must be
		// fetched every scrape (#217).
		ttls["dmidecodeInfo"] = *cacheTTL

		// Certificate inventory: descriptions and validity windows. Expiry is alerted on
		// a days-to-weeks horizon, so an hour of staleness is invisible; these carry no
		// counters, only notBefore/notAfter and in-use flags.
		ttls["certificates"] = *cacheTTL
		ttls["caCertificates"] = *cacheTTL
		ttls["acmeCertificates"] = *cacheTTL

		// Unbound DNS blocklist (dnsbl) policy config: whether policies are
		// enabled changes only on an admin config edit, not on scrape cadence.
		ttls["unboundBlocklistPolicies"] = *cacheTTL

		// Unbound local-zone/local-data/insecure-domain diagnostics (#209): wholly
		// slow-moving resolver configuration (unbound-control listlocalzones/
		// listlocaldata/listinsecure), changing only on an admin config edit —
		// unlike the DNSBL query-stats totals, which carry live counters and must
		// never be cached.
		ttls["unboundLocalZones"] = *cacheTTL
		ttls["unboundLocalData"] = *cacheTTL
		ttls["unboundInsecureDomains"] = *cacheTTL
		// Config backup history: BackupController globs /conf/backup/config-*.xml
		// and simplexml-parses every retained file (default retention 60, observed
		// as high as 100 live) on every call — not free, and the data only changes
		// when a config write actually happens, not on scrape cadence (#220).
		ttls["backupHistory"] = *cacheTTL

		// ZFS boot-environment inventory: bectl is a cheap exec, but boot
		// environments are created only around upgrades/admin action, so
		// re-running it every scrape buys nothing (#220).
		ttls["snapshotsSearch"] = *cacheTTL
		ttls["snapshotsIsSupported"] = *cacheTTL
		// ClamAV engine/signature-database version info: freshclam runs at most
		// a few times a day, so re-fetching this on every scrape only costs
		// firewall CPU (a configd shell-out + clamconf parse).
		ttls["clamavVersion"] = *cacheTTL
		// CrowdSec engine version (raw cscli version text): changes only when
		// the crowdsec package itself is upgraded, not on scrape cadence. The
		// six hub-item search endpoints (collections/scenarios/parsers/
		// postoverflows/appsecconfigs/appsecrules) are POST bootgrid searches,
		// so only their 404 is ever cacheable (see PluginGatedEndpoints) — their
		// successful bodies are re-fetched every scrape like their alerts/
		// decisions/bouncers/machines siblings.
		ttls["crowdsecVersion"] = *cacheTTL

		// Tor hidden-service hostnames (#206): the .onion hostname file for a
		// configured hidden service is written once when Tor provisions it and
		// otherwise wholly static — unlike circuits/streams, which are live
		// control-port state and must never be cached.
		ttls["torHiddenServices"] = *cacheTTL

		// Local auth posture (#222): disabled/admin/expiry/OTP flags, API key
		// count, and group count all change only on an admin config edit (user
		// add/edit, key issue/revoke, group membership change) — not on scrape
		// cadence, so re-fetching every scrape only costs firewall CPU.
		ttls["authUsers"] = *cacheTTL
		ttls["authAPIKeys"] = *cacheTTL
		ttls["authGroups"] = *cacheTTL
		// Firewall GeoIP alias-database freshness (#221): served from geoip.py's
		// cached stats file (/usr/local/share/GeoIP/alias.stats), itself refreshed
		// only by a daily filter_geoip cron/manual update — re-fetching every scrape
		// only re-reads the same cache file on the box.
		ttls["firewallGeoIP"] = *cacheTTL

		// NAT rule inventory counts (#221): all four MVC-managed NAT rule types
		// (source_nat, d_nat, one_to_one, npt) are pure config reads — rule counts
		// change only on an admin edit, not on scrape cadence.
		ttls["natSourceNATRules"] = *cacheTTL
		ttls["natDNATRules"] = *cacheTTL
		ttls["natOneToOneRules"] = *cacheTTL
		ttls["natNPTRules"] = *cacheTTL

		// Firewall rule-id map (#248): the rid -> description table log
		// enrichment resolves filterlog lines against. It changes only when the
		// ruleset is reloaded, so it is cacheable — but deliberately on a SHORT
		// TTL, not the full *cacheTTL: the enrichment refresher re-fetches this
		// endpoint when it sees an unknown rid, and an hour-long client cache
		// would hand it back the same stale map and leave a freshly added rule
		// unlabelled for that hour. Capped by *cacheTTL so that setting the flag
		// lower (or to 0) still disables caching as documented.
		ttls["firewallRuleIDs"] = min(*cacheTTL, ruleIDsCacheTTL)
	}

	return ttls
}

// AbsentCacheTTL returns how long a 404 from a plugin-gated endpoint is remembered,
// so a firewall without the plugin is not asked for it on every scrape. 0 disables
// negative caching. The endpoints this applies to are opnsense.PluginGatedEndpoints();
// they are wired in main (this package cannot import opnsense, which imports it).
func AbsentCacheTTL() time.Duration {
	return *cacheTTL
}
