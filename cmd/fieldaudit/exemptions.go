package main

// minReasonLen is the floor on an exemption's written reason, mirroring the
// NOT_ANNOTATED gate in grafana/annotations.py. An exemption with no real
// sentence behind it is a silent deletion of a payload dimension.
const minReasonLen = 20

// Exemptions is the ledger of struct fields that cmd/fieldaudit finds decoded
// from an OPNsense response and never read, and that are deliberately left that
// way. The key is "opnsense.<Type>.<Field>" exactly as the tool reports it —
// fields of anonymous nested structs carry their full dotted path.
//
// The ledger is enforced in both directions: a dead field with no entry fails
// TestNoUnexemptedDeadFields, and an entry naming a field that no longer exists
// or is now read fails TestExemptionLedgerIsCurrent. Neither side can rot.
//
// Reasons that begin "SHOULD BE EXPORTED" are the honest ones: the data is worth
// having and nobody has done the work. They are searchable on that phrase.
//
// Regenerate the report with `make fieldaudit`.
var Exemptions = map[string]string{
	// opnsense/smart.go:72  json:"threshold_percent"
	"opnsense.smartWearPercent.ThresholdPercent": "Modelled so the canary does not report it as unmodelled drift, and deliberately " +
		"not exported yet (#615). smartctl emits it alongside spare_available only — " +
		"unconditionally on the NVMe path, and on the SATA path when 0 < threshold < 50 " +
		"(nvmeprint.cpp:505, ataprint.cpp:1206-1208); no emitter writes it for " +
		"endurance_used. #615 was a decode fix that deliberately left the metric surface " +
		"unchanged, so a spare-threshold gauge is an opportunity, not part of it.",
	// opnsense/nginx.go:82  json:"maxIntegerSize"
	"opnsense.nginxVtsOverCounts.MaxIntegerSize": "Modelled deliberately so the canary does not report it as unmodelled drift, and " +
		"deliberately never read (#609). It is nginx-module-vts's build-time counter " +
		"ceiling (2^64-1 on any 64-bit box), a capability constant rather than a reading, " +
		"so it is excluded from nginxVtsOverCounts.total() and never reaches a metric. " +
		"Carried as flexString because the bare literal overflows int64.",
	// opnsense/schema_coverage.go:83  json:"pruneTrigger"
	"opnsense.CoveragePath.PruneTrigger": "Documentary field in a committed ledger/golden file, not an OPNsense response: it is " +
		"round-tripped by json so a reviewer reading the JSON knows why an entry exists, and " +
		"no code branches on the value.",
	// opnsense/schema_coverage.go:71  json:"verified"
	"opnsense.CoveragePath.Verified": "Documentary field in a committed ledger/golden file, not an OPNsense response: it is " +
		"round-tripped by json so a reviewer reading the JSON knows why an entry exists, and " +
		"no code branches on the value.",
	// opnsense/schema_coverage.go:90  json:"note"
	"opnsense.EndpointCoverage.Note": "Documentary field in a committed ledger/golden file, not an OPNsense response: it is " +
		"round-tripped by json so a reviewer reading the JSON knows why an entry exists, and " +
		"no code branches on the value.",
	// opnsense/schema.go:43  json:"method"
	"opnsense.EndpointSchema.Method": "Documentary field in a committed ledger/golden file, not an OPNsense response: it is " +
		"round-tripped by json so a reviewer reading the JSON knows why an entry exists, and " +
		"no code branches on the value.",
	// opnsense/health_check.go:58  json:"message"
	"opnsense.HealthCheckResponse.CrashReporter.Message": "Free-text health-check detail. The metric is the per-subsystem status; the message " +
		"is prose that cannot become a bounded label.",
	// opnsense/health_check.go:60  json:"statusCode"
	"opnsense.HealthCheckResponse.CrashReporter.StatusCode": "Legacy pre-26.1 health-check shape, kept for the support window. The tolerant reader " +
		"resolves the string status new-wins-else-legacy and the numeric statusCode is only " +
		"consulted on the current shape, so the legacy copy stays unread.",
	// opnsense/health_check.go:63  json:"message"
	"opnsense.HealthCheckResponse.Firewall.Message": "Free-text health-check detail. The metric is the per-subsystem status; the message " +
		"is prose that cannot become a bounded label.",
	// opnsense/health_check.go:65  json:"statusCode"
	"opnsense.HealthCheckResponse.Firewall.StatusCode": "Legacy pre-26.1 health-check shape, kept for the support window. The tolerant reader " +
		"resolves the string status new-wins-else-legacy and the numeric statusCode is only " +
		"consulted on the current shape, so the legacy copy stays unread.",
	// opnsense/health_check.go:83  json:"message"
	"opnsense.HealthCheckResponse.Metadata.CrashReporter.Message": "Free-text health-check detail. The metric is the per-subsystem status; the message " +
		"is prose that cannot become a bounded label.",
	// opnsense/health_check.go:85  json:"statusCode"
	"opnsense.HealthCheckResponse.Metadata.CrashReporter.StatusCode": "Legacy pre-26.1 health-check shape under metadata, kept for the support window. Only " +
		"the string status is resolved by the tolerant reader; the numeric copy is redundant " +
		"with it.",
	// opnsense/health_check.go:88  json:"message"
	"opnsense.HealthCheckResponse.Metadata.Firewall.Message": "Free-text health-check detail. The metric is the per-subsystem status; the message " +
		"is prose that cannot become a bounded label.",
	// opnsense/health_check.go:90  json:"statusCode"
	"opnsense.HealthCheckResponse.Metadata.Firewall.StatusCode": "Legacy pre-26.1 health-check shape under metadata, kept for the support window. Only " +
		"the string status is resolved by the tolerant reader; the numeric copy is redundant " +
		"with it.",
	// opnsense/health_check.go:38  json:"message"
	"opnsense.HealthCheckSubsystem.Message": "Free-text health-check detail. isHealthy() reads status and statusCode; the message " +
		"is prose that cannot become a bounded label.",
	// opnsense/interfaces.go:30  json:"address length"
	"opnsense.InterfaceDetails.AddressLength": "ifconfig link-layer geometry (address/header length, datalen). Constant per media " +
		"type and of no operational interest; decoded so the canary validates the whole " +
		"interfaces_info detail block.",
	// opnsense/interfaces.go:34  json:"datalen"
	"opnsense.InterfaceDetails.Datalen": "ifconfig link-layer geometry (address/header length, datalen). Constant per media " +
		"type and of no operational interest; decoded so the canary validates the whole " +
		"interfaces_info detail block.",
	// opnsense/interfaces.go:24  json:"flags"
	"opnsense.InterfaceDetails.Flags": "ifconfig flag string on the interface detail payload. The exported interface metrics " +
		"carry link/status directly; the raw flag word duplicates them in a form nothing " +
		"parses.",
	// opnsense/interfaces.go:31  json:"header length"
	"opnsense.InterfaceDetails.HeaderLength": "ifconfig link-layer geometry (address/header length, datalen). Constant per media " +
		"type and of no operational interest; decoded so the canary validates the whole " +
		"interfaces_info detail block.",
	// opnsense/interfaces.go:36  json:"metric"
	"opnsense.InterfaceDetails.Metric": "The route metric field of ifconfig, which FreeBSD has not used for routing decisions " +
		"in decades — it is 0 on every device on every box. Decoded for canary coverage only.",
	// opnsense/interfaces.go:25  json:"promiscuous listeners"
	"opnsense.InterfaceDetails.PromiscuousListeners": "Promiscuous listener count from ifconfig. The bpf_statistics collector exports the " +
		"same signal per process and interface (#544 item 3), which is the useful form; this " +
		"aggregate adds nothing.",
	// opnsense/interfaces.go:33  json:"vhid"
	"opnsense.InterfaceDetails.Vhid": "CARP virtual host id on the interface detail block. The carp collector already " +
		"exports per-VHID state from the CARP endpoint, which is the authoritative source for " +
		"it.",
	// opnsense/unbound_search_queries.go:47  json:"status"
	"opnsense.UnboundSearchQueryRow.Status": "Per-query DNS response status from the unbound query log. The collector aggregates " +
		"the log into counts; a per-query series is one row per DNS query.",
	// opnsense/acme_client.go:24  json:"uuid"
	"opnsense.acmeCertificateRow.UUID": "Row identity from a search grid (UUID/internal id). The collector aggregates to " +
		"bounded groups and never emits a per-row series; a UUID label carries nothing a name " +
		"or interface label does not. Not a cardinality-budget rejection — there is no metric " +
		"it would improve.",
	// opnsense/acme_client.go:37  json:"current"
	"opnsense.acmeCertificateSearchResponse.Current": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/acme_client.go:36  json:"rowCount"
	"opnsense.acmeCertificateSearchResponse.RowCount": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/alias.go:24  json:"status"
	"opnsense.aliasTableSizeResponse.Status": "configd/MVC envelope status string. The client's failure signal is the transport " +
		"result and the decode itself, never this field; decoded so the live-box schema " +
		"canary keeps validating the envelope's shape.",
	// opnsense/apcupsd.go:55  json:"error"
	"opnsense.apcupsdUpsStatusResponse.Error": "Envelope error/message text. Decoded and not surfaced, so a soft backend failure is " +
		"currently indistinguishable from an empty result — a real gap, but a log/metric " +
		"decision rather than a dropped payload dimension. Worth a follow-up, not a silent " +
		"drop.",
	// opnsense/arp_table.go:22  json:"current"
	// opnsense/firewall_states.go:34  json:"current"
	"opnsense.firewallStatesResponse.Current": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/firewall_states.go:33  json:"rowCount"
	"opnsense.firewallStatesResponse.RowCount": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	"opnsense.arpSearchResponse.Current": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/arp_table.go:21  json:"rowCount"
	"opnsense.arpSearchResponse.RowCount": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/snapshots.go:28  json:"name"
	"opnsense.bootEnvironmentRow.Name": "Per-boot-environment identity. The collector exports the boot-environment COUNT and " +
		"the active one; a series per snapshot name would grow without bound as snapshots " +
		"accumulate.",
	// opnsense/snapshots.go:27  json:"uuid"
	"opnsense.bootEnvironmentRow.UUID": "Row identity from a search grid (UUID/internal id). The collector aggregates to " +
		"bounded groups and never emits a per-row series; a UUID label carries nothing a name " +
		"or interface label does not. Not a cardinality-budget rejection — there is no metric " +
		"it would improve.",
	// opnsense/snapshots.go:37  json:"current"
	"opnsense.bootEnvironmentSearchResponse.Current": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/snapshots.go:36  json:"rowCount"
	"opnsense.bootEnvironmentSearchResponse.RowCount": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/snapshots.go:35  json:"total"
	"opnsense.bootEnvironmentSearchResponse.Total": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/certificates.go:10  json:"uuid"
	"opnsense.caRow.UUID": "Row identity from a search grid (UUID/internal id). The collector aggregates to " +
		"bounded groups and never emits a per-row series; a UUID label carries nothing a name " +
		"or interface label does not. Not a cardinality-budget rejection — there is no metric " +
		"it would improve.",
	// opnsense/captiveportal.go:66  json:"current"
	"opnsense.captivePortalSessionSearch.Current": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/captiveportal.go:65  json:"rowCount"
	"opnsense.captivePortalSessionSearch.RowCount": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/captiveportal.go:199  json:"validity"
	"opnsense.captivePortalVoucherRow.Validity": "Per-voucher validity window. The captive-portal collector exports voucher counts by " +
		"state; a per-voucher series would be one row per issued voucher.",
	// opnsense/carp.go:12  json:"status_txt"
	"opnsense.carpVIPRow.StatusTxt": "Localised presentation copy of the status field the carp collector already exports. " +
		"Exporting the translated string as well would make the series depend on the box's UI " +
		"language.",
	// opnsense/certificates.go:74  json:"uuid"
	"opnsense.certificateRow.UUID": "Row identity from a search grid (UUID/internal id). The collector aggregates to " +
		"bounded groups and never emits a per-row series; a UUID label carries nothing a name " +
		"or interface label does not. Not a cardinality-budget rejection — there is no metric " +
		"it would improve.",
	// opnsense/cron.go:23  json:"current"
	"opnsense.cronSearchResponse.Current": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/cron.go:21  json:"rowCount"
	"opnsense.cronSearchResponse.RowCount": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/cron.go:22  json:"total"
	"opnsense.cronSearchResponse.Total": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/dhcpv4.go:35  json:"current"
	"opnsense.dhcpv4LeaseResponse.Current": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/dhcpv4.go:37  json:"interfaces"
	"opnsense.dhcpv4LeaseResponse.Interfaces": "The lease grid's interface filter map, an echo of the request rather than lease " +
		"data. The collector groups by the per-row interface description instead.",
	// opnsense/dhcpv4.go:34  json:"rowCount"
	"opnsense.dhcpv4LeaseResponse.RowCount": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/dhcpv4.go:26  json:"ends"
	"opnsense.dhcpv4LeaseRow.Ends": "Per-lease detail. The DHCP collectors export lease COUNTS grouped by interface and " +
		"state, never a series per lease, so per-lease timestamps and client identifiers have " +
		"nowhere to go without a per-host series.",
	// opnsense/dhcpv4.go:29  json:"man"
	"opnsense.dhcpv4LeaseRow.Man": "Per-lease detail. The DHCP collectors export lease COUNTS grouped by interface and " +
		"state, never a series per lease, so per-lease timestamps and client identifiers have " +
		"nowhere to go without a per-host series.",
	// opnsense/dhcpv4.go:25  json:"starts"
	"opnsense.dhcpv4LeaseRow.Starts": "Per-lease detail. The DHCP collectors export lease COUNTS grouped by interface and " +
		"state, never a series per lease, so per-lease timestamps and client identifiers have " +
		"nowhere to go without a per-host series.",
	// opnsense/dhcpv6.go:37  json:"current"
	"opnsense.dhcpv6LeaseResponse.Current": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/dhcpv6.go:39  json:"interfaces"
	"opnsense.dhcpv6LeaseResponse.Interfaces": "The lease grid's interface filter map, an echo of the request rather than lease " +
		"data. The collector groups by the per-row interface description instead.",
	// opnsense/dhcpv6.go:36  json:"rowCount"
	"opnsense.dhcpv6LeaseResponse.RowCount": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/dhcpv6.go:29  json:"cltt"
	"opnsense.dhcpv6LeaseRow.CLTT": "Per-lease detail. The DHCP collectors export lease COUNTS grouped by interface and " +
		"state, never a series per lease, so per-lease timestamps and client identifiers have " +
		"nowhere to go without a per-host series.",
	// opnsense/dhcpv6.go:30  json:"ends"
	"opnsense.dhcpv6LeaseRow.Ends": "Per-lease detail. The DHCP collectors export lease COUNTS grouped by interface and " +
		"state, never a series per lease, so per-lease timestamps and client identifiers have " +
		"nowhere to go without a per-host series.",
	// opnsense/dhcpv6.go:27  json:"iaid"
	"opnsense.dhcpv6LeaseRow.IAID": "Per-lease detail. The DHCP collectors export lease COUNTS grouped by interface and " +
		"state, never a series per lease, so per-lease timestamps and client identifiers have " +
		"nowhere to go without a per-host series.",
	// opnsense/dhcpv6.go:28  json:"iaid_duid"
	"opnsense.dhcpv6LeaseRow.IAIDDuid": "Per-lease detail. The DHCP collectors export lease COUNTS grouped by interface and " +
		"state, never a series per lease, so per-lease timestamps and client identifiers have " +
		"nowhere to go without a per-host series.",
	// opnsense/dhcpv6.go:31  json:"man"
	"opnsense.dhcpv6LeaseRow.Man": "Per-lease detail. The DHCP collectors export lease COUNTS grouped by interface and " +
		"state, never a series per lease, so per-lease timestamps and client identifiers have " +
		"nowhere to go without a per-host series.",
	// opnsense/dhcpv6.go:138  json:"current"
	"opnsense.dhcpv6PrefixResponse.Current": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/dhcpv6.go:137  json:"rowCount"
	"opnsense.dhcpv6PrefixResponse.RowCount": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/dhcpv6.go:130  json:"cltt"
	"opnsense.dhcpv6PrefixRow.CLTT": "Per-lease detail. The DHCP collectors export lease COUNTS grouped by interface and " +
		"state, never a series per lease, so per-lease timestamps and client identifiers have " +
		"nowhere to go without a per-host series.",
	// opnsense/dhcpv6.go:128  json:"duid"
	"opnsense.dhcpv6PrefixRow.DUID": "Per-lease detail. The DHCP collectors export lease COUNTS grouped by interface and " +
		"state, never a series per lease, so per-lease timestamps and client identifiers have " +
		"nowhere to go without a per-host series.",
	// opnsense/dhcpv6.go:131  json:"ends"
	"opnsense.dhcpv6PrefixRow.Ends": "Per-lease detail. The DHCP collectors export lease COUNTS grouped by interface and " +
		"state, never a series per lease, so per-lease timestamps and client identifiers have " +
		"nowhere to go without a per-host series.",
	// opnsense/dhcpv6.go:129  json:"iaid"
	"opnsense.dhcpv6PrefixRow.IAID": "Per-lease detail. The DHCP collectors export lease COUNTS grouped by interface and " +
		"state, never a series per lease, so per-lease timestamps and client identifiers have " +
		"nowhere to go without a per-host series.",
	// opnsense/dhcpv6.go:132  json:"lease_type"
	"opnsense.dhcpv6PrefixRow.LeaseType": "Per-lease detail. The DHCP collectors export lease COUNTS grouped by interface and " +
		"state, never a series per lease, so per-lease timestamps and client identifiers have " +
		"nowhere to go without a per-host series.",
	// opnsense/dhcpv6.go:126  json:"prefix"
	"opnsense.dhcpv6PrefixRow.Prefix": "Per-lease detail. The DHCP collectors export lease COUNTS grouped by interface and " +
		"state, never a series per lease, so per-lease timestamps and client identifiers have " +
		"nowhere to go without a per-host series.",
	// opnsense/hardware.go:38  json:"status"
	"opnsense.dmidecodeServiceGetResponse.Status": "configd/MVC envelope status string. The client's failure signal is the transport " +
		"result and the decode itself, never this field; decoded so the live-box schema " +
		"canary keeps validating the envelope's shape.",
	// opnsense/dnsmasq.go:20  json:"current"
	"opnsense.dnsmasqLeaseResponse.Current": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/dnsmasq.go:22  json:"interfaces"
	"opnsense.dnsmasqLeaseResponse.Interfaces": "The lease grid's interface filter map, an echo of the request rather than lease " +
		"data. The collector groups by the per-row interface description instead.",
	// opnsense/dnsmasq.go:19  json:"rowCount"
	"opnsense.dnsmasqLeaseResponse.RowCount": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/dnsmasq.go:9  json:"client_id"
	"opnsense.dnsmasqLeaseRow.ClientID": "Per-lease detail. The DHCP collectors export lease COUNTS grouped by interface and " +
		"state, never a series per lease, so per-lease timestamps and client identifiers have " +
		"nowhere to go without a per-host series.",
	// opnsense/dnsmasq.go:6  json:"iaid"
	"opnsense.dnsmasqLeaseRow.IAID": "Per-lease detail. The DHCP collectors export lease COUNTS grouped by interface and " +
		"state, never a series per lease, so per-lease timestamps and client identifiers have " +
		"nowhere to go without a per-host series.",
	// opnsense/dnsmasq.go:12  json:"if_name"
	"opnsense.dnsmasqLeaseRow.IfName": "The kernel device name for a dnsmasq lease, the third spelling of the same interface " +
		"alongside if and if_descr. Whichever of these becomes a label, it should be one of " +
		"them, not all three.",
	// opnsense/dyndns.go:32  json:"current"
	"opnsense.dyndnsAccountSearchResponse.Current": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/dyndns.go:31  json:"rowCount"
	"opnsense.dyndnsAccountSearchResponse.RowCount": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/protocol_statistics.go:56  json:"congestion-reductions"
	"opnsense.ecnStatistics.CongestionReductions": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:55  json:"handshakes"
	"opnsense.ecnStatistics.Handshakes": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/firewall_rules.go:78  json:"interface"
	"opnsense.firewallRule.RawInterface": "The raw interface identifier behind the resolved interface label the rule metrics " +
		"already carry. Kept so the resolver has its input; exporting both forms would double " +
		"the label set.",
	// opnsense/firewall_rules.go:70  json:"current"
	"opnsense.firewallRuleSearchResponse.Current": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/firewall_rules.go:69  json:"rowCount"
	"opnsense.firewallRuleSearchResponse.RowCount": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/firewall_rules.go:68  json:"total"
	"opnsense.firewallRuleSearchResponse.Total": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/firewall_rules.go:11  json:"status"
	"opnsense.firewallRuleStatsResponse.Status": "configd/MVC envelope status string. The client's failure signal is the transport " +
		"result and the decode itself, never this field; decoded so the live-box schema " +
		"canary keeps validating the envelope's shape.",
	// opnsense/firmware.go:37  json:"current_version"
	"opnsense.firmwareStatusResponse.DowngradePackages.CurrentVersion": "Per-package detail from the firmware status payload. The collector exports the " +
		"package COUNTS per set, never per-package series — a package name/version label set " +
		"churns with every upstream release and answers a question apt/pkg answers better.",
	// opnsense/firmware.go:35  json:"name"
	"opnsense.firmwareStatusResponse.DowngradePackages.Name": "Per-package detail from the firmware status payload. The collector exports the " +
		"package COUNTS per set, never per-package series — a package name/version label set " +
		"churns with every upstream release and answers a question apt/pkg answers better.",
	// opnsense/firmware.go:38  json:"new_version"
	"opnsense.firmwareStatusResponse.DowngradePackages.NewVersion": "Per-package detail from the firmware status payload. The collector exports the " +
		"package COUNTS per set, never per-package series — a package name/version label set " +
		"churns with every upstream release and answers a question apt/pkg answers better.",
	// opnsense/firmware.go:36  json:"repository"
	"opnsense.firmwareStatusResponse.DowngradePackages.Repository": "Per-package detail from the firmware status payload. The collector exports the " +
		"package COUNTS per set, never per-package series — a package name/version label set " +
		"churns with every upstream release and answers a question apt/pkg answers better.",
	// opnsense/firmware.go:18  json:"name"
	"opnsense.firmwareStatusResponse.NewPackages.Name": "Per-package detail from the firmware status payload. The collector exports the " +
		"package COUNTS per set, never per-package series — a package name/version label set " +
		"churns with every upstream release and answers a question apt/pkg answers better.",
	// opnsense/firmware.go:19  json:"repository"
	"opnsense.firmwareStatusResponse.NewPackages.Repository": "Per-package detail from the firmware status payload. The collector exports the " +
		"package COUNTS per set, never per-package series — a package name/version label set " +
		"churns with every upstream release and answers a question apt/pkg answers better.",
	// opnsense/firmware.go:20  json:"version"
	"opnsense.firmwareStatusResponse.NewPackages.Version": "Per-package detail from the firmware status payload. The collector exports the " +
		"package COUNTS per set, never per-package series — a package name/version label set " +
		"churns with every upstream release and answers a question apt/pkg answers better.",
	// opnsense/firmware.go:41  json:"name"
	"opnsense.firmwareStatusResponse.ReinstallPackages.Name": "Per-package detail from the firmware status payload. The collector exports the " +
		"package COUNTS per set, never per-package series — a package name/version label set " +
		"churns with every upstream release and answers a question apt/pkg answers better.",
	// opnsense/firmware.go:42  json:"repository"
	"opnsense.firmwareStatusResponse.ReinstallPackages.Repository": "Per-package detail from the firmware status payload. The collector exports the " +
		"package COUNTS per set, never per-package series — a package name/version label set " +
		"churns with every upstream release and answers a question apt/pkg answers better.",
	// opnsense/firmware.go:43  json:"version"
	"opnsense.firmwareStatusResponse.ReinstallPackages.Version": "Per-package detail from the firmware status payload. The collector exports the " +
		"package COUNTS per set, never per-package series — a package name/version label set " +
		"churns with every upstream release and answers a question apt/pkg answers better.",
	// opnsense/firmware.go:54  json:"name"
	"opnsense.firmwareStatusResponse.RemovePackages.Name": "Per-package detail from the firmware status payload. The collector exports the " +
		"package COUNTS per set, never per-package series — a package name/version label set " +
		"churns with every upstream release and answers a question apt/pkg answers better.",
	// opnsense/firmware.go:55  json:"repository"
	"opnsense.firmwareStatusResponse.RemovePackages.Repository": "Per-package detail from the firmware status payload. The collector exports the " +
		"package COUNTS per set, never per-package series — a package name/version label set " +
		"churns with every upstream release and answers a question apt/pkg answers better.",
	// opnsense/firmware.go:56  json:"version"
	"opnsense.firmwareStatusResponse.RemovePackages.Version": "Per-package detail from the firmware status payload. The collector exports the " +
		"package COUNTS per set, never per-package series — a package name/version label set " +
		"churns with every upstream release and answers a question apt/pkg answers better.",
	// opnsense/firmware.go:24  json:"repository"
	"opnsense.firmwareStatusResponse.UpgradePackages.Repository": "Per-package detail from the firmware status payload. The collector exports the " +
		"package COUNTS per set, never per-package series — a package name/version label set " +
		"churns with every upstream release and answers a question apt/pkg answers better.",
	// opnsense/firmware.go:27  json:"size"
	"opnsense.firmwareStatusResponse.UpgradePackages.Size": "Per-package detail from the firmware status payload. The collector exports the " +
		"package COUNTS per set, never per-package series — a package name/version label set " +
		"churns with every upstream release and answers a question apt/pkg answers better.",
	// opnsense/firmware.go:61  json:"current_version"
	"opnsense.firmwareStatusResponse.UpgradeSets.CurrentVersion": "Per-package detail from the firmware status payload. The collector exports the " +
		"package COUNTS per set, never per-package series — a package name/version label set " +
		"churns with every upstream release and answers a question apt/pkg answers better.",
	// opnsense/firmware.go:59  json:"name"
	"opnsense.firmwareStatusResponse.UpgradeSets.Name": "Per-package detail from the firmware status payload. The collector exports the " +
		"package COUNTS per set, never per-package series — a package name/version label set " +
		"churns with every upstream release and answers a question apt/pkg answers better.",
	// opnsense/firmware.go:62  json:"new_version"
	"opnsense.firmwareStatusResponse.UpgradeSets.NewVersion": "Per-package detail from the firmware status payload. The collector exports the " +
		"package COUNTS per set, never per-package series — a package name/version label set " +
		"churns with every upstream release and answers a question apt/pkg answers better.",
	// opnsense/firmware.go:63  json:"repository"
	"opnsense.firmwareStatusResponse.UpgradeSets.Repository": "Per-package detail from the firmware status payload. The collector exports the " +
		"package COUNTS per set, never per-package series — a package name/version label set " +
		"churns with every upstream release and answers a question apt/pkg answers better.",
	// opnsense/firmware.go:60  json:"size"
	"opnsense.firmwareStatusResponse.UpgradeSets.Size": "Per-package detail from the firmware status payload. The collector exports the " +
		"package COUNTS per set, never per-package series — a package name/version label set " +
		"churns with every upstream release and answers a question apt/pkg answers better.",
	// opnsense/frr.go:436  json:"peer"
	"opnsense.frrBFDCounterEntry.Peer": "FRR routing detail decoded for schema fidelity. The FRR collectors export " +
		"per-neighbour and per-interface state that this field does not feed; it is modelled " +
		"so the live-box canary validates the payload the daemon actually sends.",
	// opnsense/frr.go:422  json:"local"
	"opnsense.frrBFDNeighborEntry.Local": "FRR routing detail decoded for schema fidelity. The FRR collectors export " +
		"per-neighbour and per-interface state that this field does not feed; it is modelled " +
		"so the live-box canary validates the payload the daemon actually sends.",
	// opnsense/frr.go:421  json:"peer"
	"opnsense.frrBFDNeighborEntry.Peer": "FRR routing detail decoded for schema fidelity. The FRR collectors export " +
		"per-neighbour and per-interface state that this field does not feed; it is modelled " +
		"so the live-box canary validates the payload the daemon actually sends.",
	// opnsense/frr.go:622  json:"bgpState"
	"opnsense.frrBGPNeighborEntry.BgpState": "FRR routing detail decoded for schema fidelity. The FRR collectors export " +
		"per-neighbour and per-interface state that this field does not feed; it is modelled " +
		"so the live-box canary validates the payload the daemon actually sends.",
	// opnsense/frr.go:623  json:"remoteAs"
	"opnsense.frrBGPNeighborEntry.RemoteAs": "FRR routing detail decoded for schema fidelity. The FRR collectors export " +
		"per-neighbour and per-interface state that this field does not feed; it is modelled " +
		"so the live-box canary validates the payload the daemon actually sends.",
	// opnsense/frr.go:752  json:"ospfEnabled"
	"opnsense.frrOSPFInterfaceEntry.OspfEnabled": "FRR routing detail decoded for schema fidelity. The FRR collectors export " +
		"per-neighbour and per-interface state that this field does not feed; it is modelled " +
		"so the live-box canary validates the payload the daemon actually sends.",
	// opnsense/frr.go:220  json:"nbrPriority"
	"opnsense.frrOSPFNeighborRow.NbrPriority": "FRR routing detail decoded for schema fidelity. The FRR collectors export " +
		"per-neighbour and per-interface state that this field does not feed; it is modelled " +
		"so the live-box canary validates the payload the daemon actually sends.",
	// opnsense/frr.go:219  json:"priority"
	"opnsense.frrOSPFNeighborRow.Priority": "FRR routing detail decoded for schema fidelity. The FRR collectors export " +
		"per-neighbour and per-interface state that this field does not feed; it is modelled " +
		"so the live-box canary validates the payload the daemon actually sends.",
	// opnsense/frr.go:232  json:"current"
	"opnsense.frrOSPFNeighborSearch.Current": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/frr.go:231  json:"rowCount"
	"opnsense.frrOSPFNeighborSearch.RowCount": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/frr.go:230  json:"total"
	"opnsense.frrOSPFNeighborSearch.Total": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/frr.go:953  json:"numberOfInterfaceScopedLsa"
	"opnsense.frrOSPFv3InterfaceEntry.NumberOfInterfaceScopedLsa": "FRR routing detail decoded for schema fidelity. The FRR collectors export " +
		"per-neighbour and per-interface state that this field does not feed; it is modelled " +
		"so the live-box canary validates the payload the daemon actually sends.",
	// opnsense/frr.go:951  json:"priority"
	"opnsense.frrOSPFv3InterfaceEntry.Priority": "FRR routing detail decoded for schema fidelity. The FRR collectors export " +
		"per-neighbour and per-interface state that this field does not feed; it is modelled " +
		"so the live-box canary validates the payload the daemon actually sends.",
	// opnsense/frr.go:948  json:"type"
	"opnsense.frrOSPFv3InterfaceEntry.Type": "FRR routing detail decoded for schema fidelity. The FRR collectors export " +
		"per-neighbour and per-interface state that this field does not feed; it is modelled " +
		"so the live-box canary validates the payload the daemon actually sends.",
	// opnsense/frr.go:871  json:"numberOfAsScopedLsa"
	"opnsense.frrOSPFv3OverviewBody.NumberOfAsScopedLsa": "FRR routing detail decoded for schema fidelity. The FRR collectors export " +
		"per-neighbour and per-interface state that this field does not feed; it is modelled " +
		"so the live-box canary validates the payload the daemon actually sends.",
	// opnsense/frr.go:870  json:"routerId"
	"opnsense.frrOSPFv3OverviewBody.RouterID": "FRR routing detail decoded for schema fidelity. The FRR collectors export " +
		"per-neighbour and per-interface state that this field does not feed; it is modelled " +
		"so the live-box canary validates the payload the daemon actually sends.",
	// opnsense/gateways.go:27  json:"current"
	"opnsense.gatewayConfigurationResponse.Current": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/gateways.go:26  json:"rowCount"
	"opnsense.gatewayConfigurationResponse.RowCount": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/hasync.go:60  json:"description"
	"opnsense.hasyncServiceRow.Description": "Human description of an HA-sync service. The service name is the identity used on " +
		"the series; the description is free text that differs between the two nodes of a " +
		"pair.",
	// opnsense/hasync.go:39  json:"message"
	"opnsense.hasyncVersionResponse.Message": "Envelope error/message text. Decoded and not surfaced, so a soft backend failure is " +
		"currently indistinguishable from an empty result — a real gap, but a log/metric " +
		"decision rather than a dropped payload dimension. Worth a follow-up, not a silent " +
		"drop.",
	// opnsense/hasync.go:38  json:"status"
	"opnsense.hasyncVersionResponse.Status": "configd/MVC envelope status string. The client's failure signal is the transport " +
		"result and the decode itself, never this field; decoded so the live-box schema " +
		"canary keeps validating the envelope's shape.",
	// opnsense/hostdiscovery.go:23  json:"ether_address"
	"opnsense.hostDiscoveryRow.EtherAddress": "Per-host identity on an inventory row. The collector exports bounded interface x " +
		"source group counts; a MAC/IP label would be one series per host with no aggregate " +
		"behind it.",
	// opnsense/hostdiscovery.go:26  json:"first_seen"
	"opnsense.hostDiscoveryRow.FirstSeen": "Per-host identity on an inventory row. The collector exports bounded interface x " +
		"source group counts; a MAC/IP label would be one series per host with no aggregate " +
		"behind it.",
	// opnsense/hostdiscovery.go:24  json:"ip_address"
	"opnsense.hostDiscoveryRow.IPAddress": "Per-host identity on an inventory row. The collector exports bounded interface x " +
		"source group counts; a MAC/IP label would be one series per host with no aggregate " +
		"behind it.",
	// opnsense/hostdiscovery.go:36  json:"current"
	"opnsense.hostDiscoverySearchResponse.Current": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/hostdiscovery.go:35  json:"rowCount"
	"opnsense.hostDiscoverySearchResponse.RowCount": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/hostdiscovery.go:34  json:"total"
	"opnsense.hostDiscoverySearchResponse.Total": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/ids.go:73  json:"modified"
	"opnsense.idsAlertLogEntry.Modified": "File mtime of a rotated IDS log file. The collector reports log presence and size; " +
		"the mtime would be a per-file timestamp gauge nothing alerts on.",
	// opnsense/ids.go:94  json:"rows"
	"opnsense.idsInstalledRulesResponse.Rows": "Left as json.RawMessage on purpose (see the type's comment): only the rule COUNT is " +
		"consumed, never a per-SID series. Decoding the rows would cost the whole rule cache " +
		"per scrape.",
	// opnsense/interfaces.go:300  json:"flags"
	"opnsense.interfaceBridgeMemberRaw.Flags": "Bridge member flag word. The bridge metrics export membership and per-member state; " +
		"the raw flag string is an unparsed duplicate of it.",
	// opnsense/interface_enumeration.go:24  json:"capabilities"
	"opnsense.interfaceConfigEntry.Capabilities": "get_interface_config field. This struct exists for the schema registry and the " +
		"live-box canary only — FetchInterfaceEnumeration deliberately hand-walks the raw " +
		"JSON to preserve key order (ifIndex derivation, #361) and never decodes into this " +
		"type at all, so no field of it can be read by construction.",
	// opnsense/interface_enumeration.go:21  json:"device"
	"opnsense.interfaceConfigEntry.Device": "get_interface_config field. This struct exists for the schema registry and the " +
		"live-box canary only — FetchInterfaceEnumeration deliberately hand-walks the raw " +
		"JSON to preserve key order (ifIndex derivation, #361) and never decodes into this " +
		"type at all, so no field of it can be read by construction.",
	// opnsense/interface_enumeration.go:23  json:"flags"
	"opnsense.interfaceConfigEntry.Flags": "get_interface_config field. This struct exists for the schema registry and the " +
		"live-box canary only — FetchInterfaceEnumeration deliberately hand-walks the raw " +
		"JSON to preserve key order (ifIndex derivation, #361) and never decodes into this " +
		"type at all, so no field of it can be read by construction.",
	// opnsense/interface_enumeration.go:41  json:"ipv4"
	"opnsense.interfaceConfigEntry.IPv4": "get_interface_config field. This struct exists for the schema registry and the " +
		"live-box canary only — FetchInterfaceEnumeration deliberately hand-walks the raw " +
		"JSON to preserve key order (ifIndex derivation, #361) and never decodes into this " +
		"type at all, so no field of it can be read by construction.",
	// opnsense/interface_enumeration.go:42  json:"ipv6"
	"opnsense.interfaceConfigEntry.IPv6": "get_interface_config field. This struct exists for the schema registry and the " +
		"live-box canary only — FetchInterfaceEnumeration deliberately hand-walks the raw " +
		"JSON to preserve key order (ifIndex derivation, #361) and never decodes into this " +
		"type at all, so no field of it can be read by construction.",
	// opnsense/interface_enumeration.go:48  json:"is_physical"
	"opnsense.interfaceConfigEntry.IsPhysical": "get_interface_config field. This struct exists for the schema registry and the " +
		"live-box canary only — FetchInterfaceEnumeration deliberately hand-walks the raw " +
		"JSON to preserve key order (ifIndex derivation, #361) and never decodes into this " +
		"type at all, so no field of it can be read by construction.",
	// opnsense/interface_enumeration.go:35  json:"macaddr"
	"opnsense.interfaceConfigEntry.MACAddr": "get_interface_config field. This struct exists for the schema registry and the " +
		"live-box canary only — FetchInterfaceEnumeration deliberately hand-walks the raw " +
		"JSON to preserve key order (ifIndex derivation, #361) and never decodes into this " +
		"type at all, so no field of it can be read by construction.",
	// opnsense/interface_enumeration.go:36  json:"macaddr_hw"
	"opnsense.interfaceConfigEntry.MACAddrHW": "get_interface_config field. This struct exists for the schema registry and the " +
		"live-box canary only — FetchInterfaceEnumeration deliberately hand-walks the raw " +
		"JSON to preserve key order (ifIndex derivation, #361) and never decodes into this " +
		"type at all, so no field of it can be read by construction.",
	// opnsense/interface_enumeration.go:54  json:"mtu"
	"opnsense.interfaceConfigEntry.MTU": "get_interface_config field. This struct exists for the schema registry and the " +
		"live-box canary only — FetchInterfaceEnumeration deliberately hand-walks the raw " +
		"JSON to preserve key order (ifIndex derivation, #361) and never decodes into this " +
		"type at all, so no field of it can be read by construction.",
	// opnsense/interface_enumeration.go:45  json:"media"
	"opnsense.interfaceConfigEntry.Media": "get_interface_config field. This struct exists for the schema registry and the " +
		"live-box canary only — FetchInterfaceEnumeration deliberately hand-walks the raw " +
		"JSON to preserve key order (ifIndex derivation, #361) and never decodes into this " +
		"type at all, so no field of it can be read by construction.",
	// opnsense/interface_enumeration.go:46  json:"media_raw"
	"opnsense.interfaceConfigEntry.MediaRaw": "get_interface_config field. This struct exists for the schema registry and the " +
		"live-box canary only — FetchInterfaceEnumeration deliberately hand-walks the raw " +
		"JSON to preserve key order (ifIndex derivation, #361) and never decodes into this " +
		"type at all, so no field of it can be read by construction.",
	// opnsense/interface_enumeration.go:33  json:"nd6"
	"opnsense.interfaceConfigEntry.ND6": "get_interface_config field. This struct exists for the schema registry and the " +
		"live-box canary only — FetchInterfaceEnumeration deliberately hand-walks the raw " +
		"JSON to preserve key order (ifIndex derivation, #361) and never decodes into this " +
		"type at all, so no field of it can be read by construction.",
	// opnsense/interface_enumeration.go:25  json:"options"
	"opnsense.interfaceConfigEntry.Options": "get_interface_config field. This struct exists for the schema registry and the " +
		"live-box canary only — FetchInterfaceEnumeration deliberately hand-walks the raw " +
		"JSON to preserve key order (ifIndex derivation, #361) and never decodes into this " +
		"type at all, so no field of it can be read by construction.",
	// opnsense/interface_enumeration.go:60  json:"sfp"
	"opnsense.interfaceConfigEntry.SFP": "get_interface_config field. This struct exists for the schema registry and the " +
		"live-box canary only — FetchInterfaceEnumeration deliberately hand-walks the raw " +
		"JSON to preserve key order (ifIndex derivation, #361) and never decodes into this " +
		"type at all, so no field of it can be read by construction.",
	// opnsense/interface_enumeration.go:47  json:"status"
	"opnsense.interfaceConfigEntry.Status": "get_interface_config field. This struct exists for the schema registry and the " +
		"live-box canary only — FetchInterfaceEnumeration deliberately hand-walks the raw " +
		"JSON to preserve key order (ifIndex derivation, #361) and never decodes into this " +
		"type at all, so no field of it can be read by construction.",
	// opnsense/interface_enumeration.go:44  json:"supported_media"
	"opnsense.interfaceConfigEntry.SupportedMedia": "get_interface_config field. This struct exists for the schema registry and the " +
		"live-box canary only — FetchInterfaceEnumeration deliberately hand-walks the raw " +
		"JSON to preserve key order (ifIndex derivation, #361) and never decodes into this " +
		"type at all, so no field of it can be read by construction.",
	// opnsense/interface_enumeration.go:66  json:"flags"
	"opnsense.interfaceND6.Flags": "get_interface_config field. This struct exists for the schema registry and the " +
		"live-box canary only — FetchInterfaceEnumeration deliberately hand-walks the raw " +
		"JSON to preserve key order (ifIndex derivation, #361) and never decodes into this " +
		"type at all, so no field of it can be read by construction.",
	// opnsense/ipsec.go:215  json:"address"
	"opnsense.ipsecLeaseRow.Address": "Per-lease client address. The IPsec collector exports pool utilisation counts, never " +
		"a series per connected client.",
	// opnsense/ipsec.go:322  json:"dst"
	"opnsense.ipsecSadRow.Dst": "Per-SA endpoint address. #226 already established that per-SA series churn with " +
		"every rekey (SPI churn); the collector exports SA counts and aggregate byte counters " +
		"instead.",
	// opnsense/ipsec.go:321  json:"src"
	"opnsense.ipsecSadRow.Src": "Per-SA endpoint address. #226 already established that per-SA series churn with " +
		"every rekey (SPI churn); the collector exports SA counts and aggregate byte counters " +
		"instead.",
	// opnsense/ipsec.go:326  json:"state"
	"opnsense.ipsecSadRow.State": "Per-SA state string. Same rekey-churn problem as the SA endpoints: the collector " +
		"counts SAs by state rather than emitting one series per SA.",
	// opnsense/ipsec.go:27  json:"current"
	"opnsense.ipsecSearchResponse.Current": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/ipsec.go:25  json:"rowCount"
	"opnsense.ipsecSearchResponse.RowCount": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/ipsec.go:26  json:"total"
	"opnsense.ipsecSearchResponse.Total": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/kea.go:75  json:"current"
	"opnsense.keaLeaseResponse.Current": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/kea.go:78  json:"interfaces"
	"opnsense.keaLeaseResponse.Interfaces": "The lease grid's interface filter map, an echo of the request rather than lease " +
		"data. The collector groups by the per-row interface description instead.",
	// opnsense/kea.go:74  json:"rowCount"
	"opnsense.keaLeaseResponse.RowCount": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/mbuf.go:44  json:"percentage"
	"opnsense.mbufStatisticsData.BytesPercent": "Percentage the API computes from figures the collector already exports as raw " +
		"counters. A ratio belongs in PromQL, not in a series — deliberately dropped.",
	// opnsense/mbuf.go:46  json:"mbuf-and-cluster"
	"opnsense.mbufStatisticsData.MbufAndCluster": "Derivable: the API's own sum of the mbuf and cluster counts, both of which are " +
		"already exported separately. A precomputed sum belongs in PromQL, not in its own " +
		"series.",
	// opnsense/monit.go:122  json:"pendingaction"
	"opnsense.monitServiceXML.PendingAction": "Transient monit action id, meaningful only between a request and its execution. It " +
		"would be zero on essentially every scrape and cannot be sampled reliably.",
	// opnsense/ndp.go:9  json:"expire"
	"opnsense.ndpEntry.Expire": "Decoded and dropped. Not worth exporting either: the reference box (OPNsense 26.1) " +
		"sends no expire key on this endpoint at all, the same negative result as " +
		"ndpEntry.Type (#539 note 9), so the field is dead on every release in the support " +
		"window. Kept only so the canary would notice if a future release started sending it.",
	// opnsense/nginx.go:341  json:"ip"
	"opnsense.nginxBanRow.IP": "Banned client address. One series per banned IP is unbounded and churns as bans " +
		"expire; the collector exports the ban count.",
	// opnsense/nginx.go:340  json:"uuid"
	"opnsense.nginxBanRow.UUID": "Row identity from a search grid (UUID/internal id). The collector aggregates to " +
		"bounded groups and never emits a per-row series; a UUID label carries nothing a name " +
		"or interface label does not. Not a cardinality-budget rejection — there is no metric " +
		"it would improve.",
	// opnsense/nginx.go:349  json:"current"
	"opnsense.nginxBanSearchResponse.Current": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/nginx.go:348  json:"rowCount"
	"opnsense.nginxBanSearchResponse.RowCount": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/ntp.go:136  json:"sentence"
	"opnsense.ntpGPSFix.Sentence": "The raw NMEA sentence behind the GPS fix. Free-text and unbounded; the parsed fix " +
		"quality and satellite count are exported instead.",
	// opnsense/openvpn.go:20  json:"current"
	"opnsense.openVPNSearchResponse.Current": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/openvpn.go:18  json:"rowCount"
	"opnsense.openVPNSearchResponse.RowCount": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/openvpn.go:19  json:"total"
	"opnsense.openVPNSearchResponse.Total": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/openvpn.go:65  json:"current"
	"opnsense.openVPNSearchSessionsResponse.Current": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/openvpn.go:63  json:"rowCount"
	"opnsense.openVPNSearchSessionsResponse.RowCount": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/openvpn.go:64  json:"total"
	"opnsense.openVPNSearchSessionsResponse.Total": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/pf_statistics.go:12  json:"rate"
	"opnsense.pfStatsCounterEntry.Rate": "A per-second rate the box computes over its own window. The counter is exported " +
		"instead so rate() controls the window; shipping a precomputed rate would " +
		"double-count and cannot be re-aggregated.",
	// opnsense/network_diagnostics.go:425  json:"current"
	"opnsense.pfsyncNodesResponse.Current": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/network_diagnostics.go:424  json:"rowCount"
	"opnsense.pfsyncNodesResponse.RowCount": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/protocol_statistics.go:327  json:"send-failed-memory-error"
	"opnsense.protocolStatisticsResponse.Statistics.Carp.SendFailedMemoryError": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:297  json:"discard-tunnel-no-gif"
	"opnsense.protocolStatisticsResponse.Statistics.IP.DiscardTunnelNoGif": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:280  json:"dropped-fragments"
	"opnsense.protocolStatisticsResponse.Statistics.IP.DroppedFragments": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:281  json:"dropped-fragments-after-timeout"
	"opnsense.protocolStatisticsResponse.Statistics.IP.DroppedFragmentsAfterTimeout": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:295  json:"fragments-created"
	"opnsense.protocolStatisticsResponse.Statistics.IP.FragmentsCreated": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:283  json:"received-local-packets"
	"opnsense.protocolStatisticsResponse.Statistics.IP.ReceivedLocalPackets": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:288  json:"received-unknown-multicast-group"
	"opnsense.protocolStatisticsResponse.Statistics.IP.ReceivedUnknownMulticastGroup": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:289  json:"redirects-sent"
	"opnsense.protocolStatisticsResponse.Statistics.IP.RedirectsSent": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:291  json:"send-packets-fabricated-header"
	"opnsense.protocolStatisticsResponse.Statistics.IP.SendPacketsFabricatedHeader": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:310  json:"discard-invalid-return-address"
	"opnsense.protocolStatisticsResponse.Statistics.Icmp.DiscardInvalidReturnAddress": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:311  json:"discard-no-route"
	"opnsense.protocolStatisticsResponse.Statistics.Icmp.DiscardNoRoute": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:302  json:"errors-not-from-message"
	"opnsense.protocolStatisticsResponse.Statistics.Icmp.ErrorsNotFromMessage": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:312  json:"icmp-address-responses"
	"opnsense.protocolStatisticsResponse.Statistics.Icmp.IcmpAddressResponses": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:352  json:"discarded-no-memory"
	"opnsense.protocolStatisticsResponse.Statistics.Pfsync.DiscardedNoMemory": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:332  json:"input-histogram"
	"opnsense.protocolStatisticsResponse.Statistics.Pfsync.InputHistogram": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:334  json:"count"
	"opnsense.protocolStatisticsResponse.Statistics.Pfsync.InputHistogram.Count": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:333  json:"name"
	"opnsense.protocolStatisticsResponse.Statistics.Pfsync.InputHistogram.Name": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:348  json:"output-histogram"
	"opnsense.protocolStatisticsResponse.Statistics.Pfsync.OutputHistogram": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:350  json:"count"
	"opnsense.protocolStatisticsResponse.Statistics.Pfsync.OutputHistogram.Count": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:349  json:"name"
	"opnsense.protocolStatisticsResponse.Statistics.Pfsync.OutputHistogram.Name": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:173  json:"ack-header-predictions"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.AckHeaderPredictions": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:159  json:"connections-updated-rtt-on-close"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.ConnectionsUpdatedRttOnClose": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:161  json:"connections-updated-ssthresh-on-close"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.ConnectionsUpdatedSsthreshOnClose": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:160  json:"connections-updated-variance-on-close"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.ConnectionsUpdatedVarianceOnClose": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:174  json:"data-packet-header-predictions"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.DataPacketHeaderPredictions": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:144  json:"discard-bad-checksum"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.DiscardBadChecksum": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:145  json:"discard-bad-header-offset"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.DiscardBadHeaderOffset": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:147  json:"discard-reassembly-queue-full"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.DiscardReassemblyQueueFull": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:146  json:"discard-too-short"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.DiscardTooShort": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:162  json:"embryonic-connections-dropped"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.EmbryonicConnectionsDropped": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:152  json:"ignored-in-window-resets"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.IgnoredInWindowResets": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:167  json:"persist-timeout"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.PersistTimeout": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:142  json:"receive-window-update-packets"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.ReceiveWindowUpdatePackets": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:115  json:"received-ack-bytes"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.ReceivedAckBytes": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:114  json:"received-ack-packets"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.ReceivedAckPackets": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:123  json:"received-acks-for-unsent-data"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.ReceivedAcksForUnsentData": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:143  json:"received-after-close-packets"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.ReceivedAfterClosePackets": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:140  json:"received-after-window-bytes"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.ReceivedAfterWindowBytes": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:139  json:"received-after-window-packets"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.ReceivedAfterWindowPackets": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:118  json:"received-bad-udp-tunneled-pkts"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.ReceivedBadUDPTunneledPkts": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:132  json:"received-completely-duplicate-packets"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.ReceivedCompletelyDuplicatePackets": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:116  json:"received-duplicate-acks"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.ReceivedDuplicateAcks": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:130  json:"received-in-sequence-packets"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.ReceivedInSequencePackets": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:134  json:"received-old-duplicate-packets"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.ReceivedOldDuplicatePackets": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:137  json:"received-out-of-order"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.ReceivedOutOfOrder": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:138  json:"received-out-of-order-bytes"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.ReceivedOutOfOrderBytes": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:136  json:"received-some-duplicate-bytes"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.ReceivedSomeDuplicateBytes": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:135  json:"received-some-duplicate-packets"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.ReceivedSomeDuplicatePackets": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:117  json:"received-udp-tunneled-pkts"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.ReceivedUDPTunneledPkts": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:141  json:"received-window-probes"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.ReceivedWindowProbes": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:164  json:"segment-update-attempts"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.SegmentUpdateAttempts": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:107  json:"sent-ack-only-packets"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.SentAckOnlyPackets": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:112  json:"sent-control-packets"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.SentControlPackets": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:101  json:"sent-data-packets"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.SentDataPackets": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:108  json:"sent-packets-delayed"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.SentPacketsDelayed": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:106  json:"sent-resends-by-mtu-discovery"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.SentResendsByMtuDiscovery": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:105  json:"sent-unnecessary-retransmitted-packets"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.SentUnnecessaryRetransmittedPackets": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:109  json:"sent-urg-only-packets"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.SentUrgOnlyPackets": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:110  json:"sent-window-probe-packets"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.SentWindowProbePackets": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:111  json:"sent-window-update-packets"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.SentWindowUpdatePackets": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:185  json:"aborted"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.Syncache.Aborted": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:186  json:"bad-ack"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.Syncache.BadAck": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:181  json:"bucket-overflow"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.Syncache.BucketOverflow": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:182  json:"cache-overflow"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.Syncache.CacheOverflow": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:180  json:"completed"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.Syncache.Completed": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:178  json:"duplicates"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.Syncache.Duplicates": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:190  json:"receivd-cookies"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.Syncache.ReceivdCookies": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:183  json:"reset"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.Syncache.Reset": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:177  json:"retransmitted"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.Syncache.Retransmitted": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:189  json:"sent-cookies"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.Syncache.SentCookies": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:184  json:"stale"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.Syncache.Stale": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:187  json:"unreachable"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.Syncache.Unreachable": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:188  json:"zone-failures"
	"opnsense.protocolStatisticsResponse.Statistics.TCP.Syncache.ZoneFailures": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:267  json:"multicast-source-filter-matches"
	"opnsense.protocolStatisticsResponse.Statistics.UDP.MulticastSourceFilterMatches": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/protocol_statistics.go:264  json:"not-for-hashed-pcb"
	"opnsense.protocolStatisticsResponse.Statistics.UDP.NotForHashedPcb": "netstat -s counter modelled so the live-box schema canary validates the whole " +
		"protocol-statistics payload, not just the slice we export. Which counters become " +
		"metrics is a catalogue decision (five sections are consumed today, #545); the field " +
		"is not a dropped dimension of anything already exported.",
	// opnsense/qfeeds.go:20  json:"licensed"
	"opnsense.qfeedsStatsResponse.Feeds.Licensed": "Zenarmor feed licensing flag. Licensing state is not an operational signal about the " +
		"firewall, and it does not change between scrapes.",
	// opnsense/relayd.go:16  json:"enabled"
	"opnsense.relaydHostProperty.Enabled": "Configured-enabled flag for a relayd host, a configuration property rather than a " +
		"runtime one. The collector exports the host's live up/down state, which is the " +
		"operational signal.",
	// opnsense/relayd.go:14  json:"uuid"
	"opnsense.relaydHostProperty.UUID": "Row identity from a search grid (UUID/internal id). The collector aggregates to " +
		"bounded groups and never emits a per-row series; a UUID label carries nothing a name " +
		"or interface label does not. Not a cardinality-budget rejection — there is no metric " +
		"it would improve.",
	// opnsense/relayd.go:64  json:"uuid"
	"opnsense.relaydTableEntry.UUID": "Row identity from a search grid (UUID/internal id). The collector aggregates to " +
		"bounded groups and never emits a per-row series; a UUID label carries nothing a name " +
		"or interface label does not. Not a cardinality-budget rejection — there is no metric " +
		"it would improve.",
	// opnsense/relayd.go:76  json:"id"
	"opnsense.relaydVirtualServerRow.ID": "Row identity from a search grid (UUID/internal id). The collector aggregates to " +
		"bounded groups and never emits a per-row series; a UUID label carries nothing a name " +
		"or interface label does not. Not a cardinality-budget rejection — there is no metric " +
		"it would improve.",
	// opnsense/relayd.go:80  json:"uuid"
	"opnsense.relaydVirtualServerRow.UUID": "Row identity from a search grid (UUID/internal id). The collector aggregates to " +
		"bounded groups and never emits a per-row series; a UUID label carries nothing a name " +
		"or interface label does not. Not a cardinality-budget rejection — there is no metric " +
		"it would improve.",
	// opnsense/services.go:13  json:"current"
	"opnsense.servicesSearchResponse.Current": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/services.go:12  json:"rowCount"
	"opnsense.servicesSearchResponse.RowCount": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/services.go:5  json:"id"
	"opnsense.servicesSearchResponse.Rows.ID": "Row identity from a search grid (UUID/internal id). The collector aggregates to " +
		"bounded groups and never emits a per-row series; a UUID label carries nothing a name " +
		"or interface label does not. Not a cardinality-budget rejection — there is no metric " +
		"it would improve.",
	// opnsense/services.go:8  json:"locked"
	"opnsense.servicesSearchResponse.Rows.Locked": "Whether a service is locked against start/stop in the UI. A configuration property " +
		"of the box, not a runtime signal; the collector exports running state.",
	// opnsense/services.go:11  json:"total"
	"opnsense.servicesSearchResponse.Total": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/syslog.go:7  json:"Description"
	"opnsense.syslogStatRow.Description": "Human description of a syslog target. The exported identity is the target name; the " +
		"description is free text an operator edits.",
	// opnsense/syslog.go:19  json:"current"
	"opnsense.syslogStatsResponse.Current": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/syslog.go:18  json:"rowCount"
	"opnsense.syslogStatsResponse.RowCount": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/system_resources.go:36  json:"available"
	"opnsense.systemDiskDevice.Available": "Redundant with the used/size pair the disk collector already exports; available is " +
		"size minus used, so exporting it adds a series that carries no new information.",
	// opnsense/system_resources.go:58  json:"updates"
	"opnsense.systemInformationResponse.Updates": "Pending-update summary string from the system information endpoint. The firmware " +
		"collector exports the same thing structurally (package counts, upgrade sets); this " +
		"is its prose form.",
	// opnsense/system_memory.go:62  json:"size"
	"opnsense.systemMemoryMallocEntry.Size": "The Size(s) bucket list of a vmstat -m malloc zone (see the field's own comment). " +
		"Modelled so the canary validates the payload; a bucket list is not a metric.",
	// opnsense/system_memory.go:78  json:"__version"
	"opnsense.systemMemoryResponse.Version": "vmstat -m payload version marker. Purely a shape signal for the canary; nothing " +
		"branches on it.",
	// opnsense/system_resources.go:24  json:"uptime"
	"opnsense.systemTimeResponse.Uptime": "The API's preformatted uptime string. Uptime is computed from boottime instead, " +
		"because the string form is locale/DST-sensitive — dstCorrectedDiffSeconds exists for " +
		"exactly that reason.",
	// opnsense/temperature.go:7  json:"type_translated"
	"opnsense.temperatureReading.TypeTranslated": "Localised presentation copy of the sensor type. The untranslated type is exported; " +
		"adding the translated one would make the label set depend on the box's UI language.",
	// opnsense/unbound_dns.go:194  json:"dnscrypt_nonce"
	"opnsense.unboundDNSStatusResponse.Data.DnscryptNonce": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:195  json:"cache"
	"opnsense.unboundDNSStatusResponse.Data.DnscryptNonce.Cache": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:196  json:"count"
	"opnsense.unboundDNSStatusResponse.Data.DnscryptNonce.Cache.Count": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:189  json:"dnscrypt_shared_secret"
	"opnsense.unboundDNSStatusResponse.Data.DnscryptSharedSecret": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:190  json:"cache"
	"opnsense.unboundDNSStatusResponse.Data.DnscryptSharedSecret.Cache": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:191  json:"count"
	"opnsense.unboundDNSStatusResponse.Data.DnscryptSharedSecret.Cache.Count": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:79  json:"dnscrypt_nonce"
	"opnsense.unboundDNSStatusResponse.Data.Mem.Cache.DnscryptNonce": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:78  json:"dnscrypt_shared_secret"
	"opnsense.unboundDNSStatusResponse.Data.Mem.Cache.DnscryptSharedSecret": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:88  json:"http"
	"opnsense.unboundDNSStatusResponse.Data.Mem.HTTP": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:89  json:"query_buffer"
	"opnsense.unboundDNSStatusResponse.Data.Mem.HTTP.QueryBuffer": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:90  json:"response_buffer"
	"opnsense.unboundDNSStatusResponse.Data.Mem.HTTP.ResponseBuffer": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:85  json:"dynlibmod"
	"opnsense.unboundDNSStatusResponse.Data.Mem.Mod.Dynlibmod": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:170  json:"max_collisions"
	"opnsense.unboundDNSStatusResponse.Data.Msg.Cache.MaxCollisions": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:131  json:"aggressive"
	"opnsense.unboundDNSStatusResponse.Data.Num.Query.Aggressive": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:132  json:"NOERROR"
	"opnsense.unboundDNSStatusResponse.Data.Num.Query.Aggressive.Noerror": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:133  json:"NXDOMAIN"
	"opnsense.unboundDNSStatusResponse.Data.Num.Query.Aggressive.Nxdomain": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:141  json:"authzone"
	"opnsense.unboundDNSStatusResponse.Data.Num.Query.Authzone": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:143  json:"down"
	"opnsense.unboundDNSStatusResponse.Data.Num.Query.Authzone.Down": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:142  json:"up"
	"opnsense.unboundDNSStatusResponse.Data.Num.Query.Authzone.Up": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:101  json:"class"
	"opnsense.unboundDNSStatusResponse.Data.Num.Query.Class": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:102  json:"IN"
	"opnsense.unboundDNSStatusResponse.Data.Num.Query.Class.In": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:135  json:"dnscrypt"
	"opnsense.unboundDNSStatusResponse.Data.Num.Query.Dnscrypt": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:139  json:"replay"
	"opnsense.unboundDNSStatusResponse.Data.Num.Query.Dnscrypt.Replay": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:136  json:"shared_secret"
	"opnsense.unboundDNSStatusResponse.Data.Num.Query.Dnscrypt.SharedSecret": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:137  json:"cachemiss"
	"opnsense.unboundDNSStatusResponse.Data.Num.Query.Dnscrypt.SharedSecret.Cachemiss": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:104  json:"opcode"
	"opnsense.unboundDNSStatusResponse.Data.Num.Query.Opcode": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:105  json:"QUERY"
	"opnsense.unboundDNSStatusResponse.Data.Num.Query.Opcode.Query": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:130  json:"ratelimited"
	"opnsense.unboundDNSStatusResponse.Data.Num.Query.Ratelimited": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:112  json:"resume"
	"opnsense.unboundDNSStatusResponse.Data.Num.Query.TLS.Resume": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:176  json:"max_collisions"
	"opnsense.unboundDNSStatusResponse.Data.Rrset.Cache.MaxCollisions": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:62  json:"elapsed"
	"opnsense.unboundDNSStatusResponse.Data.Time.Elapsed": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:60  json:"now"
	"opnsense.unboundDNSStatusResponse.Data.Time.Now": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:28  json:"dnscrypt"
	"opnsense.unboundDNSStatusResponse.Data.Total.Num.Dnscrypt": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:30  json:"cert"
	"opnsense.unboundDNSStatusResponse.Data.Total.Num.Dnscrypt.Cert": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:31  json:"cleartext"
	"opnsense.unboundDNSStatusResponse.Data.Total.Num.Dnscrypt.Cleartext": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:29  json:"crypted"
	"opnsense.unboundDNSStatusResponse.Data.Total.Num.Dnscrypt.Crypted": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:32  json:"malformed"
	"opnsense.unboundDNSStatusResponse.Data.Total.Num.Dnscrypt.Malformed": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:16  json:"queries_cookie_client"
	"opnsense.unboundDNSStatusResponse.Data.Total.Num.QueriesCookieClient": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:17  json:"queries_cookie_invalid"
	"opnsense.unboundDNSStatusResponse.Data.Total.Num.QueriesCookieInvalid": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:15  json:"queries_cookie_valid"
	"opnsense.unboundDNSStatusResponse.Data.Total.Num.QueriesCookieValid": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:35  json:"query"
	"opnsense.unboundDNSStatusResponse.Data.Total.Query": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:36  json:"queue_time_us"
	"opnsense.unboundDNSStatusResponse.Data.Total.Query.QueueTimeUs": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:37  json:"max"
	"opnsense.unboundDNSStatusResponse.Data.Total.Query.QueueTimeUs.Max": "unbound statistics field modelled for schema fidelity so the live-box canary " +
		"validates the whole extended-statistics payload. The unbound collector exports a " +
		"chosen subset of these counters; this one is not in it, and nothing already exported " +
		"summarises over it.",
	// opnsense/unbound_dns.go:456  json:"status"
	"opnsense.unboundInfraResponse.Status": "configd/MVC envelope status string. The client's failure signal is the transport " +
		"result and the decode itself, never this field; decoded so the live-box schema " +
		"canary keeps validating the envelope's shape.",
	// opnsense/unbound_dns.go:747  json:"status"
	"opnsense.unboundInsecureDomainsResponse.Status": "configd/MVC envelope status string. The client's failure signal is the transport " +
		"result and the decode itself, never this field; decoded so the live-box schema " +
		"canary keeps validating the envelope's shape.",
	// opnsense/unbound_dns.go:732  json:"name"
	"opnsense.unboundLocalDataResponse.Data.Name": "Per-record local DNS override (name, type, ttl, value). The collector exports the " +
		"COUNT of local-data overrides; a series per record would grow with the box's host " +
		"overrides and carry hostnames as labels.",
	// opnsense/unbound_dns.go:735  json:"rrtype"
	"opnsense.unboundLocalDataResponse.Data.RRType": "Per-record local DNS override (name, type, ttl, value). The collector exports the " +
		"COUNT of local-data overrides; a series per record would grow with the box's host " +
		"overrides and carry hostnames as labels.",
	// opnsense/unbound_dns.go:733  json:"ttl"
	"opnsense.unboundLocalDataResponse.Data.TTL": "Per-record local DNS override (name, type, ttl, value). The collector exports the " +
		"COUNT of local-data overrides; a series per record would grow with the box's host " +
		"overrides and carry hostnames as labels.",
	// opnsense/unbound_dns.go:734  json:"type"
	"opnsense.unboundLocalDataResponse.Data.Type": "Per-record local DNS override (name, type, ttl, value). The collector exports the " +
		"COUNT of local-data overrides; a series per record would grow with the box's host " +
		"overrides and carry hostnames as labels.",
	// opnsense/unbound_dns.go:736  json:"value"
	"opnsense.unboundLocalDataResponse.Data.Value": "Per-record local DNS override (name, type, ttl, value). The collector exports the " +
		"COUNT of local-data overrides; a series per record would grow with the box's host " +
		"overrides and carry hostnames as labels.",
	// opnsense/unbound_dns.go:730  json:"status"
	"opnsense.unboundLocalDataResponse.Status": "configd/MVC envelope status string. The client's failure signal is the transport " +
		"result and the decode itself, never this field; decoded so the live-box schema " +
		"canary keeps validating the envelope's shape.",
	// opnsense/unbound_dns.go:721  json:"zone"
	"opnsense.unboundLocalZonesResponse.Data.Zone": "Per-zone override name. The collector exports the COUNT of local zones; one series " +
		"per configured override name would grow with the box's blocklists.",
	// opnsense/unbound_dns.go:719  json:"status"
	"opnsense.unboundLocalZonesResponse.Status": "configd/MVC envelope status string. The client's failure signal is the transport " +
		"result and the decode itself, never this field; decoded so the live-box schema " +
		"canary keeps validating the envelope's shape.",
	// opnsense/unbound_search_queries.go:20  json:"current"
	"opnsense.unboundSearchQueriesResponse.Current": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/unbound_search_queries.go:19  json:"rowCount"
	"opnsense.unboundSearchQueriesResponse.RowCount": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/unbound_search_queries.go:18  json:"total"
	"opnsense.unboundSearchQueriesResponse.Total": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/vnstat.go:41  json:"name"
	"opnsense.vnstatJSONInterface.Name": "Interface name inside the vnstat JSON body. The collector keys its series on the " +
		"interface it asked for (the ?iface= query parameter), so the echoed name is " +
		"redundant.",
	// opnsense/wireguard.go:19  json:"current"
	"opnsense.wireguardClientsResponse.Current": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/wireguard.go:17  json:"rowCount"
	"opnsense.wireguardClientsResponse.RowCount": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
	// opnsense/wireguard.go:18  json:"total"
	"opnsense.wireguardClientsResponse.Total": "Bootgrid envelope pagination field. The exporter asks for every row in a single page " +
		"and counts the rows it decoded, so page state is never consulted; it stays decoded " +
		"so the live-box schema canary keeps validating the envelope's shape.",
}
