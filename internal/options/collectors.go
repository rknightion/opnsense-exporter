package options

import "github.com/alecthomas/kingpin/v2"

var (
	arpTableCollectorDisabled = kingpin.Flag(
		"exporter.disable-arp-table",
		"Disable the scraping of the ARP table",
	).Envar("OPNSENSE_EXPORTER_DISABLE_ARP_TABLE").Default("false").Bool()
	cronTableCollectorDisabled = kingpin.Flag(
		"exporter.disable-cron-table",
		"Disable the scraping of the cron table",
	).Envar("OPNSENSE_EXPORTER_DISABLE_CRON_TABLE").Default("false").Bool()
	wireguardCollectorDisabled = kingpin.Flag(
		"exporter.disable-wireguard",
		"Disable the scraping of Wireguard service",
	).Envar("OPNSENSE_EXPORTER_DISABLE_WIREGUARD").Default("false").Bool()
	ipsecCollectorDisabled = kingpin.Flag(
		"exporter.disable-ipsec",
		"Disable the scraping of IPSec service",
	).Envar("OPNSENSE_EXPORTER_DISABLE_IPSEC").Default("false").Bool()
	unboundCollectorDisabled = kingpin.Flag(
		"exporter.disable-unbound",
		"Disable the scraping of Unbound service",
	).Envar("OPNSENSE_EXPORTER_DISABLE_UNBOUND").Default("false").Bool()
	unboundInfraEnabled = kingpin.Flag(
		"exporter.enable-unbound-infra",
		"Enable per-upstream infra cache RTT metrics from Unbound (cardinality scales with the resolver's infra cache; one series pair per upstream ip/host)",
	).Envar("OPNSENSE_EXPORTER_ENABLE_UNBOUND_INFRA").Default("false").Bool()
	openVPNCollectorDisabled = kingpin.Flag(
		"exporter.disable-openvpn",
		"Disable the scraping of OpenVPN service",
	).Envar("OPNSENSE_EXPORTER_DISABLE_OPENVPN").Default("false").Bool()
	openVPNDetailsEnabled = kingpin.Flag(
		"exporter.enable-openvpn-details",
		"Enable per-session detail metrics for OpenVPN (exposes usernames and per-client tunnel addresses)",
	).Envar("OPNSENSE_EXPORTER_ENABLE_OPENVPN_DETAILS").Default("false").Bool()
	firewallCollectorDisabled = kingpin.Flag(
		"exporter.disable-firewall",
		"Disable the scraping of the firewall (pf) metrics",
	).Envar("OPNSENSE_EXPORTER_DISABLE_FIREWALL").Default("false").Bool()
	firmwareCollectorDisabled = kingpin.Flag(
		"exporter.disable-firmware",
		"Disable the scraping of the firmware metrics",
	).Envar("OPNSENSE_EXPORTER_DISABLE_FIRMWARE").Default("false").Bool()
	firmwarePackageDetailsEnabled = kingpin.Flag(
		"exporter.enable-firmware-package-details",
		"Enable per-package firmware detail metrics (pending package updates and installed plugin inventory; adds one extra API call per scrape)",
	).Envar("OPNSENSE_EXPORTER_ENABLE_FIRMWARE_PACKAGE_DETAILS").Default("false").Bool()
	systemCollectorDisabled = kingpin.Flag(
		"exporter.disable-system",
		"Disable the scraping of system resource metrics (memory, uptime, disk, swap)",
	).Envar("OPNSENSE_EXPORTER_DISABLE_SYSTEM").Default("false").Bool()
	temperatureCollectorDisabled = kingpin.Flag(
		"exporter.disable-temperature",
		"Disable the scraping of temperature metrics",
	).Envar("OPNSENSE_EXPORTER_DISABLE_TEMPERATURE").Default("false").Bool()
	dnsmasqCollectorDisabled = kingpin.Flag(
		"exporter.disable-dnsmasq",
		"Disable the scraping of Dnsmasq DHCP leases",
	).Envar("OPNSENSE_EXPORTER_DISABLE_DNSMASQ").Default("false").Bool()
	dnsmasqDetailsEnabled = kingpin.Flag(
		"exporter.enable-dnsmasq-details",
		"Enable per-lease detail metrics for Dnsmasq DHCP (high cardinality on large networks)",
	).Envar("OPNSENSE_EXPORTER_ENABLE_DNSMASQ_DETAILS").Default("false").Bool()
	firewallRulesCollectorDisabled = kingpin.Flag(
		"exporter.disable-firewall-rules",
		"Disable the scraping of firewall rule statistics",
	).Envar("OPNSENSE_EXPORTER_DISABLE_FIREWALL_RULES").Default("false").Bool()
	firewallRulesDetailsEnabled = kingpin.Flag(
		"exporter.enable-firewall-rules-details",
		"Enable per-rule detail metrics for firewall rules (high cardinality on large rulesets)",
	).Envar("OPNSENSE_EXPORTER_ENABLE_FIREWALL_RULES_DETAILS").Default("false").Bool()
	mbufCollectorDisabled = kingpin.Flag(
		"exporter.disable-mbuf",
		"Disable the scraping of mbuf statistics",
	).Envar("OPNSENSE_EXPORTER_DISABLE_MBUF").Default("false").Bool()
	ntpCollectorDisabled = kingpin.Flag(
		"exporter.disable-ntp",
		"Disable the scraping of NTP peer metrics",
	).Envar("OPNSENSE_EXPORTER_DISABLE_NTP").Default("false").Bool()
	certificatesCollectorDisabled = kingpin.Flag(
		"exporter.disable-certificates",
		"Disable the scraping of certificate expiry metrics",
	).Envar("OPNSENSE_EXPORTER_DISABLE_CERTIFICATES").Default("false").Bool()
	carpCollectorDisabled = kingpin.Flag(
		"exporter.disable-carp",
		"Disable the scraping of CARP/VIP status metrics",
	).Envar("OPNSENSE_EXPORTER_DISABLE_CARP").Default("false").Bool()
	activityCollectorDisabled = kingpin.Flag(
		"exporter.disable-activity",
		"Disable the scraping of system activity metrics (CPU percentages, thread counts)",
	).Envar("OPNSENSE_EXPORTER_DISABLE_ACTIVITY").Default("false").Bool()
	keaCollectorDisabled = kingpin.Flag(
		"exporter.disable-kea",
		"Disable the scraping of Kea DHCP lease metrics",
	).Envar("OPNSENSE_EXPORTER_DISABLE_KEA").Default("false").Bool()
	keaDetailsEnabled = kingpin.Flag(
		"exporter.enable-kea-details",
		"Enable per-lease detail metrics for Kea DHCP (high cardinality on large networks)",
	).Envar("OPNSENSE_EXPORTER_ENABLE_KEA_DETAILS").Default("false").Bool()
	networkDiagnosticsEnabled = kingpin.Flag(
		"exporter.enable-network-diagnostics",
		"Enable the network diagnostics collector (netisr, sockets, routes). Disabled by default.",
	).Envar("OPNSENSE_EXPORTER_ENABLE_NETWORK_DIAGNOSTICS").Default("false").Bool()
	netflowEnabled = kingpin.Flag(
		"exporter.enable-netflow",
		"Enable the netflow collector (enabled status, service status, cache stats). Disabled by default.",
	).Envar("OPNSENSE_EXPORTER_ENABLE_NETFLOW").Default("false").Bool()
	pfStatsCollectorDisabled = kingpin.Flag(
		"exporter.disable-pf-stats",
		"Disable the scraping of PF statistics (state table, counters, memory limits, timeouts)",
	).Envar("OPNSENSE_EXPORTER_DISABLE_PF_STATS").Default("false").Bool()
	ndpCollectorDisabled = kingpin.Flag(
		"exporter.disable-ndp",
		"Disable the scraping of the NDP (IPv6 neighbor discovery) table",
	).Envar("OPNSENSE_EXPORTER_DISABLE_NDP").Default("false").Bool()
	dhcpv4CollectorDisabled = kingpin.Flag(
		"exporter.disable-dhcpv4",
		"Disable the scraping of ISC DHCPv4 leases (silent when the legacy ISC DHCP backend is absent)",
	).Envar("OPNSENSE_EXPORTER_DISABLE_DHCPV4").Default("false").Bool()
	dhcpv4DetailsEnabled = kingpin.Flag(
		"exporter.enable-dhcpv4-details",
		"Enable per-lease detail metrics for ISC DHCPv4 (high cardinality on large networks)",
	).Envar("OPNSENSE_EXPORTER_ENABLE_DHCPV4_DETAILS").Default("false").Bool()
	acmeCollectorDisabled = kingpin.Flag(
		"exporter.disable-acme",
		"Disable the scraping of ACME client certificate renewal status and expiry metrics (silent when the os-acme-client plugin is absent)",
	).Envar("OPNSENSE_EXPORTER_DISABLE_ACME").Default("false").Bool()
	smartCollectorDisabled = kingpin.Flag(
		"exporter.disable-smart",
		"Disable the SMART disk health collector (per-disk POST fanout; silent when the os-smart plugin is absent)",
	).Envar("OPNSENSE_EXPORTER_DISABLE_SMART").Default("false").Bool()
	dyndnsCollectorDisabled = kingpin.Flag(
		"exporter.disable-dyndns",
		"Disable the scraping of DynDNS (ddclient) account update status metrics (silent when the os-ddclient plugin is absent)",
	).Envar("OPNSENSE_EXPORTER_DISABLE_DYNDNS").Default("false").Bool()
	gatewaysCollectorDisabled = kingpin.Flag(
		"exporter.disable-gateways",
		"Disable the scraping of gateway status metrics (RTT, packet loss, gateway state)",
	).Envar("OPNSENSE_EXPORTER_DISABLE_GATEWAYS").Default("false").Bool()
)

// CollectorsDisableSwitch hold the enabled/disabled state of the collectors
type CollectorsDisableSwitch struct {
	ARP                    bool
	Cron                   bool
	Wireguard              bool
	IPsec                  bool
	Unbound                bool
	UnboundInfra           bool
	OpenVPN                bool
	OpenVPNDetails         bool
	Firewall               bool
	Firmware               bool
	FirmwarePackageDetails bool
	Dnsmasq                bool
	DnsmasqDetails         bool
	FirewallRules          bool
	FirewallRulesDetails   bool
	System                 bool
	Temperature            bool
	Mbuf                   bool
	NTP                    bool
	Certificates           bool
	CARP                   bool
	Activity               bool
	Kea                    bool
	KeaDetails             bool
	NetworkDiagnostics     bool
	Netflow                bool
	PFStats                bool
	NDP                    bool
	Dhcpv4                 bool
	Dhcpv4Details          bool
	ACME                   bool
	SMART                  bool
	DynDNS                 bool
	Gateways               bool
}

// CollectorsSwitches returns configured instances of CollectorsDisableSwitch
func CollectorsSwitches() CollectorsDisableSwitch {
	return CollectorsDisableSwitch{
		ARP:                    !*arpTableCollectorDisabled,
		Cron:                   !*cronTableCollectorDisabled,
		Wireguard:              !*wireguardCollectorDisabled,
		IPsec:                  !*ipsecCollectorDisabled,
		Unbound:                !*unboundCollectorDisabled,
		UnboundInfra:           *unboundInfraEnabled,
		OpenVPN:                !*openVPNCollectorDisabled,
		OpenVPNDetails:         *openVPNDetailsEnabled,
		Firewall:               !*firewallCollectorDisabled,
		Firmware:               !*firmwareCollectorDisabled,
		FirmwarePackageDetails: *firmwarePackageDetailsEnabled,
		Dnsmasq:                !*dnsmasqCollectorDisabled,
		DnsmasqDetails:         *dnsmasqDetailsEnabled,
		FirewallRules:          !*firewallRulesCollectorDisabled,
		FirewallRulesDetails:   *firewallRulesDetailsEnabled,
		System:                 !*systemCollectorDisabled,
		Temperature:            !*temperatureCollectorDisabled,
		Mbuf:                   !*mbufCollectorDisabled,
		NTP:                    !*ntpCollectorDisabled,
		Certificates:           !*certificatesCollectorDisabled,
		CARP:                   !*carpCollectorDisabled,
		Activity:               !*activityCollectorDisabled,
		Kea:                    !*keaCollectorDisabled,
		KeaDetails:             *keaDetailsEnabled,
		NetworkDiagnostics:     *networkDiagnosticsEnabled,
		Netflow:                *netflowEnabled,
		PFStats:                !*pfStatsCollectorDisabled,
		NDP:                    !*ndpCollectorDisabled,
		Dhcpv4:                 !*dhcpv4CollectorDisabled,
		Dhcpv4Details:          *dhcpv4DetailsEnabled,
		ACME:                   !*acmeCollectorDisabled,
		SMART:                  !*smartCollectorDisabled,
		DynDNS:                 !*dyndnsCollectorDisabled,
		Gateways:               !*gatewaysCollectorDisabled,
	}
}

// CollectorFlag binds a collector switch flag to the collector subsystem it
// controls. scripts/docgen consumes this to group and label generated
// documentation; TestCollectorFlagsCoverAllSwitchFlags fails when a new
// exporter.disable-*/enable-* flag is added without an entry here.
type CollectorFlag struct {
	Flag      string // kingpin flag name without leading --
	Subsystem string // collector.XxxSubsystem constant
	Detail    bool   // true when the flag toggles extra detail metrics rather than the collector itself
}

// CollectorFlags lists every collector switch flag.
// The Subsystem values must match the XxxSubsystem constants in internal/collector/collector.go.
// (collector cannot be imported here: opnsense/client.go already imports options, which
// would create a cycle. The concurrent lane adding SubsystemDisplayNames to collector.go
// does not break that existing chain.)
var CollectorFlags = []CollectorFlag{
	{Flag: "exporter.disable-arp-table", Subsystem: "arp_table"},
	{Flag: "exporter.disable-cron-table", Subsystem: "cron"},
	{Flag: "exporter.disable-wireguard", Subsystem: "wireguard"},
	{Flag: "exporter.disable-ipsec", Subsystem: "ipsec"},
	{Flag: "exporter.disable-unbound", Subsystem: "unbound_dns"},
	{Flag: "exporter.enable-unbound-infra", Subsystem: "unbound_dns", Detail: true},
	{Flag: "exporter.disable-openvpn", Subsystem: "openvpn"},
	{Flag: "exporter.enable-openvpn-details", Subsystem: "openvpn", Detail: true},
	{Flag: "exporter.disable-firewall", Subsystem: "firewall"},
	{Flag: "exporter.disable-firmware", Subsystem: "firmware"},
	{Flag: "exporter.enable-firmware-package-details", Subsystem: "firmware", Detail: true},
	{Flag: "exporter.disable-system", Subsystem: "system"},
	{Flag: "exporter.disable-temperature", Subsystem: "temperature"},
	{Flag: "exporter.disable-dnsmasq", Subsystem: "dnsmasq"},
	{Flag: "exporter.enable-dnsmasq-details", Subsystem: "dnsmasq", Detail: true},
	{Flag: "exporter.disable-firewall-rules", Subsystem: "firewall_rule"},
	{Flag: "exporter.enable-firewall-rules-details", Subsystem: "firewall_rule", Detail: true},
	{Flag: "exporter.disable-mbuf", Subsystem: "mbuf"},
	{Flag: "exporter.disable-ntp", Subsystem: "ntp"},
	{Flag: "exporter.disable-certificates", Subsystem: "certificate"},
	{Flag: "exporter.disable-carp", Subsystem: "carp"},
	{Flag: "exporter.disable-activity", Subsystem: "activity"},
	{Flag: "exporter.disable-kea", Subsystem: "kea"},
	{Flag: "exporter.enable-kea-details", Subsystem: "kea", Detail: true},
	{Flag: "exporter.enable-network-diagnostics", Subsystem: "network_diag"},
	{Flag: "exporter.enable-netflow", Subsystem: "netflow"},
	{Flag: "exporter.disable-pf-stats", Subsystem: "pf_stats"},
	{Flag: "exporter.disable-ndp", Subsystem: "ndp"},
	{Flag: "exporter.disable-dhcpv4", Subsystem: "dhcpv4"},
	{Flag: "exporter.enable-dhcpv4-details", Subsystem: "dhcpv4", Detail: true},
	{Flag: "exporter.disable-acme", Subsystem: "acme"},
	{Flag: "exporter.disable-smart", Subsystem: "smart"},
	{Flag: "exporter.disable-dyndns", Subsystem: "dyndns"},
	{Flag: "exporter.disable-gateways", Subsystem: "gateways"},
}
