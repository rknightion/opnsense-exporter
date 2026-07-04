package options

import "github.com/alecthomas/kingpin/v2"

var (
	arpTableCollectorDisabled = kingpin.Flag(
		"exporter.disable-arp-table",
		"Disable the scraping of the ARP table",
	).Envar("OPNSENSE_EXPORTER_DISABLE_ARP_TABLE").Default("false").Bool()
	interfacesCollectorDisabled = kingpin.Flag(
		"exporter.disable-interfaces",
		"Disable the interfaces collector (per-interface traffic/link metrics)",
	).Envar("OPNSENSE_EXPORTER_DISABLE_INTERFACES").Default("false").Bool()
	protocolCollectorDisabled = kingpin.Flag(
		"exporter.disable-protocol",
		"Disable the protocol-statistics collector (TCP/UDP/IP/ICMP/ARP/CARP/pfsync counters)",
	).Envar("OPNSENSE_EXPORTER_DISABLE_PROTOCOL").Default("false").Bool()
	servicesCollectorDisabled = kingpin.Flag(
		"exporter.disable-services",
		"Disable the services collector (per-service running state)",
	).Envar("OPNSENSE_EXPORTER_DISABLE_SERVICES").Default("false").Bool()
	arpDetailsEnabled = kingpin.Flag(
		"exporter.enable-arp-details",
		"Enable per-entry ARP metrics (ip/mac/hostname labels — high, churning cardinality). Off by default; the low-cardinality entries_total aggregate is always emitted.",
	).Envar("OPNSENSE_EXPORTER_ENABLE_ARP_DETAILS").Default("false").Bool()
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
	ndpDetailsEnabled = kingpin.Flag(
		"exporter.enable-ndp-details",
		"Enable per-entry NDP metrics (ip/mac labels — high, churning cardinality from IPv6 privacy-address rotation). Off by default; the low-cardinality entries_total aggregate is always emitted.",
	).Envar("OPNSENSE_EXPORTER_ENABLE_NDP_DETAILS").Default("false").Bool()
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
	// SMART is opt-in (default-off): each scrape does a per-disk POST fanout that makes
	// OPNsense shell out `smartctl -a` per disk, with no standby guard — so a default-on
	// collector would spin up power-saving disks every scrape interval. This matches the
	// CLAUDE.md convention that reserves enable-* for collectors with extra per-scrape API
	// cost (#139).
	smartEnabled = kingpin.Flag(
		"exporter.enable-smart",
		"Enable the SMART disk health collector. Off by default: each scrape does a per-disk POST fanout that runs `smartctl -a` on the firewall (extra API/latency cost, and wakes spun-down disks). Silent when the os-smart plugin is absent.",
	).Envar("OPNSENSE_EXPORTER_ENABLE_SMART").Default("false").Bool()
	dyndnsCollectorDisabled = kingpin.Flag(
		"exporter.disable-dyndns",
		"Disable the scraping of DynDNS (ddclient) account update status metrics (silent when the os-ddclient plugin is absent)",
	).Envar("OPNSENSE_EXPORTER_DISABLE_DYNDNS").Default("false").Bool()
	gatewaysCollectorDisabled = kingpin.Flag(
		"exporter.disable-gateways",
		"Disable the scraping of gateway status metrics (RTT, packet loss, gateway state)",
	).Envar("OPNSENSE_EXPORTER_DISABLE_GATEWAYS").Default("false").Bool()
	syslogCollectorDisabled = kingpin.Flag(
		"exporter.disable-syslog",
		"Disable the scraping of syslog-ng statistics",
	).Envar("OPNSENSE_EXPORTER_DISABLE_SYSLOG").Default("false").Bool()
	qfeedsCollectorDisabled = kingpin.Flag(
		"exporter.disable-qfeeds",
		"Disable the scraping of Q-Feeds threat intelligence statistics (silent when the os-q-feeds-connector plugin is absent)",
	).Envar("OPNSENSE_EXPORTER_DISABLE_QFEEDS").Default("false").Bool()
	tailscaleCollectorDisabled = kingpin.Flag(
		"exporter.disable-tailscale",
		"Disable the scraping of Tailscale node-local metrics (silent when the os-tailscale plugin is absent; complementary to tailscale2otel)",
	).Envar("OPNSENSE_EXPORTER_DISABLE_TAILSCALE").Default("false").Bool()
	tailscalePeerDetailsEnabled = kingpin.Flag(
		"exporter.enable-tailscale-peer-details",
		"Enable per-peer detail metrics for Tailscale (per-peer cardinality; peer hostname labels)",
	).Envar("OPNSENSE_EXPORTER_ENABLE_TAILSCALE_PEER_DETAILS").Default("false").Bool()
	aliasCollectorDisabled = kingpin.Flag(
		"exporter.disable-alias",
		"Disable the scraping of firewall alias table sizes",
	).Envar("OPNSENSE_EXPORTER_DISABLE_ALIAS").Default("false").Bool()
	aliasDetailsEnabled = kingpin.Flag(
		"exporter.enable-alias-details",
		"Enable per-table pf evaluation/packet/byte counters for firewall aliases (~10 series per alias table)",
	).Envar("OPNSENSE_EXPORTER_ENABLE_ALIAS_DETAILS").Default("false").Bool()
	haproxyCollectorDisabled = kingpin.Flag(
		"exporter.disable-haproxy",
		"Disable the scraping of HAProxy statistics (silent when the os-haproxy plugin is absent)",
	).Envar("OPNSENSE_EXPORTER_DISABLE_HAPROXY").Default("false").Bool()
	nginxCollectorDisabled = kingpin.Flag(
		"exporter.disable-nginx",
		"Disable the scraping of nginx VTS statistics (silent when the os-nginx plugin is absent)",
	).Envar("OPNSENSE_EXPORTER_DISABLE_NGINX").Default("false").Bool()
	frrCollectorDisabled = kingpin.Flag(
		"exporter.disable-frr",
		"Disable the scraping of FRR routing metrics (BGP/OSPF/BFD; silent when the os-frr plugin is absent)",
	).Envar("OPNSENSE_EXPORTER_DISABLE_FRR").Default("false").Bool()
	monitCollectorDisabled = kingpin.Flag(
		"exporter.disable-monit",
		"Disable the scraping of Monit service check status (silent when Monit is not running)",
	).Envar("OPNSENSE_EXPORTER_DISABLE_MONIT").Default("false").Bool()
	crowdsecCollectorDisabled = kingpin.Flag(
		"exporter.disable-crowdsec",
		"Disable the scraping of CrowdSec alert/decision/bouncer/machine counts (silent when the os-crowdsec plugin is absent)",
	).Envar("OPNSENSE_EXPORTER_DISABLE_CROWDSEC").Default("false").Bool()
	nutCollectorDisabled = kingpin.Flag(
		"exporter.disable-nut",
		"Disable the scraping of NUT UPS metrics (silent when the os-nut plugin is absent)",
	).Envar("OPNSENSE_EXPORTER_DISABLE_NUT").Default("false").Bool()
	apcupsdCollectorDisabled = kingpin.Flag(
		"exporter.disable-apcupsd",
		"Disable the scraping of APC UPS (apcupsd) metrics (silent when the os-apcupsd plugin is absent)",
	).Envar("OPNSENSE_EXPORTER_DISABLE_APCUPSD").Default("false").Bool()
	captivePortalCollectorDisabled = kingpin.Flag(
		"exporter.disable-captiveportal",
		"Disable the scraping of captive portal zone/session metrics (silent when no zones are configured)",
	).Envar("OPNSENSE_EXPORTER_DISABLE_CAPTIVEPORTAL").Default("false").Bool()
	trafficShaperCollectorDisabled = kingpin.Flag(
		"exporter.disable-trafficshaper",
		"Disable the scraping of traffic shaper pipe/queue/rule statistics (silent when the shaper is unconfigured)",
	).Envar("OPNSENSE_EXPORTER_DISABLE_TRAFFICSHAPER").Default("false").Bool()
	hasyncEnabled = kingpin.Flag(
		"exporter.enable-hasync",
		"Enable the HA sync status collector (performs a live XML-RPC call to the CARP peer on every scrape). Disabled by default.",
	).Envar("OPNSENSE_EXPORTER_ENABLE_HASYNC").Default("false").Bool()
	chronyCollectorDisabled = kingpin.Flag(
		"exporter.disable-chrony",
		"Disable the scraping of chrony NTP tracking/source metrics (silent when the os-chrony plugin is absent)",
	).Envar("OPNSENSE_EXPORTER_DISABLE_CHRONY").Default("false").Bool()
	dhcpv6CollectorDisabled = kingpin.Flag(
		"exporter.disable-dhcpv6",
		"Disable the scraping of ISC DHCPv6 leases and delegated prefixes (silent when the legacy ISC DHCP backend is absent)",
	).Envar("OPNSENSE_EXPORTER_DISABLE_DHCPV6").Default("false").Bool()
	dhcpv6DetailsEnabled = kingpin.Flag(
		"exporter.enable-dhcpv6-details",
		"Enable per-lease detail metrics for ISC DHCPv6 (high cardinality on large networks)",
	).Envar("OPNSENSE_EXPORTER_ENABLE_DHCPV6_DETAILS").Default("false").Bool()
	bpfCollectorDisabled = kingpin.Flag(
		"exporter.disable-bpf",
		"Disable the scraping of BPF listener statistics",
	).Envar("OPNSENSE_EXPORTER_DISABLE_BPF").Default("false").Bool()
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
	Syslog                 bool
	QFeeds                 bool
	Tailscale              bool
	TailscalePeerDetails   bool
	Alias                  bool
	AliasDetails           bool
	HAProxy                bool
	Nginx                  bool
	FRR                    bool
	Monit                  bool
	CrowdSec               bool
	NUT                    bool
	Apcupsd                bool
	CaptivePortal          bool
	TrafficShaper          bool
	Hasync                 bool
	Chrony                 bool
	Dhcpv6                 bool
	Dhcpv6Details          bool
	BPF                    bool
	ArpDetails             bool
	NdpDetails             bool
	Interfaces             bool
	Protocol               bool
	Services               bool
}

// CollectorsSwitches returns configured instances of CollectorsDisableSwitch
func CollectorsSwitches() CollectorsDisableSwitch {
	return CollectorsDisableSwitch{
		ARP:                    !*arpTableCollectorDisabled,
		ArpDetails:             *arpDetailsEnabled,
		NdpDetails:             *ndpDetailsEnabled,
		Interfaces:             !*interfacesCollectorDisabled,
		Protocol:               !*protocolCollectorDisabled,
		Services:               !*servicesCollectorDisabled,
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
		SMART:                  *smartEnabled,
		DynDNS:                 !*dyndnsCollectorDisabled,
		Gateways:               !*gatewaysCollectorDisabled,
		Syslog:                 !*syslogCollectorDisabled,
		QFeeds:                 !*qfeedsCollectorDisabled,
		Tailscale:              !*tailscaleCollectorDisabled,
		TailscalePeerDetails:   *tailscalePeerDetailsEnabled,
		Alias:                  !*aliasCollectorDisabled,
		AliasDetails:           *aliasDetailsEnabled,
		HAProxy:                !*haproxyCollectorDisabled,
		Nginx:                  !*nginxCollectorDisabled,
		FRR:                    !*frrCollectorDisabled,
		Monit:                  !*monitCollectorDisabled,
		CrowdSec:               !*crowdsecCollectorDisabled,
		NUT:                    !*nutCollectorDisabled,
		Apcupsd:                !*apcupsdCollectorDisabled,
		CaptivePortal:          !*captivePortalCollectorDisabled,
		TrafficShaper:          !*trafficShaperCollectorDisabled,
		Hasync:                 *hasyncEnabled,
		Chrony:                 !*chronyCollectorDisabled,
		Dhcpv6:                 !*dhcpv6CollectorDisabled,
		Dhcpv6Details:          *dhcpv6DetailsEnabled,
		BPF:                    !*bpfCollectorDisabled,
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
	{Flag: "exporter.disable-interfaces", Subsystem: "interfaces"},
	{Flag: "exporter.disable-protocol", Subsystem: "protocol"},
	{Flag: "exporter.disable-services", Subsystem: "services"},
	{Flag: "exporter.enable-arp-details", Subsystem: "arp_table", Detail: true},
	{Flag: "exporter.enable-ndp-details", Subsystem: "ndp", Detail: true},
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
	{Flag: "exporter.enable-smart", Subsystem: "smart"},
	{Flag: "exporter.disable-dyndns", Subsystem: "dyndns"},
	{Flag: "exporter.disable-gateways", Subsystem: "gateways"},
	{Flag: "exporter.disable-syslog", Subsystem: "syslog"},
	{Flag: "exporter.disable-qfeeds", Subsystem: "qfeeds"},
	{Flag: "exporter.disable-tailscale", Subsystem: "tailscale"},
	{Flag: "exporter.enable-tailscale-peer-details", Subsystem: "tailscale", Detail: true},
	{Flag: "exporter.disable-alias", Subsystem: "alias"},
	{Flag: "exporter.enable-alias-details", Subsystem: "alias", Detail: true},
	{Flag: "exporter.disable-haproxy", Subsystem: "haproxy"},
	{Flag: "exporter.disable-nginx", Subsystem: "nginx"},
	{Flag: "exporter.disable-frr", Subsystem: "frr"},
	{Flag: "exporter.disable-monit", Subsystem: "monit"},
	{Flag: "exporter.disable-crowdsec", Subsystem: "crowdsec"},
	{Flag: "exporter.disable-nut", Subsystem: "nut"},
	{Flag: "exporter.disable-apcupsd", Subsystem: "apcupsd"},
	{Flag: "exporter.disable-captiveportal", Subsystem: "captiveportal"},
	{Flag: "exporter.disable-trafficshaper", Subsystem: "trafficshaper"},
	{Flag: "exporter.enable-hasync", Subsystem: "hasync"},
	{Flag: "exporter.disable-chrony", Subsystem: "chrony"},
	{Flag: "exporter.disable-dhcpv6", Subsystem: "dhcpv6"},
	{Flag: "exporter.enable-dhcpv6-details", Subsystem: "dhcpv6", Detail: true},
	{Flag: "exporter.disable-bpf", Subsystem: "bpf"},
}
