package options

import (
	"os"

	"github.com/alecthomas/kingpin/v2"
)

var (
	arpTableCollectorDisabled = kingpin.Flag(
		"exporter.disable-arp-table",
		"Disable the scraping of the ARP table",
	).Envar("OPN2OTEL_DISABLE_ARP_TABLE").Default("false").Bool()
	interfacesCollectorDisabled = kingpin.Flag(
		"exporter.disable-interfaces",
		"Disable the interfaces collector (per-interface traffic/link metrics)",
	).Envar("OPN2OTEL_DISABLE_INTERFACES").Default("false").Bool()
	protocolCollectorDisabled = kingpin.Flag(
		"exporter.disable-protocol",
		"Disable the protocol-statistics collector (TCP/UDP/IP/ICMP/ARP/CARP/pfsync counters)",
	).Envar("OPN2OTEL_DISABLE_PROTOCOL").Default("false").Bool()
	servicesCollectorDisabled = kingpin.Flag(
		"exporter.disable-services",
		"Disable the services collector (per-service running state)",
	).Envar("OPN2OTEL_DISABLE_SERVICES").Default("false").Bool()
	arpDetailsEnabled = kingpin.Flag(
		"exporter.enable-arp-details",
		"Enable per-entry ARP metrics (ip/mac/hostname labels - high, churning cardinality). Off by default; the low-cardinality entries_total aggregate is always emitted.",
	).Envar("OPN2OTEL_ENABLE_ARP_DETAILS").Default("false").IsSetByUser(&arpDetailsEnabledUserSet).Bool()
	cronTableCollectorDisabled = kingpin.Flag(
		"exporter.disable-cron-table",
		"Disable the scraping of the cron table",
	).Envar("OPN2OTEL_DISABLE_CRON_TABLE").Default("false").Bool()
	wireguardCollectorDisabled = kingpin.Flag(
		"exporter.disable-wireguard",
		"Disable the scraping of Wireguard service",
	).Envar("OPN2OTEL_DISABLE_WIREGUARD").Default("false").Bool()
	ipsecCollectorDisabled = kingpin.Flag(
		"exporter.disable-ipsec",
		"Disable the scraping of IPSec service",
	).Envar("OPN2OTEL_DISABLE_IPSEC").Default("false").Bool()
	ipsecLeaseDetailsEnabled = kingpin.Flag(
		"exporter.enable-ipsec-lease-details",
		"Enable per-lease IPsec mode-cfg detail metrics (opnsense_ipsec_lease_online with an unbounded road-warrior user label). Off by default; the per-pool lease aggregates stay always-on.",
	).Envar("OPN2OTEL_ENABLE_IPSEC_LEASE_DETAILS").Default("false").IsSetByUser(&ipsecLeaseDetailsEnabledUserSet).Bool()
	unboundCollectorDisabled = kingpin.Flag(
		"exporter.disable-unbound",
		"Disable the scraping of Unbound service",
	).Envar("OPN2OTEL_DISABLE_UNBOUND").Default("false").Bool()
	unboundInfraEnabled = kingpin.Flag(
		"exporter.enable-unbound-infra",
		"Enable per-upstream infra cache RTT metrics from Unbound (cardinality scales with the resolver's infra cache; one series pair per upstream ip/host)",
	).Envar("OPN2OTEL_ENABLE_UNBOUND_INFRA").Default("false").IsSetByUser(&unboundInfraEnabledUserSet).Bool()
	unboundQStatsEnabled = kingpin.Flag(
		"exporter.enable-unbound-qstats",
		"Enable Unbound DNSBL query-stats totals and blocklist size metrics, plus local-zone/data/insecure-domain counts. Off by default: the query-stats totals call is backed by an expensive configd+python+pandas+DuckDB query (~1s per scheduled poll) - skipped entirely while query-stats logging (general.stats) is off on the box, but still paid for on every scheduled poll once it is on.",
	).Envar("OPN2OTEL_ENABLE_UNBOUND_QSTATS").Default("false").IsSetByUser(&unboundQStatsEnabledUserSet).Bool()
	openVPNCollectorDisabled = kingpin.Flag(
		"exporter.disable-openvpn",
		"Disable the scraping of OpenVPN service",
	).Envar("OPN2OTEL_DISABLE_OPENVPN").Default("false").Bool()
	openVPNDetailsEnabled = kingpin.Flag(
		"exporter.enable-openvpn-details",
		"Enable per-session detail metrics for OpenVPN (exposes usernames and per-client tunnel addresses)",
	).Envar("OPN2OTEL_ENABLE_OPENVPN_DETAILS").Default("false").IsSetByUser(&openVPNDetailsEnabledUserSet).Bool()
	firewallCollectorDisabled = kingpin.Flag(
		"exporter.disable-firewall",
		"Disable the scraping of the firewall (pf) metrics",
	).Envar("OPN2OTEL_DISABLE_FIREWALL").Default("false").Bool()
	// NAT rule inventory counts are opt-in (default-off, #221): each scheduled poll does
	// four extra GETs (one per MVC-managed NAT rule type: source_nat, d_nat,
	// one_to_one, npt) on top of the always-on pf/GeoIP calls, matching the
	// AGENTS.md convention that reserves enable-* for collectors with extra
	// per-poll API cost.
	firewallNATCountsEnabled = kingpin.Flag(
		"exporter.enable-firewall-nat-counts",
		"Enable the NAT rule inventory count metric (opnsense_firewall_nat_rules), broken down by type (source_nat, d_nat, one_to_one, npt) and enabled state. Off by default: each scheduled poll does four extra GETs, one per NAT rule type. Rules created before an admin migrated to the MVC-managed NAT backend are not counted; NAT rule pf hit/byte statistics do not exist upstream.",
	).Envar("OPN2OTEL_ENABLE_FIREWALL_NAT_COUNTS").Default("false").IsSetByUser(&firewallNATCountsEnabledUserSet).Bool()
	firmwareCollectorDisabled = kingpin.Flag(
		"exporter.disable-firmware",
		"Disable the scraping of the firmware metrics",
	).Envar("OPN2OTEL_DISABLE_FIRMWARE").Default("false").Bool()
	firmwarePackageDetailsEnabled = kingpin.Flag(
		"exporter.enable-firmware-package-details",
		"Enable per-package firmware detail metrics (pending package updates and installed plugin inventory; adds one extra API call per scheduled poll)",
	).Envar("OPN2OTEL_ENABLE_FIRMWARE_PACKAGE_DETAILS").Default("false").IsSetByUser(&firmwarePackageDetailsEnabledUserSet).Bool()
	systemCollectorDisabled = kingpin.Flag(
		"exporter.disable-system",
		"Disable the scraping of system resource metrics (memory, uptime, disk, swap)",
	).Envar("OPN2OTEL_DISABLE_SYSTEM").Default("false").Bool()
	temperatureCollectorDisabled = kingpin.Flag(
		"exporter.disable-temperature",
		"Disable the scraping of temperature metrics",
	).Envar("OPN2OTEL_DISABLE_TEMPERATURE").Default("false").Bool()
	dnsmasqCollectorDisabled = kingpin.Flag(
		"exporter.disable-dnsmasq",
		"Disable the scraping of Dnsmasq DHCP leases",
	).Envar("OPN2OTEL_DISABLE_DNSMASQ").Default("false").Bool()
	dnsmasqDetailsEnabled = kingpin.Flag(
		"exporter.enable-dnsmasq-details",
		"Enable per-lease detail metrics for Dnsmasq DHCP (high cardinality on large networks)",
	).Envar("OPN2OTEL_ENABLE_DNSMASQ_DETAILS").Default("false").IsSetByUser(&dnsmasqDetailsEnabledUserSet).Bool()
	firewallRulesCollectorDisabled = kingpin.Flag(
		"exporter.disable-firewall-rules",
		"Disable the scraping of firewall rule statistics",
	).Envar("OPN2OTEL_DISABLE_FIREWALL_RULES").Default("false").Bool()
	firewallRulesDetailsEnabled = kingpin.Flag(
		"exporter.enable-firewall-rules-details",
		"Enable per-rule detail metrics for firewall rules (high cardinality on large rulesets)",
	).Envar("OPN2OTEL_ENABLE_FIREWALL_RULES_DETAILS").Default("false").IsSetByUser(&firewallRulesDetailsEnabledUserSet).Bool()
	mbufCollectorDisabled = kingpin.Flag(
		"exporter.disable-mbuf",
		"Disable the scraping of mbuf statistics",
	).Envar("OPN2OTEL_DISABLE_MBUF").Default("false").Bool()
	kernelMemoryCollectorDisabled = kingpin.Flag(
		"exporter.disable-kernel-memory",
		"Disable the kernel-memory collector (every FreeBSD UMA zone and malloc type from api/diagnostics/system/memory). On by default: UMA fail/sleep is the kernel's canonical could-not-allocate signal, covering pf state, socket and mbuf exhaustion, and a failure counter nobody has switched on is a failure counter nobody sees. About 2,600 series on a live 26.1 firewall (228 zones + 258 malloc types), against a 100k global budget, fetched by one extra GET on the 5-minute poll tier.",
	).Envar("OPN2OTEL_DISABLE_KERNEL_MEMORY").Default("false").Bool()
	ntpCollectorDisabled = kingpin.Flag(
		"exporter.disable-ntp",
		"Disable the scraping of NTP peer metrics",
	).Envar("OPN2OTEL_DISABLE_NTP").Default("false").Bool()
	certificatesCollectorDisabled = kingpin.Flag(
		"exporter.disable-certificates",
		"Disable the scraping of certificate expiry metrics",
	).Envar("OPN2OTEL_DISABLE_CERTIFICATES").Default("false").Bool()
	carpCollectorDisabled = kingpin.Flag(
		"exporter.disable-carp",
		"Disable the scraping of CARP/VIP status metrics",
	).Envar("OPN2OTEL_DISABLE_CARP").Default("false").Bool()
	activityCollectorDisabled = kingpin.Flag(
		"exporter.disable-activity",
		"Disable the scraping of system activity metrics (CPU percentages, thread counts)",
	).Envar("OPN2OTEL_DISABLE_ACTIVITY").Default("false").Bool()
	cpuCollectorDisabled = kingpin.Flag(
		"exporter.disable-cpu",
		"Disable CPU metrics. These come from a long-lived Server-Sent Events connection to "+
			"api/diagnostics/cpu_usage/stream, not from polling: the exporter holds one stream open and "+
			"accumulates its 1-second samples into cumulative cpu_seconds_total{mode} counters. Disabling "+
			"this closes that connection and leaves the firewall with no CPU utilisation series at all.",
	).Envar("OPN2OTEL_DISABLE_CPU").Default("false").Bool()
	keaCollectorDisabled = kingpin.Flag(
		"exporter.disable-kea",
		"Disable the scraping of Kea DHCP lease metrics",
	).Envar("OPN2OTEL_DISABLE_KEA").Default("false").Bool()
	keaDetailsEnabled = kingpin.Flag(
		"exporter.enable-kea-details",
		"Enable per-lease detail metrics for Kea DHCP (high cardinality on large networks)",
	).Envar("OPN2OTEL_ENABLE_KEA_DETAILS").Default("false").IsSetByUser(&keaDetailsEnabledUserSet).Bool()
	networkDiagnosticsEnabled = kingpin.Flag(
		"exporter.enable-network-diagnostics",
		"Enable the network diagnostics collector (netisr, sockets, routes). Disabled by default.",
	).Envar("OPN2OTEL_ENABLE_NETWORK_DIAGNOSTICS").Default("false").IsSetByUser(&networkDiagnosticsEnabledUserSet).Bool()
	netisrPerCPUDisabled = kingpin.Flag(
		"exporter.disable-netisr-percpu",
		"Disable the per-workstream netisr series, keeping only the per-protocol aggregates and derived summaries. On by default: the per-CPU dimension is the diagnosis for a netisr drop - one saturated workstream beside eleven idle ones is a CPU-affinity problem, and collapsed to protocol alone it is indistinguishable from uniform overload, which has the opposite remedy. Costs roughly 7 series per protocol per CPU.",
	).Envar("OPN2OTEL_DISABLE_NETISR_PERCPU").Default("false").Bool()
	netflowEnabled = kingpin.Flag(
		"exporter.enable-netflow",
		"Enable the netflow collector (enabled status, service status, cache stats). Disabled by default.",
	).Envar("OPN2OTEL_ENABLE_NETFLOW").Default("false").IsSetByUser(&netflowEnabledUserSet).Bool()
	pfStatsCollectorDisabled = kingpin.Flag(
		"exporter.disable-pf-stats",
		"Disable the scraping of PF statistics (state table, counters, memory limits, timeouts)",
	).Envar("OPN2OTEL_DISABLE_PF_STATS").Default("false").Bool()
	ndpCollectorDisabled = kingpin.Flag(
		"exporter.disable-ndp",
		"Disable the scraping of the NDP (IPv6 neighbor discovery) table",
	).Envar("OPN2OTEL_DISABLE_NDP").Default("false").Bool()
	ndpDetailsEnabled = kingpin.Flag(
		"exporter.enable-ndp-details",
		"Enable per-entry NDP metrics (ip/mac labels - high, churning cardinality from IPv6 privacy-address rotation). Off by default; the low-cardinality entries_total aggregate is always emitted.",
	).Envar("OPN2OTEL_ENABLE_NDP_DETAILS").Default("false").IsSetByUser(&ndpDetailsEnabledUserSet).Bool()
	dhcpv4CollectorDisabled = kingpin.Flag(
		"exporter.disable-dhcpv4",
		"Disable the scraping of ISC DHCPv4 leases (silent when the legacy ISC DHCP backend is absent)",
	).Envar("OPN2OTEL_DISABLE_DHCPV4").Default("false").Bool()
	dhcpv4DetailsEnabled = kingpin.Flag(
		"exporter.enable-dhcpv4-details",
		"Enable per-lease detail metrics for ISC DHCPv4 (high cardinality on large networks)",
	).Envar("OPN2OTEL_ENABLE_DHCPV4_DETAILS").Default("false").IsSetByUser(&dhcpv4DetailsEnabledUserSet).Bool()
	acmeCollectorDisabled = kingpin.Flag(
		"exporter.disable-acme",
		"Disable the scraping of ACME client certificate renewal status and expiry metrics (silent when the os-acme-client plugin is absent)",
	).Envar("OPN2OTEL_DISABLE_ACME").Default("false").Bool()
	// SMART is opt-in (default-off): each scheduled poll does a per-disk POST fanout that makes
	// OPNsense shell out `smartctl -a` per disk, with no standby guard — so a default-on
	// collector would spin up power-saving disks every poll interval. This matches the
	// AGENTS.md convention that reserves enable-* for collectors with extra per-poll API
	// cost (#139).
	smartEnabled = kingpin.Flag(
		"exporter.enable-smart",
		"Enable the SMART disk health collector. Off by default: each scheduled poll does a per-disk POST fanout that runs `smartctl -a` on the firewall (extra API/latency cost, and wakes spun-down disks). Silent when the os-smart plugin is absent.",
	).Envar("OPN2OTEL_ENABLE_SMART").Default("false").IsSetByUser(&smartEnabledUserSet).Bool()
	// Tor is opt-in (default-off, #206): each scheduled poll costs two extra configd execs
	// (a Ruby script dialing the Tor control port for circuit-status and
	// stream-status) on top of the plugin/control-port setup dependency, matching
	// the AGENTS.md convention that reserves enable-* for collectors with extra
	// per-poll API cost.
	torEnabled = kingpin.Flag(
		"exporter.enable-tor",
		"Enable the Tor circuit/stream telemetry collector (control-port GETINFO via the os-tor plugin). Off by default: each scheduled poll does two extra configd execs to query the control port, and requires the plugin's control port + password to be configured. Silent when the os-tor plugin is absent.",
	).Envar("OPN2OTEL_ENABLE_TOR").Default("false").IsSetByUser(&torEnabledUserSet).Bool()
	dyndnsCollectorDisabled = kingpin.Flag(
		"exporter.disable-dyndns",
		"Disable the scraping of DynDNS (ddclient) account update status metrics (silent when the os-ddclient plugin is absent)",
	).Envar("OPN2OTEL_DISABLE_DYNDNS").Default("false").Bool()
	gatewaysCollectorDisabled = kingpin.Flag(
		"exporter.disable-gateways",
		"Disable the scraping of gateway status metrics (RTT, packet loss, gateway state)",
	).Envar("OPN2OTEL_DISABLE_GATEWAYS").Default("false").Bool()
	gatewayGroupsCollectorDisabled = kingpin.Flag(
		"exporter.disable-gateway-groups",
		"Disable gateway failover-group membership metrics (silent on pre-26.7 OPNsense)",
	).Envar("OPN2OTEL_DISABLE_GATEWAY_GROUPS").Default("false").Bool()
	firewallMigrationCollectorDisabled = kingpin.Flag(
		"exporter.disable-firewall-migration",
		"Disable firewall legacy-rule migration debt metrics (silent on pre-26.7 OPNsense)",
	).Envar("OPN2OTEL_DISABLE_FIREWALL_MIGRATION").Default("false").Bool()
	syslogCollectorDisabled = kingpin.Flag(
		"exporter.disable-syslog",
		"Disable the scraping of syslog-ng statistics",
	).Envar("OPN2OTEL_DISABLE_SYSLOG").Default("false").Bool()
	qfeedsCollectorDisabled = kingpin.Flag(
		"exporter.disable-qfeeds",
		"Disable the scraping of Q-Feeds threat intelligence statistics (silent when the os-q-feeds-connector plugin is absent)",
	).Envar("OPN2OTEL_DISABLE_QFEEDS").Default("false").Bool()
	tailscaleCollectorDisabled = kingpin.Flag(
		"exporter.disable-tailscale",
		"Disable the scraping of Tailscale node-local metrics (silent when the os-tailscale plugin is absent; complementary to tailscale2otel)",
	).Envar("OPN2OTEL_DISABLE_TAILSCALE").Default("false").Bool()
	tailscalePeerDetailsEnabled = kingpin.Flag(
		"exporter.enable-tailscale-peer-details",
		"Enable per-peer detail metrics for Tailscale (per-peer cardinality; peer hostname labels)",
	).Envar("OPN2OTEL_ENABLE_TAILSCALE_PEER_DETAILS").Default("false").IsSetByUser(&tailscalePeerDetailsEnabledUserSet).Bool()
	aliasCollectorDisabled = kingpin.Flag(
		"exporter.disable-alias",
		"Disable the scraping of firewall alias table sizes",
	).Envar("OPN2OTEL_DISABLE_ALIAS").Default("false").Bool()
	aliasDetailsEnabled = kingpin.Flag(
		"exporter.enable-alias-details",
		"Enable per-table pf evaluation/packet/byte counters for firewall aliases (~10 series per alias table)",
	).Envar("OPN2OTEL_ENABLE_ALIAS_DETAILS").Default("false").IsSetByUser(&aliasDetailsEnabledUserSet).Bool()
	haproxyCollectorDisabled = kingpin.Flag(
		"exporter.disable-haproxy",
		"Disable the scraping of HAProxy statistics (silent when the os-haproxy plugin is absent)",
	).Envar("OPN2OTEL_DISABLE_HAPROXY").Default("false").Bool()
	nginxCollectorDisabled = kingpin.Flag(
		"exporter.disable-nginx",
		"Disable the scraping of nginx VTS statistics (silent when the os-nginx plugin is absent)",
	).Envar("OPN2OTEL_DISABLE_NGINX").Default("false").Bool()
	frrCollectorDisabled = kingpin.Flag(
		"exporter.disable-frr",
		"Disable the scraping of FRR routing metrics (BGP/OSPF/BFD; silent when the os-frr plugin is absent)",
	).Envar("OPN2OTEL_DISABLE_FRR").Default("false").Bool()
	frrRoutesEnabled = kingpin.Flag(
		"exporter.enable-frr-routes",
		"Enable FRR routing-state volume gauges (zebra RIB / OSPF route table / LSDB counts by "+
			"protocol, route type, area and LSA type - never per-prefix or per-LSA series). Off by "+
			"default: the underlying bootgrid endpoints have no success-body caching and their "+
			"payload size scales with route-table size (up to 6 extra vtysh execs per scheduled poll).",
	).Envar("OPN2OTEL_ENABLE_FRR_ROUTES").Default("false").IsSetByUser(&frrRoutesEnabledUserSet).Bool()
	monitCollectorDisabled = kingpin.Flag(
		"exporter.disable-monit",
		"Disable the scraping of Monit service check status (silent when Monit is not running)",
	).Envar("OPN2OTEL_DISABLE_MONIT").Default("false").Bool()
	crowdsecCollectorDisabled = kingpin.Flag(
		"exporter.disable-crowdsec",
		"Disable the scraping of CrowdSec alert/decision/bouncer/machine counts (silent when the os-crowdsec plugin is absent)",
	).Envar("OPN2OTEL_DISABLE_CROWDSEC").Default("false").Bool()
	nutCollectorDisabled = kingpin.Flag(
		"exporter.disable-nut",
		"Disable the scraping of NUT UPS metrics (silent when the os-nut plugin is absent)",
	).Envar("OPN2OTEL_DISABLE_NUT").Default("false").Bool()
	apcupsdCollectorDisabled = kingpin.Flag(
		"exporter.disable-apcupsd",
		"Disable the scraping of APC UPS (apcupsd) metrics (silent when the os-apcupsd plugin is absent)",
	).Envar("OPN2OTEL_DISABLE_APCUPSD").Default("false").Bool()
	captivePortalCollectorDisabled = kingpin.Flag(
		"exporter.disable-captiveportal",
		"Disable the scraping of captive portal zone/session metrics (silent when no zones are configured)",
	).Envar("OPN2OTEL_DISABLE_CAPTIVEPORTAL").Default("false").Bool()
	trafficShaperCollectorDisabled = kingpin.Flag(
		"exporter.disable-trafficshaper",
		"Disable the scraping of traffic shaper pipe/queue/rule statistics (silent when the shaper is unconfigured)",
	).Envar("OPN2OTEL_DISABLE_TRAFFICSHAPER").Default("false").Bool()
	hasyncEnabled = kingpin.Flag(
		"exporter.enable-hasync",
		"Enable the HA sync status collector (performs a live XML-RPC call to the CARP peer on every scheduled poll). Disabled by default.",
	).Envar("OPN2OTEL_ENABLE_HASYNC").Default("false").IsSetByUser(&hasyncEnabledUserSet).Bool()
	chronyCollectorDisabled = kingpin.Flag(
		"exporter.disable-chrony",
		"Disable the scraping of chrony NTP tracking/source metrics (silent when the os-chrony plugin is absent)",
	).Envar("OPN2OTEL_DISABLE_CHRONY").Default("false").Bool()
	dhcpv6CollectorDisabled = kingpin.Flag(
		"exporter.disable-dhcpv6",
		"Disable the scraping of ISC DHCPv6 leases and delegated prefixes (silent when the legacy ISC DHCP backend is absent)",
	).Envar("OPN2OTEL_DISABLE_DHCPV6").Default("false").Bool()
	dhcpv6DetailsEnabled = kingpin.Flag(
		"exporter.enable-dhcpv6-details",
		"Enable per-lease detail metrics for ISC DHCPv6 (high cardinality on large networks)",
	).Envar("OPN2OTEL_ENABLE_DHCPV6_DETAILS").Default("false").IsSetByUser(&dhcpv6DetailsEnabledUserSet).Bool()
	bpfCollectorDisabled = kingpin.Flag(
		"exporter.disable-bpf",
		"Disable the scraping of BPF listener statistics",
	).Envar("OPN2OTEL_DISABLE_BPF").Default("false").Bool()
	backupCollectorDisabled = kingpin.Flag(
		"exporter.disable-backup",
		"Disable the scraping of config backup freshness metrics (last backup timestamp/count/size)",
	).Envar("OPN2OTEL_DISABLE_BACKUP").Default("false").Bool()
	snapshotsCollectorDisabled = kingpin.Flag(
		"exporter.disable-snapshots",
		"Disable the scraping of ZFS boot-environment inventory metrics (silent/zero on non-ZFS filesystems such as UFS)",
	).Envar("OPN2OTEL_DISABLE_SNAPSHOTS").Default("false").Bool()
	clamavCollectorDisabled = kingpin.Flag(
		"exporter.disable-clamav",
		"Disable the scraping of ClamAV engine version and signature database freshness metrics (silent when the os-clamav plugin is absent)",
	).Envar("OPN2OTEL_DISABLE_CLAMAV").Default("false").Bool()
	idsCollectorDisabled = kingpin.Flag(
		"exporter.disable-ids",
		"Disable the scraping of Suricata IDS/IPS metrics (service status, IPS mode, eve log and ruleset inventory, installed-rule count; silent structures when IDS is unconfigured)",
	).Envar("OPN2OTEL_DISABLE_IDS").Default("false").Bool()
	idsAlertsEnabled = kingpin.Flag(
		"exporter.enable-ids-alerts",
		"Enable the Suricata recent-alerts gauge (opnsense_ids_recent_alerts by action). Off by default: each scheduled poll triggers a reverse read of eve.json on the box. Window set by --exporter.ids-alert-lookback.",
	).Envar("OPN2OTEL_ENABLE_IDS_ALERTS").Default("false").IsSetByUser(&idsAlertsEnabledUserSet).Bool()
	lldpdCollectorDisabled = kingpin.Flag(
		"exporter.disable-lldpd",
		"Disable the scraping of LLDP neighbor table metrics (silent when the os-lldpd plugin is absent)",
	).Envar("OPN2OTEL_DISABLE_LLDPD").Default("false").Bool()
	hardwareCollectorDisabled = kingpin.Flag(
		"exporter.disable-hardware",
		"Disable the scraping of hardware identity/PSU metrics (DMI system info via os-dmidecode; Deciso DEC-series PSU status via os-dec-hw). Silent when neither plugin is installed.",
	).Envar("OPN2OTEL_DISABLE_HARDWARE").Default("false").Bool()
	// Vnstat is opt-in (default-off): each scheduled poll does one interface_list call plus one
	// get_json_data call PER interface vnstat tracks (a configd `vnstat --json` exec each
	// time), so it adds N extra API calls per scheduled poll rather than one. This matches the
	// AGENTS.md convention that reserves enable-* for collectors with extra per-poll
	// API cost (#215).
	vnstatEnabled = kingpin.Flag(
		"exporter.enable-vnstat",
		"Enable the vnstat persistent traffic accounting collector (day/month/total bytes per interface, survives reboots). Off by default: each scheduled poll does one interface_list call plus one get_json_data call per interface vnstat tracks. Silent when the os-vnstat plugin is absent.",
	).Envar("OPN2OTEL_ENABLE_VNSTAT").Default("false").IsSetByUser(&vnstatEnabledUserSet).Bool()
	netbirdCollectorDisabled = kingpin.Flag(
		"exporter.disable-netbird",
		"Disable the scraping of NetBird management/signal connectivity, relay and peer metrics (silent when the os-netbird plugin is absent)",
	).Envar("OPN2OTEL_DISABLE_NETBIRD").Default("false").Bool()
	zeroTierCollectorDisabled = kingpin.Flag(
		"exporter.disable-zerotier",
		"Disable the scraping of ZeroTier network membership, status and assigned-address metrics (silent when the os-zerotier plugin is absent)",
	).Envar("OPN2OTEL_DISABLE_ZEROTIER").Default("false").Bool()
	netbirdDetailsEnabled = kingpin.Flag(
		"exporter.enable-netbird-details",
		"Enable per-peer detail metrics for NetBird (per-peer cardinality; peer FQDN labels)",
	).Envar("OPN2OTEL_ENABLE_NETBIRD_DETAILS").Default("false").IsSetByUser(&netbirdDetailsEnabledUserSet).Bool()
	authCollectorDisabled = kingpin.Flag(
		"exporter.disable-auth",
		"Disable the scraping of local-auth security-posture metrics (user/group/API-key counts, aggregates only - no per-user data)",
	).Envar("OPN2OTEL_DISABLE_AUTH").Default("false").Bool()
	hostdiscoveryCollectorDisabled = kingpin.Flag(
		"exporter.disable-hostdiscovery",
		"Disable the scraping of the discovered-host inventory (Interfaces > Host discovery / hostwatch): interface+source host counts, low-cardinality. A core OPNsense feature (not a plugin); reads absent/silent on releases predating it.",
	).Envar("OPN2OTEL_DISABLE_HOSTDISCOVERY").Default("false").Bool()
	relaydCollectorDisabled = kingpin.Flag(
		"exporter.disable-relayd",
		"Disable the scraping of relayd virtual server/table/host health (silent when the os-relayd plugin is absent)",
	).Envar("OPN2OTEL_DISABLE_RELAYD").Default("false").Bool()
	siproxdCollectorDisabled = kingpin.Flag(
		"exporter.disable-siproxd",
		"Disable the scraping of the siproxd active SIP registration count (silent when the os-siproxd plugin is absent)",
	).Envar("OPN2OTEL_DISABLE_SIPROXD").Default("false").Bool()
	// log_events is default-on but only produces series while the syslog receiver
	// (--logs.syslog.enabled) is running and feeding it; disabling it here both drops
	// the collector and stops the receiver deriving the counters (#258).
	logEventsCollectorDisabled = kingpin.Flag(
		"exporter.disable-log-events",
		"Disable the log_events collector (Prometheus counters derived from received syslog lines: firewall/haproxy/sshd/dhcp/audit/ids event totals). Silent until the syslog receiver is enabled and feeding it.",
	).Envar("OPN2OTEL_DISABLE_LOG_EVENTS").Default("false").Bool()
	// flow is default-on and low-cardinality by construction: every dimension it
	// labels is a closed enumeration or a bounded taxonomy, and the accumulator
	// folds anything beyond --flow.top-n into a single __other__ series. Like
	// log_events it is silent until a flow source is feeding it, and disabling it
	// here also stops the receiver lanes deriving flow records at all (#346).
	flowCollectorDisabled = kingpin.Flag(
		"exporter.disable-flow",
		"Disable the flow collector (Prometheus byte/packet volume counters rolled up from flow records, on bounded dimensions). Silent until a flow source - today the Zenarmor receiver - is enabled and feeding it.",
	).Envar("OPN2OTEL_DISABLE_FLOW").Default("false").Bool()
	// feature_availability (#517) is default-on and low-cost: it probes the SAME
	// plugin-gated endpoints PluginGatedEndpoints() already answers "is the plugin
	// absent?" for (#495) - SMART, Tor, Vnstat today - on the cold poll tier
	// (15m), bypassing the negative-cache TTL so a plugin installed after startup
	// is noticed within that window rather than up to --exporter.cache-ttl later.
	featureAvailabilityCollectorDisabled = kingpin.Flag(
		"exporter.disable-feature-availability",
		"Disable the feature-availability collector (opnsense_feature_available; #517). It periodically probes the plugin-gated endpoints backing the opt-in SMART/Tor/Vnstat collectors and logs a one-shot line naming the flag to enable any that answer successfully but are not yet enabled.",
	).Envar("OPN2OTEL_DISABLE_FEATURE_AVAILABILITY").Default("false").Bool()

	// enableAllAvailable is the single blanket opt-in switch (#517): it turns on
	// every --exporter.enable-* collector switch (both whole-collector and
	// *-details toggles) that the operator has not explicitly set themselves,
	// so a plugin-gated collector that IS available (per the availability
	// prober, internal/collector's feature_availability collector) starts
	// producing data without hunting through the flag reference. It deliberately
	// never touches the syslog/Zenarmor/NetFlow RECEIVERS: those are unauthenticated
	// listening sockets, not collectors, and are out of scope entirely - see
	// ApplyEnableAllAvailable's doc comment.
	enableAllAvailable = kingpin.Flag(
		"exporter.enable-all-available",
		"Enable every opt-in collector switch (--exporter.enable-*) that is not explicitly set on the command line or via its own env var. A collector whose PLUGIN the startup availability probe finds absent is left off, so this enables what the box can actually serve; anything gated on cost or cardinality rather than a plugin is enabled regardless. If the firewall cannot be reached at startup the probe falls open and everything is enabled. NOTE: because availability is resolved once at startup, a plugin installed LATER does not self-activate under this flag until the next restart. Never enables the syslog/Zenarmor/NetFlow receivers - those open network sockets and are out of scope. Each collector this switches on is logged individually with the reason it defaults to off; an explicit --exporter.enable-<x>=false always wins over this blanket switch.",
	).Envar("OPN2OTEL_ENABLE_ALL_AVAILABLE").Default("false").Bool()
)

// EnableAllAvailable reports whether --exporter.enable-all-available is set. main
// needs it to decide whether the startup availability probe is worth making at all.
func EnableAllAvailable() bool { return *enableAllAvailable }

// enableFlagUserSet tracks, per --exporter.enable-* flag, whether the operator
// set it explicitly on the command line (via kingpin's IsSetByUser). Env-var
// overrides are detected separately by ApplyEnableAllAvailable reading the
// flag's own Envar name from os.LookupEnv, since kingpin's IsSetByUser callback
// only fires for a CLI token (vendor/github.com/alecthomas/kingpin/v2/flags.go)
// and never for a value that arrived through Envar/OverrideDefaultFromEnvar.
var (
	arpDetailsEnabledUserSet             bool
	ipsecLeaseDetailsEnabledUserSet      bool
	unboundInfraEnabledUserSet           bool
	unboundQStatsEnabledUserSet          bool
	openVPNDetailsEnabledUserSet         bool
	firewallNATCountsEnabledUserSet      bool
	firmwarePackageDetailsEnabledUserSet bool
	dnsmasqDetailsEnabledUserSet         bool
	firewallRulesDetailsEnabledUserSet   bool
	keaDetailsEnabledUserSet             bool
	networkDiagnosticsEnabledUserSet     bool
	netflowEnabledUserSet                bool
	ndpDetailsEnabledUserSet             bool
	dhcpv4DetailsEnabledUserSet          bool
	smartEnabledUserSet                  bool
	torEnabledUserSet                    bool
	tailscalePeerDetailsEnabledUserSet   bool
	aliasDetailsEnabledUserSet           bool
	frrRoutesEnabledUserSet              bool
	hasyncEnabledUserSet                 bool
	dhcpv6DetailsEnabledUserSet          bool
	idsAlertsEnabledUserSet              bool
	vnstatEnabledUserSet                 bool
	netbirdDetailsEnabledUserSet         bool
)

// CollectorsDisableSwitch hold the enabled/disabled state of the collectors
type CollectorsDisableSwitch struct {
	ARP                    bool
	Cron                   bool
	Wireguard              bool
	IPsec                  bool
	IPsecLeaseDetails      bool
	Unbound                bool
	UnboundInfra           bool
	UnboundQStats          bool
	OpenVPN                bool
	OpenVPNDetails         bool
	Firewall               bool
	FirewallNATCounts      bool
	Firmware               bool
	FirmwarePackageDetails bool
	Dnsmasq                bool
	DnsmasqDetails         bool
	FirewallRules          bool
	FirewallRulesDetails   bool
	System                 bool
	Temperature            bool
	Mbuf                   bool
	KernelMemory           bool
	NTP                    bool
	Certificates           bool
	CARP                   bool
	Activity               bool
	CPU                    bool
	Kea                    bool
	KeaDetails             bool
	NetworkDiagnostics     bool
	NetisrPerCPU           bool
	Netflow                bool
	PFStats                bool
	NDP                    bool
	Dhcpv4                 bool
	Dhcpv4Details          bool
	ACME                   bool
	SMART                  bool
	Tor                    bool
	DynDNS                 bool
	Gateways               bool
	GatewayGroups          bool
	FirewallMigration      bool
	Syslog                 bool
	QFeeds                 bool
	Tailscale              bool
	TailscalePeerDetails   bool
	Alias                  bool
	AliasDetails           bool
	HAProxy                bool
	Nginx                  bool
	FRR                    bool
	FRRRoutes              bool
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
	ClamAV                 bool
	Hardware               bool
	Vnstat                 bool
	Netbird                bool
	NetbirdDetails         bool
	ZeroTier               bool
	Siproxd                bool
	ArpDetails             bool
	NdpDetails             bool
	Interfaces             bool
	Protocol               bool
	Services               bool
	Backup                 bool
	Snapshots              bool
	IDS                    bool
	IDSAlerts              bool
	LLDPD                  bool
	Auth                   bool
	HostDiscovery          bool
	Relayd                 bool
	LogEvents              bool
	Flow                   bool
	FeatureAvailability    bool
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
		IPsecLeaseDetails:      *ipsecLeaseDetailsEnabled,
		Unbound:                !*unboundCollectorDisabled,
		UnboundInfra:           *unboundInfraEnabled,
		UnboundQStats:          *unboundQStatsEnabled,
		OpenVPN:                !*openVPNCollectorDisabled,
		OpenVPNDetails:         *openVPNDetailsEnabled,
		Firewall:               !*firewallCollectorDisabled,
		FirewallNATCounts:      *firewallNATCountsEnabled,
		Firmware:               !*firmwareCollectorDisabled,
		FirmwarePackageDetails: *firmwarePackageDetailsEnabled,
		Dnsmasq:                !*dnsmasqCollectorDisabled,
		DnsmasqDetails:         *dnsmasqDetailsEnabled,
		FirewallRules:          !*firewallRulesCollectorDisabled,
		FirewallRulesDetails:   *firewallRulesDetailsEnabled,
		System:                 !*systemCollectorDisabled,
		Temperature:            !*temperatureCollectorDisabled,
		Mbuf:                   !*mbufCollectorDisabled,
		KernelMemory:           !*kernelMemoryCollectorDisabled,
		NTP:                    !*ntpCollectorDisabled,
		Certificates:           !*certificatesCollectorDisabled,
		CARP:                   !*carpCollectorDisabled,
		Activity:               !*activityCollectorDisabled,
		CPU:                    !*cpuCollectorDisabled,
		Kea:                    !*keaCollectorDisabled,
		KeaDetails:             *keaDetailsEnabled,
		NetworkDiagnostics:     *networkDiagnosticsEnabled,
		NetisrPerCPU:           !*netisrPerCPUDisabled,
		Netflow:                *netflowEnabled,
		PFStats:                !*pfStatsCollectorDisabled,
		NDP:                    !*ndpCollectorDisabled,
		Dhcpv4:                 !*dhcpv4CollectorDisabled,
		Dhcpv4Details:          *dhcpv4DetailsEnabled,
		ACME:                   !*acmeCollectorDisabled,
		SMART:                  *smartEnabled,
		Tor:                    *torEnabled,
		DynDNS:                 !*dyndnsCollectorDisabled,
		Gateways:               !*gatewaysCollectorDisabled,
		GatewayGroups:          !*gatewayGroupsCollectorDisabled,
		FirewallMigration:      !*firewallMigrationCollectorDisabled,
		Syslog:                 !*syslogCollectorDisabled,
		QFeeds:                 !*qfeedsCollectorDisabled,
		Tailscale:              !*tailscaleCollectorDisabled,
		TailscalePeerDetails:   *tailscalePeerDetailsEnabled,
		Alias:                  !*aliasCollectorDisabled,
		AliasDetails:           *aliasDetailsEnabled,
		HAProxy:                !*haproxyCollectorDisabled,
		Nginx:                  !*nginxCollectorDisabled,
		FRR:                    !*frrCollectorDisabled,
		FRRRoutes:              *frrRoutesEnabled,
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
		Backup:                 !*backupCollectorDisabled,
		Snapshots:              !*snapshotsCollectorDisabled,
		ClamAV:                 !*clamavCollectorDisabled,
		IDS:                    !*idsCollectorDisabled,
		IDSAlerts:              *idsAlertsEnabled,
		LLDPD:                  !*lldpdCollectorDisabled,
		Hardware:               !*hardwareCollectorDisabled,
		Vnstat:                 *vnstatEnabled,
		Netbird:                !*netbirdCollectorDisabled,
		NetbirdDetails:         *netbirdDetailsEnabled,
		ZeroTier:               !*zeroTierCollectorDisabled,
		Auth:                   !*authCollectorDisabled,
		HostDiscovery:          !*hostdiscoveryCollectorDisabled,
		Relayd:                 !*relaydCollectorDisabled,
		Siproxd:                !*siproxdCollectorDisabled,
		LogEvents:              !*logEventsCollectorDisabled,
		Flow:                   !*flowCollectorDisabled,
		FeatureAvailability:    !*featureAvailabilityCollectorDisabled,
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
	// Reason is why an enable-* flag defaults to off: extra per-poll API cost,
	// high/unbounded cardinality, or exposing sensitive data. Populated only for
	// enable-* entries, copied verbatim from the flag's own Help text above so
	// there is exactly one place each reason is authored. --exporter.enable-all-available
	// (#517) surfaces it in the per-collector log line it emits for every switch
	// it turns on.
	Reason string
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
	{Flag: "exporter.enable-arp-details", Subsystem: "arp_table", Detail: true, Reason: "high, churning cardinality (per-entry ip/mac/hostname labels)"},
	{Flag: "exporter.enable-ndp-details", Subsystem: "ndp", Detail: true, Reason: "high, churning cardinality from IPv6 privacy-address rotation (per-entry ip/mac labels)"},
	{Flag: "exporter.disable-cron-table", Subsystem: "cron"},
	{Flag: "exporter.disable-wireguard", Subsystem: "wireguard"},
	{Flag: "exporter.disable-ipsec", Subsystem: "ipsec"},
	{Flag: "exporter.enable-ipsec-lease-details", Subsystem: "ipsec", Detail: true, Reason: "unbounded road-warrior user label on the per-lease metric"},
	{Flag: "exporter.disable-unbound", Subsystem: "unbound_dns"},
	{Flag: "exporter.enable-unbound-infra", Subsystem: "unbound_dns", Detail: true, Reason: "cardinality scales with the resolver's infra cache (one series pair per upstream)"},
	{Flag: "exporter.enable-unbound-qstats", Subsystem: "unbound_dns", Detail: true, Reason: "backed by an expensive configd+python+pandas+DuckDB query (~1s per scheduled poll)"},
	{Flag: "exporter.disable-openvpn", Subsystem: "openvpn"},
	{Flag: "exporter.enable-openvpn-details", Subsystem: "openvpn", Detail: true, Reason: "exposes usernames and per-client tunnel addresses"},
	{Flag: "exporter.disable-firewall", Subsystem: "firewall"},
	{Flag: "exporter.enable-firewall-nat-counts", Subsystem: "firewall", Detail: true, Reason: "four extra GETs per scheduled poll, one per NAT rule type"},
	{Flag: "exporter.disable-firmware", Subsystem: "firmware"},
	{Flag: "exporter.enable-firmware-package-details", Subsystem: "firmware", Detail: true, Reason: "one extra API call per scheduled poll"},
	{Flag: "exporter.disable-system", Subsystem: "system"},
	{Flag: "exporter.disable-temperature", Subsystem: "temperature"},
	{Flag: "exporter.disable-dnsmasq", Subsystem: "dnsmasq"},
	{Flag: "exporter.enable-dnsmasq-details", Subsystem: "dnsmasq", Detail: true, Reason: "high cardinality on large networks (per-lease detail metrics)"},
	{Flag: "exporter.disable-firewall-rules", Subsystem: "firewall_rule"},
	{Flag: "exporter.enable-firewall-rules-details", Subsystem: "firewall_rule", Detail: true, Reason: "high cardinality on large rulesets (per-rule detail metrics)"},
	{Flag: "exporter.disable-mbuf", Subsystem: "mbuf"},
	{Flag: "exporter.disable-kernel-memory", Subsystem: "kernel_memory"},
	{Flag: "exporter.disable-ntp", Subsystem: "ntp"},
	{Flag: "exporter.disable-certificates", Subsystem: "certificate"},
	{Flag: "exporter.disable-carp", Subsystem: "carp"},
	{Flag: "exporter.disable-activity", Subsystem: "activity"},
	{Flag: "exporter.disable-cpu", Subsystem: "cpu"},
	{Flag: "exporter.disable-kea", Subsystem: "kea"},
	{Flag: "exporter.enable-kea-details", Subsystem: "kea", Detail: true, Reason: "high cardinality on large networks (per-lease detail metrics)"},
	{Flag: "exporter.enable-network-diagnostics", Subsystem: "network_diag", Reason: "not needed by every deployment; adds netisr/socket/route diagnostics collection"},
	// The only default-ON detail flag. Every other Detail entry is an enable-*
	// opt-in; this one is a disable-* opt-out because the dimension it controls is
	// the diagnosis rather than an extra. It is deliberately absent from
	// enableFlagBindings: --exporter.enable-all-available has nothing to turn on here.
	{Flag: "exporter.disable-netisr-percpu", Subsystem: "network_diag", Detail: true},
	{Flag: "exporter.enable-netflow", Subsystem: "netflow", Reason: "only relevant when NetFlow capture is configured on the firewall"},
	{Flag: "exporter.disable-pf-stats", Subsystem: "pf_stats"},
	{Flag: "exporter.disable-ndp", Subsystem: "ndp"},
	{Flag: "exporter.disable-dhcpv4", Subsystem: "dhcpv4"},
	{Flag: "exporter.enable-dhcpv4-details", Subsystem: "dhcpv4", Detail: true, Reason: "high cardinality on large networks (per-lease detail metrics)"},
	{Flag: "exporter.disable-acme", Subsystem: "acme"},
	{Flag: "exporter.enable-smart", Subsystem: "smart", Reason: "each scheduled poll runs `smartctl -a` per disk on the firewall and can wake spun-down disks"},
	{Flag: "exporter.enable-tor", Subsystem: "tor", Reason: "each scheduled poll does two extra configd execs to query the Tor control port"},
	{Flag: "exporter.disable-dyndns", Subsystem: "dyndns"},
	{Flag: "exporter.disable-gateways", Subsystem: "gateways"},
	{Flag: "exporter.disable-gateway-groups", Subsystem: "gateway_groups"},
	{Flag: "exporter.disable-firewall-migration", Subsystem: "firewall_migration"},
	{Flag: "exporter.disable-syslog", Subsystem: "syslog"},
	{Flag: "exporter.disable-qfeeds", Subsystem: "qfeeds"},
	{Flag: "exporter.disable-tailscale", Subsystem: "tailscale"},
	{Flag: "exporter.enable-tailscale-peer-details", Subsystem: "tailscale", Detail: true, Reason: "per-peer cardinality; peer hostname labels"},
	{Flag: "exporter.disable-alias", Subsystem: "alias"},
	{Flag: "exporter.enable-alias-details", Subsystem: "alias", Detail: true, Reason: "~10 series per alias table"},
	{Flag: "exporter.disable-haproxy", Subsystem: "haproxy"},
	{Flag: "exporter.disable-nginx", Subsystem: "nginx"},
	{Flag: "exporter.disable-frr", Subsystem: "frr"},
	{Flag: "exporter.enable-frr-routes", Subsystem: "frr", Detail: true, Reason: "up to 6 extra vtysh execs per scheduled poll; payload scales with route-table size"},
	{Flag: "exporter.disable-monit", Subsystem: "monit"},
	{Flag: "exporter.disable-crowdsec", Subsystem: "crowdsec"},
	{Flag: "exporter.disable-nut", Subsystem: "nut"},
	{Flag: "exporter.disable-apcupsd", Subsystem: "apcupsd"},
	{Flag: "exporter.disable-captiveportal", Subsystem: "captiveportal"},
	{Flag: "exporter.disable-trafficshaper", Subsystem: "trafficshaper"},
	{Flag: "exporter.enable-hasync", Subsystem: "hasync", Reason: "performs a live XML-RPC call to the CARP peer on every scheduled poll"},
	{Flag: "exporter.disable-chrony", Subsystem: "chrony"},
	{Flag: "exporter.disable-dhcpv6", Subsystem: "dhcpv6"},
	{Flag: "exporter.enable-dhcpv6-details", Subsystem: "dhcpv6", Detail: true, Reason: "high cardinality on large networks (per-lease detail metrics)"},
	{Flag: "exporter.disable-bpf", Subsystem: "bpf"},
	{Flag: "exporter.disable-backup", Subsystem: "backup"},
	{Flag: "exporter.disable-snapshots", Subsystem: "snapshots"},
	{Flag: "exporter.disable-clamav", Subsystem: "clamav"},
	{Flag: "exporter.disable-ids", Subsystem: "ids"},
	{Flag: "exporter.enable-ids-alerts", Subsystem: "ids", Detail: true, Reason: "each scheduled poll triggers a reverse read of eve.json on the box"},
	{Flag: "exporter.disable-lldpd", Subsystem: "lldp"},
	{Flag: "exporter.disable-hardware", Subsystem: "hardware"},
	{Flag: "exporter.enable-vnstat", Subsystem: "vnstat", Reason: "each scheduled poll does one interface_list call plus one get_json_data call per interface vnstat tracks"},
	{Flag: "exporter.disable-netbird", Subsystem: "netbird"},
	{Flag: "exporter.enable-netbird-details", Subsystem: "netbird", Detail: true, Reason: "per-peer cardinality; peer FQDN labels"},
	{Flag: "exporter.disable-zerotier", Subsystem: "zerotier"},
	{Flag: "exporter.disable-auth", Subsystem: "auth"},
	{Flag: "exporter.disable-hostdiscovery", Subsystem: "hostdiscovery"},
	{Flag: "exporter.disable-relayd", Subsystem: "relayd"},
	{Flag: "exporter.disable-siproxd", Subsystem: "siproxd"},
	{Flag: "exporter.disable-log-events", Subsystem: "log_events"},
	{Flag: "exporter.disable-flow", Subsystem: "flow"},
	{Flag: "exporter.disable-feature-availability", Subsystem: "feature"},
}

// enableFlagBinding pairs one --exporter.enable-* flag with the state
// ApplyEnableAllAvailable needs to decide, per flag, whether the operator has
// already made a choice: its live value, the CLI-tracking bool wired via
// IsSetByUser above, its env var name, and the setter that flips the
// corresponding CollectorsDisableSwitch field. Deliberately excludes
// --exporter.enable-all-available itself (nothing to bind it to) and every
// receiver flag (--logs.syslog.enabled &c, in a different options file
// entirely) - see ApplyEnableAllAvailable's doc comment.
type enableFlagBinding struct {
	flag    string
	envar   string
	value   *bool
	userSet *bool
	apply   func(*CollectorsDisableSwitch)
}

var enableFlagBindings = []enableFlagBinding{
	{"exporter.enable-arp-details", "OPN2OTEL_ENABLE_ARP_DETAILS", arpDetailsEnabled, &arpDetailsEnabledUserSet, func(s *CollectorsDisableSwitch) { s.ArpDetails = true }},
	{"exporter.enable-ndp-details", "OPN2OTEL_ENABLE_NDP_DETAILS", ndpDetailsEnabled, &ndpDetailsEnabledUserSet, func(s *CollectorsDisableSwitch) { s.NdpDetails = true }},
	{"exporter.enable-ipsec-lease-details", "OPN2OTEL_ENABLE_IPSEC_LEASE_DETAILS", ipsecLeaseDetailsEnabled, &ipsecLeaseDetailsEnabledUserSet, func(s *CollectorsDisableSwitch) { s.IPsecLeaseDetails = true }},
	{"exporter.enable-unbound-infra", "OPN2OTEL_ENABLE_UNBOUND_INFRA", unboundInfraEnabled, &unboundInfraEnabledUserSet, func(s *CollectorsDisableSwitch) { s.UnboundInfra = true }},
	{"exporter.enable-unbound-qstats", "OPN2OTEL_ENABLE_UNBOUND_QSTATS", unboundQStatsEnabled, &unboundQStatsEnabledUserSet, func(s *CollectorsDisableSwitch) { s.UnboundQStats = true }},
	{"exporter.enable-openvpn-details", "OPN2OTEL_ENABLE_OPENVPN_DETAILS", openVPNDetailsEnabled, &openVPNDetailsEnabledUserSet, func(s *CollectorsDisableSwitch) { s.OpenVPNDetails = true }},
	{"exporter.enable-firewall-nat-counts", "OPN2OTEL_ENABLE_FIREWALL_NAT_COUNTS", firewallNATCountsEnabled, &firewallNATCountsEnabledUserSet, func(s *CollectorsDisableSwitch) { s.FirewallNATCounts = true }},
	{"exporter.enable-firmware-package-details", "OPN2OTEL_ENABLE_FIRMWARE_PACKAGE_DETAILS", firmwarePackageDetailsEnabled, &firmwarePackageDetailsEnabledUserSet, func(s *CollectorsDisableSwitch) { s.FirmwarePackageDetails = true }},
	{"exporter.enable-dnsmasq-details", "OPN2OTEL_ENABLE_DNSMASQ_DETAILS", dnsmasqDetailsEnabled, &dnsmasqDetailsEnabledUserSet, func(s *CollectorsDisableSwitch) { s.DnsmasqDetails = true }},
	{"exporter.enable-firewall-rules-details", "OPN2OTEL_ENABLE_FIREWALL_RULES_DETAILS", firewallRulesDetailsEnabled, &firewallRulesDetailsEnabledUserSet, func(s *CollectorsDisableSwitch) { s.FirewallRulesDetails = true }},
	{"exporter.enable-kea-details", "OPN2OTEL_ENABLE_KEA_DETAILS", keaDetailsEnabled, &keaDetailsEnabledUserSet, func(s *CollectorsDisableSwitch) { s.KeaDetails = true }},
	{"exporter.enable-network-diagnostics", "OPN2OTEL_ENABLE_NETWORK_DIAGNOSTICS", networkDiagnosticsEnabled, &networkDiagnosticsEnabledUserSet, func(s *CollectorsDisableSwitch) { s.NetworkDiagnostics = true }},
	{"exporter.enable-netflow", "OPN2OTEL_ENABLE_NETFLOW", netflowEnabled, &netflowEnabledUserSet, func(s *CollectorsDisableSwitch) { s.Netflow = true }},
	{"exporter.enable-dhcpv4-details", "OPN2OTEL_ENABLE_DHCPV4_DETAILS", dhcpv4DetailsEnabled, &dhcpv4DetailsEnabledUserSet, func(s *CollectorsDisableSwitch) { s.Dhcpv4Details = true }},
	{"exporter.enable-smart", "OPN2OTEL_ENABLE_SMART", smartEnabled, &smartEnabledUserSet, func(s *CollectorsDisableSwitch) { s.SMART = true }},
	{"exporter.enable-tor", "OPN2OTEL_ENABLE_TOR", torEnabled, &torEnabledUserSet, func(s *CollectorsDisableSwitch) { s.Tor = true }},
	{"exporter.enable-tailscale-peer-details", "OPN2OTEL_ENABLE_TAILSCALE_PEER_DETAILS", tailscalePeerDetailsEnabled, &tailscalePeerDetailsEnabledUserSet, func(s *CollectorsDisableSwitch) { s.TailscalePeerDetails = true }},
	{"exporter.enable-alias-details", "OPN2OTEL_ENABLE_ALIAS_DETAILS", aliasDetailsEnabled, &aliasDetailsEnabledUserSet, func(s *CollectorsDisableSwitch) { s.AliasDetails = true }},
	{"exporter.enable-frr-routes", "OPN2OTEL_ENABLE_FRR_ROUTES", frrRoutesEnabled, &frrRoutesEnabledUserSet, func(s *CollectorsDisableSwitch) { s.FRRRoutes = true }},
	{"exporter.enable-hasync", "OPN2OTEL_ENABLE_HASYNC", hasyncEnabled, &hasyncEnabledUserSet, func(s *CollectorsDisableSwitch) { s.Hasync = true }},
	{"exporter.enable-dhcpv6-details", "OPN2OTEL_ENABLE_DHCPV6_DETAILS", dhcpv6DetailsEnabled, &dhcpv6DetailsEnabledUserSet, func(s *CollectorsDisableSwitch) { s.Dhcpv6Details = true }},
	{"exporter.enable-ids-alerts", "OPN2OTEL_ENABLE_IDS_ALERTS", idsAlertsEnabled, &idsAlertsEnabledUserSet, func(s *CollectorsDisableSwitch) { s.IDSAlerts = true }},
	{"exporter.enable-vnstat", "OPN2OTEL_ENABLE_VNSTAT", vnstatEnabled, &vnstatEnabledUserSet, func(s *CollectorsDisableSwitch) { s.Vnstat = true }},
	{"exporter.enable-netbird-details", "OPN2OTEL_ENABLE_NETBIRD_DETAILS", netbirdDetailsEnabled, &netbirdDetailsEnabledUserSet, func(s *CollectorsDisableSwitch) { s.NetbirdDetails = true }},
}

// explicitlySet reports whether the operator supplied b's flag themselves,
// either as a CLI token (tracked via userSet, wired through IsSetByUser at flag
// registration) or through its own env var (checked directly via os.LookupEnv,
// since kingpin's IsSetByUser callback never fires for an Envar-sourced value -
// see flags.go: isSetByUser() is only called from the CLI token parse path).
func (b enableFlagBinding) explicitlySet() bool {
	if b.userSet != nil && *b.userSet {
		return true
	}
	if b.envar != "" {
		if _, ok := os.LookupEnv(b.envar); ok {
			return true
		}
	}
	return false
}

// AutoEnabledFeature is one collector switch --exporter.enable-all-available
// turned on that the operator had not already set themselves. main logs each
// one individually with its Reason (#517 decision C: "log every feature
// enabled and why it was gated"), plus a --exporter.series-budget reminder
// once more than 5 are enabled in one run.
type AutoEnabledFeature struct {
	Flag      string
	Subsystem string
	Reason    string
}

// ApplyEnableAllAvailable is --exporter.enable-all-available's entire effect:
// when set, every --exporter.enable-* switch the operator left untouched is
// flipped to true, and the list of what changed is returned so main can log it.
//
// "AVAILABLE" in the flag's name distinguishes what it touches (opt-in
// COLLECTORS, all 24 of them) from what it never touches (the syslog/Zenarmor/
// NetFlow receivers): a collector left on is harmless when its plugin turns
// out to be absent - every plugin-gated Fetch* already treats a 404 as
// "feature absent" and stays silent (mirroring the disable-* default-on
// collectors' existing self-activation behaviour, e.g. ACME lighting up the
// moment os-acme-client is installed, #517's own motivating example) - but a
// receiver LISTENS ON A NETWORK SOCKET, which is never something a blanket
// switch should open unattended.
//
// An operator's own choice always wins, whether given on the command line or
// via the flag's env var (enableFlagBinding.explicitlySet): this only fills in
// switches nobody has touched, never overrides one somebody set.
func ApplyEnableAllAvailable(switches CollectorsDisableSwitch) (CollectorsDisableSwitch, []AutoEnabledFeature) {
	return applyEnableAllAvailable(*enableAllAvailable, enableFlagBindings, switches, nil, false)
}

// ApplyEnableAllAvailableProbed is the same thing once availability is actually
// known: a collector whose plugin the prober found ABSENT is left off, so the flag
// means what its name says (#525 decision 4).
//
// available maps a collector subsystem to whether its plugin answered. A subsystem
// MISSING from the map is enabled: most opt-in collectors are gated on API cost or
// cardinality rather than on a plugin, and there is nothing to discover about
// those — treating "not probed" as "not available" would silently disable
// everything the prober does not cover.
//
// Passing a nil map (ApplyEnableAllAvailable above) fails OPEN and enables
// everything, which is both the pre-#525 behaviour and the only honest answer
// where availability cannot be established: the --config.check preflight, which
// must not touch the network, and a firewall that was unreachable at boot. A box
// that is briefly down must never come back up as a smaller exporter than the
// operator asked for.
func ApplyEnableAllAvailableProbed(switches CollectorsDisableSwitch, available map[string]bool) (CollectorsDisableSwitch, []AutoEnabledFeature) {
	return applyEnableAllAvailable(*enableAllAvailable, enableFlagBindings, switches, available, available != nil)
}

// applyEnableAllAvailable is ApplyEnableAllAvailable's testable core: it takes
// the blanket flag's value and the binding table as plain parameters instead
// of reading the package-level kingpin flags directly, so collectors_test.go
// can exercise the precedence rules (explicit CLI flag wins, explicit env var
// wins, an untouched flag gets enabled) against synthetic bindings without
// mutating the real global flags kingpin owns for the whole test binary.
func applyEnableAllAvailable(enableAll bool, bindings []enableFlagBinding, switches CollectorsDisableSwitch, available map[string]bool, probed bool) (CollectorsDisableSwitch, []AutoEnabledFeature) {
	if !enableAll {
		return switches, nil
	}

	reasons := make(map[string]string, len(CollectorFlags))
	subsystems := make(map[string]string, len(CollectorFlags))
	for _, cf := range CollectorFlags {
		reasons[cf.Flag] = cf.Reason
		subsystems[cf.Flag] = cf.Subsystem
	}

	var enabled []AutoEnabledFeature
	for _, b := range bindings {
		if b.explicitlySet() {
			continue
		}
		if probed {
			// Only skip on a POSITIVE finding of absence. An unprobed subsystem, or
			// one whose probe could not be answered, is enabled as before.
			if got, known := available[subsystems[b.flag]]; known && !got {
				continue
			}
		}
		b.apply(&switches)
		enabled = append(enabled, AutoEnabledFeature{
			Flag:      b.flag,
			Subsystem: subsystems[b.flag],
			Reason:    reasons[b.flag],
		})
	}
	return switches, enabled
}
