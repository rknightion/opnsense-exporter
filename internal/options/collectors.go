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
	openVPNCollectorDisabled = kingpin.Flag(
		"exporter.disable-openvpn",
		"Disable the scraping of OpenVPN service",
	).Envar("OPNSENSE_EXPORTER_DISABLE_OPENVPN").Default("false").Bool()
	firewallCollectorDisabled = kingpin.Flag(
		"exporter.disable-firewall",
		"Disable the scraping of the firewall (pf) metrics",
	).Envar("OPNSENSE_EXPORTER_DISABLE_FIREWALL").Default("false").Bool()
	firmwareCollectorDisabled = kingpin.Flag(
		"exporter.disable-firmware",
		"Disable the scraping of the firmware metrics",
	).Envar("OPNSENSE_EXPORTER_DISABLE_FIRMWARE").Default("false").Bool()
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
		"Disable the scraping of per-rule firewall statistics",
	).Envar("OPNSENSE_EXPORTER_DISABLE_FIREWALL_RULES").Default("false").Bool()
	firewallRulesDetailsEnabled = kingpin.Flag(
		"exporter.enable-firewall-rules-details",
		"Enable per-rule detail metrics for firewall rules (high cardinality on large rulesets)",
	).Envar("OPNSENSE_EXPORTER_ENABLE_FIREWALL_RULES_DETAILS").Default("false").Bool()
)

// CollectorsDisableSwitch hold the enabled/disabled state of the collectors
type CollectorsDisableSwitch struct {
	ARP                  bool
	Cron                 bool
	Wireguard            bool
	IPsec                bool
	Unbound              bool
	OpenVPN              bool
	Firewall             bool
	Firmware             bool
	Dnsmasq              bool
	DnsmasqDetails       bool
	FirewallRules        bool
	FirewallRulesDetails bool
	System               bool
	Temperature          bool
}

// CollectorsSwitches returns configured instances of CollectorsDisableSwitch
func CollectorsSwitches() CollectorsDisableSwitch {
	return CollectorsDisableSwitch{
		ARP:                  !*arpTableCollectorDisabled,
		Cron:                 !*cronTableCollectorDisabled,
		Wireguard:            !*wireguardCollectorDisabled,
		IPsec:                !*ipsecCollectorDisabled,
		Unbound:              !*unboundCollectorDisabled,
		OpenVPN:              !*openVPNCollectorDisabled,
		Firewall:             !*firewallCollectorDisabled,
		Firmware:             !*firmwareCollectorDisabled,
		Dnsmasq:              !*dnsmasqCollectorDisabled,
		DnsmasqDetails:       *dnsmasqDetailsEnabled,
		FirewallRules:        !*firewallRulesCollectorDisabled,
		FirewallRulesDetails: *firewallRulesDetailsEnabled,
		System:               !*systemCollectorDisabled,
		Temperature:          !*temperatureCollectorDisabled,
	}
}
