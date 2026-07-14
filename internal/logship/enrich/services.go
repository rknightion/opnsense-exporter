package enrich

import "strings"

// services maps "port/proto" to a human-readable service name.
//
// This is deliberately a SHORT hand-picked table, not an IANA registry: the goal
// is a log line an operator can read at a glance ("dst.service=ssh"), and an
// exhaustive registry would mostly add noise (and label churn) for ports nobody
// recognises anyway. A port that is not listed simply carries no service
// attribute — never a guess.
var services = map[string]string{
	// remote access / management
	"22/tcp":   "ssh",
	"23/tcp":   "telnet",
	"3389/tcp": "rdp",
	"5900/tcp": "vnc",

	// naming / discovery
	"53/tcp":   "domain",
	"53/udp":   "domain",
	"853/tcp":  "dns-over-tls",
	"5353/udp": "mdns",
	"137/udp":  "netbios-ns",
	"138/udp":  "netbios-dgm",
	"139/tcp":  "netbios-ssn",
	"445/tcp":  "smb",

	// web
	"80/tcp":   "http",
	"443/tcp":  "https",
	"443/udp":  "quic",
	"8080/tcp": "http-alt",
	"8443/tcp": "https-alt",

	// mail
	"25/tcp":  "smtp",
	"110/tcp": "pop3",
	"143/tcp": "imap",
	"465/tcp": "smtps",
	"587/tcp": "submission",
	"993/tcp": "imaps",
	"995/tcp": "pop3s",

	// infrastructure
	"67/udp":   "dhcp",
	"68/udp":   "dhcp",
	"69/udp":   "tftp",
	"123/udp":  "ntp",
	"161/udp":  "snmp",
	"162/udp":  "snmp-trap",
	"514/udp":  "syslog",
	"514/tcp":  "syslog",
	"546/udp":  "dhcpv6",
	"547/udp":  "dhcpv6",
	"389/tcp":  "ldap",
	"636/tcp":  "ldaps",
	"88/tcp":   "kerberos",
	"1812/udp": "radius",
	"1813/udp": "radius-acct",

	// vpn / tunnels
	"500/udp":   "isakmp",
	"4500/udp":  "ipsec-nat-t",
	"1194/udp":  "openvpn",
	"1701/udp":  "l2tp",
	"1723/tcp":  "pptp",
	"51820/udp": "wireguard",

	// storage / databases / queues
	"3306/tcp":  "mysql",
	"5432/tcp":  "postgresql",
	"6379/tcp":  "redis",
	"27017/tcp": "mongodb",
	"11211/tcp": "memcached",
	"9200/tcp":  "elasticsearch",

	// misc
	"21/tcp":   "ftp",
	"179/tcp":  "bgp",
	"631/tcp":  "ipp",
	"1900/udp": "ssdp",
	"3128/tcp": "http-proxy",
	"5060/udp": "sip",
	"5060/tcp": "sip",
	"9100/tcp": "jetdirect",
}

// ServiceName resolves a port/protocol pair to a well-known service name.
// Unlisted ports return ("", false) — the caller then omits the attribute.
func ServiceName(port, proto string) (string, bool) {
	if port == "" || proto == "" {
		return "", false
	}
	v, ok := services[port+"/"+strings.ToLower(proto)]
	return v, ok
}
