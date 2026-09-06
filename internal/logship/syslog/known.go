package syslog

import "regexp"

// A known message is deliberately unstructured, not successfully parsed. It is
// still shipped and enriched. Only capture and parser-coverage diagnostics omit
// it. Reasons are code-defined; no whole-program exemption is allowed.
type knownRule struct {
	pattern *regexp.Regexp
	reason  string
}

var knownRules = map[string][]knownRule{}

func knownMessage(program, reason, pattern string) {
	knownRules[program] = append(knownRules[program], knownRule{regexp.MustCompile("^(?:" + pattern + ")[ \t]*$"), reason})
}

func knownPassThrough(env Envelope) string {
	// The opt-in buys structure, not delivery. Recognise only COMPLETE supported
	// query grammars; a future or malformed query stays an unknown even if disabled.
	if env.Program == "unbound" && !perQueryRouteEnabled() && (reUnboundQueryLog.MatchString(env.Message) || reUnboundReplyLog.MatchString(env.Message)) {
		return "unbound_per_query_disabled"
	}
	for _, rule := range knownRules[env.Program] {
		if rule.pattern.MatchString(env.Message) {
			return rule.reason
		}
	}
	return ""
}

func init() {
	knownMessage("dhclient", "dhclient_script_side_effect", `dhclient-script: Creating resolv\.conf`)
	knownMessage("dhclient", "dhclient_script_side_effect", `dhclient-script: New Hostname \([\w.-]+\): [\w.-]+`)
	knownMessage("configd.py", "template_generation", `generate template container OPNsense/[\w/-]+`)
	knownMessage("configd.py", "template_generation", ` OPNsense/[\w/*-]+ generated //[\w/.*-]+`)
	knownMessage("configctl", "forwarded_config_event", `event @ \d+\.\d+ msg: [A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} \S+ config\[\d+\]: config-event: new_config /conf/backup/config-\d+\.\d+\.xml`)
	for _, p := range []string{"Configuration reload requested over control channel;", "Loading the new configuration;", "Configuration reload finished;"} {
		knownMessage("syslog-ng", "logging_lifecycle", regexp.QuoteMeta(p))
	}
	knownMessage("syslog-ng", "logging_lifecycle", `syslog-ng (?:starting up|shutting down); version='[\w.+-]+'`)
	knownMessage("unbound", "resolver_housekeeping", `Database auto restore from /var/cache/[\w./-]+ for cleanup reasons in \d+(?:\.\d+)? seconds`)
	knownMessage("unbound", "resolver_housekeeping", `(?:Closing logger|Backgrounding unbound logging backend\.)`)
	knownMessage("unbound", "resolver_module_start", `\[\d+:\d+\] notice: init module \d+: (?:python|iterator)`)
	knownMessage("unbound", "resolver_stats_dump", `\[\d+:\d+\] info: server stats for thread \d+: \d+ queries, \d+ answers from cache, \d+ recursions, \d+ prefetch, \d+ rejected by ip ratelimiting`)
	knownMessage("unbound", "resolver_stats_dump", `\[\d+:\d+\] info: server stats for thread \d+: requestlist max \d+ avg \d+(?:\.\d+)? exceeded \d+ jostled \d+`)
	knownMessage("unbound", "resolver_stats_dump", `\[\d+:\d+\] info: average recursion processing time \d+\.\d+ sec`)
	knownMessage("unbound", "resolver_stats_dump", `\[\d+:\d+\] info: (?:histogram of recursion processing times|lower\(secs\) upper\(secs\) recursions)`)
	knownMessage("unbound", "resolver_stats_dump", `\[\d+:\d+\] info: \[25%\]=\d+\.\d+ median\[50%\]=\d+\.\d+ \[75%\]=\d+\.\d+`)
	knownMessage("unbound", "resolver_stats_dump", `\[\d+:\d+\] info: +\d+\.\d+ +\d+\.\d+ +\d+`)
	knownMessage("dnsmasq", "dns_configuration", `using only locally-known addresses for \S+`)
	knownMessage("dnsmasq", "dns_configuration", `(?:read /[\w/.-]+ - \d+ names|started, version [\w.+-]+ cachesize \d+|exiting on receipt of SIGTERM|daemonize dnsmasq dhcpd watcher\.)`)
	knownMessage("dnsmasq", "dns_build_features", `compile time options: (?:IPv[46]|GNU-getopt|no-DBus|no-UBus|no-i18n|no-IDN|DHCP|DHCPv6|no-Lua|TFTP|no-conntrack|ipset|no-nftset|auth|DNSSEC|loop-detect|inotify|dumpfile)(?: (?:IPv[46]|GNU-getopt|no-DBus|no-UBus|no-i18n|no-IDN|DHCP|DHCPv6|no-Lua|TFTP|no-conntrack|ipset|no-nftset|auth|DNSSEC|loop-detect|inotify|dumpfile))*`)
	knownMessage("dnsmasq-dhcp", "dhcp_range_configuration", `DHCP, IP range [\d.]+ -- [\d.]+, lease time \d+[hms]`)
	knownMessage("kea-dhcp6", "dhcp_helper_start", `startup kea prefix watcher`)
	knownMessage("sshd", "ssh_listener_lifecycle", `(?:Server listening on [\da-fA-F:.%a-z_-]+ port \d+\.|Received signal \d+; terminating\.)`)
	knownMessage("devd", "device_dispatch_trace", `(?:Pushing table|Processing notify event|Popping table|Testing media type of [\w.-]+ against (?:\d+|0x[0-9a-fA-F]+)|[\w.-]+ has media type (?:\d+|0x[0-9a-fA-F]+))`)
	knownMessage("devd", "device_dispatch_trace", `Executing '/usr/local/sbin/configctl interface linkup (?:start|stop) \$'[\w.-]+''`)
	knownMessage("miniupnpd", "upnp_listener_lifecycle", `(?:shutting down MiniUPnPd|Listening for NAT-PMP/PCP traffic on port \d+)`)
	knownMessage("radvd", "router_advertisement_lifecycle", `(?:attempting to reread config file|config file, /var/etc/[\w.-]+, syntax ok|resuming normal operation|exiting, \d+ sigterm\(s\) received|sending stop adverts|removing /var/run/[\w.-]+|returning from radvd main|version [\d.]+ started)`)
	knownMessage("rtsold", "router_solicitation_probe", `<rtsock_input_ifannounce> interface [\w.-]+ (?:removed|inserted)`)
	knownMessage("rtsold", "router_solicitation_probe", `<autoifprobe> probing [\w.-]+`)
	knownMessage("rtsold", "router_solicitation_probe", `<make_packet> link-layer address option has null length on [\w.-]+\. Treat as not included\.`)
	knownMessage("charon", "ipsec_host_interface_notice", `\d+\[KNL\] [\da-fA-F:.%a-z_-]+ (?:appeared on|disappeared from) [\w.-]+`)
	knownMessage("charon", "ipsec_host_interface_notice", `\d+\[KNL\] interface [\w.-]+ (?:activated|deactivated|appeared|disappeared)`)
	knownMessage("root", "bogon_update_progress", `(?:bogons update starting|update bogons is ending the update cycle|Bogons V[46] file updated: no changes\.|Bogons V[46] file updated: \d+ addresses (?:added|deleted)\.)`)
	knownMessage("firewall", "alias_cleanup", `remove old alias [\w.-]+`)
}
