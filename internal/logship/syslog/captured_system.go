package syslog

// Paths identify the rc-script grammar, not an arbitrary log-message prefix.
const opnsenseScript = `/usr/local/(?:etc/rc\.[\w.-]+(?:\.d/monitor/\d+-recover)?|sbin/pluginctl): `
const lighttpdLocation = `\(/usr/obj/usr/ports/www/lighttpd/work/lighttpd-[\w.+-]+/src/[\w.-]+\.c\.\d+\) `

func init() {
	capturedEvent("lighttpd", "web_backend_connection_failed", lighttpdLocation+`connect\(\) (/var/lib/php/tmp/[\w.-]+): ([^\r\n]+)`, "web.backend_socket", "error.message")
	capturedEvent("lighttpd", "web_tls_failed", lighttpdLocation+`SSL: addr:(\S+) ssl_err:(\d+) rd:(-?\d+) ([^\r\n]+)`, "web.client_address", "tls.error_code", "web.read_result", "error.message")
	knownMessage("lighttpd", "web_server_lifecycle", lighttpdLocation+`(?:server stopped by UID = \d+ PID = \d+|\[note\] graceful shutdown started|server started \(lighttpd/[\w.+-]+\))`)
	capturedEvent("devd", "interface_notification", `Processing event '!system=IFNET subsystem=([\w.-]+) type=(ADDR_ADD|ADDR_DEL) (?:address|inet|inet6)=(\S+)'`, "interface", "interface.notification", "interface.address")
	capturedEvent("devd", "interface_notification", `Processing event '!system=IFNET subsystem=([\w.-]+) type=(ATTACH|DETACH)'`, "interface", "interface.notification")
	capturedEvent("devd", "interface_renamed", `Processing event '!system=IFNET subsystem=([\w.-]+) type=RENAME name=([\w.-]+)'`, "interface.previous", "interface")
	knownMessage("devd", "device_node_notice", `Processing event '!system=DEVFS subsystem=CDEV type=(?:CREATE|DESTROY) cdev=[\w.-]+'`)
	knownMessage("devd", "device_dispatch_trace", `check_clients:  dropping disconnected client`)
	capturedEvent("opnsense", "interface_attachment_changed", opnsenseScript+`DEVD: Ethernet (attached|detached) event for ([\w.-]+)\(([\w.-]+)\)`, "interface.attachment", "interface.name", "interface")
	capturedEvent("opnsense", "interface_address_detection_failed", opnsenseScript+`Failed to detect IP for interface ([\w.-]+)`, "interface.name")
	capturedEvent("opnsense", "interface_address_renewal_started", opnsenseScript+`IP renewal starting \(new: (\S+), old: (\S+), interface: ([\w.-]+), device: ([\w.-]+), force: (yes|no)\)`, "interface.address", "interface.address.previous", "interface.name", "interface", "interface.force")
	capturedEvent("opnsense", "interface_address_renewal_started", opnsenseScript+`IP renewal starting \(reason: (force|request), address: (\S+) interface: ([\w.-]+), device: ([\w.-]+)\)`, "interface.reason", "interface.address", "interface.name", "interface")
	capturedEvent("opnsense", "default_route_set", opnsenseScript+`ROUTING: setting (inet6?) default route to (\S+)`, "route.address_family", "route.gateway")
	capturedEvent("opnsense", "gateway_ignored_down", opnsenseScript+`ROUTING: ignoring down gateways: ([\w.-]+)`, "gateway.name")
	capturedEvent("opnsense", "gateway_states_killed", opnsenseScript+`ROUTING: killing states for unreachable gateway ([\w.-]+) \[([0-9a-fA-F-]+)\]`, "gateway.name", "gateway.id")
	capturedEvent("opnsense", "gateway_bind_fallback", opnsenseScript+`Chose to bind ([\w.-]+) on (\S+) since we could not find a proper match\.`, "gateway.name", "gateway.bind_address")
	capturedEvent("opnsense", "tunable_missing", opnsenseScript+`warning: ignoring missing default tunable request: ([\w.]+)`, "system.tunable")
	capturedEvent("opnsense", "router_advertisement_address_missing", opnsenseScript+`radvd_configure_do\(auto\) found no suitable IPv6 address on ([\w.-]+)\(([\w.-]+)\)`, "interface.name", "interface")
	// Exact syntax of a dispatch trace. Arguments are identifiers, numbers and
	// lists, not an arbitrary suffix that could hide a future failure sentence.
	knownMessage("opnsense", "plugin_dispatch_trace", opnsenseScript+`plugins_configure [\w:]+ \((?:execute task : [\w]+\()?[-\w,\[\]]*\)?\)`)
	knownMessage("opnsense", "route_configuration_progress", opnsenseScript+`ROUTING: entering configure using (?:defaults|[\w.-]+(?:, [\w.-]+)*)`)
	knownMessage("opnsense", "route_configuration_progress", opnsenseScript+`ROUTING: treating '[\da-fA-F:.]+' as far gateway for '[\da-fA-F:./]+'`)
	knownMessage("opnsense", "route_configuration_progress", opnsenseScript+`ROUTING: configuring inet6? default gateway on [\w.-]+`)
	knownMessage("opnsense", "route_configuration_progress", opnsenseScript+`ROUTING: keeping inet6? default route to [\da-fA-F:.%a-z_0-9-]+`)
	knownMessage("opnsense", "upnp_listener_lifecycle", opnsenseScript+`miniupnpd: Starting service on interface: [\w.-]+(?:, [\w.-]+)*`)
	knownMessage("opnsense", "trust_intermediate_skip", `\(system local trust\) skip intermediate certificate /[^\r\n]+ from [^\r\n]+ \(ACME Client\)`)
	knownMessage("ntpd", "ntp_lifecycle", `ntpd exiting on signal \d+ \(Terminated\)`)
	knownMessage("ntpd", "ntp_build_banner", `ntpd [\w.@+-]+ [A-Z][a-z]{2} [A-Z][a-z]{2} +\d+ \d{2}:\d{2}:\d{2} UTC \d{4} \(\d+\): Starting`)
	knownMessage("ntpd", "ntp_configuration", `Command line: /usr/local/sbin/ntpd -g -c /var/etc/[\w.-]+`)
	knownMessage("ntpd", "ntp_build_banner", `(?:----------------------------------------------------|ntp-4 is maintained by Network Time Foundation,|Inc\. \(NTF\), a non-profit 501\(c\)\(3\) public-benefit|corporation\.  Support and training for ntp-4 are|available at https://www\.nwtime\.org/support)`)
	knownMessage("ntpd", "ntp_configuration", `(?:proto: precision = \d+\.\d+ usec \(-?\d+\)|basedate set to \d{4}-\d{2}-\d{2}|gps base set to \d{4}-\d{2}-\d{2} \(week \d+\)|initial drift restored to [+-]?\d+\.\d+)`)
	knownMessage("ntpd", "ntp_listener_notice", `Listen normally on \d+ [\w.-]+ (?:[\da-fA-F:.%a-z_-]+|\[[\da-fA-F:.%a-z_-]+\]:\d+)`)
	knownMessage("ntpd", "ntp_listener_notice", `Listening on routing socket on fd #\d+ for interface updates`)
	// PPP continuation rows describe negotiation options, not completed sessions.
	knownMessage("ppp", "ppp_negotiation_detail", `\[[\w.-]+\] (?:LCP|IPCP|IPV6CP): (?:SendConfigReq|SendConfigAck|SendTerminateAck) #\d+`)
	knownMessage("ppp", "ppp_negotiation_detail", `\[[\w.-]+\] (?:LCP|IPCP|IPV6CP): rec'd Configure (?:Request|Reject|Ack|Nak) #\d+ \((?:Req-Sent|Ack-Sent|Ack-Rcvd)\)`)
	knownMessage("ppp", "ppp_negotiation_detail", `\[[\w.-]+\]   (?:PROTOCOMP|MRU \d+|MAGICNUM 0x[0-9a-fA-F]+|AUTHPROTO CHAP MD5|IPADDR [\d.]+|COMPPROTO VJCOMP, \d+ comp\. channels, no comp-cid)`)
	knownMessage("ppp", "ppp_negotiation_detail", `\[[\w.-]+\]     [\d.]+ is OK`)
	knownMessage("ppp", "ppp_negotiation_detail", `\[[\w.-]+\] LCP: auth: peer wants CHAP, I want nothing`)
	knownMessage("ppp", "ppp_negotiation_detail", `\[[\w.-]+\] PPPoE: (?:Set PPP-Max-Payload to '\d+'|rec'd PPP-Max-Payload '\d+'|Connecting to '[^'\r\n]*')`)
	knownMessage("ppp", "ppp_peer_text", `PPPoE: rec'd ACNAME "[^"\r\n]+"`)
	knownMessage("ppp", "ppp_peer_text", `\[[\w.-]+\]   (?:Name: "[^"\r\n]+"|MESG: [^\r\n]+)`)
	knownMessage("ppp", "ppp_negotiation_detail", `\[[\w.-]+\] CHAP: (?:rec'd CHALLENGE|sending RESPONSE) #\d+ len: \d+`)
	knownMessage("ppp", "ppp_peer_text", `\[[\w.-]+\] CHAP: Using authname "[^"\r\n]+"`)
	knownMessage("ppp", "ppp_negotiation_detail", `\[[\w.-]+\] Link: Matched action 'bundle "[\w.-]+" ""'`)
	knownMessage("ppp", "ppp_negotiation_detail", `\[[\w.-]+\]   [\da-fA-F:.]+ -> [\da-fA-F:.]+`)
}
