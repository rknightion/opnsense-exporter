## OPNsense Exporter Metrics List

This table represents each metric and its labels, the subsystem that it belongs to, its description and how to disable it. The `opnsense_instance` label is applied to all metrics.

### General

![status](assets/status.png)

| Metric Name | Type | Labels | Subsystem | Description | Disable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_up | Gauge | n/a | n/a | Was the last scrape of OPNsense successful (1 = yes, 0 = no) | n/a |
| opnsense_firewall_status | Gauge | n/a | n/a | Status of the firewall reported by the system health check (1 = ok, 0 = errors) | n/a |
| opnsense_system_status_code | Gauge | n/a | n/a | Numeric system status code from health check (2 = OK for OPNsense >= 25.1) | n/a |
| opnsense_exporter_scrapes_total | Counter | n/a | n/a | Total number of times OPNsense was scraped for metrics | n/a |
| opnsense_exporter_endpoint_errors_total | Counter | endpoint | n/a | Total number of errors by endpoint returned by the OPNsense API during data fetching | n/a |

### Cron

| Metric Name | Type | Labels | Subsystem | Description | Disable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_cron_job_status | Gauge | schedule, description, command, origin | Cron | Cron job status by name and description (1 = enabled, 0 = disabled) | --exporter.disable-cron-table |

### Services

![services](assets/services.png)

| Metric Name | Type | Labels | Subsystem | Description | Disable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_services_running_total | Gauge | n/a | Services | Total number of running services | n/a |
| opnsense_services_stopped_total | Gauge | n/a | Services | Total number of stopped services | n/a |
| opnsense_services_status | Gauge | name, description | Services | Service status by name and description (1 = running, 0 = stopped) | n/a |

### Interfaces

![interfaces](assets/interfaces.png)

| Metric Name | Type | Labels | Subsystem | Description | Disable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_interfaces_mtu_bytes | Gauge | interface, device, type | Interfaces | The MTU value of the interface | n/a |
| opnsense_interfaces_received_bytes_total | Counter | interface, device, type | Interfaces | Bytes received on this interface by interface name and device | n/a |
| opnsense_interfaces_transmitted_bytes_total | Counter | interface, device, type | Interfaces | Bytes transmitted on this interface by interface name and device | n/a |
| opnsense_interfaces_received_packets_total | Counter | interface, device, type | Interfaces | Total packets received on this interface by interface name and device | n/a |
| opnsense_interfaces_transmitted_packets_total | Counter | interface, device, type | Interfaces | Total packets transmitted on this interface by interface name and device | n/a |
| opnsense_interfaces_received_multicasts_total | Counter | interface, device, type | Interfaces | Multicasts received on this interface by interface name and device | n/a |
| opnsense_interfaces_transmitted_multicasts_total | Counter | interface, device, type | Interfaces | Multicasts transmitted on this interface by interface name and device | n/a |
| opnsense_interfaces_input_errors_total | Counter | interface, device, type | Interfaces | Input errors on this interface by interface name and device | n/a |
| opnsense_interfaces_output_errors_total | Counter | interface, device, type | Interfaces | Output errors on this interface by interface name and device | n/a |
| opnsense_interfaces_collisions_total | Counter | interface, device, type | Interfaces | Collisions on this interface by interface name and device | n/a |
| opnsense_interfaces_send_queue_length | Gauge | interface, device, type | Interfaces | Current send queue length on this interface by interface name and device | n/a |
| opnsense_interfaces_send_queue_max_length | Gauge | interface, device, type | Interfaces | Maximum send queue length on this interface by interface name and device | n/a |
| opnsense_interfaces_send_queue_drops_total | Counter | interface, device, type | Interfaces | Send queue drops on this interface by interface name and device | n/a |
| opnsense_interfaces_input_queue_drops_total | Counter | interface, device, type | Interfaces | Input queue drops on this interface by interface name and device | n/a |
| opnsense_interfaces_link_state | Gauge | interface, device, type | Interfaces | Link state of this interface (1 = up, 0 = down) by interface name and device | n/a |
| opnsense_interfaces_line_rate_bits | Gauge | interface, device, type | Interfaces | Line rate in bits per second on this interface by interface name and device | n/a |

### Firewall

| Metric Name | Type | Labels | Subsystem | Description | Disable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_firewall_in_ipv4_pass_packets | Gauge | interface | Firewall | The number of IPv4 incoming packets that were allowed to pass through the firewall by interface | --exporter.disable-firewall |
| opnsense_firewall_out_ipv4_pass_packets | Gauge | interface | Firewall | The number of IPv4 outgoing packets that were allowed to pass through the firewall by interface | --exporter.disable-firewall |
| opnsense_firewall_in_ipv4_block_packets | Gauge | interface | Firewall | The number of IPv4 incoming packets that were blocked by the firewall by interface | --exporter.disable-firewall |
| opnsense_firewall_out_ipv4_block_packets | Gauge | interface | Firewall | The number of IPv4 outgoing packets that were blocked by the firewall by interface | --exporter.disable-firewall |
| opnsense_firewall_in_ipv6_pass_packets | Gauge | interface | Firewall | The number of IPv6 incoming packets that were allowed to pass through the firewall by interface | --exporter.disable-firewall |
| opnsense_firewall_out_ipv6_pass_packets | Gauge | interface | Firewall | The number of IPv6 outgoing packets that were allowed to pass through the firewall by interface | --exporter.disable-firewall |
| opnsense_firewall_in_ipv6_block_packets | Gauge | interface | Firewall | The number of IPv6 incoming packets that were blocked by the firewall by interface | --exporter.disable-firewall |
| opnsense_firewall_out_ipv6_block_packets | Gauge | interface | Firewall | The number of IPv6 outgoing packets that were blocked by the firewall by interface | --exporter.disable-firewall |
| opnsense_firewall_in_ipv4_pass_bytes_total | Gauge | interface | Firewall | The number of IPv4 incoming bytes that were allowed to pass through the firewall by interface | --exporter.disable-firewall |
| opnsense_firewall_out_ipv4_pass_bytes_total | Gauge | interface | Firewall | The number of IPv4 outgoing bytes that were allowed to pass through the firewall by interface | --exporter.disable-firewall |
| opnsense_firewall_in_ipv4_block_bytes_total | Gauge | interface | Firewall | The number of IPv4 incoming bytes that were blocked by the firewall by interface | --exporter.disable-firewall |
| opnsense_firewall_out_ipv4_block_bytes_total | Gauge | interface | Firewall | The number of IPv4 outgoing bytes that were blocked by the firewall by interface | --exporter.disable-firewall |
| opnsense_firewall_in_ipv6_pass_bytes_total | Gauge | interface | Firewall | The number of IPv6 incoming bytes that were allowed to pass through the firewall by interface | --exporter.disable-firewall |
| opnsense_firewall_out_ipv6_pass_bytes_total | Gauge | interface | Firewall | The number of IPv6 outgoing bytes that were allowed to pass through the firewall by interface | --exporter.disable-firewall |
| opnsense_firewall_in_ipv6_block_bytes_total | Gauge | interface | Firewall | The number of IPv6 incoming bytes that were blocked by the firewall by interface | --exporter.disable-firewall |
| opnsense_firewall_out_ipv6_block_bytes_total | Gauge | interface | Firewall | The number of IPv6 outgoing bytes that were blocked by the firewall by interface | --exporter.disable-firewall |
| opnsense_firewall_pf_states_current | Gauge | n/a | Firewall | Current number of active PF states | --exporter.disable-firewall |
| opnsense_firewall_pf_states_limit | Gauge | n/a | Firewall | Maximum number of PF states allowed | --exporter.disable-firewall |

### Firewall Rules

| Metric Name | Type | Labels | Subsystem | Description | Disable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_firewall_rule_rules_total | Gauge | n/a | Firewall Rules | Total number of firewall rules with statistics | --exporter.disable-firewall-rules |

Per-rule detail metrics below require `--exporter.enable-firewall-rules-details` / `OPNSENSE_EXPORTER_ENABLE_FIREWALL_RULES_DETAILS=true` (high cardinality on large rulesets):

| Metric Name | Type | Labels | Subsystem | Description | Enable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_firewall_rule_evaluations_total | Counter | uuid, description, action, interface, direction | Firewall Rules | Total number of rule evaluations per firewall rule | --exporter.enable-firewall-rules-details |
| opnsense_firewall_rule_packets_total | Counter | uuid, description, action, interface, direction | Firewall Rules | Total number of packets matched per firewall rule | --exporter.enable-firewall-rules-details |
| opnsense_firewall_rule_bytes_total | Counter | uuid, description, action, interface, direction | Firewall Rules | Total number of bytes matched per firewall rule | --exporter.enable-firewall-rules-details |
| opnsense_firewall_rule_states | Gauge | uuid, description, action, interface, direction | Firewall Rules | Current number of active states per firewall rule | --exporter.enable-firewall-rules-details |
| opnsense_firewall_rule_pf_rules | Gauge | uuid, description, action, interface, direction | Firewall Rules | Number of PF rules generated per firewall rule | --exporter.enable-firewall-rules-details |

### Firmware

![firmware](assets/firmware.png)

| Metric Name | Type | Labels | Subsystem | Description | Disable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_firmware_info | Gauge | os_version, product_version, product_id, product_abi | Firmware | OPNsense firmware information (value is always 1) | --exporter.disable-firmware |
| opnsense_firmware_needs_reboot | Gauge | n/a | Firmware | Whether OPNsense needs a reboot (1 = yes, 0 = no) | --exporter.disable-firmware |
| opnsense_firmware_upgrade_needs_reboot | Gauge | n/a | Firmware | Whether the upgrade requires a reboot (1 = yes, 0 = no) | --exporter.disable-firmware |
| opnsense_firmware_last_check_timestamp_seconds | Gauge | n/a | Firmware | Unix timestamp of the last firmware update check | --exporter.disable-firmware |
| opnsense_firmware_new_packages_count | Gauge | n/a | Firmware | Number of new packages available | --exporter.disable-firmware |
| opnsense_firmware_upgrade_packages_count | Gauge | n/a | Firmware | Number of packages with available upgrades | --exporter.disable-firmware |

### ARP Table

![arp](assets/arp.png)

| Metric Name | Type | Labels | Subsystem | Description | Disable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_arp_table_entries | Gauge | ip, mac, hostname, interface_description, type, expired, permanent | ARP Table | ARP entries by ip, mac, hostname, interface description, type, expired and permanent | --exporter.disable-arp-table |

### Gateways

![gateways](assets/gateways.png)

| Metric Name | Type | Labels | Subsystem | Description | Disable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_gateways_info | Gauge | name, description, device, protocol, enabled, weight, interface, upstream | Gateways | Configuration details of the gateway | n/a |
| opnsense_gateways_monitor_info | Gauge | name, enabled, no_route, address | Gateways | Configuration details of the gateway monitoring | n/a |
| opnsense_gateways_status | Gauge | name, address, default_gateway | Gateways | Status of the gateway by name and address (0 = Offline, 1 = Online, 2 = Unknown, 3 = Pending) | n/a |
| opnsense_gateways_rtt_milliseconds | Gauge | name, address | Gateways | RTT is the average (mean) of the round trip time in milliseconds by name and address | n/a |
| opnsense_gateways_rttd_milliseconds | Gauge | name, address | Gateways | RTTd is the standard deviation of the round trip time in milliseconds by name and address | n/a |
| opnsense_gateways_rtt_low_milliseconds | Gauge | name, address | Gateways | Lower threshold for the round trip time in milliseconds by name and address | n/a |
| opnsense_gateways_rtt_high_milliseconds | Gauge | name, address | Gateways | Upper threshold for the round trip time in milliseconds by name and address | n/a |
| opnsense_gateways_loss_percentage | Gauge | name, address | Gateways | The current gateway loss percentage by name and address | n/a |
| opnsense_gateways_loss_low_percentage | Gauge | name, address | Gateways | Lower threshold for the packet loss ratio by name and address | n/a |
| opnsense_gateways_loss_high_percentage | Gauge | name, address | Gateways | Upper threshold for the packet loss ratio by name and address | n/a |
| opnsense_gateways_probe_interval_seconds | Gauge | name, address | Gateways | Monitoring probe interval duration by name and address | n/a |
| opnsense_gateways_probe_period_seconds | Gauge | name, address | Gateways | Monitoring probe period over which results are averaged by name and address | n/a |
| opnsense_gateways_probe_timeout_seconds | Gauge | name, address | Gateways | Monitoring probe timeout by name and address | n/a |

### System

| Metric Name | Type | Labels | Subsystem | Description | Disable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_system_memory_total_bytes | Gauge | n/a | System | Total physical memory in bytes | --exporter.disable-system |
| opnsense_system_memory_used_bytes | Gauge | n/a | System | Used physical memory in bytes | --exporter.disable-system |
| opnsense_system_memory_arc_bytes | Gauge | n/a | System | ZFS ARC memory usage in bytes | --exporter.disable-system |
| opnsense_system_uptime_seconds | Gauge | n/a | System | System uptime in seconds | --exporter.disable-system |
| opnsense_system_load_average | Gauge | interval | System | System load average (interval is 1, 5, or 15 minutes) | --exporter.disable-system |
| opnsense_system_config_last_change | Gauge | n/a | System | Unix timestamp of last configuration change | --exporter.disable-system |
| opnsense_system_disk_total_bytes | Gauge | device, type, mountpoint | System | Total disk space in bytes | --exporter.disable-system |
| opnsense_system_disk_used_bytes | Gauge | device, type, mountpoint | System | Used disk space in bytes | --exporter.disable-system |
| opnsense_system_disk_usage_ratio | Gauge | device, type, mountpoint | System | Disk usage as a ratio from 0.0 to 1.0 | --exporter.disable-system |
| opnsense_system_swap_total_bytes | Gauge | device | System | Total swap space in bytes | --exporter.disable-system |
| opnsense_system_swap_used_bytes | Gauge | device | System | Used swap space in bytes | --exporter.disable-system |

### Activity

| Metric Name | Type | Labels | Subsystem | Description | Disable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_activity_threads_total | Gauge | n/a | Activity | Total number of threads on the system | --exporter.disable-activity |
| opnsense_activity_threads_running | Gauge | n/a | Activity | Number of running threads on the system | --exporter.disable-activity |
| opnsense_activity_threads_sleeping | Gauge | n/a | Activity | Number of sleeping threads on the system | --exporter.disable-activity |
| opnsense_activity_threads_waiting | Gauge | n/a | Activity | Number of waiting threads on the system | --exporter.disable-activity |
| opnsense_activity_cpu_user_percent | Gauge | n/a | Activity | CPU user usage percentage | --exporter.disable-activity |
| opnsense_activity_cpu_nice_percent | Gauge | n/a | Activity | CPU nice usage percentage | --exporter.disable-activity |
| opnsense_activity_cpu_system_percent | Gauge | n/a | Activity | CPU system usage percentage | --exporter.disable-activity |
| opnsense_activity_cpu_interrupt_percent | Gauge | n/a | Activity | CPU interrupt usage percentage | --exporter.disable-activity |
| opnsense_activity_cpu_idle_percent | Gauge | n/a | Activity | CPU idle percentage | --exporter.disable-activity |

### Temperature

| Metric Name | Type | Labels | Subsystem | Description | Disable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_temperature_celsius | Gauge | device, type, device_seq | Temperature | Temperature reading in Celsius | --exporter.disable-temperature |

### Mbuf

| Metric Name | Type | Labels | Subsystem | Description | Disable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_mbuf_current | Gauge | n/a | Mbuf | Current number of mbufs in use | --exporter.disable-mbuf |
| opnsense_mbuf_cache | Gauge | n/a | Mbuf | Number of mbufs in cache | --exporter.disable-mbuf |
| opnsense_mbuf_total | Gauge | n/a | Mbuf | Total number of mbufs available | --exporter.disable-mbuf |
| opnsense_mbuf_cluster_current | Gauge | n/a | Mbuf | Current number of mbuf clusters in use | --exporter.disable-mbuf |
| opnsense_mbuf_cluster_cache | Gauge | n/a | Mbuf | Number of mbuf clusters in cache | --exporter.disable-mbuf |
| opnsense_mbuf_cluster_total | Gauge | n/a | Mbuf | Total number of mbuf clusters available | --exporter.disable-mbuf |
| opnsense_mbuf_cluster_max | Gauge | n/a | Mbuf | Maximum number of mbuf clusters | --exporter.disable-mbuf |
| opnsense_mbuf_failures_total | Counter | type | Mbuf | Total number of mbuf allocation failures by type | --exporter.disable-mbuf |
| opnsense_mbuf_sleeps_total | Counter | type | Mbuf | Total number of mbuf allocation sleeps by type | --exporter.disable-mbuf |
| opnsense_mbuf_bytes_in_use | Gauge | n/a | Mbuf | Number of bytes of memory currently in use by mbufs | --exporter.disable-mbuf |
| opnsense_mbuf_bytes_total | Gauge | n/a | Mbuf | Total number of bytes of memory available for mbufs | --exporter.disable-mbuf |

### Certificates

| Metric Name | Type | Labels | Subsystem | Description | Disable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_certificate_info | Gauge | description, commonname, cert_type, in_use | Certificates | Certificate information (value is always 1) | --exporter.disable-certificates |
| opnsense_certificate_valid_from_seconds | Gauge | description, commonname, cert_type, in_use | Certificates | Certificate valid from timestamp in seconds since epoch | --exporter.disable-certificates |
| opnsense_certificate_valid_to_seconds | Gauge | description, commonname, cert_type, in_use | Certificates | Certificate valid to (expiry) timestamp in seconds since epoch | --exporter.disable-certificates |
| opnsense_certificate_total | Gauge | n/a | Certificates | Total number of certificates | --exporter.disable-certificates |

### NTP

| Metric Name | Type | Labels | Subsystem | Description | Disable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_ntp_peers_total | Gauge | n/a | NTP | Total number of NTP peers | --exporter.disable-ntp |
| opnsense_ntp_peer_info | Gauge | server, refid, type, status | NTP | NTP peer information (value is always 1) | --exporter.disable-ntp |
| opnsense_ntp_peer_stratum | Gauge | server | NTP | Stratum level of the NTP peer | --exporter.disable-ntp |
| opnsense_ntp_peer_when_seconds | Gauge | server | NTP | Seconds since last response from the NTP peer | --exporter.disable-ntp |
| opnsense_ntp_peer_poll_seconds | Gauge | server | NTP | Poll interval in seconds for the NTP peer | --exporter.disable-ntp |
| opnsense_ntp_peer_reach | Gauge | server | NTP | Reachability register of the NTP peer (octal decoded to decimal) | --exporter.disable-ntp |
| opnsense_ntp_peer_delay_milliseconds | Gauge | server | NTP | Round-trip delay to the NTP peer in milliseconds | --exporter.disable-ntp |
| opnsense_ntp_peer_offset_milliseconds | Gauge | server | NTP | Clock offset relative to the NTP peer in milliseconds | --exporter.disable-ntp |
| opnsense_ntp_peer_jitter_milliseconds | Gauge | server | NTP | Dispersion jitter of the NTP peer in milliseconds | --exporter.disable-ntp |

### CARP

| Metric Name | Type | Labels | Subsystem | Description | Disable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_carp_demotion | Gauge | n/a | CARP | CARP demotion level | --exporter.disable-carp |
| opnsense_carp_allow | Gauge | n/a | CARP | Whether CARP is allowed (1 = allowed, 0 = not allowed) | --exporter.disable-carp |
| opnsense_carp_maintenance_mode | Gauge | n/a | CARP | Whether CARP maintenance mode is enabled (1 = enabled, 0 = disabled) | --exporter.disable-carp |
| opnsense_carp_vips_total | Gauge | n/a | CARP | Total number of CARP Virtual IPs | --exporter.disable-carp |
| opnsense_carp_vip_status | Gauge | interface, vhid, vip | CARP | CARP VIP status (1 = MASTER, 0 = BACKUP, 2 = INIT, -1 = unknown) | --exporter.disable-carp |
| opnsense_carp_vip_advbase_seconds | Gauge | interface, vhid, vip | CARP | CARP VIP advertisement base interval in seconds | --exporter.disable-carp |
| opnsense_carp_vip_advskew | Gauge | interface, vhid, vip | CARP | CARP VIP advertisement skew | --exporter.disable-carp |

### Protocol Statistics

| Metric Name | Type | Labels | Subsystem | Description | Disable Flag |
| --- | --- | --- | --- | --- | --- |

#### TCP

| Metric Name | Type | Labels | Subsystem | Description | Disable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_protocol_tcp_connection_count_by_state | Gauge | state | Protocol Statistics | Number of TCP connections by state | n/a |
| opnsense_protocol_tcp_sent_packets_total | Counter | n/a | Protocol Statistics | Number of sent TCP packets | n/a |
| opnsense_protocol_tcp_received_packets_total | Counter | n/a | Protocol Statistics | Number of received TCP packets | n/a |
| opnsense_protocol_tcp_connection_requests_total | Counter | n/a | Protocol Statistics | Number of TCP connection requests | n/a |
| opnsense_protocol_tcp_connection_accepts_total | Counter | n/a | Protocol Statistics | Number of TCP connection accepts | n/a |
| opnsense_protocol_tcp_connections_established_total | Counter | n/a | Protocol Statistics | Number of TCP connections established | n/a |
| opnsense_protocol_tcp_connections_closed_total | Counter | n/a | Protocol Statistics | Number of TCP connections closed | n/a |
| opnsense_protocol_tcp_connection_drops_total | Counter | n/a | Protocol Statistics | Number of TCP connection drops | n/a |
| opnsense_protocol_tcp_retransmit_timeouts_total | Counter | n/a | Protocol Statistics | Number of TCP retransmit timeouts | n/a |
| opnsense_protocol_tcp_keepalive_timeouts_total | Counter | n/a | Protocol Statistics | Number of TCP keepalive timeouts | n/a |
| opnsense_protocol_tcp_keepalive_probes_total | Counter | n/a | Protocol Statistics | Total TCP keepalive probes sent | n/a |
| opnsense_protocol_tcp_listen_queue_overflows_total | Counter | n/a | Protocol Statistics | Number of TCP listen queue overflows | n/a |
| opnsense_protocol_tcp_syncache_entries_total | Counter | n/a | Protocol Statistics | Number of TCP syncache entries added | n/a |
| opnsense_protocol_tcp_syncache_dropped_total | Counter | n/a | Protocol Statistics | Total TCP syncache entries dropped | n/a |
| opnsense_protocol_tcp_bad_connection_attempts_total | Counter | n/a | Protocol Statistics | Total bad TCP connection attempts | n/a |
| opnsense_protocol_tcp_sent_data_bytes_total | Counter | n/a | Protocol Statistics | Total bytes of data sent via TCP | n/a |
| opnsense_protocol_tcp_retransmitted_packets_total | Counter | n/a | Protocol Statistics | Total number of TCP packets retransmitted | n/a |
| opnsense_protocol_tcp_retransmitted_bytes_total | Counter | n/a | Protocol Statistics | Total bytes retransmitted via TCP | n/a |
| opnsense_protocol_tcp_received_in_sequence_bytes_total | Counter | n/a | Protocol Statistics | Total bytes received in sequence via TCP | n/a |
| opnsense_protocol_tcp_received_duplicate_bytes_total | Counter | n/a | Protocol Statistics | Total completely duplicate bytes received via TCP | n/a |
| opnsense_protocol_tcp_segments_updated_rtt_total | Counter | n/a | Protocol Statistics | Total TCP segments that updated RTT | n/a |

#### UDP

| Metric Name | Type | Labels | Subsystem | Description | Disable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_protocol_udp_delivered_packets_total | Counter | n/a | Protocol Statistics | Number of delivered UDP packets | n/a |
| opnsense_protocol_udp_output_packets_total | Counter | n/a | Protocol Statistics | Number of output UDP packets | n/a |
| opnsense_protocol_udp_received_datagrams_total | Counter | n/a | Protocol Statistics | Number of received UDP datagrams | n/a |
| opnsense_protocol_udp_dropped_by_reason_total | Gauge | reason | Protocol Statistics | Number of dropped UDP packets by reason | n/a |

#### ICMP

| Metric Name | Type | Labels | Subsystem | Description | Disable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_protocol_icmp_calls_total | Counter | n/a | Protocol Statistics | Number of ICMP calls | n/a |
| opnsense_protocol_icmp_sent_packets_total | Counter | n/a | Protocol Statistics | Number of sent ICMP packets | n/a |
| opnsense_protocol_icmp_dropped_by_reason_total | Gauge | reason | Protocol Statistics | Number of dropped ICMP packets by reason | n/a |

#### IP

| Metric Name | Type | Labels | Subsystem | Description | Disable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_protocol_ip_received_packets_total | Counter | n/a | Protocol Statistics | Number of received IP packets | n/a |
| opnsense_protocol_ip_forwarded_packets_total | Counter | n/a | Protocol Statistics | Number of forwarded IP packets | n/a |
| opnsense_protocol_ip_sent_packets_total | Counter | n/a | Protocol Statistics | Number of sent IP packets | n/a |
| opnsense_protocol_ip_dropped_by_reason_total | Counter | reason | Protocol Statistics | Number of dropped IP packets by reason | n/a |
| opnsense_protocol_ip_fragments_received_total | Counter | n/a | Protocol Statistics | Number of received IP fragments | n/a |
| opnsense_protocol_ip_reassembled_packets_total | Counter | n/a | Protocol Statistics | Number of reassembled IP packets | n/a |
| opnsense_protocol_ip_sent_fragments_total | Counter | n/a | Protocol Statistics | Total IP fragments sent | n/a |

#### ARP

| Metric Name | Type | Labels | Subsystem | Description | Disable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_protocol_arp_sent_requests_total | Counter | n/a | Protocol Statistics | Number of sent ARP requests | n/a |
| opnsense_protocol_arp_received_requests_total | Counter | n/a | Protocol Statistics | Number of received ARP requests | n/a |
| opnsense_protocol_arp_sent_replies_total | Counter | n/a | Protocol Statistics | Number of ARP sent replies | n/a |
| opnsense_protocol_arp_received_replies_total | Counter | n/a | Protocol Statistics | Number of ARP received replies | n/a |
| opnsense_protocol_arp_sent_failures_total | Counter | n/a | Protocol Statistics | Number of ARP sent failures | n/a |
| opnsense_protocol_arp_received_packets_total | Counter | n/a | Protocol Statistics | Number of ARP received packets | n/a |
| opnsense_protocol_arp_dropped_no_entry_total | Counter | n/a | Protocol Statistics | Number of ARP packets dropped with no entry | n/a |
| opnsense_protocol_arp_dropped_duplicate_address_total | Counter | n/a | Protocol Statistics | Total ARP packets dropped due to duplicate address | n/a |
| opnsense_protocol_arp_entries_timeout_total | Counter | n/a | Protocol Statistics | Number of ARP entries that timed out | n/a |

#### CARP Protocol

| Metric Name | Type | Labels | Subsystem | Description | Disable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_protocol_carp_received_packets_total | Counter | address_family | Protocol Statistics | Number of received CARP packets | n/a |
| opnsense_protocol_carp_sent_packets_total | Counter | address_family | Protocol Statistics | Number of sent CARP packets | n/a |
| opnsense_protocol_carp_dropped_by_reason_total | Counter | reason | Protocol Statistics | Number of dropped CARP packets by reason | n/a |

#### Pfsync

| Metric Name | Type | Labels | Subsystem | Description | Disable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_protocol_pfsync_received_packets_total | Counter | address_family | Protocol Statistics | Number of received Pfsync packets | n/a |
| opnsense_protocol_pfsync_sent_packets_total | Counter | address_family | Protocol Statistics | Number of sent Pfsync packets | n/a |
| opnsense_protocol_pfsync_dropped_by_reason_total | Counter | reason | Protocol Statistics | Number of dropped Pfsync packets by reason | n/a |
| opnsense_protocol_pfsync_send_errors_total | Counter | n/a | Protocol Statistics | Number of Pfsync send errors | n/a |

### Unbound DNS

| Metric Name | Type | Labels | Subsystem | Description | Disable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_unbound_dns_service_running | Gauge | n/a | Unbound DNS | Whether the service is running (1 = running, 0 = stopped/disabled) | --exporter.disable-unbound |
| opnsense_unbound_dns_uptime_seconds | Gauge | n/a | Unbound DNS | Uptime of the unbound DNS service in seconds | --exporter.disable-unbound |
| opnsense_unbound_dns_blocklist_enabled | Gauge | n/a | Unbound DNS | Whether the DNS blocklist is enabled (1 = enabled, 0 = disabled) | --exporter.disable-unbound |
| opnsense_unbound_dns_queries_total | Counter | n/a | Unbound DNS | Total number of queries received | --exporter.disable-unbound |
| opnsense_unbound_dns_cache_hits_total | Counter | n/a | Unbound DNS | Total number of cache hits | --exporter.disable-unbound |
| opnsense_unbound_dns_cache_miss_total | Counter | n/a | Unbound DNS | Total number of cache misses | --exporter.disable-unbound |
| opnsense_unbound_dns_prefetch_total | Counter | n/a | Unbound DNS | Total number of cache prefetches | --exporter.disable-unbound |
| opnsense_unbound_dns_expired_total | Counter | n/a | Unbound DNS | Total number of expired entries served | --exporter.disable-unbound |
| opnsense_unbound_dns_recursive_replies_total | Counter | n/a | Unbound DNS | Total number of recursive replies sent | --exporter.disable-unbound |
| opnsense_unbound_dns_queries_timed_out_total | Counter | n/a | Unbound DNS | Total number of queries that timed out | --exporter.disable-unbound |
| opnsense_unbound_dns_queries_ip_ratelimited_total | Counter | n/a | Unbound DNS | Total number of queries that were IP rate limited | --exporter.disable-unbound |
| opnsense_unbound_dns_answers_secure_total | Counter | n/a | Unbound DNS | Total number of DNSSEC secure answers | --exporter.disable-unbound |
| opnsense_unbound_dns_answers_bogus_total | Counter | n/a | Unbound DNS | Total number of DNSSEC bogus answers | --exporter.disable-unbound |
| opnsense_unbound_dns_rrset_bogus_total | Counter | n/a | Unbound DNS | Total number of DNSSEC bogus rrsets | --exporter.disable-unbound |
| opnsense_unbound_dns_queries_by_type_total | Counter | type | Unbound DNS | Total queries by DNS record type | --exporter.disable-unbound |
| opnsense_unbound_dns_queries_by_protocol_total | Counter | protocol | Unbound DNS | Total queries by protocol | --exporter.disable-unbound |
| opnsense_unbound_dns_answers_by_rcode_total | Counter | rcode | Unbound DNS | Total answers by response code | --exporter.disable-unbound |
| opnsense_unbound_dns_unwanted_total | Counter | type | Unbound DNS | Total number of unwanted queries or replies | --exporter.disable-unbound |
| opnsense_unbound_dns_query_flags_total | Counter | flag | Unbound DNS | Total queries by DNS flag | --exporter.disable-unbound |
| opnsense_unbound_dns_edns_total | Counter | type | Unbound DNS | Total EDNS queries by type | --exporter.disable-unbound |
| opnsense_unbound_dns_request_list_avg | Gauge | n/a | Unbound DNS | Average number of requests in the internal request list | --exporter.disable-unbound |
| opnsense_unbound_dns_request_list_max | Gauge | n/a | Unbound DNS | Maximum number of requests in the internal request list | --exporter.disable-unbound |
| opnsense_unbound_dns_request_list_current | Gauge | scope | Unbound DNS | Current number of requests in the internal request list by scope | --exporter.disable-unbound |
| opnsense_unbound_dns_request_list_overwritten_total | Counter | n/a | Unbound DNS | Total number of request list entries overwritten by newer entries | --exporter.disable-unbound |
| opnsense_unbound_dns_request_list_exceeded_total | Counter | n/a | Unbound DNS | Total number of request list entries that exceeded the maximum | --exporter.disable-unbound |
| opnsense_unbound_dns_recursion_time_avg_seconds | Gauge | n/a | Unbound DNS | Average recursion time in seconds | --exporter.disable-unbound |
| opnsense_unbound_dns_recursion_time_median_seconds | Gauge | n/a | Unbound DNS | Median recursion time in seconds | --exporter.disable-unbound |
| opnsense_unbound_dns_tcp_usage_ratio | Gauge | n/a | Unbound DNS | TCP connection usage ratio for the DNS resolver (0.0 to 1.0) | --exporter.disable-unbound |
| opnsense_unbound_dns_cache_count | Gauge | cache | Unbound DNS | Number of entries in cache by cache type | --exporter.disable-unbound |
| opnsense_unbound_dns_memory_bytes | Gauge | component | Unbound DNS | Memory usage in bytes by component | --exporter.disable-unbound |

### Dnsmasq DHCP

| Metric Name | Type | Labels | Subsystem | Description | Disable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_dnsmasq_service_running | Gauge | n/a | Dnsmasq | Whether the service is running (1 = running, 0 = stopped/disabled) | --exporter.disable-dnsmasq |
| opnsense_dnsmasq_leases_total | Gauge | n/a | Dnsmasq | Total number of DHCP leases | --exporter.disable-dnsmasq |
| opnsense_dnsmasq_leases_by_interface | Gauge | interface | Dnsmasq | Number of DHCP leases per interface | --exporter.disable-dnsmasq |
| opnsense_dnsmasq_leases_reserved_total | Gauge | n/a | Dnsmasq | Total number of reserved (static) DHCP leases | --exporter.disable-dnsmasq |
| opnsense_dnsmasq_leases_dynamic_total | Gauge | n/a | Dnsmasq | Total number of dynamic DHCP leases | --exporter.disable-dnsmasq |

Per-lease detail metrics below require `--exporter.enable-dnsmasq-details` / `OPNSENSE_EXPORTER_ENABLE_DNSMASQ_DETAILS=true` (high cardinality on large networks):

| Metric Name | Type | Labels | Subsystem | Description | Enable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_dnsmasq_lease_info | Gauge | address, hostname, hwaddr, interface | Dnsmasq | Per-lease information (value is expire timestamp) | --exporter.enable-dnsmasq-details |

### Kea DHCP

| Metric Name | Type | Labels | Subsystem | Description | Disable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_kea_dhcp4_leases_total | Gauge | n/a | Kea | Total number of Kea DHCPv4 leases | --exporter.disable-kea |
| opnsense_kea_dhcp4_leases_by_interface | Gauge | interface | Kea | Number of Kea DHCPv4 leases per interface | --exporter.disable-kea |
| opnsense_kea_dhcp4_leases_reserved_total | Gauge | n/a | Kea | Total number of reserved (static) Kea DHCPv4 leases | --exporter.disable-kea |
| opnsense_kea_dhcp4_leases_dynamic_total | Gauge | n/a | Kea | Total number of dynamic Kea DHCPv4 leases | --exporter.disable-kea |
| opnsense_kea_dhcp6_leases_total | Gauge | n/a | Kea | Total number of Kea DHCPv6 leases | --exporter.disable-kea |
| opnsense_kea_dhcp6_leases_by_interface | Gauge | interface | Kea | Number of Kea DHCPv6 leases per interface | --exporter.disable-kea |
| opnsense_kea_dhcp6_leases_reserved_total | Gauge | n/a | Kea | Total number of reserved (static) Kea DHCPv6 leases | --exporter.disable-kea |
| opnsense_kea_dhcp6_leases_dynamic_total | Gauge | n/a | Kea | Total number of dynamic Kea DHCPv6 leases | --exporter.disable-kea |

Per-lease detail metrics below require `--exporter.enable-kea-details` / `OPNSENSE_EXPORTER_ENABLE_KEA_DETAILS=true` (high cardinality on large networks):

| Metric Name | Type | Labels | Subsystem | Description | Enable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_kea_dhcp4_lease_info | Gauge | address, hostname, hwaddr, interface | Kea | Per-lease DHCPv4 information (value is expire timestamp) | --exporter.enable-kea-details |
| opnsense_kea_dhcp6_lease_info | Gauge | address, hostname, hwaddr, interface | Kea | Per-lease DHCPv6 information (value is expire timestamp) | --exporter.enable-kea-details |

### Wireguard

| Metric Name | Type | Labels | Subsystem | Description | Disable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_wireguard_service_running | Gauge | n/a | Wireguard | Whether the service is running (1 = running, 0 = stopped/disabled) | --exporter.disable-wireguard |
| opnsense_wireguard_interfaces_status | Gauge | device, device_type, device_name | Wireguard | Wireguard interface status (1 = up, 0 = down) | --exporter.disable-wireguard |
| opnsense_wireguard_peer_status | Gauge | device, device_type, device_name, peer_name | Wireguard | Wireguard peer status (1 = up, 0 = down, 2 = unknown) | --exporter.disable-wireguard |
| opnsense_wireguard_peer_received_bytes_total | Counter | device, device_type, device_name, peer_name | Wireguard | Bytes received by this wireguard peer | --exporter.disable-wireguard |
| opnsense_wireguard_peer_transmitted_bytes_total | Counter | device, device_type, device_name, peer_name | Wireguard | Bytes transmitted by this wireguard peer | --exporter.disable-wireguard |
| opnsense_wireguard_peer_last_handshake_seconds | Counter | device, device_type, device_name, peer_name | Wireguard | Last handshake by peer in seconds | --exporter.disable-wireguard |

### OpenVPN

| Metric Name | Type | Labels | Subsystem | Description | Disable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_openvpn_instances | Gauge | uuid, role, description, device_type | OpenVPN | OpenVPN instances (1 = enabled, 0 = disabled) by role (server, client) | --exporter.disable-openvpn |
| opnsense_openvpn_sessions | Gauge | description, virtual_address, username | OpenVPN | OpenVPN session (1 = ok, 0 = not ok) | --exporter.disable-openvpn |

### IPsec

| Metric Name | Type | Labels | Subsystem | Description | Disable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_ipsec_service_running | Gauge | n/a | IPsec | Whether the service is running (1 = running, 0 = stopped/disabled) | --exporter.disable-ipsec |
| opnsense_ipsec_phase1_status | Gauge | description, name | IPsec | IPsec phase1 (1 = connected, 0 = down) | --exporter.disable-ipsec |
| opnsense_ipsec_phase1_install_time | Gauge | description, name | IPsec | IPsec phase1 install time (in seconds) | --exporter.disable-ipsec |
| opnsense_ipsec_phase1_bytes_in | Gauge | description, name | IPsec | IPsec phase1 bytes in | --exporter.disable-ipsec |
| opnsense_ipsec_phase1_bytes_out | Gauge | description, name | IPsec | IPsec phase1 bytes out | --exporter.disable-ipsec |
| opnsense_ipsec_phase1_packets_in | Gauge | description, name | IPsec | IPsec phase1 packets in | --exporter.disable-ipsec |
| opnsense_ipsec_phase1_packets_out | Gauge | description, name | IPsec | IPsec phase1 packets out | --exporter.disable-ipsec |
| opnsense_ipsec_phase2_install_time | Gauge | description, name, spi_in, spi_out, phase1_name | IPsec | IPsec phase2 install time (in seconds) | --exporter.disable-ipsec |
| opnsense_ipsec_phase2_rekey_time | Gauge | description, name, spi_in, spi_out, phase1_name | IPsec | IPsec phase2 rekey time (in seconds) | --exporter.disable-ipsec |
| opnsense_ipsec_phase2_life_time | Gauge | description, name, spi_in, spi_out, phase1_name | IPsec | IPsec phase2 life time (in seconds) | --exporter.disable-ipsec |
| opnsense_ipsec_phase2_bytes_in | Counter | description, name, spi_in, spi_out, phase1_name | IPsec | IPsec phase2 bytes in | --exporter.disable-ipsec |
| opnsense_ipsec_phase2_bytes_out | Counter | description, name, spi_in, spi_out, phase1_name | IPsec | IPsec phase2 bytes out | --exporter.disable-ipsec |
| opnsense_ipsec_phase2_packets_in | Counter | description, name, spi_in, spi_out, phase1_name | IPsec | IPsec phase2 packets in | --exporter.disable-ipsec |
| opnsense_ipsec_phase2_packets_out | Counter | description, name, spi_in, spi_out, phase1_name | IPsec | IPsec phase2 packets out | --exporter.disable-ipsec |

### Network Diagnostics (opt-in)

Disabled by default. Enable with `--exporter.enable-network-diagnostics` / `OPNSENSE_EXPORTER_ENABLE_NETWORK_DIAGNOSTICS=true`.

| Metric Name | Type | Labels | Subsystem | Description | Enable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_network_diag_netisr_dispatched_total | Counter | protocol | Network Diagnostics | Total number of netisr dispatches by protocol | --exporter.enable-network-diagnostics |
| opnsense_network_diag_netisr_hybrid_dispatched_total | Counter | protocol | Network Diagnostics | Total number of netisr hybrid dispatches by protocol | --exporter.enable-network-diagnostics |
| opnsense_network_diag_netisr_queued_total | Counter | protocol | Network Diagnostics | Total number of netisr packets queued by protocol | --exporter.enable-network-diagnostics |
| opnsense_network_diag_netisr_handled_total | Counter | protocol | Network Diagnostics | Total number of netisr packets handled by protocol | --exporter.enable-network-diagnostics |
| opnsense_network_diag_netisr_queue_drops_total | Counter | protocol | Network Diagnostics | Total number of netisr queue drops by protocol | --exporter.enable-network-diagnostics |
| opnsense_network_diag_netisr_queue_length | Gauge | protocol | Network Diagnostics | Current maximum netisr queue length across workstreams by protocol | --exporter.enable-network-diagnostics |
| opnsense_network_diag_netisr_queue_watermark | Gauge | protocol | Network Diagnostics | High watermark of netisr queue length across workstreams by protocol | --exporter.enable-network-diagnostics |
| opnsense_network_diag_netisr_queue_limit | Gauge | protocol | Network Diagnostics | Configured netisr queue limit by protocol | --exporter.enable-network-diagnostics |
| opnsense_network_diag_sockets_active | Gauge | type | Network Diagnostics | Number of active sockets by type | --exporter.enable-network-diagnostics |
| opnsense_network_diag_sockets_unix_total | Gauge | n/a | Network Diagnostics | Total number of active Unix domain sockets | --exporter.enable-network-diagnostics |
| opnsense_network_diag_routes_total | Gauge | proto | Network Diagnostics | Number of routing table entries by protocol | --exporter.enable-network-diagnostics |

### NetFlow (opt-in)

Disabled by default. Enable with `--exporter.enable-netflow` / `OPNSENSE_EXPORTER_ENABLE_NETFLOW=true`.

| Metric Name | Type | Labels | Subsystem | Description | Enable Flag |
| --- | --- | --- | --- | --- | --- |
| opnsense_netflow_enabled | Gauge | n/a | NetFlow | Whether netflow capture is enabled (1 = enabled, 0 = disabled) | --exporter.enable-netflow |
| opnsense_netflow_local_collection_enabled | Gauge | n/a | NetFlow | Whether local netflow collection is enabled (1 = enabled, 0 = disabled) | --exporter.enable-netflow |
| opnsense_netflow_active | Gauge | n/a | NetFlow | Whether the netflow service is active (1 = active, 0 = inactive) | --exporter.enable-netflow |
| opnsense_netflow_collectors_count | Gauge | n/a | NetFlow | Number of active netflow collectors | --exporter.enable-netflow |
| opnsense_netflow_cache_packets_total | Counter | interface | NetFlow | Total packets observed in netflow cache by interface | --exporter.enable-netflow |
| opnsense_netflow_cache_source_ip_addresses | Gauge | interface | NetFlow | Number of unique source IP addresses in netflow cache by interface | --exporter.enable-netflow |
| opnsense_netflow_cache_destination_ip_addresses | Gauge | interface | NetFlow | Number of unique destination IP addresses in netflow cache by interface | --exporter.enable-netflow |
