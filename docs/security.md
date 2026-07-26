---
title: Security
description: Security guide covering OPNsense API key management, TLS configuration, file-based secrets, and user permissions
tags:
  - Configuration
  - Deployment
---

# Security

This guide covers secure configuration of the OPNsense Exporter, including API key management, TLS, and least-privilege access.

## OPNsense API key creation

1. Log in to the OPNsense web UI.
2. Navigate to **System > Access > Users**.
3. Create a dedicated monitoring user (do not use the `root` account).
4. Assign the user to a group with only the [required permissions](#opnsense-user-permissions).
5. Scroll to the **API keys** section and click **+** to generate a new key pair.
6. Save the downloaded file - it contains the key and secret.

!!! danger "Avoid root API keys"
    API keys generated for the `root` user have full access to all OPNsense APIs, including write operations. Always create a dedicated monitoring user and grant only the ACL units required by the collectors you enable.

## OPNsense user permissions

Create a group (for example, `monitoring`) and grant the ACL units from the generated matrix for every collector you enable. The matrix covers every registered exporter endpoint, including non-collector health and log-shipping calls; status `unknown` is an explicit result and must not be replaced with a guessed narrower permission.

!!! warning "ACL units are not read-only"
    OPNsense authorises API keys by page-level URI patterns. A `wildcard; may include writes` row grants the whole API prefix, including the controller's write actions. This is a limitation of OPNsense ACL granularity, not evidence that the exporter sends writes. A dedicated monitoring user limits the blast radius, but does not make those available privileges harmless.

### Generated collector-to-ACL matrix

<!-- docgen:begin:acl-matrix -->
Generated from the endpoint ACL map, OPNsense core 26.7.1 and 26.1.11, and github.com/opnsense/plugins @ b59cf8e (2026-07-12) (re-derived 2026-07-25).

Status is **known**, **plugin-dependent**, or **unknown**. Unknown is an audited result, not an omitted recommendation. `plugin-gated` means this endpoint is treated as absent when its plugin route returns 404.

| Collector | Collection mode | Plugin gate | Endpoint | ACL status | Likely privilege (any one) | Scope | Evidence / caveat |
|-----------|-----------------|-------------|----------|------------|----------------------------|-------|-------------------|
| ACME Client | default-on (`--exporter.disable-acme` disables) | plugin-gated | `acmeCertificates`<br>`GET api/acmeclient/certificates/search` | `plugin-dependent` | Services: ACME Client (`page-services-acmeclient`) | wildcard; may include writes | -- |
| Firewall Aliases | default-on (`--exporter.disable-alias` disables) | -- | `aliasTableSize`<br>`GET api/firewall/alias/get_table_size` | `known` | Firewall: Alias: Edit (`page-firewall-alias-edit`); Firewall: Aliases (`page-firewall-aliases`) | wildcard; may include writes | -- |
| APC UPS (apcupsd) | default-on (`--exporter.disable-apcupsd` disables) | plugin-gated | `apcupsdServiceStatus`<br>`GET api/apcupsd/service/status` | `plugin-dependent` | Services: Apcupsd System Monitoring page (`page-services-apcupsd`) | wildcard; may include writes | -- |
| APC UPS (apcupsd) | default-on (`--exporter.disable-apcupsd` disables) | plugin-gated | `apcupsdUpsStatus`<br>`GET api/apcupsd/service/getUpsStatus` | `plugin-dependent` | Services: Apcupsd System Monitoring page (`page-services-apcupsd`) | wildcard; may include writes | -- |
| ARP Table | default-on (`--exporter.disable-arp-table` disables); high-cardinality opt-in (`--exporter.enable-arp-details`) | -- | `arp`<br>`POST api/diagnostics/interface/search_arp` | `known` | Diagnostics: ARP Table (`page-diagnostics-arptable`) | wildcard; may include writes | -- |
| Local Auth | default-on (`--exporter.disable-auth` disables) | -- | `authAPIKeys`<br>`GET api/auth/user/search_api_key` | `known` | System: Access: Management (`page-system-usermanager`) | wildcard; may include writes | -- |
| Local Auth | default-on (`--exporter.disable-auth` disables) | -- | `authGroups`<br>`GET api/auth/group/search` | `plugin-dependent` | System: Access: Management (`page-system-usermanager`) | wildcard; may include writes | granted by page-system-groupmanager on 26.1.11 and page-system-usermanager on 26.7.1 |
| Local Auth | default-on (`--exporter.disable-auth` disables) | -- | `authUsers`<br>`GET api/auth/user/search` | `known` | System: Access: Management (`page-system-usermanager`) | wildcard; may include writes | -- |
| Config Backup | default-on (`--exporter.disable-backup` disables) | -- | `backupHistory`<br>`GET api/core/backup/backups/this` | `known` | Diagnostics: Configuration History (`page-diagnostics-configurationhistory`) | wildcard; may include writes | -- |
| BPF Statistics | default-on (`--exporter.disable-bpf` disables) | plugin-gated | `bpfStatistics`<br>`GET api/diagnostics/interface/get_bpf_statistics` | `known` | Diagnostics: Netstat (`page-diagnostics-netstat`) | wildcard; may include writes | -- |
| Certificates | default-on (`--exporter.disable-certificates` disables) | -- | `caCertificates`<br>`GET api/trust/ca/search` | `known` | System: CA Manager (`page-system-camanager`) | wildcard; may include writes | -- |
| Captive Portal | default-on (`--exporter.disable-captiveportal` disables) | plugin-gated | `captivePortalServiceStatus`<br>`GET api/captiveportal/service/status` | `known` | Services: Captive Portal (`page-services-captiveportal`) | wildcard; may include writes | -- |
| Captive Portal | default-on (`--exporter.disable-captiveportal` disables) | plugin-gated | `captivePortalSessions`<br>`POST api/captiveportal/session/search` | `known` | Services: Captive Portal (`page-services-captiveportal`) | wildcard; may include writes | -- |
| Captive Portal | default-on (`--exporter.disable-captiveportal` disables) | -- | `captivePortalVoucherGroups`<br>`GET api/captiveportal/voucher/list_voucher_groups` | `known` | Services: Captive Portal (`page-services-captiveportal`) | wildcard; may include writes | -- |
| Captive Portal | default-on (`--exporter.disable-captiveportal` disables) | -- | `captivePortalVoucherProviders`<br>`GET api/captiveportal/voucher/list_providers` | `known` | Services: Captive Portal (`page-services-captiveportal`) | wildcard; may include writes | -- |
| Captive Portal | default-on (`--exporter.disable-captiveportal` disables) | -- | `captivePortalVouchers`<br>`GET api/captiveportal/voucher/list_vouchers` | `known` | Services: Captive Portal (`page-services-captiveportal`) | wildcard; may include writes | -- |
| Captive Portal | default-on (`--exporter.disable-captiveportal` disables) | plugin-gated | `captivePortalZones`<br>`GET api/captiveportal/session/zones` | `known` | Services: Captive Portal (`page-services-captiveportal`) | wildcard; may include writes | -- |
| CARP | default-on (`--exporter.disable-carp` disables) | -- | `carpStatus`<br>`GET api/diagnostics/interface/get_vip_status` | `known` | Interfaces: Virtual IPs: Status (`page-status-carp`) | wildcard; may include writes | -- |
| Certificates | default-on (`--exporter.disable-certificates` disables) | -- | `certificates`<br>`GET api/trust/cert/search` | `known` | System: Certificate Manager (`page-system-certmanager`) | wildcard; may include writes | -- |
| Chrony | default-on (`--exporter.disable-chrony` disables) | plugin-gated | `chronyServiceStatus`<br>`GET api/chrony/service/status` | `plugin-dependent` | Services: Chrony (`page-services-chrony`) | wildcard; may include writes | -- |
| Chrony | default-on (`--exporter.disable-chrony` disables) | plugin-gated | `chronySourceStats`<br>`GET api/chrony/service/chronysourcestats` | `plugin-dependent` | Services: Chrony (`page-services-chrony`) | wildcard; may include writes | -- |
| Chrony | default-on (`--exporter.disable-chrony` disables) | plugin-gated | `chronySources`<br>`GET api/chrony/service/chronysources` | `plugin-dependent` | Services: Chrony (`page-services-chrony`) | wildcard; may include writes | -- |
| Chrony | default-on (`--exporter.disable-chrony` disables) | plugin-gated | `chronyTracking`<br>`GET api/chrony/service/chronytracking` | `plugin-dependent` | Services: Chrony (`page-services-chrony`) | wildcard; may include writes | -- |
| ClamAV | default-on (`--exporter.disable-clamav` disables) | plugin-gated | `clamavVersion`<br>`GET api/clamav/service/version` | `plugin-dependent` | Services: ClamAV (`page-services-clamav`) | wildcard; may include writes | -- |
| System | default-on (`--exporter.disable-system` disables) | -- | `cpuType`<br>`GET api/diagnostics/cpu_usage/getCPUType` | `known` | Lobby: Dashboard (`page-system-login-logout`) | wildcard; may include writes | -- |
| Cron | default-on (`--exporter.disable-cron-table` disables) | -- | `cronJobs`<br>`POST api/cron/settings/searchJobs` | `known` | System: Settings: Cron (`page-system-cron`) | wildcard; may include writes | -- |
| CrowdSec | default-on (`--exporter.disable-crowdsec` disables) | plugin-gated | `crowdsecAlerts`<br>`POST api/crowdsec/alerts/search` | `plugin-dependent` | CrowdSec (`page-user-crowdsec`) | wildcard; may include writes | -- |
| CrowdSec | default-on (`--exporter.disable-crowdsec` disables) | plugin-gated | `crowdsecAppsecConfigs`<br>`POST api/crowdsec/appsecconfigs/search` | `plugin-dependent` | CrowdSec (`page-user-crowdsec`) | wildcard; may include writes | -- |
| CrowdSec | default-on (`--exporter.disable-crowdsec` disables) | plugin-gated | `crowdsecAppsecRules`<br>`POST api/crowdsec/appsecrules/search` | `plugin-dependent` | CrowdSec (`page-user-crowdsec`) | wildcard; may include writes | -- |
| CrowdSec | default-on (`--exporter.disable-crowdsec` disables) | plugin-gated | `crowdsecBouncers`<br>`POST api/crowdsec/bouncers/search` | `plugin-dependent` | CrowdSec (`page-user-crowdsec`) | wildcard; may include writes | -- |
| CrowdSec | default-on (`--exporter.disable-crowdsec` disables) | plugin-gated | `crowdsecCollections`<br>`POST api/crowdsec/collections/search` | `plugin-dependent` | CrowdSec (`page-user-crowdsec`) | wildcard; may include writes | -- |
| CrowdSec | default-on (`--exporter.disable-crowdsec` disables) | plugin-gated | `crowdsecDecisions`<br>`POST api/crowdsec/decisions/search` | `plugin-dependent` | CrowdSec (`page-user-crowdsec`) | wildcard; may include writes | -- |
| CrowdSec | default-on (`--exporter.disable-crowdsec` disables) | plugin-gated | `crowdsecMachines`<br>`POST api/crowdsec/machines/search` | `plugin-dependent` | CrowdSec (`page-user-crowdsec`) | wildcard; may include writes | -- |
| CrowdSec | default-on (`--exporter.disable-crowdsec` disables) | plugin-gated | `crowdsecParsers`<br>`POST api/crowdsec/parsers/search` | `plugin-dependent` | CrowdSec (`page-user-crowdsec`) | wildcard; may include writes | -- |
| CrowdSec | default-on (`--exporter.disable-crowdsec` disables) | plugin-gated | `crowdsecPostoverflows`<br>`POST api/crowdsec/postoverflows/search` | `plugin-dependent` | CrowdSec (`page-user-crowdsec`) | wildcard; may include writes | -- |
| CrowdSec | default-on (`--exporter.disable-crowdsec` disables) | plugin-gated | `crowdsecScenarios`<br>`POST api/crowdsec/scenarios/search` | `plugin-dependent` | CrowdSec (`page-user-crowdsec`) | wildcard; may include writes | -- |
| CrowdSec | default-on (`--exporter.disable-crowdsec` disables) | plugin-gated | `crowdsecServiceStatus`<br>`GET api/crowdsec/service/status` | `plugin-dependent` | CrowdSec (`page-user-crowdsec`) | wildcard; may include writes | -- |
| CrowdSec | default-on (`--exporter.disable-crowdsec` disables) | plugin-gated | `crowdsecVersion`<br>`GET api/crowdsec/version/get` | `plugin-dependent` | CrowdSec (`page-user-crowdsec`) | wildcard; may include writes | -- |
| Hardware | default-on (`--exporter.disable-hardware` disables) | plugin-gated | `dechwPowerStatus`<br>`GET api/dechw/info/power_status` | `unknown` | No matched ACL; only `page-all` | exact | the dec-hw plugin grants api/dechw/info/powerstatus; the exporter registers the underscored spelling power_status, which routes to the same action but matches no privilege except page-all. |
| ISC DHCPv4 | default-on (`--exporter.disable-dhcpv4` disables); high-cardinality opt-in (`--exporter.enable-dhcpv4-details`) | plugin-gated | `dhcpv4`<br>`GET api/dhcpv4/leases/searchLease` | `plugin-dependent` | Services: ISC DHCPv4: Leases (`page-status-dhcpleases`) | wildcard; may include writes | -- |
| ISC DHCPv6 | default-on (`--exporter.disable-dhcpv6` disables); high-cardinality opt-in (`--exporter.enable-dhcpv6-details`) | plugin-gated | `dhcpv6Leases`<br>`GET api/dhcpv6/leases/searchLease` | `plugin-dependent` | Status: ISC DHCPv6: Leases (`page-status-dhcpv6leases`) | wildcard; may include writes | -- |
| ISC DHCPv6 | default-on (`--exporter.disable-dhcpv6` disables); high-cardinality opt-in (`--exporter.enable-dhcpv6-details`) | plugin-gated | `dhcpv6Prefixes`<br>`GET api/dhcpv6/leases/searchPrefix` | `plugin-dependent` | Status: ISC DHCPv6: Leases (`page-status-dhcpv6leases`) | wildcard; may include writes | -- |
| Hardware | default-on (`--exporter.disable-hardware` disables) | plugin-gated | `dmidecodeInfo`<br>`GET api/dmidecode/service/get` | `plugin-dependent` | Service: DMI Data Widget (`page-service-dmidecode`) | exact | -- |
| Dnsmasq DHCP | default-on (`--exporter.disable-dnsmasq` disables); high-cardinality opt-in (`--exporter.enable-dnsmasq-details`) | -- | `dnsmasqLeases`<br>`GET api/dnsmasq/leases/search` | `known` | Services: Dnsmasq DNS/DHCP: Settings (`page-services-dnsforwarder`) | wildcard; may include writes | -- |
| Dnsmasq DHCP | default-on (`--exporter.disable-dnsmasq` disables); high-cardinality opt-in (`--exporter.enable-dnsmasq-details`) | -- | `dnsmasqRanges`<br>`GET api/dnsmasq/settings/searchRange` | `known` | Services: Dnsmasq DNS/DHCP: Settings (`page-services-dnsforwarder`) | wildcard; may include writes | -- |
| Dnsmasq DHCP | default-on (`--exporter.disable-dnsmasq` disables); high-cardinality opt-in (`--exporter.enable-dnsmasq-details`) | plugin-gated | `dnsmasqServiceStatus`<br>`GET api/dnsmasq/service/status` | `known` | Services: Dnsmasq DNS/DHCP: Settings (`page-services-dnsforwarder`) | wildcard; may include writes | -- |
| DynDNS | default-on (`--exporter.disable-dyndns` disables) | plugin-gated | `dyndnsAccounts`<br>`GET api/dyndns/accounts/searchItem` | `plugin-dependent` | Services: Dynamic DNS (`page-services-dyndns`) | wildcard; may include writes | -- |
| DynDNS | default-on (`--exporter.disable-dyndns` disables) | plugin-gated | `dyndnsServiceStatus`<br>`GET api/dyndns/service/status` | `plugin-dependent` | Services: Dynamic DNS (`page-services-dyndns`) | wildcard; may include writes | -- |
| Firewall | default-on (`--exporter.disable-firewall` disables) | -- | `firewallGeoIP`<br>`GET api/firewall/alias/get_geo_i_p` | `known` | Firewall: Alias: Edit (`page-firewall-alias-edit`); Firewall: Aliases (`page-firewall-aliases`) | wildcard; may include writes | -- |
| (log shipping) | non-collector endpoint | -- | `firewallRuleIDs`<br>`GET api/diagnostics/firewall/list_rule_ids` | `known` | Diagnostics: Firewall sessions (`page-diagnostics-system-pftop`) | exact | -- |
| Firewall Rules | default-on (`--exporter.disable-firewall-rules` disables); high-cardinality opt-in (`--exporter.enable-firewall-rules-details`) | -- | `firewallRuleStats`<br>`GET api/firewall/filter_util/rule_stats` | `known` | Firewall: Rules (`page-firewall-rules`) | wildcard; may include writes | -- |
| Firewall Rules | default-on (`--exporter.disable-firewall-rules` disables); high-cardinality opt-in (`--exporter.enable-firewall-rules-details`) | -- | `firewallRules`<br>`POST api/firewall/filter/search_rule` | `known` | Firewall: Rules [new] (`page-filter-api`) | wildcard; may include writes | -- |
| Firewall | default-on (`--exporter.disable-firewall` disables) | -- | `firewallStats`<br>`GET api/diagnostics/firewall/stats` | `known` | Diagnostics: Logs: Firewall: Summary View (`page-diagnostics-logs-firewall-summary`) | wildcard; may include writes | -- |
| Firmware | default-on (`--exporter.disable-firmware` disables) | -- | `firmware`<br>`GET api/core/firmware/status` | `known` | System: Firmware (`page-system-firmware-manualupdate`) | wildcard; may include writes | -- |
| Firmware | default-on (`--exporter.disable-firmware` disables) | -- | `firmwareInfo`<br>`GET api/core/firmware/info` | `known` | System: Firmware (`page-system-firmware-manualupdate`) | wildcard; may include writes | -- |
| Gateways | default-on (`--exporter.disable-gateways` disables) | -- | `gatewaysStatus`<br>`GET api/routing/settings/searchGateway` | `known` | System: Gateways (`page-system-gateways`) | wildcard; may include writes | -- |
| HAProxy | default-on (`--exporter.disable-haproxy` disables) | plugin-gated | `haproxyCounters`<br>`GET api/haproxy/statistics/counters` | `plugin-dependent` | Services: HAProxy (`page-services-haproxy`) | wildcard; may include writes | -- |
| HAProxy | default-on (`--exporter.disable-haproxy` disables) | plugin-gated | `haproxyInfo`<br>`GET api/haproxy/statistics/info` | `plugin-dependent` | Services: HAProxy (`page-services-haproxy`) | wildcard; may include writes | -- |
| HAProxy | default-on (`--exporter.disable-haproxy` disables) | plugin-gated | `haproxyServiceStatus`<br>`GET api/haproxy/service/status` | `plugin-dependent` | Services: HAProxy (`page-services-haproxy`) | wildcard; may include writes | -- |
| HAProxy | default-on (`--exporter.disable-haproxy` disables) | plugin-gated | `haproxyTables`<br>`GET api/haproxy/statistics/tables` | `plugin-dependent` | Services: HAProxy (`page-services-haproxy`) | wildcard; may include writes | -- |
| HA Sync Status | opt-in (`--exporter.enable-hasync`) | -- | `hasyncServices`<br>`POST api/core/hasync_status/services` | `known` | Status: HA backup (`page-status-habackup`) | wildcard; may include writes | -- |
| HA Sync Status | opt-in (`--exporter.enable-hasync`) | -- | `hasyncVersion`<br>`GET api/core/hasync_status/version` | `known` | Status: HA backup (`page-status-habackup`) | wildcard; may include writes | -- |
| (health probe) | non-collector endpoint | -- | `healthCheck`<br>`GET api/core/system/status` | `known` | System: Status (`page-system-status`) | wildcard; may include writes | -- |
| Host Discovery | default-on (`--exporter.disable-hostdiscovery` disables) | -- | `hostdiscoverySearch`<br>`GET api/hostdiscovery/service/search` | `known` | Interfaces: Neighbors: Automatic discovery (`page-hostdiscovery`) | wildcard; may include writes | -- |
| IDS/IPS (Suricata) | default-on (`--exporter.disable-ids` disables) | -- | `idsAlertLogs`<br>`GET api/ids/service/get_alert_logs` | `known` | Services: Intrusion Detection (`page-services-ids`) | wildcard; may include writes | -- |
| IDS/IPS (Suricata) | default-on (`--exporter.disable-ids` disables) | -- | `idsQueryAlerts`<br>`POST api/ids/service/query_alerts` | `known` | Services: Intrusion Detection (`page-services-ids`) | wildcard; may include writes | -- |
| IDS/IPS (Suricata) | default-on (`--exporter.disable-ids` disables) | -- | `idsRulesets`<br>`GET api/ids/settings/list_rulesets` | `known` | Services: Intrusion Detection (`page-services-ids`) | wildcard; may include writes | -- |
| IDS/IPS (Suricata) | default-on (`--exporter.disable-ids` disables) | -- | `idsSearchInstalledRules`<br>`POST api/ids/settings/searchInstalledRules` | `known` | Services: Intrusion Detection (`page-services-ids`) | wildcard; may include writes | -- |
| IDS/IPS (Suricata) | default-on (`--exporter.disable-ids` disables) | -- | `idsSettings`<br>`GET api/ids/settings/get` | `known` | Services: Intrusion Detection (`page-services-ids`) | wildcard; may include writes | -- |
| IDS/IPS (Suricata) | default-on (`--exporter.disable-ids` disables) | -- | `idsStatus`<br>`GET api/ids/service/status` | `known` | Services: Intrusion Detection (`page-services-ids`) | wildcard; may include writes | -- |
| (log shipping) | non-collector endpoint | -- | `interfaceConfig`<br>`GET api/diagnostics/interface/get_interface_config` | `unknown` | No matched ACL; only `page-all` | exact | no core ACL pattern covers api/diagnostics/interface/get_interface_config at all in either supported release; only page-all reaches it. |
| (log shipping) | non-collector endpoint | -- | `interfaceStatistics`<br>`GET api/diagnostics/interface/get_interface_statistics` | `known` | Diagnostics: Netstat (`page-diagnostics-netstat`) | wildcard; may include writes | -- |
| Interfaces | default-on (`--exporter.disable-interfaces` disables) | -- | `interfaces`<br>`GET api/diagnostics/traffic/interface` | `known` | Reporting: Traffic (`page-status-trafficgraph`) | wildcard; may include writes | -- |
| Interfaces | default-on (`--exporter.disable-interfaces` disables) | -- | `interfacesOverview`<br>`GET api/interfaces/overview/interfaces_info` | `known` | Status: Interfaces (`page-status-interfaces`) | wildcard; may include writes | -- |
| IPsec | default-on (`--exporter.disable-ipsec` disables) | -- | `ipsecLegacyStatus`<br>`GET api/ipsec/legacy_subsystem/status` | `plugin-dependent` | VPN: IPsec: Tunnels [legacy] (`page-vpn-ipsec`) | wildcard; may include writes | -- |
| IPsec | default-on (`--exporter.disable-ipsec` disables) | plugin-gated | `ipsecPhase1`<br>`GET api/ipsec/sessions/search_phase1` | `known` | Status: IPsec (`page-status-ipsec`) | wildcard; may include writes | -- |
| IPsec | default-on (`--exporter.disable-ipsec` disables) | plugin-gated | `ipsecPhase2`<br>`POST api/ipsec/sessions/search_phase2` | `known` | Status: IPsec (`page-status-ipsec`) | wildcard; may include writes | -- |
| IPsec | default-on (`--exporter.disable-ipsec` disables) | plugin-gated | `ipsecPools`<br>`GET api/ipsec/leases/pools` | `known` | Status: IPsec: Leasespage (`page-status-ipsec-leases`) | wildcard; may include writes | -- |
| IPsec | default-on (`--exporter.disable-ipsec` disables) | -- | `ipsecSad`<br>`GET api/ipsec/sad/search` | `known` | Status: IPsec: SAD (`page-status-ipsec-sad`) | wildcard; may include writes | -- |
| IPsec | default-on (`--exporter.disable-ipsec` disables) | plugin-gated | `ipsecServiceStatus`<br>`GET api/ipsec/service/status` | `known` | Status: IPsec: SPD (`page-status-ipsec-spd`); VPN: IPsec: Connections (`page-vpn-ipsec-connections`); VPN: IPsec: Edit Pre-Shared Keys (`page-vpn-ipsec-editkeys`); VPN: IPsec: Key Pairs (`page-vpn-ipsec-keypairs`) | wildcard; may include writes | -- |
| IPsec | default-on (`--exporter.disable-ipsec` disables) | -- | `ipsecSpd`<br>`GET api/ipsec/spd/search` | `known` | Status: IPsec: SPD (`page-status-ipsec-spd`) | wildcard; may include writes | -- |
| Kea DHCP | default-on (`--exporter.disable-kea` disables); high-cardinality opt-in (`--exporter.enable-kea-details`) | -- | `keaLeases4`<br>`GET api/kea/leases4/search` | `known` | Services: DHCP: Kea(v4) (`page-dhcp-kea-v4`) | wildcard; may include writes | -- |
| Kea DHCP | default-on (`--exporter.disable-kea` disables); high-cardinality opt-in (`--exporter.enable-kea-details`) | -- | `keaLeases6`<br>`GET api/kea/leases6/search` | `known` | Services: DHCP: Kea(v6) (`page-dhcp-kea-v6`) | wildcard; may include writes | -- |
| Kea DHCP | default-on (`--exporter.disable-kea` disables); high-cardinality opt-in (`--exporter.enable-kea-details`) | -- | `keaPdPools6`<br>`GET api/kea/dhcpv6/searchPdPool` | `known` | Services: DHCP: Kea(v6) (`page-dhcp-kea-v6`) | wildcard; may include writes | -- |
| Kea DHCP | default-on (`--exporter.disable-kea` disables); high-cardinality opt-in (`--exporter.enable-kea-details`) | plugin-gated | `keaServiceStatus`<br>`GET api/kea/service/status` | `known` | Services: DHCP: Kea Ctrl Agent (`page-dhcp-kea-ctrl-agent`); Services: DHCP: Kea DDNS Agent (`page-dhcp-kea-ddns`); Services: DHCP: Kea(v4) (`page-dhcp-kea-v4`); Services: DHCP: Kea(v6) (`page-dhcp-kea-v6`) | wildcard; may include writes | -- |
| Kea DHCP | default-on (`--exporter.disable-kea` disables); high-cardinality opt-in (`--exporter.enable-kea-details`) | -- | `keaSubnets4`<br>`GET api/kea/dhcpv4/searchSubnet` | `known` | Services: DHCP: Kea(v4) (`page-dhcp-kea-v4`) | wildcard; may include writes | -- |
| Kea DHCP | default-on (`--exporter.disable-kea` disables); high-cardinality opt-in (`--exporter.enable-kea-details`) | -- | `keaSubnets6`<br>`GET api/kea/dhcpv6/searchSubnet` | `known` | Services: DHCP: Kea(v6) (`page-dhcp-kea-v6`) | wildcard; may include writes | -- |
| LLDP Neighbors | default-on (`--exporter.disable-lldpd` disables) | plugin-gated | `lldpdNeighbors`<br>`GET api/lldpd/service/neighbor` | `plugin-dependent` | Services: Lldpd (`page-services-lldpd`) | wildcard; may include writes | -- |
| Mbuf | default-on (`--exporter.disable-mbuf` disables) | -- | `memoryStatistics`<br>`GET api/diagnostics/interface/get_memory_statistics` | `known` | Diagnostics: Netstat (`page-diagnostics-netstat`) | wildcard; may include writes | -- |
| Monit | default-on (`--exporter.disable-monit` disables) | plugin-gated | `monitServiceStatus`<br>`GET api/monit/service/status` | `known` | WebCfg - Services: Monit System Monitoring page (`page-services-monit`) | wildcard; may include writes | -- |
| Monit | default-on (`--exporter.disable-monit` disables) | plugin-gated | `monitStatus`<br>`GET api/monit/status/get/xml` | `known` | WebCfg - Services: Monit System Monitoring page (`page-services-monit`) | wildcard; may include writes | -- |
| Firewall | default-on (`--exporter.disable-firewall` disables) | -- | `natDNATRules`<br>`GET api/firewall/d_nat/search_rule` | `known` | Firewall: NAT: Destination NAT (`page-firewall-nat-portforward-edit`) | wildcard; may include writes | -- |
| Firewall | default-on (`--exporter.disable-firewall` disables) | -- | `natNPTRules`<br>`GET api/firewall/npt/search_rule` | `known` | Firewall: NAT: NPTv6 (`page-firewall-nat-npt`) | wildcard; may include writes | -- |
| Firewall | default-on (`--exporter.disable-firewall` disables) | -- | `natOneToOneRules`<br>`GET api/firewall/one_to_one/search_rule` | `known` | Firewall: NAT: 1:1 (`page-firewall-nat-1-1-edit`) | wildcard; may include writes | -- |
| Firewall | default-on (`--exporter.disable-firewall` disables) | -- | `natSourceNATRules`<br>`GET api/firewall/source_nat/search_rule` | `known` | Firewall: NAT: Source NAT (`page-filter-snat-api`) | wildcard; may include writes | -- |
| NDP | default-on (`--exporter.disable-ndp` disables); high-cardinality opt-in (`--exporter.enable-ndp-details`) | -- | `ndpTable`<br>`GET api/diagnostics/interface/get_ndp` | `known` | Diagnostics: NDP Table (`page-diagnostics-ndptable`) | wildcard; may include writes | -- |
| NetBird | default-on (`--exporter.disable-netbird` disables); high-cardinality opt-in (`--exporter.enable-netbird-details`) | plugin-gated | `netbirdServiceStatus`<br>`GET api/netbird/service/status` | `plugin-dependent` | VPN: NetBird (`page-vpn-netbird`) | wildcard; may include writes | -- |
| NetBird | default-on (`--exporter.disable-netbird` disables); high-cardinality opt-in (`--exporter.enable-netbird-details`) | plugin-gated | `netbirdStatus`<br>`GET api/netbird/status/status` | `plugin-dependent` | VPN: NetBird (`page-vpn-netbird`) | wildcard; may include writes | -- |
| NetFlow | opt-in (`--exporter.enable-netflow`) | -- | `netflowCacheStats`<br>`GET api/diagnostics/netflow/cacheStats` | `known` | Diagnostics: Netflow configuration (`page-diagnostics-netflow`) | wildcard; may include writes | -- |
| NetFlow | opt-in (`--exporter.enable-netflow`) | -- | `netflowGetConfig`<br>`GET api/diagnostics/netflow/getconfig` | `known` | Diagnostics: Netflow configuration (`page-diagnostics-netflow`) | wildcard; may include writes | -- |
| NetFlow | opt-in (`--exporter.enable-netflow`) | -- | `netflowIsEnabled`<br>`GET api/diagnostics/netflow/isEnabled` | `known` | Diagnostics: Netflow configuration (`page-diagnostics-netflow`) | wildcard; may include writes | -- |
| NetFlow | opt-in (`--exporter.enable-netflow`) | -- | `netflowStatus`<br>`GET api/diagnostics/netflow/status` | `known` | Diagnostics: Netflow configuration (`page-diagnostics-netflow`) | wildcard; may include writes | -- |
| Network Diagnostics | opt-in (`--exporter.enable-network-diagnostics`) | -- | `netisrStatistics`<br>`GET api/diagnostics/interface/get_netisr_statistics` | `known` | Diagnostics: Netstat (`page-diagnostics-netstat`) | wildcard; may include writes | -- |
| Nginx | default-on (`--exporter.disable-nginx` disables) | plugin-gated | `nginxBans`<br>`GET api/nginx/bans/searchban` | `plugin-dependent` | nginx (`page-Nginx`) | wildcard; may include writes | -- |
| Nginx | default-on (`--exporter.disable-nginx` disables) | plugin-gated | `nginxServiceStatus`<br>`GET api/nginx/service/status` | `plugin-dependent` | nginx (`page-Nginx`) | wildcard; may include writes | -- |
| Nginx | default-on (`--exporter.disable-nginx` disables) | plugin-gated | `nginxVts`<br>`GET api/nginx/service/vts` | `plugin-dependent` | nginx (`page-Nginx`) | wildcard; may include writes | -- |
| NTP | default-on (`--exporter.disable-ntp` disables) | -- | `ntpGPS`<br>`GET api/ntpd/service/gps` | `unknown` | No matched ACL; only `page-all` | exact | Status: NTP grants only the exact route api/ntpd/service/status; nothing grants api/ntpd/service/gps except page-all. |
| NTP | default-on (`--exporter.disable-ntp` disables) | -- | `ntpStatus`<br>`GET api/ntpd/service/status` | `known` | Status: NTP (`page-status-ntp`) | exact | -- |
| NUT UPS | default-on (`--exporter.disable-nut` disables) | plugin-gated | `nutServiceStatus`<br>`GET api/nut/service/status` | `plugin-dependent` | Nut (`page-nut`) | wildcard; may include writes | -- |
| NUT UPS | default-on (`--exporter.disable-nut` disables) | plugin-gated | `nutUpsStatus`<br>`GET api/nut/diagnostics/upsstatus` | `plugin-dependent` | Nut (`page-nut`) | wildcard; may include writes | -- |
| OpenVPN | default-on (`--exporter.disable-openvpn` disables) | -- | `openVPNInstances`<br>`POST api/openvpn/instances/search` | `known` | VPN: OpenVPN: Instances (`page-openvpn-instances`) | wildcard; may include writes | -- |
| OpenVPN | default-on (`--exporter.disable-openvpn` disables) | -- | `openVPNSessions`<br>`GET api/openvpn/service/search_sessions` | `known` | Status: OpenVPN (`page-status-openvpn`) | wildcard; may include writes | -- |
| Firewall | default-on (`--exporter.disable-firewall` disables) | -- | `pfStates`<br>`GET api/diagnostics/firewall/pf_states/1` | `unknown` | No matched ACL; only `page-all` | exact | Lobby: Dashboard grants the exact route api/diagnostics/firewall/pf_states with no trailing wildcard; the exporter appends the /1 parameter, so the request URI matches no privilege except page-all. |
| Firewall | default-on (`--exporter.disable-firewall` disables) | -- | `pfStatisticsByInterface`<br>`GET api/diagnostics/firewall/pf_statistics/interfaces` | `known` | Diagnostics: Firewall statistics (`page-diagnostics-pf-info`) | wildcard; may include writes | -- |
| PF Statistics | default-on (`--exporter.disable-pf-stats` disables) | -- | `pfStatsInfo`<br>`GET api/diagnostics/firewall/pf_statistics/info` | `known` | Diagnostics: Firewall statistics (`page-diagnostics-pf-info`) | wildcard; may include writes | -- |
| PF Statistics | default-on (`--exporter.disable-pf-stats` disables) | -- | `pfStatsMemory`<br>`GET api/diagnostics/firewall/pf_statistics/memory` | `known` | Diagnostics: Firewall statistics (`page-diagnostics-pf-info`) | wildcard; may include writes | -- |
| PF Statistics | default-on (`--exporter.disable-pf-stats` disables) | -- | `pfStatsTimeouts`<br>`GET api/diagnostics/firewall/pf_statistics/timeouts` | `known` | Diagnostics: Firewall statistics (`page-diagnostics-pf-info`) | wildcard; may include writes | -- |
| Network Diagnostics | opt-in (`--exporter.enable-network-diagnostics`) | -- | `pfsyncNodes`<br>`GET api/diagnostics/interface/get_pfsync_nodes` | `known` | Interfaces: Virtual IPs: Status (`page-status-carp`) | wildcard; may include writes | -- |
| Protocol Statistics | default-on (`--exporter.disable-protocol` disables) | -- | `protocolStatistics`<br>`GET api/diagnostics/interface/get_protocol_statistics` | `known` | Diagnostics: Netstat (`page-diagnostics-netstat`) | wildcard; may include writes | -- |
| Q-Feeds | default-on (`--exporter.disable-qfeeds` disables) | plugin-gated | `qfeedsStats`<br>`GET api/qfeeds/settings/stats` | `unknown` | No matched ACL; only `page-all` | exact | the q-feeds-connector plugin grants api/q_feeds/*; the exporter registers api/qfeeds/..., which routes to the same controller but matches no privilege except page-all. |
| FRR Routing (BGP/OSPF/BFD) | default-on (`--exporter.disable-frr` disables) | plugin-gated | `quaggaBfdCounters`<br>`GET api/quagga/diagnostics/bfdcounters` | `plugin-dependent` | Routing (`page-routing`) | wildcard; may include writes | -- |
| FRR Routing (BGP/OSPF/BFD) | default-on (`--exporter.disable-frr` disables) | plugin-gated | `quaggaBfdNeighbors`<br>`GET api/quagga/diagnostics/bfdneighbors` | `plugin-dependent` | Routing (`page-routing`) | wildcard; may include writes | -- |
| FRR Routing (BGP/OSPF/BFD) | default-on (`--exporter.disable-frr` disables) | plugin-gated | `quaggaBgpNeighbors`<br>`GET api/quagga/diagnostics/bgpneighbors` | `plugin-dependent` | Routing (`page-routing`) | wildcard; may include writes | -- |
| FRR Routing (BGP/OSPF/BFD) | default-on (`--exporter.disable-frr` disables) | plugin-gated | `quaggaBgpSummary`<br>`GET api/quagga/diagnostics/bgpsummary` | `plugin-dependent` | Routing (`page-routing`) | wildcard; may include writes | -- |
| FRR Routing (BGP/OSPF/BFD) | default-on (`--exporter.disable-frr` disables) | plugin-gated | `quaggaGeneralRoute4`<br>`GET api/quagga/diagnostics/search_generalroute4` | `plugin-dependent` | Routing (`page-routing`) | wildcard; may include writes | -- |
| FRR Routing (BGP/OSPF/BFD) | default-on (`--exporter.disable-frr` disables) | plugin-gated | `quaggaGeneralRoute6`<br>`GET api/quagga/diagnostics/search_generalroute6` | `plugin-dependent` | Routing (`page-routing`) | wildcard; may include writes | -- |
| FRR Routing (BGP/OSPF/BFD) | default-on (`--exporter.disable-frr` disables) | plugin-gated | `quaggaOspfDatabase`<br>`GET api/quagga/diagnostics/ospfdatabase` | `plugin-dependent` | Routing (`page-routing`) | wildcard; may include writes | -- |
| FRR Routing (BGP/OSPF/BFD) | default-on (`--exporter.disable-frr` disables) | plugin-gated | `quaggaOspfInterface`<br>`GET api/quagga/diagnostics/ospfinterface` | `plugin-dependent` | Routing (`page-routing`) | wildcard; may include writes | -- |
| FRR Routing (BGP/OSPF/BFD) | default-on (`--exporter.disable-frr` disables) | plugin-gated | `quaggaOspfNeighbors`<br>`POST api/quagga/diagnostics/searchOspfneighbor` | `plugin-dependent` | Routing (`page-routing`) | wildcard; may include writes | -- |
| FRR Routing (BGP/OSPF/BFD) | default-on (`--exporter.disable-frr` disables) | plugin-gated | `quaggaOspfOverview`<br>`GET api/quagga/diagnostics/ospfoverview` | `plugin-dependent` | Routing (`page-routing`) | wildcard; may include writes | -- |
| FRR Routing (BGP/OSPF/BFD) | default-on (`--exporter.disable-frr` disables) | plugin-gated | `quaggaOspfRoute`<br>`GET api/quagga/diagnostics/search_ospfroute` | `plugin-dependent` | Routing (`page-routing`) | wildcard; may include writes | -- |
| FRR Routing (BGP/OSPF/BFD) | default-on (`--exporter.disable-frr` disables) | plugin-gated | `quaggaOspfv3Database`<br>`GET api/quagga/diagnostics/search_ospfv3database` | `plugin-dependent` | Routing (`page-routing`) | wildcard; may include writes | -- |
| FRR Routing (BGP/OSPF/BFD) | default-on (`--exporter.disable-frr` disables) | plugin-gated | `quaggaOspfv3Interface`<br>`GET api/quagga/diagnostics/ospfv3interface` | `plugin-dependent` | Routing (`page-routing`) | wildcard; may include writes | -- |
| FRR Routing (BGP/OSPF/BFD) | default-on (`--exporter.disable-frr` disables) | plugin-gated | `quaggaOspfv3Overview`<br>`GET api/quagga/diagnostics/ospfv3overview` | `plugin-dependent` | Routing (`page-routing`) | wildcard; may include writes | -- |
| FRR Routing (BGP/OSPF/BFD) | default-on (`--exporter.disable-frr` disables) | plugin-gated | `quaggaOspfv3Route`<br>`GET api/quagga/diagnostics/search_ospfv3route` | `plugin-dependent` | Routing (`page-routing`) | wildcard; may include writes | -- |
| FRR Routing (BGP/OSPF/BFD) | default-on (`--exporter.disable-frr` disables) | plugin-gated | `quaggaServiceStatus`<br>`GET api/quagga/service/status` | `plugin-dependent` | Routing (`page-routing`) | wildcard; may include writes | -- |
| Relayd Load Balancer | default-on (`--exporter.disable-relayd` disables) | plugin-gated | `relaydStatusSum`<br>`GET api/relayd/status/sum` | `plugin-dependent` | Services: Relayd (`page-services-relayd`) | wildcard; may include writes | -- |
| Network Diagnostics | opt-in (`--exporter.enable-network-diagnostics`) | -- | `routingTable`<br>`GET api/diagnostics/interface/get_routes` | `known` | Diagnostics: Routing tables (`page-diagnostics-routingtables`) | wildcard; may include writes | -- |
| Services | default-on (`--exporter.disable-services` disables) | -- | `services`<br>`GET api/core/service/search` | `known` | Status: Services (`page-status-services`) | wildcard; may include writes | -- |
| Siproxd | default-on (`--exporter.disable-siproxd` disables) | plugin-gated | `siproxdRegistrations`<br>`GET api/siproxd/service/showregistrations` | `plugin-dependent` | Services: Siproxd (`page-services-siproxd`) | wildcard; may include writes | -- |
| SMART Disk Health | opt-in (`--exporter.enable-smart`) | plugin-gated | `smartInfo`<br>`POST api/smart/service/info` | `plugin-dependent` | Services: SMART (`page-services-smart`) | wildcard; may include writes | -- |
| SMART Disk Health | opt-in (`--exporter.enable-smart`) | plugin-gated | `smartList`<br>`POST api/smart/service/list` | `plugin-dependent` | Services: SMART (`page-services-smart`) | wildcard; may include writes | -- |
| ZFS Boot Environments | default-on (`--exporter.disable-snapshots` disables) | -- | `snapshotsIsSupported`<br>`GET api/core/snapshots/is_supported` | `known` | System: Snapshots (`page-snapshots`) | wildcard; may include writes | -- |
| ZFS Boot Environments | default-on (`--exporter.disable-snapshots` disables) | -- | `snapshotsSearch`<br>`GET api/core/snapshots/search` | `known` | System: Snapshots (`page-snapshots`) | wildcard; may include writes | -- |
| Network Diagnostics | opt-in (`--exporter.enable-network-diagnostics`) | -- | `socketStatistics`<br>`GET api/diagnostics/interface/get_socket_statistics` | `known` | Diagnostics: Netstat (`page-diagnostics-netstat`) | wildcard; may include writes | -- |
| Syslog | default-on (`--exporter.disable-syslog` disables) | plugin-gated | `syslogServiceStatus`<br>`GET api/syslog/service/status` | `known` | System: Settings: Logging (`page-diagnostics-logs-settings-targets`) | wildcard; may include writes | -- |
| Syslog | default-on (`--exporter.disable-syslog` disables) | -- | `syslogStats`<br>`GET api/syslog/service/stats` | `known` | System: Settings: Logging (`page-diagnostics-logs-settings-targets`) | wildcard; may include writes | -- |
| Activity | default-on (`--exporter.disable-activity` disables) | -- | `systemActivity`<br>`GET api/diagnostics/activity/get_activity` | `known` | Diagnostics: System Activity (`page-diagnostics-system-activity`) | wildcard; may include writes | -- |
| System | default-on (`--exporter.disable-system` disables) | -- | `systemDisk`<br>`GET api/diagnostics/system/systemDisk` | `unknown` | No matched ACL; only `page-all` | exact | the Core ACL grants the snake_case spelling api/diagnostics/system/system_disk (Lobby: Dashboard). OPNsense routes both spellings to the same action but matches the ACL against the raw request URI, so the camelCase URL the exporter registers is covered by no privilege except page-all. |
| System | default-on (`--exporter.disable-system` disables) | -- | `systemInformation`<br>`GET api/diagnostics/system/system_information` | `known` | Lobby: Dashboard (`page-system-login-logout`) | wildcard; may include writes | -- |
| Mbuf | default-on (`--exporter.disable-mbuf` disables) | -- | `systemMbuf`<br>`GET api/diagnostics/system/systemMbuf` | `unknown` | No matched ACL; only `page-all` | exact | the Core ACL grants api/diagnostics/system/system_mbuf (Lobby: Dashboard); the camelCase URL the exporter registers matches no privilege except page-all. |
| System | default-on (`--exporter.disable-system` disables) | -- | `systemResources`<br>`GET api/diagnostics/system/systemResources` | `unknown` | No matched ACL; only `page-all` | exact | the Core ACL grants api/diagnostics/system/system_resources (Lobby: Dashboard); the camelCase URL the exporter registers matches no privilege except page-all. |
| System | default-on (`--exporter.disable-system` disables) | -- | `systemSwap`<br>`GET api/diagnostics/system/systemSwap` | `unknown` | No matched ACL; only `page-all` | exact | the Core ACL grants api/diagnostics/system/system_swap (Lobby: Dashboard); the camelCase URL the exporter registers matches no privilege except page-all. |
| Temperature | default-on (`--exporter.disable-temperature` disables) | -- | `systemTemperature`<br>`GET api/diagnostics/system/systemTemperature` | `unknown` | No matched ACL; only `page-all` | exact | the Core ACL grants api/diagnostics/system/system_temperature (Lobby: Dashboard); the camelCase URL the exporter registers matches no privilege except page-all. |
| System | default-on (`--exporter.disable-system` disables) | -- | `systemTime`<br>`GET api/diagnostics/system/systemTime` | `unknown` | No matched ACL; only `page-all` | exact | the Core ACL grants api/diagnostics/system/system_time (Lobby: Dashboard); the camelCase URL the exporter registers matches no privilege except page-all. |
| Tailscale | default-on (`--exporter.disable-tailscale` disables); high-cardinality opt-in (`--exporter.enable-tailscale-peer-details`) | plugin-gated | `tailscaleServiceStatus`<br>`GET api/tailscale/service/status` | `plugin-dependent` | Tailscale (`page-tailscale-config`) | wildcard; may include writes | -- |
| Tailscale | default-on (`--exporter.disable-tailscale` disables); high-cardinality opt-in (`--exporter.enable-tailscale-peer-details`) | plugin-gated | `tailscaleStatus`<br>`GET api/tailscale/status/status` | `plugin-dependent` | Tailscale (`page-tailscale-config`) | wildcard; may include writes | -- |
| Tor | opt-in (`--exporter.enable-tor`) | plugin-gated | `torCircuits`<br>`GET api/tor/service/circuits` | `plugin-dependent` | tor (`page-tor`) | wildcard; may include writes | -- |
| Tor | opt-in (`--exporter.enable-tor`) | plugin-gated | `torHiddenServices`<br>`GET api/tor/service/get_hidden_services` | `plugin-dependent` | tor (`page-tor`) | wildcard; may include writes | -- |
| Tor | opt-in (`--exporter.enable-tor`) | plugin-gated | `torStreams`<br>`GET api/tor/service/streams` | `plugin-dependent` | tor (`page-tor`) | wildcard; may include writes | -- |
| Traffic Shaper | default-on (`--exporter.disable-trafficshaper` disables) | plugin-gated | `trafficShaperStatistics`<br>`GET api/trafficshaper/service/statistics` | `known` | Diagnostics: Shaper status (`page-diagnostics-limiter-info`); Firewall: Shaper (`page-firewall-trafficshaper`) | wildcard; may include writes | -- |
| Unbound DNS | default-on (`--exporter.disable-unbound` disables); high-cardinality opt-in (`--exporter.enable-unbound-infra`) | -- | `unboundBlocklistPolicies`<br>`GET api/unbound/overview/get_policies` | `known` | Services: Unbound (`page-services-unbound`); Status: DNS Overview (`page-status-dnsoverview`) | wildcard; may include writes | -- |
| Unbound DNS | default-on (`--exporter.disable-unbound` disables); high-cardinality opt-in (`--exporter.enable-unbound-infra`) | -- | `unboundDNSStatus`<br>`GET api/unbound/diagnostics/stats` | `known` | Services: Unbound (`page-services-unbound`) | wildcard; may include writes | -- |
| Unbound DNS | default-on (`--exporter.disable-unbound` disables); high-cardinality opt-in (`--exporter.enable-unbound-infra`) | -- | `unboundInfra`<br>`GET api/unbound/diagnostics/dumpinfra` | `known` | Services: Unbound (`page-services-unbound`) | wildcard; may include writes | -- |
| Unbound DNS | default-on (`--exporter.disable-unbound` disables); high-cardinality opt-in (`--exporter.enable-unbound-infra`) | -- | `unboundInsecureDomains`<br>`GET api/unbound/diagnostics/listinsecure` | `known` | Services: Unbound (`page-services-unbound`) | wildcard; may include writes | -- |
| Unbound DNS | default-on (`--exporter.disable-unbound` disables); high-cardinality opt-in (`--exporter.enable-unbound-infra`) | -- | `unboundLocalData`<br>`GET api/unbound/diagnostics/listlocaldata` | `known` | Services: Unbound (`page-services-unbound`) | wildcard; may include writes | -- |
| Unbound DNS | default-on (`--exporter.disable-unbound` disables); high-cardinality opt-in (`--exporter.enable-unbound-infra`) | -- | `unboundLocalZones`<br>`GET api/unbound/diagnostics/listlocalzones` | `known` | Services: Unbound (`page-services-unbound`) | wildcard; may include writes | -- |
| Unbound DNS | default-on (`--exporter.disable-unbound` disables); high-cardinality opt-in (`--exporter.enable-unbound-infra`) | -- | `unboundQueryStatsEnabled`<br>`GET api/unbound/overview/is_enabled` | `known` | Services: Unbound (`page-services-unbound`); Status: DNS Overview (`page-status-dnsoverview`) | wildcard; may include writes | -- |
| Unbound DNS | default-on (`--exporter.disable-unbound` disables); high-cardinality opt-in (`--exporter.enable-unbound-infra`) | -- | `unboundQueryStatsTotals`<br>`GET api/unbound/overview/totals/1` | `known` | Services: Unbound (`page-services-unbound`); Status: DNS Overview (`page-status-dnsoverview`) | wildcard; may include writes | -- |
| (log shipping) | non-collector endpoint | -- | `unboundSearchQueries`<br>`POST api/unbound/overview/search_queries` | `known` | Services: Unbound (`page-services-unbound`); Status: DNS Overview (`page-status-dnsoverview`) | wildcard; may include writes | -- |
| Unbound DNS | default-on (`--exporter.disable-unbound` disables); high-cardinality opt-in (`--exporter.enable-unbound-infra`) | plugin-gated | `unboundServiceStatus`<br>`GET api/unbound/service/status` | `known` | Services: Unbound (`page-services-unbound`) | wildcard; may include writes | -- |
| Vnstat Traffic Accounting | opt-in (`--exporter.enable-vnstat`) | -- | `vnstatGetJsonData`<br>`GET api/vnstat/service/get_json_data` | `plugin-dependent` | Services: Vnstat (`page-services-vnstat`) | wildcard; may include writes | -- |
| Vnstat Traffic Accounting | opt-in (`--exporter.enable-vnstat`) | plugin-gated | `vnstatInterfaceList`<br>`GET api/vnstat/service/interface_list` | `plugin-dependent` | Services: Vnstat (`page-services-vnstat`) | wildcard; may include writes | -- |
| Wireguard | default-on (`--exporter.disable-wireguard` disables) | -- | `wireguardClients`<br>`GET api/wireguard/service/show` | `known` | VPN: WireGuard: Configuration (`page-wireguard-config`); VPN: WireGuard: Status (`page-wireguard-diagnostics`) | wildcard; may include writes | -- |
| Wireguard | default-on (`--exporter.disable-wireguard` disables) | plugin-gated | `wireguardServiceStatus`<br>`GET api/wireguard/service/status` | `known` | VPN: WireGuard: Configuration (`page-wireguard-config`); VPN: WireGuard: Status (`page-wireguard-diagnostics`) | wildcard; may include writes | -- |
<!-- docgen:end:acl-matrix -->

### 401 and 403 remediation

For a 401 or 403, the exporter log and operator console identify the collector, endpoint, and likely privilege from this matrix. Grant the indicated privilege to the API key's user, then check **System > Access > Users > Effective Privileges**. The guidance never includes an API key, secret, authorization header, or response body.

## TLS configuration

### Using OPNsense with HTTPS

The exporter connects to OPNsense via HTTPS by default when `--opnsense.protocol=https` is set. For OPNsense instances using a certificate signed by a public CA, no additional configuration is needed.

### Self-signed or private-CA certificates

If your OPNsense uses a self-signed certificate or one issued by a private CA,
trust the CA where the exporter can see it. The recommended approach depends on
how the exporter runs.

**Host / bare binary (recommended for non-container installs)**

On a normal Linux host the exporter uses the OS trust store. Add the OPNsense CA
to it and refresh the bundle:

```bash
sudo cp opnsense-ca.crt /usr/local/share/ca-certificates/opnsense-ca.crt
sudo update-ca-certificates
```

This works only where `update-ca-certificates` (or your distro's equivalent)
merges that directory into the system bundle. It does **not** apply to the
official container image.

**Container (official distroless image)**

The official runtime image is distroless: it has no `update-ca-certificates` and
does not merge `/usr/local/share/ca-certificates` into Go's trust roots, so
mounting a certificate there leaves it untrusted. Instead mount the CA bundle at
any path and point Go's TLS stack at it with `SSL_CERT_FILE`:

```yaml
services:
  opnsense-exporter:
    image: ghcr.io/rknightion/opnsense-exporter:latest
    environment:
      SSL_CERT_FILE: /certs/opnsense-ca.pem
    volumes:
      - ./opnsense-ca.pem:/certs/opnsense-ca.pem:ro
```

See [Custom CA certificates](deployment/docker.md#custom-ca-certificates) in the
Docker deployment guide for the full example.

**Disable TLS verification (not recommended)**

```bash
--opnsense.insecure
```

Or via environment variable:

```bash
OPNSENSE_EXPORTER_OPS_INSECURE=true
```

!!! warning
    Disabling TLS verification exposes the API key and secret to man-in-the-middle attacks. Only use this for testing or on trusted networks. When enabled, the exporter logs a startup warning: `TLS certificate verification disabled (opnsense.insecure); API credentials and data are exposed to MITM risk`.

### Exporter TLS (web config)

The exporter itself can serve metrics over HTTPS using the Prometheus exporter toolkit's [web configuration](https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md):

```bash
--web.config.file=/path/to/web-config.yml
```

Example web config:

```yaml title="web-config.yml"
tls_server_config:
  cert_file: /path/to/cert.pem
  key_file: /path/to/key.pem
```

Avoid enabling the exporter toolkit's `rate_limit` option in the web config on listeners reachable by untrusted peers: it is a single pre-authentication global bucket, so any one client can exhaust it and starve legitimate Prometheus scrapes.

## File-based secrets

For production deployments, avoid passing API credentials as command-line flags or plain environment variables. Instead, use file-based secrets:

| Env Var | Description |
|---------|-------------|
| `OPS_API_KEY_FILE` | Path to a file containing the API key |
| `OPS_API_SECRET_FILE` | Path to a file containing the API secret |

The exporter reads the first line of each file. File-based secrets take precedence over flag/env var values when set.

### Docker secrets example

```yaml
services:
  opnsense-exporter:
    image: ghcr.io/rknightion/opnsense-exporter:latest
    environment:
      OPS_API_KEY_FILE: /run/secrets/opnsense-api-key
      OPS_API_SECRET_FILE: /run/secrets/opnsense-api-secret
    secrets:
      - opnsense-api-key
      - opnsense-api-secret
```

### Kubernetes secrets example

```yaml
env:
  - name: OPS_API_KEY_FILE
    value: /etc/opnsense-exporter/creds/api-key
  - name: OPS_API_SECRET_FILE
    value: /etc/opnsense-exporter/creds/api-secret
volumeMounts:
  - name: api-key-vol
    mountPath: /etc/opnsense-exporter/creds
    readOnly: true
```

### Systemd with file permissions

```bash
# Create credential files
echo "your-api-key" | sudo tee /etc/opnsense-exporter/api-key > /dev/null
echo "your-api-secret" | sudo tee /etc/opnsense-exporter/api-secret > /dev/null

# Restrict permissions
sudo chmod 600 /etc/opnsense-exporter/api-key /etc/opnsense-exporter/api-secret
sudo chown root:root /etc/opnsense-exporter/api-key /etc/opnsense-exporter/api-secret
```

## OPNsense settings

One collector needs an extra OPNsense setting enabled:

- **Unbound DNS collector:** Enable **Unbound DNS > Advanced > Extended Statistics** in the OPNsense web UI for full DNS metrics.

## Container security

The official container image is hardened:

- **Distroless base image** - minimal attack surface with no shell, package manager, or unnecessary binaries
- **Non-root execution** - runs as UID 65532 (nonroot)
- **Read-only root filesystem** - supported in Kubernetes and Docker
- **No capabilities** - all Linux capabilities are dropped in the Kubernetes deployment manifest
- **Static binary** - no runtime dependencies, CGO disabled

The `/metrics` endpoint requires no authentication by default, so restrict who can reach it at the network layer. On Kubernetes, a sample [NetworkPolicy](deployment/kubernetes.md#restrict-access-with-a-networkpolicy) limiting ingress on the metrics port to Prometheus is provided at [`deploy/k8s/networkpolicy.yaml`](https://github.com/rknightion/opnsense-exporter/blob/main/deploy/k8s/networkpolicy.yaml).
