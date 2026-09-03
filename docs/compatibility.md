---
title: Compatibility
description: Which OPNsense releases the exporter supports, how it handles cross-version payload changes, and which metrics and labels upstream OPNsense stopped serving
tags:
  - compatibility
  - upgrading
---

# Compatibility

## Support policy

The exporter targets the **current stable OPNsense release and the previous stable**: today
that means **26.1.x and 25.7**. Older releases are best-effort - they generally keep working,
but a payload change that only affects them will not hold up a release.

One binary handles every supported payload shape at once: no compatibility flags, no
version-detection switch, nothing to configure. The API client resolves payload differences
**by shape**, reading whichever field a given firewall actually sends, so the same image
scrapes a 25.7 box and a 26.1 box correctly.

Payload drift is caught by a daily canary that diffs live OPNsense responses against the exporter's
own structs. Its results, and every compatibility decision behind this page, are tracked in the
[GitHub issue tracker](https://github.com/rknightion/opnsense2otel/issues). If your release is
not handled correctly, [open an issue](https://github.com/rknightion/opnsense2otel/issues/new)
with the OPNsense version and the raw API response.

When a release drops out of the support window, the shims that carried its payload shape get
pruned. That is a normal release change, not a breaking one, because by then no supported
firewall sends the old shape.

A shim also gets pruned when it turns out never to have been needed. Reading whichever field a
firewall actually sends only works if both spellings are real, so each alternate field name is
checked against upstream's own history before it is trusted, and one that no release ever emitted
is deleted rather than carried. The OSPF per-area fully-adjacent-neighbour count was one: it was
read from `nbrFullAdjacentCounter` with a fallback to `nbrFullAdjacencyCount`, and the second name
appears nowhere in FRR's history - `nbrFullAdjacentCounter` has been the only spelling since OSPF
JSON output was added in 2015, present in every FRR release the `os-frr` plugin has ever shipped.
Removing that fallback changes no metric, because the branch could never run. It does fix one
reading: an area with interfaces up but no neighbour reaching `Full` now reports 0 rather than
falling through to the fallback, and 0 is the number that matters there.

## Version-dependent data availability

Some data is gone from the OPNsense API. Where upstream stopped serving a field, the
metric or label built from it reads absent, empty or zero **on newer firewalls regardless of
which exporter version you run**. Upgrading or downgrading the exporter cannot bring it back.

| Metric / label | Behaviour | From |
| --- | --- | --- |
| `opnsense_ndp_entries` - `type` label | Empty string. OPNsense stopped populating the NDP table's `type` column, so the label survives but carries no value. Series still emitted (with `--exporter.enable-ndp-details`); the `opnsense_ndp_entries_total` aggregate is unaffected. | 26.1.11 |
| `opnsense_kea_dhcp4_pool_size` - `interface` label | Empty string. The `%interface` column was removed from the Kea DHCPv4 subnet rows, so the subnet's interface name is no longer available to join on. `subnet` and the metric value are unaffected, as are the `interface`-labelled *lease* metrics (`opnsense_kea_dhcp4_leases_by_interface`), which take their interface from the lease rows. | 26.7 |
| `opnsense_unbound_dns_queries_by_type_total`<br>`opnsense_unbound_dns_answers_by_rcode_total`<br>`opnsense_unbound_dns_query_flags_total`<br>`opnsense_unbound_dns_edns_total`<br>`opnsense_unbound_dns_answers_secure_total`<br>`opnsense_unbound_dns_answers_bogus_total`<br>`opnsense_unbound_dns_rrset_bogus_total`<br>`opnsense_unbound_dns_cache_count`<br>`opnsense_unbound_dns_memory_bytes`<br>`opnsense_unbound_dns_unwanted_total` | Not emitted on a **default** install. Unbound now ships with `extended-statistics: no`, and these series are all built from its extended statistics. Re-enable *Services > Unbound DNS > Advanced > Extended Statistics* on the firewall and they come back. The exporter detects the extended block's presence on each scheduled poll and needs no flag or restart. | 26.7 |

Unbound's core totals - `opnsense_unbound_dns_queries_total`, `opnsense_unbound_dns_cache_hits_total`,
`opnsense_unbound_dns_cache_miss_total`, the `recursion_time_*` and `request_list_*` series and
`opnsense_unbound_dns_uptime_seconds` - are not part of the extended block and are unaffected.

### Metrics introduced with OPNsense 26.7 APIs

Two collector families use core API endpoints that OPNsense first added in 26.7. On 26.1 and
earlier, the exporter treats the endpoint's 404 as feature absence and emits no series from that
family; the rest of the scrape remains healthy.

| Metric | Behaviour before 26.7 |
| --- | --- |
| `opnsense_gateway_groups_member` | Not emitted. The gateway-group settings endpoint does not exist. Existing per-gateway status metrics remain available. |
| `opnsense_firewall_migration_legacy_rules`<br>`opnsense_firewall_migration_legacy_outbound_nat_rules` | Not emitted. The firewall migration-count endpoints do not exist; absence is not reported as zero migration debt. |

### API-key permissions after the 26.7 ACL merge

OPNsense 26.7 consolidates the local user-management ACL entries. In 26.1,
`api/auth/group/*` belonged to `page-system-groupmanager` (System: Access: Groups),
while `api/auth/user/*` - including `search_api_key` - belonged to
`page-system-usermanager` (System: Access: Users). In 26.7 the separate group-manager
and privilege entries are gone: the user, group and privilege API paths are all under
`page-system-usermanager`, renamed System: Access: Management. Compare the
[26.1 ACL definition](https://github.com/opnsense/core/blob/stable/26.1/src/opnsense/mvc/app/models/OPNsense/Core/ACL/ACL.xml#L540-L580)
with the [26.7 ACL definition](https://github.com/opnsense/core/blob/stable/26.7/src/opnsense/mvc/app/models/OPNsense/Core/ACL/ACL.xml#L550-L575).

After upgrading a restricted monitoring user, check **System > Access > Users > Effective
Privileges** and re-grant/save `System: Access: Management`
(`page-system-usermanager`) if it is absent. That is the consolidated grant needed by the
`authUsers`, `authGroups` and `authAPIKeys` searches. A 403 from one of these endpoints
after the upgrade is an ACL grant issue; no exporter compatibility switch is needed. The
[security matrix](security.md#generated-collector-to-acl-matrix) records the same
cross-release difference for `authGroups`.

### Unbound query-log blocklist identity

The opt-in Unbound query-log source also spans two response shapes. Legacy
`search_queries` rows carry the backend blocklist short code, so the exporter
ships it as `blocklist` in the JSON body and Loki structured metadata. OPNsense
26.7 adds `category` and replaces that code with a configured display value; the
original code is not present and cannot be recovered. For that shape the
exporter omits `blocklist` from both places rather than inventing a stable-looking
display-valued identity. Downstream consumers must allow this attribute to be
absent on 26.7; use the [Unbound log-shipping contract](log-shipping.md#unbound-per-query-dns-log)
for the record-level details.

Several other fields disappeared from OPNsense payloads in the same window without any metric
impact, because the exporter never exposed them: the mbuf pool's `mbuf-max`, `percentage` and
`mbuf-and-cluster` keys, and the per-counter `rate` values in the pf state-table and
source-tracking statistics (both 26.1.11). There is nothing to do about these; they are listed
here only so a payload diff against an older firewall does not read as a regression.

## How drift is caught

Two canaries run daily. The **API contract canary** diffs the exporter's endpoint set against the
OPNsense source tree (both `master` and `stable`), catching renamed, removed and GET→POST-flipped
endpoints before anyone's firewall upgrades into them. The **live schema canary** scrapes a real
OPNsense devel box and validates the actual payload structure (key paths and JSON types) against
the exporter's structs. That is what catches a field quietly changing type or vanishing from a
response body.

Genuine drift lands as an `api-drift` issue on the repository. If you hit a payload problem the
canaries have not already filed, open an issue with the release version and the raw API response.
