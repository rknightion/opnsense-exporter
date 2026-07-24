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
[GitHub issue tracker](https://github.com/rknightion/opnsense-exporter/issues). If your release is
not handled correctly, [open an issue](https://github.com/rknightion/opnsense-exporter/issues/new)
with the OPNsense version and the raw API response.

When a release drops out of the support window, the shims that carried its payload shape get
pruned. That is a normal release change, not a breaking one, because by then no supported
firewall sends the old shape.

## Version-dependent data availability

Some data is gone from the OPNsense API. Where upstream stopped serving a field, the
metric or label built from it reads absent, empty or zero **on newer firewalls regardless of
which exporter version you run**. Upgrading or downgrading the exporter cannot bring it back.

| Metric / label | Behaviour | From |
| --- | --- | --- |
| `opnsense_ndp_entries` - `type` label | Empty string. OPNsense stopped populating the NDP table's `type` column, so the label survives but carries no value. Series still emitted (with `--exporter.enable-ndp-details`); the `opnsense_ndp_entries_total` aggregate is unaffected. | 26.1.11 |
| `opnsense_kea_dhcp4_pool_size` - `interface` label | Empty string. The `%interface` column was removed from the Kea DHCPv4 subnet rows, so the subnet's interface name is no longer available to join on. `subnet` and the metric value are unaffected, as are the `interface`-labelled *lease* metrics (`opnsense_kea_dhcp4_leases_by_interface`), which take their interface from the lease rows. | 26.7 |
| `opnsense_unbound_dns_queries_by_type_total`<br>`opnsense_unbound_dns_answers_by_rcode_total`<br>`opnsense_unbound_dns_query_flags_total`<br>`opnsense_unbound_dns_edns_total`<br>`opnsense_unbound_dns_answers_secure_total`<br>`opnsense_unbound_dns_answers_bogus_total`<br>`opnsense_unbound_dns_rrset_bogus_total`<br>`opnsense_unbound_dns_cache_count`<br>`opnsense_unbound_dns_memory_bytes`<br>`opnsense_unbound_dns_unwanted_total` | Not emitted on a **default** install. Unbound now ships with `extended-statistics: no`, and these series are all built from its extended statistics. Re-enable *Services > Unbound DNS > Advanced > Extended Statistics* on the firewall and they come back. The exporter detects the extended block's presence per scrape and needs no flag or restart. | 26.7 |

Unbound's core totals - `opnsense_unbound_dns_queries_total`, `opnsense_unbound_dns_cache_hits_total`,
`opnsense_unbound_dns_cache_miss_total`, the `recursion_time_*` and `request_list_*` series and
`opnsense_unbound_dns_uptime_seconds` - are not part of the extended block and are unaffected.

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
