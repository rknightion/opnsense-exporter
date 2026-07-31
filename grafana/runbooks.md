<!-- GENERATED FILE. Do not hand-edit; run `make rules` (grafana/alerts/build_rules.py). -->

# Alerts & Recording Rules

One section per alert rule in `grafana/alerts/build_rules.py`'s `RULES`, in source order, followed by every recording rule in `RECORDING`. Each alert section states what its expression measures, its threshold and window, what absent/no-data means for that specific rule, first checks, likely causes, and how to confirm it has genuinely recovered - mined from the same source comments and descriptions that drive the generated manifests, so this document and the alert's own annotations can never contradict each other.

Total: **59 alert rules** and **14 recording rules**.

## OPNsenseExporterDown

**Severity:** critical  
**Pending window:** 15m0s  
**Rule name:** `opnsense-exporter-down`

**Expression:**
```promql
opnsense_up
```

**What it measures:** opnsense_up: whether the exporter's most recent poll of the OPNsense system-status API succeeded at all. It is reachability-only - a reachable box self-reporting a degraded subsystem stays at 1.

**Threshold & window:** lt 1 for 15m. The 15m window is sized to ride out a normal reboot (typically <10m) without paging.

**Absent / no-data semantics:** noDataState is Alerting - a totally-missing series (the whole fleet gone) pages immediately here. A SINGLE instance disappearing while others keep reporting is Grafana's MissingSeries case instead, which this rule structurally cannot see; OPNsenseExporterInstanceMissing exists to catch that.

**First checks:**
- Check the Prometheus Targets page for this scrape target before assuming the firewall itself is down - it may be a network path or scrape-config problem
- Read opnsense_system_status_code and the crash-reporter/firewall-status gauges for the same instance - if those are non-zero the box is reachable but sick, a different alert
- Reach the OPNsense box directly (console/SSH) to tell a full outage from an API-only fault

**Likely causes:**
- The OPNsense box is powered off, rebooting past the 15m grace window, or unreachable over the network
- The OPNsense API credentials were revoked/expired or the API service crashed
- The exporter process itself died or lost its network path to the firewall

**Verify recovery:**
- opnsense_up reads 1 again on the next scrape for the named instance
- No further NoData gap appears on the Overview tab's Exporter/API panels for at least one full scrape interval

## OPNsenseExporterInstanceMissing

**Severity:** critical  
**Pending window:** 10m0s  
**Rule name:** `opnsense-exporter-instance-missing`

**Expression:**
```promql
max by (opnsense_instance) (present_over_time(opnsense_up[1h])) unless on(opnsense_instance) opnsense_up
```

**What it measures:** Compares a 1h present_over_time baseline of opnsense_up against what is reporting right now, `unless`-subtracting instances still present - what survives is exactly the set that has vanished while at least one other instance keeps reporting.

**Threshold & window:** gt 0 for 10m. The 1h lookback is a historical baseline, not a configured inventory: self-protecting for a new exporter once it has been up an hour, at the cost of alerting for up to that hour after a deliberate decommission.

**Absent / no-data semantics:** noDataState is Ok on purpose: if the WHOLE fleet disappears this query also returns nothing, and OPNsenseExporterDown already pages for that case - alerting here too would double-page one event.

**First checks:**
- Read the firing opnsense_instance label and check whether that scrape target still exists in Prometheus service discovery
- Check whether that instance was deliberately decommissioned - if so, silence it rather than chase it
- Look for a label change on that instance in the last hour (version bump, relabel, scrape-config edit) - a changed label set can itself look like a vanished instance (#472)

**Likely causes:**
- The exporter process for that instance was stopped or its host decommissioned
- The exporter crashed or its host went down unexpectedly
- Prometheus stopped scraping that target (dropped from service discovery, firewall rule, DNS failure)

**Verify recovery:**
- The named instance's opnsense_up series is present and back at 1 on the next scrape
- The instance no longer appears as a firing alert instance after one more evaluation cycle

## OPNsenseFirewallUnhealthy

**Severity:** warning  
**Pending window:** 10m0s  
**Rule name:** `opnsense-firewall-unhealthy`

**Expression:**
```promql
opnsense_firewall_status
```

**What it measures:** opnsense_firewall_status, the firewall subsystem's own entry in OPNsense's combined system-status payload (the same API call opnsense_up is derived from).

**Threshold & window:** lt 1 (0 = errors reported) sustained for 10m.

**Absent / no-data semantics:** Default noDataState (Ok). Because this comes from the same status call as opnsense_up, a total absence here usually means the whole status API is unreachable - which OPNsenseExporterDown already covers - rather than an independent signal to alert on.

**First checks:**
- Check opnsense_system_status_code and opnsense_crash_reporter_status for the same instance - OPNsense reports these as one combined payload
- Open the OPNsense UI's own Dashboard status widget for the actual subsystem error text, which this gauge cannot carry
- Confirm opnsense_up is still 1 - if it is 0 too, this is a symptom of full unreachability, not an independent firewall fault

**Likely causes:**
- A firewall ruleset failed to apply or reload cleanly
- pf itself is reporting an internal error state
- A subsystem that rolls up into firewall health (e.g. Suricata/IDS) broke

**Verify recovery:**
- opnsense_firewall_status returns to 1
- The OPNsense UI's own status widget for this subsystem shows OK/green

## OPNsenseCrashReports

**Severity:** warning  
**Pending window:** 5m0s  
**Rule name:** `opnsense-crash-reports`

**Expression:**
```promql
opnsense_crash_reporter_status
```

**What it measures:** opnsense_crash_reporter_status: whether OPNsense's own crash-report collector has one or more unreviewed crash reports on disk.

**Threshold & window:** lt 1 (0 = reports present) sustained for 5m.

**Absent / no-data semantics:** Default noDataState (Ok) - absence means the status API itself is down, covered by OPNsenseExporterDown, not that crash reports are clear.

**First checks:**
- Open the OPNsense UI's crash reporter page to read the actual report(s), which the gauge cannot carry
- Check whether the crash coincides with a recent firmware/plugin update
- Confirm opnsense_up is 1 - this fires independently of reachability, on a box that is otherwise healthy

**Likely causes:**
- A daemon or kernel module crashed and OPNsense's monitor captured a core/report
- A plugin update introduced a regression

**Verify recovery:**
- The crash report is reviewed and cleared in the OPNsense UI
- opnsense_crash_reporter_status returns to 1 and no new report appears after clearing it

## OPNsenseDiskSpaceLow

**Severity:** warning  
**Pending window:** 10m0s  
**Rule name:** `opnsense-disk-space-low`

**Expression:**
```promql
opnsense_system_subsystem_status_code{subsystem="diskspace"}
```

**What it measures:** opnsense_system_subsystem_status_code{subsystem="diskspace"}, OPNsense's own root filesystem health-check subsystem (2=OK, 1=NOTICE, 0=WARNING nearly full, -1=ERROR critically full).

**Threshold & window:** lt 2 (below OK) sustained for 10m.

**Absent / no-data semantics:** Absent means healthy on purpose - OPNsense omits an OK subsystem from the health-check payload entirely rather than emitting a 2, so noDataState is deliberately left at the default Ok.

**First checks:**
- Check actual root filesystem usage on the box (`df -h /`) rather than relying on the coarse 4-value gauge
- Look for a runaway log, a stuck package cache, or a full config-backup history filling the root partition

**Likely causes:**
- Log rotation is misconfigured or a service is logging excessively
- Firmware/package upgrade left old files uncleaned
- The root partition is simply undersized for the installed plugin set

**Verify recovery:**
- The subsystem key disappears from the payload again (return to the healthy, absent-means-OK state) or reads 2
- `df -h /` on the box shows headroom restored

## OPNsenseEndpointErrors

**Severity:** warning  
**Pending window:** 15m0s  
**Rule name:** `opnsense-endpoint-errors`

**Expression:**
```promql
sum by (opnsense_instance, endpoint) (increase(opnsense_exporter_endpoint_errors_total[2m]))
```

**What it measures:** Per-endpoint count of opnsense_exporter_endpoint_errors_total increases in rolling 2m windows, summed by opnsense_instance and endpoint - a FAST/MEDIUM-tier signal that names which API call is failing.

**Threshold & window:** gt 0 for 15m, with a deliberately short 2m inner window: a burst under ~10m clears the 2m window before the 15m pending period elapses, so a router reboot doesn't false-page (#94), while genuinely sustained errors keep every rolling 2m window non-empty.

**Absent / no-data semantics:** Default noDataState (Ok) - no errors means no series, which is the healthy state, not an outage signal.

**First checks:**
- Read the endpoint label to know exactly which OPNsense API call is failing
- Check the exporter's own logs for the HTTP status/error body from that endpoint
- Confirm the API key/secret still has permission for that endpoint, and that any gating plugin is still installed

**Likely causes:**
- An API key was revoked or its permissions narrowed
- The relevant OPNsense plugin was removed or is misbehaving
- OPNsense itself returned malformed or unexpected data for that endpoint

**Verify recovery:**
- The 2m rolling increase() for that endpoint returns to 0 and stays there
- opnsense_exporter_scrape_collector_success for the owning collector reads 1 again

## OPNsenseCollectorDataStale

**Severity:** warning  
**Pending window:** 5m0s  
**Rule name:** `opnsense-collector-data-stale`

**Expression:**
```promql
(time() - opnsense_exporter_collector_snapshot_timestamp_seconds - 120) / opnsense_exporter_collector_poll_interval_seconds
```

**What it measures:** How many of a collector's own poll intervals have elapsed since its stored metric buffer was last replaced (time() minus the snapshot timestamp, minus a 120s scrape-lag allowance, divided by the collector's own poll interval) - staleness expressed in MISSED INTERVALS so one rule covers every tier.

**Threshold & window:** gt 3 missed intervals for 5m, which works out to roughly 8m on the fast (15s) tier and 52m on the cold (15m) tier; one failed poll followed by recovery peaks at ~2 missed intervals on any tier and cannot fire.

**Absent / no-data semantics:** Both feeding gauges are absent until first successfully stored, so a collector that has NEVER stored data produces no series here and cannot alert on staleness - that gap is what OPNsenseCollectorNeverStoredData exists to close.

**First checks:**
- Read the collector label and check opnsense_exporter_scrape_collector_success and the endpoint-error panels for that same collector
- Note the last-poll-timestamp panel is USELESS here - it advances on every failed attempt too, so don't use it to judge freshness
- Confirm the dashboard's stale value is old but not blanked - retained last-good data is deliberate (#336 D8), so a flat panel does not mean the outage just started

**Likely causes:**
- The collector's endpoint started erroring on every attempt
- A plugin the collector depends on was removed or disabled
- The firewall itself stopped exposing that data (feature disabled, subsystem down)

**Verify recovery:**
- The missed-interval expression drops back under 3 and stays there for at least one poll interval
- opnsense_exporter_collector_snapshot_timestamp_seconds advances again on schedule

## OPNsenseCollectorDegraded

**Severity:** info  
**Pending window:** 10m0s  
**Rule name:** `opnsense-collector-degraded`

**Expression:**
```promql
((time() - opnsense_exporter_collector_last_success_timestamp_seconds - 120) / opnsense_exporter_collector_poll_interval_seconds) unless on(opnsense_instance, collector) (((time() - opnsense_exporter_collector_snapshot_timestamp_seconds - 120) / opnsense_exporter_collector_poll_interval_seconds) > 3)
```

**What it measures:** The same missed-interval-age expression as OPNsenseCollectorDataStale, but built from opnsense_exporter_collector_last_success_timestamp_seconds (last fully CLEAN poll) rather than the snapshot timestamp, with an `unless` clause suppressing anything already covered by that fully-stale rule.

**Threshold & window:** gt 6 missed intervals for 10m - looser than the 3-interval stale threshold, because the collector IS still refreshing partial data; this is degradation, not a freeze.

**Absent / no-data semantics:** No dedicated nodata handling (default Ok) - same absent-until-first-store gap as OPNsenseCollectorDataStale.

**First checks:**
- Read the collector label and check its endpoint-error panels - the classic shape is one endpoint of a multi-endpoint collector erroring every poll while the rest keep updating
- Confirm this collector is NOT also firing OPNsenseCollectorDataStale - if it is, treat that as the primary signal
- Check whether a specific sub-feature (not the whole collector) is missing from its metrics on the dashboard

**Likely causes:**
- One endpoint of a multi-endpoint collector is failing every poll while its sibling endpoints keep succeeding
- A specific plugin sub-feature was disabled or lost permission while the rest of the collector's data source stayed healthy

**Verify recovery:**
- The missed-interval expression built from last_success drops back under 6
- The endpoint-error panel for the previously-failing endpoint returns to zero increase

## OPNsenseCollectorNeverStoredData

**Severity:** warning  
**Pending window:** 30m0s  
**Rule name:** `opnsense-collector-never-stored`

**Expression:**
```promql
opnsense_exporter_collector_last_poll_timestamp_seconds unless on(opnsense_instance, collector) opnsense_exporter_collector_snapshot_timestamp_seconds
```

**What it measures:** opnsense_exporter_collector_last_poll_timestamp_seconds present (the scheduler has attempted this collector) `unless` opnsense_exporter_collector_snapshot_timestamp_seconds present (it has ever stored a buffer) - what survives is a collector that has attempted every poll since startup and succeeded at none of them.

**Threshold & window:** gt 0 for 30m. The scheduler polls every collector within seconds of startup (up to 5s jitter), so 30m is a fixed pending period safe on every tier, not one scaled to the collector's own interval.

**Absent / no-data semantics:** No dedicated nodata handling - a collector that has never even attempted a poll (the left-hand gauge itself absent) produces no series here, which is expected during the first seconds after startup.

**First checks:**
- Read the collector label and check whether its required OPNsense plugin is installed
- Confirm the API key has permission for that collector's endpoint(s)
- Check whether this collector is even applicable to this firewall (e.g. a collector enabled against a box that doesn't run the subsystem)

**Likely causes:**
- A missing OPNsense plugin the collector depends on
- An API key without permission for that collector's endpoint
- The collector enabled against a firewall that does not run the relevant subsystem at all

**Verify recovery:**
- opnsense_exporter_collector_snapshot_timestamp_seconds appears for the first time for that collector
- The collector's own metrics start appearing on its dashboard tab

## OPNsenseGatewayDown

**Severity:** critical  
**Pending window:** 5m0s  
**Rule name:** `opnsense-gateway-down`

**Expression:**
```promql
opnsense_gateways_status{default_gateway="true"}
```

**What it measures:** opnsense_gateways_status{default_gateway="true"}: the API-reported up/down state of the box's PRIMARY WAN gateway.

**Threshold & window:** lt 1 (down) for 5m - tight, because the primary WAN typically reconverges in under a minute after a reboot.

**Absent / no-data semantics:** Default noDataState (Ok) - a totally-absent series means the exporter itself is down (OPNsenseExporterDown already pages for that); it does not fire for gateways with OPNsense-side monitoring disabled, which legitimately have no status series.

**First checks:**
- Read the name/address labels to identify the specific gateway
- Check OPNsense's own Gateway status widget and dpinger logs for the same gateway
- Confirm whether the upstream ISP link itself is down vs. a local interface/dpinger fault

**Likely causes:**
- The upstream ISP circuit is down
- A local WAN interface (physical link, PPPoE session, DHCP lease) failed
- dpinger itself stopped monitoring the gateway

**Verify recovery:**
- opnsense_gateways_status for that gateway returns to 1
- Traffic is observably flowing again on the interface (rx/tx byte-rate panels moving)

## OPNsenseGatewayDownFailover

**Severity:** warning  
**Pending window:** 15m0s  
**Rule name:** `opnsense-gw-down-failover`

**Expression:**
```promql
opnsense_gateways_status{default_gateway="false"}
```

**What it measures:** opnsense_gateways_status{default_gateway="false"}: the same up/down state, for a failover/secondary WAN gateway rather than the primary.

**Threshold & window:** lt 1 (down) for 15m - looser than the primary's 5m, because a secondary WAN can legitimately take ~7-10m to re-establish (DHCP + dpinger convergence) after a reboot.

**Absent / no-data semantics:** Default noDataState (Ok), same reasoning as OPNsenseGatewayDown: absence is the gateway lacking OPNsense-side monitoring, not a fault.

**First checks:**
- Read the name/address labels to identify the specific secondary gateway
- Confirm the primary gateway is still up (this is lower urgency precisely because it is)
- Check OPNsense's Gateway status widget for the secondary's own convergence state

**Likely causes:**
- The secondary ISP circuit or interface is down
- The secondary WAN is still mid-convergence after a reboot (should self-clear within the 15m window if so)

**Verify recovery:**
- opnsense_gateways_status for that gateway returns to 1
- Failover routing (if in use) reports the secondary as available again

## OPNsenseGatewayAlarmFlapping

**Severity:** warning  
**Pending window:** 0s  
**Rule name:** `opnsense-gateway-alarm-flapping`

**Expression:**
```promql
sum by (opnsense_instance, gateway) (increase(opnsense_log_events_gateway_total{event="alarm_started"}[15m]))
```

**What it measures:** Count of dpinger alarm_started transitions for one gateway in a 15m window, from shipped syslog events - a TRANSITION signal, not a current-state assertion.

**Threshold & window:** gt 2 (three or more starts) in the fixed 15m observation window, for_min=0 so it fires the instant the count is exceeded.

**Absent / no-data semantics:** Default noDataState (Ok) - no alarm_started events in the window is the normal, quiet state.

**First checks:**
- Check OPNsenseGatewayDown/OPNsenseGatewayDownFailover and the Gateway Status panel for this gateway's CURRENT state - this alert only proves instability happened, not that the gateway is down now
- Look at the gateway's RTT/loss panels over the same 15m window for a pattern (intermittent vs. one-off)

**Likely causes:**
- An unstable upstream link (flapping DSL/cable/PPPoE session)
- dpinger's monitor target itself is intermittently unreachable
- Congestion or a misconfigured latency/loss threshold making dpinger over-sensitive

**Verify recovery:**
- No further alarm_started events for the gateway in the next 15m window
- The gateway's current status gauge stays at 1 (up) for a sustained period

## OPNsenseGatewayHighLoss

**Severity:** warning  
**Pending window:** 10m0s  
**Rule name:** `opnsense-gateway-high-loss`

**Expression:**
```promql
opnsense_gateways_loss_percentage
```

**What it measures:** opnsense_gateways_loss_percentage: dpinger's measured packet loss to the gateway's monitor target.

**Threshold & window:** gt 20% sustained for 10m.

**Absent / no-data semantics:** Default noDataState (Ok) - absence means the gateway has no dpinger loss data (e.g. monitoring disabled), not that loss is zero.

**First checks:**
- Read the name label and check the gateway's RTT panel alongside this one for a combined latency/loss picture
- Check whether this coincides with an OPNsenseGatewayAlarmFlapping firing for the same gateway
- Rule out local congestion (interface error/drop counters) before blaming the upstream link

**Likely causes:**
- Upstream ISP link degradation or congestion
- A flapping or marginal physical/PPPoE connection
- Local interface saturation causing dpinger's own probes to be dropped

**Verify recovery:**
- opnsense_gateways_loss_percentage drops back under 20% and stays there for 10m

## OPNsenseGatewayHighRTT

**Severity:** warning  
**Pending window:** 10m0s  
**Rule name:** `opnsense-gateway-high-rtt`

**Expression:**
```promql
opnsense_gateways_rtt_milliseconds / (opnsense_gateways_rtt_high_milliseconds > 0)
```

**What it measures:** opnsense_gateways_rtt_milliseconds divided by the gateway's own configured high-latency threshold (opnsense_gateways_rtt_high_milliseconds) - a ratio over 1 means the gateway has crossed ITS OWN configured threshold, not a fixed global one.

**Threshold & window:** gt 1 (over its own configured high-RTT threshold) sustained for 10m.

**Absent / no-data semantics:** Default noDataState (Ok) - the division guard (`> 0`) means a gateway with no configured high threshold produces no series, deliberately, rather than firing on a meaningless comparison.

**First checks:**
- Read the name label and check the gateway's loss panel for a combined picture
- Check the gateway's configured high-RTT threshold value itself in OPNsense - it may need retuning rather than the link being genuinely unhealthy

**Likely causes:**
- Upstream network congestion or a route change adding latency
- The configured high-RTT threshold is tighter than the link's normal baseline

**Verify recovery:**
- The ratio drops back to 1 or below and stays there for 10m

## OPNsenseKernelZoneAllocationFailure

**Severity:** critical  
**Pending window:** 5m0s  
**Rule name:** `opnsense-kernel-zone-alloc-failure`

**Expression:**
```promql
sum by (zone, opnsense_instance) (rate(opnsense_kernel_memory_zone_failures_total{zone=~"pf states|pf state keys|pf source nodes|socket|tcp_inpcb|udp_inpcb|tcpreass"}[5m]))
```

**What it measures:** rate of UMA allocation failures in the zones whose exhaustion has a direct operational consequence.

**Threshold & window:** gt 0 for 5m, SCOPED to pf states, pf state keys, pf source nodes, socket, tcp_inpcb, udp_inpcb and tcpreass. The scoping is essential and must not be widened to all zones: UMA bucket zones, vm pgcache and vmem btag fail BY DESIGN and fall back to a slower path, and they account for all 158,488 failures on a healthy prod box. An unscoped rule would page continuously and immediately.

**Absent / no-data semantics:** Default noDataState (Ok). The zone set follows loaded kernel modules, so a zone can legitimately be absent on a box that does not use the feature.

**First checks:**
- Check the zone occupancy panel on the Kernel Memory tab for whether this zone is at a configured ceiling or simply out of memory
- Remember limit=0 means NO CEILING CONFIGURED, not a ceiling of zero - a zero limit does not mean the zone is capped
- Check overall memory pressure on System & Resources, since a zone can fail because the machine is out of memory rather than because the zone is capped
- For pf states specifically, cross-check OPNsensePFStateTableNearLimit, which watches the same exhaustion from the pf side

**Likely causes:**
- The zone has hit a configured limit and the workload genuinely needs more
- System-wide memory exhaustion, so no zone can grow
- A traffic flood opening connections faster than the box can allocate state for them

**Verify recovery:**
- The failure rate returns to zero and stays there
- Zone occupancy falls back below its ceiling, or the ceiling is raised deliberately

## OPNsenseKernelZoneNearLimit

**Severity:** warning  
**Pending window:** 15m0s  
**Rule name:** `opnsense-kernel-zone-near-limit`

**Expression:**
```promql
opnsense_kernel_memory_zone_used / (opnsense_kernel_memory_zone_limit > 0)
```

**What it measures:** zone occupancy as a fraction of its configured ceiling, across every zone that HAS a ceiling.

**Threshold & window:** gt 0.8 sustained for 15m. The `> 0` division guard is load-bearing: limit=0 means no ceiling configured rather than a ceiling of zero, and 113 of 242 zones on a real box report limit=0 with non-zero use, so an unguarded division would evaluate +Inf on half of them and fire permanently.

**Absent / no-data semantics:** Default noDataState (Ok). A zone with no configured limit produces no series here at all, by design.

**First checks:**
- Identify the zone and whether its growth is a trend or a spike
- Check whether the workload changed - more concurrent connections, a new plugin, a traffic flood
- Ignore pf anchors and pf Ethernet anchors: their limit is 2147483647 (INT_MAX), so they can never approach it and never fire here

**Likely causes:**
- Legitimate growth in the resource the zone backs
- A limit left at a default that is undersized for this box
- A leak in whatever allocates from the zone

**Verify recovery:**
- Occupancy falls back below 80% and stays there

## OPNsenseDefaultRouteMissing

**Severity:** critical  
**Pending window:** 5m0s  
**Rule name:** `opnsense-default-route-missing`

**Expression:**
```promql
opnsense_network_diag_default_route_present
```

**What it measures:** whether a default route exists per address family: 1 present, 0 absent.

**Threshold & window:** lt 1 for 5m. The metric is emitted for a FIXED ipv4/ipv6 set every scrape rather than only when a route exists, precisely so the absent case is a 0 that can be alerted on rather than a missing series that cannot.

**Absent / no-data semantics:** Default noDataState (Ok). No series at all means the network diagnostics collector is off (it is opt-in), not that the route is fine.

**First checks:**
- Check the Default Route Detail table for what the gateway and interface were before it vanished
- Check gateway health - a dpinger-driven failover that found no healthy member can leave no default route at all
- For IPv6 specifically, check whether the WAN still holds a delegated prefix and a router advertisement

**Likely causes:**
- The WAN interface went down and took its default route with it
- Gateway failover removed the failed route and had no healthy alternative to install
- A DHCP or PPPoE lease expired without renewing
- For IPv6, the RA or prefix delegation lapsed

**Verify recovery:**
- The metric returns to 1 and the Default Route Detail table shows a plausible gateway

## OPNsenseNetmapRingFull

**Severity:** warning  
**Pending window:** 30m0s  
**Rule name:** `opnsense-netmap-ring-full`

**Expression:**
```promql
sum by (device, opnsense_instance) (rate(opnsense_log_events_netmap_ring_full_events_total[15m]))
```

**What it measures:** rate(opnsense_log_events_netmap_ring_full_events_total[15m]) - how often the kernel reported a full netmap host ring, derived from syslog rather than polled.

**Threshold & window:** gt 0 sustained for 30m. The long window is deliberate: an isolated burst during a traffic spike is normal, a persistent condition is not.

**Absent / no-data semantics:** Default noDataState (Ok). Absence means no report, NOT no drops - a box with the syslog receiver disabled, or with Zenarmor not running, produces no series at all.

**First checks:**
- Confirm Zenarmor is actually running and check its own engine health - it owns this datapath
- Check throughput on the named device against what the box normally carries
- Do NOT expect the interface drop counters to corroborate this on ixl/ixgbe/igb hardware - see causes below

**Likely causes:**
- Traffic volume exceeds what the Zenarmor capture ring can absorb
- Zenarmor is wedged or too slow to drain the ring, so it backs up
- The ring is sized for a lighter load than the box now carries

**Verify recovery:**
- The event rate returns to zero and stays there across a full traffic peak, not just a quiet period

## OPNsenseDHCPClientLeaseRenewalOverdue

**Severity:** critical  
**Pending window:** 15m0s  
**Rule name:** `opnsense-dhcp-client-lease-overdue`

**Expression:**
```promql
opnsense_log_events_dhcp_client_lease_renewal_timestamp_seconds - time()
```

**What it measures:** The renewal (T1) deadline dhclient last reported, minus now. Negative means the deadline has passed and nothing has rebound since.

**Threshold & window:** lt 0 sustained for 15m. Note this is the RENEWAL deadline, not absolute lease expiry - dhclient never logs the latter, so there is more headroom than this alert implies, not less.

**Absent / no-data semantics:** Default noDataState (Ok). No series means no bound-lease line has been seen since the exporter started - expected on a static or PPPoE WAN, which never runs dhclient at all.

**First checks:**
- Check the WAN DHCP Client Messages panel for a request storm with no matching ack - that is the upstream refusing or ignoring renewals
- Check for any nak, which means the server actively rejected the current address
- Confirm physical link and upstream reachability on the WAN interface

**Likely causes:**
- The upstream DHCP server is unreachable or not responding
- The ISP changed its allocation and is refusing to renew the existing address
- dhclient has died or is wedged on that interface

**Verify recovery:**
- A fresh bind appears and the countdown resets to a positive value
- Time since last bind drops back to near zero on the countdown panel

## OPNsenseDHCPClientNak

**Severity:** warning  
**Pending window:** 5m0s  
**Rule name:** `opnsense-dhcp-client-nak`

**Expression:**
```promql
sum by (interface, opnsense_instance) (rate(opnsense_log_events_dhcp_client_total{type="nak"}[15m]))
```

**What it measures:** rate of DHCPNAK messages received by the WAN dhclient.

**Threshold & window:** gt 0 for 5m. Any NAK at all is abnormal on a stable WAN.

**Absent / no-data semantics:** Default noDataState (Ok). No dhclient on this box means no series.

**First checks:**
- Check whether the WAN address actually changed after the NAK
- Check whether anything downstream is pinned to the old address (NAT rules, dynamic DNS, VPN endpoints)

**Likely causes:**
- The ISP moved the box to a different subnet or reclaimed the address
- The upstream lease database was reset and no longer recognises this client
- Two clients are presenting the same identifier upstream

**Verify recovery:**
- A new address is bound and the NAK rate returns to zero

## OPNsenseDHCPClientRequestStorm

**Severity:** warning  
**Pending window:** 30m0s  
**Rule name:** `opnsense-dhcp-client-storm`

**Expression:**
```promql
sum by (interface, opnsense_instance) (rate(opnsense_log_events_dhcp_client_total{type="request"}[15m]))
```

**What it measures:** rate of DHCPREQUEST messages sent by the WAN dhclient.

**Threshold & window:** gt 0.1/s (360/hour) sustained for 30m. Calibrated against a real incident: the box that motivated this alert ran a ~42/hour baseline and sustained ~4,500/hour for 11-12 hours, so this threshold sits roughly 8x above normal and 12x below the observed storm.

**Absent / no-data semantics:** Default noDataState (Ok). No dhclient on this box means no series.

**First checks:**
- Check whether acks are coming back at all - requests without acks is the storm signature
- Check the lease renewal countdown: if it is still positive and being refreshed, the address is not yet at risk
- Check upstream link quality - a lossy WAN produces retransmits without any DHCP fault

**Likely causes:**
- The upstream DHCP server is not responding to renewals
- Packet loss on the WAN is eating the requests or the replies
- The upstream server is rate-limiting or blocklisting this client

**Verify recovery:**
- The request rate falls back to baseline and a fresh bind is recorded

## OPNsenseDHCPClientScriptFailure

**Severity:** critical  
**Pending window:** 5m0s  
**Rule name:** `opnsense-dhcp-client-script-failure`

**Expression:**
```promql
sum by (interface, reason, opnsense_instance) (rate(opnsense_log_events_dhcp_client_script_total{reason=~"expire|fail|timeout"}[15m]))
```

**What it measures:** rate of dhclient-script invocations whose reason indicates lease loss or failure.

**Threshold & window:** gt 0 for 5m on reason expire, fail or timeout. The healthy reasons (bound, renew, rebind, reboot) are deliberately excluded.

**Absent / no-data semantics:** Default noDataState (Ok). No dhclient on this box means no series.

**First checks:**
- Confirm whether the WAN interface still has an address at all
- Check the request/ack panel for how long the renewal had been failing beforehand - OPNsenseDHCPClientRequestStorm should have fired first

**Likely causes:**
- The upstream DHCP server has been unreachable long enough for the full lease to run out
- Physical WAN link failure
- dhclient could not obtain any lease on a fresh start

**Verify recovery:**
- A bound or renew reason follows and the interface regains an address

## OPNsenseDHCP6PrefixExpiring

**Severity:** critical  
**Pending window:** 10m0s  
**Rule name:** `opnsense-dhcp6-prefix-expiring`

**Expression:**
```promql
opnsense_log_events_dhcp6c_prefix_valid_expiry_timestamp_seconds - time()
```

**What it measures:** The valid-lifetime deadline dhcp6c last reported for the delegated prefix, minus now. Negative means it has passed with nothing refreshing it.

**Threshold & window:** lt 0 sustained for 10m. The prefix is already gone at 0 - the for_min is there so a renewal landing a moment late does not page, not to add headroom.

**Absent / no-data semantics:** Default noDataState (Ok). No series means no prefix-delegation line has been seen since the exporter started, which is the normal state on a WAN with no PD or no IPv6 at all.

**First checks:**
- Check the WAN DHCPv6 Client Messages panel for sent renew climbing with no matching received - that is the upstream having stopped answering, and it would have been visible for hours
- Check whether the preferred-lifetime countdown went negative first; if both crossed together the prefix was withdrawn rather than allowed to age out
- Confirm the v4 side is healthy - if both stopped at once this is a link or PPPoE problem, not a DHCPv6 one

**Likely causes:**
- The upstream DHCPv6 server stopped answering Renew, so the delegation was never refreshed
- The ISP withdrew or re-delegated the prefix
- dhcp6c died or is wedged on the WAN interface

**Verify recovery:**
- A prefix_updated event appears and both lifetime countdowns reset to positive values
- Downstream interfaces regain their IPv6 addresses

## OPNsenseDHCP6PrefixNotRefreshing

**Severity:** warning  
**Pending window:** 15m0s  
**Rule name:** `opnsense-dhcp6-prefix-not-refreshing`

**Expression:**
```promql
time() - opnsense_log_events_dhcp6c_prefix_updated_timestamp_seconds
```

**What it measures:** Time since the last prefix create/update line from dhcp6c for this interface.

**Threshold & window:** gt 7200s (2h), for_min=15. Sized as roughly 2x the observed refresh interval - the reference box renews hourly (pltime=3600), so two missed refreshes. Retune if your ISP hands out a longer lifetime; the honest threshold is 2x whatever pltime the prefix actually carries.

**Absent / no-data semantics:** Default noDataState (Ok). No series means no prefix delegation on this box, which is normal on a WAN without PD.

**First checks:**
- Check the WAN DHCPv6 Client Messages panel: sent renew with no received reply means the upstream has gone quiet
- Check the valid and preferred countdowns for how much time is actually left before it matters

**Likely causes:**
- The upstream DHCPv6 server has stopped responding to Renew
- dhcp6c is wedged - it may still be sending without processing replies

**Verify recovery:**
- A prefix_updated event lands and the age drops back to near zero

## OPNsenseDHCP6AddressExpiring

**Severity:** critical  
**Pending window:** 10m0s  
**Rule name:** `opnsense-dhcp6-address-expiring`

**Expression:**
```promql
opnsense_log_events_dhcp6c_address_valid_expiry_timestamp_seconds - time()
```

**What it measures:** The valid-lifetime deadline dhcp6c last reported for the WAN address lease, minus now. Negative means it has passed with nothing refreshing it.

**Threshold & window:** lt 0 sustained for 10m, same shape as OPNsenseDHCP6PrefixExpiring - the for_min exists so a renewal landing a moment late does not page.

**Absent / no-data semantics:** Default noDataState (Ok). No series means either no address-lease line has been seen since the exporter started (normal on a PD-only WAN), or the address was explicitly removed - ClearDHCP6CAddress deletes the series rather than freezing it, so absence here can mean a clean removal rather than an unreported expiry.

**First checks:**
- Check the WAN DHCPv6 Client Messages panel for sent renew climbing with no matching received
- Check whether an address_lease_removed event landed just before the series went absent - that is a clean teardown, not a silent failure
- Confirm the v4 side is healthy - if both stopped at once this is a link problem, not a DHCPv6 one

**Likely causes:**
- The upstream DHCPv6 server stopped answering Renew/Request, so the lease was never refreshed
- The ISP withdrew the address
- dhcp6c died or is wedged on the WAN interface

**Verify recovery:**
- An address_lease_created or address_lease_updated event appears and the deadline resets to a positive value

## OPNsenseDHCP6AddressNotRefreshing

**Severity:** warning  
**Pending window:** 15m0s  
**Rule name:** `opnsense-dhcp6-address-not-refreshing`

**Expression:**
```promql
time() - opnsense_log_events_dhcp6c_address_updated_timestamp_seconds
```

**What it measures:** Time since the last address-lease create/update line from dhcp6c for this interface.

**Threshold & window:** gt 7200s (2h), for_min=15 - same 2x-observed-refresh-interval sizing as OPNsenseDHCP6PrefixNotRefreshing (pltime=1125 observed on the captured box). Retune to 2x whatever pltime your ISP actually hands out.

**Absent / no-data semantics:** Default noDataState (Ok). No series means either no IA_NA address lease on this box (normal on a PD-only WAN) or the lease was cleanly removed.

**First checks:**
- Check the WAN DHCPv6 Client Messages panel: sent renew/request with no received reply means the upstream has gone quiet
- Check the valid-expiry countdown for how much time is actually left before it matters

**Likely causes:**
- The upstream DHCPv6 server has stopped responding to Renew/Request
- dhcp6c is wedged - it may still be sending without processing replies

**Verify recovery:**
- An address_lease_created or address_lease_updated event lands and the age drops back to near zero

## OPNsenseDHCP6AllocationFailures

**Severity:** warning  
**Pending window:** 30m0s  
**Rule name:** `opnsense-dhcp6-alloc-failures`

**Expression:**
```promql
sum by (reason, opnsense_instance) (rate(opnsense_log_events_dhcp6_alloc_fail_total[5m]))
```

**What it measures:** Rate of DHCPv6 allocation failures reported by kea-dhcp6, by reason. Counted once per failed allocation - kea emits up to three lines per failure sharing a tid, and only the cause line is counted.

**Threshold & window:** gt 0 on a 5m window, sustained for 30m. The pending period deliberately EXCEEDS the window (#594): a lone refusal keeps a rate window non-empty for the width of that window, so a pending period shorter than the window fires on a single event. Requiring every rolling 5m window to be non-empty for 30m straight means a real stuck pool fires while an occasional refusal does not.

**Absent / no-data semantics:** Default noDataState (Ok). No series means kea-dhcp6 has refused nothing, which is the normal state.

**First checks:**
- FIRST, establish whether the refusal was for an ADDRESS or a PREFIX - the metric cannot tell you, and the answer changes everything below. Capture a request: `tcpdump -i <lan-if> -n -vv "udp port 547"` and read whether the client SOLICIT carries IA_NA or IA_PD. An ADVERTISE answering with `IA_PD ... status-code NoPrefixAvail` is a prefix-delegation refusal
- Identify the client. Every kea alloc-fail line carries duid=[...]; the exporter ships it as the dhcp.duid attribute, so group the log events by it. A single DUID at a low steady cadence is usually a border router asking for a prefix, not a subnet full of denied clients
- reason=no_pools on an IA_PD request: the subnet has no pd-pools entry. Configure one (Services > Kea DHCP > DHCPv6, Prefix Delegation Pools) if the delegation is wanted, and be aware kea installs no route back to a delegated prefix. If it is not wanted, this is cosmetic
- reason=no_pools on an IA_NA request: check that the subnet the client is on actually has a v6 address pool defined - this one never resolves itself
- reason=exhausted: check pool utilisation against the lease count on the DHCP tab, and whether the lease time is long enough to be holding addresses for departed clients
- Check whether the failures correlate with the delegated prefix changing - a re-delegation invalidates the pool the old subnet was carved from

**Likely causes:**
- The v6 address pool is genuinely full
- No address pool is configured for the subnet or client class in question
- No pd-pools is configured and something on the LAN wants a delegated prefix - commonly a Thread border router or a downstream router. Benign if the delegation is not wanted; the client falls back to a self-generated ULA prefix
- The delegated prefix changed and the configured pools still reference the old one

**Verify recovery:**
- The failure rate returns to zero and clients obtain leases again
- For the IA_PD case, the client SOLICIT is answered with a prefix rather than NoPrefixAvail

## OPNsenseNetisrQueueDrops

**Severity:** warning  
**Pending window:** 10m0s  
**Rule name:** `opnsense-netisr-queue-drops`

**Expression:**
```promql
sum by (protocol, opnsense_instance) (rate(opnsense_network_diag_netisr_queue_drops_total[5m]))
```

**What it measures:** rate(opnsense_network_diag_netisr_queue_drops_total[5m]) - packets per second discarded by netisr because a workstream queue was full.

**Threshold & window:** gt 0 (any sustained drop rate) for 10m.

**Absent / no-data semantics:** Default noDataState (Ok). The network diagnostics collector is opt-in (--exporter.enable-network-diagnostics), so no series at all usually means the collector is off rather than that the box is healthy.

**First checks:**
- Read opnsense_network_diag_netisr_drop_concentration_ratio for this protocol FIRST. At or near 1.0 every drop is landing on ONE workstream, which is a CPU-affinity problem, not a queue-size problem
- Open the NetISR Per-CPU Distribution row and find which cpu is dropping - the per-CPU drops panel names it directly
- Compare opnsense_network_diag_netisr_active_workstreams against the box core count. Four active workstreams on a twelve-core box means netisr is only using a third of the machine
- Check the NetISR Protocol Policy table: a policy_type of "source" is single-lane by design and cannot spread, so one busy workstream there is expected
- Do NOT reach straight for net.isr.maxqlen. On the box that motivated this rule, ip6 dropped 683 packets entirely on cpu0 while cpu1-3 ran at roughly half their watermark and cpu4-11 were completely idle - raising the queue limit there would have masked an affinity problem rather than fixing it

**Likely causes:**
- netisr work is bound to a subset of CPUs - check net.isr.maxthreads and net.isr.bindthreads
- The NIC RSS / queue configuration is steering all traffic into one hardware queue and so onto one workstream
- cpu0 additionally carries interrupt and userland work the other cores do not, so it saturates first even with fewer packets queued
- A genuine traffic volume increase beyond what the configured queue depth absorbs

**Verify recovery:**
- The drop rate returns to zero and stays there for 10m
- drop_concentration_ratio and queue_imbalance_ratio both fall, showing work actually spread rather than the queue merely being enlarged

## OPNsenseNetisrQueueNearLimit

**Severity:** warning  
**Pending window:** 10m0s  
**Rule name:** `opnsense-netisr-queue-near-limit`

**Expression:**
```promql
(opnsense_network_diag_netisr_queue_watermark / (opnsense_network_diag_netisr_queue_limit > 0)) and (delta(opnsense_network_diag_netisr_queue_watermark[1h]) > 0)
```

**What it measures:** netisr_queue_watermark divided by netisr_queue_limit - how close the deepest queue occupancy since boot has come to the configured ceiling, evaluated only while the watermark is still climbing.

**Threshold & window:** gt 0.9 sustained for 10m, and only while the watermark rose within the last hour. The rising-edge guard (delta over 1h) is deliberate and must not be removed: the watermark is a since-boot HIGH-WATER MARK that never decays, so a bare ratio > 0.9 would latch on the first burst and alert continuously until the next reboot whether or not anything was still wrong. This is a deviation from the rule as originally proposed in #538, made because the metric it reads does not behave like a gauge.

**Absent / no-data semantics:** Default noDataState (Ok). The division guard means a protocol reporting limit=0 produces no series rather than a divide-by-zero artifact.

**First checks:**
- Identify the protocol and check whether its watermark is climbing steadily or jumped once during a traffic burst
- Check the per-CPU watermark panel: one workstream at the limit beside idle siblings is an affinity problem, all of them near the limit is genuine volume
- Confirm whether drops have started yet via OPNsenseNetisrQueueDrops

**Likely causes:**
- Rising traffic on the affected protocol is filling the queue faster than it drains
- netisr work concentrated on too few workstreams, so per-lane depth grows while total capacity sits unused
- A queue limit left at a default that is undersized for this box

**Verify recovery:**
- The ratio stops rising - the rising-edge guard clears the alert on its own once the watermark stops moving
- Per-CPU watermarks even out across active workstreams

## OPNsensePFStateTableNearLimit

**Severity:** warning  
**Pending window:** 10m0s  
**Rule name:** `opnsense-pf-states-near-limit`

**Expression:**
```promql
opnsense_firewall_pf_states_current / (opnsense_firewall_pf_states_limit > 0)
```

**What it measures:** opnsense_firewall_pf_states_current divided by opnsense_firewall_pf_states_limit - how full the pf state table is relative to its configured ceiling.

**Threshold & window:** gt 0.9 (over 90% full) sustained for 10m.

**Absent / no-data semantics:** Default noDataState (Ok) - the division guard means a box with no configured limit produces no series rather than a divide-by-zero artifact.

**First checks:**
- Check the Firewall & PF tab for which connection types/rules are consuming the most states
- Look for a sudden traffic spike (flood, misbehaving client, DDoS) versus a slow organic climb

**Likely causes:**
- A legitimate traffic surge is opening more concurrent connections than usual
- A flood/DDoS or a misbehaving internal host opening excessive connections
- The configured pf state-table limit is simply undersized for normal load

**Verify recovery:**
- The ratio drops back under 0.9 and stays there for 10m
- opnsense_firewall_pf_states_current stabilises at a sustainable level

## OPNsenseCPUStreamStalled

**Severity:** warning  
**Pending window:** 5m0s  
**Rule name:** `opnsense-cpu-stream-stalled`

**Expression:**
```promql
opnsense_cpu_stream_last_frame_age_seconds
```

**What it measures:** opnsense_cpu_stream_last_frame_age_seconds: seconds since the last CPU sample arrived over the SSE stream.

**Threshold & window:** gt 120 for 5m. Two minutes is well past the 10s stall watchdog and one full re-dial cycle, so an ordinary reconnect never fires this.

**Absent / no-data semantics:** Default noDataState (Ok) - the series is absent before the first frame ever arrives and on a box with --exporter.disable-cpu set.

**First checks:**
- Read opnsense_cpu_stream_up for the same instance: 0 means the exporter cannot establish the connection at all, 1 means it connected and the data stopped anyway
- Read rate(opnsense_cpu_stream_reconnects_total[5m]): a high rate means the connection is being established and torn down repeatedly rather than never established
- Check opnsense_up - a firewall that is wholly unreachable explains this and much else besides
- On the firewall, confirm lighttpd and configd are running and that php-cgi worker capacity is not exhausted (max-procs x PHP_FCGI_CHILDREN)

**Likely causes:**
- The firewall is rebooting or applying a firmware update, so there is nothing to reconnect to
- configd or the iostat process behind the stream has wedged
- php-cgi worker capacity on the firewall is exhausted, so the stream cannot be re-established
- The API credentials were revoked, so every re-dial is rejected

**Verify recovery:**
- opnsense_cpu_stream_last_frame_age_seconds drops back under a few seconds
- opnsense_cpu_stream_counters_published returns to 1 and the CPU Usage panel stops reading absent

## OPNsenseMemoryHigh

**Severity:** warning  
**Pending window:** 15m0s  
**Rule name:** `opnsense-memory-high`

**Expression:**
```promql
opnsense_system_memory_used_bytes / (opnsense_system_memory_total_bytes > 0)
```

**What it measures:** opnsense_system_memory_used_bytes divided by opnsense_system_memory_total_bytes - physical memory utilisation.

**Threshold & window:** gt 0.9 (over 90%) sustained for 15m.

**Absent / no-data semantics:** Default noDataState (Ok) - the division guard suppresses the series if total memory is unreported, rather than alerting on a meaningless ratio.

**First checks:**
- Check which process/service is consuming memory on the box directly (OPNsense UI System Activity, or SSH `top`)
- Look for a recently-added plugin or a runaway daemon rather than assuming a hardware limit

**Likely causes:**
- A plugin or service leaking memory over time
- The box is simply under-provisioned for its configured feature set (e.g. IDS/IPS rules, many VPN tunnels)

**Verify recovery:**
- The ratio drops back under 0.9 and stays there for 15m

## OPNsenseDiskUsageHigh

**Severity:** warning  
**Pending window:** 15m0s  
**Rule name:** `opnsense-disk-usage-high`

**Expression:**
```promql
opnsense_system_disk_usage_ratio
```

**What it measures:** opnsense_system_disk_usage_ratio for one mounted filesystem/device.

**Threshold & window:** gt 0.9 (over 90% full) sustained for 15m.

**Absent / no-data semantics:** Default noDataState (Ok) - absence means that mountpoint isn't reported (e.g. not present on this box), not that it's empty.

**First checks:**
- Read the mountpoint/device labels to identify which filesystem is filling up
- Check for oversized logs, config-backup history, or package caches on that mount

**Likely causes:**
- Log growth or a service writing excessively to that filesystem
- Accumulated firmware/package upgrade artifacts or config backups
- The mount is genuinely undersized for its role

**Verify recovery:**
- opnsense_system_disk_usage_ratio for that mountpoint drops back under 0.9

## OPNsenseHighTemperature

**Severity:** warning  
**Pending window:** 10m0s  
**Rule name:** `opnsense-high-temperature`

**Expression:**
```promql
opnsense_temperature_celsius
```

**What it measures:** opnsense_temperature_celsius for one hardware sensor (CPU, chassis, drive bay, etc).

**Threshold & window:** gt 85°C sustained for 10m.

**Absent / no-data semantics:** Default noDataState (Ok) - absence means that sensor isn't present/reported on this hardware, not that it has cooled.

**First checks:**
- Read the device label to identify which sensor is hot
- Check physical airflow/fan status and ambient conditions around the appliance

**Likely causes:**
- A failed or blocked chassis/CPU fan
- Blocked intake/exhaust airflow or high ambient temperature
- Sustained high CPU load driving thermal output up

**Verify recovery:**
- opnsense_temperature_celsius for that sensor drops back under 85°C and stays there

## OPNsenseSmartHealthFailed

**Severity:** critical  
**Pending window:** 5m0s  
**Rule name:** `opnsense-smart-failed`

**Expression:**
```promql
opnsense_smart_device_health
```

**What it measures:** opnsense_smart_device_health: the disk's own SMART overall-health self-assessment.

**Threshold & window:** lt 1 (FAILED) - any occurrence for 5m, since a SMART FAILED verdict is never transient noise worth waiting out.

**Absent / no-data semantics:** Default noDataState (Ok) - absence means SMART data isn't available for that device (e.g. a virtual disk), not that it passed.

**First checks:**
- Read the device/model labels and pull the full SMART report on the box (`smartctl -a`) for the specific failing attribute
- Check whether a backup/replacement disk is on hand before the drive fails outright

**Likely causes:**
- The physical disk is genuinely failing (reallocated sectors, pending sectors, etc.)
- A SMART firmware quirk on some controllers can occasionally misreport - cross-check with the raw attribute values before assuming imminent failure

**Verify recovery:**
- opnsense_smart_device_health returns to 1 only after replacing the drive (a genuine SMART FAILED verdict does not self-clear)

## OPNsenseFirmwareNeedsReboot

**Severity:** warning  
**Pending window:** 30m0s  
**Rule name:** `opnsense-firmware-needs-reboot`

**Expression:**
```promql
opnsense_firmware_needs_reboot
```

**What it measures:** opnsense_firmware_needs_reboot: whether a previously-applied firmware/package update is waiting on a reboot to take effect.

**Threshold & window:** gt 0 sustained for 30m (a deliberately long grace period, since this is rarely urgent).

**Absent / no-data semantics:** Default noDataState (Ok) - absence means no update is pending a reboot.

**First checks:**
- Check the OPNsense UI's firmware/updates page for exactly which update is pending
- Plan a maintenance window for the reboot rather than treating this as an emergency

**Likely causes:**
- A kernel, base-system, or driver update was applied and needs a reboot to load

**Verify recovery:**
- opnsense_firmware_needs_reboot returns to 0 after the reboot completes

## OPNsenseUpdateCheckFailing

**Severity:** warning  
**Pending window:** 60m0s  
**Rule name:** `opnsense-update-check-failing`

**Expression:**
```promql
opnsense_firmware_update_check_success
```

**What it measures:** opnsense_firmware_update_check_success: whether OPNsense's own STORED update check ran and succeeded (not a real-time mirror probe). opnsense_firmware_update_check_state says which half broke: connection (DNS/proxy/credentials) or repository (fingerprint/subscription/release train).

**Threshold & window:** lt 1 for 60m. This value is read through the exporter's firmware response cache (default 12h TTL), so a failure can take up to that long to appear and just as long to clear - the value stays constant across that window, so the 1h pending period filters scrape gaps and restarts rather than genuine mirror flapping.

**Absent / no-data semantics:** The series exists only once a check has been stored; a box that has never checked produces NoData and stays at the default Ok state instead of firing.

**First checks:**
- Read opnsense_firmware_update_check_state to know which half failed before digging further
- Manually trigger an update check in the OPNsense UI and read the actual error text
- Check DNS/proxy reachability to the OPNsense mirror, and subscription/fingerprint validity if the state points at the repository side

**Likely causes:**
- The configured mirror is unreachable (DNS, proxy, or network path)
- An expired subscription, revoked fingerprint, or unavailable release train

**Verify recovery:**
- opnsense_firmware_update_check_success returns to 1 (note: can take up to the firmware cache TTL to reflect a fix)

## OPNsenseCertificateExpiringSoon

**Severity:** warning  
**Pending window:** 0s  
**Rule name:** `opnsense-cert-expiring`

**Expression:**
```promql
(opnsense_certificate_valid_to_seconds - time()) / 86400
```

**What it measures:** Days until a certificate's notAfter time ((opnsense_certificate_valid_to_seconds - time()) / 86400).

**Threshold & window:** within_range [0, 14] - the certificate expires within the next 14 days (and has not already expired, which is covered by the critical rule below).

**Absent / no-data semantics:** Default noDataState (Ok) - absence means that certificate is no longer tracked (removed/replaced), not that it's safely far from expiry.

**First checks:**
- Read the commonname/description labels to identify the exact certificate
- Check whether it's ACME-managed (should auto-renew) or a manually-imported cert needing a manual renewal

**Likely causes:**
- A manually-managed certificate was never scheduled for renewal
- An ACME renewal is failing silently (check the ACME client's own log/status)

**Verify recovery:**
- The certificate's valid_to timestamp moves out past the 14-day window after renewal

## OPNsenseCertificateExpiringCritical

**Severity:** critical  
**Pending window:** 0s  
**Rule name:** `opnsense-cert-expiring-critical`

**Expression:**
```promql
(opnsense_certificate_valid_to_seconds - time()) / 86400
```

**What it measures:** The same days-until-expiry expression as OPNsenseCertificateExpiringSoon ((opnsense_certificate_valid_to_seconds - time()) / 86400).

**Threshold & window:** within_range [0, 3] - imminent expiry, escalated to critical severity because there is very little runway left to act.

**Absent / no-data semantics:** Default noDataState (Ok) - same reasoning as the warning-tier sibling: absence means the certificate is no longer tracked.

**First checks:**
- Read the commonname/description labels and confirm this is the same cert already flagged by OPNsenseCertificateExpiringSoon, or a newly-discovered one
- Renew or replace the certificate immediately - anything consuming it (web UI, VPN, reverse proxy) will start failing TLS validation at expiry

**Likely causes:**
- OPNsenseCertificateExpiringSoon's warning was missed or not actioned in time
- An ACME renewal has been failing for multiple cycles

**Verify recovery:**
- The certificate's valid_to timestamp moves out past the 3-day window
- Whatever service depends on the cert (UI, VPN, proxy) still presents a valid chain after renewal

## OPNsenseServiceDown

**Severity:** warning  
**Pending window:** 10m0s  
**Rule name:** `opnsense-service-down`

**Expression:**
```promql
opnsense_services_status{name!="iperf"}
```

**What it measures:** opnsense_services_status: whether a monitored OPNsense service is running (excludes on-demand services such as iperf, which are expected to be stopped between test runs).

**Threshold & window:** lt 1 (stopped) sustained for 10m. One alert instance per service.

**Absent / no-data semantics:** Default noDataState (Ok) - absence means that service is no longer configured/tracked, not that it's running.

**First checks:**
- Read the name/description labels to identify the exact service
- Check the OPNsense UI's Services page for the actual stop reason/crash log
- Try restarting it from the UI and watch whether it stays up or crash-loops

**Likely causes:**
- The service crashed and did not auto-restart
- A configuration error is preventing the service from starting
- A dependency (interface, another service, a plugin) it needs is unavailable

**Verify recovery:**
- opnsense_services_status for that service returns to 1 and stays there (not just a one-shot restart that crashes again)

## OPNsenseNTPPeerUnreachable

**Severity:** warning  
**Pending window:** 15m0s  
**Rule name:** `opnsense-ntp-unsynced`

**Expression:**
```promql
opnsense_ntp_peer_reach
```

**What it measures:** opnsense_ntp_peer_reach: whether NTP considers a specific configured time peer reachable.

**Threshold & window:** lt 1 sustained for 15m.

**Absent / no-data semantics:** Default noDataState (Ok) - absence means that peer is no longer configured, not that it's reachable.

**First checks:**
- Read the server label to identify the specific NTP peer
- Check outbound connectivity/firewall rules to that peer's address and port (UDP/123)
- Confirm the peer itself hasn't been decommissioned or renumbered upstream

**Likely causes:**
- The configured NTP peer is down or unreachable from this network
- A firewall rule change blocked outbound NTP
- DNS resolution for the peer's hostname is failing

**Verify recovery:**
- opnsense_ntp_peer_reach for that peer returns to 1

## OPNsenseUnboundDNSSECBogus

**Severity:** info  
**Pending window:** 0s  
**Rule name:** `opnsense-unbound-dnssec-bogus`

**Expression:**
```promql
sum by (opnsense_instance) (increase(opnsense_unbound_dns_answers_bogus_total[15m]))
```

**What it measures:** Count of DNSSEC-bogus DNS answers Unbound has returned in a rolling 15m window, summed by opnsense_instance.

**Threshold & window:** gt 5 bogus answers in 15m, for_min=0 - a genuine count-in-window threshold that fires immediately once exceeded (no persistence period needed, unlike the endpoint-error rule's #94 trap).

**Absent / no-data semantics:** Default noDataState (Ok) - no bogus answers is the normal, healthy state.

**First checks:**
- Check Unbound's own logs for which domain(s) are producing bogus DNSSEC validation
- Determine whether this correlates with a specific external resolver/domain misconfiguration versus active tampering on the network path

**Likely causes:**
- A misconfigured authoritative zone upstream (broken DNSSEC signing)
- Clock skew on the box breaking signature validity windows
- Active DNS tampering/spoofing on the network path (the case this alert exists to surface)

**Verify recovery:**
- The 15m rolling count of bogus answers returns to 0 or stays under the threshold

## OPNsenseLogShipSinkErrors

**Severity:** warning  
**Pending window:** 10m0s  
**Rule name:** `opnsense-logship-sink-errors`

**Expression:**
```promql
sum by (opnsense_instance) (rate(opnsense_exporter_logs_ship_errors_total[5m]))
```

**What it measures:** Rate of failed Emit attempts by the log-shipping sink (OTLP/Loki) over 5m, summed by opnsense_instance - retry/degradation activity, not proof that records were actually lost.

**Threshold & window:** gt 0 sustained for 10m.

**Absent / no-data semantics:** Default noDataState (Ok) - no errors means the sink is delivering cleanly.

**First checks:**
- Check connectivity/auth to the configured OTLP or Loki destination from the exporter's network path
- Check OPNsenseLogShipCountedLoss separately - this rule only proves retrying is happening, not that anything was actually dropped

**Likely causes:**
- The log-shipping destination (OTLP/Loki backend) is unreachable or rejecting requests
- Credentials for the destination expired or were rotated without updating the exporter

**Verify recovery:**
- The 5m error rate returns to 0 and stays there
- opnsense_exporter_logs_dropped_total stops incrementing for this instance

## OPNsenseLogShipQueueNearCapacity

**Severity:** warning  
**Pending window:** 5m0s  
**Rule name:** `opnsense-logship-queue-near-capacity`

**Expression:**
```promql
max by (opnsense_instance) (label_replace(avg_over_time(opnsense_exporter_logs_queue_length[5m]) / (opnsense_exporter_logs_queue_capacity > 0), "bound", "count", "__name__", ".*") or label_replace(avg_over_time(opnsense_exporter_logs_queue_bytes[5m]) / (opnsense_exporter_logs_queue_max_bytes > 0), "bound", "bytes", "__name__", ".*"))
```

**What it measures:** The higher of two ratios for the log-shipping backpressure queue: record-count occupancy (queue_length / queue_capacity) or byte occupancy where a byte budget is enabled (queue_bytes / queue_max_bytes), max'd by opnsense_instance. The numerator is a 5m AVERAGE, not the instantaneous depth - see the threshold note.

**Threshold & window:** gt 0.75 of whichever bound is enabled, on a 5m average, sustained for a further 5m. The numerator is averaged deliberately. An earlier version of this rule read the INSTANTANEOUS queue depth against a 0.9 threshold and it was structurally unable to fire: the emitter drains a whole batch at once, so occupancy sawtooths on roughly the batch period and almost never sits above a fixed line for 5 consecutive minutes. Measured over one week on a live box it went Normal->Pending 148 times and reached Alerting twice, while the queue was in fact overflowing and losing records the whole time. Averaging reads the sawtooth as the sustained pressure it actually is.

**Absent / no-data semantics:** Default noDataState (Ok) - the `> 0` guards mean an unconfigured bound produces no series for that half rather than a meaningless ratio.

**First checks:**
- Check the downstream sink's health first (OPNsenseLogShipSinkErrors) - a stalled destination is the most common reason the queue backs up
- Check the configured queue capacity/byte budget against current log volume

**Likely causes:**
- The log-shipping destination has slowed or stopped accepting records, so the queue is backing up behind it
- A sudden spike in log volume (e.g. a flood on a push source) is outrunning the configured queue bound

**Verify recovery:**
- The occupancy ratio drops back under 0.9 and stays there for 5m
- No overflow drops appear in OPNsenseLogShipCountedLoss immediately afterward

## OPNsenseLogShipCountedLoss

**Severity:** warning  
**Pending window:** 0s  
**Rule name:** `opnsense-logship-counted-loss`

**Expression:**
```promql
sum by (opnsense_instance, source, reason) (increase(opnsense_exporter_logs_dropped_total[15m]))
```

**What it measures:** Count of log records counted as lost in a rolling 15m window, grouped by the exact source and reason (overflow, record_too_large, rejected, ship_failed_permanent, ship_failed).

**Threshold & window:** gt 0 in 15m, for_min=0 - fires immediately, since any counted loss is worth knowing about.

**Absent / no-data semantics:** Default noDataState (Ok) - no loss events is the normal state.

**First checks:**
- Read the reason label first - it tells you which of five distinct failure modes occurred (queue-bound eviction, oversized record, destination refusal, retry exhaustion, or shutdown abandonment)
- Cross-check OPNsenseLogShipQueueNearCapacity and OPNsenseLogShipSinkErrors for the same window - overflow/ship_failed reasons usually correlate with one of those

**Likely causes:**
- overflow: the queue bound evicted the oldest record under sustained backpressure
- record_too_large: a single record exceeded the configured size limit
- rejected / ship_failed_permanent: the destination terminally refused it or retries were exhausted
- ship_failed: records were abandoned during shutdown

**Verify recovery:**
- The 15m rolling count for that source/reason returns to 0

## OPNsenseLogShipResourceCapped

**Severity:** warning  
**Pending window:** 0s  
**Rule name:** `opnsense-logship-resource-capped`

**Expression:**
```promql
sum by (opnsense_instance) (increase(opnsense_exporter_logs_resource_capped_total[15m]))
```

**What it measures:** Count of records shipped with their opnsense.* resource labels dropped in a rolling 15m window, summed by opnsense_instance.

**Threshold & window:** gt 0 in 15m, for_min=0.

**Absent / no-data semantics:** Default noDataState (Ok) - no capped records is the normal state.

**First checks:**
- Check whether label-scoped queries against recently-shipped log records are silently under-reporting for this instance
- Check the configured resource-attribute budget/limit on the log-shipping pipeline

**Likely causes:**
- The configured cap on resource attributes per record was hit under high label cardinality or volume

**Verify recovery:**
- The 15m rolling count of capped records returns to 0
- Newly-shipped records carry their full opnsense.* resource labels again

## OPNsenseLogShipCursorStalled

**Severity:** warning  
**Pending window:** 0s  
**Rule name:** `opnsense-logship-cursor-stalled`

**Expression:**
```promql
time() - max by (opnsense_instance, source) (opnsense_exporter_logs_last_exported_timestamp_seconds{source=~"syslog|zenarmor"})
```

**What it measures:** Seconds since the last exported event timestamp for a continuously-active push source, restricted to source=~"syslog|zenarmor" - both are always-on push feeds, so silence from either is itself the anomaly.

**Threshold & window:** gt 900s (15m) of silence, for_min=0.

**Absent / no-data semantics:** Default noDataState (Ok) - deliberately scoped to only the two always-active sources, so a legitimately quiet or unconfigured source (excluded from the query) cannot false-fire.

**First checks:**
- Confirm the source (syslog sender or Zenarmor) is still actually configured to push to the exporter
- Check the exporter's log-shipping receiver logs for connection resets or parse errors from that source
- Confirm the firewall/network path between the source and the exporter's receiver port hasn't changed

**Likely causes:**
- The syslog sender or Zenarmor was reconfigured/pointed elsewhere
- A network path or firewall rule change blocked the push
- The receiver itself hit an unhandled error and stopped accepting from that source

**Verify recovery:**
- opnsense_exporter_logs_last_exported_timestamp_seconds for that source starts advancing again

## OPNsenseOTLPDeliveryFailing

**Severity:** warning  
**Pending window:** 15m0s  
**Rule name:** `opnsense-otlp-delivery-failing`

**Expression:**
```promql
opnsense_exporter_otlp_consecutive_failures
```

**What it measures:** opnsense_exporter_otlp_consecutive_failures: how many OTLP metric export attempts have failed back-to-back, resetting to 0 on the next success - so ">0 sustained" means an ONGOING outage, including the never-worked-since-boot case a staleness rule can't see.

**Threshold & window:** gt 0 for 15m. At the default 60s export interval that's ~15 consecutive failed exports, so a single blip or a rolling restart of the collector endpoint does not fire.

**Absent / no-data semantics:** No dedicated nodata handling - this metric simply does not exist on a box with OTLP export disabled.

**First checks:**
- READ THIS FIRST: an exporter cannot ship its own failure metric through the path that is failing, so this signal CANNOT reach a pure-OTLP backend during the outage itself - it is for /metrics scrapers, the passive operator console, and post-recovery forensics only
- Read opnsense_exporter_otlp_last_success_timestamp_seconds: 0 means no export has EVER succeeded since startup (wrong endpoint or bad credential), a non-zero value gives the recovery timeline
- On a pure-OTLP backend, look for STALENESS of this exporter's own data at the backend as the in-band symptom instead of this rule

**Likely causes:**
- The configured OTLP endpoint is wrong or unreachable
- The OTLP credential/token is invalid or expired
- The OTLP collector/backend itself is down or rejecting exports

**Verify recovery:**
- opnsense_exporter_otlp_consecutive_failures returns to 0
- opnsense_exporter_otlp_last_success_timestamp_seconds advances to a recent time

## OPNsenseIPsecTunnelDown

**Severity:** warning  
**Pending window:** 10m0s  
**Rule name:** `opnsense-ipsec-tunnel-down`

**Expression:**
```promql
opnsense_ipsec_phase1_status
```

**What it measures:** opnsense_ipsec_phase1_status: whether a specific IPsec phase1 tunnel is connected. Catches a tunnel dropping while the strongSwan/racoon daemon itself keeps running, which OPNsenseServiceDown cannot see.

**Threshold & window:** lt 1 (down; connected=1) sustained for 10m.

**Absent / no-data semantics:** Default noDataState (Ok) - absence means that tunnel is no longer configured, not that it's connected.

**First checks:**
- Read the name/description labels to identify the specific tunnel
- Check the OPNsense UI's IPsec status page and the daemon's own log for the negotiation failure reason
- Confirm the remote peer's public IP/credentials haven't changed

**Likely causes:**
- The remote peer is unreachable or its public IP changed
- A pre-shared key or certificate mismatch after a credential rotation
- A phase1/phase2 proposal mismatch introduced by a config change on either side

**Verify recovery:**
- opnsense_ipsec_phase1_status for that tunnel returns to 1 (connected)
- Traffic is observably flowing across the tunnel again

## OPNsenseWireGuardPeerDown

**Severity:** warning  
**Pending window:** 10m0s  
**Rule name:** `opnsense-wireguard-peer-down`

**Expression:**
```promql
opnsense_wireguard_peer_status
```

**What it measures:** opnsense_wireguard_peer_status for one peer. Values are 1=up, 0=down, 2=unknown, 3=stale; this alert deliberately fires on 0 only.

**Threshold & window:** lt 1 sustained for 10m - matches 0 (down) only; 2 (unknown) and 3 (stale) are deliberately not alerted, since neither is the same claim as confirmed down.

**Absent / no-data semantics:** Default noDataState (Ok) - absence means that peer is no longer configured.

**First checks:**
- Read the peer_name/device_name labels to identify the specific peer and interface
- Check the peer's last-handshake time in the OPNsense UI - a peer stuck at 0 rather than cycling through 2/3 usually means the endpoint address is simply wrong or unreachable
- Confirm the peer's allowed-IPs and endpoint configuration haven't drifted from the remote side

**Likely causes:**
- The remote peer's network endpoint changed or became unreachable
- A key mismatch after a credential rotation on either side
- A firewall rule blocking the WireGuard UDP port

**Verify recovery:**
- opnsense_wireguard_peer_status for that peer returns to 1 (up)
- The peer's last-handshake timestamp is recent

## OPNsenseHASyncUnreachable

**Severity:** warning  
**Pending window:** 10m0s  
**Rule name:** `opnsense-hasync-unreachable`

**Expression:**
```promql
opnsense_hasync_remote_reachable == 0 and on(opnsense_instance) (opnsense_hasync_remote_services_total > 0)
```

**What it measures:** opnsense_hasync_remote_reachable, guarded to only fire on boxes where HA sync is actually configured (opnsense_hasync_remote_services_total > 0) - reachable=0 on an unconfigured box is the normal, expected reading and is deliberately excluded.

**Threshold & window:** lt 1 sustained for 10m, on a box where HA sync is configured.

**Absent / no-data semantics:** Default noDataState (Ok) - absence means HA sync isn't configured on this box at all, which the guard already treats as non-alertable.

**First checks:**
- Confirm the HA peer box is actually up and reachable on the network from this instance
- Check the configured HA sync IP/interface for a recent change on either side
- Check the OPNsense UI's HA Sync status page for the specific connection error

**Likely causes:**
- The HA peer firewall is down or unreachable
- A network path change (interface, VLAN, firewall rule) broke the sync link
- HA sync credentials were rotated on one box but not the other

**Verify recovery:**
- opnsense_hasync_remote_reachable returns to 1
- Config changes on the primary are observed to sync to the peer again

## OPNsenseCARPVIPFault

**Severity:** warning  
**Pending window:** 5m0s  
**Rule name:** `opnsense-carp-vip-fault`

**Expression:**
```promql
(opnsense_carp_vip_status != 3) unless on(opnsense_instance) (opnsense_carp_maintenance_mode == 1)
```

**What it measures:** opnsense_carp_vip_status for one VIP/interface. Values: 1=MASTER, 0=BACKUP (both normal, inside [0,1]), 2=INIT, 3=DISABLED, -1=unknown. Suppressed while opnsense_carp_maintenance_mode is 1 (deliberate maintenance).

**Threshold & window:** outside_range [0, 1] sustained for 5m - fires on INIT(2)/unknown(-1) only. BACKUP is healthy and never fires; DISABLED(3) is administrative and is filtered out of the series before the threshold is applied.

**Absent / no-data semantics:** Default noDataState (Ok) - absence means that VIP/interface is no longer configured.

**First checks:**
- Read the vip/interface labels to identify the exact VIP in fault
- Check opnsense_carp_maintenance_mode for this instance - if it's 1, this is intentional and won't fire (if you're seeing this alert, maintenance mode is NOT the cause)
- Check OPNsenseCARPStateFlapping for recent transition history on the same interface/vhid

**Likely causes:**
- The CARP peer relationship is broken (pfsync misconfigured, network partition between nodes)
- The interface the VIP is bound to went down
- A VHID/advertising-frequency conflict with another device on the same broadcast domain

**Verify recovery:**
- opnsense_carp_vip_status for that VIP returns to 0 or 1 (BACKUP or MASTER)

## OPNsenseCARPStateFlapping

**Severity:** warning  
**Pending window:** 0s  
**Rule name:** `opnsense-carp-state-flapping`

**Expression:**
```promql
sum by (opnsense_instance, interface, vhid) (increase(opnsense_log_events_carp_total{event="state_changed"}[15m]))
```

**What it measures:** Count of CARP state_changed transitions for one interface+vhid pair in a rolling 15m window, from shipped syslog events - a TRANSITION signal complementing OPNsenseCARPVIPFault's current-state gauge, grouped by vhid AND interface since a vhid is only unique within an interface.

**Threshold & window:** gt 3 (four or more changes) in 15m, for_min=0. A boot sequence is two changes (INIT->BACKUP->MASTER) and a single failover is one, so this threshold sits above one planned event with margin. Deliberately DIFFERENT from the dpinger sibling's >2 threshold - the two event shapes aren't comparable, don't tune them to match.

**Absent / no-data semantics:** Default noDataState (Ok) - no state_changed events in the window is the normal, quiet state.

**First checks:**
- Read carp.reason on the shipped log records for the kernel's own stated cause
- Check OPNsenseCARPVIPFault and the CARP VIP Status panel for where the VIP actually sits now - this alert is transition evidence, not a current-state claim

**Likely causes:**
- An unstable network path between HA peers causing repeated MASTER/BACKUP transitions
- A pfsync/CARP advertisement misconfiguration
- Genuine repeated hardware/service disruptions on one node

**Verify recovery:**
- No further state_changed events for that vhid/interface in the next 15m window
- opnsense_carp_vip_status for the VIP settles at a stable value

## OPNsenseCARPUnexpectedDemotion

**Severity:** warning  
**Pending window:** 0s  
**Rule name:** `opnsense-carp-unexpected-demotion`

**Expression:**
```promql
sum by (opnsense_instance) (increase(opnsense_log_events_carp_total{event="demoted"}[15m]))
```

**What it measures:** Count of positive CARP demotion adjustments (event="demoted") for the instance in a rolling 15m window, from shipped syslog events - a node stepping back from its willingness to be master.

**Threshold & window:** gt 3 (four or more) in 15m, for_min=0. DO NOT tighten to >0: one pfsync bulk-transfer cycle is one demoted plus one promoted event, ROUTINE operation (the #405 capture recorded 11 pairs on a healthy cluster) - a threshold of >0 would page on normal behaviour and train people to ignore the alert.

**Absent / no-data semantics:** Default noDataState (Ok) - no demoted events in the window is the normal, quiet state.

**First checks:**
- Read carp.reason, carp.demotion.delta, and carp.demotion.total on the shipped log records for the kernel's own stated cause and the resulting demotion level - none of these are metric labels
- Compare opnsense_carp_demotion for the current level, and look for the matching promoted event that releases the demotion
- Check for repeated pfsync bulk transfers, a flapping interface, or an actual service disruption on this node

**Likely causes:**
- Repeated pfsync bulk transfers (each one demotes and promotes once - only churn, four or more cycles in 15m, is the actual signal)
- A service disruption on this node
- A flapping interface causing repeated CARP re-evaluation

**Verify recovery:**
- No further demoted events in the next 15m window
- opnsense_carp_demotion returns to its baseline level

## OPNsenseIDSAlertSpike

**Severity:** info  
**Pending window:** 5m0s  
**Rule name:** `opnsense-ids-alert-spike`

**Expression:**
```promql
sum by (opnsense_instance) (opnsense_ids_recent_alerts{action="blocked"})
```

**What it measures:** Count of currently-held blocked-action IDS alerts in the recent-alerts window, summed by opnsense_instance. action is only ever allowed/blocked (no drop/reject values exist).

**Threshold & window:** gt 50 for 5m. Both the threshold and --exporter.ids-alert-lookback window are deployment-specific - tune per site.

**Absent / no-data semantics:** Default noDataState (Ok) - a quiet IDS is the normal state.

**First checks:**
- Open the IDS/IPS tab to see which signature(s)/source IPs are driving the spike
- Check whether this correlates with a known scan, a new malicious campaign, or a misbehaving internal host being flagged repeatedly

**Likely causes:**
- An active scan or attack against the firewall's public-facing services
- A misconfigured or compromised internal host triggering repeated egress alerts
- A signature update introducing a burst of (possibly false-positive) matches

**Verify recovery:**
- The blocked-alert count in the lookback window drops back under 50

## OPNsenseFlowCorrelatorEvicting

**Severity:** warning  
**Pending window:** 15m0s  
**Rule name:** `opnsense-flow-correlator-evicting`

**Expression:**
```promql
sum by (opnsense_instance) (rate(opnsense_flow_correlator_evicted_total[5m]))
```

**What it measures:** Rate of forced-eviction of flow-correlator entries over 5m, summed by opnsense_instance - the correlate window can no longer be held under current flow volume. No bytes are lost (the oldest entry is force-emitted, not dropped).

**Threshold & window:** gt 0 sustained for 15m.

**Absent / no-data semantics:** Default noDataState (Ok) - no eviction is the normal state.

**First checks:**
- Check current flow volume/cardinality (Flow Volume tab on the operational dashboard, Flow Pipeline tab on the health dashboard) against --flow.correlate.max-entries
- Confirm nothing is generating an unusual number of concurrent flows (scan, flood, a chatty new service)

**Likely causes:**
- --flow.correlate.max-entries is set too low for current flow volume
- A traffic pattern change (more concurrent connections) increased pressure on the correlate accumulator

**Verify recovery:**
- The eviction rate returns to 0 and stays there for 15m
- Raising --flow.correlate.max-entries (if that was the cause) removes the eviction pressure

## OPNsenseFlowLogsTruncated

**Severity:** warning  
**Pending window:** 10m0s  
**Rule name:** `opnsense-flow-logs-truncated`

**Expression:**
```promql
sum by (opnsense_instance) (rate(opnsense_flow_logs_truncated_total[5m]))
```

**What it measures:** Rate of flow log records dropped by the --flow.max-logs-per-window budget over 5m, summed by opnsense_instance. Metrics themselves are never truncated, only per-flow LOGS.

**Threshold & window:** gt 0 sustained for 10m.

**Absent / no-data semantics:** Default noDataState (Ok) - no truncation is the normal state.

**First checks:**
- Check whether this is expected volume (raise --flow.max-logs-per-window) or a flood on the unauthenticated NetFlow ingress
- Check --flow.netflow.allowed-peers if a flood from an unexpected source looks likely

**Likely causes:**
- Genuinely high flow volume exceeding the configured per-window log budget
- A flood on the unauthenticated NetFlow ingress from an unexpected/unrestricted peer

**Verify recovery:**
- The truncation rate returns to 0
- Per-flow log completeness is restored (no further gaps on the health dashboard's Flow Pipeline tab)

## OPNsenseFlowGeoIPDatabaseStale

**Severity:** warning  
**Pending window:** 60m0s  
**Rule name:** `opnsense-flow-geoip-database-stale`

**Expression:**
```promql
max by (opnsense_instance, database) (time() - opnsense_flow_geoip_database_build_timestamp_seconds)
```

**What it measures:** Age in seconds of the loaded GeoIP database, per database (country, asn), against MaxMind's own BUILD date rather than the download time - a re-download of the same build correctly does NOT reset it.

**Threshold & window:** gt 3888000s (45d), for_min=60. Raised from 14d by #549: the image now ships DB-IP Lite, which republishes MONTHLY, so 14d would fire on a healthy stock deployment for half of every month. 45d clears a ~31d publish interval plus refresh lag for every database the exporter can load.

**Absent / no-data semantics:** Default noDataState (Ok). The gauge is omitted entirely for a database that is not loaded (a zero would read as "built in 1970" and fire permanently), so a deployment with --geoip.enabled off has no series here and cannot false-fire.

**First checks:**
- Check opnsense_flow_geoip_downloads_total: a rising result="failure" rate is a fetch problem, while a flat counter with --geoip.download.enabled set means the updater goroutine is not running at all
- With the built-in downloader: verify the MaxMind license key has not expired and that the exporter has egress to download.maxmind.com
- With operator-managed files: confirm the geoipupdate cron / sidecar is still running and writing to the configured --geoip.country-database and --geoip.asn-database paths
- On a stock deployment using the database bundled in the image, no updater exists to fix - the image is what is old, so pull a current one
- Check opnsense_flow_geoip_reloads_total for result="failure" - a corrupt replacement leaves the OLD database serving, which looks exactly like no update at all
- Confirm the download directory is persistent: a volume lost on restart re-downloads every start and can exhaust the daily limit

**Likely causes:**
- MaxMind license key expired or the account was disabled
- Egress to download.maxmind.com blocked, or the daily download limit exhausted
- A geoipupdate cron / sidecar stopped running, or its output path no longer matches the exporter configuration
- A corrupt or truncated replacement file that fails to parse, leaving the previous database serving indefinitely
- A stock deployment running an image that has not been pulled for over 45 days, so the bundled DB-IP Lite copy is simply as old as the image

**Verify recovery:**
- opnsense_flow_geoip_database_build_timestamp_seconds advances to a recent build
- opnsense_flow_geoip_downloads_total{result="updated"} increments once, then settles back to result="unmodified"

## OPNsenseNetFlowHookDead

**Severity:** warning  
**Pending window:** 5m0s  
**Rule name:** `opnsense-netflow-hook-dead`

**Expression:**
```promql
max by (opnsense_instance, interface, device) (
  (opnsense_netflow_capture_expected == 1)
    * on (opnsense_instance, interface) group_left (device) opnsense_flow_interface_info
)
and on (opnsense_instance, device) max by (opnsense_instance, device) (
  label_join(increase(opnsense_netflow_cache_packets_total[45m]), "device", "", "interface") == 0
)
and on (opnsense_instance, device) max by (opnsense_instance, device) (
  label_join(increase(opnsense_firewall_in_ipv4_pass_bytes_total[45m]), "device", "", "interface") > 0
)
and on (opnsense_instance) (opnsense_netflow_capture_active_timeout_seconds < 2700)
unless on (opnsense_instance, interface) (opnsense_flow_interface_capture_unsupported == 1)
```

**What it measures:** A five-clause join proving a specific NetFlow capture hook has gone silent while pf still passes traffic on the same kernel device - the #368 dead-hook failure mode, where ng_netflow accepted a bogus hook and silently captured nothing. PPPoE interfaces, where that is permanent and unfixable (ng_netflow attaches to mpd's framing node, not the ng_iface node ng_pppoe exposes), are excluded by clause 5 rather than reported forever.

**Threshold & window:** gt 0 for 5m. Clause 1 restricts to interfaces actually configured for capture; clause 2 checks the interface's OWN ng_netflow cache node recorded zero packets in 45m; clause 3 confirms pf actually passed bytes on the same device in that window (telling a dead hook from a legitimately idle interface); clause 4 withdraws the whole query unless the box's own configured NetFlow active timeout is at least the 45m observation window; clause 5 drops any interface whose device can never capture at all (opnsense_flow_interface_capture_unsupported), which is every PPPoE WAN.

**Absent / no-data semantics:** Default noDataState (Ok) - a healthy hook, an interface not configured for capture, a PPPoE interface (clause 5, permanently incapable), or a box whose active timeout is shorter than 45m (clause 4's honesty guard) all produce no series here, which is the intended quiet state.

**First checks:**
- Check opnsense_netflow_capture_active_timeout_seconds FIRST if you believe a hook is dead but this never fires - a box with a shorter active timeout is structurally excluded by clause 4
- Open the operator console's NetFlow/ifIndex tab and confirm the device label is a real ng_netflow node with `ngctl list` on the box
- Read docs/flow.md ('Joining the two label spaces') for the full query derivation before changing this rule

**Likely causes:**
- The capture hook was bound to the wrong kernel device (e.g. a PPPoE interface's framing node rather than its actual ng_iface) - the #368 pattern
- The ng_netflow hook was silently dropped by a reconfiguration and never rebound

**Verify recovery:**
- opnsense_netflow_cache_packets_total for the device resumes counting - the alert resolves automatically once it does

## Recording rules

Precomputed PromQL expressions following the `instance:opnsense_<subsystem>_<measurement>:<op>` naming convention. These are plain recording rules with no alerting semantics of their own - they exist to keep a common aggregation/ratio computed once for dashboards and other rules to reuse.

### instance:opnsense_interface_rx_bits:rate5m

```promql
sum by (opnsense_instance, interface) (rate(opnsense_interfaces_received_bytes_total[5m])) * 8
```

### instance:opnsense_interface_tx_bits:rate5m

```promql
sum by (opnsense_instance, interface) (rate(opnsense_interfaces_transmitted_bytes_total[5m])) * 8
```

### instance:opnsense_firewall_block_packets:rate5m

```promql
sum by (opnsense_instance, interface) (rate(opnsense_firewall_in_ipv4_block_packets_total[5m]) + rate(opnsense_firewall_out_ipv4_block_packets_total[5m]) + rate(opnsense_firewall_in_ipv6_block_packets_total[5m]) + rate(opnsense_firewall_out_ipv6_block_packets_total[5m]))
```

### instance:opnsense_pf_state:utilization

```promql
opnsense_firewall_pf_states_current / (opnsense_firewall_pf_states_limit > 0)
```

### instance:opnsense_unbound_cache:hit_ratio

```promql
rate(opnsense_unbound_dns_cache_hits_total[5m]) / (rate(opnsense_unbound_dns_cache_hits_total[5m]) + rate(opnsense_unbound_dns_cache_miss_total[5m]) > 0)
```

### instance:opnsense_unbound_queries:rate5m

```promql
rate(opnsense_unbound_dns_queries_total[5m])
```

### instance:opnsense_gateway_loss:ratio

```promql
opnsense_gateways_loss_percentage / 100
```

### instance:opnsense_system_mem:utilization

```promql
opnsense_system_memory_used_bytes / (opnsense_system_memory_total_bytes > 0)
```

### instance:opnsense_zenarmor_block:ratio5m

```promql
sum by (opnsense_instance) (rate(opnsense_log_events_zenarmor_total{action="block"}[5m])) / (sum by (opnsense_instance) (rate(opnsense_log_events_zenarmor_total[5m])) > 0)
```

### instance:opnsense_haproxy_5xx:ratio5m

```promql
sum by (opnsense_instance, backend) (rate(opnsense_log_events_haproxy_total{status_class="5xx"}[5m])) / (sum by (opnsense_instance, backend) (rate(opnsense_log_events_haproxy_total[5m])) > 0)
```

### instance:opnsense_ipsec_tunnels_down:count

```promql
sum by (opnsense_instance) (opnsense_ipsec_phase1_status == bool 0)
```

### instance:opnsense_wireguard_peers_down:count

```promql
sum by (opnsense_instance) (opnsense_wireguard_peer_status == bool 0)
```

### instance:opnsense_ids_alerts:active

```promql
sum by (opnsense_instance) (opnsense_ids_recent_alerts{action="blocked"})
```

### instance:opnsense_flow_bytes:rate5m

```promql
sum by (opnsense_instance, interface, direction) (rate(opnsense_flow_bytes_total{source="netflow"}[5m]))
```
