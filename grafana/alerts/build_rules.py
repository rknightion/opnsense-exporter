#!/usr/bin/env python3
"""
Single-source builder for OPNsense exporter alert + recording rules.

Rules are defined once (RULES / RECORDING below) and emitted as Grafana-managed manifests:

  * `grafana-managed/*.json`         — Grafana-managed `rules.alerting.grafana.app/v0alpha1`
                                       AlertRule / RecordingRule manifests (+ a folder),
                                       pushable with `gcx resources push`. Use `--stack` to add
                                       an IRM label contract (domain/page) for routed alerting.

Grafana-managed alerting is the only supported format: it carries `noDataState` (so the
exporter-down/NoData case actually fires) and Grafana templating (`$values`), neither of which
a portable Prometheus rule-group file can express. A previously-shipped portable
`opnsense.rules.yaml` was dropped for this reason.

Usage:
    python3 build_rules.py                       # generic labels
    python3 build_rules.py --stack               # add domain=infra (+page on critical)
    python3 build_rules.py --datasource <uid>    # datasource UID (default grafanacloud-prom)
    python3 build_rules.py --folder <name>       # grafana folder (default opnsense-alerts)

Alerts are defined as a value-producing query `A` plus a threshold condition, rendered to the
Grafana A→C query/threshold node pipeline.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
GRAFANA_DIR = os.path.dirname(HERE)
RUNBOOKS_MD_PATH = os.path.join(GRAFANA_DIR, "runbooks.md")
# The runbook URL is shared with the dashboard's own "Alert runbooks" link (#419):
# one registry, so an alert notification and the dashboard can never point at two
# different pages. `runbook_url()` builds the PER-RULE anchor into runbooks.md (#430).
sys.path.insert(0, os.path.dirname(HERE))
from uids import RUNBOOK_URL, runbook_url  # noqa: E402

# #430: every alert's summary should identify WHICH box fired when the query can carry
# opnsense_instance at all - a bare "gateway X is down" is ambiguous the moment more
# than one firewall is scraped. This is the documented exception list (style matches
# grafana/annotations.py's NOT_ANNOTATED): a rule goes here only when its own source
# metric structurally cannot carry the label, never as a shortcut to skip writing it in.
SUMMARY_INSTANCE_EXEMPT = {
    "opnsense-otlp-delivery-failing":
        "opnsense_exporter_otlp_consecutive_failures is a bare process-wide "
        "prometheus.Gauge registered directly against telemetry.Start's raw registry "
        "(internal/telemetry/delivery.go:77), never wrapped by logship.SelfMetricsRegisterer "
        "the way opnsense_exporter_logs_* is (internal/logship/pipeline.go:88-89) - so it "
        "carries no opnsense_instance label to put in the summary at all. This is the same "
        "identity gap #466 tracks for the OTLP dashboard panels; fixing the summary would "
        "require the same registry-wrapping fix as that issue, not a runbook-side change.",
}

# Each alert: name(slug), title, A (value query), cond (op, params), for_min, severity,
# summary, description. op in {gt, lt, within_range, outside_range}.
RULES = [
    dict(name="opnsense-exporter-down", title="OPNsenseExporterDown",
         A="opnsense_up", op="lt", params=[1, 0], for_min=15, severity="critical",
         nodata="Alerting",
         summary="OPNsense exporter/box down ({{ $labels.opnsense_instance }})",
         description="opnsense_up has been 0 (the OPNsense API was unreachable / the scrape failed) "
                     "or the target produced NoData for 15m. opnsense_up reflects API reachability ONLY - "
                     "a reachable box reporting a degraded subsystem (e.g. a crash report) stays up=1 and is "
                     "covered by the lower-severity OPNsenseCrashReports / OPNsenseFirewallUnhealthy alerts, "
                     "so this critical/page fires on genuine unreachability only. The 15m window tolerates a "
                     "router reboot (typically <10m) without paging.",
         runbook=dict(
             measures="opnsense_up: whether the exporter's most recent poll of the OPNsense system-status API succeeded at all. It is reachability-only - a reachable box self-reporting a degraded subsystem stays at 1.",
             threshold='lt 1 for 15m. The 15m window is sized to ride out a normal reboot (typically <10m) without paging.',
             absent="noDataState is Alerting - a totally-missing series (the whole fleet gone) pages immediately here. A SINGLE instance disappearing while others keep reporting is Grafana's MissingSeries case instead, which this rule structurally cannot see; OPNsenseExporterInstanceMissing exists to catch that.",
             checks=[
                'Check the Prometheus Targets page for this scrape target before assuming the firewall itself is down - it may be a network path or scrape-config problem',
                'Read opnsense_system_status_code and the crash-reporter/firewall-status gauges for the same instance - if those are non-zero the box is reachable but sick, a different alert',
                'Reach the OPNsense box directly (console/SSH) to tell a full outage from an API-only fault',
            ],
             causes=[
                'The OPNsense box is powered off, rebooting past the 15m grace window, or unreachable over the network',
                'The OPNsense API credentials were revoked/expired or the API service crashed',
                'The exporter process itself died or lost its network path to the firewall',
            ],
             verify=[
                'opnsense_up reads 1 again on the next scrape for the named instance',
                "No further NoData gap appears on the Overview tab's Exporter/API panels for at least one full scrape interval",
            ],
         )),
    # #427. The rule above cannot detect a PARTIAL fleet loss, and the reason is a
    # Grafana distinction that is easy to miss:
    #
    #   No Data      - the query returns no series AT ALL. noDataState governs it,
    #                  which is why the rule above sets Alerting: total loss pages.
    #   MissingSeries - the query still returns series, but one dimension has gone.
    #                  Grafana retains that alert instance briefly, then EVICTS it as
    #                  stale. It never passes through noDataState.
    #
    # So with edge-a and edge-b, losing edge-a entirely leaves opnsense_up{edge-b}
    # returning happily; the edge-a instance is quietly evicted and nothing pages.
    # A bare `opnsense_up` cannot detect its own absence — a series that does not
    # exist cannot match a selector. Something has to assert what SHOULD be there.
    #
    # present_over_time gives one series per instance that reported at any point in
    # the lookback; `unless` removes the ones still reporting. What survives is
    # exactly the set that has vanished, still labelled with opnsense_instance so the
    # page can name the box.
    #
    # The baseline is HISTORICAL, not a configured inventory. That is a deliberate
    # trade: it is self-contained (nothing to maintain, a new exporter protects
    # itself the moment it has been up an hour) at the cost of alerting for up to the
    # lookback after a planned decommission. One hour is short enough to wait out and
    # long enough to survive a slow reboot, a Prometheus restart, or a brief scrape
    # outage without a false page. A configured expected-instance list would avoid
    # the decommission noise but silently protects nothing when someone forgets to
    # add a box — failing open on the exact event this rule exists to catch.
    #
    # noDataState stays Ok on purpose: when the whole fleet disappears THIS query
    # returns nothing too, and OPNsenseExporterDown already pages for that. Alerting
    # here would double-page one event.
    #
    # The `max by (opnsense_instance)` is load-bearing, not tidiness. present_over_time
    # yields one series per distinct LABEL SET, not per instance, so any label churn
    # inside the lookback — a version label changing, a relabel, a scrape-config edit —
    # leaves several historical series for one box. Without the aggregation a single
    # missing exporter would raise one alert instance per historical label set, paging
    # repeatedly for one event. Verified live 2026-07-27: the raw form returned two
    # series for the one real instance, differing only by a service_version label that
    # had been removed earlier that day (#472).
    dict(name="opnsense-exporter-instance-missing", title="OPNsenseExporterInstanceMissing",
         A="max by (opnsense_instance) (present_over_time(opnsense_up[1h])) "
           "unless on(opnsense_instance) opnsense_up",
         op="gt", params=[0, 0], for_min=10, severity="critical",
         summary="OPNsense exporter {{ $labels.opnsense_instance }} has stopped reporting",
         description="opnsense_up reported for {{ $labels.opnsense_instance }} at some point in the last "
                     "1h and is now absent entirely, while at least one other exporter is still "
                     "reporting. That is Grafana's MissingSeries case, NOT NoData: the vanished alert "
                     "instance is evicted as stale rather than passing through noDataState, so "
                     "OPNsenseExporterDown cannot see it. Causes: the exporter process died, its host "
                     "went away, or Prometheus stopped scraping that target — note this fires when the "
                     "series is GONE, whereas OPNsenseExporterDown fires when the exporter is alive and "
                     "reporting opnsense_up=0. Check the scrape target's health first, then the "
                     "exporter process. If the instance was decommissioned deliberately, this "
                     "self-resolves once it has been absent for 1h; silence it until then.",
         runbook=dict(
             measures='Compares a 1h present_over_time baseline of opnsense_up against what is reporting right now, `unless`-subtracting instances still present - what survives is exactly the set that has vanished while at least one other instance keeps reporting.',
             threshold='gt 0 for 10m. The 1h lookback is a historical baseline, not a configured inventory: self-protecting for a new exporter once it has been up an hour, at the cost of alerting for up to that hour after a deliberate decommission.',
             absent='noDataState is Ok on purpose: if the WHOLE fleet disappears this query also returns nothing, and OPNsenseExporterDown already pages for that case - alerting here too would double-page one event.',
             checks=[
                'Read the firing opnsense_instance label and check whether that scrape target still exists in Prometheus service discovery',
                'Check whether that instance was deliberately decommissioned - if so, silence it rather than chase it',
                'Look for a label change on that instance in the last hour (version bump, relabel, scrape-config edit) - a changed label set can itself look like a vanished instance (#472)',
            ],
             causes=[
                'The exporter process for that instance was stopped or its host decommissioned',
                'The exporter crashed or its host went down unexpectedly',
                'Prometheus stopped scraping that target (dropped from service discovery, firewall rule, DNS failure)',
            ],
             verify=[
                "The named instance's opnsense_up series is present and back at 1 on the next scrape",
                'The instance no longer appears as a firing alert instance after one more evaluation cycle',
            ],
         )),
    dict(name="opnsense-firewall-unhealthy", title="OPNsenseFirewallUnhealthy",
         A="opnsense_firewall_status", op="lt", params=[1, 0], for_min=10, severity="warning",
         summary="OPNsense firewall health check failing ({{ $labels.opnsense_instance }})",
         description="opnsense_firewall_status has reported 0 (errors) for 10m.",
         runbook=dict(
             measures="opnsense_firewall_status, the firewall subsystem's own entry in OPNsense's combined system-status payload (the same API call opnsense_up is derived from).",
             threshold='lt 1 (0 = errors reported) sustained for 10m.',
             absent='Default noDataState (Ok). Because this comes from the same status call as opnsense_up, a total absence here usually means the whole status API is unreachable - which OPNsenseExporterDown already covers - rather than an independent signal to alert on.',
             checks=[
                'Check opnsense_system_status_code and opnsense_crash_reporter_status for the same instance - OPNsense reports these as one combined payload',
                "Open the OPNsense UI's own Dashboard status widget for the actual subsystem error text, which this gauge cannot carry",
                'Confirm opnsense_up is still 1 - if it is 0 too, this is a symptom of full unreachability, not an independent firewall fault',
            ],
             causes=[
                'A firewall ruleset failed to apply or reload cleanly',
                'pf itself is reporting an internal error state',
                'A subsystem that rolls up into firewall health (e.g. Suricata/IDS) broke',
            ],
             verify=[
                'opnsense_firewall_status returns to 1',
                "The OPNsense UI's own status widget for this subsystem shows OK/green",
            ],
         )),
    dict(name="opnsense-crash-reports", title="OPNsenseCrashReports",
         A="opnsense_crash_reporter_status", op="lt", params=[1, 0], for_min=5, severity="warning",
         summary="OPNsense crash reports present ({{ $labels.opnsense_instance }})",
         description="opnsense_crash_reporter_status is 0 — one or more crash reports are present.",
         runbook=dict(
             measures="opnsense_crash_reporter_status: whether OPNsense's own crash-report collector has one or more unreviewed crash reports on disk.",
             threshold='lt 1 (0 = reports present) sustained for 5m.',
             absent='Default noDataState (Ok) - absence means the status API itself is down, covered by OPNsenseExporterDown, not that crash reports are clear.',
             checks=[
                "Open the OPNsense UI's crash reporter page to read the actual report(s), which the gauge cannot carry",
                'Check whether the crash coincides with a recent firmware/plugin update',
                'Confirm opnsense_up is 1 - this fires independently of reachability, on a box that is otherwise healthy',
            ],
             causes=[
                "A daemon or kernel module crashed and OPNsense's monitor captured a core/report",
                'A plugin update introduced a regression',
            ],
             verify=[
                'The crash report is reviewed and cleared in the OPNsense UI',
                'opnsense_crash_reporter_status returns to 1 and no new report appears after clearing it',
            ],
         )),
    # #218: the root filesystem "diskspace" health-check subsystem, surfaced by the generic
    # opnsense_system_subsystem_status_code gauge (no dedicated gauge for this one). OPNsense
    # omits a healthy subsystem from the payload entirely, so the series is ABSENT (not 0/OK)
    # on a healthy box — noDataState is deliberately left at the default "Ok" (see nodata=
    # default below) rather than "Alerting", unlike opnsense-exporter-down.
    dict(name="opnsense-disk-space-low", title="OPNsenseDiskSpaceLow",
         A='opnsense_system_subsystem_status_code{subsystem="diskspace"}', op="lt", params=[2, 0],
         for_min=10, severity="warning",
         summary="OPNsense root filesystem disk space low ({{ $labels.opnsense_instance }})",
         description="opnsense_system_subsystem_status_code{subsystem=\"diskspace\"} has reported below OK "
                     "(2 = OK, 1 = NOTICE, 0 = WARNING nearly full, -1 = ERROR critically full) for 10m. "
                     "Absent means healthy — OPNsense omits an OK subsystem from the health-check payload.",
         runbook=dict(
             measures='opnsense_system_subsystem_status_code{subsystem="diskspace"}, OPNsense\'s own root filesystem health-check subsystem (2=OK, 1=NOTICE, 0=WARNING nearly full, -1=ERROR critically full).',
             threshold='lt 2 (below OK) sustained for 10m.',
             absent='Absent means healthy on purpose - OPNsense omits an OK subsystem from the health-check payload entirely rather than emitting a 2, so noDataState is deliberately left at the default Ok.',
             checks=[
                'Check actual root filesystem usage on the box (`df -h /`) rather than relying on the coarse 4-value gauge',
                'Look for a runaway log, a stuck package cache, or a full config-backup history filling the root partition',
            ],
             causes=[
                'Log rotation is misconfigured or a service is logging excessively',
                'Firmware/package upgrade left old files uncleaned',
                'The root partition is simply undersized for the installed plugin set',
            ],
             verify=[
                'The subsystem key disappears from the payload again (return to the healthy, absent-means-OK state) or reads 2',
                '`df -h /` on the box shows headroom restored',
            ],
         )),
    # The alert-condition window MUST be short (2m) so the long for:15m actually measures how long
    # errors PERSIST. If the window equals for (both 15m), increase()>0 stays true for 15m after the
    # last error, so for:15m is satisfied by any burst spanning >1 eval interval and the alert fires
    # ~15m AFTER recovery (#94). With a 2m window, an 8m error burst keeps the condition true only
    # ~t=0..10m (<15m) → for:15m never elapses → no false page; genuinely sustained errors keep every
    # rolling 2m window non-empty, so the condition stays true past 15m and the alert fires.
    dict(name="opnsense-endpoint-errors", title="OPNsenseEndpointErrors",
         A="sum by (opnsense_instance, endpoint) (increase(opnsense_exporter_endpoint_errors_total[2m]))",
         op="gt", params=[0, 0], for_min=15, severity="warning",
         summary="OPNsense exporter endpoint errors on {{ $labels.endpoint }} ({{ $labels.opnsense_instance }})",
         description="The {{ $labels.endpoint }} API endpoint has produced errors sustained for 15m "
                     "(at least one error in every rolling 2m window for the full 15m). A brief router "
                     "reboot / WAN blip empties the 2m window well before 15m elapses, so it does not fire. "
                     "One alert per endpoint. SCOPE (#382): this rule is the FAST/MEDIUM-tier signal and "
                     "the one that names the failing endpoint. It structurally cannot fire for a collector "
                     "on the slow (5m) or cold (15m) poll tier, because such a collector increments the "
                     "counter only once per tier and the 2m window is empty in between, resetting the 15m "
                     "pending clock every eval. Widening the window to cover those tiers would reintroduce "
                     "the #94 false page (a window as long as `for` keeps the condition true for a full "
                     "window after recovery), so the window is deliberately left at 2m and every tier is "
                     "covered instead by OPNsenseCollectorDataStale, which is driven by the data clock and "
                     "scales its tolerance with each collector's own interval.",
         runbook=dict(
             measures='Per-endpoint count of opnsense_exporter_endpoint_errors_total increases in rolling 2m windows, summed by opnsense_instance and endpoint - a FAST/MEDIUM-tier signal that names which API call is failing.',
             threshold="gt 0 for 15m, with a deliberately short 2m inner window: a burst under ~10m clears the 2m window before the 15m pending period elapses, so a router reboot doesn't false-page (#94), while genuinely sustained errors keep every rolling 2m window non-empty.",
             absent='Default noDataState (Ok) - no errors means no series, which is the healthy state, not an outage signal.',
             checks=[
                'Read the endpoint label to know exactly which OPNsense API call is failing',
                "Check the exporter's own logs for the HTTP status/error body from that endpoint",
                'Confirm the API key/secret still has permission for that endpoint, and that any gating plugin is still installed',
            ],
             causes=[
                'An API key was revoked or its permissions narrowed',
                'The relevant OPNsense plugin was removed or is misbehaving',
                'OPNsense itself returned malformed or unexpected data for that endpoint',
            ],
             verify=[
                'The 2m rolling increase() for that endpoint returns to 0 and stays there',
                'opnsense_exporter_scrape_collector_success for the owning collector reads 1 again',
            ],
         )),
    # ---- tier-aware collector staleness (#382) -------------------------------------
    # Error-aware retention (#336 D8) keeps a collector's last-good metrics when a poll
    # fails with nothing to emit. That is deliberate and stays. What was missing was any
    # alertable expression of how OLD the retained data is: last_poll_timestamp advances
    # on every failed attempt, so it can never express staleness.
    #
    # Shape, shared by the two rules below:
    #
    #   (time() - <data clock> - 120) / opnsense_exporter_collector_poll_interval_seconds
    #
    # i.e. staleness measured in MISSED POLL INTERVALS, not a fixed window — the whole
    # point, since the tiers span 15s to 15m. Vector matching is left at the default
    # (all labels bar __name__): both series are emitted from the same collector with an
    # identical {collector, opnsense_instance} label set, so the pairing is exactly 1:1
    # and stays correct with several exporters scraped for one opnsense_instance, which
    # an explicit on(...) would turn into a many-to-many error.
    #
    # The 120s subtracted is SCRAPE-LAG ALLOWANCE and is load-bearing on the fast tier.
    # The gauge is read from the most recent scrape sample, so at eval time the computed
    # age already includes up to one scrape interval of sample staleness on top of one
    # poll interval. Without the allowance a perfectly healthy 15s-tier collector reads
    # (15 + 60) / 15 = 5 missed intervals on a 60s scrape and would fire constantly.
    #
    # Worked tolerance at threshold 3, with a 60s scrape:
    #
    #   tier          healthy peak   one transient failure   persistent failure fires at
    #   fast   15s    ~0.0           ~0.0                    age 165s   (+5m for → ~8m)
    #   medium 60s    0.0            1.0                     age 300s   (+5m for → ~10m)
    #   slow    5m    0.8            1.8                     age 1020s  (+5m for → ~22m)
    #   cold   15m    0.9            1.9                     age 2820s  (+5m for → ~52m)
    #
    # So a persistent slow-tier AND a persistent cold-tier failure both fire (which
    # OPNsenseEndpointErrors cannot do), while a single failed poll followed by recovery
    # peaks at ~2 missed intervals on every tier and never reaches the threshold.
    # Unlike an increase()-window rule this expression is monotone while the fault
    # persists, so the pending clock never resets between two once-per-tier attempts.
    dict(name="opnsense-collector-data-stale", title="OPNsenseCollectorDataStale",
         A="(time() - opnsense_exporter_collector_snapshot_timestamp_seconds - 120) "
           "/ opnsense_exporter_collector_poll_interval_seconds",
         op="gt", params=[3, 0], for_min=5, severity="warning",
         summary="OPNsense collector {{ $labels.collector }} is serving stale data ({{ $labels.opnsense_instance }})",
         description="Collector {{ $labels.collector }} has not replaced its stored metric buffer for more "
                     "than 3 of its own poll intervals ({{ $values.A.Value | printf \"%.1f\" }} missed "
                     "intervals and counting), so every scrape and every OTLP export is replaying retained "
                     "last-good values of that age. Tolerance is expressed in MISSED INTERVALS, so it "
                     "scales with the collector's tier (fast 15s / medium 60s / slow 5m / cold 15m, or a "
                     "--collector.poll-interval-override): 3 missed intervals plus a 120s scrape-lag "
                     "allowance plus the 5m pending period, which is ~8m on the fast tier and ~52m on the "
                     "cold tier. One failed poll followed by recovery peaks at ~2 missed intervals and "
                     "cannot fire. The data is NOT blanked — retention is deliberate (#336 D8) — so the "
                     "dashboard still shows values; they are just old. Check "
                     "opnsense_exporter_scrape_collector_success and the endpoint-error panels for the "
                     "cause. NOTE the last-poll clock is useless here: it advances on every failed attempt "
                     "too (#382).",
         runbook=dict(
             measures="How many of a collector's own poll intervals have elapsed since its stored metric buffer was last replaced (time() minus the snapshot timestamp, minus a 120s scrape-lag allowance, divided by the collector's own poll interval) - staleness expressed in MISSED INTERVALS so one rule covers every tier.",
             threshold='gt 3 missed intervals for 5m, which works out to roughly 8m on the fast (15s) tier and 52m on the cold (15m) tier; one failed poll followed by recovery peaks at ~2 missed intervals on any tier and cannot fire.',
             absent='Both feeding gauges are absent until first successfully stored, so a collector that has NEVER stored data produces no series here and cannot alert on staleness - that gap is what OPNsenseCollectorNeverStoredData exists to close.',
             checks=[
                'Read the collector label and check opnsense_exporter_scrape_collector_success and the endpoint-error panels for that same collector',
                "Note the last-poll-timestamp panel is USELESS here - it advances on every failed attempt too, so don't use it to judge freshness",
                "Confirm the dashboard's stale value is old but not blanked - retained last-good data is deliberate (#336 D8), so a flat panel does not mean the outage just started",
            ],
             causes=[
                "The collector's endpoint started erroring on every attempt",
                'A plugin the collector depends on was removed or disabled',
                'The firewall itself stopped exposing that data (feature disabled, subsystem down)',
            ],
             verify=[
                'The missed-interval expression drops back under 3 and stays there for at least one poll interval',
                'opnsense_exporter_collector_snapshot_timestamp_seconds advances again on schedule',
            ],
         )),
    # Second clock: fully-clean success. A collector whose primary endpoint works and
    # whose secondary endpoint errors every time keeps REPLACING its buffer with partial
    # data, so snapshot age stays low and the rule above correctly stays silent — but
    # part of its metric set has been silently missing the whole time. The `unless`
    # suppresses this rule for anything already alerting as fully stale, so a total
    # outage pages once rather than twice; set-operator matching is pinned explicitly to
    # (opnsense_instance, collector) since both sides are arithmetic results.
    # Tolerance is looser (6 missed intervals) and severity lower: data IS still
    # refreshing, so this is a degradation, not a freeze.
    dict(name="opnsense-collector-degraded", title="OPNsenseCollectorDegraded",
         A="((time() - opnsense_exporter_collector_last_success_timestamp_seconds - 120) "
           "/ opnsense_exporter_collector_poll_interval_seconds) "
           "unless on(opnsense_instance, collector) "
           "(((time() - opnsense_exporter_collector_snapshot_timestamp_seconds - 120) "
           "/ opnsense_exporter_collector_poll_interval_seconds) > 3)",
         op="gt", params=[6, 0], for_min=10, severity="info",
         summary="OPNsense collector {{ $labels.collector }} has not fully succeeded ({{ $labels.opnsense_instance }})",
         description="Collector {{ $labels.collector }} is still refreshing its stored metrics, but no "
                     "poll has completed CLEANLY for more than 6 of its own poll intervals "
                     "({{ $values.A.Value | printf \"%.1f\" }} missed intervals). That is the "
                     "persistent-partial-failure signature: one endpoint of a multi-endpoint collector "
                     "erroring every poll while the rest keep updating, so part of its metric set is "
                     "silently absent or frozen while everything looks fresh. Tolerance is in MISSED "
                     "INTERVALS so it scales with the collector's tier, and the rule deliberately excludes "
                     "collectors already covered by OPNsenseCollectorDataStale (fully frozen data), which "
                     "would otherwise fire both. Severity is info, not warning: data is still flowing, and "
                     "the endpoint-error panels name the failing endpoint (#382).",
         runbook=dict(
             measures='The same missed-interval-age expression as OPNsenseCollectorDataStale, but built from opnsense_exporter_collector_last_success_timestamp_seconds (last fully CLEAN poll) rather than the snapshot timestamp, with an `unless` clause suppressing anything already covered by that fully-stale rule.',
             threshold='gt 6 missed intervals for 10m - looser than the 3-interval stale threshold, because the collector IS still refreshing partial data; this is degradation, not a freeze.',
             absent='No dedicated nodata handling (default Ok) - same absent-until-first-store gap as OPNsenseCollectorDataStale.',
             checks=[
                'Read the collector label and check its endpoint-error panels - the classic shape is one endpoint of a multi-endpoint collector erroring every poll while the rest keep updating',
                'Confirm this collector is NOT also firing OPNsenseCollectorDataStale - if it is, treat that as the primary signal',
                'Check whether a specific sub-feature (not the whole collector) is missing from its metrics on the dashboard',
            ],
             causes=[
                'One endpoint of a multi-endpoint collector is failing every poll while its sibling endpoints keep succeeding',
                "A specific plugin sub-feature was disabled or lost permission while the rest of the collector's data source stayed healthy",
            ],
             verify=[
                'The missed-interval expression built from last_success drops back under 6',
                'The endpoint-error panel for the previously-failing endpoint returns to zero increase',
            ],
         )),
    # The two rules above are absent-tolerant by construction — both new gauges are
    # absent until first set, so a collector that has NEVER stored data produces no
    # series and cannot alert on staleness. That is the one blind spot they leave and
    # this rule closes it: a collector that has completed at least one attempt (the
    # last-poll clock exists) but has never once stored a buffer has failed every poll
    # since the exporter started, which is the wrong-credential / plugin-missing /
    # broken-endpoint-from-boot case. The scheduler polls each collector immediately at
    # startup (after up to 5s jitter), so last_poll appears within seconds on every
    # tier, making a fixed 30m pending period safe here rather than tier-scaled.
    dict(name="opnsense-collector-never-stored", title="OPNsenseCollectorNeverStoredData",
         A="opnsense_exporter_collector_last_poll_timestamp_seconds "
           "unless on(opnsense_instance, collector) "
           "opnsense_exporter_collector_snapshot_timestamp_seconds",
         op="gt", params=[0, 0], for_min=30, severity="warning",
         summary="OPNsense collector {{ $labels.collector }} has never returned data ({{ $labels.opnsense_instance }})",
         description="Collector {{ $labels.collector }} has been polling for 30m and has never once stored "
                     "a metric buffer — every poll since the exporter started has failed with nothing to "
                     "emit, so it exports no domain metrics at all. A clean poll that legitimately finds "
                     "nothing still counts as stored, so this is a real failure, not an empty subsystem. "
                     "OPNsenseCollectorDataStale cannot cover this: the snapshot-timestamp gauge is absent "
                     "until the first successful store (deliberately, so it never renders as a 1970 "
                     "epoch), leaving no series to measure staleness against. Usual causes are a missing "
                     "plugin, an API key without permission for that endpoint, or a collector enabled "
                     "against a firewall that does not run the subsystem (#382).",
         runbook=dict(
             measures='opnsense_exporter_collector_last_poll_timestamp_seconds present (the scheduler has attempted this collector) `unless` opnsense_exporter_collector_snapshot_timestamp_seconds present (it has ever stored a buffer) - what survives is a collector that has attempted every poll since startup and succeeded at none of them.',
             threshold="gt 0 for 30m. The scheduler polls every collector within seconds of startup (up to 5s jitter), so 30m is a fixed pending period safe on every tier, not one scaled to the collector's own interval.",
             absent='No dedicated nodata handling - a collector that has never even attempted a poll (the left-hand gauge itself absent) produces no series here, which is expected during the first seconds after startup.',
             checks=[
                'Read the collector label and check whether its required OPNsense plugin is installed',
                "Confirm the API key has permission for that collector's endpoint(s)",
                "Check whether this collector is even applicable to this firewall (e.g. a collector enabled against a box that doesn't run the subsystem)",
            ],
             causes=[
                'A missing OPNsense plugin the collector depends on',
                "An API key without permission for that collector's endpoint",
                'The collector enabled against a firewall that does not run the relevant subsystem at all',
            ],
             verify=[
                'opnsense_exporter_collector_snapshot_timestamp_seconds appears for the first time for that collector',
                "The collector's own metrics start appearing on its dashboard tab",
            ],
         )),
    # Split primary vs failover: the default (primary) WAN reconverges in <1m after a reboot, so it
    # keeps a tight for=5m + critical/page. A secondary/failover WAN can take ~7-10m to re-establish
    # (DHCP + dpinger convergence) after a reboot, so it gets for=15m + warning (no page) to avoid
    # false pages during reboots. Requires the default_gateway label (opnsense-exporter >=0.x).
    dict(name="opnsense-gateway-down", title="OPNsenseGatewayDown",
         A='opnsense_gateways_status{default_gateway="true"}', op="lt", params=[1, 0], for_min=5, severity="critical",
         summary="OPNsense PRIMARY gateway {{ $labels.name }} is offline ({{ $labels.opnsense_instance }})",
         description="Primary WAN gateway {{ $labels.name }} ({{ $labels.address }}) offline (status 0) for 5m.",
         runbook=dict(
             measures='opnsense_gateways_status{default_gateway="true"}: the API-reported up/down state of the box\'s PRIMARY WAN gateway.',
             threshold='lt 1 (down) for 5m - tight, because the primary WAN typically reconverges in under a minute after a reboot.',
             absent='Default noDataState (Ok) - a totally-absent series means the exporter itself is down (OPNsenseExporterDown already pages for that); it does not fire for gateways with OPNsense-side monitoring disabled, which legitimately have no status series.',
             checks=[
                'Read the name/address labels to identify the specific gateway',
                "Check OPNsense's own Gateway status widget and dpinger logs for the same gateway",
                'Confirm whether the upstream ISP link itself is down vs. a local interface/dpinger fault',
            ],
             causes=[
                'The upstream ISP circuit is down',
                'A local WAN interface (physical link, PPPoE session, DHCP lease) failed',
                'dpinger itself stopped monitoring the gateway',
            ],
             verify=[
                'opnsense_gateways_status for that gateway returns to 1',
                'Traffic is observably flowing again on the interface (rx/tx byte-rate panels moving)',
            ],
         )),
    dict(name="opnsense-gw-down-failover", title="OPNsenseGatewayDownFailover",
         A='opnsense_gateways_status{default_gateway="false"}', op="lt", params=[1, 0], for_min=15, severity="warning",
         summary="OPNsense FAILOVER gateway {{ $labels.name }} is offline ({{ $labels.opnsense_instance }})",
         description="Failover/secondary WAN gateway {{ $labels.name }} ({{ $labels.address }}) offline (status 0) for 15m. "
                     "Lower urgency — primary WAN unaffected. The 15m window tolerates a router reboot / slow secondary-WAN re-establish.",
         runbook=dict(
             measures='opnsense_gateways_status{default_gateway="false"}: the same up/down state, for a failover/secondary WAN gateway rather than the primary.',
             threshold="lt 1 (down) for 15m - looser than the primary's 5m, because a secondary WAN can legitimately take ~7-10m to re-establish (DHCP + dpinger convergence) after a reboot.",
             absent='Default noDataState (Ok), same reasoning as OPNsenseGatewayDown: absence is the gateway lacking OPNsense-side monitoring, not a fault.',
             checks=[
                'Read the name/address labels to identify the specific secondary gateway',
                'Confirm the primary gateway is still up (this is lower urgency precisely because it is)',
                "Check OPNsense's Gateway status widget for the secondary's own convergence state",
            ],
             causes=[
                'The secondary ISP circuit or interface is down',
                'The secondary WAN is still mid-convergence after a reboot (should self-clear within the 15m window if so)',
            ],
             verify=[
                'opnsense_gateways_status for that gateway returns to 1',
                'Failover routing (if in use) reports the secondary as available again',
            ],
         )),
    # #405: a dpinger alarm is a transition event, not a replacement for the
    # current-state gateway collector. Count the starts per gateway; a strict >2
    # threshold is three or more starts in this fixed 15-minute observation window.
    dict(name="opnsense-gateway-alarm-flapping", title="OPNsenseGatewayAlarmFlapping",
         A='sum by (opnsense_instance, gateway) '
           '(increase(opnsense_log_events_gateway_total{event="alarm_started"}[15m]))',
         op="gt", params=[2, 0], for_min=0, severity="warning",
         summary="OPNsense gateway {{ $labels.gateway }} alarm is flapping ({{ $labels.opnsense_instance }})",
         description="dpinger emitted three or more alarm_started transitions for gateway {{ $labels.gateway }} in 15m. "
                     "This is transition evidence from syslog, not an assertion that the gateway is currently down; check OPNsenseGatewayDown and the Gateway Status panel for current state.",
         runbook=dict(
             measures='Count of dpinger alarm_started transitions for one gateway in a 15m window, from shipped syslog events - a TRANSITION signal, not a current-state assertion.',
             threshold='gt 2 (three or more starts) in the fixed 15m observation window, for_min=0 so it fires the instant the count is exceeded.',
             absent='Default noDataState (Ok) - no alarm_started events in the window is the normal, quiet state.',
             checks=[
                "Check OPNsenseGatewayDown/OPNsenseGatewayDownFailover and the Gateway Status panel for this gateway's CURRENT state - this alert only proves instability happened, not that the gateway is down now",
                "Look at the gateway's RTT/loss panels over the same 15m window for a pattern (intermittent vs. one-off)",
            ],
             causes=[
                'An unstable upstream link (flapping DSL/cable/PPPoE session)',
                "dpinger's monitor target itself is intermittently unreachable",
                'Congestion or a misconfigured latency/loss threshold making dpinger over-sensitive',
            ],
             verify=[
                'No further alarm_started events for the gateway in the next 15m window',
                "The gateway's current status gauge stays at 1 (up) for a sustained period",
            ],
         )),
    dict(name="opnsense-gateway-high-loss", title="OPNsenseGatewayHighLoss",
         A="opnsense_gateways_loss_percentage", op="gt", params=[20, 0], for_min=10, severity="warning",
         summary="OPNsense gateway {{ $labels.name }} high packet loss ({{ $labels.opnsense_instance }})",
         description="Gateway {{ $labels.name }} packet loss > 20% for 10m (current {{ $values.A.Value | printf \"%.1f\" }}%).",
         runbook=dict(
             measures="opnsense_gateways_loss_percentage: dpinger's measured packet loss to the gateway's monitor target.",
             threshold='gt 20% sustained for 10m.',
             absent='Default noDataState (Ok) - absence means the gateway has no dpinger loss data (e.g. monitoring disabled), not that loss is zero.',
             checks=[
                "Read the name label and check the gateway's RTT panel alongside this one for a combined latency/loss picture",
                'Check whether this coincides with an OPNsenseGatewayAlarmFlapping firing for the same gateway',
                'Rule out local congestion (interface error/drop counters) before blaming the upstream link',
            ],
             causes=[
                'Upstream ISP link degradation or congestion',
                'A flapping or marginal physical/PPPoE connection',
                "Local interface saturation causing dpinger's own probes to be dropped",
            ],
             verify=[
                'opnsense_gateways_loss_percentage drops back under 20% and stays there for 10m',
            ],
         )),
    dict(name="opnsense-gateway-high-rtt", title="OPNsenseGatewayHighRTT",
         A="opnsense_gateways_rtt_milliseconds / (opnsense_gateways_rtt_high_milliseconds > 0)",
         op="gt", params=[1, 0], for_min=10, severity="warning",
         summary="OPNsense gateway {{ $labels.name }} RTT over its high threshold ({{ $labels.opnsense_instance }})",
         description="Gateway {{ $labels.name }} mean RTT has exceeded its configured high-latency threshold for 10m.",
         runbook=dict(
             measures="opnsense_gateways_rtt_milliseconds divided by the gateway's own configured high-latency threshold (opnsense_gateways_rtt_high_milliseconds) - a ratio over 1 means the gateway has crossed ITS OWN configured threshold, not a fixed global one.",
             threshold='gt 1 (over its own configured high-RTT threshold) sustained for 10m.',
             absent='Default noDataState (Ok) - the division guard (`> 0`) means a gateway with no configured high threshold produces no series, deliberately, rather than firing on a meaningless comparison.',
             checks=[
                "Read the name label and check the gateway's loss panel for a combined picture",
                "Check the gateway's configured high-RTT threshold value itself in OPNsense - it may need retuning rather than the link being genuinely unhealthy",
            ],
             causes=[
                'Upstream network congestion or a route change adding latency',
                "The configured high-RTT threshold is tighter than the link's normal baseline",
            ],
             verify=[
                'The ratio drops back to 1 or below and stays there for 10m',
            ],
         )),
    dict(name="opnsense-pf-states-near-limit", title="OPNsensePFStateTableNearLimit",
         A="opnsense_firewall_pf_states_current / (opnsense_firewall_pf_states_limit > 0)",
         op="gt", params=[0.9, 0], for_min=10, severity="warning",
         summary="OPNsense PF state table near its limit ({{ $labels.opnsense_instance }})",
         description="PF state table is over 90% of its configured limit for 10m.",
         runbook=dict(
             measures='opnsense_firewall_pf_states_current divided by opnsense_firewall_pf_states_limit - how full the pf state table is relative to its configured ceiling.',
             threshold='gt 0.9 (over 90% full) sustained for 10m.',
             absent='Default noDataState (Ok) - the division guard means a box with no configured limit produces no series rather than a divide-by-zero artifact.',
             checks=[
                'Check the Firewall & PF tab for which connection types/rules are consuming the most states',
                'Look for a sudden traffic spike (flood, misbehaving client, DDoS) versus a slow organic climb',
            ],
             causes=[
                'A legitimate traffic surge is opening more concurrent connections than usual',
                'A flood/DDoS or a misbehaving internal host opening excessive connections',
                'The configured pf state-table limit is simply undersized for normal load',
            ],
             verify=[
                'The ratio drops back under 0.9 and stays there for 10m',
                'opnsense_firewall_pf_states_current stabilises at a sustainable level',
            ],
         )),
    dict(name="opnsense-memory-high", title="OPNsenseMemoryHigh",
         A="opnsense_system_memory_used_bytes / (opnsense_system_memory_total_bytes > 0)",
         op="gt", params=[0.9, 0], for_min=15, severity="warning",
         summary="OPNsense memory usage high ({{ $labels.opnsense_instance }})",
         description="Physical memory usage has been above 90% for 15m.",
         runbook=dict(
             measures='opnsense_system_memory_used_bytes divided by opnsense_system_memory_total_bytes - physical memory utilisation.',
             threshold='gt 0.9 (over 90%) sustained for 15m.',
             absent='Default noDataState (Ok) - the division guard suppresses the series if total memory is unreported, rather than alerting on a meaningless ratio.',
             checks=[
                'Check which process/service is consuming memory on the box directly (OPNsense UI System Activity, or SSH `top`)',
                'Look for a recently-added plugin or a runaway daemon rather than assuming a hardware limit',
            ],
             causes=[
                'A plugin or service leaking memory over time',
                'The box is simply under-provisioned for its configured feature set (e.g. IDS/IPS rules, many VPN tunnels)',
            ],
             verify=[
                'The ratio drops back under 0.9 and stays there for 15m',
            ],
         )),
    dict(name="opnsense-disk-usage-high", title="OPNsenseDiskUsageHigh",
         A="opnsense_system_disk_usage_ratio", op="gt", params=[0.9, 0], for_min=15, severity="warning",
         summary="OPNsense disk {{ $labels.mountpoint }} almost full ({{ $labels.opnsense_instance }})",
         description="Filesystem {{ $labels.mountpoint }} ({{ $labels.device }}) usage above 90% for 15m.",
         runbook=dict(
             measures='opnsense_system_disk_usage_ratio for one mounted filesystem/device.',
             threshold='gt 0.9 (over 90% full) sustained for 15m.',
             absent="Default noDataState (Ok) - absence means that mountpoint isn't reported (e.g. not present on this box), not that it's empty.",
             checks=[
                'Read the mountpoint/device labels to identify which filesystem is filling up',
                'Check for oversized logs, config-backup history, or package caches on that mount',
            ],
             causes=[
                'Log growth or a service writing excessively to that filesystem',
                'Accumulated firmware/package upgrade artifacts or config backups',
                'The mount is genuinely undersized for its role',
            ],
             verify=[
                'opnsense_system_disk_usage_ratio for that mountpoint drops back under 0.9',
            ],
         )),
    dict(name="opnsense-high-temperature", title="OPNsenseHighTemperature",
         A="opnsense_temperature_celsius", op="gt", params=[85, 0], for_min=10, severity="warning",
         summary="OPNsense sensor {{ $labels.device }} hot ({{ $labels.opnsense_instance }})",
         description="Temperature sensor {{ $labels.device }} above 85°C for 10m.",
         runbook=dict(
             measures='opnsense_temperature_celsius for one hardware sensor (CPU, chassis, drive bay, etc).',
             threshold='gt 85°C sustained for 10m.',
             absent="Default noDataState (Ok) - absence means that sensor isn't present/reported on this hardware, not that it has cooled.",
             checks=[
                'Read the device label to identify which sensor is hot',
                'Check physical airflow/fan status and ambient conditions around the appliance',
            ],
             causes=[
                'A failed or blocked chassis/CPU fan',
                'Blocked intake/exhaust airflow or high ambient temperature',
                'Sustained high CPU load driving thermal output up',
            ],
             verify=[
                'opnsense_temperature_celsius for that sensor drops back under 85°C and stays there',
            ],
         )),
    dict(name="opnsense-smart-failed", title="OPNsenseSmartHealthFailed",
         A="opnsense_smart_device_health", op="lt", params=[1, 0], for_min=5, severity="critical",
         summary="OPNsense SMART health failed on {{ $labels.device }} ({{ $labels.opnsense_instance }})",
         description="SMART overall-health for {{ $labels.device }} ({{ $labels.model }}) reports FAILED.",
         runbook=dict(
             measures="opnsense_smart_device_health: the disk's own SMART overall-health self-assessment.",
             threshold='lt 1 (FAILED) - any occurrence for 5m, since a SMART FAILED verdict is never transient noise worth waiting out.',
             absent="Default noDataState (Ok) - absence means SMART data isn't available for that device (e.g. a virtual disk), not that it passed.",
             checks=[
                'Read the device/model labels and pull the full SMART report on the box (`smartctl -a`) for the specific failing attribute',
                'Check whether a backup/replacement disk is on hand before the drive fails outright',
            ],
             causes=[
                'The physical disk is genuinely failing (reallocated sectors, pending sectors, etc.)',
                'A SMART firmware quirk on some controllers can occasionally misreport - cross-check with the raw attribute values before assuming imminent failure',
            ],
             verify=[
                'opnsense_smart_device_health returns to 1 only after replacing the drive (a genuine SMART FAILED verdict does not self-clear)',
            ],
         )),
    dict(name="opnsense-firmware-needs-reboot", title="OPNsenseFirmwareNeedsReboot",
         A="opnsense_firmware_needs_reboot", op="gt", params=[0, 0], for_min=30, severity="warning",
         summary="OPNsense needs a reboot ({{ $labels.opnsense_instance }})",
         description="A firmware update flagged that OPNsense needs a reboot.",
         runbook=dict(
             measures='opnsense_firmware_needs_reboot: whether a previously-applied firmware/package update is waiting on a reboot to take effect.',
             threshold='gt 0 sustained for 30m (a deliberately long grace period, since this is rarely urgent).',
             absent='Default noDataState (Ok) - absence means no update is pending a reboot.',
             checks=[
                "Check the OPNsense UI's firmware/updates page for exactly which update is pending",
                'Plan a maintenance window for the reboot rather than treating this as an emergency',
            ],
             causes=[
                'A kernel, base-system, or driver update was applied and needs a reboot to load',
            ],
             verify=[
                'opnsense_firmware_needs_reboot returns to 0 after the reboot completes',
            ],
         )),
    # #373: the stored update check RAN AND FAILED (mirror unreachable, expired
    # subscription, revoked fingerprint, unavailable release train). The series
    # exists only once a check has been stored, so a box that has never checked
    # produces NoData and stays at the default "Ok" state instead of firing —
    # that presence gate is the guard, exactly like opnsense-disk-space-low.
    dict(name="opnsense-update-check-failing", title="OPNsenseUpdateCheckFailing",
         A="opnsense_firmware_update_check_success", op="lt", params=[1, 0],
         for_min=60, severity="warning",
         summary="OPNsense update check failing ({{ $labels.opnsense_instance }})",
         description="opnsense_firmware_update_check_success is 0: the firewall's stored update "
                     "check RAN AND FAILED, so the box cannot currently see security updates. "
                     "opnsense_firmware_update_check_state says which half broke - component "
                     "connection (DNS/proxy/credentials) or component repository "
                     "(fingerprint/subscription/release train). This is NOT real-time mirror "
                     "monitoring: it is the STORED result of a check OPNsense runs roughly daily, "
                     "read through the exporter's firmware response cache, so a failure can take "
                     "up to --exporter.firmware-cache-ttl (default 12h) to appear here and just "
                     "as long to clear after it is fixed. The value is therefore constant across "
                     "that window, so the 1h pending period filters scrape gaps and restarts, "
                     "not mirror flapping.",
         runbook=dict(
             measures="opnsense_firmware_update_check_success: whether OPNsense's own STORED update check ran and succeeded (not a real-time mirror probe). opnsense_firmware_update_check_state says which half broke: connection (DNS/proxy/credentials) or repository (fingerprint/subscription/release train).",
             threshold="lt 1 for 60m. This value is read through the exporter's firmware response cache (default 12h TTL), so a failure can take up to that long to appear and just as long to clear - the value stays constant across that window, so the 1h pending period filters scrape gaps and restarts rather than genuine mirror flapping.",
             absent='The series exists only once a check has been stored; a box that has never checked produces NoData and stays at the default Ok state instead of firing.',
             checks=[
                'Read opnsense_firmware_update_check_state to know which half failed before digging further',
                'Manually trigger an update check in the OPNsense UI and read the actual error text',
                'Check DNS/proxy reachability to the OPNsense mirror, and subscription/fingerprint validity if the state points at the repository side',
            ],
             causes=[
                'The configured mirror is unreachable (DNS, proxy, or network path)',
                'An expired subscription, revoked fingerprint, or unavailable release train',
            ],
             verify=[
                'opnsense_firmware_update_check_success returns to 1 (note: can take up to the firmware cache TTL to reflect a fix)',
            ],
         )),
    dict(name="opnsense-cert-expiring", title="OPNsenseCertificateExpiringSoon",
         A="(opnsense_certificate_valid_to_seconds - time()) / 86400",
         op="within_range", params=[0, 14], for_min=0, severity="warning",
         summary="OPNsense certificate expiring soon: {{ $labels.commonname }} ({{ $labels.opnsense_instance }})",
         description="Certificate {{ $labels.commonname }} ({{ $labels.description }}) expires within 14 days.",
         runbook=dict(
             measures="Days until a certificate's notAfter time ((opnsense_certificate_valid_to_seconds - time()) / 86400).",
             threshold='within_range [0, 14] - the certificate expires within the next 14 days (and has not already expired, which is covered by the critical rule below).',
             absent="Default noDataState (Ok) - absence means that certificate is no longer tracked (removed/replaced), not that it's safely far from expiry.",
             checks=[
                'Read the commonname/description labels to identify the exact certificate',
                "Check whether it's ACME-managed (should auto-renew) or a manually-imported cert needing a manual renewal",
            ],
             causes=[
                'A manually-managed certificate was never scheduled for renewal',
                "An ACME renewal is failing silently (check the ACME client's own log/status)",
            ],
             verify=[
                "The certificate's valid_to timestamp moves out past the 14-day window after renewal",
            ],
         )),
    dict(name="opnsense-cert-expiring-critical", title="OPNsenseCertificateExpiringCritical",
         A="(opnsense_certificate_valid_to_seconds - time()) / 86400",
         op="within_range", params=[0, 3], for_min=0, severity="critical",
         summary="OPNsense certificate expiring imminently: {{ $labels.commonname }} ({{ $labels.opnsense_instance }})",
         description="Certificate {{ $labels.commonname }} ({{ $labels.description }}) expires within 3 days.",
         runbook=dict(
             measures='The same days-until-expiry expression as OPNsenseCertificateExpiringSoon ((opnsense_certificate_valid_to_seconds - time()) / 86400).',
             threshold='within_range [0, 3] - imminent expiry, escalated to critical severity because there is very little runway left to act.',
             absent='Default noDataState (Ok) - same reasoning as the warning-tier sibling: absence means the certificate is no longer tracked.',
             checks=[
                'Read the commonname/description labels and confirm this is the same cert already flagged by OPNsenseCertificateExpiringSoon, or a newly-discovered one',
                'Renew or replace the certificate immediately - anything consuming it (web UI, VPN, reverse proxy) will start failing TLS validation at expiry',
            ],
             causes=[
                "OPNsenseCertificateExpiringSoon's warning was missed or not actioned in time",
                'An ACME renewal has been failing for multiple cycles',
            ],
             verify=[
                "The certificate's valid_to timestamp moves out past the 3-day window",
                'Whatever service depends on the cert (UI, VPN, proxy) still presents a valid chain after renewal',
            ],
         )),
    # Exclude on-demand services that are expected to be stopped (e.g. iperf, which only runs during
    # an explicit performance test). Add other expected-down service names to the exclusion as needed.
    dict(name="opnsense-service-down", title="OPNsenseServiceDown",
         A='opnsense_services_status{name!="iperf"}', op="lt", params=[1, 0], for_min=10, severity="warning",
         summary="OPNsense service {{ $labels.name }} stopped ({{ $labels.opnsense_instance }})",
         description="Service {{ $labels.name }} ({{ $labels.description }}) has been stopped for 10m. "
                     "On-demand services (e.g. iperf) are excluded. One alert per service.",
         runbook=dict(
             measures='opnsense_services_status: whether a monitored OPNsense service is running (excludes on-demand services such as iperf, which are expected to be stopped between test runs).',
             threshold='lt 1 (stopped) sustained for 10m. One alert instance per service.',
             absent="Default noDataState (Ok) - absence means that service is no longer configured/tracked, not that it's running.",
             checks=[
                'Read the name/description labels to identify the exact service',
                "Check the OPNsense UI's Services page for the actual stop reason/crash log",
                'Try restarting it from the UI and watch whether it stays up or crash-loops',
            ],
             causes=[
                'The service crashed and did not auto-restart',
                'A configuration error is preventing the service from starting',
                'A dependency (interface, another service, a plugin) it needs is unavailable',
            ],
             verify=[
                'opnsense_services_status for that service returns to 1 and stays there (not just a one-shot restart that crashes again)',
            ],
         )),
    dict(name="opnsense-ntp-unsynced", title="OPNsenseNTPPeerUnreachable",
         A="opnsense_ntp_peer_reach", op="lt", params=[1, 0], for_min=15, severity="warning",
         summary="OPNsense NTP peer {{ $labels.server }} unreachable ({{ $labels.opnsense_instance }})",
         description="NTP peer {{ $labels.server }} reachability register has been 0 for 15m.",
         runbook=dict(
             measures='opnsense_ntp_peer_reach: whether NTP considers a specific configured time peer reachable.',
             threshold='lt 1 sustained for 15m.',
             absent="Default noDataState (Ok) - absence means that peer is no longer configured, not that it's reachable.",
             checks=[
                'Read the server label to identify the specific NTP peer',
                "Check outbound connectivity/firewall rules to that peer's address and port (UDP/123)",
                "Confirm the peer itself hasn't been decommissioned or renumbered upstream",
            ],
             causes=[
                'The configured NTP peer is down or unreachable from this network',
                'A firewall rule change blocked outbound NTP',
                "DNS resolution for the peer's hostname is failing",
            ],
             verify=[
                'opnsense_ntp_peer_reach for that peer returns to 1',
            ],
         )),
    # Unlike opnsense-endpoint-errors, this is a genuine count-in-window threshold (>5 bogus answers
    # per rolling 15m) with for:0 — it fires immediately when the count is exceeded, so there is no
    # for-duration whose meaning the 15m window could distort. The #94 defect (long for paired with an
    # equally-long increase window) does not apply here, so the 15m window is intentional and kept.
    dict(name="opnsense-unbound-dnssec-bogus", title="OPNsenseUnboundDNSSECBogus",
         A="sum by (opnsense_instance) (increase(opnsense_unbound_dns_answers_bogus_total[15m]))",
         op="gt", params=[5, 0], for_min=0, severity="info",
         summary="OPNsense Unbound DNSSEC bogus answers ({{ $labels.opnsense_instance }})",
         description="More than 5 DNSSEC-bogus answers in 15m — possible misconfiguration or tampering.",
         runbook=dict(
             measures='Count of DNSSEC-bogus DNS answers Unbound has returned in a rolling 15m window, summed by opnsense_instance.',
             threshold="gt 5 bogus answers in 15m, for_min=0 - a genuine count-in-window threshold that fires immediately once exceeded (no persistence period needed, unlike the endpoint-error rule's #94 trap).",
             absent='Default noDataState (Ok) - no bogus answers is the normal, healthy state.',
             checks=[
                "Check Unbound's own logs for which domain(s) are producing bogus DNSSEC validation",
                'Determine whether this correlates with a specific external resolver/domain misconfiguration versus active tampering on the network path',
            ],
             causes=[
                'A misconfigured authoritative zone upstream (broken DNSSEC signing)',
                'Clock skew on the box breaking signature validity windows',
                'Active DNS tampering/spoofing on the network path (the case this alert exists to surface)',
            ],
             verify=[
                'The 15m rolling count of bogus answers returns to 0 or stays under the threshold',
            ],
         )),
    # The syslog/Zenarmor push-based log receiver (#248-#261) had no alert coverage yet — these four
    # close that gap for the log-shipping pipeline itself (sink health, backpressure, label loss,
    # source liveness).
    dict(name="opnsense-logship-sink-errors", title="OPNsenseLogShipSinkErrors",
         A="sum by (opnsense_instance) (rate(opnsense_exporter_logs_ship_errors_total[5m]))",
         op="gt", params=[0, 0], for_min=10, severity="warning",
         summary="OPNsense log-shipping sink retrying ({{ $labels.opnsense_instance }})",
         description="The log-shipping sink (OTLP/Loki) has had failed Emit attempts for 10m. The "
                     "unacknowledged remainder is in retry/degradation, not "
                     "proof of counted record loss. Check OPNsenseLogShipCountedLoss separately.",
         runbook=dict(
             measures='Rate of failed Emit attempts by the log-shipping sink (OTLP/Loki) over 5m, summed by opnsense_instance - retry/degradation activity, not proof that records were actually lost.',
             threshold='gt 0 sustained for 10m.',
             absent='Default noDataState (Ok) - no errors means the sink is delivering cleanly.',
             checks=[
                "Check connectivity/auth to the configured OTLP or Loki destination from the exporter's network path",
                'Check OPNsenseLogShipCountedLoss separately - this rule only proves retrying is happening, not that anything was actually dropped',
            ],
             causes=[
                'The log-shipping destination (OTLP/Loki backend) is unreachable or rejecting requests',
                'Credentials for the destination expired or were rotated without updating the exporter',
            ],
             verify=[
                'The 5m error rate returns to 0 and stays there',
                'opnsense_exporter_logs_dropped_total stops incrementing for this instance',
            ],
         )),
    dict(name="opnsense-logship-queue-near-capacity", title="OPNsenseLogShipQueueNearCapacity",
         A="max by (opnsense_instance) ("
           "label_replace(opnsense_exporter_logs_queue_length / "
           "(opnsense_exporter_logs_queue_capacity > 0), \"bound\", \"count\", \"__name__\", \".*\") "
           "or label_replace(opnsense_exporter_logs_queue_bytes / "
           "(opnsense_exporter_logs_queue_max_bytes > 0), \"bound\", \"bytes\", \"__name__\", \".*\"))",
         op="gt", params=[0.9, 0], for_min=5, severity="warning",
         summary="OPNsense log-shipping queue near capacity ({{ $labels.opnsense_instance }})",
         description="The log-shipping backpressure queue has been above 90% of either its record-count "
                     "capacity or its enabled byte budget for 5m — overflow drops are imminent.",
         runbook=dict(
             measures="The higher of two ratios for the log-shipping backpressure queue: record-count occupancy (queue_length / queue_capacity) or byte occupancy where a byte budget is enabled (queue_bytes / queue_max_bytes), max'd by opnsense_instance.",
             threshold='gt 0.9 (over 90% of whichever bound is enabled) sustained for 5m.',
             absent='Default noDataState (Ok) - the `> 0` guards mean an unconfigured bound produces no series for that half rather than a meaningless ratio.',
             checks=[
                "Check the downstream sink's health first (OPNsenseLogShipSinkErrors) - a stalled destination is the most common reason the queue backs up",
                'Check the configured queue capacity/byte budget against current log volume',
            ],
             causes=[
                'The log-shipping destination has slowed or stopped accepting records, so the queue is backing up behind it',
                'A sudden spike in log volume (e.g. a flood on a push source) is outrunning the configured queue bound',
            ],
             verify=[
                'The occupancy ratio drops back under 0.9 and stays there for 5m',
                'No overflow drops appear in OPNsenseLogShipCountedLoss immediately afterward',
            ],
         )),
    dict(name="opnsense-logship-counted-loss", title="OPNsenseLogShipCountedLoss",
         A="sum by (opnsense_instance, source, reason) "
           "(increase(opnsense_exporter_logs_dropped_total[15m]))",
         op="gt", params=[0, 0], for_min=0, severity="warning",
         summary="OPNsense log-shipping counted record loss ({{ $labels.reason }}) on "
                 "{{ $labels.source }} ({{ $labels.opnsense_instance }})",
         description="Log records were counted as lost in the last 15m, grouped by the exact source and "
                     "reason. overflow means either queue bound evicted the oldest record; "
                     "record_too_large was rejected at ingest; rejected was terminally refused by the "
                     "destination; ship_failed_permanent exhausted the configured retry bound; and "
                     "ship_failed was abandoned during shutdown. Retry attempts alone increment "
                     "logs_ship_errors_total, not this alert.",
         runbook=dict(
             measures='Count of log records counted as lost in a rolling 15m window, grouped by the exact source and reason (overflow, record_too_large, rejected, ship_failed_permanent, ship_failed).',
             threshold='gt 0 in 15m, for_min=0 - fires immediately, since any counted loss is worth knowing about.',
             absent='Default noDataState (Ok) - no loss events is the normal state.',
             checks=[
                'Read the reason label first - it tells you which of five distinct failure modes occurred (queue-bound eviction, oversized record, destination refusal, retry exhaustion, or shutdown abandonment)',
                'Cross-check OPNsenseLogShipQueueNearCapacity and OPNsenseLogShipSinkErrors for the same window - overflow/ship_failed reasons usually correlate with one of those',
            ],
             causes=[
                'overflow: the queue bound evicted the oldest record under sustained backpressure',
                'record_too_large: a single record exceeded the configured size limit',
                'rejected / ship_failed_permanent: the destination terminally refused it or retries were exhausted',
                'ship_failed: records were abandoned during shutdown',
            ],
             verify=[
                'The 15m rolling count for that source/reason returns to 0',
            ],
         )),
    dict(name="opnsense-logship-resource-capped", title="OPNsenseLogShipResourceCapped",
         A="sum by (opnsense_instance) (increase(opnsense_exporter_logs_resource_capped_total[15m]))",
         op="gt", params=[0, 0], for_min=0, severity="warning",
         summary="OPNsense log-shipping records had labels dropped ({{ $labels.opnsense_instance }})",
         description="Records were shipped with their opnsense.* resource labels dropped in the last "
                     "15m, so label-scoped queries against them silently under-report.",
         runbook=dict(
             measures='Count of records shipped with their opnsense.* resource labels dropped in a rolling 15m window, summed by opnsense_instance.',
             threshold='gt 0 in 15m, for_min=0.',
             absent='Default noDataState (Ok) - no capped records is the normal state.',
             checks=[
                'Check whether label-scoped queries against recently-shipped log records are silently under-reporting for this instance',
                'Check the configured resource-attribute budget/limit on the log-shipping pipeline',
            ],
             causes=[
                'The configured cap on resource attributes per record was hit under high label cardinality or volume',
            ],
             verify=[
                'The 15m rolling count of capped records returns to 0',
                'Newly-shipped records carry their full opnsense.* resource labels again',
            ],
         )),
    # Scoped to syslog|zenarmor: both are continuously-active push sources, so 15m of silence is a
    # genuine stall. A source that is legitimately quiet or not configured would false-fire if
    # included, so it is deliberately excluded rather than covered here.
    dict(name="opnsense-logship-cursor-stalled", title="OPNsenseLogShipCursorStalled",
         A='time() - max by (opnsense_instance, source) (opnsense_exporter_logs_last_exported_timestamp_seconds{source=~"syslog|zenarmor"})',
         op="gt", params=[900, 0], for_min=0, severity="warning",
         summary="OPNsense log-shipping source {{ $labels.source }} stalled ({{ $labels.opnsense_instance }})",
         description="Push source {{ $labels.source }} has shipped no events for 15m despite being "
                     "continuously active. Scoped to syslog|zenarmor only, so a quiet or unconfigured "
                     "source cannot false-fire.",
         runbook=dict(
             measures='Seconds since the last exported event timestamp for a continuously-active push source, restricted to source=~"syslog|zenarmor" - both are always-on push feeds, so silence from either is itself the anomaly.',
             threshold='gt 900s (15m) of silence, for_min=0.',
             absent='Default noDataState (Ok) - deliberately scoped to only the two always-active sources, so a legitimately quiet or unconfigured source (excluded from the query) cannot false-fire.',
             checks=[
                'Confirm the source (syslog sender or Zenarmor) is still actually configured to push to the exporter',
                "Check the exporter's log-shipping receiver logs for connection resets or parse errors from that source",
                "Confirm the firewall/network path between the source and the exporter's receiver port hasn't changed",
            ],
             causes=[
                'The syslog sender or Zenarmor was reconfigured/pointed elsewhere',
                'A network path or firewall rule change blocked the push',
                'The receiver itself hit an unhandled error and stopped accepting from that source',
            ],
             verify=[
                'opnsense_exporter_logs_last_exported_timestamp_seconds for that source starts advancing again',
            ],
         )),
    # OTLP metric delivery (#388). consecutive_failures is the right signal rather than
    # a rate() on otlp_exports_total{result="error"}: it resets to 0 on the next success,
    # so ">0 sustained" means an ONGOING outage, and it counts from the very first
    # attempt — which covers the never-worked-since-boot case (wrong endpoint, expired
    # credential) that a last-success-staleness rule cannot see, because
    # otlp_last_success_timestamp_seconds is 0 until something lands and time()-0 is a
    # meaningless 56-year age. At the default --otlp.export-interval=60s the 15m pending
    # period is ~15 consecutive failed exports, so a single backend blip or a rolling
    # restart of the collector endpoint does not fire.
    dict(name="opnsense-otlp-delivery-failing", title="OPNsenseOTLPDeliveryFailing",
         A="opnsense_exporter_otlp_consecutive_failures", op="gt", params=[0, 0],
         for_min=15, severity="warning",
         summary="OPNsense exporter OTLP metric delivery failing",
         description="Every OTLP metric export has failed back-to-back for 15m "
                     "({{ $values.A.Value | printf \"%.0f\" }} consecutive failures) — no metrics are "
                     "reaching the OTLP backend. READ THIS BEFORE RELYING ON IT: an exporter cannot ship "
                     "its own failure metric through the path that is failing, so this signal CANNOT REACH "
                     "A PURE-OTLP BACKEND DURING THE OUTAGE. It is for /metrics scrapers, for the operator "
                     "console (which reads it passively), and as post-recovery forensics once delivery "
                     "resumes and the backfilled series shows how long it was broken. On a pure-OTLP "
                     "backend the in-band signal for this failure mode is staleness of the exporter's data "
                     "itself, not this rule. opnsense_exporter_otlp_last_success_timestamp_seconds gives "
                     "the recovery timeline; 0 there means no export has EVER succeeded since startup, "
                     "which points at a wrong endpoint or a bad credential rather than a backend outage — "
                     "the exporter connects lazily, so a clean start proves nothing about delivery (#388).",
         runbook=dict(
             measures='opnsense_exporter_otlp_consecutive_failures: how many OTLP metric export attempts have failed back-to-back, resetting to 0 on the next success - so ">0 sustained" means an ONGOING outage, including the never-worked-since-boot case a staleness rule can\'t see.',
             threshold="gt 0 for 15m. At the default 60s export interval that's ~15 consecutive failed exports, so a single blip or a rolling restart of the collector endpoint does not fire.",
             absent='No dedicated nodata handling - this metric simply does not exist on a box with OTLP export disabled.',
             checks=[
                'READ THIS FIRST: an exporter cannot ship its own failure metric through the path that is failing, so this signal CANNOT reach a pure-OTLP backend during the outage itself - it is for /metrics scrapers, the passive operator console, and post-recovery forensics only',
                'Read opnsense_exporter_otlp_last_success_timestamp_seconds: 0 means no export has EVER succeeded since startup (wrong endpoint or bad credential), a non-zero value gives the recovery timeline',
                "On a pure-OTLP backend, look for STALENESS of this exporter's own data at the backend as the in-band symptom instead of this rule",
            ],
             causes=[
                'The configured OTLP endpoint is wrong or unreachable',
                'The OTLP credential/token is invalid or expired',
                'The OTLP collector/backend itself is down or rejecting exports',
            ],
             verify=[
                'opnsense_exporter_otlp_consecutive_failures returns to 0',
                'opnsense_exporter_otlp_last_success_timestamp_seconds advances to a recent time',
            ],
         )),
    dict(name="opnsense-ipsec-tunnel-down", title="OPNsenseIPsecTunnelDown",
         A="opnsense_ipsec_phase1_status", op="lt", params=[1, 0], for_min=10, severity="warning",
         summary="OPNsense IPsec tunnel {{ $labels.name }} down ({{ $labels.opnsense_instance }})",
         description="IPsec phase1 tunnel {{ $labels.name }} ({{ $labels.description }}) has reported "
                     "status 0 (down; connected=1) for 10m. Catches a tunnel dropping while the daemon "
                     "itself keeps running, which opnsense-service-down misses.",
         runbook=dict(
             measures='opnsense_ipsec_phase1_status: whether a specific IPsec phase1 tunnel is connected. Catches a tunnel dropping while the strongSwan/racoon daemon itself keeps running, which OPNsenseServiceDown cannot see.',
             threshold='lt 1 (down; connected=1) sustained for 10m.',
             absent="Default noDataState (Ok) - absence means that tunnel is no longer configured, not that it's connected.",
             checks=[
                'Read the name/description labels to identify the specific tunnel',
                "Check the OPNsense UI's IPsec status page and the daemon's own log for the negotiation failure reason",
                "Confirm the remote peer's public IP/credentials haven't changed",
            ],
             causes=[
                'The remote peer is unreachable or its public IP changed',
                'A pre-shared key or certificate mismatch after a credential rotation',
                'A phase1/phase2 proposal mismatch introduced by a config change on either side',
            ],
             verify=[
                'opnsense_ipsec_phase1_status for that tunnel returns to 1 (connected)',
                'Traffic is observably flowing across the tunnel again',
            ],
         )),
    # Verified semantics: 1=up, 0=down, 2=unknown, 3=stale. lt 1 fires on 0 only — 2/3 are
    # deliberately NOT alerted, since unknown/stale is not the same claim as confirmed down.
    dict(name="opnsense-wireguard-peer-down", title="OPNsenseWireGuardPeerDown",
         A="opnsense_wireguard_peer_status", op="lt", params=[1, 0], for_min=10, severity="warning",
         summary="OPNsense WireGuard peer {{ $labels.peer_name }} down ({{ $labels.opnsense_instance }})",
         description="WireGuard peer {{ $labels.peer_name }} on {{ $labels.device_name }} has reported "
                     "status 0 (down) for 10m. Status values are 1=up, 0=down, 2=unknown, 3=stale — "
                     "this alert deliberately fires on 0 only, not on unknown/stale.",
         runbook=dict(
             measures='opnsense_wireguard_peer_status for one peer. Values are 1=up, 0=down, 2=unknown, 3=stale; this alert deliberately fires on 0 only.',
             threshold='lt 1 sustained for 10m - matches 0 (down) only; 2 (unknown) and 3 (stale) are deliberately not alerted, since neither is the same claim as confirmed down.',
             absent='Default noDataState (Ok) - absence means that peer is no longer configured.',
             checks=[
                'Read the peer_name/device_name labels to identify the specific peer and interface',
                "Check the peer's last-handshake time in the OPNsense UI - a peer stuck at 0 rather than cycling through 2/3 usually means the endpoint address is simply wrong or unreachable",
                "Confirm the peer's allowed-IPs and endpoint configuration haven't drifted from the remote side",
            ],
             causes=[
                "The remote peer's network endpoint changed or became unreachable",
                'A key mismatch after a credential rotation on either side',
                'A firewall rule blocking the WireGuard UDP port',
            ],
             verify=[
                'opnsense_wireguard_peer_status for that peer returns to 1 (up)',
                "The peer's last-handshake timestamp is recent",
            ],
         )),
    # remote_services_total>0 is load-bearing: reachable=0 also means "HA sync isn't configured at
    # all", so the guard restricts firing to boxes where HA sync is actually set up.
    dict(name="opnsense-hasync-unreachable", title="OPNsenseHASyncUnreachable",
         A="opnsense_hasync_remote_reachable == 0 and on(opnsense_instance) "
           "(opnsense_hasync_remote_services_total > 0)",
         op="lt", params=[1, 0], for_min=10, severity="warning",
         summary="OPNsense HA sync peer unreachable ({{ $labels.opnsense_instance }})",
         description="opnsense_hasync_remote_reachable has been 0 for 10m on a box where HA sync is "
                     "configured (remote_services_total > 0). The guard excludes boxes with HA sync "
                     "unconfigured, where reachable=0 is the normal, expected reading.",
         runbook=dict(
             measures='opnsense_hasync_remote_reachable, guarded to only fire on boxes where HA sync is actually configured (opnsense_hasync_remote_services_total > 0) - reachable=0 on an unconfigured box is the normal, expected reading and is deliberately excluded.',
             threshold='lt 1 sustained for 10m, on a box where HA sync is configured.',
             absent="Default noDataState (Ok) - absence means HA sync isn't configured on this box at all, which the guard already treats as non-alertable.",
             checks=[
                'Confirm the HA peer box is actually up and reachable on the network from this instance',
                'Check the configured HA sync IP/interface for a recent change on either side',
                "Check the OPNsense UI's HA Sync status page for the specific connection error",
            ],
             causes=[
                'The HA peer firewall is down or unreachable',
                'A network path change (interface, VLAN, firewall rule) broke the sync link',
                'HA sync credentials were rotated on one box but not the other',
            ],
             verify=[
                'opnsense_hasync_remote_reachable returns to 1',
                'Config changes on the primary are observed to sync to the peer again',
            ],
         )),
    # carp_vip_status: 1=MASTER, 0=BACKUP (both normal — inside the [0,1] range), 2=INIT, -1=unknown
    # (faults — outside the range). The `unless` clause suppresses alerts during deliberate maintenance
    # mode.
    dict(name="opnsense-carp-vip-fault", title="OPNsenseCARPVIPFault",
         A="opnsense_carp_vip_status unless on(opnsense_instance) (opnsense_carp_maintenance_mode == 1)",
         op="outside_range", params=[0, 1], for_min=5, severity="warning",
         summary="OPNsense CARP VIP {{ $labels.vip }} fault on {{ $labels.interface }} ({{ $labels.opnsense_instance }})",
         description="CARP VIP {{ $labels.vip }} on {{ $labels.interface }} has been outside the normal "
                     "MASTER(1)/BACKUP(0) range for 5m — status 2 (INIT) or -1 (unknown). BACKUP is a "
                     "normal, healthy state and does not fire; this only fires on INIT/unknown. "
                     "Suppressed while opnsense_carp_maintenance_mode is 1.",
         runbook=dict(
             measures='opnsense_carp_vip_status for one VIP/interface. Values: 1=MASTER, 0=BACKUP (both normal, inside [0,1]), 2=INIT, -1=unknown (faults, outside the range). Suppressed while opnsense_carp_maintenance_mode is 1 (deliberate maintenance).',
             threshold='outside_range [0, 1] sustained for 5m - fires on INIT(2)/unknown(-1) only; BACKUP is healthy and never fires.',
             absent='Default noDataState (Ok) - absence means that VIP/interface is no longer configured.',
             checks=[
                'Read the vip/interface labels to identify the exact VIP in fault',
                "Check opnsense_carp_maintenance_mode for this instance - if it's 1, this is intentional and won't fire (if you're seeing this alert, maintenance mode is NOT the cause)",
                'Check OPNsenseCARPStateFlapping for recent transition history on the same interface/vhid',
            ],
             causes=[
                'The CARP peer relationship is broken (pfsync misconfigured, network partition between nodes)',
                'The interface the VIP is bound to went down',
                'A VHID/advertising-frequency conflict with another device on the same broadcast domain',
            ],
             verify=[
                'opnsense_carp_vip_status for that VIP returns to 0 or 1 (BACKUP or MASTER)',
            ],
         )),
    # #405: kernel CARP transitions are EVENTS, and these two rules complement
    # OPNsenseCARPVIPFault above rather than replacing it — that one reads the
    # current-state gauge, these read the transitions the gauge cannot retain.
    # Grouped by interface AND vhid because a vhid is only unique within an interface.
    #
    # THRESHOLD: strict >3, i.e. four or more changes in the window. A boot/init
    # sequence is INIT -> BACKUP -> MASTER (two changes) and a single failover is one,
    # so four-or-more sits above one planned event with margin.
    #
    # This DELIBERATELY DIVERGES from the dpinger sibling OPNsenseGatewayAlarmFlapping
    # below, which uses >2 — do not "fix" the two to match. They are different event
    # shapes: dpinger emits alarm/clear PAIRS for one gateway, so >2 there is calibrated
    # against a pair count, whereas CARP emits one record per state edge and a normal
    # boot already spends two of them. Matching the numbers for symmetry would make this
    # rule page on every planned failover.
    dict(name="opnsense-carp-state-flapping", title="OPNsenseCARPStateFlapping",
         A='sum by (opnsense_instance, interface, vhid) '
           '(increase(opnsense_log_events_carp_total{event="state_changed"}[15m]))',
         op="gt", params=[3, 0], for_min=0, severity="warning",
         summary="OPNsense CARP vhid {{ $labels.vhid }} is flapping on {{ $labels.interface }} ({{ $labels.opnsense_instance }})",
         description="Four or more CARP state changes for vhid {{ $labels.vhid }} on interface "
                     "{{ $labels.interface }} in 15m. A boot sequence is two changes "
                     "(INIT -> BACKUP -> MASTER) and a single failover is one, so neither fires. "
                     "This is transition evidence from "
                     "syslog, not an assertion about the current state; read the kernel's cause from "
                     "the carp.reason field on the shipped log records, and check OPNsenseCARPVIPFault "
                     "and the CARP VIP Status panel for where the VIP actually sits now.",
         runbook=dict(
             measures="Count of CARP state_changed transitions for one interface+vhid pair in a rolling 15m window, from shipped syslog events - a TRANSITION signal complementing OPNsenseCARPVIPFault's current-state gauge, grouped by vhid AND interface since a vhid is only unique within an interface.",
             threshold="gt 3 (four or more changes) in 15m, for_min=0. A boot sequence is two changes (INIT->BACKUP->MASTER) and a single failover is one, so this threshold sits above one planned event with margin. Deliberately DIFFERENT from the dpinger sibling's >2 threshold - the two event shapes aren't comparable, don't tune them to match.",
             absent='Default noDataState (Ok) - no state_changed events in the window is the normal, quiet state.',
             checks=[
                "Read carp.reason on the shipped log records for the kernel's own stated cause",
                'Check OPNsenseCARPVIPFault and the CARP VIP Status panel for where the VIP actually sits now - this alert is transition evidence, not a current-state claim',
            ],
             causes=[
                'An unstable network path between HA peers causing repeated MASTER/BACKUP transitions',
                'A pfsync/CARP advertisement misconfiguration',
                'Genuine repeated hardware/service disruptions on one node',
            ],
             verify=[
                'No further state_changed events for that vhid/interface in the next 15m window',
                'opnsense_carp_vip_status for the VIP settles at a stable value',
            ],
         )),
    # Demotion is how a node steps back from being master: pfsync bulk transfer, a
    # service disruption, or an interface being taken down.
    #
    # THRESHOLD: strict >3, i.e. four or more demotions in the window. DO NOT "tighten"
    # this to >0 for sensitivity — that is the trap, and the #405 capture proves it.
    # The evidence window recorded 11 `demoted by 240 (pfsync bulk start)` and 11
    # `demoted by -240 (pfsync bulk fail)` records: demotion during pfsync bulk transfer
    # is ROUTINE OPERATION, so >0 pages on a healthy cluster doing exactly what it is
    # supposed to do, and an alert that fires on normal behaviour trains people to
    # ignore it. One bulk cycle is one `demoted` plus one `promoted`, so this is
    # effectively a bulk-cycle counter; four or more in fifteen minutes is churn rather
    # than routine sync.
    #
    # increase(), NOT rate(): the threshold is a COUNT OVER THE WINDOW. rate() is
    # per-second, so four events in 15m is 0.0044/s and any threshold >=1 on a rate()
    # could never fire — a silently dead alert. increase() is still rate-derived rather
    # than a bare cumulative total, which is what matters here.
    dict(name="opnsense-carp-unexpected-demotion", title="OPNsenseCARPUnexpectedDemotion",
         A='sum by (opnsense_instance) '
           '(increase(opnsense_log_events_carp_total{event="demoted"}[15m]))',
         op="gt", params=[3, 0], for_min=0, severity="warning",
         summary="OPNsense CARP node is demoting itself ({{ $labels.opnsense_instance }})",
         description="Four or more positive CARP demotion adjustments in 15m — this node keeps making "
                     "itself less willing to be master. A single pfsync bulk transfer demotes and then "
                     "promotes once and does NOT fire; this threshold sits above routine sync so it "
                     "means churn. Common causes are repeated pfsync bulk "
                     "transfers, a service disruption, or an interface flapping; the kernel states "
                     "which on the shipped log record as carp.reason, with the signed adjustment in "
                     "carp.demotion.delta and the resulting level in carp.demotion.total. Neither the "
                     "cause nor those numbers is a metric label. Compare opnsense_carp_demotion for the "
                     "current level, and note the matching promoted event when the demotion is released.",
         runbook=dict(
             measures='Count of positive CARP demotion adjustments (event="demoted") for the instance in a rolling 15m window, from shipped syslog events - a node stepping back from its willingness to be master.',
             threshold='gt 3 (four or more) in 15m, for_min=0. DO NOT tighten to >0: one pfsync bulk-transfer cycle is one demoted plus one promoted event, ROUTINE operation (the #405 capture recorded 11 pairs on a healthy cluster) - a threshold of >0 would page on normal behaviour and train people to ignore the alert.',
             absent='Default noDataState (Ok) - no demoted events in the window is the normal, quiet state.',
             checks=[
                "Read carp.reason, carp.demotion.delta, and carp.demotion.total on the shipped log records for the kernel's own stated cause and the resulting demotion level - none of these are metric labels",
                'Compare opnsense_carp_demotion for the current level, and look for the matching promoted event that releases the demotion',
                'Check for repeated pfsync bulk transfers, a flapping interface, or an actual service disruption on this node',
            ],
             causes=[
                'Repeated pfsync bulk transfers (each one demotes and promotes once - only churn, four or more cycles in 15m, is the actual signal)',
                'A service disruption on this node',
                'A flapping interface causing repeated CARP re-evaluation',
            ],
             verify=[
                'No further demoted events in the next 15m window',
                'opnsense_carp_demotion returns to its baseline level',
            ],
         )),
    # Threshold and lookback are deployment-specific: tune --exporter.ids-alert-lookback and the 50
    # threshold per site, same tone as opnsense-unbound-dnssec-bogus above. Verified: action is only
    # ever allowed/blocked — no drop/reject values exist.
    dict(name="opnsense-ids-alert-spike", title="OPNsenseIDSAlertSpike",
         A='sum by (opnsense_instance) (opnsense_ids_recent_alerts{action="blocked"})',
         op="gt", params=[50, 0], for_min=5, severity="info",
         summary="OPNsense IDS blocked-alert spike ({{ $labels.opnsense_instance }})",
         description="More than 50 blocked IDS alerts held in the recent-alerts window for 5m. The "
                     "threshold and --exporter.ids-alert-lookback window are deployment-specific — tune "
                     "both per site. action is only ever allowed/blocked (no drop/reject).",
         runbook=dict(
             measures='Count of currently-held blocked-action IDS alerts in the recent-alerts window, summed by opnsense_instance. action is only ever allowed/blocked (no drop/reject values exist).',
             threshold='gt 50 for 5m. Both the threshold and --exporter.ids-alert-lookback window are deployment-specific - tune per site.',
             absent='Default noDataState (Ok) - a quiet IDS is the normal state.',
             checks=[
                'Open the IDS/IPS tab to see which signature(s)/source IPs are driving the spike',
                'Check whether this correlates with a known scan, a new malicious campaign, or a misbehaving internal host being flagged repeatedly',
            ],
             causes=[
                "An active scan or attack against the firewall's public-facing services",
                'A misconfigured or compromised internal host triggering repeated egress alerts',
                'A signature update introducing a burst of (possibly false-positive) matches',
            ],
             verify=[
                'The blocked-alert count in the lookback window drops back under 50',
            ],
         )),
    # No bytes are lost on eviction (the oldest is force-emitted, not dropped), so this is a warning,
    # not a page: the correlate window can no longer be held under current flow volume.
    dict(name="opnsense-flow-correlator-evicting", title="OPNsenseFlowCorrelatorEvicting",
         A="sum by (opnsense_instance) (rate(opnsense_flow_correlator_evicted_total[5m]))",
         op="gt", params=[0, 0], for_min=15, severity="warning",
         summary="OPNsense flow correlator evicting entries ({{ $labels.opnsense_instance }})",
         description="The flow correlator has force-emitted entries for 15m because "
                     "--flow.correlate.max-entries is binding under current flow volume. No bytes are "
                     "lost, but the cap should be raised so the accumulator can hold a full correlate "
                     "window; sustained eviction shortens the effective join window and lowers the "
                     "merged hit-rate.",
         runbook=dict(
             measures='Rate of forced-eviction of flow-correlator entries over 5m, summed by opnsense_instance - the correlate window can no longer be held under current flow volume. No bytes are lost (the oldest entry is force-emitted, not dropped).',
             threshold='gt 0 sustained for 15m.',
             absent='Default noDataState (Ok) - no eviction is the normal state.',
             checks=[
                'Check current flow volume/cardinality (Flow Volume tab) against --flow.correlate.max-entries',
                'Confirm nothing is generating an unusual number of concurrent flows (scan, flood, a chatty new service)',
            ],
             causes=[
                '--flow.correlate.max-entries is set too low for current flow volume',
                'A traffic pattern change (more concurrent connections) increased pressure on the correlate accumulator',
            ],
             verify=[
                'The eviction rate returns to 0 and stays there for 15m',
                'Raising --flow.correlate.max-entries (if that was the cause) removes the eviction pressure',
            ],
         )),
    # Metrics are never truncated, only per-flow logs, so this is a warning about log completeness and a
    # possible flood on the unauthenticated NetFlow ingress rather than a data-integrity page.
    dict(name="opnsense-flow-logs-truncated", title="OPNsenseFlowLogsTruncated",
         A="sum by (opnsense_instance) (rate(opnsense_flow_logs_truncated_total[5m]))",
         op="gt", params=[0, 0], for_min=10, severity="warning",
         summary="OPNsense flow logs truncated by budget ({{ $labels.opnsense_instance }})",
         description="Flow log records have been dropped by the --flow.max-logs-per-window budget for "
                     "10m. Metrics are unaffected, but per-flow logs are incomplete. Raise the budget if "
                     "this is expected volume, or restrict the unauthenticated NetFlow ingress with "
                     "--flow.netflow.allowed-peers if it is a flood.",
         runbook=dict(
             measures='Rate of flow log records dropped by the --flow.max-logs-per-window budget over 5m, summed by opnsense_instance. Metrics themselves are never truncated, only per-flow LOGS.',
             threshold='gt 0 sustained for 10m.',
             absent='Default noDataState (Ok) - no truncation is the normal state.',
             checks=[
                'Check whether this is expected volume (raise --flow.max-logs-per-window) or a flood on the unauthenticated NetFlow ingress',
                'Check --flow.netflow.allowed-peers if a flood from an unexpected source looks likely',
            ],
             causes=[
                'Genuinely high flow volume exceeding the configured per-window log budget',
                'A flood on the unauthenticated NetFlow ingress from an unexpected/unrestricted peer',
            ],
             verify=[
                'The truncation rate returns to 0',
                "Per-flow log completeness is restored (no further gaps in the Flow Volume tab's log-derived panels)",
            ],
         )),
    # #402: managed alert for the #368 dead-hook detector. Query is copied VERBATIM from
    # docs/flow.md ("Joining the two label spaces") - do not simplify it, each clause kills
    # a specific false positive. Clause 1 restricts to interfaces actually configured for
    # capture. Clause 2 is the only signal a dead hook cannot hide from: ng_netflow fills one
    # side of every flow from a FIB lookup, so merged flow records can still name a dead
    # interface via a peer's route - only the interface's OWN cache node proves it silent.
    # Clause 3 is what tells a dead hook from a legitimately idle interface (a quiet guest
    # VLAN's cache node is flat too; pf confirms bytes actually crossed the device). Clause 4
    # is the honesty guard: it withdraws the whole query once the box's own NetFlow active
    # timeout is at least the 45m observation window, rather than letting a shorter box-side
    # timeout make "45m of silence" a lie. Do NOT read NetFlow source_id=0 as loss elsewhere -
    # it is not a sequence counter. Live-verified 2026-07-25 against the reference box: exactly
    # one row, {interface="AAISP", device="pppoe0"} - the hook whose death took a packet
    # capture to find.
    dict(name="opnsense-netflow-hook-dead", title="OPNsenseNetFlowHookDead",
         A="max by (opnsense_instance, interface, device) (\n"
           "  (opnsense_netflow_capture_expected == 1)\n"
           "    * on (opnsense_instance, interface) group_left (device) opnsense_flow_interface_info\n"
           ")\n"
           "and on (opnsense_instance, device) max by (opnsense_instance, device) (\n"
           "  label_join(increase(opnsense_netflow_cache_packets_total[45m]), \"device\", \"\", "
           "\"interface\") == 0\n"
           ")\n"
           "and on (opnsense_instance, device) max by (opnsense_instance, device) (\n"
           "  label_join(increase(opnsense_firewall_in_ipv4_pass_bytes_total[45m]), \"device\", \"\", "
           "\"interface\") > 0\n"
           ")\n"
           "and on (opnsense_instance) (opnsense_netflow_capture_active_timeout_seconds < 2700)",
         op="gt", params=[0, 0], for_min=5, severity="warning",
         summary="OPNsense NetFlow hook dead on {{ $labels.interface }} ({{ $labels.device }}, {{ $labels.opnsense_instance }})",
         description="The NetFlow hook configured for interface {{ $labels.interface }} (kernel device "
                     "{{ $labels.device }}) on {{ $labels.opnsense_instance }} has recorded zero packets "
                     "on its own ng_netflow node (opnsense_netflow_cache_packets_total) for 45m while pf "
                     "keeps passing traffic on the same device (opnsense_firewall_in_ipv4_pass_bytes_total "
                     "> 0) - the #368 pppoe0 failure mode, where ng_netflow accepted a bogus hook on a "
                     "PPPoE interface and silently captured nothing, because ng_netflow attaches to mpd's "
                     "framing node rather than the ng_iface node ng_pppoe exposes. The alert withdraws "
                     "itself if the box's own configured NetFlow active timeout is 45m (2700s) or more, "
                     "rather than call a shorter window dead on an honesty guard it cannot clear - check "
                     "opnsense_netflow_capture_active_timeout_seconds first if this never fires on a box "
                     "you know has a dead hook. On firing: open the operator console's NetFlow / ifIndex "
                     "tab, confirm {{ $labels.device }} is a real ng_netflow node with `ngctl list` on the "
                     "box, then rebind the capture to the correct kernel device. See docs/flow.md "
                     "('Joining the two label spaces') for the full derivation. Resolves automatically "
                     "once opnsense_netflow_cache_packets_total resumes counting on the device.",
         runbook=dict(
             measures="A four-clause join proving a specific NetFlow capture hook has gone silent while pf still passes traffic on the same kernel device - the #368 dead-hook failure mode, where ng_netflow accepted a bogus hook on a PPPoE interface (it attaches to mpd's framing node, not the ng_iface node ng_pppoe exposes) and silently captured nothing.",
             threshold="gt 0 for 5m. Clause 1 restricts to interfaces actually configured for capture; clause 2 checks the interface's OWN ng_netflow cache node recorded zero packets in 45m; clause 3 confirms pf actually passed bytes on the same device in that window (telling a dead hook from a legitimately idle interface); clause 4 withdraws the whole query unless the box's own configured NetFlow active timeout is at least the 45m observation window.",
             absent="Default noDataState (Ok) - a healthy hook, an interface not configured for capture, or a box whose active timeout is shorter than 45m (clause 4's honesty guard) all produce no series here, which is the intended quiet state.",
             checks=[
                'Check opnsense_netflow_capture_active_timeout_seconds FIRST if you believe a hook is dead but this never fires - a box with a shorter active timeout is structurally excluded by clause 4',
                "Open the operator console's NetFlow/ifIndex tab and confirm the device label is a real ng_netflow node with `ngctl list` on the box",
                "Read docs/flow.md ('Joining the two label spaces') for the full query derivation before changing this rule",
            ],
             causes=[
                "The capture hook was bound to the wrong kernel device (e.g. a PPPoE interface's framing node rather than its actual ng_iface) - the #368 pattern",
                'The ng_netflow hook was silently dropped by a reconfiguration and never rebound',
            ],
             verify=[
                'opnsense_netflow_cache_packets_total for the device resumes counting - the alert resolves automatically once it does',
            ],
         )),
]

# Recording rules: metric name (level:metric:operation) + value query.
RECORDING = [
    dict(metric="instance:opnsense_interface_rx_bits:rate5m",
         expr="sum by (opnsense_instance, interface) (rate(opnsense_interfaces_received_bytes_total[5m])) * 8"),
    dict(metric="instance:opnsense_interface_tx_bits:rate5m",
         expr="sum by (opnsense_instance, interface) (rate(opnsense_interfaces_transmitted_bytes_total[5m])) * 8"),
    dict(metric="instance:opnsense_firewall_block_packets:rate5m",
         expr="sum by (opnsense_instance, interface) ("
              "rate(opnsense_firewall_in_ipv4_block_packets_total[5m]) + rate(opnsense_firewall_out_ipv4_block_packets_total[5m]) + "
              "rate(opnsense_firewall_in_ipv6_block_packets_total[5m]) + rate(opnsense_firewall_out_ipv6_block_packets_total[5m]))"),
    dict(metric="instance:opnsense_pf_state:utilization",
         expr="opnsense_firewall_pf_states_current / (opnsense_firewall_pf_states_limit > 0)"),
    dict(metric="instance:opnsense_unbound_cache:hit_ratio",
         expr="rate(opnsense_unbound_dns_cache_hits_total[5m]) / "
              "(rate(opnsense_unbound_dns_cache_hits_total[5m]) + rate(opnsense_unbound_dns_cache_miss_total[5m]) > 0)"),
    dict(metric="instance:opnsense_unbound_queries:rate5m",
         expr="rate(opnsense_unbound_dns_queries_total[5m])"),
    dict(metric="instance:opnsense_gateway_loss:ratio",
         expr="opnsense_gateways_loss_percentage / 100"),
    dict(metric="instance:opnsense_system_mem:utilization",
         expr="opnsense_system_memory_used_bytes / (opnsense_system_memory_total_bytes > 0)"),
    dict(metric="instance:opnsense_zenarmor_block:ratio5m",
         expr='sum by (opnsense_instance) (rate(opnsense_log_events_zenarmor_total{action="block"}[5m])) / '
              '(sum by (opnsense_instance) (rate(opnsense_log_events_zenarmor_total[5m])) > 0)'),
    dict(metric="instance:opnsense_haproxy_5xx:ratio5m",
         expr='sum by (opnsense_instance, backend) (rate(opnsense_log_events_haproxy_total{status_class="5xx"}[5m])) / '
              '(sum by (opnsense_instance, backend) (rate(opnsense_log_events_haproxy_total[5m])) > 0)'),
    dict(metric="instance:opnsense_ipsec_tunnels_down:count",
         expr="sum by (opnsense_instance) (opnsense_ipsec_phase1_status == bool 0)"),
    dict(metric="instance:opnsense_wireguard_peers_down:count",
         expr="sum by (opnsense_instance) (opnsense_wireguard_peer_status == bool 0)"),
    dict(metric="instance:opnsense_ids_alerts:active",
         expr='sum by (opnsense_instance) (opnsense_ids_recent_alerts{action="blocked"})'),
    # Pins source="netflow" deliberately. The flow family carries TWO independent measurements of the
    # same traffic (Zenarmor and NetFlow) and #346 decision 3 forbids summing them; NetFlow post-repair
    # is authoritative for volume, so pinning it here gives a double-count-safe per-WAN byte rate that
    # dashboards and alerts can build on without every query having to remember the source filter.
    dict(metric="instance:opnsense_flow_bytes:rate5m",
         expr='sum by (opnsense_instance, interface, direction) '
              '(rate(opnsense_flow_bytes_total{source="netflow"}[5m]))'),
]

def grafana_for(for_min: int) -> str:
    return "0s" if not for_min else f"{for_min}m0s"


def emit_grafana_managed(ds: str, folder: str, stack: bool):
    outdir = os.path.join(HERE, "grafana-managed")
    os.makedirs(outdir, exist_ok=True)
    for stale in os.listdir(outdir):  # clear stale manifests so renames don't linger
        if stale.endswith(".json"):
            os.remove(os.path.join(outdir, stale))
    written = []
    # Folder manifest (named so its UID == folder); pushed first so the rules resolve.
    folder_manifest = {
        "apiVersion": "folder.grafana.app/v1beta1", "kind": "Folder",
        "metadata": {"name": folder},
        "spec": {"title": "OPNsense Exporter Alerts"},
    }
    fp = os.path.join(outdir, "_folder.json")
    with open(fp, "w") as f:
        json.dump(folder_manifest, f, indent=2)
        f.write("\n")
    written.append(fp)
    for r in RULES:
        labels = {"severity": r["severity"]}
        if stack:
            labels["domain"] = "infra"
            if r["severity"] == "critical":
                labels["page"] = "true"
        cond = {"evaluator": {"type": r["op"], "params": r["params"]},
                "operator": {"type": "and"}, "query": {"params": []},
                "reducer": {"type": "last", "params": []}, "type": "query"}
        manifest = {
            "apiVersion": "rules.alerting.grafana.app/v0alpha1", "kind": "AlertRule",
            "metadata": {"name": r["name"],
                         "annotations": {"grafana.app/folder": folder},
                         "labels": {"grafana.app/folder": folder}},
            "spec": {
                "title": r["title"], "noDataState": r.get("nodata", "Ok"),
                "execErrState": "Error", "for": grafana_for(r["for_min"]),
                "trigger": {"interval": "1m"}, "labels": labels,
                "annotations": {"summary": r["summary"], "description": r["description"],
                                "runbook_url": runbook_url(r["title"])},
                "expressions": {
                    "A": {"datasourceUID": ds,
                          "relativeTimeRange": {"from": "15m0s", "to": "0s"},
                          "model": {"datasource": {"type": "prometheus", "uid": ds},
                                    "editorMode": "code", "expr": r["A"], "instant": True,
                                    "range": False, "intervalMs": 60000,
                                    "maxDataPoints": 43200, "refId": "A"}},
                    "C": {"model": {"datasource": {"type": "__expr__", "uid": "__expr__"},
                                    "expression": "A", "type": "threshold", "refId": "C",
                                    "intervalMs": 1000, "maxDataPoints": 43200,
                                    "conditions": [cond]},
                          "source": True},
                },
            },
        }
        p = os.path.join(outdir, f"{r['name']}.json")
        with open(p, "w") as f:
            json.dump(manifest, f, indent=2)
            f.write("\n")
        written.append(p)
    for r in RECORDING:
        labels = {"domain": "infra"} if stack else {}
        # Grafana rule UIDs are capped at 40 chars; keep the slug compact.
        short = (r["metric"].replace("instance:opnsense_", "").replace("opnsense_", "")
                 .replace(":", "-").replace("_", "-"))
        slug = "oxrec-" + short
        manifest = {
            "apiVersion": "rules.alerting.grafana.app/v0alpha1", "kind": "RecordingRule",
            "metadata": {"name": slug,
                         "annotations": {"grafana.app/folder": folder},
                         "labels": {"grafana.app/folder": folder}},
            "spec": {"title": r["metric"], "metric": r["metric"],
                     "targetDatasourceUID": ds, "paused": False,
                     "trigger": {"interval": "1m"}, "labels": labels,
                     "expressions": {"A": {"datasourceUID": ds,
                                           "relativeTimeRange": {"from": "10m0s", "to": "0s"},
                                           "model": {"datasource": {"type": "prometheus", "uid": ds},
                                                     "editorMode": "code", "expr": r["expr"],
                                                     "format": "table", "instant": True,
                                                     "range": False,
                                                     "intervalMs": 1000, "maxDataPoints": 43200,
                                                     "refId": "A"},
                                           "source": True}}},
        }
        p = os.path.join(outdir, f"{slug}.json")
        with open(p, "w") as f:
            json.dump(manifest, f, indent=2)
            f.write("\n")
        written.append(p)
    return outdir, written


# #430: the top-level heading whose slug RUNBOOK_URL's anchor names (grafana/uids.py).
# Kept as one literal, asserted against RUNBOOK_URL below, so the two can never drift -
# a renamed heading here without updating uids.py fails the build instead of shipping a
# dead index link.
RUNBOOKS_MD_TITLE = "Alerts & Recording Rules"


RUNBOOK_KEYS = ("measures", "threshold", "absent", "checks", "causes", "verify")


def require_complete_runbook(name: str, rb: dict) -> None:
    """Every rule's runbook=dict(...) must carry all six keys, each non-empty. Raises
    ValueError (a hard build failure, not a silent skip) otherwise - called from
    `_runbook_section` so a missing/incomplete runbook fails `make rules` itself, not
    just a test that happens to be run."""
    for key in RUNBOOK_KEYS:
        if key not in rb:
            raise ValueError(f"{name}: runbook is missing required key {key!r}")
        value = rb[key]
        if isinstance(value, list):
            if not value or any(not str(item).strip() for item in value):
                raise ValueError(f"{name}: runbook[{key!r}] is empty or has a blank entry")
        elif not str(value).strip():
            raise ValueError(f"{name}: runbook[{key!r}] is empty")


def _runbook_section(r: dict) -> str:
    rb = r["runbook"]
    require_complete_runbook(r["name"], rb)

    def bullets(items):
        return "\n".join(f"- {item}" for item in items)

    exempt_note = ""
    if r["name"] in SUMMARY_INSTANCE_EXEMPT:
        exempt_note = (
            "\n**Instance identity:** this alert's summary does not carry "
            "`opnsense_instance` - "
            f"{SUMMARY_INSTANCE_EXEMPT[r['name']]}\n"
        )

    return (
        f"## {r['title']}\n\n"
        f"**Severity:** {r['severity']}  \n"
        f"**Pending window:** {grafana_for(r['for_min'])}  \n"
        f"**Rule name:** `{r['name']}`\n\n"
        "**Expression:**\n"
        "```promql\n"
        f"{r['A']}\n"
        "```\n\n"
        f"**What it measures:** {rb['measures']}\n\n"
        f"**Threshold & window:** {rb['threshold']}\n\n"
        f"**Absent / no-data semantics:** {rb['absent']}\n\n"
        f"**First checks:**\n{bullets(rb['checks'])}\n\n"
        f"**Likely causes:**\n{bullets(rb['causes'])}\n\n"
        f"**Verify recovery:**\n{bullets(rb['verify'])}\n"
        f"{exempt_note}"
    )


def _recording_section(r: dict) -> str:
    return (
        f"### {r['metric']}\n\n"
        "```promql\n"
        f"{r['expr']}\n"
        "```\n"
    )


def generate_runbooks_md() -> str:
    """Render `grafana/runbooks.md` (#430): one `## <Title>` section per alert in RULES
    order (exact 1:1 with the manifests `emit_grafana_managed` writes, from the same
    source list), followed by a recording-rule section covering all of RECORDING.
    `runbook_url()` in uids.py builds the per-alert anchor into this same document, and
    `grafana/alerts/validate_manifests.py` checks it actually resolves here."""
    title_slug = None
    try:
        from uids import github_heading_slug
        title_slug = github_heading_slug(RUNBOOKS_MD_TITLE)
    except ImportError:  # pragma: no cover - uids.py is always on sys.path in this repo
        pass
    expected_anchor = RUNBOOK_URL.rsplit("#", 1)[1]
    if title_slug != expected_anchor:
        raise RuntimeError(
            f"RUNBOOKS_MD_TITLE {RUNBOOKS_MD_TITLE!r} slugs to {title_slug!r}, which does "
            f"not match RUNBOOK_URL's anchor {expected_anchor!r} (grafana/uids.py) - keep "
            "them in sync or the dashboard's 'Alert runbooks' link 404s"
        )

    parts = [
        "<!-- GENERATED FILE. Do not hand-edit; run `make rules` "
        "(grafana/alerts/build_rules.py). -->",
        "",
        f"# {RUNBOOKS_MD_TITLE}",
        "",
        "One section per alert rule in `grafana/alerts/build_rules.py`'s `RULES`, in "
        "source order, followed by every recording rule in `RECORDING`. Each alert "
        "section states what its expression measures, its threshold and window, what "
        "absent/no-data means for that specific rule, first checks, likely causes, and "
        "how to confirm it has genuinely recovered - mined from the same source comments "
        "and descriptions that drive the generated manifests, so this document and the "
        "alert's own annotations can never contradict each other.",
        "",
        f"Total: **{len(RULES)} alert rules** and **{len(RECORDING)} recording rules**.",
        "",
    ]
    for r in RULES:
        parts.append(_runbook_section(r))
    parts.append("## Recording rules")
    parts.append("")
    parts.append(
        "Precomputed PromQL expressions following the "
        "`instance:opnsense_<subsystem>_<measurement>:<op>` naming convention. These are "
        "plain recording rules with no alerting semantics of their own - they exist to "
        "keep a common aggregation/ratio computed once for dashboards and other rules to "
        "reuse."
    )
    parts.append("")
    for r in RECORDING:
        parts.append(_recording_section(r))
    return "\n".join(parts).rstrip() + "\n"


def write_runbooks_md() -> str:
    content = generate_runbooks_md()
    with open(RUNBOOKS_MD_PATH, "w") as f:
        f.write(content)
    return RUNBOOKS_MD_PATH


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--datasource", default="grafanacloud-prom")
    ap.add_argument("--folder", default="opnsense-alerts")
    ap.add_argument("--stack", action="store_true",
                    help="add IRM label contract (domain=infra; page=true on critical)")
    args = ap.parse_args()

    outdir, written = emit_grafana_managed(args.datasource, args.folder, args.stack)
    print(f"wrote {len(written)} grafana-managed manifests to {outdir}")
    print(f"alerts: {len(RULES)}  recording rules: {len(RECORDING)}  stack-labels: {args.stack}")

    runbooks_path = write_runbooks_md()
    print(f"wrote runbooks to {runbooks_path}")


if __name__ == "__main__":
    main()
