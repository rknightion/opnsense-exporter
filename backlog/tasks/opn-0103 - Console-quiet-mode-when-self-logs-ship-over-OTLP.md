---
id: OPN-0103
title: Console quiet mode when self-logs ship over OTLP
status: In Progress
assignee:
  - '@claude-opus'
created_date: '2026-09-06 14:30'
updated_date: '2026-09-06 15:07'
labels: []
dependencies: []
priority: high
type: feature
ordinal: 57000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
OPN2OTEL_LOGS_SELF_ENABLED tees the slog stream: SelfLogHandler wraps the promslog stderr handler (main.go, logship.NewSelfLogHandler) and adds an OTLP record per line, so stderr is unchanged. On camden the Fleet-managed docker integration already ships the container stderr to Loki (job="integrations/docker", container="opnsense2otel"), so enabling self-logs there now lands every line twice. Camden has enabled self-logs anyway (2026-09-06) because the OTLP path carries the exporter resource attributes (opnsense_source="exporter", service_instance_id, opnsense_subsystem) that the docker path cannot. The exporter needs a way to make the OTLP path the only one, and the health dashboard should read that stream rather than the docker one.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A new flag/env (name to be chosen, e.g. --log.console=quiet|full with OPN2OTEL_LOG_CONSOLE) suppresses the stderr copy of records that the self-log adapter accepted, while records emitted before the OTLP sink is ready, and any record the sink cannot take, still reach stderr
- [x] #2 Quiet mode is rejected by --config.check and at startup unless --logs.self.enabled is on, with an error naming both flags
- [x] #3 Startup and shutdown self-log loss (OPN-0073) remains observable in quiet mode: the shutdown flush drains the self-log path before the process exits, and losses are counted
- [x] #4 The health dashboard (grafana/dashboard-health.json via grafana/build_dashboard.py) gains a Loki panel for exporter self-logs selecting {opnsense_source="exporter"} scoped by $opnsense_instance, and any existing panel or runbook pointing at the docker container log stream is updated to that selector
- [x] #5 docs/log-shipping.md documents the quiet mode, the duplicate-with-docker-integration case that motivates it, and the operator choice between the two paths
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Add --log.console (OPN2OTEL_LOG_CONSOLE, enum full|quiet, default full) in internal/options/log_console.go with a pure ValidateLogConsole(console, selfEnabled) naming both flags; call it from resolveOptions beside ValidateLogsSelf so --config.check and a real start share the rule.
2. Teach logship.SelfLogHandler a quiet-console mode via a variadic option (NewSelfLogHandler(next, WithQuietConsole(bool))): submit() returns whether the pipeline accepted the record; in quiet mode Handle submits first and writes stderr ONLY when the record was not accepted (pre-bind buffer, post-Unbind, queue reject). Full mode keeps today's stderr-first ordering. DiagnosticLogger and the startup-overflow diagnostic keep bypassing the adapter, so they always reach stderr.
3. Tests first: selflog quiet cases (pre-bind to stderr, accepted suppressed, rejected/overflowed to stderr, Unbind drain unchanged, overflow diagnostic still printed, WithAttrs/WithGroup clones stay quiet) and options tests for the flag registration + validator.
4. Wire main.go: pass options.LogConsoleQuiet() into NewSelfLogHandler.
5. Dashboard: add a Loki self-log panel + has_self_logs sentinel to grafana/tabs/logs.py on the Log Shipping tab, selector loki_sel('opnsense_source="exporter"'); regenerate with just dashboard. Record the grep proving no existing panel/runbook points at the docker container stream.
6. Docs: document quiet mode in docs/log-shipping.md (duplicate-with-docker-integration motivation and the operator choice); regenerate the flag tables with just docs.
7. Gate: just check.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented in this worktree (uncommitted; the main thread commits).

Flag: --log.console, OPN2OTEL_LOG_CONSOLE, enum full|quiet, default full (internal/options/log_console.go). Named after AC #1's suggestion and the existing --log.level/--log.format family; an enum rather than a --log.no-console boolean because the choice is which copy is authoritative, not whether to log. Pure ValidateLogConsole(console, selfEnabled) called from resolveOptions beside ValidateLogsSelf, so --config.check and a real start share one rule (TestConfigValidationCannotDriftFromStartup enforces that placement).

Suppression is per record and decided by the pipeline: SelfLogHandler.submit now RETURNS whether enqueue accepted the record, and in quiet mode Handle submits first and writes stderr only when it did not. Not accepted, therefore still on stderr: records buffered before Bind (startup), records after Unbind (shutdown), records a full queue refuses, the bounded self-log startup buffer overflow diagnostic (written direct to the wrapped handler), and everything on DiagnosticLogger (sink/retry/delivery diagnostics, which never enter the adapter). Full mode keeps today's stderr-first ordering. Quiet is carried through WithAttrs/WithGroup clones. Constructed via a variadic option (logship.WithQuietConsole(bool)) so the 12 existing call sites are untouched.

Loss accounting is unchanged: rejected self-log records are still counted on opnsense_exporter_logs_dropped_total{source=exporter} by pipeline.noteOverflow/enqueue, and Unbind still blocks on in-flight callbacks (OPN-0073 AC2) before the queue closes.

Red-then-green proof for the suppression itself: with the quiet branch in Handle temporarily disabled, TestSelfLogHandlerQuietConsoleSuppressesAcceptedRecords, ...SurvivesWithAttrsAndWithGroup and ...FollowsPerRecordAcceptance FAIL; restored, all 9 quiet/full console tests pass.

Dashboard: grafana/tabs/logs.py gains loki_sentinel has_self_logs and a 24-wide logs panel 'Exporter Self-Logs' on Health > Delivery > Log Shipping, collapsed row. LogQL: {service_instance_id=~$opnsense_instance,opnsense_source=exporter, opnsense_subsystem=self}. AC #4's 'any existing panel or runbook pointing at the docker container log stream' clause: there is none - a recursive case-insensitive search for integrations/docker, container=opnsense2otel, job=integrations, container_name=~ and compose_service over grafana/ docs/ charts/ deploy/ returns nothing, and grafana/runbooks.md is generated by build_rules.py and did not change. Regenerating shifted health panel ids by one, so build_rules.py rewrote __panelId__ in 10 grafana-managed alert manifests (e.g. opnsense2otel-down.json 102 -> 103); that is generator output, included in the diff.

Docs: docs/log-shipping.md gains a 'Console quiet mode (--log.console)' subsection under Exporter self-logs - the duplicate-with-docker-integration motivation, the exact list of what still reaches stderr, the two-path operator choice as a table, and the compose snippet. Generated surfaces (docs/configuration.md, .env.example, docs/deployment/reference.md, charts/opnsense2otel/values.yaml) picked the flag up from just docs; not hand-edited.

Gate: just check EXIT=0. Tail: 'validated 1248 Prometheus targets, 125 variable queries, 22 annotation queries and 78 rule expressions / validated 80 grafana-managed manifests: OK / govulncheck: No vulnerabilities found.' The regenerated artifacts were staged to the index first (not committed) because grafana-check's staleness leg diffs the index against the worktree; without staging it reports the uncommitted regeneration as drift.

DoD #2 left unchecked deliberately: just gen ran (just docs, just dashboard, and build_rules.py via grafana-check) and every regenerated artifact is in the worktree diff, but the commit is the main thread's - check it with the SHA.
<!-- SECTION:NOTES:END -->
