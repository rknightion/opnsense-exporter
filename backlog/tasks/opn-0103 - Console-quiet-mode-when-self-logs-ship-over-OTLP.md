---
id: OPN-0103
title: Console quiet mode when self-logs ship over OTLP
status: To Do
assignee: []
created_date: '2026-09-06 14:30'
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
- [ ] #1 A new flag/env (name to be chosen, e.g. --log.console=quiet|full with OPN2OTEL_LOG_CONSOLE) suppresses the stderr copy of records that the self-log adapter accepted, while records emitted before the OTLP sink is ready, and any record the sink cannot take, still reach stderr
- [ ] #2 Quiet mode is rejected by --config.check and at startup unless --logs.self.enabled is on, with an error naming both flags
- [ ] #3 Startup and shutdown self-log loss (OPN-0073) remains observable in quiet mode: the shutdown flush drains the self-log path before the process exits, and losses are counted
- [ ] #4 The health dashboard (grafana/dashboard-health.json via grafana/build_dashboard.py) gains a Loki panel for exporter self-logs selecting {opnsense_source="exporter"} scoped by $opnsense_instance, and any existing panel or runbook pointing at the docker container log stream is updated to that selector
- [ ] #5 docs/log-shipping.md documents the quiet mode, the duplicate-with-docker-integration case that motivates it, and the operator choice between the two paths
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
