---
title: Metrics Reference
description: Explore the 1,006 Prometheus metrics exposed by 65 opnsense2otel collectors across OPNsense firewall subsystems.
tags:
  - Prometheus
  - Monitoring
---

# Metrics Reference

opnsense2otel provides 1006 Prometheus metrics across 65 collectors, covering every major subsystem of the firewall platform.

Every metric on this page is generated from the collector source, so it always matches the shipped
binary. Read the collector implementations in
[`internal/collector/` on GitHub](https://github.com/rknightion/opnsense2otel/tree/main/internal/collector),
or [open an issue](https://github.com/rknightion/opnsense2otel/issues/new) if a metric you need
is missing.

<div class="grid cards" markdown>

-   :material-book-open-variant:{ .lg .middle } **Metrics Overview**

    ---

    Naming conventions, common labels, metric types, and PromQL examples.

    [:octicons-arrow-right-24: Overview](overview.md)

-   :material-format-list-bulleted:{ .lg .middle } **Complete Reference**

    ---

    Auto-generated list of every metric with type, labels, and help text.

    [:octicons-arrow-right-24: Complete reference](metrics.md)

</div>

## Quick facts

- **1006 metrics** across 65 collectors
- **Naming convention:** `opnsense_<subsystem>_<metric_name>`
- **Common label:** `opnsense_instance` on every metric
- **Metric types:** Gauge (most metrics), Counter (`_total` suffix)
- **Top-level health:** `opnsense_up`, `opnsense_firewall_status`, `opnsense_system_status_code`

!!! info "Auto-generated reference"
    The [Complete Reference](metrics.md) page is auto-generated from the exporter source code by a docgen tool. It is always up to date with the latest release.
