---
title: Metrics Reference
description: Overview of all 320+ Prometheus metrics exposed by the OPNsense Exporter
tags:
  - Prometheus
  - Monitoring
---

# Metrics Reference

The OPNsense Exporter provides 320+ Prometheus metrics across 26 collectors, covering every major subsystem of the OPNsense firewall platform.

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

- **320+ metrics** across 26 collectors
- **Naming convention:** `opnsense_<subsystem>_<metric_name>`
- **Common label:** `opnsense_instance` on every metric
- **Metric types:** Gauge (most metrics), Counter (`_total` suffix)
- **Top-level health:** `opnsense_up`, `opnsense_firewall_status`, `opnsense_system_status_code`

!!! info "Auto-generated reference"
    The [Complete Reference](metrics.md) page is auto-generated from the exporter source code by a docgen tool. It is always up to date with the latest release.
