---
title: Adding a Collector
description: Step-by-step guide for adding a new collector to the OPNsense Exporter
tags:
  - OPNsense
---

# Adding a Collector

This guide walks through adding a new collector to the OPNsense Exporter. The process involves five steps across three packages.

## Overview

1. Create the collector file in `internal/collector/`
2. Add an `init()` function for auto-registration
3. Add a `Fetch*()` method and data structs in `opnsense/`
4. Add a disable flag in `internal/options/collectors.go`
5. Wire the disable flag in `internal/collector/collector.go` and `main.go`

## Step 1: Create the collector

Create a new file `internal/collector/<subsystem>.go` implementing the `CollectorInstance` interface:

```go title="internal/collector/example.go"
package collector

import (
    "log/slog"

    "github.com/prometheus/client_golang/prometheus"
    "github.com/rknightion/opnsense-exporter/opnsense"
)

type exampleCollector struct {
    log           *slog.Logger
    instanceLabel string

    // Define your metric descriptors
    exampleGauge *prometheus.Desc
    exampleTotal *prometheus.Desc
}

func init() {
    collectorInstances = append(collectorInstances, &exampleCollector{})
}

func (c *exampleCollector) Name() string {
    return "example" // Must match a subsystem constant
}

func (c *exampleCollector) Register(namespace, instance string, log *slog.Logger) {
    c.log = log
    c.instanceLabel = instance

    c.exampleGauge = prometheus.NewDesc(
        prometheus.BuildFQName(namespace, "example", "value"),
        "Description of the metric",
        []string{"label1", "label2"},  // variable labels
        prometheus.Labels{
            instanceLabelName: instance,
        },
    )

    c.exampleTotal = prometheus.NewDesc(
        prometheus.BuildFQName(namespace, "example", "items_total"),
        "Total number of example items",
        nil,
        prometheus.Labels{
            instanceLabelName: instance,
        },
    )
}

func (c *exampleCollector) Describe(ch chan<- *prometheus.Desc) {
    ch <- c.exampleGauge
    ch <- c.exampleTotal
}

func (c *exampleCollector) Update(
    client *opnsense.Client,
    ch chan<- prometheus.Metric,
) *opnsense.APICallError {
    data, err := client.FetchExample()
    if err != nil {
        return err
    }

    // Emit the total count
    ch <- prometheus.MustNewConstMetric(
        c.exampleTotal,
        prometheus.GaugeValue,
        float64(len(data.Items)),
    )

    // Emit per-item metrics
    for _, item := range data.Items {
        ch <- prometheus.MustNewConstMetric(
            c.exampleGauge,
            prometheus.GaugeValue,
            item.Value,
            item.Label1,
            item.Label2,
        )
    }

    return nil
}
```

## Step 2: Auto-registration

The `init()` function in the collector file (shown above) handles registration. It appends the collector instance to the global `collectorInstances` slice. No changes to any central registry file are needed.

Add a subsystem constant to `internal/collector/collector.go`:

```go
const ExampleSubsystem = "example"
```

## Step 3: Add the API fetch method

Create or modify a file in `opnsense/` to add the fetch method and data structures:

```go title="opnsense/example.go"
package opnsense

// ExampleData represents the API response structure
type ExampleData struct {
    Items []ExampleItem `json:"items"`
}

type ExampleItem struct {
    Label1 string  `json:"label1"`
    Label2 string  `json:"label2"`
    Value  float64 `json:"value"`
}

// FetchExample retrieves example data from the OPNsense API
func (c *Client) FetchExample() (*ExampleData, *APICallError) {
    var data ExampleData

    url, ok := c.endpoints["example"]
    if !ok {
        return nil, &APICallError{
            Endpoint: "example",
            Err:      ErrEndpointNotFound,
        }
    }

    if err := c.do("GET", url, &data); err != nil {
        return nil, &APICallError{
            Endpoint: string(url),
            Err:      err,
        }
    }

    return &data, nil
}
```

Register the endpoint in the client's endpoint map (in `opnsense/client.go` or the relevant setup):

```go
"example": "/api/example/endpoint",
```

## Step 4: Add the disable flag

Add a new flag in `internal/options/collectors.go`:

```go
exampleCollectorDisabled = kingpin.Flag(
    "exporter.disable-example",
    "Disable the scraping of example metrics",
).Envar("OPNSENSE_EXPORTER_DISABLE_EXAMPLE").Default("false").Bool()
```

Add the field to `CollectorsDisableSwitch`:

```go
type CollectorsDisableSwitch struct {
    // ... existing fields ...
    Example bool
}
```

Wire it in `CollectorsSwitches()`:

```go
func CollectorsSwitches() CollectorsDisableSwitch {
    return CollectorsDisableSwitch{
        // ... existing fields ...
        Example: !*exampleCollectorDisabled,
    }
}
```

## Step 5: Wire the disable flag

Add the `Without` option in `internal/collector/collector.go`:

```go
func WithoutExampleCollector() Option {
    return withoutCollectorInstance(ExampleSubsystem)
}
```

Wire it in `main.go`:

```go
if !collectorsSwitches.Example {
    collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutExampleCollector())
    logger.Info("example collector disabled")
}
```

## Testing

Add tests for the new collector in `internal/collector/example_test.go` and for the fetch method in `opnsense/example_test.go`.

Run the tests:

```bash
go test ./internal/collector/ -run TestExample
go test ./opnsense/ -run TestFetchExample
```

## Checklist

- [ ] Collector implements `CollectorInstance` interface
- [ ] `init()` function registers the collector
- [ ] Subsystem constant added to `collector.go`
- [ ] `Fetch*()` method and data structs added to `opnsense/`
- [ ] API endpoint registered in the client
- [ ] Disable flag added to `internal/options/collectors.go`
- [ ] `Without*()` option added to `collector.go`
- [ ] Disable logic wired in `main.go`
- [ ] Tests added and passing
- [ ] README "Changes from Upstream" section updated
