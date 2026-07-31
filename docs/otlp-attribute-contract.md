# OTLP attribute contract

Rules for naming and placing custom OTLP attributes, written to be referenced by every
exporter writing into the same Loki tenant - this one, `tailscale2otel` and `graph2otel`.
The rules are not specific to OPNsense; they exist because Loki's promotion model has
three properties that are easy to get wrong, and two of them have already produced a
broken tenant config.

## The one structural rule

**Only OTLP *resource* attributes can become index labels.** `otlp_config` has an
`index_label` action under `resource_attributes` and nowhere else; `scope_attributes`
and `log_attributes` accept `structured_metadata` and `drop` only. A log attribute is
therefore unindexable by construction, not by configuration - no tenant setting makes it
a label.

This is the whole reason placement matters more than naming. An attribute on the record
is a query-time filter forever; an attribute on the resource *can* be promoted later.

A non-promoted resource attribute is not lost - it lands in structured metadata, exactly
where a log attribute would. So moving a key onto the resource is query-compatible until
someone promotes it, which is what makes "hoist now, promote later" safe.

## The two limits, which are not the same limit

These get conflated, and conflating them produces an imaginary scarcity that drives bad
design.

| Limit | What it bounds | Shared between exporters? |
| --- | --- | --- |
| `max_label_names_per_series`, default **15** | Label names on a **single stream**. Enforced by the distributor at ingest; breach is a non-retryable `400`. | **No** |
| Grafana Cloud self-serve cap, recorded as **30** | Length of the tenant's promoted-attribute **list**. | **Yes** |

The 15 is per stream. A `tailscale2otel` stream never carries an `opnsense_*` label, so
promoting `opnsense.*` costs the other exporters nothing and each gets its own 15.

What *is* shared is the tenant's `attributes_config` list. Adding entries to it is
additive and cannot affect another exporter's streams, but it is one list, so edits to it
are a coordinated change. The 30 is recorded from the self-serve API rather than
re-verified on every read; the arithmetic below has enough headroom that it does not
turn on the exact figure.

## Naming rules

1. **Namespace every custom resource attribute under an emitter prefix** - `opnsense.*`,
   `tailscale.*`, `graph2otel.*`.
2. **Never bare, unnamespaced names** (`source`, `action`, `interface`). They collide
   with future semconv, and a first draft of this tenant's config reached for exactly
   these.
3. **Never squat a semconv namespace with a different meaning.** semconv `device.*` means
   *the device the telemetry originates from*. Using it for an observed network client is
   a reserved name carrying a foreign meaning - worse than a private namespace. Using a
   genuine semconv name where the meaning actually matches is fine and preferred.
4. **Emitter-specific, not shared.** Two exporters do not share a dimension unless the
   *values* mean the same thing. A unified `subsystem` matching both an OPNsense DNS
   record and something else's leaves `service.name` as the only disambiguator, which is
   what you already had.
5. **Only promote closed, code-defined sets.** Anything that arrives off a wire is
   attacker-influenceable cardinality. `program` comes off syslog and any process can
   pick its own tag with `logger(1)`, so it stays on the record.

## Tenant config rules

**Names in the config are dotted, as sent.** Loki matches the OTLP attribute name and
does the dot-to-underscore conversion itself on the way to the label. The config says
`opnsense.source` and `service.instance.id`; `opnsense_source` and `service_instance_id`
match nothing.

**`ignore_defaults: true` requires re-listing `service.name` and `service.instance.id`.**
Both are on the distributor's default promotion list, which is why they are labels with
no config at all. Dropping the defaults without re-listing them removes them as labels
and breaks every existing query against the tenant - a strictly worse outcome than the
new labels simply failing to appear.

**`PUT` fully replaces the tenant `otlp_config`.** GET, merge, PUT. Never a blind partial
write. Changes return `pending` and can take a couple of business days to become
`applied`.

**A key's presence in `series` output is proof of promotion**, because `series` returns
stream labels only and structured metadata cannot appear there:

```
gcx datasources loki series -d grafanacloud-logs --match '{opnsense_source=~".+"}'
```

Check the deployed build first, or "not promoted" and "not deployed" are
indistinguishable.

## Hoisting is not free

An OTLP resource binds to a `LoggerProvider`, not to a record. So N distinct values of a
shape dimension means N `LoggerProvider`s. In this repo that is the machinery in
`internal/logship/sink_otlp.go`: a provider map keyed on `resourceKey`, one shared
exporter so partitioning costs no extra connections, deterministic per-partition flush
ordering, a `maxLogResources` cap, and a degrade path that drops the custom attributes
once the cap is hit.

Adopting the *naming* is free. Hoisting a dimension onto the resource is not, and any
exporter wanting a promoted label needs that pattern rather than a rename. Weigh it per
repo against what a promoted label actually buys - which is query scan, never ingest
cost.

## Current registry

| Exporter | Custom resource attributes | Promoted |
| --- | --- | --- |
| `opnsense2otel` | `opnsense.source`, `opnsense.subsystem`, `opnsense.action`, `opnsense.device_category`, `opnsense.interface` | all five |
| `tailscale2otel` | none | none |
| `graph2otel` | none | none |

The siblings' domain attributes are **log** attributes, so they are unindexable as they
stand. Neither is blocked on naming; both would need the hoisting work above first.

Widest stream this exporter produces carries seven label names - the five above plus
`service_name` and `service_instance_id` - against a per-stream limit of 15.

## Decision record

Per-emitter namespaces, no shared namespace, and no migration of `opnsense.*`.

The case for a shared namespace rested on the three exporters competing for a tenant-wide
pool of ~15 promotion slots. They do not: the 15 is per stream, so the pool was never
shared and the per-emitter approach scales past the third exporter and past the tenth.
Without that pressure, a shared namespace buys cross-exporter selector ergonomics and
costs a dual-label transition on a live tenant for the only repo with promoted labels -
13 stream selectors, and every historical line keeping the old label until retention
rolls over.

Reconsider only if the exporters ever need to be queried as one stream set, which is a
different requirement from the one that motivated this.
