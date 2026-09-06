# Adding a collector

The registration contract spans eight files. Most steps have a unit test that fails when skipped, so
a partial job fails loudly rather than shipping a dead flag; the two that do not are marked.

## Code

1. Create `internal/collector/<subsystem>.go` implementing `CollectorInstance` (`Name()`,
   `Register()`, `Describe()`, `Update()`) with an `init()` that appends to `collectorInstances`.
   Registration is by `init()` only - there is no central list to edit.
2. Assign a poll tier in `collectorTiers` (`internal/collector/interval_tiers.go`) if the data is not
   medium-volatility. Absent from that table means the 60s medium default. Operators override any
   collector with `--collector.poll-interval-override=<collector>=<dur>`.
3. Add `Fetch<Subsystem>()` in `opnsense/` with its data structs and register its endpoints in
   `defaultEndpoints()` (`opnsense/client.go`). Tests build their client from `defaultEndpoints()`
   directly and `TestNewClient_EndpointCount` asserts content-equality; bump the count in
   `opnsense/client_test.go`. For a plugin-gated endpoint, treat 404 as "feature absent" - return
   empty data and `nil`, mirroring `FetchACMECertificates` - so the collector stays silent when the
   plugin is missing.
4. POST endpoints only (`c.do("POST", ...)` or `c.doForm(...)`): add the endpoint-name key to
   `postEndpoints` (`opnsense/contract.go`) and bump the golden POST count in
   `opnsense/contract_test.go`. GET endpoints derive automatically.
5. Plugin-gated endpoints: add the endpoint name to `NegativeCacheable404Endpoints()`
   (`opnsense/cache.go`), GET or POST, so boxes without the plugin stop re-asking every scrape.
   Never list a core endpoint there - a cached 404 on `healthCheck` would keep reporting a recovered
   firewall as down, and a test enforces this.
6. Add the response struct to `schemaRegistry` (`opnsense/schema_registry.go`) and run `just schemas`.
   POST endpoints also need their request body in `captureRequests`
   (`opnsense/capture_requests.go`). These feed the daily live-box schema canary (`cmd/apidrift`,
   `.github/workflows/live-canary.yml`). Golden schemas are structure-only, key paths and JSON types:
   never commit response values.
7. Add a `<Subsystem>Subsystem` const and a `Without<Subsystem>Collector()` option in
   `internal/collector/collector.go`, plus the display name in `SubsystemDisplayNames`.
8. Add the flag, the `CollectorsDisableSwitch` field, the switch entry and the `CollectorFlags`
   binding in `internal/options/collectors.go`. Use `exporter.disable-*` (default-on) for
   low-cardinality collectors; reserve `exporter.enable-*` (default-off) for collectors with extra
   per-scrape API cost or high cardinality.
9. Wire it in `main.go` (`if !collectorsSwitches.<X> { ... WithoutXCollector() }`).
   `TestEveryDisableSwitchWiredInMain` reflects every switch field against `main.go`, so a documented
   flag cannot silently be a no-op.

## Two 404 lists, two different questions

`NegativeCacheable404Endpoints()` answers "may this 404 be cached?". `PluginGatedEndpoints()` answers
"does this 404 mean a plugin is absent?". The second is a superset and is what the canary and
`opnsense/acl.go` read. They differ when the real request path carries a query string the cache key
does not (`vnstatGetJsonData`'s `?iface=`), which makes a TTL a no-op while the 404 is still
plugin-absence. An endpoint in that shape goes in `PluginGatedEndpoints()` only, or the canary files
its 404 as "core route vanished upstream".

## What may be cached

The client has a per-endpoint TTL response cache (`opnsense/cache.go`), opt-in per endpoint. Two
rules, and they are not the same rule.

- **A successful body** may be cached only for a **GET**, and only if the payload is wholly
  slow-moving. Anything carrying a counter, a rate or a live status (a service's running state, a
  link's up/down) freezes the series and invents flat `rate()` plateaus. A POST body is never cached:
  `smartInfo` is POSTed once per device, so replaying one response would return another device's data.
- **A 404** may be cached for **any method** including POST, and even for endpoints whose success
  payload is live. A 404 is a property of the route (`{"errorMessage":"Endpoint not found"}`, the
  plugin is not installed), not of the request body, so it changes only when an admin installs the
  plugin. Verified against a live OPNsense 26.1: a bad *resource* does not 404 - `smartInfo` with a
  nonexistent device returns 200 `{"message":"Invalid device name"}`.

## Docs and dashboard

Run `just docs` and commit the result; `just docs-check` fails on stale generated docs or an invalid
doc flag/env token. Never hand-edit content between `<!-- docgen:begin/end -->` markers.

Every catalogue metric must appear on the Grafana dashboard. Add panels to the relevant tab module
under `grafana/tabs/` (`grafana/tabs/AUTHORING.md` has the builder API) or a new module wired into
`register_subsystem_tabs` in `grafana/build_dashboard.py`, then run `just dashboard` - it exits
non-zero in both write and `--check` mode if a catalogue metric is left off. Alert and recording
rules go in `grafana/alerts/build_rules.py` via `just rules`. `just grafana-check` gates all of it.
