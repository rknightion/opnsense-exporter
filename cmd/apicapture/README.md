# apicapture — response-shape canary

The exporter has **two** API-drift canaries that cover different failure modes:

| Canary | Sees | Misses |
|--------|------|--------|
| **Endpoint manifest** (`cmd/apicontract`, `.github/workflows/api-contract.yml`) | Renamed/removed endpoints and GET↔POST verb drift, diffed against OPNsense source. | Response **body** changes — the path and verb are unchanged. |
| **Response shape** (`cmd/apicapture` + `opnsense.TestResponseContracts`) | Payload-shape drift at an unchanged endpoint: a moved/renamed field, an unrecognised status enum, data the structs silently stop consuming. | Anything no contract covers yet. |

The response canary exists because of a real miss: OPNsense **26.1** moved per-subsystem
health into a top-level `subsystems` map and changed the overall status to a string enum.
The endpoint (`api/core/system/status`, GET) was unchanged, so the endpoint canary saw nothing,
while the exporter silently reported a false-OK crash reporter, `system_status_code=0`, and a
spurious `opnsense_up=0`. The response contract asserts the data the collectors actually consume
still decodes into usable values, and flags any **new top-level key** (which is how the 26.1
`subsystems` data first appeared).

## How it works

- **Contracts** live in `opnsense/response_contract.go` (`ResponseContracts()`): each names an
  endpoint, the fixtures to check, its known top-level keys, and a semantic validator.
- **`TestResponseContracts`** runs in normal CI (`go test ./...`) over committed fixtures
  (`opnsense/testdata/health/*.json`) plus any local captures.
- **`make capture`** fetches the contract endpoints from a live box into the gitignored
  `opnsense/testdata/captures/` scratch dir so you can validate the **current** box's payloads.

## Catching a new release early

```bash
# Point at a beta/RC box (reuses the same OPS_* vars as `make local-run`):
OPS_ADDRESS=192.168.1.1 OPS_API_KEY=… OPS_API_SECRET=… OPS_INSECURE=1 make capture
go test ./opnsense/ -run TestResponseContracts -v
```

A red result means the box's response shape no longer matches what the exporter extracts — fix
the structs/accessors (with a fixture, TDD) before that OPNsense version reaches your fleet.

Captures may contain host/network data, so they are gitignored by default. To make a shape a
**permanent** CI gate, review a capture and copy it into a curated fixture, e.g.
`opnsense/testdata/health/v26_2_ok.json`.

## Adding a contract for another endpoint

1. `make capture` (or hand-capture) a real response; save a sanitised copy under
   `opnsense/testdata/<area>/`.
2. Add a `ResponseContract` entry in `opnsense/response_contract.go` with its `KnownTopLevelKeys`
   and a validator asserting the fields the collector consumes are populated.
3. `go test ./opnsense/ -run TestResponseContracts`.
