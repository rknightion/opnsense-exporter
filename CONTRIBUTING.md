## Contributing

The full contribution guide — build commands, the complete test/lint/docs/Grafana gate, project
structure, and conventions — lives on the docs site and is the canonical source. This file
intentionally does not duplicate that content, so the two can't silently drift apart:

**[docs/development/contributing.md](docs/development/contributing.md)**
(rendered at <https://m7kni.io/opnsense-exporter/development/contributing/>)

What follows is specific to running the exporter against a real OPNsense box, which isn't otherwise
obvious from that guide.

### Requirements

- Go 1.26
- GNU Make
- Docker (optional)
- An OPNsense box with admin access

### Create an API key and secret in OPNsense

`System > Access > Users > [user] > API keys` — see the
[OPNsense documentation](https://docs.opnsense.org/development/how-tos/api.html#creating-keys).

### Run the exporter locally against that box

```bash
OPS_ADDRESS="ops.example.com" OPS_API_KEY=your-api-key OPS_API_SECRET=your-api-secret make local-run
curl http://localhost:8080/metrics
```

Before opening a PR, read the [contribution guide](docs/development/contributing.md) for the full
gate every PR must pass.
