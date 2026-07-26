# Pull Request

## Description

Summarize the change and link the issue it addresses. Include relevant motivation/context and any dependencies this change requires.

Fixes # (issue)

## Type of change

Delete the options that don't apply.

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation only

## How has this been tested?

Delete if not relevant. Describe the tests you ran, and how to reproduce them.

- [ ] `go test ./...`
- [ ] Manual verification against a live OPNsense box

## Checklist

- [ ] If I added or changed a collector/metric, I ran `make docs` and committed the regenerated output. I did **not** hand-edit anything between `<!-- docgen:begin/end -->` markers — those are generated files (see `docs/metrics/metrics.md`, `docs/reference/collectors.md`, `docs/configuration.md`).
- [ ] If I added or changed a metric, I added the corresponding Grafana panel and ran `make dashboard` (see `grafana/README.md`).
- [ ] If I changed `go.mod`, I ran `make sync-vendor` and committed the vendor diff.
- [ ] I commented my code, particularly in hard-to-understand areas.
- [ ] I added or updated tests that prove the fix or feature works.
- [ ] Local gate is green: `go test ./...`, `go test -race ./...`, `golangci-lint run ./...`, `make docs-check`, `make grafana-check`. (These are exactly the jobs `ci-success` requires; a Docker build-verify job also runs in CI and can optionally be reproduced locally with `docker build .`.)
