# API contract tooling

`extract.py` emits the OPNsense API endpoint manifest as JSON by reusing the
`opnsense/docs` PHP parser; `cmd/apicontract` diffs it against the exporter's own
endpoint manifest (the API-contract drift canary, `.github/workflows/api-contract.yml`).

## Running the tests locally

`extract_test.py` pins the parser-wrapper contract (`isPost()`-based verb detection,
default-GET classification, the `mvc/app/controllers/.../Api` path filter, and per-file
fault isolation). It requires a checkout of [`opnsense/docs`](https://github.com/opnsense/docs)
(the parser lib) and the pinned Python deps:

```bash
python -m pip install -r tools/opnsense_api_contract/requirements.txt
git clone --depth 1 https://github.com/opnsense/docs /tmp/opnsense-docs
OPNSENSE_DOCS_REPO=/tmp/opnsense-docs python -m pytest tools/opnsense_api_contract/ -q
```

CI runs exactly this (against the SHA-pinned docs clone) in the `api-contract` job, so a
docs-side change that breaks the parser contract fails there rather than silently
producing a wrong manifest.
