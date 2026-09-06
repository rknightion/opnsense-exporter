# Triaging a schema-canary finding

Every finding from the daily live-box canary (`cmd/apidrift`, `.github/workflows/live-canary.yml`)
gets exactly one of five verdicts.

**Ask "did upstream actually change?" first.** Four of the five presuppose it did. **box-state** is
the one that does not, and it is the most common answer in practice - reach for it before the others
or you will force-fit `drop` onto a live tunnel that merely fell over.

- **box-state** - the box has nothing to report, so the key is absent. Not drift, and **never a code
  change**. A missing path proves nothing on its own: an endpoint with no IPsec SAs, no nginx cache
  node, no reporting subsystem or an empty vnstat DB legitimately omits the key. Confirm against
  upstream *source* that the key is conditional, then either exempt it with a `missingOK` entry whose
  prune trigger names the **box state** (not a release), or fix the testbed so the data exists.
  Prefer fixing the testbed when the field backs an exported metric: an exemption there blinds the
  canary to real drift on a consumed field.
- **absorb** - the payload changed representation only (a number arrived as a string, an object as an
  array of one). Flex types and `KindNumeric` usually already handle it; retype the field.
- **chase** - the data moved or was renamed. Write a tolerant reader: keep the legacy field, add the
  new one alongside it, resolve new-wins-else-legacy in an accessor. Template:
  `opnsense/health_check.go`.
- **drop** - upstream removed the data. Keep the legacy field for the length of the support window;
  the metric reads absent or zero on newer releases. Record it in `docs/compatibility.md`.
- **opportunity** - new data not modelled yet. Roadmap candidate, not a bug: exempt it via
  `knownExtraTopKeys` so the canary stops flagging it.

## Rules

- **Verify against upstream source before assigning any verdict.** Read the controller or script that
  builds the payload and check whether the key is conditional. Two canary runs disagreeing about the
  same key is a box-state tell, not intermittent drift. Guessing here is how a phantom generation
  gets modelled: `metadata.subsystems` was modelled from a release shape upstream has never
  populated, which cost two fabricated fixtures and a permanently dead branch.
- **The support window is current + previous stable OPNsense.** Never version-sniff - resolve by
  payload *shape*. Never remove a legacy field while a release that still sends it is in the window.
- **A fixture must never encode a shape upstream cannot produce.** Derive fixtures from a real
  capture (`just capture`) or from the source's own branches. A deliberately synthetic fixture
  pinning parser tolerance says so in its case comment.
- **`opnsense/testdata/schemas/exemptions.json` is the compat ledger.** Every kept-legacy path gets a
  `missingOK` entry (the prefix form `section.*` is supported) naming the generation it belongs to
  and the trigger that will let it be pruned. Unmodelled new top-level keys go in `knownExtraTopKeys`.
- Run `just schemas` after changing structs. Goldens are structure-only and must never contain
  response values.
