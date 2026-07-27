"""
Generate the feature-sentinel contract from the live dashboard registry (#417).

Every hidden presence sentinel (`b.sentinel(...)` / `b.loki_sentinel(...)`) is a
navigation element: it decides whether a tab or row renders at all. Before #413/#414
that inventory was a hand-maintained ~40-row table in `grafana/tabs/AUTHORING.md`
that had drifted so far it prescribed queries the build now actively rejects (a
`leases_total > 0` DHCP gate the #114 guard exists to fail on). This module replaces
the hand-written table with a generator that reads the SAME `Builder` instance
`build_dashboard.build_all()` produces, so the documentation cannot diverge from
what actually ships — a stale page fails `make grafana-check` exactly like a stale
`dashboard.json` (see the Makefile `grafana-check` target).

Two callers consume this module:

* `build_dashboard.py` writes the structured form to `grafana/sentinel-contract.json`
  and renders the human-readable form into the marked region of
  `grafana/tabs/AUTHORING.md` (between `<!-- sentinelgen:begin -->` /
  `<!-- sentinelgen:end -->`).
* `tests/test_sentinel_contract.py` rebuilds both from the current registry and
  diffs them against the committed files — the fast, no-subprocess version of the
  same staleness check `make grafana-check` runs via `git diff --exit-code`.

Nothing here mutates a `Builder` — nor does it import from `grafana/tabs/*` or
change `builder.py`; it only reads the manifest `build_dashboard.build_all()`
already assembled.
"""

from __future__ import annotations

import json
from collections import Counter

from builder import SENTINEL_SCOPES

# The single scope mode every Loki sentinel uses (builder.py's `loki_sentinel()`
# has no `scope=` parameter at all — the stream selector always comes from
# `loki_sel()`, so there is nothing to declare). Kept distinct from
# `SENTINEL_SCOPES` (Prometheus-only) so a reader never mistakes it for one of
# the four Prometheus modes.
LOKI_SCOPE = "stream_selector"

PRESENCE_EXISTENCE = "existence"
PRESENCE_VALUE = "value"

# Human-readable phrasing for the generated markdown, kept in sync with the
# "Two hard rules" prose in grafana/tabs/AUTHORING.md.
_PRESENCE_LABEL = {
    PRESENCE_EXISTENCE: "existence (series presence)",
    PRESENCE_VALUE: "value (nonzero threshold)",
}

BEGIN_MARKER = "<!-- sentinelgen:begin -->"
END_MARKER = "<!-- sentinelgen:end -->"


def _classify_presence(query: str) -> str:
    """Derive the presence-test kind from the query `Builder._sentinel_query`
    already built, rather than re-declaring it here.

    `Builder.sentinel(nonzero=True)` is the ONLY path that emits ` > 0)` — the
    `target_join` path's `query_result(...)` join and every `label_values(...)`
    existence probe never do (`target_join` + `nonzero=True` is rejected by
    `Builder._sentinel_query` itself). So this substring is an exact, load-bearing
    discriminator, not a heuristic.
    """
    return PRESENCE_VALUE if " > 0)" in query else PRESENCE_EXISTENCE


def _extract_prometheus_sentinels(builder) -> dict[str, str]:
    """Hidden Prometheus QueryVariables -> their built query string, as shipped.

    Mirrors `tests/test_sentinel_scoping.py:prometheus_sentinels()` deliberately:
    both independently filter the same shipped variables, so a change to how
    sentinels are emitted has to break two call sites before either goes silently
    stale, rather than one importing the other's assumptions.
    """
    found = {}
    for variable in builder.variables:
        spec = variable["spec"]
        if variable["kind"] != "QueryVariable" or spec["hide"] != "hideVariable":
            continue
        query = spec["query"]
        if query["group"] != "prometheus":
            continue
        found[spec["name"]] = query["spec"]["query"]
    return found


def _extract_loki_sentinels(builder) -> dict[str, str]:
    """Hidden Loki QueryVariables -> their built LogQL string, as shipped."""
    found = {}
    for variable in builder.variables:
        spec = variable["spec"]
        if variable["kind"] != "QueryVariable" or spec["hide"] != "hideVariable":
            continue
        query = spec["query"]
        if query["group"] != "loki":
            continue
        found[spec["name"]] = query["spec"]["__legacyStringValue"]
    return found


def _record_gate(cond: dict, path: str, out: dict[str, list[str]]) -> None:
    for item in cond.get("spec", {}).get("items", []):
        ispec = item.get("spec", {})
        name = ispec.get("variable")
        if not name:
            continue
        label = path if ispec.get("operator") != "notMatches" else f"{path} (absent)"
        out.setdefault(name, [])
        if label not in out[name]:
            out[name].append(label)


def _walk_tab(tab_spec: dict, path: list[str], out: dict[str, list[str]]) -> None:
    title = tab_spec["title"]
    full_path = path + [title]
    cond = tab_spec.get("conditionalRendering")
    if cond:
        _record_gate(cond, " > ".join(full_path), out)

    layout = tab_spec["layout"]
    if layout["kind"] == "TabsLayout":
        for child in layout["spec"]["tabs"]:
            _walk_tab(child["spec"], full_path, out)
    elif layout["kind"] == "RowsLayout":
        for row in layout["spec"]["rows"]:
            rspec = row["spec"]
            row_title = rspec.get("title") or ""
            row_path = full_path + ([row_title] if row_title else [])
            rcond = rspec.get("conditionalRendering")
            if rcond:
                _record_gate(rcond, " > ".join(row_path), out)


def sentinel_gates(tabs: list) -> dict[str, list[str]]:
    """name -> sorted, deduplicated list of "Domain > Leaf[ > Row]" paths where
    that sentinel drives `conditionalRendering`, walked from the FINAL tab tree
    (i.e. after `build_dashboard.organize_tabs()` has nested every leaf under its
    top-level domain). A sentinel referenced by an OR group across several rows,
    or by both its leaf tab and the enclosing domain (every fully-optional
    domain re-declares its children's presence at the group level), legitimately
    appears more than once — that is a real, documented fact about the manifest,
    not a bug in the walk.
    """
    out: dict[str, list[str]] = {}
    for tab in tabs:
        _walk_tab(tab["spec"], [], out)
    return {name: sorted(paths) for name, paths in out.items()}


def build_contract(builder) -> dict:
    """Build the full JSON-serializable sentinel contract from a built `Builder`.

    Deterministic by construction: sentinels are emitted in name-sorted order and
    scope totals in the fixed `SENTINEL_SCOPES` order, so two runs against an
    unchanged registry byte-for-byte agree — required for the `git diff
    --exit-code` staleness check in `make grafana-check`.
    """
    scopes = dict(getattr(builder, "_sentinel_scopes", {}))
    gates = sentinel_gates(builder.tabs)

    prom_queries = _extract_prometheus_sentinels(builder)
    prom_entries = []
    for name in sorted(prom_queries):
        query = prom_queries[name]
        prom_entries.append({
            "name": name,
            "datasource": "prometheus",
            "scope": scopes.get(name, "UNDECLARED"),
            "presence": _classify_presence(query),
            "query": query,
            "gates": gates.get(name, []),
        })

    loki_queries = _extract_loki_sentinels(builder)
    loki_entries = []
    for name in sorted(loki_queries):
        query = loki_queries[name]
        loki_entries.append({
            "name": name,
            "datasource": "loki",
            "scope": LOKI_SCOPE,
            "presence": PRESENCE_EXISTENCE,
            "query": query,
            "gates": gates.get(name, []),
        })

    by_scope = Counter(e["scope"] for e in prom_entries)

    return {
        "prometheus": {
            "total": len(prom_entries),
            "by_scope": {mode: by_scope.get(mode, 0) for mode in SENTINEL_SCOPES},
            "sentinels": prom_entries,
        },
        "loki": {
            "total": len(loki_entries),
            "sentinels": loki_entries,
        },
    }


def contract_json(contract: dict) -> str:
    """Render the contract as the exact bytes `build_dashboard.py` writes to
    `sentinel-contract.json`, so generator and staleness test share one
    serialization (indent, trailing newline)."""
    return json.dumps(contract, indent=2) + "\n"


def _escape_cell(text: str) -> str:
    """Markdown table cells break on a literal newline or unescaped pipe."""
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def _render_table(entries: list) -> list[str]:
    lines = [
        "| Sentinel | Scope | Presence test | Gates (tab/row) | Query |",
        "|---|---|---|---|---|",
    ]
    for e in entries:
        gates = "; ".join(e["gates"]) if e["gates"] else "_none — dead sentinel_"
        lines.append(
            "| `{name}` | `{scope}` | {presence} | {gates} | `{query}` |".format(
                name=e["name"],
                scope=e["scope"],
                presence=_PRESENCE_LABEL.get(e["presence"], e["presence"]),
                gates=_escape_cell(gates),
                query=_escape_cell(e["query"]),
            )
        )
    return lines


def render_authoring_section(contract: dict) -> str:
    """Render the markdown that goes between the `sentinelgen` markers in
    `grafana/tabs/AUTHORING.md`. Pure function of the contract dict — never reads
    or writes a file itself, so it stays trivially testable."""
    prom = contract["prometheus"]
    loki = contract["loki"]
    scope_summary = " / ".join(f"{mode} {prom['by_scope'].get(mode, 0)}" for mode in SENTINEL_SCOPES)

    lines = []
    lines.append(
        f"### Prometheus sentinels — {prom['total']} total ({scope_summary})"
    )
    lines.append("")
    lines.extend(_render_table(prom["sentinels"]))
    lines.append("")
    lines.append(f"### Loki sentinels — {loki['total']} total (scope: `{LOKI_SCOPE}`)")
    lines.append("")
    lines.extend(_render_table(loki["sentinels"]))
    return "\n".join(lines)


def inject_authoring_section(doc: str, content: str) -> str:
    """Replace the region between the `sentinelgen` markers, keeping the marker
    lines themselves and everything outside them untouched. Raises if either
    marker is missing — a hand-deleted marker must fail loud, not silently skip
    regeneration."""
    bi = doc.find(BEGIN_MARKER)
    ei = doc.find(END_MARKER)
    if bi < 0 or ei < 0:
        raise ValueError(
            "sentinelgen region markers missing from grafana/tabs/AUTHORING.md "
            f"(begin found={bi >= 0}, end found={ei >= 0})"
        )
    if ei < bi:
        raise ValueError("sentinelgen end marker appears before the begin marker")
    return (
        doc[:bi + len(BEGIN_MARKER)]
        + "\n" + content.strip() + "\n"
        + doc[ei:]
    )
