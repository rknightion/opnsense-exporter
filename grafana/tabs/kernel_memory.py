"""
Kernel Memory tab — FreeBSD UMA zone and malloc-type allocator statistics (#543),
from `api/diagnostics/system/memory` (`vmstat -m -z --libxo json`).

Its own tab rather than a row on System & Resources because the families are wide:
~228 zones x 8 metrics plus 258 malloc types on a real box, roughly 2,600 series.

Why it exists: `fail` is FreeBSD's canonical "the kernel could not allocate this"
counter, and it covers resources a firewall genuinely exhausts (pf states, pf state
keys, pf source nodes, sockets, inpcbs, tcpreass) with no other signal anywhere.

Three traps encoded in the panels below, all verified live rather than assumed:

  * `limit == 0` means NO CEILING CONFIGURED, not a ceiling of zero. 113 of 242
    zones on the prod box report limit=0 with non-zero use, so every saturation
    expression guards `limit > 0` or it returns +Inf on half the box.
  * Failures are NORMAL in the bucket allocator. `N Bucket`, `vm pgcache` and
    `vmem btag` fail by design and fall back, and account for every one of the
    158,488 failures on the prod box. Panels and alerts scope them out.
  * The mbuf zones here overlap the mbuf collector, which reads the same kernel
    state from a different endpoint at a different moment. Never sum the two.

Coverage:
  opnsense_kernel_memory_zone_used
  opnsense_kernel_memory_zone_free
  opnsense_kernel_memory_zone_limit
  opnsense_kernel_memory_zone_item_size_bytes
  opnsense_kernel_memory_zone_requests_total
  opnsense_kernel_memory_zone_failures_total
  opnsense_kernel_memory_zone_sleeps_total
  opnsense_kernel_memory_zone_xdomain_total
  opnsense_kernel_memory_zone_failures_all_total
  opnsense_kernel_memory_malloc_in_use
  opnsense_kernel_memory_malloc_bytes
  opnsense_kernel_memory_malloc_requests_total
"""

from builder import Builder, sel, grp, RATE

# Zones whose failures are ordinary allocator behaviour rather than a fault. UMA's
# per-CPU bucket allocator is EXPECTED to fail and fall back to the slow path, and
# the page-cache and boundary-tag zones behave the same way. Every failure observed
# on all three test boxes was in this set.
BENIGN_FAIL = r'.+ Bucket|vm pgcache|vmem btag'

# The zones a firewall operator actually cares about exhausting. Each one has a real
# consequence: no new pf state means a dropped connection, no socket means a refused
# one. All read fail=0 on prod, dev release and dev nightly.
CRITICAL_ZONES = r'pf states|pf state keys|pf source nodes|socket|tcp_inpcb|udp_inpcb|tcpreass'


def build(b: Builder):
    b.sentinel("has_kernel_memory",
               metric="opnsense_kernel_memory_zone_failures_all_total")

    # ======================================================================
    # Row 1 — allocation failures, the reason this collector exists
    # ======================================================================
    fail_all = b.stat(
        "Kernel Allocation Failures (all zones)",
        sel("opnsense_kernel_memory_zone_failures_all_total"),
        unit="short", w=6, h=4, instant=True, graph="none",
        desc="Every UMA allocation failure on the box, summed across all zones so a failure in a "
             "zone nobody thought to look at is still visible on one series. Cumulative since "
             "boot, so read the rate rather than the absolute value. A large number here is NOT "
             "automatically alarming - see the benign-allocator panel below.",
    )
    fail_critical = b.ts(
        "Allocation Failures — zones that matter (rate)",
        [(f'rate({sel("opnsense_kernel_memory_zone_failures_total", f'zone=~"{CRITICAL_ZONES}"')}'
          f'[{RATE}])', "{{zone}}")],
        unit="ops", w=12, h=8,
        desc="Failures per second in the zones whose exhaustion has a direct operational "
             "consequence: no new pf state is a dropped connection, no socket is a refused one. "
             "These read zero on a healthy box - prod, dev release and dev nightly are all at zero "
             "- so ANY sustained line here is real. This is what OPNsenseKernelZoneAllocationFailure "
             "alerts on.",
    )
    fail_benign = b.ts(
        "Allocation Failures — benign allocator fallback (rate)",
        [(f'rate({sel("opnsense_kernel_memory_zone_failures_total", f'zone=~"{BENIGN_FAIL}"')}'
          f'[{RATE}])', "{{zone}}")],
        unit="ops", w=12, h=8,
        desc="Failures in UMA's own per-CPU bucket allocator and the page-cache/boundary-tag "
             "zones. These are DESIGNED to fail and fall back to a slower path, and they account "
             "for all 158,488 failures on the prod box. Shown separately so the panel above stays "
             "readable and so nobody alerts on this. Non-zero here is normal.",
    )
    sleeps = b.ts(
        "Zone Allocation Sleeps (rate)",
        [(f'topk by (opnsense_instance) (10, rate({sel("opnsense_kernel_memory_zone_sleeps_total")}[{RATE}]))',
          "{{zone}}")],
        unit="ops", w=12, h=8,
        desc="Allocations that BLOCKED waiting for memory and then succeeded - the softer signal "
             "that precedes outright failure. Zero on every zone on all three test boxes, so a "
             "line appearing here is a genuine change. Top 10 by rate.",
    )

    # ======================================================================
    # Row 2 — saturation against configured ceilings
    # ======================================================================
    saturation = b.ts(
        "Zone Saturation (used / limit)",
        [(f'topk by (opnsense_instance) (15, {sel("opnsense_kernel_memory_zone_used")} / '
          f'({sel("opnsense_kernel_memory_zone_limit")} > 0))', "{{zone}}")],
        unit="percentunit", w=12, h=8,
        desc="How full each zone is against its configured ceiling. The `> 0` guard is load-bearing "
             "and must not be removed: limit=0 means NO CEILING CONFIGURED rather than a ceiling of "
             "zero, and 113 of 242 zones on the prod box report limit=0 with non-zero use, so an "
             "unguarded division returns +Inf on half of them. Note `pf anchors` carries a limit of "
             "2147483647 (INT_MAX), so it reads as permanently 0% and tells you nothing.",
    )
    critical_use = b.ts(
        "Critical Zone Occupancy",
        [(f'{sel("opnsense_kernel_memory_zone_used", f'zone=~"{CRITICAL_ZONES}"')}',
          "{{zone}} used")],
        unit="short", w=12, h=8,
        desc="Absolute item counts in the zones worth watching. Useful even where limit=0, which is "
             "most of them - a trend is readable without a ceiling. `pf source nodes` reads zero on "
             "a box that does not use source tracking; that is configuration, not a fault.",
    )
    zone_table = b.table(
        "UMA Zones",
        [f'{sel("opnsense_kernel_memory_zone_used")}'],
        w=24, h=12,
        excludes=["Value", "__name__", "job", "instance", "env"],
        renames={"zone": "Zone", "opnsense_instance": "Instance"},
        sort_by="Zone",
        desc="Every UMA zone the box reports. The set tracks LOADED KERNEL MODULES rather than the "
             "OPNsense release - the two dev boxes report identical zone sets across 26.7.1 and "
             "27.1.a, while prod differs from both because it runs NetFlow. Zones reported once per "
             "NUMA domain or per instance are merged by name, so `NetFlow IPv4 cache` (seven rows on "
             "the wire) appears once with its counters summed.",
    )

    # ======================================================================
    # Row 3 — churn and sizing
    # ======================================================================
    requests = b.ts(
        "Zone Allocation Rate (top 15)",
        [(f'topk by (opnsense_instance) (15, rate({sel("opnsense_kernel_memory_zone_requests_total")}[{RATE}]))',
          "{{zone}}")],
        unit="ops", w=12, h=8,
        desc="Allocations per second, busiest zones first. Useful as context for a failure: a zone "
             "failing at high request rate is under genuine pressure, one failing at low rate is "
             "more likely misconfigured.",
    )
    free_used = b.ts(
        "Zone Free Items (top 15 by free)",
        [(f'topk by (opnsense_instance) (15, {sel("opnsense_kernel_memory_zone_free")})', "{{zone}} free")],
        unit="short", w=12, h=8,
        desc="Cached-but-unused items per zone. Large free counts are normal - UMA keeps freed "
             "items for reuse rather than returning them to the system immediately.",
    )
    item_size = b.table(
        "Zone Item Size",
        [sel("opnsense_kernel_memory_zone_item_size_bytes")],
        w=12, h=10,
        excludes=["Value", "__name__", "job", "instance", "env"],
        renames={"zone": "Zone", "opnsense_instance": "Instance"},
        sort_by="Zone",
        desc="Bytes per item in each zone, so used x item size approximates the zone's memory "
             "footprint. Where rows were merged by name this is the MAX across them, not a single "
             "configured value - the two `buffer arena-40` rows on prod genuinely differ (4096 vs "
             "40960).",
    )
    xdomain = b.ts(
        "Cross-Domain Frees (rate)",
        [(f'topk by (opnsense_instance) (10, rate({sel("opnsense_kernel_memory_zone_xdomain_total")}[{RATE}]))',
          "{{zone}}")],
        unit="ops", w=12, h=8,
        desc="Frees that crossed a NUMA domain boundary. Only meaningful on a multi-socket box; "
             "flat zero on a single-domain machine is expected, not a gap.",
    )

    # ======================================================================
    # Row 4 — malloc types
    # ======================================================================
    malloc_bytes = b.ts(
        "Malloc Memory In Use (top 15)",
        [(f'topk by (opnsense_instance) (15, {sel("opnsense_kernel_memory_malloc_bytes")})', "{{type}}")],
        unit="bytes", w=12, h=8,
        desc="Kernel memory currently held per malloc type. A different accounting from the UMA "
             "zones above, not a subset of them - a growing type here that never levels off is the "
             "shape of a kernel memory leak.",
    )
    malloc_count = b.ts(
        "Malloc Allocations In Use (top 15)",
        [(f'topk by (opnsense_instance) (15, {sel("opnsense_kernel_memory_malloc_in_use")})', "{{type}}")],
        unit="short", w=12, h=8,
        desc="Outstanding allocation COUNT per malloc type, as opposed to bytes. The two diverge "
             "when a type holds many small allocations or few large ones, and the divergence is "
             "often the more informative reading.",
    )
    malloc_rate = b.ts(
        "Malloc Request Rate (top 15)",
        [(f'topk by (opnsense_instance) (15, rate({sel("opnsense_kernel_memory_malloc_requests_total")}[{RATE}]))',
          "{{type}}")],
        unit="ops", w=12, h=8,
        desc="Allocation requests per second per malloc type. The malloc type set is release "
             "sensitive in a way the zone set is not - `inotify` exists only on 27.1.a, from the "
             "newer FreeBSD base.",
    )

    b.tab("Kernel Memory", [
        b.row("Allocation Failures", [fail_all, fail_critical, fail_benign, sleeps],
              present="has_kernel_memory"),
        b.row("Saturation", [saturation, critical_use, zone_table],
              present="has_kernel_memory"),
        b.row("Churn & Sizing", [requests, free_used, item_size, xdomain],
              present="has_kernel_memory"),
        b.row("Malloc Types", [malloc_bytes, malloc_count, malloc_rate],
              present="has_kernel_memory"),
    ])
