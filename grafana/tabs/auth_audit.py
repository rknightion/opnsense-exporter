"""
Authentication & Audit tab — who authenticated against this firewall, and who
changed it (#523).

Three log-derived families that have no metrics-side home anywhere else: sshd
outcomes on the firewall's own SSH service, the audit stream's config-write and
GUI/API authorization decisions, and FreeRADIUS access accepts/rejects. They shared
a tab with firewall and DHCP events until the Observability domain was retired;
grouped by the question they answer instead, they are one coherent view — "is
somebody getting in, and did anything change".

Every panel is built by `tabs/log_events.py`, which owns the queries and the
cardinality rules for the whole `opnsense_log_events_*` family. This module owns
only the grouping.

The tab is gated on the OR of its three sentinels (see `OPTIONAL_TAB_PRESENCE`), so
a box shipping no syslog at all never renders it.
"""

from builder import Builder
from tabs.log_events import audit_row, radius_row, sshd_row


def build(b: Builder):
    b.tab("Authentication & Audit", [
        sshd_row(b),
        audit_row(b),
        radius_row(b),
    ], present=["has_log_events_sshd", "has_log_events_audit", "has_log_events_radius"])
