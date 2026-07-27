"""
Siproxd tab — covers the single opnsense_siproxd_registrations metric.

The os-siproxd plugin is default-on (--exporter.disable-siproxd) but
plugin-gated (silent 404 when not installed), so the tab is gated on the
presence of opnsense_siproxd_registrations. No per-registration user/host
detail is exposed (SIP AORs and their real IPs are PII, #224) — this is a
validate-first rider: the underlying line format was derived from source
(the pfSense siproxd package's identical-file parser), not a live capture,
since the os-siproxd plugin wasn't installed on the test box.
"""

from builder import Builder, sel


def build(b: Builder):
    b.sentinel("has_siproxd", metric="opnsense_siproxd_registrations")

    registrations = b.stat(
        "Active SIP Registrations",
        sel("opnsense_siproxd_registrations"),
        unit="short", w=6, h=4,
        thresholds=[{"color": "blue", "value": None}],
        desc=(
            "Number of active SIP registrations tracked by siproxd (gauge — "
            "instantaneous count, no per-registration labels)."
        ),
    )

    b.tab("Siproxd", [
        b.row("Registrations", [registrations], present="has_siproxd"),
    ])
