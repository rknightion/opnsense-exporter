"""
Tailscale tab — node-local Tailscale metrics (opnsense_tailscale_*).
Plugin-gated; per-peer row additionally gated on the opt-in details flag.
Complementary to tailscale2otel (fleet/control-plane — including peer
"online" status — lives there); session activity here is derived purely
from local WireGuard handshakes.
"""

from builder import Builder, sel, RATE, RUNSTOP


def build(b: Builder):
    b.sentinel("has_tailscale",
               "label_values(opnsense_tailscale_service_running, __name__)")
    b.sentinel("has_tailscale_peers",
               "label_values(opnsense_tailscale_peer_session_active, __name__)")

    svc = b.stat("Plugin Service", sel("opnsense_tailscale_service_running"),
                 unit="short", w=4, h=4, mappings=RUNSTOP)
    backend = b.stat("Backend (tailscaled)", sel("opnsense_tailscale_backend_running"),
                     unit="short", w=4, h=4, mappings=RUNSTOP)
    total = b.stat("Peers Known", sel("opnsense_tailscale_peers_total"),
                   unit="short", w=4, h=4)
    sessions = b.stat("Active Sessions", sel("opnsense_tailscale_peers_with_active_session"),
                      unit="short", w=4, h=4,
                      desc="Peers with an established WireGuard session from this node "
                           "(handshake-derived; NOT coordination-server online status).")
    info = b.table("Node Info", [sel("opnsense_tailscale_info")],
                   w=8, h=4,
                   excludes=["Value", "__name__", "job", "instance"],
                   renames={"version": "Version", "relay": "DERP Relay"})

    peer_traffic = b.ts("Per-Peer Traffic (from this node)",
                        [(f'topk(20, rate({sel("opnsense_tailscale_peer_rx_bytes_total")}[{RATE}]))*8',
                          "rx {{peer}}"),
                         (f'topk(20, rate({sel("opnsense_tailscale_peer_tx_bytes_total")}[{RATE}]))*8',
                          "tx {{peer}}")],
                        unit="bps", w=12, h=9)
    peer_session = b.statetimeline("Peer WireGuard Session (node-local)",
                                   [(sel("opnsense_tailscale_peer_session_active"), "{{peer}}")],
                                   mappings={"0": ("No session", "blue"),
                                             "1": ("Active", "green")},
                                   w=12, h=9)
    # peer_direct is only emitted for peers WITH a session, so "Relayed" here
    # never mislabels idle peers.
    peer_direct = b.statetimeline("Session Path (direct vs DERP-relayed)",
                                  [(sel("opnsense_tailscale_peer_direct"), "{{peer}}")],
                                  mappings={"0": ("Relayed", "orange"),
                                            "1": ("Direct", "green")},
                                  w=12, h=8)
    peer_handshake = b.table("Last Handshake",
                             [sel("opnsense_tailscale_peer_last_handshake_timestamp_seconds")],
                             w=12, h=8,
                             excludes=["__name__", "job", "instance"],
                             renames={"peer": "Peer"},
                             unit_overrides={"Value": "dateTimeAsIso"},
                             sort_by="Value", sort_desc=True)

    b.tab("Tailscale", [
        b.row("Tailscale Node", [svc, backend, total, sessions, info],
              present="has_tailscale"),
        b.row("Tailscale Peers (details flag)",
              [peer_traffic, peer_session, peer_direct, peer_handshake],
              present="has_tailscale_peers"),
    ])
