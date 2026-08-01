"""
Tailscale tab — node-local Tailscale metrics (opnsense_tailscale_*).
Plugin-gated; per-peer row additionally gated on the opt-in details flag.
Complementary to tailscale2otel (fleet/control-plane — including peer
"online" status — lives there); session activity here is derived purely
from local WireGuard handshakes.
"""

from builder import Builder, sel, grp, epoch_ms, RATE, RUNSTOP, YESNO


def build(b: Builder):
    b.sentinel("has_tailscale", metric="opnsense_tailscale_service_running")
    b.sentinel("has_tailscale_peers", metric="opnsense_tailscale_peer_session_active")

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
    health = b.stat("Health Warnings", sel("opnsense_tailscale_health_warnings"),
                    unit="short", w=4, h=4,
                    thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}],
                    color_mode="background",
                    desc="opnsense_tailscale_health_warnings: count of live warning strings "
                         "reported by the local tailscaled client (update available, DERP "
                         "unreachable, key expiry, ...). The warning text itself is not exported.")
    # #583. Two separate failure modes that both end the tunnel and need
    # different humans. reauth_required is always present, so it can carry a
    # background colour; key expiry is ABSENT on a node whose key does not
    # expire, so the panel reads "No data" rather than 1970.
    reauth = b.stat("Reauth Required", sel("opnsense_tailscale_reauth_required"),
                    unit="short", w=4, h=4, mappings=YESNO,
                    color_mode="background",
                    thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 1}],
                    desc="opnsense_tailscale_reauth_required: 1 when tailscaled is parked "
                         "holding an interactive login URL. The tunnel stays down until a "
                         "human completes that login — no restart clears it, which is what "
                         "separates this from Backend (tailscaled) reading 0. The URL itself "
                         "is a credential and is never exported.")
    key_expiry = b.stat("Node Key Expires In",
                        f'{sel("opnsense_tailscale_key_expiry_timestamp_seconds")} - time()',
                        unit="s", w=4, h=4,
                        color_mode="background",
                        thresholds=[{"color": "red", "value": None},
                                    {"color": "orange", "value": 7 * 86400},
                                    {"color": "green", "value": 30 * 86400}],
                        desc="Time until THIS node's own Tailscale key expires. When it does "
                             "the tunnel dies with no other warning. Red inside 7 days "
                             "(including already expired, which reads negative), amber 7 to 30 "
                             "days, green beyond. No data means the node key does not expire — "
                             "upstream omits the field entirely then, and the exporter "
                             "deliberately emits nothing rather than a 1970 epoch. Self only: "
                             "peer key expiry is tailscale2otel's job.")
    info = b.table("Node Info", [sel("opnsense_tailscale_info")],
                   w=4, h=4,
                   excludes=["Value", "__name__", "job", "instance"],
                   renames={"version": "Version", "relay": "DERP Relay"})

    peer_traffic = b.ts("Per-Peer Traffic (from this node)",
                        [(f'topk {grp()} (20, rate({sel("opnsense_tailscale_peer_rx_bytes_total")}[{RATE}]))*8',
                          "rx {{peer}}"),
                         (f'topk {grp()} (20, rate({sel("opnsense_tailscale_peer_tx_bytes_total")}[{RATE}]))*8',
                          "tx {{peer}}")],
                        unit="bps", w=12, h=9,
                        desc=(
                             "Bits per second to and from each peer as measured BY THIS NODE "
                             "(byte counters ×8), since tailscaled start. Shows the top 20 per "
                             "firewall, not the top 20 overall. A series outside the top 20 is "
                             "ABSENT rather than zero, and one that leaves and re-enters reads "
                             "as a counter reset on that one series."
                        ))
    peer_session = b.statetimeline("Peer WireGuard Session (node-local)",
                                   [(sel("opnsense_tailscale_peer_session_active"), "{{peer}}")],
                                   mappings={"0": ("No session", "blue"),
                                             "1": ("Active", "green")},
                                   w=12, h=9,
                                   desc=(
                                        "Whether this node has an established WireGuard session "
                                        "with each peer — derived from a local handshake having "
                                        "been recorded since tailscaled started, deliberately "
                                        "NOT the coordination server's online flag. A peer with "
                                        "no session has no series."
                                   ))
    # peer_direct is only emitted for peers WITH a session, so "Relayed" here
    # never mislabels idle peers.
    peer_direct = b.statetimeline("Session Path (direct vs DERP-relayed)",
                                  [(sel("opnsense_tailscale_peer_direct"), "{{peer}}")],
                                  mappings={"0": ("Relayed", "orange"),
                                            "1": ("Direct", "green")},
                                  w=12, h=8,
                                  desc=(
                                       "1 = direct path, 0 = relayed through DERP. Emitted only "
                                       "for peers that have a session, so a missing row means no "
                                       "session rather than a relayed one. Sustained relaying is "
                                       "a NAT-traversal problem, not an outage."
                                  ))
    peer_handshake = b.table("Last Handshake",
                             [epoch_ms(sel("opnsense_tailscale_peer_last_handshake_timestamp_seconds"))],
                             w=12, h=8,
                             excludes=["__name__", "job", "instance"],
                             renames={"peer": "Peer"},
                             unit_overrides={"Value": "dateTimeAsIso"},
                             sort_by="Value", sort_desc=True,
                             desc=(
                                  "Wall-clock time of the last WireGuard handshake with each "
                                  "peer, from this node. The metric is epoch seconds scaled to "
                                  "milliseconds for display: a peer that has never handshaked "
                                  "reads as 1970, not as empty."
                             ))

    b.tab("Tailscale", [
        b.autogrid_row("Tailscale Node", [svc, backend, total, sessions, health, reauth,
                                 key_expiry, info],
              present="has_tailscale"),
        b.row("Tailscale Peers (details flag)",
              [peer_traffic, peer_session, peer_direct, peer_handshake],
              present="has_tailscale_peers"),
    ])
