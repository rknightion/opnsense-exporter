"""
NetBird tab — node-local NetBird metrics (opnsense_netbird_*).
Plugin-gated; per-peer row additionally gated on the opt-in details flag
(--exporter.enable-netbird-details).

Verification status (see opnsense/netbird.go): management/signal connectivity,
relay counts, peer counts, service state and version info are live-verified
against a dev-box capture (daemon up, unenrolled). The per-peer detail metrics
(connection type, transfer, handshake, latency) are SOURCE-DERIVED from
netbirdio/netbird's client/status/status.go — no enrolled netbird network was
available to observe them live (#211).
"""

from builder import Builder, sel, epoch_ms, RATE, RUNSTOP


def build(b: Builder):
    b.sentinel("has_netbird", metric="opnsense_netbird_service_running")
    b.sentinel("has_netbird_peers", metric="opnsense_netbird_peer_connected")

    svc = b.stat("Plugin Service", sel("opnsense_netbird_service_running"),
                 unit="short", w=4, h=4, mappings=RUNSTOP)
    mgmt = b.stat("Management Connected", sel("opnsense_netbird_management_connected"),
                  unit="short", w=4, h=4, mappings=RUNSTOP,
                  desc="Whether this node's netbird daemon has an active connection "
                       "to the management server.")
    signal = b.stat("Signal Connected", sel("opnsense_netbird_signal_connected"),
                    unit="short", w=4, h=4, mappings=RUNSTOP,
                    desc="Whether this node's netbird daemon has an active connection "
                         "to the signal server.")
    relays_total = b.stat("Relays Known", sel("opnsense_netbird_relays_total"),
                          unit="short", w=4, h=4)
    relays_available = b.stat("Relays Available", sel("opnsense_netbird_relays_available"),
                              unit="short", w=4, h=4,
                              desc="Relay servers currently reachable, out of "
                                   "Relays Known.")
    peers_total = b.stat("Peers Known", sel("opnsense_netbird_peers_total"),
                         unit="short", w=4, h=4)
    peers_connected = b.stat("Peers Connected", sel("opnsense_netbird_peers_connected"),
                             unit="short", w=4, h=4,
                             desc="Peers this node currently has an active WireGuard "
                                  "connection to.")
    info = b.table("Node Info", [sel("opnsense_netbird_info")],
                   w=8, h=4,
                   excludes=["Value", "__name__", "job", "instance"],
                   renames={"cli_version": "CLI Version", "daemon_version": "Daemon Version"})

    peer_traffic = b.ts("Per-Peer Traffic",
                        [(f'topk(20, rate({sel("opnsense_netbird_peer_received_bytes_total")}[{RATE}]))*8',
                          "rx {{fqdn}}"),
                         (f'topk(20, rate({sel("opnsense_netbird_peer_transmitted_bytes_total")}[{RATE}]))*8',
                          "tx {{fqdn}}")],
                        unit="bps", w=12, h=9)
    peer_connected_tl = b.statetimeline("Peer Connection State",
                                        [(sel("opnsense_netbird_peer_connected"), "{{fqdn}}")],
                                        mappings={"0": ("Not connected", "blue"),
                                                  "1": ("Connected", "green")},
                                        w=12, h=9)
    # peer_direct is only emitted for peers WITH an active connection, so
    # "Relayed" here never mislabels a peer with no session at all.
    peer_direct = b.statetimeline("Connection Path (direct vs relayed)",
                                  [(sel("opnsense_netbird_peer_direct"), "{{fqdn}}")],
                                  mappings={"0": ("Relayed", "orange"),
                                            "1": ("Direct (P2P)", "green")},
                                  w=12, h=8)
    peer_latency = b.ts("Per-Peer Latency",
                        [(sel("opnsense_netbird_peer_latency_seconds"), "{{fqdn}}")],
                        unit="s", w=12, h=8)
    peer_handshake = b.table("Last Handshake",
                             [epoch_ms(sel("opnsense_netbird_peer_last_handshake_timestamp_seconds"))],
                             w=24, h=8,
                             excludes=["__name__", "job", "instance"],
                             renames={"fqdn": "Peer"},
                             unit_overrides={"Value": "dateTimeAsIso"},
                             sort_by="Value", sort_desc=True)

    b.tab("NetBird", [
        b.row("NetBird Node",
              [svc, mgmt, signal, relays_total, relays_available, peers_total, peers_connected, info],
              present="has_netbird"),
        b.row("NetBird Peers (details flag)",
              [peer_traffic, peer_connected_tl, peer_direct, peer_latency, peer_handshake],
              present="has_netbird_peers"),
    ])
