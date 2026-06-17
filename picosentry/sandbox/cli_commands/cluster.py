from __future__ import annotations

import argparse
import json
import os
import sys

NAME = "cluster"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    cluster_parser = subparsers.add_parser(NAME, help="Manage daemon cluster mode")
    cluster_sub = cluster_parser.add_subparsers(dest="cluster_action", help="cluster sub-commands")


    cluster_join = cluster_sub.add_parser("join", help="Join a cluster via peer address")
    cluster_join.add_argument("peer_address", help="Peer address (host:port)")
    cluster_join.add_argument("--port", type=int, default=8444, help="Local cluster port (default: 8444)")
    cluster_join.add_argument("--node-id", help="Custom node ID (default: auto-generated)")
    cluster_join.add_argument(
        "--backend",
        choices=["memory", "sqlite"],
        default="memory",
        help="State backend (default: memory)",
    )
    cluster_join.add_argument(
        "--heartbeat-interval", type=int, default=10, help="Heartbeat interval in seconds (default: 10)"
    )
    cluster_join.add_argument(
        "--heartbeat-timeout", type=int, default=30, help="Heartbeat timeout in seconds (default: 30)"
    )
    cluster_join.add_argument(
        "--cluster-token",
        default=os.environ.get("PICODOME_CLUSTER_TOKEN", ""),
        help="Shared secret required for gossip membership (also PICODOME_CLUSTER_TOKEN env)",
    )
    cluster_join.add_argument(
        "--tls-cert",
        default=os.environ.get("PICODOME_CLUSTER_TLS_CERT", ""),
        help="Client certificate path for TLS/mTLS gossip (also PICODOME_CLUSTER_TLS_CERT env)",
    )
    cluster_join.add_argument(
        "--tls-key",
        default=os.environ.get("PICODOME_CLUSTER_TLS_KEY", ""),
        help="Client private key path for TLS/mTLS gossip (also PICODOME_CLUSTER_TLS_KEY env)",
    )
    cluster_join.add_argument(
        "--tls-ca",
        default=os.environ.get("PICODOME_CLUSTER_TLS_CA", ""),
        help="CA bundle path to verify peer certificates (also PICODOME_CLUSTER_TLS_CA env)",
    )


    cluster_status = cluster_sub.add_parser("status", help="Show cluster node status")
    cluster_status.add_argument(
        "--format", "-f", choices=["json", "table"], default="table", help="Output format (default: table)"
    )


    _cluster_leave = cluster_sub.add_parser("leave", help="Gracefully leave the cluster")


def cmd(args: argparse.Namespace) -> int:
    from picosentry.sandbox.cluster import (
        ClusterNode,
        MemoryStateBackend,
        NodeStatus,
        SQLiteStateBackend,
        get_cluster_manager,
        setup_cluster_manager,
    )

    action = getattr(args, "cluster_action", None)

    if action == "join":

        peer = args.peer_address
        if ":" in peer:
            peer_host, peer_port_str = peer.rsplit(":", 1)
            try:
                peer_port = int(peer_port_str)
            except ValueError:
                print(f"Error: invalid peer address: {peer}", file=sys.stderr)
                return 1
        else:
            peer_host = peer
            peer_port = 8444


        backend = MemoryStateBackend() if args.backend == "memory" else SQLiteStateBackend()

        manager = setup_cluster_manager(
            address="127.0.0.1",
            port=args.port,
            node_id=args.node_id,
            backend=backend,
            heartbeat_interval=args.heartbeat_interval,
            heartbeat_timeout=args.heartbeat_timeout,
            cluster_token=args.cluster_token,
            tls_cert_path=args.tls_cert,
            tls_key_path=args.tls_key,
            tls_ca_path=args.tls_ca,
        )
        manager.start()


        peer_node = ClusterNode(
            node_id=f"peer-{peer_host}-{peer_port}",
            address=peer_host,
            port=peer_port,
            status=NodeStatus.ONLINE,
            last_heartbeat="",
            load=0,
        )
        manager.state.add_node(peer_node)


        manager.state.elect_leader()

        status = manager.get_status()
        print(f"✓ Joined cluster as node {manager.node_id}")
        print(f"  Peer: {peer_host}:{peer_port}")
        print(f"  Leader: {status['leader_id'] or 'none'}")
        print(f"  Nodes: {status['nodes_online']} online, {status['nodes_total']} total")
        print(f"  Backend: {args.backend}")
        if args.cluster_token:
            print("  Cluster token: configured")
        if args.tls_ca or (args.tls_cert and args.tls_key):
            print("  Gossip TLS: configured")
        return 0

    elif action == "status":

        manager = get_cluster_manager()
        status = manager.get_status()

        if args.format == "json":
            print(json.dumps(status, sort_keys=True, indent=2))
        else:
            print("\n  Cluster Status")
            print("  ─────────────")
            print(f"  Self:       {status['self_id']}")
            print(f"  Leader:     {status['leader_id'] or 'none'}")
            print(f"  Nodes:      {status['nodes_online']} online / {status['nodes_total']} total")
            print(f"  Draining:   {status['nodes_draining']}")
            print(
                f"  Scans:      {status['scans_pending']} pending /"
                f" {status['scans_running']} running /"
                f" {status['scans_completed']} completed"
            )
            print()
            if status["nodes"]:
                print(f"  {'Node ID':<30} {'Address':<20} {'Port':<6} {'Status':<10} {'Load':<5} {'Last HB'}")
                print(f"  {'─' * 30} {'─' * 20} {'─' * 6} {'─' * 10} {'─' * 5} {'─' * 20}")
                for n in status["nodes"]:
                    print(
                        f"  {n['node_id']:<30} "
                        f"{n['address']:<20} "
                        f"{n['port']:<6} "
                        f"{n['status']:<10} "
                        f"{n['load']:<5} "
                        f"{n['last_heartbeat']}"
                    )
            print()
        return 0

    elif action == "leave":
        manager = get_cluster_manager()
        manager.stop()
        print(f"✓ Left cluster (node {manager.node_id})")
        return 0

    else:
        print("Usage: picodome cluster {join|status|leave}", file=sys.stderr)
        return 1


__all__ = ["NAME", "add_arguments", "cmd"]
