from __future__ import annotations

import argparse
import json
import sys

NAME = "scan_grpc"  # Python identifier; argparse subcommand is "scan-grpc"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("scan-grpc", help="Scan via gRPC client")
    parser.add_argument("target", nargs=argparse.REMAINDER, help="Command to scan")
    parser.add_argument("--address", default="localhost:50051", help="gRPC server address (default: localhost:50051)")
    parser.add_argument("--policy", "-p", help="Policy name")
    parser.add_argument("--timeout", "-t", type=float, default=30.0, help="Timeout in seconds")
    parser.add_argument("--cwd", "-C", help="Working directory")
    parser.add_argument("--tls-cert", help="Client TLS certificate path")
    parser.add_argument("--tls-key", help="Client TLS key path")
    parser.add_argument("--tls-ca", help="CA certificate path for mTLS")
    parser.add_argument("--retries", type=int, default=3, help="Max retry attempts (default: 3)")


def cmd(args: argparse.Namespace) -> int:
    from picosentry.sandbox.grpc_transport import is_grpc_available

    if not is_grpc_available():
        print("Error: grpcio is not installed. Install with: pip install grpcio", file=sys.stderr)
        return 1

    from picosentry.sandbox.grpc_transport.client import PicoDomeGRPCClient

    command = args.target
    if not command:
        print("Error: no command specified", file=sys.stderr)
        return 1

    mtls_config = None
    if args.tls_cert or args.tls_key or args.tls_ca:
        try:
            from picosentry.sandbox.mtls.context import MTLSConfig

            mtls_config = MTLSConfig(
                cert_path=args.tls_cert or "",
                key_path=args.tls_key or "",
                ca_path=args.tls_ca or "",
                verify_client=bool(args.tls_ca),
            )
        except Exception as e:
            print(f"Error configuring mTLS: {e}", file=sys.stderr)
            return 1

    client = PicoDomeGRPCClient(
        target=args.address,
        mtls_config=mtls_config,
        timeout=args.timeout,
        max_retries=args.retries,
    )

    try:
        result = client.scan(
            command=command,
            policy=args.policy,
            timeout=args.timeout,
            cwd=args.cwd,
        )

        if result.result_json:
            try:
                data = json.loads(result.result_json)
                print(json.dumps(data, sort_keys=True, indent=2))
            except json.JSONDecodeError:
                print(result.result_json)
        else:
            print(f"Verdict: {result.verdict}")
            print(f"Exit code: {result.exit_code}")
            if result.l3_verdict:
                print(f"L3 verdict: {result.l3_verdict}")
            if result.l4_verdict:
                print(f"L4 verdict: {result.l4_verdict}")
            print(f"Findings: {result.findings_count}")

        bad_verdicts = {"DENY", "KILL", "MALICIOUS", "SUSPICIOUS"}
        if result.verdict in bad_verdicts:
            return 1
        return 0

    except ConnectionError as e:
        print(f"Connection error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Scan error: {e}", file=sys.stderr)
        return 1
    finally:
        client.close()


__all__ = ["NAME", "add_arguments", "cmd"]
