from __future__ import annotations

import argparse
import sys

NAME = "admission"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        NAME,
        help="Start PicoDome K8s admission webhook server (TLS required)",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8443, help="Bind port (default: 8443)")
    parser.add_argument(
        "--cert-file",
        required=True,
        help="Path to TLS certificate file (PEM, required — K8s requires TLS)",
    )
    parser.add_argument(
        "--key-file",
        required=True,
        help="Path to TLS private key file (PEM, required — K8s requires TLS)",
    )
    parser.add_argument("--background", action="store_true", help="Run in background")
    parser.add_argument(
        "--scan-enabled",
        action="store_true",
        default=None,
        help="Enable container image scanning via the daemon",
    )
    parser.add_argument(
        "--scan-fail-closed",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Deny pods when the daemon is unreachable during image scanning (default: true)",
    )
    parser.add_argument(
        "--scan-min-severity",
        choices=["info", "low", "medium", "high", "critical"],
        default="high",
        help="Minimum severity for image-scan blocking (default: high)",
    )
    parser.add_argument(
        "--daemon-url",
        default=None,
        help="PicoDome daemon URL for image scanning (default: http://127.0.0.1:8443)",
    )


def cmd(args: argparse.Namespace) -> int:
    from picosentry.sandbox.admission import AdmissionWebhookServer
    from picosentry.sandbox.admission.validator import PodSecurityValidator
    from picosentry.sandbox.admission.scanner import ImageScanner

    # Build the validator chain.  PodSecurityValidator runs first
    # (pod-level security context checks).  If image scanning is
    # enabled, an ImageScanner is composed as a second pass.
    pod_validator = PodSecurityValidator()

    scan_enabled = getattr(args, "scan_enabled", None)
    if scan_enabled:
        image_scanner = ImageScanner(
            enabled=True,
            min_severity=getattr(args, "scan_min_severity", "high"),
            daemon_url=getattr(args, "daemon_url", None),
            fail_closed=getattr(args, "scan_fail_closed", True),
        )

        def composite_validator(req):
            allowed, reason = pod_validator.validate(req)
            if not allowed:
                return False, reason
            return image_scanner.scan_pod(req)

        validator = composite_validator
    else:
        validator = pod_validator

    server = AdmissionWebhookServer(
        host=args.host,
        port=args.port,
        cert_file=args.cert_file,
        key_file=args.key_file,
        validator=validator,
    )

    try:
        server.start(background=args.background)
        if args.background:
            print(f"PicoDome admission webhook started on {args.host}:{args.port}")
        return 0
    except KeyboardInterrupt:
        server.stop()
        return 0
    except Exception as e:
        print(f"Admission webhook error: {e}", file=sys.stderr)
        return 1


__all__ = ["NAME", "add_arguments", "cmd"]
