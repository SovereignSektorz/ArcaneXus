from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .chain import ChainError, verify as verify_chain
from .node import status
from .receipts import ReceiptError, append as append_receipt, verify as verify_receipts
from .scope import Engagement, ScopeDenied
from .trust import TrustStore, UntrustedKey, Verifier

DEFAULT_RECEIPTS = Path.home() / ".local/state/arcanexus-throne/mobile-receipts.jsonl"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ax-throne", description="Rootless ArcaneXus mobile throne node")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="show bounded mobile-node status")
    v = sub.add_parser("verify", help="verify a signed CANON chain using pinned public key only")
    v.add_argument("--chain", required=True, type=Path)
    v.add_argument("--trust-dir", required=True, type=Path)
    v.add_argument("--role", default="release")
    r = sub.add_parser("receipt", help="append a local hash-chained observation receipt")
    r.add_argument("--text", required=True)
    r.add_argument("--source", default="STEWARD_INPUT")
    r.add_argument("--path", type=Path, default=DEFAULT_RECEIPTS)
    rv = sub.add_parser("receipt-verify", help="verify local observation receipts")
    rv.add_argument("--path", type=Path, default=DEFAULT_RECEIPTS)
    sc = sub.add_parser("scope-check", help="resolve and validate a target against a signed engagement; does not connect")
    sc.add_argument("--engagement", required=True, type=Path)
    sc.add_argument("--trust-dir", required=True, type=Path)
    sc.add_argument("--role", default="engagement")
    sc.add_argument("--port", required=True, type=int)
    sc.add_argument("--protocol", default="tcp", choices=["tcp"])
    sc.add_argument("--receipt-path", type=Path, default=DEFAULT_RECEIPTS)
    sc.add_argument("target")
    args = parser.parse_args(argv)
    try:
        if args.command == "status":
            print(json.dumps(status(), indent=2))
            return 0
        if args.command == "verify":
            verifier = Verifier(TrustStore(args.trust_dir, args.role))
            records = verify_chain(args.chain, verifier)
            print(json.dumps({"verified": True, "records": len(records), "head": records[-1].body_digest(),
                              "trust_role": args.role, "public_key_fingerprint": verifier.fingerprint,
                              "private_key_used": False, "promotion_authority": False}, indent=2))
            return 0
        if args.command == "receipt":
            row = append_receipt(args.path, "MOBILE_OBSERVATION", {"text": args.text, "source": args.source,
                                                                     "classification": "UNVERIFIED_INPUT"})
            print(json.dumps({"stored": True, "sequence": row["sequence"], "event_hash": row["event_hash"],
                              "promotion": "NOT_AUTHORIZED"}, indent=2))
            return 0
        if args.command == "receipt-verify":
            count, head = verify_receipts(args.path)
            print(json.dumps({"valid": True, "receipts": count, "head": head}, indent=2))
            return 0
        if args.command == "scope-check":
            trust = TrustStore(args.trust_dir, args.role)
            engagement = Engagement(args.engagement, trust)
            pinned = engagement.resolve(args.target, args.port, args.protocol)
            receipt = append_receipt(args.receipt_path, "SCOPE_ALLOW", {
                "target": pinned.requested,
                "hostname": pinned.hostname,
                "addresses": list(pinned.addresses),
                "port": pinned.port,
                "protocol": pinned.protocol,
                "engagement_id": pinned.engagement_id,
                "engagement_sha256": pinned.engagement_sha256,
                "expires_at": pinned.expires_at,
                "decision": "ALLOW",
                "connected": False
            })
            print(json.dumps({
                "authorized": True,
                "connected": False,
                "target": pinned.requested,
                "canonical_hostname": pinned.hostname,
                "pinned_addresses": list(pinned.addresses),
                "port": pinned.port,
                "protocol": pinned.protocol,
                "engagement_id": pinned.engagement_id,
                "engagement_sha256": pinned.engagement_sha256,
                "validated_at": pinned.validated_at,
                "expires_at": pinned.expires_at,
                "redirects_allowed": pinned.redirects_allowed,
                "private_key_used": False,
                "receipt_sequence": receipt["sequence"],
                "receipt_event_hash": receipt["event_hash"]
            }, indent=2))
            return 0
    except (ChainError, ReceiptError, UntrustedKey, ScopeDenied, OSError, ValueError, KeyError) as exc:
        if getattr(args, "command", None) == "scope-check":
            try:
                append_receipt(args.receipt_path, "SCOPE_DENY", {
                    "target": args.target,
                    "port": args.port,
                    "protocol": args.protocol,
                    "decision": "DENY",
                    "reason_type": type(exc).__name__,
                    "reason": str(exc)[:500],
                    "connected": False
                })
            except Exception as ledger_exc:
                print(f"LEDGER_DENY: {type(ledger_exc).__name__}: {ledger_exc}", file=sys.stderr)
        print(f"DENY: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
