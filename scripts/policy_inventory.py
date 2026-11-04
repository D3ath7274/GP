"""Validate/import an operator-described policy; inspect snapshots without firewall credentials."""

import argparse
import json
from pathlib import Path
import sqlite3
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "Controller"))
from firewall_policy import FORMAT, PolicyEvaluator, canonical_bytes, diff_policies, query, read_input, sha256
from policy_store import PolicyStore


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("--input", type=Path, required=True)
    ingest = commands.add_parser("import")
    ingest.add_argument("--input", type=Path, required=True)
    ingest.add_argument("--store", type=Path, required=True)
    listing = commands.add_parser("list")
    listing.add_argument("--store", type=Path, required=True)
    listing.add_argument("--limit", type=int, default=100)
    show = commands.add_parser("show")
    show.add_argument("--store", type=Path, required=True)
    show.add_argument("--snapshot", required=True)
    search = commands.add_parser("search")
    search.add_argument("--store", type=Path, required=True)
    search.add_argument("--snapshot", required=True)
    search.add_argument("--source", required=True)
    search.add_argument("--destination", required=True)
    search.add_argument("--protocol", required=True, choices=("tcp", "udp", "icmp", "icmpv6"))
    search.add_argument("--destination-port", type=int)
    search.add_argument("--source-port", type=int)
    search.add_argument("--limit", type=int, default=100)
    search.add_argument("--include-disabled", action="store_true")
    compare = commands.add_parser("diff")
    compare.add_argument("--store", type=Path, required=True)
    compare.add_argument("--before", required=True)
    compare.add_argument("--after", required=True)
    serve = commands.add_parser("serve")
    serve.add_argument("--store", type=Path, required=True)
    serve.add_argument("--port", type=int, default=8082)
    args = parser.parse_args()
    try:
        if args.command in ("validate", "import"):
            raw, policy = read_input(args.input)
            if args.command == "validate":
                result = {"valid": True, "format": FORMAT, "snapshot_id": sha256(canonical_bytes(policy)),
                          "rules": len(policy["rules"]), "objects": len(policy["objects"]),
                          "source_kind": "operator_description", "enforcement": "NOT_ATTEMPTED"}
            else:
                with PolicyStore(args.store, writable=True) as store:
                    result = store.import_snapshot(raw, policy)
        elif args.command == "serve":
            if not 1 <= args.port <= 65535:
                raise ValueError("Port must be 1..65535")
            from policy_http import make_server
            with make_server(args.store, args.port) as server:
                print(f"Read-only policy workbench http://127.0.0.1:{args.port}/", flush=True)
                try:
                    server.serve_forever()
                except KeyboardInterrupt:
                    pass
            return 0
        else:
            with PolicyStore(args.store) as store:
                if args.command == "list":
                    result = store.list_snapshots(args.limit)
                elif args.command == "show":
                    result = {"snapshot_id": args.snapshot, "policy": store.get_snapshot(args.snapshot),
                              "provenance": store.provenance(args.snapshot)}
                elif args.command == "diff":
                    result = dict(diff_policies(store.get_snapshot(args.before), store.get_snapshot(args.after)),
                                  before=args.before, after=args.after)
                else:
                    point = query(args.source, args.destination, args.protocol, args.destination_port, args.source_port)
                    result = dict(PolicyEvaluator(store.get_snapshot(args.snapshot)).search(point, args.limit, args.include_disabled),
                                  snapshot_id=args.snapshot)
        print(json.dumps(result, indent=2, allow_nan=False))
        return 0
    except (OSError, ValueError, TypeError, KeyError, sqlite3.Error) as error:
        parser.exit(1, f"Policy operation failed: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
