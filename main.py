from __future__ import annotations

import argparse
from typing import Iterable

from proxy_ca import cleanup_stale_ca, install_ca, register_shutdown_cleanup, remove_ca
from proxy_server import DEFAULT_HOST, DEFAULT_PORT, serve


def run_proxy(host: str, port: int) -> None:
    state = install_ca()
    register_shutdown_cleanup()
    print(f"Installed local proxy CA in CurrentUser Root: {state.thumbprint}")
    print(f"Configure your client to use HTTP proxy {host}:{port}")
    try:
        serve(host, port)
    finally:
        remove_ca()
        print("Removed local proxy CA.")


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local-only HTTP/HTTPS MITM forward proxy.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="register the CA and run the proxy")
    run_parser.add_argument("--host", default=DEFAULT_HOST)
    run_parser.add_argument("--port", type=int, default=DEFAULT_PORT)

    subparsers.add_parser("cleanup", help="remove stale proxy CA material and trust entry")

    try:
        args = parser.parse_args(argv)
        if args.command == "run":
            run_proxy(args.host, args.port)
        elif args.command == "cleanup":
            cleanup_stale_ca()
            print("Cleanup complete.")
    except KeyboardInterrupt:
        print("Proxy stopped.")
    except Exception as exc:
        print(f"error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
