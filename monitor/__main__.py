from __future__ import annotations

import argparse
import sys
import threading
import webbrowser
from dataclasses import replace

from .config import load_config
from .database import Database
from .server import create_server
from .service import MonitorService


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ProxyPulse personal proxy latency monitor")
    parser.add_argument("--config", default=None, help="path to config.toml")
    parser.add_argument("--host", default=None, help="override listen host")
    parser.add_argument("--port", type=int, default=None, help="override listen port")
    parser.add_argument("--once", action="store_true", help="probe every enabled node once and exit")
    parser.add_argument("--no-monitor", action="store_true", help="serve the API without scheduled probes")
    parser.add_argument("--open-browser", action="store_true", help="open the local dashboard after startup")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config = load_config(args.config)
    if args.host is not None:
        config = replace(config, host=args.host)
    if args.port is not None:
        config = replace(config, port=args.port)
    if not 1 <= config.port <= 65535:
        print("端口范围应为 1～65535", file=sys.stderr)
        return 2

    database = Database(config.database_path)
    database.initialize(config)
    service = MonitorService(database)

    if args.once:
        results = service.run_all_nodes()
        service.stop()
        print(f"Completed probes for {len(results)} node(s).")
        return 0

    if not args.no_monitor:
        service.start()
    server = create_server(database, service, config)
    browser_host = "127.0.0.1" if config.host in {"0.0.0.0", "::"} else config.host
    dashboard_url = f"http://{browser_host}:{config.port}/"
    print(f"ProxyPulse is running: {dashboard_url}")
    print("Press Ctrl+C to stop. Proxy credentials stay in the local database.")
    if args.open_browser:
        timer = threading.Timer(0.8, lambda: webbrowser.open(dashboard_url))
        timer.daemon = True
        timer.start()
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        server.shutdown()
        server.server_close()
        service.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
