"""Serve a directory for GET, and append POST /events to reports.ndjson.

Used on the bench Mac so a device can pull artifacts over HTTP and POST
OTA status to the same origin. Not part of the on-device agent.
"""

from __future__ import annotations

import argparse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class Handler(SimpleHTTPRequestHandler):
    reports_path: Path

    def do_POST(self):
        if self.path.split("?", 1)[0] not in ("/events", "/ota-events"):
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.reports_path.parent.mkdir(parents=True, exist_ok=True)
        with self.reports_path.open("ab") as handle:
            handle.write(body)
            if not body.endswith(b"\n"):
                handle.write(b"\n")
        self.send_response(202)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}\n')
        self.log_message("event %s", body[:200])

    def log_message(self, fmt, *args):
        sys_stderr = __import__("sys").stderr
        sys_stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", type=Path, default=Path("."))
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--bind", default="0.0.0.0")
    args = parser.parse_args()
    root = args.dir.resolve()
    Handler.reports_path = root / "reports.ndjson"

    class Bound(Handler):
        def __init__(self, *a, **k):
            super().__init__(*a, directory=str(root), **k)

    server = ThreadingHTTPServer((args.bind, args.port), Bound)
    print(f"serving {root} on {args.bind}:{args.port}  POST /events -> {Handler.reports_path}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
