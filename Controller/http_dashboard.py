"""Read-only dashboard transport shared by site collection and legacy observation."""

from http.server import BaseHTTPRequestHandler
import json
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent


class DashboardHandler(BaseHTTPRequestHandler):
    """Serve static UI/docs and delegate JSON reads to the supplied sensor."""

    def __init__(self, *args, sensor, **kwargs):
        self.sensor = sensor
        super().__init__(*args, **kwargs)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/docs" or path.startswith("/docs/"):
            from local_docs import document
            status, content_type, data = document(path)
            self.respond(status, content_type, data)
            return
        if path == "/":
            data = (ROOT.parent / "Dashboard" / "index.html").read_bytes()
            self.respond(200, "text/html; charset=utf-8", data)
            return
        payload = self.sensor.read(path)
        self.respond(200 if payload is not None else 404, "application/json",
                     json.dumps(payload if payload is not None else
                                {"status": "not_found"}, allow_nan=False).encode())

    def respond(self, status, content_type, data):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_args):
        pass
