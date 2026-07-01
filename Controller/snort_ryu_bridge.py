#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import json, logging, os, time, requests
from threading import Lock
from datetime import datetime, timedelta

BRIDGE_HOST          = "127.0.0.1"
BRIDGE_PORT          = 9000
RYU_API_URL          = os.environ.get("RYU_API_URL", "http://127.0.0.1:8081/ips/block")
MIN_PRIORITY         = 2
DEDUP_WINDOW_SECONDS = 60
IDLE_TIMEOUT         = 300
HARD_TIMEOUT         = 600

os.makedirs("/var/log/snort_ryu_bridge", exist_ok=True)
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [BRIDGE] %(levelname)s: %(message)s",
    handlers=[logging.FileHandler("/var/log/snort_ryu_bridge/bridge.log"),
              logging.StreamHandler()])
log = logging.getLogger(__name__)

_block_cache = {}
_cache_lock  = Lock()
WHITELIST = {"127.0.0.1", "::1"}

def should_block(alert):
    src_ip   = alert.get("src_ip", "")
    priority = int(alert.get("priority", 1))
    message  = alert.get("message", "")
    if src_ip in WHITELIST:
        return False, f"Whitelisted: {src_ip}"
    if priority > MIN_PRIORITY:
        return False, f"Priority {priority} too low"
    with _cache_lock:
        last = _block_cache.get(src_ip)
        if last:
            elapsed = (datetime.utcnow() - last).total_seconds()
            if elapsed < DEDUP_WINDOW_SECONDS:
                return False, f"Already blocked {elapsed:.0f}s ago"
        _block_cache[src_ip] = datetime.utcnow()
    return True, f"Alert: {message} | Priority: {priority}"

def push_block_to_ryu(src_ip, reason):
    payload = {"src_ip": src_ip, "reason": reason,
               "idle_timeout": IDLE_TIMEOUT, "hard_timeout": HARD_TIMEOUT}
    try:
        resp = requests.post(RYU_API_URL, json=payload, timeout=5)
        if resp.status_code == 200:
            log.info(f"Blocked {src_ip}: {resp.json().get('switches', [])}")
            return True
        log.warning(f"Ryu returned {resp.status_code}: {resp.text}")
        return False
    except requests.RequestException as e:
        log.error(f"Cannot reach Ryu: {e}")
        return False

class BridgeHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass

    def do_POST(self):
        if self.path == "/block":
            length = int(self.headers.get("Content-Length", 0))
            try:
                alert = json.loads(self.rfile.read(length))
            except:
                return self._respond(400, {"status": "error"})
            src_ip = alert.get("src_ip", "")
            if not src_ip:
                return self._respond(400, {"status": "error", "message": "src_ip required"})
            block, reason = should_block(alert)
            if block:
                success = push_block_to_ryu(src_ip, reason)
                self._respond(200 if success else 500,
                              {"status": "blocked" if success else "ryu_error", "src_ip": src_ip})
            else:
                log.debug(f"Skipped {src_ip}: {reason}")
                self._respond(200, {"status": "skipped", "src_ip": src_ip})
        else:
            self._respond(404, {"status": "not_found"})

    def do_GET(self):
        if self.path == "/health":
            self._respond(200, {"status": "ok", "cache_size": len(_block_cache)})
        else:
            self._respond(404, {"status": "not_found"})

    def _respond(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

def cleanup_cache():
    while True:
        time.sleep(60)
        cutoff = datetime.utcnow() - timedelta(seconds=DEDUP_WINDOW_SECONDS * 2)
        with _cache_lock:
            stale = [ip for ip, ts in _block_cache.items() if ts < cutoff]
            for ip in stale: del _block_cache[ip]

if __name__ == "__main__":
    import threading
    threading.Thread(target=cleanup_cache, daemon=True).start()
    server = HTTPServer((BRIDGE_HOST, BRIDGE_PORT), BridgeHandler)
    log.info(f"Bridge listening on {BRIDGE_HOST}:{BRIDGE_PORT}")
    log.info(f"Forwarding to Ryu: {RYU_API_URL}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Bridge stopped.")
