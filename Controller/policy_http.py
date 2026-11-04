"""Loopback-only, read-only UI/API for the offline policy workbench."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import sqlite3
from urllib.parse import parse_qs, urlsplit

from firewall_policy import FORMAT, PolicyEvaluator, diff_policies, query
from policy_store import PolicyStore


PAGE = b'''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Adaptive IPS framework - policy workbench</title>
<style>body{font:16px/1.5 system-ui;background:#101317;color:#e5e7eb;max-width:1000px;margin:30px auto;padding:20px}a{color:#5eead4}input,select,button{font:inherit;padding:8px;margin:5px;background:#20252c;color:#fff;border:1px solid #64748b;border-radius:5px}label{display:inline-block}pre{padding:16px;overflow:auto;background:#20252c}strong{color:#5eead4}button{cursor:pointer}</style>
<h1>Adaptive IPS framework</h1><h2>Read-only policy workbench</h2>
<p><strong>Operator-described header model.</strong> Native firewall parsing, routing, NAT, session state and actual enforcement are outside this assessment.</p>
<p><a href="/docs/deployment/policy-workbench">Test runbook</a> | <a href="/docs/developers/policy-workbench-code-tour">Code and rationale</a></p>
<p id="status" role="status">Loading snapshots...</p>
<label>Snapshot <select id="snapshot" aria-label="Policy snapshot"></select></label>
<button id="details">Show policy and provenance</button>
<button id="audit">Audit supported header subset</button>
<form id="search"><h3>Concrete header query</h3>
<label>Source IP <input id="source" value="192.0.2.10" required></label>
<label>Destination IP <input id="destination" value="198.51.100.20" required></label>
<label>Protocol <select id="protocol"><option>tcp</option><option>udp</option><option>icmp</option><option>icmpv6</option></select></label>
<label>Destination port <input id="dport" value="443" type="number" min="0" max="65535"></label>
<label>Source port (optional) <input id="sport" type="number" min="0" max="65535"></label>
<button type="submit">Evaluate model and search rules</button></form>
<h3>Snapshot comparison</h3><label>Earlier snapshot ID <input id="before" size="40"></label>
<button id="diff">Compare earlier with selected</button>
<button id="impact">Compare modeled impact</button>
<h3>Offline model-change preview</h3>
<p>No changes are applied or imported. An equivalent header verdict does not establish native firewall safety.</p>
<label>Operation <select id="operation"><option value="disable_rule">Disable model rule</option><option value="remove_rule">Remove model rule</option><option value="move_rule_before">Move model rule before another</option></select></label>
<label>Target rule ID <input id="rule"></label>
<label>Before rule ID (move only) <input id="anchor"></label>
<button id="preview">Preview without applying</button>
<pre id="result" aria-live="polite">Import the supplied reference fixture with the CLI first. All actions here are read-only.</pre>
<script>
const el=id=>document.getElementById(id);
async function load(path){const r=await fetch(path,{cache:'no-store'});const data=await r.json();if(!r.ok)throw Error(data.error||'Request failed');return data;}
async function display(path){try{el('result').textContent=JSON.stringify(await load(path),null,2);}catch(e){el('result').textContent=e.message;}}
el('details').onclick=()=>display('/policy/snapshots/'+encodeURIComponent(el('snapshot').value));
el('audit').onclick=()=>display('/policy/audit?'+new URLSearchParams({snapshot:el('snapshot').value}));
el('search').onsubmit=e=>{e.preventDefault();const p=new URLSearchParams({snapshot:el('snapshot').value,source:el('source').value,destination:el('destination').value,protocol:el('protocol').value});if(el('dport').value)p.set('destination_port',el('dport').value);if(el('sport').value)p.set('source_port',el('sport').value);display('/policy/search?'+p);};
el('protocol').onchange=()=>{const ports=['tcp','udp'].includes(el('protocol').value);el('dport').disabled=!ports;el('sport').disabled=!ports;if(!ports){el('dport').value='';el('sport').value='';}};
el('diff').onclick=()=>display('/policy/diff?'+new URLSearchParams({before:el('before').value,after:el('snapshot').value}));
el('impact').onclick=()=>display('/policy/impact?'+new URLSearchParams({before:el('before').value,after:el('snapshot').value}));
el('preview').onclick=()=>{const p=new URLSearchParams({snapshot:el('snapshot').value,operation:el('operation').value,rule:el('rule').value});if(el('operation').value==='move_rule_before')p.set('before_rule',el('anchor').value);display('/policy/preview?'+p);};
load('/policy/snapshots').then(data=>{el('status').textContent=data.total+' snapshot(s); '+(data.truncated?'list truncated; use CLI IDs':'all listed')+'. No firewall writes.';for(const item of data.snapshots){const o=document.createElement('option');o.value=item.id;o.textContent=item.site+'/'+item.device+'/'+item.context+' - '+item.revision+' - '+item.id.slice(0,12);el('snapshot').append(o);}}).catch(e=>el('status').textContent=e.message);
</script></html>'''


def _arguments(parameters, allowed, required=()):
    if set(parameters) - set(allowed) or any(len(values) != 1 for values in parameters.values()):
        raise ValueError("Unknown or repeated query parameter")
    values = {key: items[0] for key, items in parameters.items()}
    if any(not values.get(name) for name in required):
        raise ValueError("Missing required query parameter")
    return values


def read_policy_api(store, path, parameters):
    if path == "/policy/status":
        _arguments(parameters, ())
        return {"mode": "read_only", "format": FORMAT, "source_kind": "operator_description",
                "native_vendor_parser": False, "reachability": "NOT_EVALUATED", "enforcement": "NOT_ATTEMPTED"}
    if path == "/policy/snapshots":
        values = _arguments(parameters, ("limit",))
        return store.list_snapshots(int(values.get("limit", "100")))
    if path.startswith("/policy/snapshots/"):
        _arguments(parameters, ())
        identifier = path.removeprefix("/policy/snapshots/")
        return {"snapshot_id": identifier, "policy": store.get_snapshot(identifier),
                "provenance": store.provenance(identifier)}
    if path == "/policy/search":
        values = _arguments(parameters, ("snapshot", "source", "destination", "protocol", "destination_port",
                                        "source_port", "limit", "include_disabled"),
                            ("snapshot", "source", "destination", "protocol"))
        if values.get("include_disabled", "false") not in ("true", "false"):
            raise ValueError("include_disabled must be true or false")
        point = query(values["source"], values["destination"], values["protocol"],
                      int(values["destination_port"]) if values.get("destination_port") else None,
                      int(values["source_port"]) if values.get("source_port") else None)
        result = PolicyEvaluator(store.get_snapshot(values["snapshot"])).search(
            point, int(values.get("limit", "100")), values.get("include_disabled") == "true")
        return dict(result, snapshot_id=values["snapshot"])
    if path == "/policy/diff":
        values = _arguments(parameters, ("before", "after"), ("before", "after"))
        return dict(diff_policies(store.get_snapshot(values["before"]), store.get_snapshot(values["after"])),
                    before=values["before"], after=values["after"])
    if path == "/policy/audit":
        values = _arguments(parameters, ("snapshot",), ("snapshot",))
        from policy_audit import audit_policy
        return dict(audit_policy(store.get_snapshot(values["snapshot"])), snapshot_id=values["snapshot"])
    if path == "/policy/impact":
        values = _arguments(parameters, ("before", "after", "limit"), ("before", "after"))
        from policy_change import impact
        return impact(store.get_snapshot(values["before"]), store.get_snapshot(values["after"]), int(values.get("limit", "100")))
    if path == "/policy/preview":
        values = _arguments(parameters, ("snapshot", "operation", "rule", "before_rule", "limit"), ("snapshot", "operation", "rule"))
        from policy_change import proposal
        operation = {"operation": values["operation"], "rule": values["rule"]}
        if "before_rule" in values:
            operation["before_rule"] = values["before_rule"]
        request = {"version": "policy-proposal-v1", "base_snapshot": values["snapshot"],
                   "reason": "Interactive offline model preview; operator review still required", "operations": [operation]}
        return proposal(store.get_snapshot(values["snapshot"]), request, int(values.get("limit", "100")))
    return None


class PolicyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            target = urlsplit(self.path)
            parameters = parse_qs(target.query, keep_blank_values=True, strict_parsing=True, max_num_fields=16)
            if target.path == "/":
                _arguments(parameters, ())
                self.respond(200, "text/html; charset=utf-8", PAGE)
                return
            if target.path == "/docs" or target.path.startswith("/docs/"):
                from local_docs import document
                status, content_type, body = document(target.path)
                self.respond(status, content_type, body)
                return
            # Each HTTP request owns a read-only SQLite connection; no cross-thread reuse.
            with PolicyStore(self.server.store_path) as store:
                payload = read_policy_api(store, target.path, parameters)
            self.json_response(200 if payload is not None else 404,
                               payload if payload is not None else {"error": "Unknown policy route"})
        except KeyError:
            self.json_response(404, {"error": "Unknown snapshot"})
        except (ValueError, TypeError) as error:
            self.json_response(400, {"error": str(error)})
        except (OSError, sqlite3.Error):
            self.json_response(503, {"error": "Policy store unavailable; inspect the local database"})

    def json_response(self, status, payload):
        self.respond(status, "application/json", json.dumps(payload, allow_nan=False).encode())

    def respond(self, status, content_type, body):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass  # URLs can contain private device addresses; do not emit access logs.


def make_server(path, port=8082):
    with PolicyStore(path):
        pass  # Validate before opening a listener.
    server = ThreadingHTTPServer(("127.0.0.1", port), PolicyHandler)
    server.store_path = path
    return server
