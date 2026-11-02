"""Read-only inventory HTTP server. No credentials or mutation endpoints."""

import csv
import io
import ipaddress
import json
import os
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from docker_inventory import address_key, snapshot

CONFIG = Path(os.environ.get("YGGFLARE_CONFIG", "/config"))
DATA = Path(os.environ.get("YGGFLARE_DATA", "/data"))
NETWORK = ipaddress.ip_network(os.environ.get("YGGFLARE_LAN_CIDR", "10.4.20.0/23"))
SOURCE = Path(os.environ.get("YGGFLARE_SOURCE", "/compose-source"))
MAX_BYTES = 4 * 1024 * 1024

CSS = """
:root{color-scheme:dark;--bg:#101721;--panel:#192431;--border:#334155;--fg:#edf2f7;--muted:#a8b7c8;--accent:#7dd3fc}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px system-ui,-apple-system,sans-serif}
header{padding:22px 28px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
h1{font-size:24px;margin:0}h2{font-size:16px;margin:22px 0 12px}.muted{color:var(--muted)}main{padding:20px 28px;max-width:1700px;margin:auto}
nav{display:flex;gap:8px;flex-wrap:wrap}a{color:var(--accent);text-decoration:none}nav a{border:1px solid var(--border);padding:8px 12px;border-radius:8px}
nav a.active{background:#24364b}.toolbar{display:flex;gap:12px;flex-wrap:wrap;align-items:center;margin-bottom:18px}
input{background:var(--panel);color:var(--fg);border:1px solid var(--border);border-radius:8px;padding:11px;min-width:230px;flex:1}
.card{border:1px solid var(--border);background:var(--panel);border-radius:10px;padding:14px;margin-bottom:16px}
.scroll{overflow:auto}table{border-collapse:collapse;width:100%;min-width:940px}th,td{padding:9px 11px;border-bottom:1px solid var(--border);text-align:left;vertical-align:top}
th{position:sticky;top:0;background:#253548;font-size:12px;color:var(--muted);cursor:pointer}
td code{color:#b5e4ff}tr:hover td{background:#233244}.group{background:#29394d;font-weight:700}
.pill{display:inline-block;border:1px solid #4b6175;border-radius:6px;padding:2px 6px;margin:2px;font-size:12px}
footer{padding:28px;color:var(--muted)}@media(max-width:700px){main{padding:12px}header{padding:16px}h1{font-size:20px}}
"""

SCRIPT = """
const filter=document.querySelector('#filter');
const rows=[...document.querySelectorAll('tr[data-search]')];
function update(){const q=(filter?.value||'').toLowerCase();for(const row of rows){row.hidden=!row.dataset.search.includes(q);}
for(const group of document.querySelectorAll('section[data-group]')){group.hidden=!!q&&!group.querySelector('tr[data-search]:not([hidden])');}}
if(filter){filter.addEventListener('input',update);}
function compareCells(a,b,index){
const x=a.cells[index],y=b.cells[index];
if(x.dataset.sort!==undefined&&y.dataset.sort!==undefined){return x.dataset.sort<y.dataset.sort?-1:x.dataset.sort>y.dataset.sort?1:0;}
return x.textContent.localeCompare(y.textContent,undefined,{numeric:true});}
for(const th of document.querySelectorAll('th[data-col]')){th.addEventListener('click',()=>{
const index=+th.dataset.col;const table=th.closest('table');const body=table.querySelector('tbody[data-sortable]');if(!body)return;
const direction=th.dataset.direction==='asc'?-1:1;
for(const other of table.querySelectorAll('th')){delete other.dataset.direction;other.removeAttribute('aria-sort');}
th.dataset.direction=direction===1?'asc':'desc';th.setAttribute('aria-sort',direction===1?'ascending':'descending');
const sorted=[...body.querySelectorAll('tr[data-search]')].sort((a,b)=>direction*compareCells(a,b,index));body.replaceChildren(...sorted);});}
"""


def read_json(path):
    """Read bounded local JSON, returning an empty object for absent optional state."""
    if not path.is_file():
        return {}
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("Inventory input exceeds 4 MiB")
    return json.loads(path.read_text(encoding="utf-8"))


def model():
    """Combine static inventory, read-only Docker metadata and saved scans."""
    inventory = read_json(CONFIG / "static-hosts.json")
    state = read_json(DATA / "network-inventory" / "state.json")
    ownership = read_json(DATA / "managed-hosts.json")
    retained = read_json(CONFIG / "retained-dns.json")
    hosts = []
    known = set()
    for item in inventory.get("hosts", []):
        ip = item.get("ipv4", "")
        if not isinstance(ip, str):
            continue
        known.add(ip)
        try:
            subnet = str(ipaddress.ip_network(f"{ip}/27", strict=False))
        except ValueError:
            subnet = "Unassigned"
        observed = state.get("hosts", {}).get(ip, {})
        ports = item.get("ports", [])
        declared_ports = [
            f"{p.get('protocol','tcp')}/{p.get('port')}"
            for p in ports
            if isinstance(p, dict) and p.get("port") is not None
        ]
        hosts.append(
            {
                "hostname": item.get("hostname", ""),
                "ipv4": ip,
                "mac": item.get("mac", ""),
                "description": item.get("notes", item.get("description", "")),
                "aliases": item.get("aliases", []),
                "ipv6": item.get("ipv6", ""),
                "subnet": subnet,
                "ports": declared_ports,
                "observed_ports": observed.get("ports", []),
                "last_seen": state.get("scanned_at", "") if observed else "",
                "status": "seen" if observed else "not observed",
            }
        )
    docker_hosts, warnings = snapshot(
        SOURCE, NETWORK, os.environ.get("YGGFLARE_INTERNAL_DOMAIN", "")
    )
    for item in docker_hosts:
        ip = item["ipv4"]
        observed = state.get("hosts", {}).get(ip, {})
        known.add(ip)
        hosts.append(
            {
                **item,
                "subnet": (
                    str(ipaddress.ip_network(f"{ip}/27", strict=False))
                    if ip
                    else "Unassigned"
                ),
                "observed_ports": observed.get("ports", []),
                "last_seen": state.get("scanned_at", "") if observed else "",
            }
        )
    for ip, observed in state.get("hosts", {}).items():
        if ip in known:
            continue
        try:
            subnet = str(ipaddress.ip_network(f"{ip}/27", strict=False))
        except ValueError:
            subnet = "Unassigned"
        hosts.append(
            {
                "hostname": "",
                "ipv4": ip,
                "mac": observed.get("mac", ""),
                "description": "Not in static inventory",
                "aliases": [],
                "ipv6": "",
                "subnet": subnet,
                "ports": [],
                "observed_ports": observed.get("ports", []),
                "last_seen": state.get("scanned_at", ""),
                "status": "unmanaged",
            }
        )
    return {
        "hosts": sorted(hosts, key=lambda h: (address_key(h["ipv4"]), h["hostname"])),
        "warnings": warnings,
        "services": state.get("advertisements", []),
        "scanned_at": state.get("scanned_at", ""),
        "managed_hosts": sorted(ownership.get("hosts", {}).keys()),
        "retained_dns": retained,
    }


def page(tab, content):
    links = "".join(
        f'<a class="{"active" if name == tab else ""}" href="/{name}">{label}</a>'
        for name, label in (
            ("inventory", "Inventory"),
            ("ports", "Ports & DNS-SD"),
            ("cloudflare", "Cloudflare ownership"),
        )
    )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Yggflare · {escape(tab.title())}</title><style>{CSS}</style></head>
<body><header><div><h1>Yggflare</h1><span class="muted">Read-only network inventory</span></div><nav>{links}</nav></header>
<main>{content}</main><footer>Yggflare · Local snapshot · No modification endpoints</footer>
<script>{SCRIPT}</script></body></html>"""


def table(headers, rows):
    head = "".join(
        f'<th data-col="{i}">{escape(h)}</th>' for i, h in enumerate(headers)
    )
    body = []
    for values in rows:
        cells = ""
        for header, value in zip(headers, values):
            attribute = ""
            if header in ("IP", "IPv6"):
                version, number, prefix = address_key(value)
                attribute = f' data-sort="{version}:{number:039d}:{prefix:03d}"'
            cells += f"<td{attribute}>{escape(str(value))}</td>"
        search = escape(" ".join(str(v) for v in values).lower(), quote=True)
        body.append(f'<tr data-search="{search}">{cells}</tr>')
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody data-sortable="1">{"".join(body)}</tbody></table></div>'


def render(tab, data):
    search = '<div class="toolbar"><input id="filter" type="search" placeholder="Search host, IP, MAC, ports, notes…" aria-label="Filter inventory"><a href="/api/inventory.csv">Export CSV</a> · <a href="/api/inventory.json">Export JSON</a></div>'
    if tab == "inventory":
        groups = {}
        for item in data["hosts"]:
            groups.setdefault(item["subnet"], []).append(item)
        blocks = []
        for group, hosts in sorted(groups.items(), key=lambda x: address_key(x[0])):
            rows = [
                [
                    i["hostname"],
                    i["mac"],
                    i["ipv4"],
                    i["description"],
                    (
                        ", ".join(i["aliases"])
                        if isinstance(i["aliases"], list)
                        else str(i["aliases"])
                    ),
                    i["ipv6"],
                    ", ".join(i["ports"]),
                    i["status"],
                ]
                for i in sorted(
                    hosts, key=lambda a: (address_key(a["ipv4"]), a["hostname"])
                )
            ]
            blocks.append(
                f'<section class="card" data-group="1"><h2>{escape(group)} · {len(rows)} hosts</h2>'
                + table(
                    [
                        "Host",
                        "MAC",
                        "IP",
                        "Comment",
                        "Aliases / router names",
                        "IPv6",
                        "Ports",
                        "Status",
                    ],
                    rows,
                )
                + "</section>"
            )
        content = (
            f'<p class="muted">Latest inventory scan: {escape(data["scanned_at"] or "not available")}</p>'
            + search
            + "".join(blocks)
        )
    elif tab == "ports":
        rows = [
            [
                i["hostname"],
                i["ipv4"],
                ", ".join(i["ports"]),
                ", ".join(i["observed_ports"]),
                "; ".join(
                    f"{port}: {', '.join(sources)}"
                    for port, sources in i.get("port_sources", {}).items()
                ),
                i["status"],
            ]
            for i in data["hosts"]
        ]
        services = [[x] for x in data["services"]]
        content = (
            search
            + '<section class="card"><h2>Declared vs observed ports</h2>'
            + table(
                [
                    "Host",
                    "IP",
                    "Declared / inferred",
                    "Observed",
                    "Port evidence",
                    "Status",
                ],
                rows,
            )
            + "</section>"
        )
        content += (
            '<section class="card"><h2>Last DNS-SD advertisements</h2>'
            + table(["Service identity"], services)
            + "</section>"
        )
    else:
        rows = [[host, "Owned"] for host in data["managed_hosts"]]
        content = '<p class="muted">Ownership registry only. Use the Cloudflare audit CLI for a live orphan/unmanaged classification.</p>'
        content += (
            '<section class="card"><h2>Explicitly owned hostnames</h2>'
            + table(["Hostname", "Ownership"], rows)
            + "</section>"
        )
    notices = "".join(
        f'<p class="muted">{escape(warning)}</p>'
        for warning in data.get("warnings", [])
    )
    return page(tab, notices + content)


class Handler(BaseHTTPRequestHandler):
    """Only GET/HEAD endpoints; do not expose secrets or allow caching."""

    def respond(self, send_body=True):
        uri = urlsplit(self.path).path
        if uri == "/":
            uri = "/inventory"
        if uri not in (
            "/inventory",
            "/ports",
            "/cloudflare",
            "/api/inventory.json",
            "/api/inventory.csv",
        ):
            self.send_error(404)
            return
        try:
            data = model()
            if uri == "/api/inventory.json":
                content = json.dumps(data["hosts"], indent=2).encode()
                mime = "application/json; charset=utf-8"
            elif uri == "/api/inventory.csv":
                output = io.StringIO()
                writer = csv.writer(output)
                columns = (
                    "hostname",
                    "mac",
                    "ipv4",
                    "description",
                    "ipv6",
                    "subnet",
                    "aliases",
                    "ports",
                    "observed_ports",
                    "source",
                    "status",
                )
                writer.writerow(columns)
                for host in data["hosts"]:
                    writer.writerow(
                        [
                            (
                                ", ".join(host.get(key, []))
                                if isinstance(host.get(key), list)
                                else host.get(key, "")
                            )
                            for key in columns
                        ]
                    )
                content = output.getvalue().encode()
                mime = "text/csv; charset=utf-8"
            else:
                content = render(uri.removeprefix("/"), data).encode()
                mime = "text/html; charset=utf-8"
        except (OSError, ValueError, TypeError, KeyError):
            self.send_error(503, "Inventory unavailable")
            return
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'",
        )
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        if send_body:
            self.wfile.write(content)

    def do_GET(self):
        self.respond()

    def do_HEAD(self):
        self.respond(False)

    def log_message(self, fmt, *args):
        return


def serve():
    """Bind only to loopback unless explicitly configured otherwise."""
    port = int(os.environ.get("YGGFLARE_WEB_PORT", "8787"))
    if not 1 <= port <= 65535:
        raise ValueError("Invalid YGGFLARE_WEB_PORT")
    host = os.environ.get("YGGFLARE_WEB_BIND", "127.0.0.1")
    if host not in ("127.0.0.1", "::1", "0.0.0.0"):
        raise ValueError("Unsupported web bind address")
    with ThreadingHTTPServer((host, port), Handler) as server:
        server.serve_forever()


if __name__ == "__main__":
    serve()
