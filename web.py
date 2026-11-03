"""Read-only inventory HTTP server. No credentials or mutation endpoints."""

import csv
import io
import ipaddress
import json
import os
import sys
import traceback
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from docker_inventory import address_key, snapshot
from inventory_catalog import records as catalog_records
from inventory_catalog import view as catalog_view
from inventory_view import decorate, diff_view
from web_views import cloudflare_view, drift_view, ports_view

CONFIG = Path("/config")
DATA = Path("/data")
NETWORK = ipaddress.ip_network(os.environ.get("YGGFLARE_LAN_CIDR", "10.4.20.0/23"))
SOURCE = Path("/compose-source")
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
.pill{white-space:nowrap;overflow-wrap:normal;word-break:normal;display:inline-block;border:1px solid #4b6175;border-radius:6px;padding:2px 6px;margin:2px;font-size:12px}
button,select{font:inherit;background:var(--panel);color:var(--fg);border:1px solid var(--border);border-radius:7px;padding:10px;min-height:44px}
summary{font-weight:700;cursor:pointer;padding:8px;min-height:44px}details:not([open]){padding-bottom:8px}
tr[data-flags~="missing"] td,.pill.missing{background:#493d1b}
tr[data-flags~="retired"] td,.pill.retired{background:#333b46;color:#c0c8d1}
tr[data-flags~="new"] td,.pill.new{background:#123f36}
tr[data-flags~="drift"] td,.pill.drift{background:#4a2531}
.field-drift{color:#ffb6c4!important;font-weight:700}.difference{display:block;margin-top:5px;font-size:12px}
[hidden]{display:none!important}td{overflow-wrap:anywhere}summary:focus-visible,button:focus-visible,select:focus-visible{outline:2px solid var(--accent)}
@media(max-width:700px){
.scroll{overflow:visible}table{min-width:0}thead{display:block}thead tr{display:flex;flex-wrap:wrap;gap:4px}th{position:static;border:1px solid var(--border);border-radius:5px;padding:8px;min-height:44px}
tbody,tr,td{display:block}tbody tr{border:1px solid var(--border);border-radius:8px;margin:12px 0;overflow:hidden}
td{display:grid;grid-template-columns:110px minmax(0,1fr);gap:10px}td::before{content:attr(data-label);font-size:12px;font-weight:600;color:var(--muted)}
.toolbar input{min-width:0;width:100%;flex-basis:100%}.toolbar label{display:flex;gap:8px;align-items:center}nav{width:100%}nav a{flex:1;text-align:center}details.card{padding:8px}
}
footer{padding:28px;color:var(--muted)}@media(max-width:700px){main{padding:12px}header{padding:16px}h1{font-size:20px}}
"""

SCRIPT = """
const filter=document.querySelector('#filter');
const rows=[...document.querySelectorAll('tr[data-search]')];
const statusFilter=document.querySelector('#status-filter');
const classFilter=document.querySelector('#class-filter');
function update(){
const q=(filter?.value||'').toLowerCase(), flag=statusFilter?.value||'', kind=classFilter?.value||'';
for(const row of rows){row.hidden=!row.dataset.search.includes(q)||(!!flag&&!(row.dataset.flags||'').split(' ').includes(flag))||(!!kind&&row.dataset.kind!==kind);}
const active=!!(q||flag||kind);
for(const group of document.querySelectorAll('details[data-group]')){
if(active&&group.dataset.beforeSearch===undefined)group.dataset.beforeSearch=String(group.open);
group.hidden=active&&!group.querySelector('tr[data-search]:not([hidden])');
if(active&&!group.hidden)group.open=true;
if(!active&&group.dataset.beforeSearch!==undefined){group.open=group.dataset.beforeSearch==='true';delete group.dataset.beforeSearch;}
}}
for(const control of [filter,statusFilter,classFilter]){if(control)control.addEventListener('input',update);}
for(const [id,open] of [['expand-all',true],['collapse-all',false]]){
const button=document.querySelector('#'+id);if(button)button.addEventListener('click',()=>{for(const group of document.querySelectorAll('details[data-group]')){group.open=open;delete group.dataset.beforeSearch;}});}
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
                "source": "Static inventory",
            }
        )
    docker_hosts, warnings = snapshot(
        SOURCE, NETWORK, os.environ.get("YGGFLARE_INTERNAL_DOMAIN", "")
    )

    def optional_state(filename):
        try:
            value = read_json(DATA / filename)
            if not isinstance(value, dict):
                raise ValueError("Invalid state")
            return value
        except (OSError, ValueError, TypeError):
            warnings.append(
                f"{filename} is unavailable or invalid; showing other observations."
            )
            return {}

    # The metadata cache is shared; request-specific notices must not mutate it.
    warnings = list(warnings)
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
    catalogs = {}
    for kind, filename in [
        ("reserved", "static-hosts-reserved.json"),
        ("retired", "retired-devices.json"),
    ]:
        try:
            catalogs[kind] = (
                catalog_records(read_json(CONFIG / filename))
                if (CONFIG / filename).is_file()
                else []
            )
        except (OSError, ValueError, TypeError):
            catalogs[kind] = []
            warnings.append(
                f"{filename} could not be read: expected a list of records or an object with a hosts/devices list."
            )
    diffs = decorate(hosts, inventory, state)
    return {
        **catalogs,
        "diffs": diffs,
        "hosts": sorted(hosts, key=lambda h: (address_key(h["ipv4"]), h["hostname"])),
        "warnings": warnings,
        "network_state": state,
        "cloudflare_view": optional_state("cloudflare-view.json"),
        "cloudflare_view_status": optional_state("cloudflare-view-status.json"),
        "orphan_observations": optional_state("orphan-observations.json"),
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
            ("reserved", "Reserved"),
            ("retired", "Retired"),
            ("ports", "Ports & DNS-SD"),
            ("drift", "Recent drift"),
            ("diff", "Inventory diff"),
            ("cloudflare", "Cloudflare lifecycle"),
        )
    )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Yggflare · {escape(tab.title())}</title><style>{CSS}</style></head>
<body><header><div><h1>Yggflare</h1><span class="muted">Read-only network inventory</span></div><nav>{links}</nav></header>
<main>{content}</main><footer>Yggflare · Local snapshot · No modification endpoints</footer>
<script>{SCRIPT}</script></body></html>"""


def table(headers, rows, row_meta=None):
    head = "".join(
        f'<th data-col="{i}">{escape(h)}</th>' for i, h in enumerate(headers)
    )
    body = []
    for row_index, values in enumerate(rows):
        cells = ""
        meta = row_meta[row_index] if row_meta else {}
        for header, value in zip(headers, values):
            attribute = ""
            if header in ("IP", "IPv6"):
                version, number, prefix = address_key(value)
                attribute = f' data-sort="{version}:{number:039d}:{prefix:03d}"'
            display = escape(str(value))
            if header in ("Class", "Flags") and value:
                display = " ".join(
                    f'<span class="pill">{escape(v.strip())}</span>'
                    for v in str(value).split(",")
                )
            field = {
                "IP": "IPv4",
                "MAC": "MAC",
                "Ports": "Port",
                "Status": "Presence",
            }.get(header)
            changes = [
                d
                for d in meta.get("differences", [])
                if d["field"] == field and d["severity"] == "drift"
            ]
            if changes:
                attribute += ' class="field-drift"'
                display += "".join(
                    '<small class="difference">'
                    + escape(
                        f"{d['field']} drift: declared {d['expected']}; observed {d['observed']}"
                    )
                    + "</small>"
                    for d in changes
                )
            cells += f'<td{attribute} data-label="{escape(header, quote=True)}"><span>{display}</span></td>'
        search = escape(" ".join(str(v) for v in values).lower(), quote=True)
        flags = escape(" ".join(meta.get("flags", [])), quote=True)
        kind = escape(meta.get("device_class", ""), quote=True)
        body.append(
            f'<tr data-search="{search}" data-flags="{flags}" data-kind="{kind}">{cells}</tr>'
        )
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
                    i.get("device_class", "device"),
                    i.get("last_seen") or "Never observed",
                    ", ".join(i.get("flags", [])),
                    i["status"],
                ]
                for i in sorted(
                    hosts, key=lambda a: (address_key(a["ipv4"]), a["hostname"])
                )
            ]
            blocks.append(
                f'<details class="card" data-group="1" open><summary>{escape(group)} · {len(rows)} hosts</summary>'
                + table(
                    [
                        "Host",
                        "MAC",
                        "IP",
                        "Comment",
                        "Aliases / router names",
                        "IPv6",
                        "Ports",
                        "Class",
                        "Last seen",
                        "Flags",
                        "Status",
                    ],
                    rows,
                    sorted(
                        hosts, key=lambda a: (address_key(a["ipv4"]), a["hostname"])
                    ),
                )
                + "</details>"
            )
        controls = '<div class="toolbar"><button type="button" id="expand-all">Expand all</button><button type="button" id="collapse-all">Collapse all</button><label>Show <select id="status-filter"><option value="">All flags</option><option value="missing">Missing info</option><option value="drift">Drift</option><option value="retired">Retired</option><option value="new">Newly discovered</option></select></label><label>Class <select id="class-filter"><option value="">All classes</option>'
        controls += "".join(
            f"<option>{escape(kind)}</option>"
            for kind in sorted({h.get("device_class", "device") for h in data["hosts"]})
        )
        controls += '</select></label></div><p class="legend"><span class="pill missing">Missing info</span> <span class="pill drift">Drift</span> <span class="pill retired">Retired</span> <span class="pill new">Newly discovered</span></p>'
        content = (
            f'<p class="muted">Latest inventory scan: {escape(data["scanned_at"] or "not available")}</p>'
            + search
            + controls
            + "".join(blocks)
        )
    elif tab in ("reserved", "retired"):
        content = search + catalog_view(tab, data, table)
    elif tab == "ports":
        content = search + ports_view(data, table)
    elif tab == "diff":
        content = search + diff_view(data, table)
    elif tab == "drift":
        content = search + drift_view(data, table)
    else:
        content = search + cloudflare_view(data, table)
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
            "/reserved",
            "/retired",
            "/ports",
            "/drift",
            "/diff",
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
                    "device_class",
                    "last_seen",
                    "flags",
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
        except (OSError, ValueError, TypeError, KeyError) as error:
            # Log code locations only: exception messages and local values may
            # contain private inventory, credentials or Docker metadata.
            frames = traceback.extract_tb(error.__traceback__)
            location = " -> ".join(
                f"{Path(frame.filename).name}:{frame.lineno}:{frame.name}"
                for frame in frames
            )
            print(
                f"[web] Inventory unavailable: {type(error).__name__} at {location}",
                file=sys.stderr,
                flush=True,
            )
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
