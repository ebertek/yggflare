"""Explicit read-only operator views over the same query layer as MCP."""

import json
from html import escape
from urllib.parse import urlencode

# Fixed dispatch; never use user input to select arbitrary Python methods.
VIEWS = {
    "services": {
        "list": ("Docker services", "list_docker_services", "query"),
        "show": ("Exact service", "get_docker_service", "identifier"),
        "drift": ("Compose review findings", "get_compose_drift", ""),
        "dependencies": (
            "Declared dependencies",
            "get_service_dependencies",
            "identifier",
        ),
        "ingress": ("Ingress evidence", "get_ingress_path", "hostname"),
        "assurance": (
            "Cross-source ingress evidence",
            "get_ingress_evidence",
            "hostname",
        ),
    },
    "topology": {
        "networks": ("Network relationships", "get_network_topology", ""),
    },
    "assurance": {
        "audit": ("Cloudflare audit findings", "get_cloudflare_audit", "hostname"),
        "dns": ("Cloudflare DNS", "get_cloudflare_dns", "hostname"),
        "access": ("Cloudflare Access", "get_cloudflare_access", "hostname"),
        "tunnel": ("Cloudflare Tunnel", "get_cloudflare_tunnel", "hostname"),
    },
    "traefik": {
        "status": ("Traefik collection status", "get_traefik_status", ""),
        "routes": ("Traefik routers", "list_traefik_routes", "query"),
        "services": ("Traefik backend services", "list_traefik_services", "query"),
        "middlewares": ("Traefik middlewares", "list_traefik_middlewares", "query"),
    },
    "komodo": {
        "status": ("Komodo collection status", "get_komodo_status", ""),
        "servers": ("Komodo servers", "list_komodo_servers", "query"),
        "stacks": ("Komodo stacks and revisions", "list_komodo_stacks", "query"),
        "services": ("Komodo stack services", "list_komodo_services", "query"),
        "deployments": (
            "Komodo standalone deployments",
            "list_komodo_deployments",
            "query",
        ),
    },
    "kuma": {
        "status": ("Kuma collection status", "get_kuma_status", ""),
        "monitors": ("Kuma exported monitors", "list_kuma_monitors", "query"),
        "coverage": (
            "Candidate monitoring coverage",
            "get_monitoring_coverage",
            "query",
        ),
    },
    "probes": {
        "status": ("Probe collection status", "get_probe_status", ""),
        "results": ("Independent probe results", "list_probe_results", "query"),
    },
    "findings": {
        "history": ("Finding lifecycle", "list_finding_history", "query"),
        "transitions": ("Finding transitions", "list_finding_transitions", "query"),
    },
    "operations": {
        "health": ("Controller health", "get_yggflare_health", ""),
        "evidence": ("Source evidence quality", "get_evidence_overview", ""),
        "jobs": ("Scheduled jobs", "get_job_status", ""),
        "history": ("Job history", "get_job_history", "job"),
        "backup": ("Backup evidence", "get_backup_status", ""),
        "notifications": ("Notification evidence", "get_notification_status", ""),
    },
}
UNPAGED = {
    "get_yggflare_health",
    "get_evidence_overview",
    "get_job_status",
    "get_backup_status",
    "get_notification_status",
    "get_traefik_status",
    "get_komodo_status",
    "get_kuma_status",
    "get_probe_status",
}
REQUIRED = {"identifier", "hostname"}
CLI_VIEWS = {
    **{("services", name): ("services", name) for name in VIEWS["services"]},
    ("network", "topology"): ("topology", "networks"),
    ("cloudflare", "status"): ("assurance", "audit"),
    ("cloudflare", "dns"): ("assurance", "dns"),
    ("cloudflare", "access"): ("assurance", "access"),
    ("cloudflare", "tunnel"): ("assurance", "tunnel"),
    ("system", "status"): ("operations", "health"),
    ("system", "evidence"): ("operations", "evidence"),
    ("system", "jobs"): ("operations", "jobs"),
    ("system", "history"): ("operations", "history"),
    ("backup", "status"): ("operations", "backup"),
    ("network", "notifications"): ("operations", "notifications"),
    ("network", "findings"): ("findings", "history"),
    ("network", "transitions"): ("findings", "transitions"),
    **{
        (area, name): (area, name)
        for area in ("traefik", "komodo", "kuma", "probes")
        for name in VIEWS[area]
    },
}


class SnapshotChanged(ValueError):
    """A page no longer corresponds to the preceding result set."""


def query(tools, area, view, value="", offset=0, project="", snapshot_id=""):
    """All callers consume the same allowlisted query and pagination contract."""
    if area not in VIEWS or view not in VIEWS[area]:
        raise ValueError("Unknown operator view")
    _, method, field = VIEWS[area][view]
    if len(value) > 512 or len(project) > 253 or offset < 0:
        raise ValueError("Invalid operator view filter")
    if field in REQUIRED and not value and area == "services":
        raise ValueError("An exact service or hostname is required")
    if value and not field:
        raise ValueError("This view accepts no identifier")
    if (
        project
        and area not in {"services", "topology"}
        and (area, view) != ("kuma", "coverage")
    ):
        raise ValueError("Project filter is not supported for this view")
    if project and view in {"ingress", "assurance"}:
        raise ValueError("Project filter is not supported for ingress")
    kwargs = {field: value} if field else {}
    if method not in UNPAGED:
        kwargs.update(offset=offset, limit=50)
    elif offset:
        raise ValueError("This view does not support pagination")
    if project:
        kwargs["project_name"] = project
    result = getattr(tools, method)(**kwargs)
    if snapshot_id and snapshot_id != result.get("snapshot_id"):
        raise SnapshotChanged("Result set changed; restart pagination at offset zero")
    return result


def display(value):
    """Represent null as unknown and never interpret evidence as markup."""
    if value is None:
        return "Unknown"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, list):
        return ", ".join(display(item) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=True, sort_keys=True)
    # Escape terminal control characters as well as embedded newlines.
    return "".join(
        char if char.isprintable() else repr(char)[1:-1] for char in str(value)
    )


def sections(result):
    """Separate context from rows, including nested ingress layer evidence."""
    context = {
        key: val
        for key, val in result.items()
        if key not in {"items", "jobs", "layers"}
    }
    groups = []
    for key in ("items", "jobs"):
        if isinstance(result.get(key), list):
            groups.append((key.capitalize(), result[key]))
    for key, layer in result.get("layers", {}).items():
        groups.append((key.capitalize(), layer.get("items", [])))
        context[key + "_total"] = layer.get("total")
        context[key + "_source_truncated"] = layer.get("source_truncated")
    return context, groups


def cli_text(result):
    context, groups = sections(result)
    lines = [f"{key}: {display(value)}" for key, value in context.items()]
    for title, rows in groups:
        lines.append("\n" + title + ":")
        if not rows:
            lines.append("  No observations in this page")
        for row in rows:
            lines.append(
                "  "
                + " | ".join(f"{key}={display(value)}" for key, value in row.items())
            )
    return "\n".join(lines)


def render(area, tools, table, params):
    """Render only explicit GET views; no buttons trigger collection or writes."""
    views = VIEWS[area]
    view = params.get("view", [next(iter(views))])[0]
    value = params.get("q", [""])[0]
    project = params.get("project", [""])[0]
    offset = int(params.get("offset", ["0"])[0])

    def link(target, label, **extra):
        args = {"view": target, **extra}
        return f'<a href="/{area}?{escape(urlencode(args), quote=True)}">{escape(label)}</a>'

    nav = (
        '<div class="toolbar">'
        + " · ".join(link(key, item[0]) for key, item in views.items())
        + "</div>"
    )
    if view in {"show", "dependencies", "ingress", "assurance"} and not value:
        return nav + "<p>Choose an exact service or alias from the service list.</p>"
    try:
        result = query(
            tools,
            area,
            view,
            value,
            offset,
            project,
            params.get("snapshot_id", [""])[0],
        )
    except SnapshotChanged:
        return (
            nav
            + "<p>Result set changed; "
            + link(view, "restart pagination", q=value, project=project)
            + ".</p>"
        )
    context, groups = sections(result)
    content = nav + f"<h2>{escape(views[view][0])}</h2>"
    content += '<div class="toolbar"><input id="filter" type="search" aria-label="Filter this page" placeholder="Filter this page…"></div>'
    content += (
        '<div class="card">'
        + table(
            ["Evidence", "Value"], [[key, display(val)] for key, val in context.items()]
        )
        + "</div>"
    )
    for title, rows in groups:
        content += f"<h2>{escape(title)}</h2>"
        if not rows:
            content += '<p class="muted">No observations in this page.</p>'
            continue
        columns = list(dict.fromkeys(key for row in rows for key in row))
        content += table(
            columns, [[display(row.get(key)) for key in columns] for row in rows]
        )
    if area == "services" and view == "list":
        links = []
        for row in result.get("items", []):
            identifier = row.get("container_name")
            if identifier:
                options = {"q": identifier, "project": row.get("project") or ""}
                links.append(
                    link("show", identifier, **options)
                    + " · "
                    + link("dependencies", "Dependencies", **options)
                )
            for alias in row.get("aliases", []):
                links.append(
                    link("ingress", "Ingress: " + alias, q=alias)
                    + " · "
                    + link("assurance", "Cross-source evidence", q=alias)
                )
        if links:
            content += (
                '<h2>Investigate a service</h2><div class="card">'
                + "<p>"
                + "</p><p>".join(links)
                + "</p></div>"
            )
    pages = []
    if offset:
        pages.append(
            link(
                view, "Previous (restart if results changed)", q=value, project=project
            )
        )
    if result.get("next_offset") is not None:
        pages.append(
            link(
                view,
                "Next page",
                q=value,
                project=project,
                offset=result["next_offset"],
                snapshot_id=result.get("snapshot_id", ""),
            )
        )
    if pages:
        content += '<div class="toolbar">' + " · ".join(pages) + "</div>"
    return content
