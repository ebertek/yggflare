"""Service evidence, drift history and read-only lifecycle presentation."""

import unittest
from datetime import UTC, datetime, timedelta

import web
from web_views import advertisements, service_rows


class DetailViewsTests(unittest.TestCase):
    def test_ports_join_by_exact_address_and_protocol(self):
        hosts = [
            {
                "hostname": "device.example",
                "ipv4": "10.4.20.9",
                "ports": ["tcp/80"],
                "observed_ports": ["tcp/80"],
                "port_sources": {},
            }
        ]
        state = {
            "hosts": {
                "10.4.20.9": {
                    "services": {"tcp/80": {"name": "http", "method": "table"}}
                }
            },
            "advertisement_details": [
                {
                    "host": "device.local",
                    "service": "_http._tcp",
                    "name": "Web",
                    "port": 80,
                    "addresses": ["10.4.20.9"],
                },
                {
                    "host": "other.local",
                    "service": "_http._tcp",
                    "name": "Other",
                    "port": 80,
                    "addresses": ["10.4.20.10"],
                },
                {
                    "host": "device.local",
                    "service": "_quic._udp",
                    "name": "QUIC",
                    "port": 80,
                    "addresses": ["10.4.20.9"],
                },
            ],
        }
        rows = service_rows(hosts, state)
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0][4], "open (scan)")
        self.assertIn("port-name hint", rows[0][5])
        self.assertIn("Web", rows[0][6])
        self.assertNotIn("Other", rows[0][6])
        self.assertEqual(rows[1][3:5], ["udp", "advertised only"])
        self.assertEqual(rows[2][1], "10.4.20.10")

    def test_probed_service_and_legacy_dns_sd(self):
        state = {"advertisements": ["host.local|_ssh._tcp|22"]}
        self.assertEqual(advertisements(state)[0]["addresses"], [])
        rows = service_rows([], state)
        self.assertEqual(rows[0][4], "advertised only")
        host = {"hostname": "host", "ipv4": "10.4.20.2", "observed_ports": ["tcp/22"]}
        state = {
            "hosts": {
                "10.4.20.2": {
                    "services": {
                        "tcp/22": {
                            "name": "ssh",
                            "product": "OpenSSH",
                            "method": "probed",
                        }
                    }
                }
            }
        }
        self.assertEqual(service_rows([host], state)[0][5], "ssh OpenSSH (probed)")

    def test_drift_categories_baseline_and_escaping(self):
        state = {
            "reported": {"a": "CHANGED MAC <script>"},
            "recent_events": [
                {
                    "observed_at": "now",
                    "message": "NEW DNS-SD host.local|_http._tcp|80",
                    "baseline": True,
                },
                {
                    "observed_at": "later",
                    "message": "NEW PORT host: tcp/443",
                    "baseline": False,
                },
            ],
        }
        html = web.render("drift", {"network_state": state})
        self.assertIn("Changed MAC", html)
        self.assertIn("New DNS-SD service", html)
        self.assertIn("Initial baseline (not notified)", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("MAC <script>", html)
        self.assertLess(html.index(">later</span>"), html.index(">now</span>"))

    def test_old_state_has_active_drift_without_fabricated_history(self):
        html = web.render(
            "drift", {"network_state": {"reported": {"x": "NEW DEVICE 10.4.20.9"}}}
        )
        self.assertIn("New device", html)
        self.assertIn("History begins", html)

    def test_cloudflare_missing_snapshot_never_guesses_lifecycle(self):
        html = web.render("cloudflare", {"managed_hosts": ["claimed.example"]})
        self.assertIn("classification unavailable", html)
        self.assertIn("claimed.example", html)

    def test_cloudflare_stale_failed_scope_and_resource_projection(self):
        stamp = (datetime.now(UTC) - timedelta(hours=9)).isoformat()
        data = {
            "cloudflare_view": {
                "audited_at": stamp,
                "scope": {"account": "one"},
                "hosts": [
                    {
                        "hostname": "old.example",
                        "lifecycle": "orphaned",
                        "claimed_app_id": "app-id",
                        "claimed_dns_id": "dns-id",
                        "claimed_tunnel_route": "old.example",
                        "access_app_ids": ["app-id"],
                        "dns_record_ids": ["dns-id"],
                        "tunnel_routes": 1,
                    }
                ],
            },
            "cloudflare_view_status": {"ok": False},
            "orphan_observations": {
                "scope": {"account": "two"},
                "missing": {"old.example": {"first": "wrong-scope-timer"}},
            },
        }
        html = web.render("cloudflare", data)
        self.assertIn("Snapshot is stale", html)
        self.assertIn("Latest refresh failed", html)
        self.assertIn("Access: app-id", html)
        self.assertNotIn("wrong-scope-timer", html)
        data["orphan_observations"]["scope"] = {"account": "one"}
        self.assertIn("wrong-scope-timer", web.render("cloudflare", data))
