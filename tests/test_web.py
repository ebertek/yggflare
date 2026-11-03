"""Read-only web presentation and inventory integration tests."""

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import web


class WebTests(unittest.TestCase):
    def setUp(self):
        mock = patch.object(web, "snapshot", return_value=([], []))
        self.docker = mock.start()
        self.addCleanup(mock.stop)

    def test_docker_rows_replace_unmanaged_and_sort_all_surfaces(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "network-inventory").mkdir()
            addresses = [
                "10.4.21.100",
                "10.4.21.10",
                "10.4.21.99",
                "10.4.21.9",
                "10.4.21.224",
                "10.4.21.32",
            ]
            (root / "network-inventory/state.json").write_text(
                json.dumps({"hosts": {ip: {"ports": ["tcp/443"]} for ip in addresses}})
            )
            self.docker.return_value = (
                [
                    {
                        "hostname": "docker-" + ip,
                        "ipv4": ip,
                        "ipv6": "fd00::1",
                        "mac": "",
                        "aliases": ["alias"],
                        "ports": ["tcp/80"],
                        "status": "docker running",
                        "description": "Docker service",
                        "source": "Compose",
                    }
                    for ip in addresses
                ],
                [],
            )
            with patch.object(web, "CONFIG", root), patch.object(web, "DATA", root):
                data = web.model()
            expected = [
                "10.4.21.9",
                "10.4.21.10",
                "10.4.21.32",
                "10.4.21.99",
                "10.4.21.100",
                "10.4.21.224",
            ]
            self.assertEqual([h["ipv4"] for h in data["hosts"]], expected)
            self.assertTrue(all(h["status"] == "docker running" for h in data["hosts"]))
            self.assertTrue(
                all(h["observed_ports"] == ["tcp/443"] for h in data["hosts"])
            )
            html = web.render("inventory", data)
            self.assertLess(html.index("10.4.21.32/27"), html.index("10.4.21.224/27"))
            self.assertIn('data-sort="4:', html)
            self.assertIn('data-sort="6:', html)
            ports = web.render("ports", data)
            self.assertLess(
                ports.index("docker-10.4.21.9<"), ports.index("docker-10.4.21.10<")
            )

    def test_invalid_address_does_not_break_render(self):
        data = {
            "hosts": [
                {
                    "hostname": "host",
                    "ipv4": "",
                    "ipv6": "",
                    "mac": "",
                    "aliases": [],
                    "ports": [],
                    "subnet": "Unassigned",
                    "description": "",
                    "status": "docker declared",
                }
            ],
            "scanned_at": "",
        }
        self.assertIn("Unassigned", web.render("inventory", data))

    @unittest.skipUnless(shutil.which("node"), "Node required for browser-script test")
    def test_browser_numeric_sort_and_direction_toggle(self):
        script = (
            """
const assert = require('node:assert/strict');
let current = [];
const body = {querySelectorAll:()=>current, replaceChildren:(...rows)=>{current=rows;}};
let click;
const th = {dataset:{col:'0'},addEventListener:(event,fn)=>{click=fn;},closest:()=>table,removeAttribute:()=>{},setAttribute:()=>{}};
const table = {querySelector:()=>body,querySelectorAll:()=>[th]};
global.document = {querySelector:()=>null,querySelectorAll:(selector)=>selector==='th[data-col]'?[th]:[]};
"""
            + web.SCRIPT
            + """
function row(text,n){return {cells:[{textContent:text,dataset:{sort:'4:'+String(n).padStart(39,'0')+':032'}}]};}
current=[row('10.4.21.100',100),row('10.4.21.10',10),row('10.4.21.9',9),row('10.4.21.99',99)];
click();assert.deepEqual(current.map(r=>r.cells[0].textContent),['10.4.21.9','10.4.21.10','10.4.21.99','10.4.21.100']);
click();assert.deepEqual(current.map(r=>r.cells[0].textContent),['10.4.21.100','10.4.21.99','10.4.21.10','10.4.21.9']);
"""
        )
        subprocess.run([shutil.which("node"), "-e", script], check=True, timeout=10)

    def test_invalid_ip_sort_attribute_cannot_inject_html(self):
        html = web.table(["IP"], [['" onmouseover="alert(1)']])
        self.assertNotIn(' onmouseover="', html)
        self.assertIn("&quot;", html)

    def test_inventory_groups_and_escapes_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "config"
            state = root / "data"
            (state / "network-inventory").mkdir(parents=True)
            config.mkdir()
            inventory = {
                "version": 1,
                "hosts": [
                    {
                        "hostname": "test.ygg.nu",
                        "ipv4": "10.4.20.34",
                        "mac": "aa:bb:cc:dd:ee:ff",
                        "notes": "<script>alert(1)</script>",
                        "ports": [{"protocol": "tcp", "port": 443}],
                    }
                ],
            }
            (config / "static-hosts.json").write_text(json.dumps(inventory))
            observed = {
                "scanned_at": "2026-11-02T18:00:00Z",
                "hosts": {
                    "10.4.20.34": {"mac": "aa:bb:cc:dd:ee:ff", "ports": ["tcp/443"]}
                },
                "advertisements": ["example.local|_http._tcp|80"],
            }
            (state / "network-inventory/state.json").write_text(json.dumps(observed))
            (state / "managed-hosts.json").write_text(
                '{"version":1,"hosts":{"test.ebi.nu":{}}}'
            )
            with patch.object(web, "CONFIG", config), patch.object(web, "DATA", state):
                data = web.model()
            self.assertEqual(data["hosts"][0]["subnet"], "10.4.20.32/27")
            self.assertEqual(data["hosts"][0]["status"], "seen")
            html = web.render("inventory", data)
            self.assertIn("10.4.20.32/27", html)
            self.assertIn("&lt;script&gt;", html)
            self.assertNotIn("<script>alert(1)</script>", html)
            self.assertIn("test.ebi.nu", web.render("cloudflare", data))

    def test_unknown_observed_host_is_visible(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "config"
            state = root / "data"
            (state / "network-inventory").mkdir(parents=True)
            config.mkdir()
            (config / "static-hosts.json").write_text('{"version":1,"hosts":[]}')
            observed = {
                "hosts": {"10.4.21.207": {"mac": "7e:92:e2:7a:5f:77", "ports": []}},
            }
            (state / "network-inventory/state.json").write_text(json.dumps(observed))
            with patch.object(web, "CONFIG", config), patch.object(web, "DATA", state):
                data = web.model()
            self.assertEqual(data["hosts"][0]["status"], "unmanaged")
            self.assertIn("10.4.21.192/27", web.render("inventory", data))


    def test_discovery_groups_ipv4_ipv6_and_multiple_interfaces_by_mac(self):
        data = {
            "hosts": [],
            "discovery_devices": [
                {
                    "hostname": "printer.ygg.nu",
                    "ipv4": "10.4.20.34",
                    "mac": "aa:bb:cc:dd:ee:ff",
                }
            ],
            "network_state": {
                "supplemental": {
                    "observed_at": "2026-11-03T19:00:00Z",
                    "records": [
                        {
                            "ip": "10.4.20.34",
                            "interface": "enp86s0",
                            "source": "ARP reply",
                            "detail": "aa:bb:cc:dd:ee:ff",
                        },
                        {
                            "ip": "10.4.20.34",
                            "interface": "macvlan1-host",
                            "source": "Neighbor cache",
                            "detail": "aa:bb:cc:dd:ee:ff (STALE)",
                        },
                        {
                            "ip": "fd0e:be00:da00:20::34",
                            "interface": "enp86s0",
                            "source": "NDP reply",
                            "detail": "aa:bb:cc:dd:ee:ff",
                        },
                        {
                            "ip": "fd0e:be00:da00:20::34",
                            "interface": "enp86s0",
                            "source": "Nmap IPv6",
                            "detail": "tcp/443 https",
                        },
                    ],
                }
            },
        }
        html = web.render("discovery", data)
        self.assertEqual(html.count('data-group="1"'), 1)
        self.assertIn("printer.ygg.nu · 4 evidence records", html)
        self.assertIn("fd0e:be00:da00:20::34", html)
        self.assertIn("macvlan1-host", html)
        self.assertIn("tcp/443 https", html)

    def test_discovery_keeps_competing_macs_and_uncorrelated_ipv6_separate(self):
        data = {
            "hosts": [],
            "discovery_devices": [
                {
                    "hostname": "router.ygg.nu",
                    "ipv4": "10.4.20.1",
                    "mac": "aa:aa:aa:aa:aa:aa",
                }
            ],
            "network_state": {
                "supplemental": {
                    "records": [
                        {
                            "ip": "10.4.20.1",
                            "interface": "enp86s0",
                            "source": "Neighbor cache",
                            "detail": "aa:aa:aa:aa:aa:aa (STALE)",
                        },
                        {
                            "ip": "10.4.20.1",
                            "interface": "macvlan1-host",
                            "source": "ARP reply",
                            "detail": "bb:bb:bb:bb:bb:bb",
                        },
                        {
                            "ip": "fd0e:be00:da00:20::8888",
                            "interface": "enp86s0",
                            "source": "Nmap IPv6",
                            "detail": "tcp/80 http",
                        },
                    ]
                }
            },
        }
        html = web.render("discovery", data)
        self.assertEqual(html.count('data-group="1"'), 2)
        self.assertIn("Conflicting identity: 10.4.20.1", html)
        self.assertIn("aa:aa:aa:aa:aa:aa", html)
        self.assertIn("bb:bb:bb:bb:bb:bb", html)
        self.assertIn("Unassigned address: fd0e:be00:da00:20::8888", html)

    def test_discovery_preserves_link_only_evidence_and_escapes_it(self):
        data = {
            "discovery_devices": [],
            "network_state": {
                "supplemental": {
                    "records": [
                        {
                            "ip": "",
                            "interface": "enp86s0",
                            "source": "LLDP",
                            "detail": "<script>neighbor</script>",
                        }
                    ]
                }
            },
        }
        html = web.render("discovery", data)
        self.assertIn("Link neighbour: enp86s0", html)
        self.assertIn("&lt;script&gt;neighbor&lt;/script&gt;", html)
        self.assertNotIn("<script>neighbor</script>", html)



if __name__ == "__main__":
    unittest.main()
