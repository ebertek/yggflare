"""Inventory flags/diff, durable last-seen and HTTP privacy regressions."""

import json
import shutil
import subprocess
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import patch
from urllib.request import urlopen

import web
from inventory_view import decorate, private_projection


def fixture():
    host = {
        "hostname": "private-device.example",
        "ipv4": "10.4.20.9",
        "mac": "aa:bb:cc:dd:ee:ff",
        "ipv6": "fd00::9",
        "aliases": ["private-alias.example"],
        "description": "private-location",
        "subnet": "10.4.20.0/27",
        "ports": ["tcp/80"],
        "observed_ports": ["tcp/80"],
        "status": "seen",
        "device_class": "server",
        "last_seen": "2026-11-02T00:00:00Z",
        "flags": [],
        "source": "Static inventory",
    }
    return {
        "hosts": [host],
        "scanned_at": "2026-11-02T00:00:00Z",
        "network_state": {
            "hosts": {host["ipv4"]: {"mac": host["mac"], "ports": ["tcp/80"]}},
            "reported": {"x": "CHANGED MAC private-device.example aa:bb:cc:dd:ee:ff"},
            "recent_events": [
                {
                    "observed_at": "2026-11-02T00:00:00Z",
                    "message": "NEW DEVICE 10.4.20.9 MAC aa:bb:cc:dd:ee:ff",
                }
            ],
            "advertisement_details": [
                {
                    "host": "private-device.example",
                    "service": "_http._tcp",
                    "name": "private-location",
                    "port": 80,
                    "addresses": ["10.4.20.9"],
                }
            ],
        },
        "cloudflare_view": {
            "audited_at": "2026-11-02T00:00:00Z",
            "scope": {"account": "private-account"},
            "hosts": [
                {
                    "hostname": "private-device.example",
                    "lifecycle": "managed",
                    "declared": True,
                    "claimed_app_id": "private-resource",
                    "access_app_ids": ["private-resource"],
                    "dns_record_ids": [],
                    "tunnel_routes": 1,
                }
            ],
        },
        "managed_hosts": ["private-device.example"],
        "diffs": [
            {
                "hostname": host["hostname"],
                "ipv4": host["ipv4"],
                "field": "MAC",
                "expected": host["mac"],
                "observed": "private-new-mac",
                "severity": "drift",
            }
        ],
        "api_token": "CREDENTIAL-NEVER-SERVED",
    }


class InventoryViewTests(unittest.TestCase):
    def test_missing_new_retired_and_drift_are_evidence_based(self):
        hosts = fixture()["hosts"]
        hosts.append(
            {
                **hosts[0],
                "hostname": "",
                "ipv4": "10.4.20.10",
                "mac": "",
                "source": "",
                "status": "unmanaged",
            }
        )
        inventory = {
            "hosts": [
                {
                    "hostname": hosts[0]["hostname"],
                    "ipv4": hosts[0]["ipv4"],
                    "mac": hosts[0]["mac"],
                    "retired": True,
                    "device_class": "server",
                }
            ]
        }
        state = {
            "scanned_at": "now",
            "last_seen": {"10.4.20.9": "yesterday"},
            "hosts": {"10.4.20.9": {"mac": "11:22:33:44:55:66", "ports": ["tcp/443"]}},
            "latest_events": ["NEW DEVICE 10.4.20.10 MAC unknown"],
        }
        diffs = decorate(hosts, inventory, state)
        self.assertEqual(hosts[0]["last_seen"], "yesterday")
        self.assertEqual(set(hosts[0]["flags"]), {"retired", "drift"})
        self.assertEqual(hosts[0]["device_class"], "server")
        self.assertEqual(set(hosts[1]["flags"]), {"missing", "new"})
        self.assertTrue(any(d["field"] == "MAC" for d in diffs))
        self.assertTrue(any("not proof of closure" in d["observed"] for d in diffs))

    def test_offline_is_not_retired_and_alternate_mac_is_not_drift(self):
        hosts = fixture()["hosts"]
        item = {
            "hostname": hosts[0]["hostname"],
            "ipv4": hosts[0]["ipv4"],
            "mac": "00:00:00:00:00:01",
            "observed_macs": ["aa:bb:cc:dd:ee:ff"],
        }
        data = fixture()
        self.assertEqual(decorate(hosts, {"hosts": [item]}, data["network_state"]), [])
        diffs = decorate(hosts, {"hosts": [item]}, {"hosts": {}})
        self.assertNotIn("retired", hosts[0]["flags"])
        self.assertEqual(diffs[0]["severity"], "unknown")

    @unittest.skipUnless(shutil.which("node"), "Node needed for UI controls")
    def test_filter_expands_matches_and_restores_collapsed_groups(self):
        script = (
            """
const assert=require('node:assert/strict');
const makeControl=()=>({value:'',listeners:{},addEventListener(event,fn){this.listeners[event]=fn;}});
const controls=Object.fromEntries(['filter','status-filter','class-filter','expand-all','collapse-all'].map(k=>['#'+k,makeControl()]));
const r1={dataset:{search:'printer 10.4.20.9 aa:bb',flags:'drift',kind:'printer'},hidden:false};
const r2={dataset:{search:'server 10.4.21.9 cc:dd',flags:'missing',kind:'server'},hidden:false};
const groups=[r1,r2].map(row=>({dataset:{},open:false,hidden:false,querySelector:()=>row.hidden?null:row}));
global.document={querySelector:s=>controls[s]||null,querySelectorAll:s=>s==='tr[data-search]'?[r1,r2]:s==='details[data-group]'?groups:[]};
"""
            + web.SCRIPT
            + """
controls['#filter'].value='aa:bb';controls['#filter'].listeners.input();
assert.equal(r1.hidden,false);assert.equal(r2.hidden,true);assert.equal(groups[0].open,true);assert.equal(groups[1].hidden,true);
controls['#filter'].value='';controls['#filter'].listeners.input();assert.equal(groups[0].open,false);
controls['#class-filter'].value='server';controls['#class-filter'].listeners.input();assert.equal(r1.hidden,true);assert.equal(r2.hidden,false);
controls['#status-filter'].value='drift';controls['#status-filter'].listeners.input();assert.equal(r2.hidden,true);
controls['#class-filter'].value='';controls['#status-filter'].value='';controls['#filter'].listeners.input();
controls['#expand-all'].listeners.click();assert(groups.every(g=>g.open));
controls['#collapse-all'].listeners.click();assert(groups.every(g=>!g.open));
"""
        )
        subprocess.run([shutil.which("node"), "-e", script], check=True, timeout=10)

    def test_private_projection_does_not_mutate_cached_model(self):
        data = fixture()
        before = json.dumps(data)
        hidden = private_projection(data)
        self.assertNotIn("private-", json.dumps(hidden))
        self.assertNotIn("10.4.20.", json.dumps(hidden))
        self.assertNotIn("aa:bb:", json.dumps(hidden))
        self.assertEqual(before, json.dumps(data))
        self.assertEqual(hidden["hosts"][0]["hostname"], "Device 001")

    def test_http_all_views_and_exports_obey_server_side_flag(self):
        data = fixture()
        server = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            for value in ("false", "true", "TRUE", ""):
                with (
                    self.subTest(flag=value),
                    patch.object(web, "model", return_value=data),
                    patch.dict("os.environ", {"YGGFLARE_WEB_SHOW_SECRETS": value}),
                ):
                    for path in (
                        "/inventory",
                        "/ports",
                        "/diff",
                        "/drift",
                        "/cloudflare",
                        "/api/inventory.json",
                        "/api/inventory.csv",
                    ):
                        with urlopen(
                            f"http://127.0.0.1:{server.server_port}{path}", timeout=5
                        ) as response:
                            body = response.read().decode()
                        self.assertNotIn("CREDENTIAL-NEVER-SERVED", body)
                        if value != "true":
                            for secret in (
                                "private-",
                                "10.4.20.",
                                "aa:bb:cc:",
                                "fd00::9",
                            ):
                                self.assertNotIn(secret, body, path)
                        else:
                            self.assertIn("private-device.example", body, path)
        finally:
            server.shutdown()
            server.server_close()
            worker.join()

    def test_inventory_has_collapsible_groups_badges_last_seen_and_mobile_labels(self):
        html = web.render("inventory", fixture())
        self.assertIn('<details class="card"', html)
        self.assertIn('id="collapse-all"', html)
        self.assertIn('id="status-filter"', html)
        self.assertIn('id="class-filter"', html)
        self.assertIn('data-label="Last seen"', html)
        self.assertIn('data-kind="server"', html)
