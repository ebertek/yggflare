"""Offline saved collector evidence resilience checks."""

import json
import os
import tempfile
import unittest
from pathlib import Path

import integration_inventory as integration
import traefik_inventory as traefik


class SavedSnapshotTests(unittest.TestCase):
    def test_strict_bounded_reader(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "view.json"
            for payload in (
                b'{"version":true}',
                b'{"version":1,"version":1}',
                b'{"version":1,"value":NaN}',
                b'{"version":1,"value":1e999}',
                b'{"version":1,"value":"\xff"}',
                b'{"version":1,"value":' + b"[" * 2000 + b"]" * 2000 + b"}",
                b"x" * (traefik.MAX_BYTES + 1),
            ):
                with self.subTest(payload=payload[:64]):
                    path.write_bytes(payload)
                    self.assertFalse(traefik.read(path))
            deep = (
                "[" * traefik.MAX_SNAPSHOT_DEPTH + "]" * traefik.MAX_SNAPSHOT_DEPTH
            )
            path.write_text('{"version":1,"items":[null,' + deep + "]}")
            self.assertFalse(traefik.read(path))
            path.write_text('{"version":1,"items":[]}')
            self.assertEqual(traefik.read(path), {"version": 1, "items": []})
            link = root / "link"
            link.symlink_to(path)
            self.assertEqual(traefik.read(link), {})
            fifo = root / "fifo"
            os.mkfifo(fifo)
            self.assertEqual(traefik.read(fifo), {})
            self.assertEqual(traefik.read(root), {})

    def test_traefik_missing_duplicate_and_truncated_rows(self):
        env = {
            "YGGFLARE_LAN_CIDR": "192.0.2.0/24",
            "YGGFLARE_TRAEFIK_API_URL": "http://192.0.2.10:8080",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = traefik.settings(env)
            row = {
                "protocol": "http",
                "kind": "routers",
                "name": "example@docker",
                "status": "enabled",
            }
            stamp = traefik.timestamp()
            view = {
                "version": 1,
                "source_id": traefik.source_id(config),
                "observed_at": stamp,
                "items": [row],
            }
            path = root / "traefik-view.json"
            traefik.write(path, view)
            original = json.loads(path.read_text())
            self.assertEqual(original["item_count"], 1)
            traefik.write(
                root / "traefik-view-status.json",
                {
                    "version": 1,
                    "source_id": view["source_id"],
                    "attempted_at": stamp,
                    "observed_at": stamp,
                    "ok": True,
                },
            )
            self.assertTrue(traefik.saved(root, env)["fresh"])
            missing = {key: value for key, value in view.items() if key != "items"}
            for invalid in (
                missing,
                {**original, "items": []},
                {**view, "items": [row, row]},
                {**view, "items": [{}]},
                {**view, "items": [{**row, "status": []}]},
                {**view, "item_count": True},
            ):
                with self.subTest(invalid=invalid):
                    path.write_text(json.dumps(invalid))
                    result = traefik.saved(root, env)
                    self.assertFalse(result["available"])
                    self.assertFalse(result["fresh"])
                    self.assertFalse(result["last_refresh_verified"])
                    self.assertEqual(result["items"], [])
            # Legacy snapshots and genuine empty inventories remain supported.
            for valid in (view, {**view, "items": []}):
                path.write_text(json.dumps(valid))
                self.assertTrue(traefik.saved(root, env)["fresh"])

    def test_integration_row_validation(self):
        monitor = {"kind": "monitors", "name": "demo", "status": "up"}
        self.assertTrue(integration.valid_rows("kuma", [monitor]))
        for row in (
            {},
            {**monitor, "target_port": True},
            {**monitor, "target_host": {}},
            {**monitor, "status": []},
            {**monitor, "kind": "stacks"},
        ):
            self.assertFalse(integration.valid_rows("kuma", [row]))
        stack = {"kind": "stacks", "name": "demo", "state": "running"}
        self.assertTrue(integration.valid_rows("komodo", [stack]))
        self.assertFalse(integration.valid_rows("komodo", [{**stack, "state": []}]))
        self.assertFalse(
            integration.valid_rows(
                "komodo", [{"kind": "stack_services", "name": "worker"}]
            )
        )
