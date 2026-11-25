"""Offline security, pagination and last-good snapshot tests."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import traefik_inventory as traefik

ENV = {
    "YGGFLARE_LAN_CIDR": "192.168.0.0/24",
    "YGGFLARE_TRAEFIK_API_URL": "http://192.168.0.10:8080",
}


def fixture(config, protocol, kind, page):
    if protocol == "http" and kind == "routers":
        return [
            {
                "name": f"demo-{page}@docker",
                "status": "enabled",
                "provider": "docker",
                "rule": "Host(`demo.invalid`) && Header(`Authorization`, `SECRET`)",
                "middlewares": ["auth@docker"],
                "tls": {"options": "SECRET"},
                "error": ["SECRET"],
                "service": "demo@docker",
            }
        ], page == 1
    if protocol == "http" and kind == "services":
        return [
            {
                "name": "demo@docker",
                "loadBalancer": {
                    "servers": [
                        {"url": "http://backend.invalid:8080/SECRET?token=SECRET"},
                        {"url": "http://user:SECRET@backend.invalid"},
                    ]
                },
                "serverStatus": {"http://backend.invalid/SECRET": "UP"},
            }
        ], False
    if protocol == "http" and kind == "middlewares":
        return [
            {
                "name": "auth@docker",
                "type": "basicAuth",
                "basicAuth": {"users": ["SECRET"]},
            }
        ], False
    return [], False


class TraefikTests(unittest.TestCase):
    def test_scope_and_config_validation(self):
        self.assertIsNone(traefik.settings({}))
        self.assertEqual(traefik.settings(ENV), ("http", "192.168.0.10", 8080))
        for url in (
            "http://example.invalid",
            "http://8.8.8.8",
            "http://192.168.0.10:0",
            "http://user:password@192.168.0.10",
            "http://192.168.0.10/api",
            "http://192.168.0.10/?q=x",
            "file:///etc/passwd",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                traefik.settings({**ENV, "YGGFLARE_TRAEFIK_API_URL": url})

    def test_pagination_and_projection(self):
        view = traefik.collect(traefik.settings(ENV), fixture)
        self.assertEqual(len(view["items"]), 4)
        self.assertNotIn("SECRET", json.dumps(view))
        routers = [row for row in view["items"] if row["kind"] == "routers"]
        self.assertEqual(len(routers), 2)
        self.assertEqual(routers[0]["literal_hosts"], ["demo.invalid"])
        self.assertFalse(routers[0]["simple_host_rule"])
        service = next(row for row in view["items"] if row["kind"] == "services")
        self.assertEqual(service["backend_origins"], ["http://backend.invalid:8080"])
        self.assertEqual(service["backend_up_count"], 1)

    def test_fixed_http_get_and_redirect_rejected(self):
        config = traefik.settings(ENV)
        with patch.object(traefik.http.client, "HTTPConnection") as connection:
            response = connection.return_value.getresponse.return_value
            response.status = 302
            with self.assertRaises(ValueError):
                traefik.get_page(config, "http", "routers", 1)
            connection.return_value.request.assert_called_once_with(
                "GET",
                "/api/http/routers?page=1&per_page=100",
                headers={"Accept": "application/json"},
            )
            connection.return_value.close.assert_called_once()
        with self.assertRaises(ValueError):
            traefik.get_page(config, "http", "rawdata", 1)

    def test_real_traefik_terminal_header(self):
        config = traefik.settings(ENV)
        for page, count, header, more in (
            (1, 0, "1", False),
            (1, 3, "1", False),
            (1, 100, "1", False),
            (2, 100, "1", False),
            (1, 100, "2", True),
            (2, 100, "3", True),
            (2, 3, "", False),
            (1, 100, "", True),
        ):
            with self.subTest(page=page, count=count, header=header):
                with patch.object(traefik.http.client, "HTTPConnection") as connection:
                    response = connection.return_value.getresponse.return_value
                    response.status = 200
                    response.read.return_value = json.dumps(
                        [{"name": f"router-{i}@docker"} for i in range(count)]
                    ).encode()
                    response.getheader.return_value = header
                    rows, continuation = traefik.get_page(
                        config, "http", "routers", page
                    )
                    self.assertEqual(len(rows), count)
                    self.assertEqual(continuation, more)
                    connection.return_value.close.assert_called_once()

    def test_pagination_rejects_invalid_continuations(self):
        config = traefik.settings(ENV)
        for page, count, header in (
            (1, 0, "2"),
            (1, 99, "2"),
            (1, 100, "3"),
            (3, 100, "2"),
            (1, 100, "https://example.invalid"),
        ):
            with self.subTest(page=page, count=count, header=header):
                with patch.object(traefik.http.client, "HTTPConnection") as connection:
                    response = connection.return_value.getresponse.return_value
                    response.status = 200
                    response.read.return_value = json.dumps([{}] * count).encode()
                    response.getheader.return_value = header
                    with self.assertRaises(ValueError):
                        traefik.get_page(config, "http", "routers", page)

    def test_all_endpoints_with_terminal_headers_and_full_last_page(self):
        config = traefik.settings(ENV)
        calls = []

        def request(method, path, **kwargs):
            self.assertEqual(method, "GET")
            calls.append(path)

        def respond():
            path = calls[-1]
            first = path.startswith("/api/http/routers?")
            page_one = "page=1&" in path
            count = 100 if first else 0
            base = 0 if page_one else 100
            response = connection.return_value.getresponse.return_value
            response.status = 200
            response.read.return_value = json.dumps(
                [{"name": f"router-{base+i}@docker"} for i in range(count)]
            ).encode()
            response.getheader.return_value = "2" if first and page_one else "1"
            return response

        with patch.object(traefik.http.client, "HTTPConnection") as connection:
            connection.return_value.request.side_effect = request
            connection.return_value.getresponse.side_effect = respond
            # Explicit fetch uses the real parser, not a pre-decoded fixture.
            result = traefik.collect(config, traefik.get_page)
        self.assertEqual(len(result["items"]), 200)
        self.assertEqual(len(calls), len(traefik.SECTIONS) + 1)
        self.assertEqual(sum("page=2&" in path for path in calls), 1)

    def test_failure_diagnostics_do_not_expose_raw_exception(self):
        def fail(*args):
            raise ValueError("PRIVATE RESPONSE")

        with contextlib.redirect_stderr(io.StringIO()) as output:
            with self.assertRaises(ValueError):
                traefik.collect(traefik.settings(ENV), fail)
        self.assertIn("http/routers page 1: invalid_response", output.getvalue())
        self.assertNotIn("PRIVATE RESPONSE", output.getvalue())

    def test_failed_refresh_preserves_last_good_and_detects_changed_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = traefik.settings(ENV)
            traefik.refresh(root, config, fixture)
            first = traefik.saved(root, ENV)
            self.assertTrue(first["fresh"])

            def fail(*args):
                raise ValueError("SECRET")

            with self.assertRaises(ValueError):
                traefik.refresh(root, config, fail)
            after = traefik.saved(root, ENV)
            self.assertEqual(after["items"], first["items"])
            self.assertFalse(after["last_refresh_verified"])
            self.assertFalse(after["fresh"])
            self.assertEqual(
                traefik.saved(
                    root,
                    {**ENV, "YGGFLARE_TRAEFIK_API_URL": "http://192.168.0.11:8080"},
                )["items"],
                [],
            )
            self.assertEqual((root / "traefik-view.json").stat().st_mode & 0o777, 0o600)
            self.assertNotIn("SECRET", (root / "traefik-view-status.json").read_text())
