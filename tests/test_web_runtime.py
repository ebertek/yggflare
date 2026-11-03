"""Exercise real model construction through HTTP, not a mocked web model."""

import contextlib
import io
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import urlopen

import docker_inventory
import web


class RuntimeWebTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in ("CONFIG", "DATA", "SOURCE"):
            mock = patch.object(web, name, self.root)
            mock.start()
            self.addCleanup(mock.stop)
        docker_inventory._CACHE.clear()
        self.addCleanup(docker_inventory._CACHE.clear)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.addCleanup(self.close_server)

    def close_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join()

    def fetch(self, path):
        return urlopen(f"http://127.0.0.1:{self.server.server_port}{path}", timeout=5)

    def test_all_pages_with_two_containers_absent_from_compose(self):
        containers = [{"Name": "/runtime-a"}, {"Name": "/runtime-b"}]
        with patch.object(
            docker_inventory, "inspect_containers", return_value=containers
        ):
            for path in (
                "/inventory",
                "/ports",
                "/drift",
                "/cloudflare",
                "/api/inventory.json",
                "/api/inventory.csv",
            ):
                with self.subTest(path=path), self.fetch(path) as response:
                    self.assertEqual(response.status, 200)

    def test_503_logs_code_location_without_private_exception_text(self):
        (self.root / "static-hosts.json").write_text('"PRIVATE-DO-NOT-LOG" invalid')
        output = io.StringIO()
        with contextlib.redirect_stderr(output), self.assertRaises(HTTPError) as caught:
            self.fetch("/inventory")
        self.assertEqual(caught.exception.code, 503)
        log = output.getvalue()
        self.assertIn("JSONDecodeError", log)
        self.assertIn("web.py:", log)
        self.assertNotIn("PRIVATE-DO-NOT-LOG", log)
        self.assertNotIn(str(self.root), log)
