"""MCP HTTP logging is consistent, bounded and separate from stdio."""

import io
import json
import logging
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import controller
from mcp_logging import http_logging
from mcp_server import guarded


class MCPLoggingTests(unittest.TestCase):
    def test_sdk_lifecycle_uses_controller_text_and_json_formats(self):
        for mode in ("text", "json"):
            with (
                self.subTest(mode=mode),
                patch.object(controller, "LOG_FORMAT", mode),
                redirect_stdout(io.StringIO()) as output,
                http_logging(controller.log),
            ):
                logging.getLogger("mcp.server.streamable_http_manager").info(
                    "StreamableHTTP session manager started"
                )
            lines = output.getvalue().splitlines()
            self.assertEqual(len(lines), 1)
            if mode == "json":
                event = json.loads(lines[0])
                self.assertEqual(event["level"], "info")
                self.assertEqual(event["component"], "mcp")
                self.assertTrue(event["timestamp"].endswith("Z"))
                self.assertEqual(
                    event["message"], "StreamableHTTP session manager started"
                )
            else:
                self.assertRegex(
                    lines[0],
                    r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ INFO  \[mcp\] "
                    r"StreamableHTTP session manager started$",
                )

    def test_existing_handlers_do_not_duplicate_or_expose_private_data(self):
        logger = logging.getLogger("mcp.test.logging")
        root = logging.getLogger()
        previous = (logger.handlers[:], logger.propagate, logger.level)
        root_handlers = root.handlers[:]
        raw = io.StringIO()
        handler = logging.StreamHandler(raw)
        logger.handlers = [handler]
        logger.propagate = False
        logger.setLevel(logging.DEBUG)
        try:
            with (
                patch.object(controller, "LOG_FORMAT", "json"),
                redirect_stdout(io.StringIO()) as output,
                http_logging(controller.log),
            ):
                logger.info("request %s", "private-token")
                logger.warning("request %s", "private-token")
                try:
                    raise ValueError("private-exception")
                except ValueError:
                    logging.getLogger("uvicorn.error").exception("private-request")
                logging.getLogger("uvicorn.access").warning("private-url")
            self.assertEqual(raw.getvalue(), "")
            self.assertNotIn("private-", output.getvalue())
            events = [json.loads(line) for line in output.getvalue().splitlines()]
            self.assertEqual(
                [(event["level"], event["message"]) for event in events],
                [
                    ("warning", "MCP SDK diagnostic (details omitted)"),
                    ("error", "Uvicorn diagnostic (details omitted)"),
                ],
            )
            self.assertEqual(logger.handlers, [handler])
            self.assertFalse(logger.propagate)
            self.assertEqual(logger.level, logging.DEBUG)
            self.assertEqual(root.handlers, root_handlers)
        finally:
            logger.handlers, logger.propagate, level = previous
            logger.setLevel(level)
            handler.close()

    def test_http_audit_uses_sink_but_stdio_stays_on_stderr(self):
        slots = threading.BoundedSemaphore(1)
        with (
            patch.object(controller, "LOG_FORMAT", "json"),
            redirect_stdout(io.StringIO()) as output,
            redirect_stderr(io.StringIO()) as stderr,
        ):
            guarded(
                lambda: {}, "get_unifi_status", slots, True, audit_log=controller.log
            )()
            guarded(lambda: {}, "get_unifi_status", slots, True)()
        event = json.loads(output.getvalue())
        self.assertEqual(event["component"], "mcp")
        self.assertEqual(event["tool"], "get_unifi_status")
        self.assertEqual(event["outcome"], "succeeded")
        self.assertIsInstance(event["duration_ms"], int)
        self.assertIn("[mcp] get_unifi_status succeeded", stderr.getvalue())
