"""SSDP scope and projection without fetching untrusted URLs."""

import ipaddress
import unittest
from unittest.mock import MagicMock, patch

from discovery_ssdp import ssdp


class SSDPTests(unittest.TestCase):
    def test_scope_allowlist_and_no_location(self):
        sock = MagicMock()
        payload = b"HTTP/1.1 200 OK\r\nST: media\r\nSERVER: device\r\nLOCATION: http://private/secret\r\n\r\n"
        sock.recvfrom.side_effect = [
            (payload, ("8.8.8.8", 1900)),
            (payload, ("10.0.0.2", 1900)),
        ]
        with (
            patch("discovery_ssdp.socket.socket") as factory,
            patch("discovery_ssdp.time.monotonic", side_effect=[0, 0, 0, 4]),
        ):
            factory.return_value.__enter__.return_value = sock
            result = ssdp("eth0", lambda a: a in ipaddress.ip_network("10.0.0.0/24"))
        self.assertEqual(result, [("10.0.0.2", "st: media; server: device")])
        self.assertEqual(sock.sendto.call_count, 1)
