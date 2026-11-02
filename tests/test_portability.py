"""Prove that non-Ygg deployments can use entirely different CIDRs and DNS zones."""

import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PortableConfigurationTests(unittest.TestCase):
    def test_custom_domains_and_networks(self):
        env = {
            **os.environ,
            "PYTHONPATH": str(ROOT / "src" / "cloudflare"),
            "YGGFLARE_LAN_CIDR": "192.168.10.0/23",
            "YGGFLARE_DEVICES_CIDR": "192.168.10.0/24",
            "YGGFLARE_DOCKER_CIDR": "192.168.11.0/24",
            "YGGFLARE_INTERNAL_DOMAIN": "home.example.net",
            "YGGFLARE_EXTERNAL_DOMAIN": "edge.example.com",
        }
        code = """
from cloudflare_desired import HOST as external_host
from cloudflare_static_dns import HOST as internal_host, STATIC_NETWORK
from cloudflare_live_diff import DOCKER_NETWORK
from yggflare_config import domain
assert external_host.fullmatch('plex.edge.example.com')
assert not external_host.fullmatch('plex.ebi.nu')
assert internal_host.fullmatch('printer.home.example.net')
assert not internal_host.fullmatch('printer.ygg.nu')
assert '192.168.10.45' in [str(ip) for ip in STATIC_NETWORK.hosts()]
assert '192.168.11.45' in [str(ip) for ip in DOCKER_NETWORK.hosts()]
assert domain('YGGFLARE_INTERNAL_DOMAIN') == 'home.example.net'
"""
        subprocess.run([sys.executable, "-c", code], env=env, check=True, timeout=20)

    def test_missing_domain_fails_closed(self):
        env = {
            **os.environ,
            "PYTHONPATH": str(ROOT / "src" / "cloudflare"),
            "YGGFLARE_EXTERNAL_DOMAIN": "",
        }
        code = "from cloudflare_desired import HOST"
        completed = subprocess.run(
            [sys.executable, "-c", code],
            env=env,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("YGGFLARE_EXTERNAL_DOMAIN", completed.stderr)


if __name__ == "__main__":
    unittest.main()
