"""Passive projections retain identity only."""

import ipaddress
import unittest

from discovery_passive import lldp_records, p0f_records


class PassiveTests(unittest.TestCase):
    def test_lldp_interface_and_fields(self):
        xml = '<lldp><interface name="eth0" via="CDPv2"><chassis><name>switch</name><descr>model</descr><secret>do-not-export</secret></chassis><port><id>1</id></port></interface></lldp>'
        self.assertEqual(lldp_records(xml, ["other"]), [])
        result = lldp_records(xml, ["eth0"])
        self.assertEqual(result[0][2], "CDPv2")
        self.assertIn("port: 1", result[0][3])
        self.assertNotIn("do-not-export", str(result))

    def test_p0f_scope_and_subject(self):
        scope = ipaddress.ip_network("10.0.0.0/24")
        raw = "[time]|mod=syn|cli=10.0.0.2/123|srv=8.8.8.8/80|subj=cli|os=Linux|raw_sig=private\n[time]|cli=10.0.0.2/123|srv=8.8.8.8/80|subj=srv|os=Other"
        self.assertEqual(
            p0f_records(raw, lambda a: a in scope), [("10.0.0.2", "Linux")]
        )
