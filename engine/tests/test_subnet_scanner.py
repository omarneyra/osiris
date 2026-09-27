"""
Unit tests for Infrastructure & Subnet Scanner Engine (Python).
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from subnet_scanner import parse_cidr, generate_ip_range, assess_subnet_exposure


class TestSubnetScanner(unittest.TestCase):
    def test_parse_cidr_valid(self):
        res = parse_cidr("192.168.1.0/24")
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["network_address"], "192.168.1.0")
        self.assertEqual(res["netmask"], "255.255.255.0")
        self.assertEqual(res["broadcast_address"], "192.168.1.255")
        self.assertEqual(res["total_hosts"], 256)
        self.assertEqual(res["usable_hosts"], 254)
        self.assertTrue(res["is_private"])

    def test_parse_cidr_invalid(self):
        res = parse_cidr("invalid-cidr-notation")
        self.assertEqual(res["status"], "error")

    def test_generate_ip_range(self):
        ips = generate_ip_range("10.0.0.0/30", max_limit=10)
        self.assertEqual(len(ips), 2)
        self.assertIn("10.0.0.1", ips)
        self.assertIn("10.0.0.2", ips)

    def test_assess_subnet_exposure(self):
        scanned = [
            {"ip": "192.168.1.1", "open_ports": [22, 80]},
            {"ip": "192.168.1.2", "open_ports": [3389]},
            {"ip": "192.168.1.3", "open_ports": []},
        ]
        res = assess_subnet_exposure(scanned)
        self.assertEqual(res["total_hosts_analyzed"], 3)
        self.assertEqual(res["exposed_hosts_count"], 2)
        self.assertGreater(res["high_risk_services_count"], 0)
        self.assertGreater(res["risk_score"], 0)


if __name__ == "__main__":
    unittest.main()
