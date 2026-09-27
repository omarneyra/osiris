"""
Unit tests for OSINT Intel Collector (Python).
"""

import sys
import unittest
from pathlib import Path

# Ensure engine directory is in sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from intel_collector import (
    is_valid_ip,
    is_valid_mmsi,
    is_valid_icao24,
    calculate_risk_score,
    enrich_ip,
    enrich_vessel,
    enrich_aircraft,
)


class TestIntelCollector(unittest.TestCase):
    def test_is_valid_ip(self):
        self.assertTrue(is_valid_ip("192.168.1.1"))
        self.assertTrue(is_valid_ip("8.8.8.8"))
        self.assertFalse(is_valid_ip("256.0.0.1"))
        self.assertFalse(is_valid_ip("invalid-ip"))

    def test_is_valid_mmsi(self):
        self.assertTrue(is_valid_mmsi("123456789"))
        self.assertFalse(is_valid_mmsi("1234"))
        self.assertFalse(is_valid_mmsi("abc123456"))

    def test_is_valid_icao24(self):
        self.assertTrue(is_valid_icao24("400a0c"))
        self.assertTrue(is_valid_icao24("A3B4C5"))
        self.assertFalse(is_valid_icao24("12345"))
        self.assertFalse(is_valid_icao24("GHIJKL"))

    def test_calculate_risk_score(self):
        self.assertEqual(calculate_risk_score([]), 0.0)
        self.assertEqual(calculate_risk_score(["TOR_EXIT_NODE"]), 35.0)
        self.assertEqual(calculate_risk_score(["KNOWN_MALWARE_C2", "SANCTIONED_ENTITY"]), 100.0)

    def test_enrich_ip(self):
        res = enrich_ip("10.0.0.1")
        self.assertEqual(res["status"], "success")
        self.assertTrue(res["is_private"])
        self.assertIn("INTERNAL_NETWORK", res["indicators"])

        res_invalid = enrich_ip("999.999.999.999")
        self.assertEqual(res_invalid["status"], "error")

    def test_enrich_vessel(self):
        res = enrich_vessel("123456789")
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["mmsi"], "123456789")

        res_invalid = enrich_vessel("123")
        self.assertEqual(res_invalid["status"], "error")

    def test_enrich_aircraft(self):
        res = enrich_aircraft("a01234", "FORTE11")
        self.assertEqual(res["status"], "success")
        self.assertTrue(res["is_military"])
        self.assertGreater(res["risk_score"], 0)


if __name__ == "__main__":
    unittest.main()
