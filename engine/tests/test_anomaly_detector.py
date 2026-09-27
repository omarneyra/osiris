"""
Unit tests for Anomaly Detection & Threat Alert Engine (Python).
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from anomaly_detector import (
    detect_aircraft_anomalies,
    detect_vessel_anomalies,
    detect_seismic_anomalies,
)


class TestAnomalyDetector(unittest.TestCase):
    def test_detect_aircraft_anomalies_emergency_squawk(self):
        planes = [
            {"icao24": "a01234", "callsign": "FORTE11", "squawk": "7700", "vertical_rate": -500},
            {"icao24": "b56789", "callsign": "DAL123", "squawk": "1200", "vertical_rate": 0},
        ]
        anomalies = detect_aircraft_anomalies(planes)
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0]["type"], "AIRCRAFT_SQUAWK_EMERGENCY")
        self.assertEqual(anomalies[0]["squawk"], "7700")
        self.assertEqual(anomalies[0]["severity"], "HIGH")

    def test_detect_aircraft_rapid_descent(self):
        planes = [
            {"icao24": "c99999", "callsign": "TEST99", "squawk": "1200", "vertical_rate": -4500}
        ]
        anomalies = detect_aircraft_anomalies(planes)
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0]["type"], "AIRCRAFT_RAPID_DESCENT")

    def test_detect_vessel_anomalies_dark_ship(self):
        vessels = [
            {"mmsi": "123456789", "name": "GHOST SHIP", "ais_age_minutes": 120, "speed_knots": 12.0}
        ]
        anomalies = detect_vessel_anomalies(vessels)
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0]["type"], "VESSEL_AIS_BLACKOUT")

    def test_detect_seismic_anomalies(self):
        events = [
            {"magnitude": 6.8, "place": "Off Coast of Honshu, Japan", "depth_km": 25.0},
            {"magnitude": 3.2, "place": "Minor Shake Zone", "depth_km": 5.0},
        ]
        anomalies = detect_seismic_anomalies(events, min_magnitude=5.0)
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0]["magnitude"], 6.8)
        self.assertEqual(anomalies[0]["severity"], "HIGH")


if __name__ == "__main__":
    unittest.main()
