"""
Unit tests for Geofencing & Spatial Intelligence Analyzer (Python).
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from geofence_analyzer import is_point_in_polygon, analyze_entity_geofence


class TestGeofenceAnalyzer(unittest.TestCase):
    def test_is_point_in_polygon(self):
        # Square polygon around (0,0) to (10,10)
        polygon = [(0.0, 0.0), (10.0, 0.0), (10.0, 10.0), (0.0, 10.0)]

        self.assertTrue(is_point_in_polygon(5.0, 5.0, polygon))
        self.assertFalse(is_point_in_polygon(15.0, 15.0, polygon))

    def test_analyze_entity_geofence(self):
        aois = [
            {
                "id": "aoi-1",
                "name": "Restricted Zone Alpha",
                "severity": "CRITICAL",
                "polygon": [(0.0, 0.0), (10.0, 0.0), (10.0, 10.0), (0.0, 10.0)],
            }
        ]

        res_inside = analyze_entity_geofence("target-1", 5.0, 5.0, aois)
        self.assertTrue(res_inside["in_geofence"])
        self.assertEqual(res_inside["highest_severity"], "CRITICAL")

        res_outside = analyze_entity_geofence("target-2", 20.0, 20.0, aois)
        self.assertFalse(res_outside["in_geofence"])
        self.assertEqual(res_outside["highest_severity"], "NONE")


if __name__ == "__main__":
    unittest.main()
