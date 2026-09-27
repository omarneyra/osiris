"""
OSIRIS — Python Geofencing & Spatial Intelligence Analyzer
Simple functional style (no OOP).
"""

from typing import List, Tuple, Dict, Any


def is_point_in_polygon(lat: float, lon: float, polygon: List[Tuple[float, float]]) -> bool:
    """
    Check if (lat, lon) is inside a polygon defined by list of (lat, lon) tuples
    using Ray-Casting algorithm.
    """
    if len(polygon) < 3:
        return False

    inside = False
    n = len(polygon)
    j = n - 1

    for i in range(n):
        lat_i, lon_i = polygon[i]
        lat_j, lon_j = polygon[j]

        # Check ray intersection with polygon edge
        intersects = ((lon_i > lon) != (lon_j > lon)) and (
            lat < (lat_j - lat_i) * (lon - lon_i) / (lon_j - lon_i + 1e-12) + lat_i
        )
        if intersects:
            inside = not inside
        j = i

    return inside


def analyze_entity_geofence(
    entity_id: str,
    lat: float,
    lon: float,
    aois: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Analyze entity coordinates against a list of active Areas of Interest (AOIs).
    Returns alerts if entity is inside any high-risk AOI.
    """
    matches = []
    highest_severity = "INFO"

    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "INFO": 1}

    for aoi in aois:
        aoi_id = aoi.get("id", "unknown")
        name = aoi.get("name", "AOI Area")
        severity = aoi.get("severity", "MEDIUM").upper()
        polygon = aoi.get("polygon", [])

        if is_point_in_polygon(lat, lon, polygon):
            matches.append({
                "aoi_id": aoi_id,
                "name": name,
                "severity": severity,
            })
            if severity_rank.get(severity, 1) > severity_rank.get(highest_severity, 1):
                highest_severity = severity

    return {
        "entity_id": entity_id,
        "lat": lat,
        "lon": lon,
        "in_geofence": len(matches) > 0,
        "matches_count": len(matches),
        "highest_severity": highest_severity if matches else "NONE",
        "matched_aois": matches,
    }
