"""
OSIRIS — Python Anomaly Detection & Threat Alert Engine
Simple functional style (no OOP).
"""

from typing import List, Dict, Any


EMERGENCY_SQUAWKS = {
    "7700": "GENERAL_EMERGENCY",
    "7600": "RADIO_FAILURE",
    "7500": "HIJACKING_UNLAWFUL_INTERFERENCE",
}


def detect_aircraft_anomalies(aircraft_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect transponder anomalies (emergency squawks 7700/7600/7500, rapid descent, loss of signal).
    """
    anomalies = []

    for plane in aircraft_list:
        callsign = plane.get("callsign", "UNKNOWN").strip()
        icao24 = plane.get("icao24", "").strip()
        squawk = str(plane.get("squawk", "")).strip()
        vertical_rate = plane.get("vertical_rate", 0.0)

        # Emergency squawk check
        if squawk in EMERGENCY_SQUAWKS:
            anomalies.append({
                "type": "AIRCRAFT_SQUAWK_EMERGENCY",
                "target": callsign or icao24,
                "icao24": icao24,
                "squawk": squawk,
                "code": EMERGENCY_SQUAWKS[squawk],
                "severity": "CRITICAL" if squawk == "7500" else "HIGH",
                "details": f"Aircraft {callsign} squawking emergency code {squawk} ({EMERGENCY_SQUAWKS[squawk]})",
            })

        # Rapid descent check (> -3000 ft/min)
        if vertical_rate and vertical_rate < -3000:
            anomalies.append({
                "type": "AIRCRAFT_RAPID_DESCENT",
                "target": callsign or icao24,
                "icao24": icao24,
                "vertical_rate_fpm": vertical_rate,
                "severity": "HIGH",
                "details": f"Aircraft {callsign} rapid descent rate: {vertical_rate} ft/min",
            })

    return anomalies


def detect_vessel_anomalies(vessels_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect maritime AIS anomalies (dark vessels disabling transponders, unusual speed).
    """
    anomalies = []

    for ship in vessels_list:
        mmsi = str(ship.get("mmsi", "")).strip()
        name = ship.get("name", mmsi)
        speed = ship.get("speed_knots", 0.0)
        ais_age_minutes = ship.get("ais_age_minutes", 0)

        # AIS Signal blackout / dark ship (> 60 mins stale)
        if ais_age_minutes > 60:
            anomalies.append({
                "type": "VESSEL_AIS_BLACKOUT",
                "target": name,
                "mmsi": mmsi,
                "ais_age_minutes": ais_age_minutes,
                "severity": "HIGH",
                "details": f"Vessel {name} AIS transponder dark for {ais_age_minutes} minutes",
            })

        # Abnormally high speed (> 40 knots for non-military ships)
        if speed > 40.0:
            anomalies.append({
                "type": "VESSEL_HIGH_SPEED_ANOMALY",
                "target": name,
                "mmsi": mmsi,
                "speed_knots": speed,
                "severity": "MEDIUM",
                "details": f"Vessel {name} reported unusual speed of {speed} knots",
            })

    return anomalies


def detect_seismic_anomalies(earthquakes_list: List[Dict[str, Any]], min_magnitude: float = 5.0) -> List[Dict[str, Any]]:
    """
    Detect major seismic events exceeding magnitude threshold.
    """
    anomalies = []

    for eq in earthquakes_list:
        mag = eq.get("magnitude", 0.0)
        place = eq.get("place", "Unknown location")
        depth = eq.get("depth_km", 0.0)

        if mag >= min_magnitude:
            anomalies.append({
                "type": "MAJOR_SEISMIC_EVENT",
                "target": place,
                "magnitude": mag,
                "depth_km": depth,
                "severity": "CRITICAL" if mag >= 7.0 else ("HIGH" if mag >= 6.0 else "MEDIUM"),
                "details": f"Earthquake M{mag} detected at {place} (depth: {depth}km)",
            })

    return anomalies
