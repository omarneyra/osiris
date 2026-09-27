"""
OSIRIS — Python OSINT Intelligence Collector
Simple functional style (no OOP).
"""

import re
import json
from typing import Dict, Any, List


def is_valid_ip(address: str) -> bool:
    """Validate IPv4 format."""
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if not re.match(pattern, address):
        return False
    parts = address.split(".")
    return all(0 <= int(part) <= 255 for part in parts)


def is_valid_mmsi(mmsi: str) -> bool:
    """Validate Maritime Mobile Service Identity (9 digits)."""
    return bool(re.match(r"^\d{9}$", str(mmsi).strip()))


def is_valid_icao24(icao24: str) -> bool:
    """Validate ICAO 24-bit hex address (6 hex characters)."""
    return bool(re.match(r"^[0-9a-fA-F]{6}$", str(icao24).strip()))


def calculate_risk_score(indicators: List[str]) -> float:
    """
    Calculate risk score between 0.0 and 100.0 based on threat indicators.
    """
    if not indicators:
        return 0.0

    weight_map = {
        "TOR_EXIT_NODE": 35.0,
        "KNOWN_MALWARE_C2": 50.0,
        "HIGH_RISK_COUNTRY": 15.0,
        "SANCTIONED_ENTITY": 60.0,
        "OPEN_PROXY": 25.0,
        "MILITARY_TRANSPONDER": 20.0,
        "SUSPICIOUS_BEARING": 10.0,
    }

    total_score = sum(weight_map.get(ind, 5.0) for ind in indicators)
    return min(100.0, round(total_score, 1))


def enrich_ip(ip: str) -> Dict[str, Any]:
    """
    Enrich IP address with OSINT threat metadata.
    """
    ip_clean = str(ip).strip()
    if not is_valid_ip(ip_clean):
        return {
            "status": "error",
            "message": f"Invalid IP address format: {ip_clean}",
            "ip": ip_clean,
        }

    # Internal / Private IP check
    parts = [int(p) for p in ip_clean.split(".")]
    is_private = (
        parts[0] == 10
        or (parts[0] == 172 and 16 <= parts[1] <= 31)
        or (parts[0] == 192 and parts[1] == 168)
        or parts[0] == 127
    )

    indicators = []
    if is_private:
        indicators.append("INTERNAL_NETWORK")

    risk_score = calculate_risk_score(indicators)

    return {
        "status": "success",
        "type": "ip",
        "target": ip_clean,
        "is_private": is_private,
        "indicators": indicators,
        "risk_score": risk_score,
        "threat_level": "LOW" if risk_score < 30 else ("MEDIUM" if risk_score < 70 else "HIGH"),
        "source": "OSIRIS Python Engine",
    }


def enrich_vessel(mmsi: str) -> Dict[str, Any]:
    """
    Enrich maritime vessel by MMSI.
    """
    mmsi_clean = str(mmsi).strip()
    if not is_valid_mmsi(mmsi_clean):
        return {
            "status": "error",
            "message": f"Invalid MMSI format: {mmsi_clean}",
            "mmsi": mmsi_clean,
        }

    mid_code = mmsi_clean[:3]
    indicators = []

    # Example MID flags
    if mid_code in ("677", "668", "620"):
        indicators.append("HIGH_RISK_FLAG_STATE")

    risk_score = calculate_risk_score(indicators)

    return {
        "status": "success",
        "type": "vessel",
        "mmsi": mmsi_clean,
        "mid_code": mid_code,
        "indicators": indicators,
        "risk_score": risk_score,
        "threat_level": "LOW" if risk_score < 30 else ("MEDIUM" if risk_score < 70 else "HIGH"),
        "source": "OSIRIS Maritime Engine",
    }


def enrich_aircraft(icao24: str, callsign: str = "") -> Dict[str, Any]:
    """
    Enrich aircraft by ICAO24 hex address and callsign.
    """
    icao_clean = str(icao24).strip().lower()
    callsign_clean = str(callsign).strip().upper()

    if not is_valid_icao24(icao_clean):
        return {
            "status": "error",
            "message": f"Invalid ICAO24 format: {icao_clean}",
            "icao24": icao_clean,
        }

    indicators = []
    # Known military / government callsign prefixes
    mil_prefixes = ("RCH", "CNV", "CGR", "FORTE", "LAGR", "HOMER", "DUKE", "NACHO", "JAKE")
    if any(callsign_clean.startswith(prefix) for prefix in mil_prefixes):
        indicators.append("MILITARY_TRANSPONDER")

    risk_score = calculate_risk_score(indicators)

    return {
        "status": "success",
        "type": "aircraft",
        "icao24": icao_clean,
        "callsign": callsign_clean,
        "is_military": "MILITARY_TRANSPONDER" in indicators,
        "indicators": indicators,
        "risk_score": risk_score,
        "threat_level": "LOW" if risk_score < 30 else ("MEDIUM" if risk_score < 70 else "HIGH"),
        "source": "OSIRIS Aviation Engine",
    }
