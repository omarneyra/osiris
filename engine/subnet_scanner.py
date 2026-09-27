"""
OSIRIS — Python Infrastructure & Subnet (CIDR) Scanner Engine
Simple functional style (no OOP).
"""

import ipaddress
from typing import Dict, Any, List


HIGH_RISK_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    445: "SMB",
    1433: "MSSQL",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRESQL",
    9200: "ELASTICSEARCH",
}


def parse_cidr(cidr_block: str) -> Dict[str, Any]:
    """
    Parse CIDR block and calculate network properties.
    """
    cidr_clean = str(cidr_block).strip()

    try:
        network = ipaddress.ip_network(cidr_clean, strict=False)
        return {
            "status": "success",
            "cidr": str(network),
            "network_address": str(network.network_address),
            "netmask": str(network.netmask),
            "broadcast_address": str(network.broadcast_address),
            "total_hosts": network.num_addresses,
            "usable_hosts": max(0, network.num_addresses - 2) if network.prefixlen < 31 else network.num_addresses,
            "prefixlen": network.prefixlen,
            "is_private": network.is_private,
        }
    except ValueError as err:
        return {
            "status": "error",
            "message": f"Invalid CIDR notation '{cidr_clean}': {str(err)}",
            "cidr": cidr_clean,
        }


def generate_ip_range(cidr_block: str, max_limit: int = 256) -> List[str]:
    """
    Generate list of usable host IP strings up to max_limit.
    """
    parsed = parse_cidr(cidr_block)
    if parsed["status"] == "error":
        return []

    network = ipaddress.ip_network(parsed["cidr"], strict=False)
    hosts = [str(ip) for ip in network.hosts()]
    return hosts[:max_limit]


def assess_subnet_exposure(scanned_hosts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Assess overall exposure risk of a scanned host list in a subnet.
    """
    total_hosts = len(scanned_hosts)
    if total_hosts == 0:
        return {
            "total_hosts_analyzed": 0,
            "exposed_hosts_count": 0,
            "risk_score": 0.0,
            "exposure_level": "LOW",
            "open_port_summary": {},
        }

    exposed_hosts = 0
    port_summary: Dict[int, int] = {}
    high_risk_detected = 0

    for host in scanned_hosts:
        open_ports = host.get("open_ports", [])
        if open_ports:
            exposed_hosts += 1
            for port in open_ports:
                port_summary[port] = port_summary.get(port, 0) + 1
                if port in HIGH_RISK_PORTS:
                    high_risk_detected += 1

    exposure_ratio = exposed_hosts / total_hosts
    raw_score = (exposure_ratio * 50.0) + min(50.0, high_risk_detected * 10.0)
    risk_score = round(min(100.0, raw_score), 1)

    exposure_level = "LOW"
    if risk_score >= 75.0:
        exposure_level = "CRITICAL"
    elif risk_score >= 50.0:
        exposure_level = "HIGH"
    elif risk_score >= 25.0:
        exposure_level = "MEDIUM"

    return {
        "total_hosts_analyzed": total_hosts,
        "exposed_hosts_count": exposed_hosts,
        "high_risk_services_count": high_risk_detected,
        "risk_score": risk_score,
        "exposure_level": exposure_level,
        "open_port_summary": port_summary,
    }
