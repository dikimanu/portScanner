import nmap
import socket
import time

from services import services
from analyzer import security_analysis


def run_nmap_scan(target, start_port, end_port):

    scanner = nmap.PortScanner()

    start_time = time.time()

    try:
        hostname = socket.gethostbyaddr(target)[0]
    except:
        hostname = "Hostname Not Found"

    port_range = f"{start_port}-{end_port}"

    scanner.scan(
        target,
        ports=port_range,
        arguments="-sS"
    )

    results = []

    for port in range(start_port, end_port + 1):

        try:
            state = scanner[target]["tcp"][port]["state"]
        except:
            state = "filtered"

        status = state.upper()

        service = services.get(
            port,
            "Unknown Service"
        )

        analysis = security_analysis.get(port, {
            "risk_level": "UNKNOWN",
            "purpose": "Unknown Service",
            "risk": "Unknown risk",
            "recommendation": "Investigate manually"
        })

        results.append({

            "port": port,

            "service": service,

            "status": status,

            "risk_level": analysis["risk_level"],

            "purpose": analysis["purpose"],

            "risk": analysis["risk"],

            "recommendation": analysis["recommendation"]
        })

    end_time = time.time()

    open_ports = [
        p for p in results
        if p["status"] == "OPEN"
    ]

    closed_ports = [
        p for p in results
        if p["status"] == "CLOSED"
    ]

    filtered_ports = [
        p for p in results
        if p["status"] == "FILTERED"
    ]

    return {

        "target": target,

        "hostname": hostname,

        "start_port": start_port,

        "end_port": end_port,

        "duration": round(end_time - start_time, 2),

        "open_ports": open_ports,

        "all_results": results,

        "summary": {

            "open": len(open_ports),

            "closed": len(closed_ports),

            "filtered": len(filtered_ports)
        }
    }