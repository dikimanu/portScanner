import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from services import services
from analyzer import security_analysis


# =========================
# SCAN SINGLE PORT
# =========================
def scan_port(ip, port, timeout=1.0):

    status = "CLOSED"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)

            result = sock.connect_ex((ip, port))

            # 0 = connection succeeded -> port is OPEN
            # non-zero (e.g. connection refused) -> port is CLOSED
            status = "OPEN" if result == 0 else "CLOSED"

    except socket.timeout:
        # No response at all -> firewall/filter dropping packets
        status = "FILTERED"

    except Exception:
        status = "FILTERED"

    service = services.get(port, "Unknown Service")

    analysis = security_analysis.get(port, {
        "risk_level": "UNKNOWN",
        "purpose": "Unknown Service",
        "risk": "Unknown risk",
        "recommendation": "Investigate manually"
    })

    return {
        "port": port,
        "service": service,
        "status": status,
        "risk_level": analysis["risk_level"],
        "purpose": analysis["purpose"],
        "risk": analysis["risk"],
        "recommendation": analysis["recommendation"]
    }


# =========================
# MAIN SCAN FUNCTION
# =========================
def run_scan(target, start_port, end_port):

    start_time = time.time()

    # Resolve target (hostname or IP) to a single IP address up front.
    # This also validates the target early: bad input fails fast here
    # instead of causing every single port scan to error out silently.
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return {
            "target": target,
            "hostname": "Could not resolve target",
            "start_port": start_port,
            "end_port": end_port,
            "duration": 0,
            "open_ports": [],
            "all_results": [],
            "summary": {"open": 0, "closed": 0, "filtered": 0},
            "error": f"Could not resolve target '{target}'. Check the IP or hostname."
        }

    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        hostname = "Hostname Not Found"

    results = []

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [
            executor.submit(scan_port, ip, port)
            for port in range(start_port, end_port + 1)
        ]

        for future in as_completed(futures):
            results.append(future.result())

    # keep ports in ascending order (as_completed finishes out of order)
    results.sort(key=lambda r: r["port"])

    end_time = time.time()

    open_ports = [p for p in results if p["status"] == "OPEN"]
    closed_ports = [p for p in results if p["status"] == "CLOSED"]
    filtered_ports = [p for p in results if p["status"] == "FILTERED"]

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
        },

        "engine": "custom"
        }
    