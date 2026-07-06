import socket
import time
from concurrent.futures import ThreadPoolExecutor

from services import services
from analyzer import security_analysis

# =========================
# GLOBAL RESULT STORE
# =========================
results = []


# =========================
# SCAN SINGLE PORT
# =========================
def scan_port(target, port):

    status = "CLOSED"

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.8)

        result = sock.connect_ex((target, port))

        # OPEN PORT
        if result == 0:
            status = "OPEN"

        # FILTERED (timeout-like behavior)
        elif result != 0:
            status = "CLOSED"

        sock.close()

    except:
        status = "FILTERED"

    service = services.get(port, "Unknown Service")

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


# =========================
# MAIN SCAN FUNCTION
# =========================
def run_scan(target, start_port, end_port):

    global results
    results = []

    start_time = time.time()

    try:
        hostname = socket.gethostbyaddr(target)[0]
    except:
        hostname = "Hostname Not Found"

    with ThreadPoolExecutor(max_workers=100) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(scan_port, target, port)

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
        }
    }