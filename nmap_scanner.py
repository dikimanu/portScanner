import nmap
import socket
import time


def run_nmap_scan(target, start_port, end_port):
    """
    Runs a scan using the real Nmap engine (via python-nmap) and returns
    a result dict with the same shape as scanner_engine.run_scan(), so
    app.py, results.html, and report_generator.py can handle either
    engine's output identically.
    """

    from services import services
    from analyzer import security_analysis

    start_time = time.time()

    scanner = nmap.PortScanner()
    port_range = f"{start_port}-{end_port}"

    try:
        # -sV = service/version detection, -T4 = faster timing template
        scanner.scan(target, port_range, arguments="-sV -T4")
    except Exception as e:
        return {
            "target": target,
            "hostname": "N/A",
            "start_port": start_port,
            "end_port": end_port,
            "duration": 0,
            "open_ports": [],
            "all_results": [],
            "summary": {"open": 0, "closed": 0, "filtered": 0},
            "engine": "nmap",
            "error": f"Nmap scan failed: {e}"
        }

    if target not in scanner.all_hosts():
        return {
            "target": target,
            "hostname": "N/A",
            "start_port": start_port,
            "end_port": end_port,
            "duration": round(time.time() - start_time, 2),
            "open_ports": [],
            "all_results": [],
            "summary": {"open": 0, "closed": 0, "filtered": 0},
            "engine": "nmap",
            "error": f"Host {target} appears to be down or unreachable"
        }

    try:
        hostname = scanner[target].hostname() or socket.gethostbyaddr(target)[0]
    except Exception:
        hostname = "Hostname Not Found"

    results = []
    reported_ports = set()

    for proto in scanner[target].all_protocols():
        ports = scanner[target][proto].keys()

        for port in sorted(ports):
            port_info = scanner[target][proto][port]

            # Nmap states: "open", "closed", "filtered" (map to your existing labels)
            status = port_info.get("state", "unknown").upper()

            service_name = services.get(port, port_info.get("name", "Unknown Service"))

            analysis = security_analysis.get(port, {
                "risk_level": "UNKNOWN",
                "purpose": "Unknown Service",
                "risk": "Unknown risk",
                "recommendation": "Investigate manually"
            })

            results.append({
                "port": port,
                "service": service_name,
                "product": port_info.get("product", ""),
                "version": port_info.get("version", ""),
                "status": status,
                "risk_level": analysis["risk_level"],
                "purpose": analysis["purpose"],
                "risk": analysis["risk"],
                "recommendation": analysis["recommendation"]
            })

            reported_ports.add(port)

    # Nmap only reports ports it considers "interesting" (open/filtered) by default.
    # Any port in the requested range that wasn't reported at all is safely
    # assumed CLOSED (Nmap collapses these into a "Not shown: N closed ports" summary
    # instead of listing each one). This fills them back in so totals match the
    # full requested range, consistent with the custom scanner's behavior.
    for port in range(start_port, end_port + 1):
        if port not in reported_ports:

            service_name = services.get(port, "Unknown Service")

            analysis = security_analysis.get(port, {
                "risk_level": "UNKNOWN",
                "purpose": "Unknown Service",
                "risk": "Unknown risk",
                "recommendation": "Investigate manually"
            })

            results.append({
                "port": port,
                "service": service_name,
                "product": "",
                "version": "",
                "status": "CLOSED",
                "risk_level": analysis["risk_level"],
                "purpose": analysis["purpose"],
                "risk": analysis["risk"],
                "recommendation": analysis["recommendation"]
            })

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

        "engine": "nmap"
    }