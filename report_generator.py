import csv
import os
from datetime import datetime


# =========================
# CSV REPORT (ALL PORTS)
# =========================
def save_csv_report(all_results, scan_id="latest"):

    os.makedirs("reports", exist_ok=True)

    path = f"reports/scan_report_{scan_id}.csv"

    with open(path, mode="w", newline="") as file:

        writer = csv.writer(file)

        writer.writerow([
            "Port",
            "Service",
            "Status",
            "Risk Level"
        ])

        for item in all_results:

            writer.writerow([
                item.get("port", ""),
                item.get("service", ""),
                item.get("status", ""),
                item.get("risk_level", "")
            ])

    return path


# =========================
# TXT REPORT (FULL REPORT)
# =========================
def save_txt_report(scan_data, scan_id="latest"):

    os.makedirs("reports", exist_ok=True)

    path = f"reports/scan_report_{scan_id}.txt"

    all_ports = scan_data.get("all_results", [])

    summary = scan_data.get("summary", {
        "open": 0,
        "closed": 0,
        "filtered": 0
    })

    with open(path, "w") as file:

        file.write("=" * 60 + "\n")
        file.write("NETWORK PORT SCAN REPORT\n")
        file.write("=" * 60 + "\n\n")

        file.write(f"Scan Date : {datetime.now()}\n\n")

        # =========================
        # TARGET INFO
        # =========================
        file.write("TARGET INFORMATION\n")
        file.write("-" * 60 + "\n")

        file.write(f"Target IP   : {scan_data.get('target', '')}\n")
        file.write(f"Hostname    : {scan_data.get('hostname', '')}\n")
        file.write(f"Port Range  : {scan_data.get('start_port', '')} - {scan_data.get('end_port', '')}\n")
        file.write(f"Duration    : {scan_data.get('duration', 0)} seconds\n\n")

        # =========================
        # SUMMARY
        # =========================
        file.write("SCAN SUMMARY\n")
        file.write("-" * 60 + "\n")

        file.write(f"Open Ports     : {summary.get('open', 0)}\n")
        file.write(f"Closed Ports   : {summary.get('closed', 0)}\n")
        file.write(f"Filtered Ports : {summary.get('filtered', 0)}\n")
        file.write(f"Total Scanned  : {len(all_ports)}\n\n")

        # =========================
        # OPEN PORTS
        # =========================
        file.write("OPEN PORTS\n")
        file.write("-" * 60 + "\n")

        open_ports = [p for p in all_ports if p.get("status") == "OPEN"]

        if open_ports:
            for item in open_ports:
                file.write(
                    f"Port {item.get('port')} --> "
                    f"{item.get('service')} --> OPEN\n"
                )
        else:
            file.write("No Open Ports Found\n")

        file.write("\n")

        # =========================
        # FULL PORT BREAKDOWN
        # =========================
        file.write("DETAILED PORT STATUS\n")
        file.write("-" * 60 + "\n")

        for item in all_ports:

            file.write(
                f"Port {item.get('port')} --> "
                f"{item.get('service')} --> "
                f"{item.get('status')}\n"
            )

        file.write("\n")

        # =========================
        # SECURITY ANALYSIS
        # =========================
        file.write("SECURITY ANALYSIS\n")
        file.write("-" * 60 + "\n")

        if open_ports:

            for item in open_ports:

                file.write(f"\nPort {item.get('port')} ({item.get('service')})\n")

                file.write(f"Purpose        : {item.get('purpose', 'N/A')}\n")
                file.write(f"Risk Level     : {item.get('risk_level', 'UNKNOWN')}\n")
                file.write(f"Risk           : {item.get('risk', 'Unknown')}\n")
                file.write(f"Recommendation : {item.get('recommendation', 'Investigate manually')}\n")

        else:
            file.write("No open ports detected.\n")

    return path