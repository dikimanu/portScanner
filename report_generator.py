import csv
import os
from datetime import datetime


# =========================
# CSV REPORT (ALL PORTS)
# =========================
def save_csv_report(all_results, scan_id="latest"):

    os.makedirs("reports", exist_ok=True)

    path = f"reports/scan_report_{scan_id}.csv"

    # Show a Version column only if at least one result actually has version info
    # (keeps the custom-scanner CSV unchanged, since it never sets this field)
    show_version = any(item.get("version") for item in all_results)

    with open(path, mode="w", newline="") as file:

        writer = csv.writer(file)

        header = ["Port", "Service"]
        if show_version:
            header.append("Version")
        header += ["Status", "Risk Level"]

        writer.writerow(header)

        for item in all_results:

            row = [
                item.get("port", ""),
                item.get("service", "")
            ]

            if show_version:
                product = item.get("product", "")
                version = item.get("version", "")
                row.append(f"{product} {version}".strip())

            row += [
                item.get("status", ""),
                item.get("risk_level", "")
            ]

            writer.writerow(row)

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

    engine = scan_data.get("engine", "custom")

    with open(path, "w") as file:

        file.write("=" * 60 + "\n")
        file.write("NETWORK PORT SCAN REPORT\n")
        file.write("=" * 60 + "\n\n")

        file.write(f"Scan Date : {datetime.now()}\n")
        file.write(f"Scan Engine : {engine.capitalize()}\n\n")

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
                version_info = ""
                if item.get("product"):
                    version_info = f" ({item.get('product')} {item.get('version', '')})".rstrip()

                file.write(
                    f"Port {item.get('port')} --> "
                    f"{item.get('service')}{version_info} --> OPEN\n"
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

                if item.get("product"):
                    file.write(f"Detected  : {item.get('product')} {item.get('version', '')}\n")

                file.write(f"Purpose        : {item.get('purpose', 'N/A')}\n")
                file.write(f"Risk Level     : {item.get('risk_level', 'UNKNOWN')}\n")
                file.write(f"Risk           : {item.get('risk', 'Unknown')}\n")
                file.write(f"Recommendation : {item.get('recommendation', 'Investigate manually')}\n")

        else:
            file.write("No open ports detected.\n")

    return path