import csv
from datetime import datetime


# Generate CSV Report
def save_csv_report(open_ports):

    path = "reports/scan_report.csv"

    with open(

        path,

        mode="w",

        newline=""

    ) as file:

        writer = csv.writer(file)

        writer.writerow([

            "Port",
            "Service",
            "Status",
            "Risk Level"

        ])

        for item in open_ports:

            writer.writerow([

                item["port"],
                item["service"],
                item["status"],
                item["risk_level"]

            ])

    return path


# Generate TXT Report
def save_txt_report(scan_data):

    path = "reports/scan_report.txt"

    with open(path, "w") as file:

        file.write("=" * 50 + "\n")

        file.write(
            "NETWORK PORT SCAN REPORT\n"
        )

        file.write("=" * 50 + "\n\n")

        file.write(

            f"Scan Date : "
            f"{datetime.now()}\n\n"

        )

        file.write(
            "TARGET INFORMATION\n"
        )

        file.write("-" * 50 + "\n")

        file.write(

            f"Target IP : "
            f"{scan_data['target']}\n"

        )

        file.write(

            f"Hostname : "
            f"{scan_data['hostname']}\n"

        )

        file.write(

            f"Port Range : "

            f"{scan_data['start_port']}"

            f" - "

            f"{scan_data['end_port']}\n"

        )

        file.write(

            f"Scan Duration : "

            f"{scan_data['duration']} "

            f"seconds\n\n"

        )

        file.write(
            "OPEN PORTS\n"
        )

        file.write("-" * 50 + "\n")

        if scan_data["open_ports"]:

            for item in scan_data["open_ports"]:

                file.write(

                    f"Port {item['port']} "

                    f"--> "

                    f"{item['service']} "

                    f"--> "

                    f"{item['status']}\n"

                )

        else:

            file.write(
                "No Open Ports Found\n"
            )

        file.write("\n")

        file.write(
            "SECURITY ANALYSIS\n"
        )

        file.write("-" * 50 + "\n")

        for item in scan_data["open_ports"]:

            file.write(

                f"\nPort {item['port']} "
                f"({item['service']})\n"

            )

            file.write(

                f"Purpose : "
                f"{item['purpose']}\n"

            )

            file.write(

                f"Risk Level : "
                f"{item['risk_level']}\n"

            )

            file.write(

                f"Risk : "
                f"{item['risk']}\n"

            )

            file.write(

                f"Recommendation : "
                f"{item['recommendation']}\n"

            )

    return path
