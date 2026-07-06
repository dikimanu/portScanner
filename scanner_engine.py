import socket
import time

from concurrent.futures import ThreadPoolExecutor

from services import services
from analyzer import security_analysis


# Store Open Ports
open_ports = []


# Scan Single Port
def scan_port(target, port):

    try:

        scanner = socket.socket(

            socket.AF_INET,
            socket.SOCK_STREAM

        )

        scanner.settimeout(0.5)

        result = scanner.connect_ex(

            (target, port)

        )

        if result == 0:

            service_name = services.get(

                port,
                "Unknown Service"

            )

            analysis = security_analysis.get(port)

            if analysis:

                risk_level = analysis["risk_level"]

                purpose = analysis["purpose"]

                risk = analysis["risk"]

                recommendation = (

                    analysis["recommendation"]

                )

            else:

                risk_level = "UNKNOWN"

                purpose = (
                    "Unknown Service"
                )

                risk = (
                    "Unknown security risk."
                )

                recommendation = (
                    "Investigate manually."
                )

            open_ports.append({

                "port": port,
                "service": service_name,
                "status": "OPEN",
                "risk_level": risk_level,
                "purpose": purpose,
                "risk": risk,
                "recommendation": recommendation

            })

        scanner.close()

    except:

        pass


# Main Scan Function
def run_scan(

    target,
    start_port,
    end_port

):

    global open_ports

    open_ports = []

    # Start Time
    start_time = time.time()

    # Hostname
    try:

        hostname = socket.gethostbyaddr(

            target

        )[0]

    except:

        hostname = "Hostname Not Found"


    # Multithreaded Scan
    with ThreadPoolExecutor(

        max_workers=100

    ) as executor:

        for port in range(

            start_port,
            end_port + 1

        ):

            executor.submit(

                scan_port,
                target,
                port

            )


    # End Time
    end_time = time.time()

    duration = round(

        end_time - start_time,
        2

    )

    return {

        "target": target,

        "hostname": hostname,

        "start_port": start_port,

        "end_port": end_port,

        "duration": duration,

        "open_ports": open_ports

    }

