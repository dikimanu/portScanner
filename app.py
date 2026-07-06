from flask import (

    Flask,
    render_template,
    request,
    send_file

)

from scanner_engine import run_scan

from report_generator import (

    save_csv_report,
    save_txt_report

)


app = Flask(__name__)


# Home Page
@app.route("/")

def home():

    return render_template(

        "index.html"

    )


# Scan Route
@app.route(

    "/scan",

    methods=["POST"]

)

def scan():

    target = request.form["target"]

    start_port = int(

        request.form["start_port"]

    )

    end_port = int(

        request.form["end_port"]

    )

    # Run Scanner
    scan_data = run_scan(

        target,
        start_port,
        end_port

    )

    # Generate Reports
    save_csv_report(

        scan_data["open_ports"]

    )

    save_txt_report(

        scan_data

    )

    return render_template(

        "results.html",

        data=scan_data

    )


# Download CSV
@app.route("/download/csv")

def download_csv():

    return send_file(

        "reports/scan_report.csv",

        as_attachment=True

    )


# Download TXT
@app.route("/download/txt")

def download_txt():

    return send_file(

        "reports/scan_report.txt",

        as_attachment=True

    )


# Run Flask App
if __name__ == "__main__":

    app.run(

        debug=True

    )
