from flask import Flask, render_template, request, send_file
from scanner_engine import run_scan
from report_generator import save_csv_report, save_txt_report

app = Flask(__name__)


# -------------------------
# HOME PAGE
# -------------------------
@app.route("/")
def home():
    return render_template("index.html")


# -------------------------
# SCAN ROUTE
# -------------------------
@app.route("/scan", methods=["POST"])
def scan():

    # Get user input
    target = request.form.get("target", "").strip()
    start_port = int(request.form.get("start_port", 1))
    end_port = int(request.form.get("end_port", 1024))

    # Basic validation (important for stability)
    if not target:
        return "Invalid Target IP", 400

    if start_port < 1 or end_port > 65535 or start_port > end_port:
        return "Invalid Port Range", 400

    # Run scan engine
    scan_data = run_scan(target, start_port, end_port)

    # Save full results (OPEN + CLOSED + FILTERED)
    save_csv_report(scan_data["all_results"])
    save_txt_report(scan_data)

    return render_template("results.html", data=scan_data)


# -------------------------
# DOWNLOAD CSV
# -------------------------
@app.route("/download/csv")
def download_csv():
    return send_file(
        "reports/scan_report.csv",
        as_attachment=True
    )


# -------------------------
# DOWNLOAD TXT
# -------------------------
@app.route("/download/txt")
def download_txt():
    return send_file(
        "reports/scan_report.txt",
        as_attachment=True
    )


# -------------------------
# RUN SERVER (LAN READY)
# -------------------------
if __name__ == "__main__":

    # IMPORTANT: allows access from other devices in LAN
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )