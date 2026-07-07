from flask import Flask, render_template, request, send_file, session
from scanner_engine import run_scan
from report_generator import save_csv_report, save_txt_report
import os
import re
import uuid

app = Flask(__name__)

# Use a random secret key generated at startup.
# NOTE: this changes every time the server restarts, which will invalidate
# existing sessions (and their stored report paths). For production, set
# a fixed secret via an environment variable instead:
#   app.secret_key = os.environ["FLASK_SECRET_KEY"]
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24).hex())


# Very basic sanity check for target input: IPv4 address or hostname-like string.
# This won't catch every invalid case, but blocks obviously malformed input
# (spaces, empty strings, illegal characters) before it reaches socket calls.
TARGET_PATTERN = re.compile(r"^[a-zA-Z0-9.\-]+$")


def is_valid_target(target):
    if not target or len(target) > 255:
        return False
    return bool(TARGET_PATTERN.match(target))


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():

    target = request.form.get("target", "").strip()

    try:
        start_port = int(request.form.get("start_port", 1))
        end_port = int(request.form.get("end_port", 1024))
    except ValueError:
        return render_template("error.html", message="Port values must be numbers"), 400

    if not is_valid_target(target):
        return render_template("error.html", message="Invalid Target IP or Hostname"), 400

    if start_port < 1 or end_port > 65535 or start_port > end_port:
        return render_template("error.html", message="Invalid Port Range"), 400

    scan_data = run_scan(target, start_port, end_port)

    # target passed basic format validation but couldn't actually be resolved
    if scan_data.get("error"):
        return render_template("error.html", message=scan_data["error"]), 400

    # unique filenames per scan so concurrent users don't overwrite each other
    scan_id = uuid.uuid4().hex
    csv_path = save_csv_report(scan_data["all_results"], scan_id)
    txt_path = save_txt_report(scan_data, scan_id)

    # remember this user's own report paths
    session["csv_path"] = csv_path
    session["txt_path"] = txt_path

    return render_template("results.html", data=scan_data)


@app.route("/download/csv")
def download_csv():
    path = session.get("csv_path")
    if not path or not os.path.exists(path):
        return render_template("error.html", message="No report available"), 404
    return send_file(path, as_attachment=True)


@app.route("/download/txt")
def download_txt():
    path = session.get("txt_path")
    if not path or not os.path.exists(path):
        return render_template("error.html", message="No report available"), 404
    return send_file(path, as_attachment=True)


if __name__ == "__main__":
    # debug=True is fine for local development only.
    # Turn this off (or remove host="0.0.0.0") before exposing this to a LAN/network.
    app.run(host="0.0.0.0", port=5000, debug=True)