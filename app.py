import os
import json
import glob
import uuid
import threading
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename

from email_parser import parse_email
from analyzer import analyze
from virustotal import check_urls_batch, is_configured
from report_generator import generate_pdf

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5MB max upload
UPLOAD_FOLDER = "uploads"
REPORTS_FOLDER = "reports"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)

# Scan state store
scan_store = {}


def run_analysis(scan_id, file_path=None, raw_text=None):
    """Background analysis task."""
    try:
        scan_store[scan_id]["status"] = "parsing"

        # Parse
        parsed = parse_email(file_path=file_path, raw_text=raw_text)
        scan_store[scan_id]["status"] = "analyzing"

        # Heuristic analysis
        analysis = analyze(parsed)

        # VirusTotal (if configured and links exist)
        vt_results = []
        if is_configured() and parsed["links"]:
            scan_store[scan_id]["status"] = "virustotal"
            vt_results = check_urls_batch(parsed["links"], max_urls=5)

            # Boost score for malicious VT results
            malicious_count = sum(1 for r in vt_results if r.get("verdict") == "MALICIOUS")
            if malicious_count > 0:
                analysis["risk_score"] = min(analysis["risk_score"] + malicious_count * 30, 100)
                analysis["flags"].append({
                    "type": "VIRUSTOTAL_MALICIOUS",
                    "severity": "CRITICAL",
                    "detail": f"VirusTotal flagged {malicious_count} link(s) as malicious"
                })
                analysis["verdict"] = "PHISHING"
                analysis["verdict_color"] = "red"

        # Save results JSON
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        subject_clean = "".join(c for c in parsed["subject"][:20] if c.isalnum() or c == " ").strip().replace(" ", "_")
        json_file = os.path.join(REPORTS_FOLDER, f"scan_{subject_clean}_{timestamp}.json")

        result_data = {
            "scan_id": scan_id,
            "timestamp": timestamp,
            "parsed": {
                "subject": parsed["subject"],
                "from": parsed["from"],
                "to": parsed["to"],
                "reply_to": parsed["reply_to"],
                "date": parsed["date"],
                "links": parsed["links"],
                "attachments": parsed["attachments"],
                "body_text": parsed["body_text"][:500]  # Truncate for storage
            },
            "analysis": analysis,
            "vt_results": vt_results
        }

        with open(json_file, "w") as f:
            json.dump(result_data, f, indent=2)

        # Generate PDF
        pdf_file = json_file.replace(".json", ".pdf")
        generate_pdf(result_data, pdf_file)

        scan_store[scan_id].update({
            "status": "complete",
            "results_file": json_file,
            "pdf_file": pdf_file,
            "result": result_data
        })

    except Exception as e:
        scan_store[scan_id]["status"] = f"error: {str(e)}"


@app.route("/")
def index():
    return render_template("index.html", vt_configured=is_configured())


@app.route("/analyze", methods=["POST"])
def analyze_email():
    scan_id = str(uuid.uuid4())
    scan_store[scan_id] = {"status": "starting"}

    file_path = None
    raw_text = None

    if "email_file" in request.files and request.files["email_file"].filename:
        f = request.files["email_file"]
        filename = secure_filename(f.filename)
        file_path = os.path.join(UPLOAD_FOLDER, f"{scan_id}_{filename}")
        f.save(file_path)
    elif request.form.get("raw_email"):
        raw_text = request.form.get("raw_email")
    else:
        return jsonify({"error": "No email provided"}), 400

    thread = threading.Thread(target=run_analysis, args=(scan_id, file_path, raw_text))
    thread.daemon = True
    thread.start()

    return jsonify({"scan_id": scan_id})


@app.route("/status/<scan_id>")
def status(scan_id):
    data = scan_store.get(scan_id, {"status": "not_found"})
    return jsonify({"status": data["status"]})


@app.route("/results/<scan_id>")
def results(scan_id):
    data = scan_store.get(scan_id)
    if not data or data["status"] != "complete":
        return "Analysis not complete yet.", 404
    return render_template("results.html", data=data["result"])


@app.route("/download/<scan_id>")
def download(scan_id):
    data = scan_store.get(scan_id)
    if data and data.get("pdf_file") and os.path.exists(data["pdf_file"]):
        return send_file(data["pdf_file"], as_attachment=True)

    # Fallback to most recent PDF
    pdfs = sorted(glob.glob("reports/*.pdf"), reverse=True)
    if pdfs:
        return send_file(pdfs[0], as_attachment=True)
    return "No report found.", 404


@app.route("/history")
def history():
    files = sorted(glob.glob("reports/*.json"), reverse=True)
    scans = []
    for f in files[:20]:
        try:
            with open(f) as fp:
                data = json.load(fp)
                scans.append({
                    "subject": data["parsed"]["subject"] or "(no subject)",
                    "from": data["parsed"]["from"],
                    "timestamp": data["timestamp"],
                    "verdict": data["analysis"]["verdict"],
                    "verdict_color": data["analysis"]["verdict_color"],
                    "risk_score": data["analysis"]["risk_score"],
                    "file": f
                })
        except Exception:
            pass
    return render_template("history.html", scans=scans)


if __name__ == "__main__":
    print("=" * 60)
    print("  PHISHING EMAIL ANALYZER — Web Interface")
    print("  Open http://127.0.0.1:5001 in your browser")
    print("=" * 60)
    app.run(debug=True, port=5001)