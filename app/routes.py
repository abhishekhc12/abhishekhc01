import os
import tempfile
from typing import Dict, Any, List
from flask import Blueprint, current_app, render_template, request, redirect, url_for, flash

from .scanners.hash_scanner import compute_hashes, get_file_metadata
from .scanners.yara_scanner import run_yara_rules
from .scanners.clamav_scanner import run_clamav_scan
from .services.virustotal import query_virustotal


bp = Blueprint("main", __name__)


@bp.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        uploaded = request.files.get("file")
        if not uploaded or uploaded.filename == "":
            flash("Please select a file to upload.")
            return redirect(url_for("main.index"))

        # Save to a secure temp file inside uploads
        upload_dir = os.path.abspath(current_app.config["UPLOAD_FOLDER"])
        os.makedirs(upload_dir, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(prefix="scan_", dir=upload_dir)
        os.close(fd)
        uploaded.save(temp_path)

        try:
            results: Dict[str, Any] = {}

            # Metadata + Hashes
            results["metadata"] = get_file_metadata(temp_path, original_name=uploaded.filename)
            results["hashes"] = compute_hashes(temp_path)

            # YARA
            yara_matches: List[Dict[str, Any]] = run_yara_rules(
                temp_path, current_app.config["RULES_FOLDER"]
            )
            results["yara"] = {
                "enabled": yara_matches is not None,
                "matches": yara_matches or [],
            }

            # ClamAV
            clamav_result = run_clamav_scan(temp_path)
            results["clamav"] = clamav_result

            # VirusTotal (optional)
            vt_resp = query_virustotal(results["hashes"].get("sha256"))
            results["virustotal"] = vt_resp

            # Compute overall verdict
            verdict = {
                "level": "safe",  # safe | suspicious | malicious | unknown
                "label": "No issues detected",
                "reasons": [],
            }

            # ClamAV strong signal
            if clamav_result.get("available") and clamav_result.get("infected") is True:
                verdict["level"] = "malicious"
                verdict["label"] = "Malicious (ClamAV)"
                verdict["reasons"].append("ClamAV reported infection")

            # VirusTotal signal
            if vt_resp.get("enabled") and vt_resp.get("found"):
                stats = vt_resp.get("stats", {}) or {}
                malicious = int(stats.get("malicious", 0))
                suspicious = int(stats.get("suspicious", 0))
                if malicious > 0:
                    verdict["level"] = "malicious"
                    verdict["label"] = f"Malicious ({malicious} engines)"
                    verdict["reasons"].append(f"VirusTotal: {malicious} malicious detections")
                elif suspicious > 0 and verdict["level"] != "malicious":
                    verdict["level"] = "suspicious"
                    verdict["label"] = f"Suspicious ({suspicious} engines)"
                    verdict["reasons"].append(f"VirusTotal: {suspicious} suspicious detections")

            # YARA heuristic (weaker than VT/ClamAV)
            if results["yara"].get("enabled") and results["yara"].get("matches"):
                if verdict["level"] == "safe":
                    verdict["level"] = "suspicious"
                    verdict["label"] = "Suspicious (YARA match)"
                verdict["reasons"].append("YARA rule(s) matched")

            if not verdict["reasons"] and verdict["level"] == "safe":
                verdict["reasons"].append("No engines or rules flagged the file")

            results["verdict"] = verdict

            # Counts summary
            vt_malicious = 0
            if vt_resp.get("enabled") and vt_resp.get("found"):
                vt_malicious = int((vt_resp.get("stats") or {}).get("malicious", 0))
            clam_detections = clamav_result.get("detections") or 0
            results["counts"] = {
                "virustotal_malicious": vt_malicious,
                "clamav_detections": clam_detections,
                "total_detected": vt_malicious + clam_detections,
            }

            return render_template("result.html", results=results)
        finally:
            try:
                os.remove(temp_path)
            except OSError:
                pass

    return render_template("index.html")


