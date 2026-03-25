"""
ECU XDF Generator — Flask web application.

Routes
  GET  /                      → main SPA
  POST /api/analyze           → upload .bin, return analysis JSON
  POST /api/generate          → receive XDF config JSON, download .xdf
  GET  /api/preview           → receive XDF config JSON (query), return XML string
  POST /api/checksum/calc     → calculate checksums for uploaded binary
  POST /api/checksum/patch    → write corrected checksum into binary, download patched .bin
  GET  /api/profiles          → return ECU profile list
"""

import base64
from io import BytesIO

from flask import Flask, jsonify, render_template, request, send_file

from xdf.analyzer import BinaryAnalyzer
from xdf.checksum import ChecksumCalculator
from xdf.generator import XDFGenerator

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024  # 32 MB upload limit


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_int_addr(value, default: int = 0) -> int:
    """Accept hex string or int."""
    if value is None:
        return default
    if isinstance(value, int):
        return value
    s = str(value).strip()
    return int(s, 16) if s.lower().startswith("0x") else int(s)


# ---------------------------------------------------------------------------
# Main page
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# Binary analysis
# ---------------------------------------------------------------------------

@app.route("/api/analyze", methods=["POST"])
def analyze():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "No file selected"}), 400

    data = f.read()
    if not data:
        return jsonify({"error": "Uploaded file is empty"}), 400

    try:
        result = BinaryAnalyzer(data).analyze()
        # Also send back base64 so the frontend can use it for checksum ops
        result["file_b64"] = base64.b64encode(data).decode()
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# XDF generation
# ---------------------------------------------------------------------------

@app.route("/api/generate", methods=["POST"])
def generate():
    config = request.get_json()
    if not config:
        return jsonify({"error": "No configuration provided"}), 400

    try:
        xdf_xml = XDFGenerator(config).generate()
        filename = (config.get("title", "generated") or "generated").replace(" ", "_") + ".xdf"
        output = BytesIO(xdf_xml.encode("utf-8"))
        return send_file(
            output,
            mimetype="application/xml",
            as_attachment=True,
            download_name=filename,
        )
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/preview", methods=["POST"])
def preview():
    """Return XDF XML as a string (for in-browser preview)."""
    config = request.get_json()
    if not config:
        return jsonify({"error": "No configuration provided"}), 400
    try:
        xdf_xml = XDFGenerator(config).generate()
        return jsonify({"xml": xdf_xml})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# Checksum tools
# ---------------------------------------------------------------------------

@app.route("/api/checksum/calc", methods=["POST"])
def checksum_calc():
    payload = request.get_json()
    if not payload:
        return jsonify({"error": "No data provided"}), 400

    try:
        if "file_data" in payload:
            binary = base64.b64decode(payload["file_data"])
        elif "hex" in payload:
            binary = bytes.fromhex(payload["hex"].replace(" ", "").replace("\n", ""))
        else:
            return jsonify({"error": "Provide file_data (base64) or hex string"}), 400

        r_start = _parse_int_addr(payload.get("region_start", 0))
        r_end   = _parse_int_addr(payload.get("region_end",   len(binary)))

        calc = ChecksumCalculator(binary)
        result = calc.calculate_all(r_start, r_end)
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/checksum/patch", methods=["POST"])
def checksum_patch():
    payload = request.get_json()
    if not payload:
        return jsonify({"error": "No data provided"}), 400

    try:
        algorithm = payload.get("algorithm", "subaru")
        patched, info = ChecksumCalculator(b"").patch(algorithm, payload)
        output = BytesIO(patched)
        return send_file(
            output,
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name="patched.bin",
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# ECU profiles
# ---------------------------------------------------------------------------

@app.route("/api/profiles", methods=["GET"])
def profiles():
    from xdf.profiles import ECU_PROFILES
    return jsonify(ECU_PROFILES)


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import os
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug, host="0.0.0.0", port=5000)
