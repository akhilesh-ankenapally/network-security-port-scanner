"""
Network Security Port Scanner - Web Application Backend
Flask API server providing scan coordination and interface serving.
"""

import os
import re
from flask import Flask, jsonify, render_template, request
from scanner import resolve_target, scan_ports

app = Flask(__name__)

# Predefined common port profiles for quick 3-minute demonstrations
PORT_PRESETS = {
    "web": [80, 443, 8000, 8080, 8443, 8888],
    "top20": [21, 22, 23, 25, 53, 80, 110, 119, 123, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432],
    "database": [1433, 1521, 3306, 5432, 6379, 27017],
    "remote": [22, 23, 3389, 5900],
}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """
    Executes a port scan against a specified target and port selection.
    """
    payload = request.get_json(silent=True) or {}

    target = payload.get("target", "").strip()
    if not target:
        return jsonify({
            "success": False,
            "error": "Target IP address or hostname is required."
        }), 400

    # Validate and resolve target IP
    ip, err = resolve_target(target)
    if err:
        return jsonify({
            "success": False,
            "error": err
        }), 400

    mode = payload.get("mode", "range")
    ports_to_scan = []

    try:
        if mode == "preset":
            preset_name = payload.get("preset", "top20")
            ports_to_scan = PORT_PRESETS.get(preset_name, PORT_PRESETS["top20"])
        elif mode == "custom":
            custom_input = payload.get("custom_ports", "")
            if isinstance(custom_input, list):
                ports_to_scan = [int(p) for p in custom_input if 1 <= int(p) <= 65535]
            else:
                tokens = re.split(r"[,;\s]+", str(custom_input).strip())
                for t in tokens:
                    if not t:
                        continue
                    if "-" in t:
                        start_str, end_str = t.split("-", 1)
                        s, e = int(start_str), int(end_str)
                        if s > e:
                            s, e = e, s
                        ports_to_scan.extend(range(max(1, s), min(65535, e) + 1))
                    else:
                        p = int(t)
                        if 1 <= p <= 65535:
                            ports_to_scan.append(p)
        else:
            # Range mode (default)
            start_port = int(payload.get("start_port", 20))
            end_port = int(payload.get("end_port", 100))

            if start_port < 1 or start_port > 65535 or end_port < 1 or end_port > 65535:
                return jsonify({
                    "success": False,
                    "error": "Port numbers must be between 1 and 65535."
                }), 400

            if start_port > end_port:
                start_port, end_port = end_port, start_port

            # Limit to 1024 ports per scan to ensure demo speed and prevent resource exhaustion
            if (end_port - start_port + 1) > 1024:
                return jsonify({
                    "success": False,
                    "error": "For quick academic demonstrations, maximum allowed range per scan is 1024 ports."
                }), 400

            ports_to_scan = list(range(start_port, end_port + 1))

    except ValueError:
        return jsonify({
            "success": False,
            "error": "Invalid port number format. Please check your port inputs."
        }), 400

    # Deduplicate and sort
    ports_to_scan = sorted(list(set(ports_to_scan)))
    if not ports_to_scan:
        return jsonify({
            "success": False,
            "error": "No valid ports specified to scan."
        }), 400

    # Parse timeout
    try:
        timeout = float(payload.get("timeout", 0.4))
        timeout = max(0.1, min(timeout, 2.0))
    except (ValueError, TypeError):
        timeout = 0.4

    # Run multithreaded scan
    scan_data = scan_ports(ip, ports_to_scan, timeout=timeout)

    return jsonify({
        "success": True,
        "target": target,
        "ip": ip,
        "total_ports": scan_data["total_ports"],
        "open_count": scan_data["open_count"],
        "closed_count": scan_data["closed_count"],
        "duration_seconds": scan_data["duration_seconds"],
        "results": scan_data["results"],
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5055))
    print(f"\n=======================================================")
    print(f" Network Security Port Scanner Started!")
    print(f" Access Web Interface at: http://127.0.0.1:{port}")
    print(f"=======================================================\n")
    app.run(host="127.0.0.1", port=port, debug=False)
