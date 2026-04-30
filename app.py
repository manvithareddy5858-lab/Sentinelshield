"""
SentinelShield - Flask Application
Main entry point: WAF middleware, API routes, dashboard serving.
"""

from flask import Flask, request, jsonify, render_template, abort
from detector import inspect_request
from logger import write_log, read_logs, get_stats, clear_logs
import json

app = Flask(__name__)

# ─────────────────────────────────────────────
#  Helper: get real IP
# ─────────────────────────────────────────────

def get_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1").split(",")[0].strip()


# ─────────────────────────────────────────────
#  WAF Middleware — applied to /test endpoint
# ─────────────────────────────────────────────

@app.route("/test", methods=["GET", "POST"])
def waf_test():
    """
    Main WAF inspection endpoint.
    Students submit requests here to see detection in action.
    """
    ip = get_ip()
    method = request.method
    path = request.full_path or "/"
    params = {k: v for k, v in request.args.items()}
    headers = dict(request.headers)
    body = request.get_data(as_text=True) or ""

    result = inspect_request(ip, method, path, params, headers, body)

    # Log every request
    write_log(result)

    if result["allowed"]:
        return jsonify({
            "status": "ALLOWED",
            "message": "✅ Request passed WAF inspection.",
            "severity": result["severity"],
            "ip": ip,
            "timestamp": result["timestamp"],
        }), 200
    else:
        return jsonify({
            "status": "BLOCKED",
            "message": "🚫 Request blocked by SentinelShield WAF.",
            "severity": result["severity"],
            "threats": result["threats"],
            "matched": result["matched_patterns"],
            "rate_limit": result["rate_limit"],
            "ip": ip,
            "timestamp": result["timestamp"],
        }), 403


# ─────────────────────────────────────────────
#  Manual Simulation Endpoint
# ─────────────────────────────────────────────

@app.route("/simulate", methods=["POST"])
def simulate():
    """
    Accepts a JSON body describing a simulated request.
    Used by the dashboard's simulation panel.
    """
    data = request.get_json(force=True) or {}
    ip = data.get("ip", "10.0.0.1")
    method = data.get("method", "GET")
    path = data.get("path", "/")
    params = data.get("params", {})
    headers = data.get("headers", {})
    body = data.get("body", "")

    result = inspect_request(ip, method, path, params, headers, body)
    write_log(result)
    return jsonify(result)


# ─────────────────────────────────────────────
#  API Routes for Dashboard
# ─────────────────────────────────────────────

@app.route("/api/logs")
def api_logs():
    limit = int(request.args.get("limit", 100))
    return jsonify(read_logs(limit=limit))


@app.route("/api/stats")
def api_stats():
    return jsonify(get_stats())


@app.route("/api/clear", methods=["POST"])
def api_clear():
    clear_logs()
    return jsonify({"status": "ok", "message": "Logs cleared."})


# ─────────────────────────────────────────────
#  Seed Demo Data
# ─────────────────────────────────────────────

@app.route("/api/seed", methods=["POST"])
def api_seed():
    """Inject realistic demo attack logs for dashboard testing."""
    demo_requests = [
        # SQL Injection attempts
        ("192.168.1.10", "GET", "/login", {"user": "admin' OR '1'='1", "pass": "x"}, {}, ""),
        ("192.168.1.10", "GET", "/search", {"q": "1 UNION SELECT username,password FROM users--"}, {}, ""),
        ("10.0.0.55",    "POST", "/login", {}, {}, "username=admin'--&password=x"),
        ("10.0.0.55",    "GET", "/products", {"id": "1; DROP TABLE products--"}, {}, ""),
        # XSS attempts
        ("172.16.0.4",   "GET", "/comment", {"msg": "<script>alert('XSS')</script>"}, {}, ""),
        ("172.16.0.4",   "GET", "/search",  {"q": "<img src=x onerror=document.cookie>"}, {}, ""),
        ("203.0.113.5",  "POST", "/feedback",{}, {}, "text=<svg onload=alert(1)>"),
        # LFI / Path Traversal
        ("10.10.10.1",   "GET", "/file",    {"name": "../../../../etc/passwd"}, {}, ""),
        ("10.10.10.1",   "GET", "/include", {"page": "php://filter/convert.base64-encode/resource=index.php"}, {}, ""),
        # Command Injection
        ("45.33.32.156",  "GET", "/ping",   {"host": "127.0.0.1; cat /etc/passwd"}, {}, ""),
        ("45.33.32.156",  "GET", "/exec",   {"cmd": "ls -la | grep passwd"}, {}, ""),
        ("45.33.32.156",  "GET", "/exec",   {"cmd": "`whoami`"}, {}, ""),
        # Normal requests
        ("192.168.1.50",  "GET", "/home",   {}, {}, ""),
        ("192.168.1.51",  "GET", "/about",  {}, {}, ""),
        ("192.168.1.52",  "POST", "/login", {}, {}, "username=student&password=pass123"),
        ("192.168.1.53",  "GET", "/products",{"id": "42"}, {}, ""),
    ]

    # Simulate brute-force from one IP
    for i in range(25):
        demo_requests.append(("99.88.77.66", "POST", "/login", {}, {}, f"username=admin&password=attempt{i}"))

    for (ip, method, path, params, headers, body) in demo_requests:
        result = inspect_request(ip, method, path, params, headers, body)
        write_log(result)

    return jsonify({"status": "ok", "seeded": len(demo_requests)})


# ─────────────────────────────────────────────
#  Dashboard
# ─────────────────────────────────────────────

@app.route("/")
@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


if __name__ == "__main__":
    app.run(debug=True, port=5000)
