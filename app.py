"""
SentinelShield - Flask Application
Main entry point: WAF middleware, API routes, dashboard serving.
 
DEPLOYMENT FIXES applied:
- Added /health endpoint for Render health checks
- Use PORT env var so Render can bind on the right port
- debug=False in production (was True — caused Render startup crash)
- Gunicorn-compatible: no app.run() in production path
"""
 
import os
from flask import Flask, request, jsonify, render_template
from detector import inspect_request
from logger import write_log, read_logs, get_stats, clear_logs
 
app = Flask(__name__)
 
# ─────────────────────────────────────────────
# Demo data definition
# ─────────────────────────────────────────────
 
def _build_demo_requests():
    demo = [
        # SQL Injection
        ("192.168.1.10", "GET",  "/login",    {"user": "admin' OR '1'='1", "pass": "x"}, {}, ""),
        ("192.168.1.10", "GET",  "/search",   {"q": "1 UNION SELECT username,password FROM users--"}, {}, ""),
        ("10.0.0.55",    "POST", "/login",    {}, {}, "username=admin'--&password=x"),
        ("10.0.0.55",    "GET",  "/products", {"id": "1; DROP TABLE products--"}, {}, ""),
        # XSS
        ("172.16.0.4",   "GET",  "/comment",  {"msg": "<script>alert('XSS')</script>"}, {}, ""),
        ("172.16.0.4",   "GET",  "/search",   {"q": "<img src=x onerror=document.cookie>"}, {}, ""),
        ("203.0.113.5",  "POST", "/feedback", {}, {}, "text=<svg onload=alert(1)>"),
        # LFI / Path Traversal
        ("10.10.10.1",   "GET",  "/file",     {"name": "../../../../etc/passwd"}, {}, ""),
        ("10.10.10.1",   "GET",  "/include",  {"page": "php://filter/convert.base64-encode/resource=index.php"}, {}, ""),
        # Command Injection
        ("45.33.32.156",  "GET", "/ping",     {"host": "127.0.0.1; cat /etc/passwd"}, {}, ""),
        ("45.33.32.156",  "GET", "/exec",     {"cmd": "ls -la | grep passwd"}, {}, ""),
        ("45.33.32.156",  "GET", "/exec",     {"cmd": "`whoami`"}, {}, ""),
        # Normal / clean requests
        ("192.168.1.50", "GET",  "/home",     {}, {}, ""),
        ("192.168.1.51", "GET",  "/about",    {}, {}, ""),
        ("192.168.1.52", "POST", "/login",    {}, {}, "username=student&password=pass123"),
        ("192.168.1.53", "GET",  "/products", {"id": "42"}, {}, ""),
    ]
    # Brute-force simulation
    for i in range(25):
        demo.append(("99.88.77.66", "POST", "/login", {}, {}, f"username=admin&password=attempt{i}"))
    return demo
 
 
def _seed_data():
    """Populate in-memory log with demo attack data on boot."""
    for (ip, method, path, params, headers, body) in _build_demo_requests():
        result = inspect_request(ip, method, path, params, headers, body)
        write_log(result)
 
 
# Auto-seed so dashboard is never empty on first load
_seed_data()
 
 
# ─────────────────────────────────────────────
# Health check — required by Render
# ─────────────────────────────────────────────
 
@app.route("/health")
def health():
    """Render health check endpoint. Must return 200 for deploy to succeed."""
    return jsonify({"status": "ok", "service": "SentinelShield"}), 200
 
 
# ─────────────────────────────────────────────
# Helper: get real client IP
# ─────────────────────────────────────────────
 
def get_ip():
    return (
        request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1")
        .split(",")[0]
        .strip()
    )
 
 
# ─────────────────────────────────────────────
# WAF Middleware — /test endpoint
# ─────────────────────────────────────────────
 
@app.route("/test", methods=["GET", "POST"])
def waf_test():
    ip     = get_ip()
    method = request.method
    path   = request.full_path or "/"
    params = {k: v for k, v in request.args.items()}
    headers = dict(request.headers)
    body   = request.get_data(as_text=True) or ""
 
    result = inspect_request(ip, method, path, params, headers, body)
    write_log(result)
 
    if result["allowed"]:
        return jsonify({
            "status":    "ALLOWED",
            "message":   "✅ Request passed WAF inspection.",
            "severity":  result["severity"],
            "ip":        ip,
            "timestamp": result["timestamp"],
        }), 200
    else:
        return jsonify({
            "status":    "BLOCKED",
            "message":   "🚫 Request blocked by SentinelShield WAF.",
            "severity":  result["severity"],
            "threats":   result["threats"],
            "matched":   result["matched_patterns"],
            "rate_limit": result["rate_limit"],
            "ip":        ip,
            "timestamp": result["timestamp"],
        }), 403
 
 
# ─────────────────────────────────────────────
# Simulation endpoint
# ─────────────────────────────────────────────
 
@app.route("/simulate", methods=["POST"])
def simulate():
    data    = request.get_json(force=True) or {}
    ip      = data.get("ip", "10.0.0.1")
    method  = data.get("method", "GET")
    path    = data.get("path", "/")
    params  = data.get("params", {})
    headers = data.get("headers", {})
    body    = data.get("body", "")
 
    result = inspect_request(ip, method, path, params, headers, body)
    write_log(result)
    return jsonify(result)
 
 
# ─────────────────────────────────────────────
# API Routes for Dashboard
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
 
 
@app.route("/api/seed", methods=["POST"])
def api_seed():
    demo = _build_demo_requests()
    for (ip, method, path, params, headers, body) in demo:
        result = inspect_request(ip, method, path, params, headers, body)
        write_log(result)
    return jsonify({"status": "ok", "seeded": len(demo)})
 
 
# ─────────────────────────────────────────────
# Dashboard
# ─────────────────────────────────────────────
 
@app.route("/")
@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")
 
 
# ─────────────────────────────────────────────
# Entry point — local dev only
# Gunicorn does NOT call this block in production
# ─────────────────────────────────────────────
 
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    # debug=True only when running locally, never on Render
    debug = os.environ.get("FLASK_ENV", "production") != "production"
    app.run(debug=debug, host="0.0.0.0", port=port)
