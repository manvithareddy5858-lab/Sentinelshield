"""
tests/test_sentinelshield.py
Pytest suite for SentinelShield — detector, logger, and Flask API routes.
Run with: pytest tests/ -v
"""
import sys, os, json, pytest
 
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
 
import app as app_module
from detector import inspect_request, RateLimiter, RULES, _compiled_rules
from logger import write_log, read_logs, get_stats, clear_logs
 
 
# ── Fixtures ──────────────────────────────────────────────────────────────────
 
@pytest.fixture(autouse=True)
def clear_store():
    """Wipe the log store before every test for isolation."""
    clear_logs()
    yield
    clear_logs()
 
 
@pytest.fixture
def client():
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as c:
        yield c
 
 
# ── Detector: clean request ───────────────────────────────────────────────────
 
class TestCleanRequests:
    def test_clean_get_is_allowed(self):
        r = inspect_request("1.2.3.4", "GET", "/home", {}, {}, "")
        assert r["allowed"] is True
 
    def test_clean_severity_is_clean(self):
        r = inspect_request("1.2.3.4", "GET", "/about", {}, {}, "")
        assert r["severity"] == "CLEAN"
 
    def test_clean_has_no_threats(self):
        r = inspect_request("1.2.3.4", "GET", "/products", {"id": "42"}, {}, "")
        assert r["threats"] == []
 
    def test_clean_result_has_required_keys(self):
        r = inspect_request("1.2.3.4", "GET", "/", {}, {}, "")
        for key in ("allowed", "threats", "matched_patterns", "rate_limit",
                    "severity", "timestamp", "ip", "method", "path"):
            assert key in r
 
    def test_clean_login_allowed(self):
        r = inspect_request("1.2.3.4", "POST", "/login", {},
                             {}, "username=alice&password=pass123")
        assert r["allowed"] is True
 
 
# ── Detector: SQL injection ───────────────────────────────────────────────────
 
class TestSQLInjection:
    def test_or_1_equals_1_blocked(self):
        r = inspect_request("1.2.3.4", "GET", "/login",
                             {"user": "admin' OR '1'='1", "pass": "x"}, {}, "")
        assert not r["allowed"]
        assert "SQL_INJECTION" in r["threats"]
 
    def test_union_select_blocked(self):
        r = inspect_request("1.2.3.4", "GET", "/search",
                             {"q": "1 UNION SELECT username,password FROM users--"}, {}, "")
        assert "SQL_INJECTION" in r["threats"]
 
    def test_drop_table_in_body_blocked(self):
        r = inspect_request("1.2.3.4", "POST", "/login", {},
                             {}, "username=admin'--&password=x; DROP TABLE users")
        assert "SQL_INJECTION" in r["threats"]
 
    def test_select_from_blocked(self):
        r = inspect_request("1.2.3.4", "GET", "/",
                             {"q": "SELECT * FROM users"}, {}, "")
        assert "SQL_INJECTION" in r["threats"]
 
 
# ── Detector: XSS ────────────────────────────────────────────────────────────
 
class TestXSS:
    def test_script_tag_blocked(self):
        r = inspect_request("1.2.3.4", "GET", "/comment",
                             {"msg": "<script>alert('XSS')</script>"}, {}, "")
        assert not r["allowed"]
        assert "XSS" in r["threats"]
 
    def test_img_onerror_blocked(self):
        r = inspect_request("1.2.3.4", "GET", "/search",
                             {"q": "<img src=x onerror=document.cookie>"}, {}, "")
        assert "XSS" in r["threats"]
 
    def test_svg_onload_in_body_blocked(self):
        r = inspect_request("1.2.3.4", "POST", "/feedback", {},
                             {}, "text=<svg onload=alert(1)>")
        assert "XSS" in r["threats"]
 
    def test_javascript_scheme_blocked(self):
        r = inspect_request("1.2.3.4", "GET", "/",
                             {"url": "javascript:alert(1)"}, {}, "")
        assert "XSS" in r["threats"]
 
 
# ── Detector: LFI / Path traversal ───────────────────────────────────────────
 
class TestLFI:
    def test_etc_passwd_blocked(self):
        r = inspect_request("1.2.3.4", "GET", "/file",
                             {"name": "../../../../etc/passwd"}, {}, "")
        assert not r["allowed"]
        assert "LFI" in r["threats"]
 
    def test_php_filter_blocked(self):
        r = inspect_request("1.2.3.4", "GET", "/include",
                             {"page": "php://filter/convert.base64-encode/resource=index.php"}, {}, "")
        assert "LFI" in r["threats"]
 
    def test_dotdot_slash_path_blocked(self):
        r = inspect_request("1.2.3.4", "GET", "/../../../etc/passwd", {}, {}, "")
        assert "LFI" in r["threats"] or "DIRECTORY_TRAVERSAL" in r["threats"]
 
 
# ── Detector: Command injection ───────────────────────────────────────────────
 
class TestCommandInjection:
    def test_semicolon_cat_blocked(self):
        r = inspect_request("1.2.3.4", "GET", "/ping",
                             {"host": "127.0.0.1; cat /etc/passwd"}, {}, "")
        assert not r["allowed"]
        assert "COMMAND_INJECTION" in r["threats"]
 
    def test_pipe_whoami_blocked(self):
        r = inspect_request("1.2.3.4", "GET", "/exec",
                             {"cmd": "echo hello | bash"}, {}, "")
        assert "COMMAND_INJECTION" in r["threats"]
 
    def test_backtick_execution_blocked(self):
        r = inspect_request("1.2.3.4", "GET", "/exec",
                             {"cmd": "`whoami`"}, {}, "")
        assert "COMMAND_INJECTION" in r["threats"]
 
    def test_subshell_blocked(self):
        r = inspect_request("1.2.3.4", "GET", "/exec",
                             {"cmd": "$(id)"}, {}, "")
        assert "COMMAND_INJECTION" in r["threats"]
 
 
# ── Detector: multiple threats → HIGH severity ────────────────────────────────
 
class TestSeverityEscalation:
    def test_two_threats_is_high(self):
        r = inspect_request("1.2.3.4", "GET", "/file",
                             {"q": "<script>alert(1)</script>",
                              "name": "../../../../etc/passwd"}, {}, "")
        assert r["severity"] in ("HIGH", "CRITICAL")
 
    def test_single_threat_is_medium(self):
        r = inspect_request("5.6.7.8", "GET", "/search",
                             {"q": "<script>alert(1)</script>"}, {}, "")
        assert r["severity"] == "MEDIUM"
 
    def test_clean_is_clean(self):
        r = inspect_request("9.9.9.9", "GET", "/home", {}, {}, "")
        assert r["severity"] == "CLEAN"
 
 
# ── Detector: rate limiter ────────────────────────────────────────────────────
 
class TestRateLimiter:
    def test_under_limit_not_exceeded(self):
        rl = RateLimiter(max_requests=5, window_seconds=30)
        for _ in range(4):
            result = rl.check("1.2.3.4")
        assert not result["exceeded"]
 
    def test_over_limit_exceeded(self):
        rl = RateLimiter(max_requests=5, window_seconds=30)
        for _ in range(6):
            result = rl.check("1.2.3.4")
        assert result["exceeded"]
 
    def test_different_ips_independent(self):
        rl = RateLimiter(max_requests=3, window_seconds=30)
        for _ in range(4):
            rl.check("1.1.1.1")
        result_b = rl.check("2.2.2.2")
        assert not result_b["exceeded"]
 
    def test_rate_limit_triggers_low_severity(self):
        # Brute-force with a clean payload triggers LOW, not CLEAN
        rl = RateLimiter(max_requests=3, window_seconds=30)
        from detector import rate_limiter as global_rl
        # Use fresh limiter with low threshold
        original_max = global_rl.max_requests
        global_rl.max_requests = 3
        try:
            for _ in range(25):
                r = inspect_request("brute.force.ip", "POST", "/login",
                                    {}, {}, "username=admin&password=wrong")
            assert r["severity"] in ("LOW", "CRITICAL")  # CRITICAL if threats too
        finally:
            global_rl.max_requests = original_max
 
    def test_rate_limit_plus_threats_is_critical(self):
        from detector import rate_limiter as global_rl
        original_max = global_rl.max_requests
        global_rl.max_requests = 3
        try:
            for _ in range(10):
                r = inspect_request("evil.ip", "GET", "/search",
                                    {"q": "<script>alert(1)</script>"}, {}, "")
            assert r["severity"] == "CRITICAL"
        finally:
            global_rl.max_requests = original_max
 
 
# ── Logger ────────────────────────────────────────────────────────────────────
 
class TestLogger:
    def _make_entry(self, allowed=True, severity="CLEAN", ip="1.2.3.4",
                    threats=None, method="GET", path="/"):
        return {
            "allowed": allowed, "severity": severity, "ip": ip,
            "threats": threats or [], "matched_patterns": [],
            "method": method, "path": path,
            "rate_limit": {"exceeded": False, "count": 1, "limit": 20, "window": 30},
            "timestamp": "2026-01-01T00:00:00Z"
        }
 
    def test_write_and_read(self):
        write_log(self._make_entry())
        logs = read_logs()
        assert len(logs) == 1
 
    def test_read_returns_newest_first(self):
        write_log(self._make_entry(ip="1.1.1.1"))
        write_log(self._make_entry(ip="2.2.2.2"))
        logs = read_logs()
        assert logs[0]["ip"] == "2.2.2.2"
 
    def test_read_limit_respected(self):
        for i in range(20):
            write_log(self._make_entry(ip=f"10.0.0.{i}"))
        logs = read_logs(limit=5)
        assert len(logs) == 5
 
    def test_stats_total_count(self):
        for _ in range(5):
            write_log(self._make_entry())
        stats = get_stats()
        assert stats["total"] == 5
 
    def test_stats_blocked_count(self):
        write_log(self._make_entry(allowed=True))
        write_log(self._make_entry(allowed=False, severity="MEDIUM",
                                   threats=["SQL_INJECTION"]))
        write_log(self._make_entry(allowed=False, severity="HIGH",
                                   threats=["XSS"]))
        stats = get_stats()
        assert stats["blocked"] == 2
        assert stats["allowed"] == 1
 
    def test_stats_threat_counts(self):
        write_log(self._make_entry(allowed=False, threats=["SQL_INJECTION"]))
        write_log(self._make_entry(allowed=False, threats=["SQL_INJECTION", "XSS"]))
        stats = get_stats()
        assert stats["threat_counts"]["SQL_INJECTION"] == 2
        assert stats["threat_counts"]["XSS"] == 1
 
    def test_stats_detection_rate(self):
        for _ in range(4):
            write_log(self._make_entry(allowed=False, threats=["XSS"]))
        write_log(self._make_entry(allowed=True))
        stats = get_stats()
        assert stats["detection_rate"] == 80.0
 
    def test_stats_top_ips(self):
        for _ in range(3):
            write_log(self._make_entry(ip="evil.ip"))
        write_log(self._make_entry(ip="normal.ip"))
        stats = get_stats()
        top_ip = stats["top_ips"][0]
        assert top_ip[0] == "evil.ip"
        assert top_ip[1] == 3
 
    def test_clear_empties_store(self):
        write_log(self._make_entry())
        clear_logs()
        assert read_logs() == []
 
    def test_memory_cap_at_2000(self):
        for i in range(2100):
            write_log(self._make_entry(ip=f"1.1.{i//256}.{i%256}"))
        logs = read_logs(limit=9999)
        assert len(logs) <= 2000
 
 
# ── Flask API routes ──────────────────────────────────────────────────────────
 
class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        r = client.get("/health")
        assert r.status_code == 200
 
    def test_health_returns_ok(self, client):
        r = client.get("/health")
        data = r.get_json()
        assert data["status"] == "ok"
 
    def test_health_has_service_name(self, client):
        r = client.get("/health")
        data = r.get_json()
        assert "service" in data
 
 
class TestWAFEndpoint:
    def test_clean_request_returns_200(self, client):
        r = client.get("/test?page=home")
        assert r.status_code == 200
 
    def test_clean_request_status_allowed(self, client):
        r = client.get("/test?page=home")
        assert r.get_json()["status"] == "ALLOWED"
 
    def test_sql_injection_returns_403(self, client):
        r = client.get("/test?q=1+UNION+SELECT+*+FROM+users--")
        assert r.status_code == 403
 
    def test_sql_injection_status_blocked(self, client):
        r = client.get("/test?q=1+UNION+SELECT+*+FROM+users--")
        assert r.get_json()["status"] == "BLOCKED"
 
    def test_xss_returns_403(self, client):
        r = client.get("/test?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
        assert r.status_code == 403
 
    def test_blocked_response_has_threats_field(self, client):
        r = client.get("/test?q=1+UNION+SELECT+*+FROM+users--")
        data = r.get_json()
        assert "threats" in data
        assert len(data["threats"]) > 0
 
    def test_waf_post_body_inspected(self, client):
        r = client.post("/test", data="username=admin'--&password=x",
                        content_type="application/x-www-form-urlencoded")
        assert r.status_code == 403
 
 
class TestSimulateEndpoint:
    def test_simulate_clean(self, client):
        r = client.post("/simulate",
                        json={"ip": "clean.test.sim", "method": "GET", "path": "/home"})
        assert r.status_code == 200
        assert r.get_json()["allowed"] is True
 
    def test_simulate_sql_injection(self, client):
        r = client.post("/simulate", json={
            "ip": "5.5.5.5", "method": "GET", "path": "/search",
            "params": {"q": "1 UNION SELECT * FROM users--"}
        })
        data = r.get_json()
        assert data["allowed"] is False
        assert "SQL_INJECTION" in data["threats"]
 
    def test_simulate_logs_entry(self, client):
        client.post("/simulate",
                    json={"ip": "9.9.9.9", "method": "GET", "path": "/test"})
        logs = read_logs()
        assert any(e["ip"] == "9.9.9.9" for e in logs)
 
 
class TestAPILogsEndpoint:
    def test_logs_returns_list(self, client):
        r = client.get("/api/logs")
        assert r.status_code == 200
        assert isinstance(r.get_json(), list)
 
    def test_logs_limit_param(self, client):
        # Seed 20 entries via simulate
        for i in range(20):
            client.post("/simulate",
                        json={"ip": f"1.2.3.{i}", "method": "GET", "path": "/"})
        r = client.get("/api/logs?limit=5")
        assert len(r.get_json()) <= 5
 
 
class TestAPIStatsEndpoint:
    def test_stats_returns_dict(self, client):
        r = client.get("/api/stats")
        assert r.status_code == 200
        data = r.get_json()
        assert isinstance(data, dict)
 
    def test_stats_has_required_keys(self, client):
        r = client.get("/api/stats")
        data = r.get_json()
        for key in ("total", "blocked", "allowed", "detection_rate",
                    "threat_counts", "severity_counts", "top_ips"):
            assert key in data, f"Missing key: {key}"
 
 
class TestSeedAndClearEndpoints:
    def test_seed_endpoint_adds_logs(self, client):
        client.post("/api/seed")
        r = client.get("/api/stats")
        assert r.get_json()["total"] > 0
 
    def test_clear_endpoint_empties_logs(self, client):
        client.post("/api/seed")
        client.post("/api/clear")
        r = client.get("/api/stats")
        assert r.get_json()["total"] == 0
 
 
class TestDashboardRoute:
    def test_dashboard_root_returns_200(self, client):
        r = client.get("/")
        assert r.status_code == 200
 
    def test_dashboard_route_returns_200(self, client):
        r = client.get("/dashboard")
        assert r.status_code == 200
