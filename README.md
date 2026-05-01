# SentinelShield — WAF Intrusion Detection System

A realistic, hands-on Web Application Firewall simulation for learning intrusion detection, request inspection, and alert generation.

---

## Project Structure

```
sentinelshield/
├── app.py               ← Flask app: routes, WAF middleware, API
├── detector.py          ← Core detection engine (rules + rate limiter)
├── logger.py            ← Structured JSON logger + stats
├── requirements.txt     ← Python dependencies
├── templates/
│   └── dashboard.html   ← Full interactive dashboard UI
├── logs/
│   └── sentinelshield.log  ← Auto-created on first run
└── README.md
```

---

## Setup & Running

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the app

```bash
python app.py
```

App starts at: **http://127.0.0.1:5000**

### 3. Open the dashboard

Visit **http://127.0.0.1:5000/dashboard** in your browser.

---

## API Endpoints

| Method | Endpoint       | Description                                          |
|--------|----------------|------------------------------------------------------|
| GET    | `/dashboard`   | Main UI dashboard                                    |
| GET    | `/test`        | WAF inspection endpoint (GET with params)            |
| POST   | `/test`        | WAF inspection endpoint (POST with body)             |
| POST   | `/simulate`    | Simulate a request via JSON body                     |
| GET    | `/api/logs`    | Fetch recent log entries (`?limit=N`)                |
| GET    | `/api/stats`   | Aggregate statistics (threat counts, top IPs, etc.)  |
| POST   | `/api/seed`    | Inject demo attack data for testing                  |
| POST   | `/api/clear`   | Clear all logs                                       |

---

## Testing with curl

### Normal request (should be ALLOWED)
```bash
curl "http://127.0.0.1:5000/test?user=student&page=home"
```

### SQL Injection (should be BLOCKED)
```bash
curl "http://127.0.0.1:5000/test?user=admin%27+OR+%271%27%3D%271"
```

### XSS Attack (should be BLOCKED)
```bash
curl "http://127.0.0.1:5000/test?q=%3Cscript%3Ealert(1)%3C/script%3E"
```

### LFI / Path Traversal (should be BLOCKED)
```bash
curl "http://127.0.0.1:5000/test?file=../../../../etc/passwd"
```

### Command Injection (should be BLOCKED)
```bash
curl "http://127.0.0.1:5000/test?cmd=ls+-la+|+cat+/etc/passwd"
```

### POST with malicious body
```bash
curl -X POST http://127.0.0.1:5000/test \
  -d "username=admin'--&password=x"
```

### Simulate brute-force (rate limit triggers after 20 req/30s)
```bash
for i in {1..25}; do
  curl -s "http://127.0.0.1:5000/test?login=attempt$i" > /dev/null
done
```

### Simulate a custom request via JSON
```bash
curl -X POST http://127.0.0.1:5000/simulate \
  -H "Content-Type: application/json" \
  -d '{"ip":"10.0.0.1","method":"POST","path":"/login","body":"username=admin OR 1=1"}'
```

---

## Detection Rules

| Category             | Examples Detected                                              |
|----------------------|----------------------------------------------------------------|
| SQL_INJECTION        | `' OR '1'='1`, `UNION SELECT`, `DROP TABLE`, encoded variants |
| XSS                  | `<script>`, `onerror=`, `javascript:`, `<svg onload=`         |
| LFI                  | `../../../`, `php://filter`, `/etc/passwd`, `boot.ini`        |
| COMMAND_INJECTION    | `; cat`, `| whoami`, backtick execution, `$()` subshell       |
| DIRECTORY_TRAVERSAL  | `../../`, double-encoded `%252e%252e`, Windows-style `..\\`   |

---

## Severity Levels

| Severity | Condition                              | Action  |
|----------|----------------------------------------|---------|
| CLEAN    | No threats, no rate limit exceeded     | ALLOWED |
| LOW      | Rate limit exceeded, no threats        | BLOCKED |
| MEDIUM   | 1 threat category detected             | BLOCKED |
| HIGH     | 2+ threat categories detected          | BLOCKED |
| CRITICAL | Rate limit exceeded AND threats found  | BLOCKED |

---

## Dashboard Features

- **Live stat cards** — Total requests, blocked, allowed, detection rate
- **Severity donut chart** — Visual breakdown by severity level
- **Threat category bars** — Which attack types are most common
- **Top offending IPs** — Ranked by request count with visual bar
- **Request simulator** — Send test payloads directly from the UI
- **Quick payload buttons** — One-click SQL, XSS, LFI, Cmd, Clean payloads
- **Filterable log table** — Filter by All / Critical / High / Medium / Blocked
- **Seed demo data** — Instantly populate with realistic attack scenarios
- **Auto-refresh** — Dashboard updates every 10 seconds

---

## How Detection Works

1. Incoming request → `inspect_request()` in `detector.py`
2. All parts (URL, params, headers, body) joined into one string
3. Each of the 5 rule categories checked using compiled regex patterns
4. Rate limiter checks the source IP against a 30-second sliding window
5. Severity calculated from threat count + rate limit status
6. Result logged via `write_log()` in `logger.py`
7. Response returned: `200 ALLOWED` or `403 BLOCKED`

---

## Practical Exercise Suggestions

1. Add a new rule category (e.g. `SSRF`, `XXE`, `OPEN_REDIRECT`)
2. Tune the rate limiter threshold and observe behavior
3. Test URL-encoded payloads and see if they bypass detection
4. Add a custom header-based detection rule
5. Export the log file and analyze it in Excel/Python
