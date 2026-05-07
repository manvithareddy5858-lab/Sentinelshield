# SentinelShield — Intrusion Detection & Web Application Firewall

A lightweight, realistic Web Application Firewall (WAF) simulator built for practical cybersecurity learning. SentinelShield inspects HTTP requests, detects attack signatures, monitors traffic patterns, logs events, and visualises everything through a real-time dashboard.

**Live Demo:** https://sentinelshield-1-r14u.onrender.com

---

## What It Does

SentinelShield mimics the core behaviour of a production WAF. Every request that passes through it is:

1. Disassembled into URL path, query parameters, headers, and body
2. Scanned against a library of regex-based attack signatures
3. Checked against a rate limiter (sliding 30-second window per IP)
4. Classified with a severity level (CLEAN → LOW → MEDIUM → HIGH → CRITICAL)
5. Logged as a structured JSON entry
6. Reflected immediately on the live dashboard

---

## Attack Categories Detected

| Category | Example Payload |
|---|---|
| SQL Injection | `admin' OR '1'='1`, `UNION SELECT username FROM users--` |
| Cross-Site Scripting | `<script>alert(1)</script>`, `<img onerror=document.cookie>` |
| Local File Inclusion | `../../../../etc/passwd`, `php://filter/convert.base64-encode/...` |
| Command Injection | `; cat /etc/passwd`, `` `whoami` ``, `$(uname -a)` |
| Directory Traversal | `../../../`, `%2e%2e%2f%2e%2e%2f`, double-encoded variants |

---

## Project Structure

```
sentinelshield/
├── app.py              # Flask app — routes, WAF middleware, API endpoints
├── detector.py         # Detection engine — regex rules + rate limiter
├── logger.py           # In-memory log store + statistics aggregator
├── requirements.txt    # Python dependencies
└── templates/
    └── dashboard.html  # Real-time monitoring dashboard (HTML/JS/CSS)
```

---

## Running Locally

```bash
# 1. Clone the repository
git clone https://github.com/manvithareddy5858-lab/Sentinelshield.git
cd Sentinelshield

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the server
python app.py

# 4. Open the dashboard
# Navigate to http://127.0.0.1:5000 in your browser
```

---

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Real-time monitoring dashboard |
| `/test` | GET / POST | WAF inspection endpoint — submit any request here |
| `/simulate` | POST | JSON-based simulation endpoint used by the dashboard |
| `/api/logs` | GET | Returns the last N log entries as JSON |
| `/api/stats` | GET | Aggregate statistics — totals, threat counts, top IPs |
| `/api/seed` | POST | Injects demo attack data for dashboard testing |
| `/api/clear` | POST | Clears all log entries |

### Example — Testing with curl

```bash
# Clean request (should be ALLOWED)
curl "http://127.0.0.1:5000/test?id=42"

# SQL Injection (should be BLOCKED)
curl "http://127.0.0.1:5000/test?user=admin'+OR+'1'='1"

# XSS payload
curl "http://127.0.0.1:5000/test?q=<script>alert(1)</script>"

# LFI / path traversal
curl "http://127.0.0.1:5000/test?page=../../../../etc/passwd"

# Command injection
curl "http://127.0.0.1:5000/test?host=127.0.0.1;+cat+/etc/passwd"

# Simulate via JSON
curl -X POST http://127.0.0.1:5000/simulate \
  -H "Content-Type: application/json" \
  -d '{"ip":"10.0.0.1","method":"GET","path":"/search","params":{"q":"1 UNION SELECT * FROM users"},"body":""}'
```

---

## Rate Limiting

The rate limiter tracks request counts per source IP using a sliding time window:

- **Threshold:** 20 requests per 30-second window
- **Scope:** Per IP address
- **Effect:** Exceeding the threshold sets severity to LOW (no threats) or CRITICAL (threats present)

---

## Severity Levels

| Level | Condition |
|---|---|
| CLEAN | No threats detected, rate limit not exceeded |
| LOW | Rate limit exceeded, no attack signatures matched |
| MEDIUM | One attack category detected |
| HIGH | Two or more attack categories detected simultaneously |
| CRITICAL | Attack signatures detected AND rate limit exceeded |

---

## Deployment

The project is deployed on **Render** (free tier). The `gunicorn` WSGI server is used in production as specified in `requirements.txt`. Logs are stored in memory (in-memory store bounded to 2,000 entries) with a best-effort disk write to `logs/sentinelshield.log`.

> Note: Render's free tier spins down after inactivity. The first request after a sleep period may take 30–60 seconds to respond.

---

## Technologies Used

- **Python 3.10+** — backend runtime
- **Flask 2.3+** — HTTP request handling and routing
- **Gunicorn 21+** — production WSGI server
- **Chart.js 4.4.1** — dashboard visualisations
- **HTML5 / CSS3 / Vanilla JS** — frontend dashboard
