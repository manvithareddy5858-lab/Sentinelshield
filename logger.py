"""
SentinelShield - Logging Module
Writes structured JSON log entries and provides query helpers.
"""

import json
import os
from datetime import datetime
from pathlib import Path

LOG_FILE = Path(__file__).parent / "logs" / "sentinelshield.log"
LOG_FILE.parent.mkdir(exist_ok=True)


def write_log(entry: dict):
    """Append a JSON log entry to the log file."""
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")


def read_logs(limit: int = 200) -> list:
    """Read last N log entries, newest first."""
    if not LOG_FILE.exists():
        return []
    with open(LOG_FILE, "r") as f:
        lines = f.readlines()
    entries = []
    for line in reversed(lines[-limit:]):
        line = line.strip()
        if line:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return entries


def get_stats() -> dict:
    """Compute aggregate statistics from all logs."""
    logs = read_logs(limit=5000)

    total = len(logs)
    blocked = sum(1 for e in logs if not e.get("allowed"))
    allowed = total - blocked

    threat_counts = {}
    ip_counts = {}
    severity_counts = {"CLEAN": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    recent_alerts = []

    for e in logs:
        # Threat categories
        for t in e.get("threats", []):
            threat_counts[t] = threat_counts.get(t, 0) + 1

        # IP tracking
        ip = e.get("ip", "unknown")
        ip_counts[ip] = ip_counts.get(ip, 0) + 1

        # Severity
        sev = e.get("severity", "CLEAN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Recent non-clean alerts (newest first, up to 50)
        if e.get("severity") != "CLEAN" and len(recent_alerts) < 50:
            recent_alerts.append(e)

    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "total": total,
        "blocked": blocked,
        "allowed": allowed,
        "threat_counts": threat_counts,
        "severity_counts": severity_counts,
        "top_ips": top_ips,
        "recent_alerts": recent_alerts[:20],
        "detection_rate": round((blocked / total * 100), 1) if total else 0,
    }


def clear_logs():
    """Wipe the log file (for testing resets)."""
    if LOG_FILE.exists():
        LOG_FILE.unlink()
    LOG_FILE.touch()
