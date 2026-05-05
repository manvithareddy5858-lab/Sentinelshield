"""
SentinelShield - Logging Module
In-memory log store (works on Render free tier where filesystem is ephemeral).
Also writes to disk as a best-effort backup.
"""

import json
from datetime import datetime
from pathlib import Path

# ── In-memory store (primary) ──────────────────────────────
_LOG_STORE: list = []   # list of dicts, append-only, newest at end

# ── Disk backup (best-effort) ──────────────────────────────
LOG_FILE = Path(__file__).parent / "logs" / "sentinelshield.log"
try:
    LOG_FILE.parent.mkdir(exist_ok=True)
except Exception:
    pass


def write_log(entry: dict):
    """Append a log entry to the in-memory store and best-effort to disk."""
    _LOG_STORE.append(entry)
    # Keep memory bounded to last 2000 entries
    if len(_LOG_STORE) > 2000:
        _LOG_STORE.pop(0)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def read_logs(limit: int = 200) -> list:
    """Return last N entries newest-first from in-memory store."""
    return list(reversed(_LOG_STORE[-limit:]))


def get_stats() -> dict:
    """Compute aggregate statistics from in-memory log."""
    logs = _LOG_STORE

    total   = len(logs)
    blocked = sum(1 for e in logs if not e.get("allowed"))
    allowed = total - blocked

    threat_counts  = {}
    ip_counts      = {}
    severity_counts = {"CLEAN": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    recent_alerts  = []

    for e in reversed(logs):          # newest first
        for t in e.get("threats", []):
            threat_counts[t] = threat_counts.get(t, 0) + 1
        ip = e.get("ip", "unknown")
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
        sev = e.get("severity", "CLEAN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        if sev != "CLEAN" and len(recent_alerts) < 50:
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
    """Clear in-memory store and disk log."""
    global _LOG_STORE
    _LOG_STORE.clear()
    try:
        if LOG_FILE.exists():
            LOG_FILE.unlink()
        LOG_FILE.touch()
    except Exception:
        pass
