"""
SentinelShield - Core Detection Engine
Inspects HTTP requests and classifies attack types.
"""

import re
import time
from collections import defaultdict
from datetime import datetime

# ─────────────────────────────────────────────
#  Attack Signature Rules
# ─────────────────────────────────────────────

RULES = {
    "SQL_INJECTION": [
        r"('|\%27).*(or|and|union|select|insert|update|delete|drop|--|\%2D\%2D)",
        r"(union(\s|\+)+select)",
        r"(select.+from)",
        r"(insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+table)",
        r"(;\s*(drop|alter|truncate|exec|execute))",
        r"(1\s*=\s*1|1\s*=\s*'1'|'\s*or\s*'\s*=\s*')",
        r"(--\s*$|#\s*$|\/\*.*\*\/)",
        r"(\%27|\%22|\%3D|\%3B)",  # URL-encoded SQL chars
    ],
    "XSS": [
        r"(<\s*script.*?>)",
        r"(javascript\s*:)",
        r"(on\w+\s*=\s*['\"].*?['\"])",  # onerror=, onclick=, etc.
        r"(<\s*iframe.*?>)",
        r"(<\s*img[^>]+src\s*=\s*['\"]javascript)",
        r"(document\.(cookie|write|location))",
        r"(window\.(location|open))",
        r"(<\s*svg.*?on\w+\s*=)",
        r"(\%3Cscript|\%3C\/script\%3E)",
    ],
    "LFI": [
        r"(\.\./|\.\.\%2F|\%2e\%2e\%2f)",  # path traversal
        r"(\/etc\/passwd|\/etc\/shadow|\/proc\/self)",
        r"(boot\.ini|win\.ini|system32)",
        r"(php://|file://|data://|expect://|zip://)",
        r"(\.\./\.\./\.\./)",
        r"(include\s*\(|require\s*\(|include_once\s*\()",
    ],
    "COMMAND_INJECTION": [
        r"(;\s*(ls|cat|pwd|id|whoami|uname|ifconfig|wget|curl|chmod|rm|nc|bash|sh)(\s|$|\;|\|))",
        r"(\|\s*(ls|cat|id|whoami|bash|sh|python|perl|ruby))",
        r"(`[^`]*`)",  # backtick execution
        r"(\$\([^)]*\))",  # $() subshell
        r"(&&\s*(ls|cat|id|whoami|rm|wget|curl))",
        r"(\%60|\%7C|\%26\%26)",  # URL-encoded shell chars
        r"(\/bin\/bash|\/bin\/sh|\/usr\/bin\/python)",
    ],
    "DIRECTORY_TRAVERSAL": [
        r"(\.\./){2,}",
        r"(%2e%2e%2f){2,}",
        r"(%252e%252e%252f)",  # double-encoded
        r"(\.\.\\\\|\.\.\/)",
        r"(\/\.\.\/\.\.\/)",
    ],
}

# Flatten for quick multi-category check
_compiled_rules = {
    category: [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
    for category, patterns in RULES.items()
}

# ─────────────────────────────────────────────
#  Rate Limiter
# ─────────────────────────────────────────────

class RateLimiter:
    """Tracks request counts per IP within a sliding time window."""

    def __init__(self, max_requests=20, window_seconds=30):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._buckets = defaultdict(list)  # ip -> [timestamps]

    def check(self, ip: str) -> dict:
        now = time.time()
        window_start = now - self.window_seconds
        # Prune old entries
        self._buckets[ip] = [t for t in self._buckets[ip] if t > window_start]
        self._buckets[ip].append(now)
        count = len(self._buckets[ip])
        exceeded = count > self.max_requests
        return {
            "exceeded": exceeded,
            "count": count,
            "limit": self.max_requests,
            "window": self.window_seconds,
        }

    def get_stats(self):
        now = time.time()
        window_start = now - self.window_seconds
        return {
            ip: len([t for t in ts if t > window_start])
            for ip, ts in self._buckets.items()
        }


# ─────────────────────────────────────────────
#  Main Detector
# ─────────────────────────────────────────────

rate_limiter = RateLimiter(max_requests=20, window_seconds=30)


def inspect_request(ip: str, method: str, path: str, params: dict, headers: dict, body: str = "") -> dict:
    """
    Inspect an incoming HTTP request for attack signatures.

    Returns a result dict with:
      - allowed: bool
      - threats: list of detected categories
      - matched_patterns: list of matched strings
      - rate_limit: rate limit status
      - severity: CLEAN / LOW / MEDIUM / HIGH / CRITICAL
      - timestamp: ISO timestamp
    """
    # Combine all inspectable content into one string
    target_parts = [path]
    for k, v in params.items():
        target_parts.append(f"{k}={v}")
    # 🔒 Do NOT scan headers (avoids false positives in production)
pass
    if body:
        target_parts.append(body)

    full_content = " ".join(target_parts)

    threats = []
    matched_patterns = []

    for category, patterns in _compiled_rules.items():
        for pattern in patterns:
            m = pattern.search(full_content)
            if m:
                if category not in threats:
                    threats.append(category)
                matched_patterns.append(m.group(0)[:80])  # cap length
                break  # one match per category is enough

    # Rate limit check
    rl = rate_limiter.check(ip)

    # Determine severity
    if rl["exceeded"] and threats:
        severity = "CRITICAL"
    elif len(threats) >= 2:
        severity = "HIGH"
    elif threats:
        severity = "MEDIUM"
    elif rl["exceeded"]:
        severity = "LOW"
    else:
        severity = "CLEAN"

    allowed = severity == "CLEAN"

    return {
        "allowed": allowed,
        "threats": threats,
        "matched_patterns": matched_patterns,
        "rate_limit": rl,
        "severity": severity,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "ip": ip,
        "method": method,
        "path": path,
    }
