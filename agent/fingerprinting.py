"""
Ozz — Behavioral Fingerprinting (Track E)

Classify callers as human vs bot via 4 layers:
  Layer 1: User-Agent analysis (bot patterns, automation signatures)
  Layer 2: Header analysis (order, values, missing headers)
  Layer 3: Navigation behavior (timing, patterns, sequence)
  Layer 4: Honeypot tripwires (hidden links, invisible form fields)

Each layer contributes a confidence score (0.0 = definitely human, 1.0 = definitely bot).
Final classification uses weighted aggregation.

Designed to complement the Bifurcation Engine:
  fingerprinting.classify() → deception.should_bifurcate()
"""

import hashlib
import json
import logging
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("ozz.fingerprint")


# ============================================================
# Layer 1: User-Agent Analysis
# ============================================================

class UserAgentAnalyzer:
    """Analyze User-Agent strings for bot/automation signatures."""

    # Known bot/automation User-Agent patterns
    _BOT_PATTERNS = [
        # Explicit bots
        (r"(?i)bot\b", 0.9),
        (r"(?i)crawler", 0.9),
        (r"(?i)spider", 0.9),
        (r"(?i)scraper", 0.95),
        # Automation tools
        (r"(?i)python-requests", 0.85),
        (r"(?i)python-urllib", 0.85),
        (r"(?i)httpx", 0.8),
        (r"(?i)aiohttp", 0.85),
        (r"(?i)curl/", 0.7),
        (r"(?i)wget", 0.75),
        (r"(?i)libwww-perl", 0.85),
        (r"(?i)go-http-client", 0.8),
        (r"(?i)java/", 0.6),
        (r"(?i)apache-httpclient", 0.8),
        (r"(?i)okhttp", 0.75),
        (r"(?i)node-fetch", 0.7),
        (r"(?i)axios/", 0.7),
        (r"(?i)scrapy", 0.95),
        (r"(?i)selenium", 0.9),
        (r"(?i)puppeteer", 0.95),
        (r"(?i)playwright", 0.95),
        (r"(?i)headless", 0.85),
        (r"(?i)phantomjs", 0.95),
        # CTF-specific automation
        (r"(?i)nmap", 0.95),
        (r"(?i)gobuster", 0.95),
        (r"(?i)nikto", 0.95),
        (r"(?i)sqlmap", 0.95),
        (r"(?i)hydra", 0.95),
        (r"(?i)burp", 0.9),
        (r"(?i)zap", 0.85),
        (r"(?i)dirbuster", 0.95),
        (r"(?i)wfuzz", 0.95),
        (r"(?i)ffuf", 0.95),
    ]

    # Empty or missing User-Agent is suspicious
    _EMPTY_UA_SUSPICION = 0.5

    # Overly generic UAs
    _GENERIC_PATTERNS = [
        (r"^Mozilla/5\.0$", 0.6),  # Too short
        (r"^User-Agent$", 0.8),
        (r"^test$", 0.7),
        (r"^agent$", 0.7),
    ]

    def analyze(self, user_agent: str) -> tuple[float, list[str]]:
        """
        Analyze a User-Agent string.

        Returns:
            (confidence, reasons) — confidence is 0.0 (human) to 1.0 (bot)
        """
        if not user_agent or not user_agent.strip():
            return self._EMPTY_UA_SUSPICION, ["empty_user_agent"]

        confidence = 0.0
        reasons = []

        # Check bot patterns
        for pattern, bot_score in self._BOT_PATTERNS:
            if re.search(pattern, user_agent):
                confidence = max(confidence, bot_score)
                reasons.append(f"bot_pattern:{pattern}")

        # Check generic patterns
        for pattern, score in self._GENERIC_PATTERNS:
            if re.match(pattern, user_agent.strip()):
                confidence = max(confidence, score)
                reasons.append(f"generic_ua:{pattern}")

        # Length anomalies (too short = suspicious)
        if len(user_agent) < 20:
            confidence = max(confidence, 0.4)
            reasons.append("ua_too_short")
        elif len(user_agent) > 500:
            confidence = max(confidence, 0.3)
            reasons.append("ua_too_long")

        # Version anomalies (unrealistic version numbers)
        version_match = re.search(r"Chrome/(\d+)", user_agent)
        if version_match:
            version = int(version_match.group(1))
            if version > 150 or version < 50:
                confidence = max(confidence, 0.6)
                reasons.append(f"unrealistic_chrome_version:{version}")

        return min(confidence, 1.0), reasons


# ============================================================
# Layer 2: Header Analysis
# ============================================================

class HeaderAnalyzer:
    """Analyze HTTP headers for bot signatures."""

    # Headers that real browsers always send
    _EXPECTED_BROWSER_HEADERS = [
        "accept",
        "accept-language",
        "accept-encoding",
        "connection",
        "host",
        "user-agent",
    ]

    # Headers that are suspicious if present from "browsers"
    _SUSPICIOUS_HEADERS = [
        "x-forwarded-for",
        "x-real-ip",
        "via",
        "x-proxyuser-agent",
    ]

    # Typical header order in Chrome (approximate)
    _CHROME_HEADER_ORDER = [
        "host", "connection", "sec-ch-ua", "sec-ch-ua-mobile",
        "sec-ch-ua-platform", "upgrade-insecure-requests",
        "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode",
        "sec-fetch-user", "sec-fetch-dest", "accept-encoding",
        "accept-language", "cookie",
    ]

    def analyze(self, headers: dict[str, str]) -> tuple[float, list[str]]:
        """
        Analyze HTTP headers.

        Returns:
            (confidence, reasons)
        """
        if not headers:
            return 0.3, ["no_headers"]

        confidence = 0.0
        reasons = []
        header_keys_lower = {k.lower() for k in headers}

        # 1. Missing expected browser headers
        missing = []
        for expected in self._EXPECTED_BROWSER_HEADERS:
            if expected.lower() not in header_keys_lower:
                missing.append(expected)

        if len(missing) >= 3:
            confidence = max(confidence, 0.6)
            reasons.append(f"missing_headers:{','.join(missing)}")
        elif len(missing) >= 1:
            confidence = max(confidence, 0.3)
            reasons.append(f"missing_header:{missing[0]}")

        # 2. Suspicious headers present
        for sus in self._SUSPICIOUS_HEADERS:
            if sus.lower() in header_keys_lower:
                confidence = max(confidence, 0.4)
                reasons.append(f"suspicious_header:{sus}")

        # 3. Header order analysis (if we have enough headers)
        if len(header_keys_lower) >= 5:
            order_score = self._check_header_order(headers)
            if order_score > 0.5:
                confidence = max(confidence, order_score * 0.7)
                reasons.append(f"header_order_anomaly:{order_score:.2f}")

        # 4. Accept header analysis
        accept = headers.get("accept", headers.get("Accept", ""))
        if not accept:
            confidence = max(confidence, 0.4)
            reasons.append("missing_accept")
        elif accept == "*/*" and len(headers) > 5:
            # Overly permissive accept with many headers = suspicious
            confidence = max(confidence, 0.3)
            reasons.append("overly_permissive_accept")

        # 5. Cookie analysis (cookies present in first request is suspicious for bots)
        if "cookie" in header_keys_lower and len(headers) < 5:
            confidence = max(confidence, 0.3)
            reasons.append("cookies_few_headers")

        return min(confidence, 1.0), reasons

    def _check_header_order(self, headers: dict[str, str]) -> float:
        """Check if header order matches known browser patterns."""
        actual_order = [k.lower() for k in headers.keys()]
        chrome_order = self._CHROME_HEADER_ORDER

        # Calculate how many headers are in expected relative order
        matches = 0
        comparisons = 0
        for i, h1 in enumerate(actual_order):
            for h2 in actual_order[i + 1:]:
                if h1 in chrome_order and h2 in chrome_order:
                    comparisons += 1
                    idx1 = chrome_order.index(h1)
                    idx2 = chrome_order.index(h2)
                    if idx1 < idx2:
                        matches += 1

        if comparisons == 0:
            return 0.0

        order_ratio = matches / comparisons
        # Perfect order = 1.0, random order ≈ 0.5
        # We want to flag non-browser orderings
        return max(0.0, 1.0 - order_ratio * 2)  # Invert: high order match = low suspicion


# ============================================================
# Layer 3: Navigation Behavior Analysis
# ============================================================

class NavigationAnalyzer:
    """Analyze navigation timing and patterns."""

    def __init__(self):
        self._sessions: dict[str, list[dict]] = {}

    def record_access(self, session_id: str, path: str, timestamp: float = None):
        """Record a page access for behavior analysis."""
        if session_id not in self._sessions:
            self._sessions[session_id] = []
        self._sessions[session_id].append({
            "path": path,
            "timestamp": timestamp or time.time(),
        })

    def analyze(self, session_id: str) -> tuple[float, list[str]]:
        """
        Analyze navigation behavior for a session.

        Returns:
            (confidence, reasons)
        """
        accesses = self._sessions.get(session_id, [])
        if len(accesses) < 3:
            return 0.0, ["insufficient_data"]

        confidence = 0.0
        reasons = []

        # 1. Timing analysis
        intervals = []
        for i in range(1, len(accesses)):
            delta = accesses[i]["timestamp"] - accesses[i - 1]["timestamp"]
            intervals.append(delta)

        if intervals:
            avg_interval = sum(intervals) / len(intervals)
            # Bot-like: very consistent timing
            if len(intervals) >= 3:
                variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                if variance < 0.01 and avg_interval < 2.0:
                    confidence = max(confidence, 0.8)
                    reasons.append(f"consistent_timing:var={variance:.4f},avg={avg_interval:.2f}s")
                elif variance < 0.1 and avg_interval < 1.0:
                    confidence = max(confidence, 0.6)
                    reasons.append(f"fast_consistent_timing:var={variance:.4f},avg={avg_interval:.2f}s")

            # Bot-like: unnaturally fast (sub-second)
            fast_count = sum(1 for i in intervals if i < 0.5)
            if fast_count > len(intervals) * 0.5:
                confidence = max(confidence, 0.7)
                reasons.append(f"rapid_fire:{fast_count}/{len(intervals)} under 0.5s")

        # 2. Path pattern analysis
        paths = [a["path"] for a in accesses]

        # Sequential path enumeration (like /admin, /backup, /config...)
        sequential = self._detect_sequential_paths(paths)
        if sequential:
            confidence = max(confidence, 0.75)
            reasons.append(f"sequential_path_enum:{len(paths)} paths")

        # Alphabetical or sorted access = brute-force
        if len(paths) >= 5:
            sorted_paths = sorted(paths)
            if paths == sorted_paths:
                confidence = max(confidence, 0.6)
                reasons.append("alphabetical_access_pattern")

        # 3. Resource access pattern
        # Bots typically don't load CSS/JS/images
        resource_exts = {".css", ".js", ".png", ".jpg", ".gif", ".svg", ".ico", ".woff"}
        resource_count = sum(1 for p in paths if any(p.lower().endswith(ext) for ext in resource_exts))
        html_count = sum(1 for p in paths if not any(p.lower().endswith(ext) for ext in resource_exts))

        if html_count > 10 and resource_count == 0:
            confidence = max(confidence, 0.7)
            reasons.append(f"no_resources_loaded:{html_count} pages, 0 resources")
        elif html_count > 5 and resource_count < html_count * 0.1:
            confidence = max(confidence, 0.5)
            reasons.append(f"low_resource_ratio:{resource_count}/{html_count}")

        return min(confidence, 1.0), reasons

    def _detect_sequential_paths(self, paths: list[str]) -> bool:
        """Detect if paths are being enumerated sequentially."""
        if len(paths) < 5:
            return False
        # Check for dictionary-style enumeration
        # Common patterns: /admin, /backup, /config, /debug, /dev...
        common_dirs = {
            "/admin", "/backup", "/config", "/debug", "/dev",
            "/api", "/static", "/uploads", "/test", "/tmp",
            "/login", "/register", "/dashboard", "/panel",
        }
        hits = sum(1 for p in paths if p.lower() in common_dirs)
        return hits >= len(paths) * 0.5


# ============================================================
# Layer 4: Honeypot Tripwires
# ============================================================

class HoneypotLayer:
    """
    Honeypot tripwires embedded in responses.

    Hidden links and invisible form fields that real users never touch
    but bots always follow/click.
    """

    # Hidden trap URLs
    _TRAP_URLS = [
        "/admin/secret-panel",
        "/.hidden/debug-console",
        "/backup/credentials.json",
        "/internal/api-keys",
        "/dev/shell-access",
        "/.git/config.bak",
        "/wp-admin/install.php",
    ]

    # Invisible form field names
    _TRAP_FIELDS = [
        "honeypot_email",
        "trap_url",
        "redirect_to",
        "hidden_token",
        "anti_spam",
        "_hp_",
    ]

    def __init__(self):
        self._tripped: dict[str, list[str]] = {}  # session_id → tripped traps

    def inject_honeypots(self, html_response: str, session_id: str) -> str:
        """
        Inject honeypot elements into an HTML response.

        Real users won't see these (CSS-hidden). Bots parse HTML and follow them.
        """
        trap_url = self._choose_trap(session_id)

        # Invisible link (CSS hidden)
        honeypot_link = (
            f'\n<div style="display:none;visibility:hidden;position:absolute;left:-9999px;">'
            f'<a href="{trap_url}">Admin Login</a></div>'
        )

        # Invisible form field
        trap_field = (
            f'\n<input type="text" name="honeypot_email" value="" '
            f'style="display:none;" tabindex="-1" autocomplete="off">'
        )

        # Inject into HTML
        if "</body>" in html_response.lower():
            idx = html_response.lower().rindex("</body>")
            html_response = html_response[:idx] + honeypot_link + trap_field + html_response[idx:]
        else:
            html_response += honeypot_link + trap_field

        return html_response

    def check_trap(self, session_id: str, path: str, form_data: dict = None) -> bool:
        """
        Check if a request hit a honeypot trap.

        Returns True if the session has tripped a trap.
        """
        if session_id not in self._tripped:
            self._tripped[session_id] = []

        # Check URL traps
        for trap in self._TRAP_URLS:
            if trap.lower() in path.lower():
                self._tripped[session_id].append(f"url:{trap}")
                logger.info(f"🍯 Honeypot tripped! Session {session_id[:16]}... hit URL trap: {trap}")
                return True

        # Check form field traps
        if form_data:
            for field_name in self._TRAP_FIELDS:
                if field_name in form_data:
                    self._tripped[session_id].append(f"field:{field_name}")
                    logger.info(f"🍯 Honeypot tripped! Session {session_id[:16]}... submitted trap field: {field_name}")
                    return True

        return False

    def has_tripped(self, session_id: str) -> tuple[bool, list[str]]:
        """Check if a session has tripped any honeypot traps."""
        traps = self._tripped.get(session_id, [])
        return bool(traps), traps

    def _choose_trap(self, session_id: str) -> str:
        """Deterministically choose a trap URL for a session."""
        idx = int(hashlib.md5(session_id.encode()).hexdigest()[:4], 16) % len(self._TRAP_URLS)
        return self._TRAP_URLS[idx]

    def get_stats(self) -> dict:
        """Get honeypot statistics."""
        total_trips = sum(len(t) for t in self._tripped.values())
        return {
            "total_sessions_tracked": len(self._tripped),
            "total_trips": total_trips,
            "tripped_sessions": sum(1 for t in self._tripped.values() if t),
        }


# ============================================================
# Behavioral Fingerprint — Main Classifier
# ============================================================

@dataclass
class FingerprintResult:
    """Result of behavioral fingerprinting."""
    session_id: str
    is_bot: bool
    confidence: float  # 0.0 = human, 1.0 = bot
    layer_scores: dict = field(default_factory=dict)
    layer_reasons: dict = field(default_factory=dict)
    classification: str = "unknown"  # human, likely_human, unknown, likely_bot, bot

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id[:16] + "...",
            "is_bot": self.is_bot,
            "confidence": round(self.confidence, 3),
            "classification": self.classification,
            "layer_scores": {k: round(v, 3) for k, v in self.layer_scores.items()},
            "layer_reasons": self.layer_reasons,
        }


class BehavioralFingerprint:
    """
    4-layer behavioral fingerprinting system.

    Layer weights (configurable):
      - User-Agent:  0.30
      - Headers:     0.25
      - Navigation:  0.30
      - Honeypots:   0.15 (but 1.0 if tripped → instant bot classification)
    """

    # Layer weights
    WEIGHT_UA = 0.30
    WEIGHT_HEADERS = 0.25
    WEIGHT_NAV = 0.30
    WEIGHT_HONEYPOT = 0.15

    # Classification thresholds
    THRESHOLD_BOT = 0.7
    THRESHOLD_LIKELY_BOT = 0.5
    THRESHOLD_LIKELY_HUMAN = 0.3

    def __init__(self):
        self.ua_analyzer = UserAgentAnalyzer()
        self.header_analyzer = HeaderAnalyzer()
        self.nav_analyzer = NavigationAnalyzer()
        self.honeypot_layer = HoneypotLayer()
        self._results_cache: dict[str, FingerprintResult] = {}

    def classify(self, session_id: str, user_agent: str = "",
                 headers: dict = None, path: str = "",
                 form_data: dict = None) -> FingerprintResult:
        """
        Classify a caller using all 4 layers.

        Args:
            session_id: Unique session identifier
            user_agent: User-Agent header value
            headers: All HTTP headers as dict
            path: Request path
            form_data: Form data if applicable

        Returns:
            FingerprintResult with bot classification
        """
        layer_scores = {}
        layer_reasons = {}

        # Layer 1: User-Agent
        ua_score, ua_reasons = self.ua_analyzer.analyze(user_agent or "")
        layer_scores["user_agent"] = ua_score
        layer_reasons["user_agent"] = ua_reasons

        # Layer 2: Headers
        hdr_score, hdr_reasons = self.header_analyzer.analyze(headers or {})
        layer_scores["headers"] = hdr_score
        layer_reasons["headers"] = hdr_reasons

        # Layer 3: Navigation
        self.nav_analyzer.record_access(session_id, path)
        nav_score, nav_reasons = self.nav_analyzer.analyze(session_id)
        layer_scores["navigation"] = nav_score
        layer_reasons["navigation"] = nav_reasons

        # Layer 4: Honeypots
        honeypot_tripped = self.honeypot_layer.check_trap(session_id, path, form_data)
        has_tripped, trip_details = self.honeypot_layer.has_tripped(session_id)
        if has_tripped:
            honeypot_score = 1.0  # Instant bot classification
            layer_reasons["honeypot"] = trip_details
        else:
            honeypot_score = 0.0
            layer_reasons["honeypot"] = ["clean"]
        layer_scores["honeypot"] = honeypot_score

        # Weighted aggregation
        confidence = (
            ua_score * self.WEIGHT_UA +
            hdr_score * self.WEIGHT_HEADERS +
            nav_score * self.WEIGHT_NAV +
            honeypot_score * self.WEIGHT_HONEYPOT
        )

        # Honeypot override: if tripped, guarantee high confidence
        if has_tripped:
            confidence = max(confidence, 0.95)

        # Classify
        if confidence >= self.THRESHOLD_BOT:
            classification = "bot"
            is_bot = True
        elif confidence >= self.THRESHOLD_LIKELY_BOT:
            classification = "likely_bot"
            is_bot = True
        elif confidence >= self.THRESHOLD_LIKELY_HUMAN:
            classification = "unknown"
            is_bot = False
        else:
            classification = "human" if confidence < 0.15 else "likely_human"
            is_bot = False

        result = FingerprintResult(
            session_id=session_id,
            is_bot=is_bot,
            confidence=confidence,
            layer_scores=layer_scores,
            layer_reasons=layer_reasons,
            classification=classification,
        )

        self._results_cache[session_id] = result
        return result

    def get_cached(self, session_id: str) -> Optional[FingerprintResult]:
        """Get cached fingerprint result for a session."""
        return self._results_cache.get(session_id)

    def get_stats(self) -> dict:
        """Get overall fingerprinting statistics."""
        total = len(self._results_cache)
        bots = sum(1 for r in self._results_cache.values() if r.is_bot)
        classifications = defaultdict(int)
        for r in self._results_cache.values():
            classifications[r.classification] += 1

        return {
            "total_sessions_classified": total,
            "bots_detected": bots,
            "humans_detected": total - bots,
            "classifications": dict(classifications),
            "honeypot_stats": self.honeypot_layer.get_stats(),
        }


# ============================================================
# Integration Helper
# ============================================================

def create_fingerprinter() -> BehavioralFingerprint:
    """Factory function for easy integration."""
    return BehavioralFingerprint()
