"""
Ozz — Scoreboard Client
Handles flag submission to CTF scoreboard REST APIs.
Supports multiple scoreboard formats (HALctf, CTFd, rCTF, HTB, custom).
Includes retry logic, deduplication, and submission verification.
"""

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Optional
import requests

logger = logging.getLogger("ozz.scoreboard")


@dataclass
class SubmissionResult:
    """Result of a flag submission attempt."""
    success: bool
    flag: str
    message: str = ""
    points: int = 0
    already_solved: bool = False
    error: str = ""
    response_code: int = 0


class ScoreboardClient:
    """
    Autonomous flag submission client for CTF scoreboards.
    
    Supports:
    - HALctf scoreboard (custom REST API)
    - CTFd-based platforms
    - rCTF
    - Generic POST-based flag submission
    
    Configuration via environment variables:
    - SCOREBOARD_URL: Base URL of the scoreboard API
    - SCOREBOARD_TOKEN: Authentication token (if required)
    - SCOREBOARD_TEAM: Team name/ID
    - FLAG_FORMAT: Regex pattern for valid flags (default: [A-Z]+\\{[^}]+\\})
    """

    # Common flag format patterns (ordered specificity - more specific first)
    # Use word boundaries to prevent substring matches (e.g., CTF inside HALCTF)
    FLAG_PATTERNS = [
        r'HALCTF\{[^}]+\}',
        r'DEFCON\{[^}]+\}',
        r'picoCTF\{[^}]+\}',
        r'flag\{[^}]+\}',
        r'\bCTF\{[^}]+\}',
        r'[A-Z][A-Z0-9_]{2,}\{[a-zA-Z0-9_!@#$%^&*().\-]+\}',
    ]

    def __init__(self):
        self.base_url = os.environ.get("SCOREBOARD_URL", "").rstrip("/")
        self.token = os.environ.get("SCOREBOARD_TOKEN", "")
        self.team = os.environ.get("SCOREBOARD_TEAM", "")
        self.flag_format = os.environ.get("FLAG_FORMAT", "")
        self.submitted_flags: set[str] = set()
        self.submission_log: list[dict] = []
        self.max_retries = 3
        self.retry_delay = 2.0
        self.timeout = 15
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "Ozz-HALctf/1.0"})

        if self.token:
            self._session.headers["Authorization"] = f"Bearer {self.token}"

        # Detect scoreboard type from URL
        self.scoreboard_type = self._detect_scoreboard_type()
        logger.info(f"Scoreboard client initialized: type={self.scoreboard_type}, url={self.base_url or 'LOCAL'}")

    def _detect_scoreboard_type(self) -> str:
        """Auto-detect the scoreboard platform type."""
        if not self.base_url:
            return "local"

        url_lower = self.base_url.lower()
        if "halctf" in url_lower or "aivillage" in url_lower:
            return "halctf"
        if "/api/v1/" in url_lower:
            return "rctf"
        if "/challenges" in url_lower or "/api/" in url_lower:
            return "ctfd"

        # Probe the scoreboard
        try:
            resp = self._session.get(f"{self.base_url}/api/v1/challenges", timeout=5)
            if resp.status_code == 200:
                return "ctfd"
        except Exception:
            pass

        return "generic"

    def submit_flag(self, flag: str, challenge_id: str = "", challenge_name: str = "") -> SubmissionResult:
        """
        Submit a flag to the scoreboard.
        
        Args:
            flag: The flag string to submit
            challenge_id: Optional challenge identifier
            challenge_name: Optional challenge name
            
        Returns:
            SubmissionResult with success status and details
        """
        flag = flag.strip()

        # Validate flag format
        if not self._validate_flag(flag):
            return SubmissionResult(
                success=False, flag=flag,
                error=f"Flag format validation failed: {flag}"
            )

        # Deduplication
        if flag in self.submitted_flags:
            logger.info(f"Flag already submitted (dedup): {flag}")
            return SubmissionResult(
                success=True, flag=flag,
                message="Already submitted (dedup)", already_solved=True
            )

        # Submit with retry
        result = self._submit_with_retry(flag, challenge_id, challenge_name)

        if result.success or result.already_solved:
            self.submitted_flags.add(flag)

        self.submission_log.append({
            "timestamp": time.time(),
            "flag": flag,
            "challenge_id": challenge_id,
            "success": result.success,
            "message": result.message,
            "points": result.points,
        })

        return result

    def _validate_flag(self, flag: str) -> bool:
        """Validate flag against known patterns."""
        if not flag or len(flag) < 4:
            return False

        # Custom format if specified
        if self.flag_format:
            return bool(re.match(self.flag_format, flag))

        # Check against known patterns
        for pattern in self.FLAG_PATTERNS:
            if re.search(pattern, flag, re.IGNORECASE):
                return True

        # Fallback: any string that looks flag-like (contains { and })
        if '{' in flag and '}' in flag and len(flag) >= 8:
            return True

        return False

    def _submit_with_retry(self, flag: str, challenge_id: str, challenge_name: str) -> SubmissionResult:
        """Submit flag with exponential backoff retry."""
        for attempt in range(1, self.max_retries + 1):
            try:
                return self._do_submit(flag, challenge_id, challenge_name)
            except requests.RequestException as e:
                logger.warning(f"Submission attempt {attempt}/{self.max_retries} failed: {e}")
                if attempt < self.max_retries:
                    delay = self.retry_delay * (2 ** (attempt - 1))
                    time.sleep(delay)

        return SubmissionResult(
            success=False, flag=flag,
            error=f"All {self.max_retries} submission attempts failed"
        )

    def _do_submit(self, flag: str, challenge_id: str, challenge_name: str) -> SubmissionResult:
        """Actual flag submission based on scoreboard type."""
        if self.scoreboard_type == "local":
            return self._submit_local(flag, challenge_id, challenge_name)
        elif self.scoreboard_type == "halctf":
            return self._submit_halctf(flag, challenge_id, challenge_name)
        elif self.scoreboard_type == "ctfd":
            return self._submit_ctfd(flag, challenge_id)
        elif self.scoreboard_type == "rctf":
            return self._submit_rctf(flag, challenge_id)
        else:
            return self._submit_generic(flag, challenge_id, challenge_name)

    def _submit_local(self, flag: str, challenge_id: str, challenge_name: str) -> SubmissionResult:
        """Local submission (store in memory, no network call)."""
        logger.info(f"🚩 FLAG CAPTURED (local): {flag}")
        return SubmissionResult(
            success=True, flag=flag,
            message=f"Flag captured locally: {flag}", points=100
        )

    def _submit_halctf(self, flag: str, challenge_id: str, challenge_name: str) -> SubmissionResult:
        """Submit to HALctf scoreboard."""
        payload = {"flag": flag}
        if challenge_id:
            payload["challenge_id"] = challenge_id
        if challenge_name:
            payload["challenge_name"] = challenge_name
        if self.team:
            payload["team"] = self.team

        resp = self._session.post(
            f"{self.base_url}/api/submit",
            json=payload, timeout=self.timeout
        )
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}

        if resp.status_code == 200:
            if data.get("correct") or data.get("success") or "correct" in str(data).lower():
                points = data.get("points", data.get("score", 100))
                return SubmissionResult(
                    success=True, flag=flag,
                    message=data.get("message", "Correct!"),
                    points=points, response_code=resp.status_code
                )
            if "already" in str(data).lower() or "solved" in str(data).lower():
                return SubmissionResult(
                    success=True, flag=flag,
                    message="Already solved", already_solved=True,
                    response_code=resp.status_code
                )
            return SubmissionResult(
                success=False, flag=flag,
                message=data.get("message", "Incorrect flag"),
                response_code=resp.status_code
            )

        return SubmissionResult(
            success=False, flag=flag,
            error=f"HTTP {resp.status_code}: {resp.text[:200]}",
            response_code=resp.status_code
        )

    def _submit_ctfd(self, flag: str, challenge_id: str) -> SubmissionResult:
        """Submit to CTFd-based scoreboard."""
        payload = {"challenge_id": challenge_id, "submission": flag}
        resp = self._session.post(
            f"{self.base_url}/api/v1/challenges/attempt",
            json=payload, timeout=self.timeout
        )

        if resp.status_code in [200, 201]:
            data = resp.json()
            if data.get("success"):
                return SubmissionResult(
                    success=True, flag=flag,
                    message="Correct!", points=data.get("data", {}).get("points", 100)
                )
            return SubmissionResult(
                success=False, flag=flag,
                message=str(data.get("data", "Incorrect"))
            )

        if resp.status_code == 403:
            return SubmissionResult(
                success=True, flag=flag,
                message="Already solved", already_solved=True
            )

        return SubmissionResult(
            success=False, flag=flag,
            error=f"HTTP {resp.status_code}", response_code=resp.status_code
        )

    def _submit_rctf(self, flag: str, challenge_id: str) -> SubmissionResult:
        """Submit to rCTF scoreboard."""
        payload = {"challengeId": challenge_id, "flag": flag}
        resp = self._session.post(
            f"{self.base_url}/api/v1/challs/submit",
            json=payload, timeout=self.timeout
        )
        data = resp.json() if resp.status_code == 200 else {}

        if data.get("kind") == "flagCorrect":
            return SubmissionResult(success=True, flag=flag, message="Correct!")
        if data.get("kind") == "flagAlreadySolved":
            return SubmissionResult(success=True, flag=flag, message="Already solved", already_solved=True)

        return SubmissionResult(
            success=False, flag=flag,
            message=data.get("message", "Incorrect"), response_code=resp.status_code
        )

    def _submit_generic(self, flag: str, challenge_id: str, challenge_name: str) -> SubmissionResult:
        """Generic POST-based flag submission."""
        payload = {"flag": flag}
        if challenge_id:
            payload["id"] = challenge_id
        if challenge_name:
            payload["challenge"] = challenge_name

        # Try common endpoints
        endpoints = ["/api/submit", "/api/flag", "/submit", "/flag", "/api/v1/submit"]
        for endpoint in endpoints:
            try:
                resp = self._session.post(
                    f"{self.base_url}{endpoint}",
                    json=payload, timeout=self.timeout
                )
                if resp.status_code in [200, 201]:
                    data = resp.json() if "json" in resp.headers.get("content-type", "") else {}
                    if data.get("success") or data.get("correct") or "correct" in str(data).lower():
                        return SubmissionResult(
                            success=True, flag=flag,
                            message=data.get("message", "Correct!"),
                            points=data.get("points", 100)
                        )
                    if "already" in str(data).lower():
                        return SubmissionResult(success=True, flag=flag, already_solved=True, message="Already solved")
            except Exception:
                continue

        # Last resort: store locally
        logger.warning(f"Could not submit flag via API, storing locally: {flag}")
        return self._submit_local(flag, challenge_id, challenge_name)

    def get_submission_summary(self) -> dict:
        """Get summary of all submissions."""
        return {
            "total_submitted": len(self.submitted_flags),
            "unique_flags": list(self.submitted_flags),
            "log": self.submission_log[-20:],  # Last 20
            "scoreboard_type": self.scoreboard_type,
            "scoreboard_url": self.base_url,
        }

    def extract_flags_from_text(self, text: str) -> list[str]:
        """Extract all potential flags from arbitrary text."""
        flags = []
        for pattern in self.FLAG_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            flags.extend(matches)
        # Remove substrings that are already part of longer flags
        unique = list(set(flags))
        filtered = []
        for f in unique:
            # Check if this flag is a substring of another longer flag
            if not any(f != other and f in other for other in unique):
                filtered.append(f)
        return filtered
