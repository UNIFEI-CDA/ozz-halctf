"""
Bounded Context: Coding Assistant Security Domain Solver
Detects malicious patterns in cloned repositories targeting AI coding assistants.
Based on DEF CON 34 AI Village: "Malicious Context Propagation: Weaponizing the
Extensibility of AI Coding Assistants" (Harness).

Attack surface:
  1. Malicious git hooks (pre-commit, post-checkout, post-merge)
  2. Auto-invoke skills/plugins without user consent
  3. Poisoned MCP server configs injecting malicious context
  4. Project configs disabling guardrails (.eslintrc, .prettierrc, pyproject.toml)
  5. Cross-tool contamination via IDE/linter/formatter/CI configs
  6. Credential exfiltration patterns in hooks, scripts, Docker builds
"""
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .base import BaseDomainSolver
from .registry import register_solver
from ..dtos.domain_dtos import AnalysisRequest, DomainAnalysisReport


# ── Severity & Verdict ────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Verdict(str, Enum):
    SAFE = "safe"
    UNSAFE = "unsafe"
    NEEDS_REVIEW = "needs_review"


@dataclass
class Finding:
    """A single suspicious pattern detected in a repository."""
    rule_id: str
    severity: Severity
    category: str
    file_path: str
    line_number: Optional[int]
    description: str
    evidence: str = ""
    recommendation: str = ""


@dataclass
class RiskAssessment:
    """Aggregate risk score for a repository."""
    score: float                          # 0.0 (safe) .. 100.0 (critical)
    verdict: Verdict
    findings: List[Finding] = field(default_factory=list)
    summary: str = ""
    scanned_files: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0


# ── Detection Rule Catalogue ──────────────────────────────────────────

# Each rule: (rule_id, severity, category, file_globs, patterns, description)
# patterns are compiled regexes applied per-line.

_RULES_RAW: List[Dict[str, Any]] = [
    # ── 1. Malicious Git Hooks ────────────────────────────────────────
    {
        "id": "HOOK-PRE-COMMIT-EXFIL",
        "severity": Severity.CRITICAL,
        "category": "malicious_hook",
        "globs": [".git/hooks/pre-commit", "hooks/pre-commit"],
        "patterns": [
            r"curl\s+.*\|\s*(bash|sh)",
            r"wget\s+.*\|\s*(bash|sh)",
            r"requests\.post\(",
            r"urllib\.request\.urlopen\(",
            r"http[s]?://.*\.(env|credentials|ssh|pem|key)",
        ],
        "desc": "Pre-commit hook exfiltrates data to external server",
    },
    {
        "id": "HOOK-POST-CHECKOUT-ENUM",
        "severity": Severity.CRITICAL,
        "category": "malicious_hook",
        "globs": [".git/hooks/post-checkout", "hooks/post-checkout"],
        "patterns": [
            r"os\.environ",
            r"env\b.*\|",
            r"printenv",
            r"export\s+.*=",
            r"curl.*\$",
            r"wget.*\$",
        ],
        "desc": "Post-checkout hook enumerates environment variables",
    },
    {
        "id": "HOOK-POST-MERGE-RCE",
        "severity": Severity.CRITICAL,
        "category": "malicious_hook",
        "globs": [".git/hooks/post-merge", "hooks/post-merge"],
        "patterns": [
            r"eval\s*\(",
            r"exec\s*\(",
            r"subprocess\.(call|run|Popen)\(",
            r"os\.system\(",
            r"__import__\s*\(",
        ],
        "desc": "Post-merge hook executes arbitrary code",
    },
    {
        "id": "HOOK-GENERIC-EXFIL",
        "severity": Severity.HIGH,
        "category": "malicious_hook",
        "globs": [".git/hooks/*", "hooks/*"],
        "patterns": [
            r"curl\s+.*-d\s+",
            r"curl\s+.*--data",
            r"wget\s+.*--post-data",
            r"base64\s+(--decode|--encode).*\|",
            r"nc\s+-[el]",           # netcat listener
            r"/dev/tcp/",            # bash reverse shell
            r"python.*-c\s+['\"]import\s+socket",
        ],
        "desc": "Git hook contains exfiltration or reverse-shell pattern",
    },

    # ── 2. Auto-Invoke Skills / Plugins ───────────────────────────────
    {
        "id": "SKILL-AUTO-INVOKE",
        "severity": Severity.HIGH,
        "category": "auto_invoke_skill",
        "globs": [
            ".cursor/**", ".windsurf/**", ".copilot/**", ".aider/**",
            ".claude/**", ".cline/**", ".continue/**", ".codeium/**",
            "SKILL.md", "skills/**/SKILL.md",
        ],
        "patterns": [
            r"auto[_-]?invoke\s*[=:]\s*true",
            r"auto[_-]?run\s*[=:]\s*true",
            r"trigger\s*[=:]\s*always",
            r"on[_-]?open\s*[=:]\s*true",
            r"execute\s*[=:]\s*true",
        ],
        "desc": "Skill/plugin configured to auto-invoke without user consent",
    },
    {
        "id": "SKILL-HIDDEN-COMMAND",
        "severity": Severity.HIGH,
        "category": "auto_invoke_skill",
        "globs": [
            ".cursor/**", ".windsurf/**", ".copilot/**",
            ".claude/**", ".cline/**", ".continue/**",
            "skills/**/*.md", "skills/**/*.json",
        ],
        "patterns": [
            r"<!--.*\b(rm|curl|wget|eval|exec|import\s+os)\b.*-->",
            r"```[a-z]*\s*\n.*(curl|wget|eval|exec).*\n```",
        ],
        "desc": "Hidden commands embedded in skill documentation (HTML comments / code blocks)",
    },

    # ── 3. Poisoned MCP Servers ───────────────────────────────────────
    {
        "id": "MCP-POISONED-SERVER",
        "severity": Severity.CRITICAL,
        "category": "poisoned_mcp",
        "globs": [
            "mcp.json", ".mcp.json", "mcp-servers.json",
            "**/mcp*.json", ".vscode/mcp.json",
        ],
        "patterns": [
            r"command.*:\s*['\"]?(bash|sh)['\"]?",
            r"args.*:\s*\[.*['\"]?-c['\"]",
            r"env\s*:.*\{.*TOKEN|SECRET|KEY|PASSWORD",
            r"stdio.*command.*:\s*['\"]?npx",
            r"transport.*:\s*['\"]?stdio['\"]?.*command",
            r"(endpoint|url)\s*:.*\.(xyz|tk|ml|ga|cf|top|cc)",
        ],
        "desc": "MCP server config injects malicious context or exfiltrates data",
    },
    {
        "id": "MCP-SUSPICIOUS-TRANSPORT",
        "severity": Severity.HIGH,
        "category": "poisoned_mcp",
        "globs": [
            "mcp.json", ".mcp.json", "mcp-servers.json",
            "**/mcp*.json", ".vscode/mcp.json",
        ],
        "patterns": [
            r"https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0).*mcp",
            r"wss?://(?!localhost|127\.0\.0\.1).*",
            r"port\s*:\s*(?!3000|8080|8000|5000|9000)\d{2,5}",
        ],
        "desc": "MCP server uses remote transport (potential data exfiltration)",
    },

    # ── 4. Guardrail-Disabling Project Configs ────────────────────────
    {
        "id": "GUARD-ESLINT-DISABLED",
        "severity": Severity.MEDIUM,
        "category": "guardrail_bypass",
        "globs": [
            ".eslintrc*", "eslint.config.*", ".eslintignore",
        ],
        "patterns": [
            r"\"rules\"\s*:\s*\{\s*\}",
            r"\"no-eval\"\s*:\s*['\"]?off",
            r"\"no-implied-eval\"\s*:\s*['\"]?off",
            r"\"no-new-func\"\s*:\s*['\"]?off",
            r"\"security/detect.*:\s*['\"]?off",
            r"\"@typescript-eslint/no-require-imports\"\s*:\s*['\"]?off",
            r"eslint-disable.*security",
        ],
        "desc": "ESLint security rules disabled or weakened",
    },
    {
        "id": "GUARD-PRETTIER-MALICIOUS",
        "severity": Severity.MEDIUM,
        "category": "guardrail_bypass",
        "globs": [".prettierrc*", "prettier.config.*"],
        "patterns": [
            r"plugin.*:\s*['\"]?\.",
            r"require.*\bchild_process\b",
        ],
        "desc": "Prettier config loads local plugin (potential code execution)",
    },
    {
        "id": "GUARD-PYPROJECT-DANGEROUS",
        "severity": Severity.HIGH,
        "category": "guardrail_bypass",
        "globs": ["pyproject.toml", "setup.cfg", "setup.py"],
        "patterns": [
            r"exec\s*\(",
            r"eval\s*\(",
            r"__import__\s*\(",
            r"subprocess\.(call|run|Popen)\(",
            r"os\.system\(",
            r"compile\s*\(.*exec\b",
            r"\[tool\.setuptools\.cmdclass\]",
        ],
        "desc": "Python project config contains code execution in build step",
    },
    {
        "id": "GUARD-NPM-LIFECYCLE",
        "severity": Severity.HIGH,
        "category": "guardrail_bypass",
        "globs": ["package.json"],
        "patterns": [
            r"\"preinstall\"\s*:\s*\".*curl",
            r"\"postinstall\"\s*:\s*\".*curl",
            r"\"preinstall\"\s*:\s*\".*wget",
            r"\"postinstall\"\s*:\s*\".*wget",
            r"\"preinstall\"\s*:\s*\".*eval",
            r"\"preinstall\"\s*:\s*\".*node\s+-e",
            r"\"prepublish\"\s*:\s*\".*curl",
            r"\"prepare\"\s*:\s*\".*curl",
        ],
        "desc": "npm lifecycle script performs exfiltration during install",
    },

    # ── 5. Cross-Tool Contamination ───────────────────────────────────
    {
        "id": "CROSS-VSCODE-MALICIOUS",
        "severity": Severity.HIGH,
        "category": "cross_tool_contamination",
        "globs": [".vscode/settings.json", ".vscode/tasks.json", ".vscode/launch.json"],
        "patterns": [
            r"terminal\.integrated\.shellArgs.*\b(curl|wget|nc)\b",
            r"code-runner\.executorMap.*\b(curl|wget)\b",
            r"terminal\.integrated\.env.*\b(TOKEN|SECRET|KEY)\b",
            r"preLaunchTask.*\b(curl|wget|eval)\b",
            r"postDebugTask.*\b(curl|wget|eval)\b",
        ],
        "desc": "VS Code config injects commands into terminal/debugger",
    },
    {
        "id": "CROSS-IDEA-MALICIOUS",
        "severity": Severity.HIGH,
        "category": "cross_tool_contamination",
        "globs": [".idea/*.xml", ".idea/**/*.xml"],
        "patterns": [
            r"<option\s+name=\"COMMAND\".*value=\".*\b(curl|wget|nc)\b",
            r"<component\s+name=\".*RunConfiguration\".*>.*\b(curl|wget)\b",
            r"make\spath=\".*\b(curl|wget)\b",
        ],
        "desc": "JetBrains IDE config injects malicious run configurations",
    },
    {
        "id": "CROSS-LINTER-EXEC",
        "severity": Severity.HIGH,
        "category": "cross_tool_contamination",
        "globs": [
            ".eslintrc*", "eslint.config.*",
            ".flake8", "setup.cfg", ".pylintrc",
            "tox.ini", ".rubocop.yml",
        ],
        "patterns": [
            r"exec\s*\(",
            r"subprocess",
            r"os\.system",
            r"__import__",
            r"eval\s*\(",
            r"require\s*\(\s*['\"]child_process",
        ],
        "desc": "Linter config contains executable code or imports",
    },
    {
        "id": "CROSS-FORMATTER-INJECT",
        "severity": Severity.MEDIUM,
        "category": "cross_tool_contamination",
        "globs": [".editorconfig"],
        "patterns": [
            r"curl|wget|eval|exec|system\(",
            r"https?://.*\.(sh|py|js|rb)\b",
        ],
        "desc": "Formatter config contains injected payload",
    },
    {
        "id": "CROSS-CICD-EXFIL",
        "severity": Severity.CRITICAL,
        "category": "cross_tool_contamination",
        "globs": [
            ".github/workflows/*.yml", ".github/workflows/*.yaml",
            ".gitlab-ci.yml", "Jenkinsfile", "azure-pipelines.yml",
            ".circleci/config.yml", "bitbucket-pipelines.yml",
            ".travis.yml",
        ],
        "patterns": [
            r"curl\s+.*\$\{\{\s*secrets\.",
            r"curl\s+.*\$[A-Z_]*(TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL)",
            r"wget\s+.*\$\{\{\s*secrets\.",
            r"cat\s+.*\.(env|pem|key|ssh).*\|.*curl",
            r"base64.*\$\{\{\s*secrets\.",
            r"curl\s+.*--data.*\$\{",
            r"webhook.*\$\{",
            r"https?://.*\.(xyz|tk|ml|ga|cf|top|cc).*\$\{",
        ],
        "desc": "CI/CD pipeline exfiltrates secrets to external endpoint",
    },

    # ── 6. Credential Exfiltration Patterns ───────────────────────────
    {
        "id": "CREDEXFIL-ENV-DUMP",
        "severity": Severity.CRITICAL,
        "category": "credential_exfiltration",
        "globs": [
            ".git/hooks/*", "hooks/*",
            "scripts/*", "bin/*",
        ],
        "patterns": [
            r"printenv\s*>",
            r"env\s*>.*\.(txt|log|tmp)",
            r"os\.environ\.items\(\)",
            r"process\.env\.\w+.*\b(curl|fetch|request)\b",
            r"cat\s+/proc/self/environ",
        ],
        "desc": "Script dumps environment variables (credential harvesting)",
    },
    {
        "id": "CREDEXFIL-NPM-SCRIPT",
        "severity": Severity.CRITICAL,
        "category": "credential_exfiltration",
        "globs": ["package.json"],
        "patterns": [
            r"\"(pre|post)?install\"\s*:.*\b(npm_config|process\.env)\b.*\b(fetch|http|request)\b",
            r"\"(pre|post)?install\"\s*:.*\b(npm_config_registry|npm_config_auth)\b",
            r"\"(pre|post)?install\"\s*:.*\.npmrc",
        ],
        "desc": "npm install script accesses and exfiltrates npm credentials",
    },
    {
        "id": "CREDEXFIL-DOCKER-SECRETS",
        "severity": Severity.HIGH,
        "category": "credential_exfiltration",
        "globs": ["Dockerfile*", "docker-compose*.yml", "docker-compose*.yaml"],
        "patterns": [
            r"ARG\s+(TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL)",
            r"ENV\s+(TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL)\s*=",
            r"RUN\s+.*cat\s+/run/secrets/",
            r"RUN\s+.*curl.*\b(TOKEN|SECRET|KEY|PASSWORD)\b",
            r"RUN\s+.*--mount=type=secret",
            r"ADD\s+.*\.env\b",
            r"COPY\s+.*\.env\b",
            r"COPY\s+.*\.pem\b",
            r"COPY\s+.*\.key\b",
        ],
        "desc": "Docker build leaks secrets via ARG/ENV or copies sensitive files",
    },
    {
        "id": "CREDEXFIL-HOOK-SSH",
        "severity": Severity.CRITICAL,
        "category": "credential_exfiltration",
        "globs": [".git/hooks/*", "hooks/*", "scripts/*"],
        "patterns": [
            r"\.ssh/(id_rsa|id_ed25519|authorized_keys|known_hosts)",
            r"\.aws/(credentials|config)",
            r"\.gnupg/",
            r"\.docker/config\.json",
            r"\.kube/config",
            r"\.netrc",
        ],
        "desc": "Script accesses sensitive credential files",
    },
    {
        "id": "CREDEXFIL-REVERSE-SHELL",
        "severity": Severity.CRITICAL,
        "category": "credential_exfiltration",
        "globs": [
            ".git/hooks/*", "hooks/*", "scripts/*", "bin/*",
            "Makefile", "Justfile",
        ],
        "patterns": [
            r"/dev/tcp/",
            r"bash\s+-i\s+>&\s+/dev/tcp",
            r"nc\s+-[a-z]*e\s+/bin/(ba)?sh",
            r"ncat\s+.*-e\s+/bin/(ba)?sh",
            r"python.*socket\.socket.*connect",
            r"mkfifo.*/tmp/.*\bnc\b",
        ],
        "desc": "Script establishes reverse shell connection",
    },
]

# Pre-compile all regex patterns
_COMPILED_RULES = []
for _rule in _RULES_RAW:
    _compiled = []
    for _pat in _rule["patterns"]:
        try:
            _compiled.append(re.compile(_pat, re.IGNORECASE))
        except re.error:
            pass
    _COMPILED_RULES.append((_rule, _compiled))


# ── File Scanning Engine ──────────────────────────────────────────────

def _match_glob(file_path: str, glob_pattern: str) -> bool:
    """Simple glob matching: ** for recursive, * for single segment."""
    fp = file_path.replace("\\", "/")
    gp = glob_pattern.replace("\\", "/")

    if "**" in gp:
        # Handle **/pattern and prefix/**/suffix
        parts = gp.split("**")
        prefix = parts[0].rstrip("/")
        suffix = parts[1].lstrip("/") if len(parts) > 1 else ""

        if prefix and not fp.startswith(prefix + "/") and fp != prefix:
            return False
        if suffix:
            # Match suffix anywhere in remaining path
            remaining = fp[len(prefix):].lstrip("/") if prefix else fp
            # Try matching at each directory level
            segments = remaining.split("/")
            for i in range(len(segments)):
                candidate = "/".join(segments[i:])
                import fnmatch
                if fnmatch.fnmatch(candidate, suffix):
                    return True
            return False
        return True

    if "*" in gp:
        import fnmatch
        return fnmatch.fnmatch(fp, gp)

    return fp == gp or fp.endswith("/" + gp) or fp.endswith(gp)


def _scan_file_content(file_path: str, rel_path: str, content: str) -> List[Finding]:
    """Scan a single file's content against all rules."""
    findings: List[Finding] = []
    lines = content.split("\n")

    for rule, compiled_patterns in _COMPILED_RULES:
        matched_glob = any(_match_glob(rel_path, g) for g in rule["globs"])
        if not matched_glob:
            continue

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") and "curl" not in stripped.lower():
                # skip empty/comment lines (except if they contain suspicious content)
                for pat in compiled_patterns:
                    if pat.search(line):
                        findings.append(Finding(
                            rule_id=rule["id"],
                            severity=rule["severity"],
                            category=rule["category"],
                            file_path=rel_path,
                            line_number=line_num,
                            description=rule["desc"],
                            evidence=stripped[:200],
                        ))
                        break
                continue

            for pat in compiled_patterns:
                if pat.search(line):
                    findings.append(Finding(
                        rule_id=rule["id"],
                        severity=rule["severity"],
                        category=rule["category"],
                        file_path=rel_path,
                        line_number=line_num,
                        description=rule["desc"],
                        evidence=stripped[:200],
                    ))
                    break  # one match per line per rule is enough

    return findings


def scan_repository(repo_path: Path) -> RiskAssessment:
    """Walk a repository and produce a full risk assessment."""
    findings: List[Finding] = []
    scanned = 0

    skip_dirs = {
        "node_modules", ".venv", "venv", "__pycache__",
        ".git/objects", ".git/refs", ".git/logs",
        "dist", "build", ".tox", ".mypy_cache",
    }

    for path in repo_path.rglob("*"):
        if not path.is_file():
            continue

        rel = str(path.relative_to(repo_path)).replace("\\", "/")

        # skip irrelevant dirs
        if any(rel.startswith(d + "/") or ("/" + d + "/") in rel for d in skip_dirs):
            continue

        # skip binary files (heuristic: > 1MB or known binary extensions)
        binary_exts = {
            ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2",
            ".ttf", ".eot", ".mp3", ".mp4", ".avi", ".mov", ".zip",
            ".tar", ".gz", ".bz2", ".7z", ".rar", ".exe", ".dll",
            ".so", ".dylib", ".bin", ".dat", ".db", ".sqlite",
        }
        if path.suffix.lower() in binary_exts:
            continue

        try:
            if path.stat().st_size > 1_000_000:  # 1MB
                continue
            content = path.read_text(errors="ignore")
        except (OSError, PermissionError):
            continue

        scanned += 1
        findings.extend(_scan_file_content(str(path), rel, content))

    # Deduplicate: same rule_id + file_path + line_number
    seen: Set[Tuple[str, str, Optional[int]]] = set()
    deduped: List[Finding] = []
    for f in findings:
        key = (f.rule_id, f.file_path, f.line_number)
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    findings = deduped

    return _compute_risk(findings, scanned)


def _compute_risk(findings: List[Finding], scanned: int) -> RiskAssessment:
    """Convert findings into a risk score and verdict."""
    severity_weights = {
        Severity.CRITICAL: 25,
        Severity.HIGH: 15,
        Severity.MEDIUM: 8,
        Severity.LOW: 3,
        Severity.INFO: 1,
    }

    critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in findings if f.severity == Severity.HIGH)
    medium = sum(1 for f in findings if f.severity == Severity.MEDIUM)
    low = sum(1 for f in findings if f.severity == Severity.LOW)

    raw_score = sum(severity_weights[f.severity] for f in findings)
    # Normalize: cap at 100
    score = min(100.0, raw_score)

    if critical > 0 or score >= 50:
        verdict = Verdict.UNSAFE
    elif high > 0 or score >= 25:
        verdict = Verdict.NEEDS_REVIEW
    else:
        verdict = Verdict.SAFE

    summary_parts = []
    if critical:
        summary_parts.append(f"{critical} CRITICAL")
    if high:
        summary_parts.append(f"{high} HIGH")
    if medium:
        summary_parts.append(f"{medium} MEDIUM")
    if low:
        summary_parts.append(f"{low} LOW")

    summary = f"Risk score {score:.0f}/100 ({verdict.value}). Found: {', '.join(summary_parts)}" if summary_parts else f"Risk score {score:.0f}/100 ({verdict.value}). No suspicious patterns found."

    return RiskAssessment(
        score=score,
        verdict=verdict,
        findings=findings,
        summary=summary,
        scanned_files=scanned,
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
    )


# ── Domain Solver Integration ─────────────────────────────────────────

@register_solver("code_assist")
class CodeAssistDomainSolver(BaseDomainSolver):
    """Solver for Coding Assistant Security — detects malicious context propagation."""

    @property
    def domain_type(self) -> str:
        return "code_assist"

    def analyze(self, request: AnalysisRequest) -> DomainAnalysisReport:
        target = request.target_resource
        repo_path = Path(target).expanduser()

        if not repo_path.exists():
            return DomainAnalysisReport(
                domain=self.domain_type,
                success=False,
                errors=[f"Target path does not exist: {target}"],
            )

        if not repo_path.is_dir():
            return DomainAnalysisReport(
                domain=self.domain_type,
                success=False,
                errors=[f"Target path is not a directory: {target}"],
            )

        assessment = scan_repository(repo_path)

        observations = []
        observations.append(f"📊 Repository Risk Assessment: {assessment.summary}")
        observations.append(f"Scanned {assessment.scanned_files} files")
        observations.append("")

        # Group findings by severity
        by_severity: Dict[str, List[Finding]] = {}
        for f in assessment.findings:
            by_severity.setdefault(f.severity.value, []).append(f)

        for sev in ["critical", "high", "medium", "low", "info"]:
            group = by_severity.get(sev, [])
            if not group:
                continue
            observations.append(f"{'🔴' if sev == 'critical' else '🟠' if sev == 'high' else '🟡' if sev == 'medium' else '🔵'} [{sev.upper()}] ({len(group)} findings)")
            for f in group:
                loc = f"{f.file_path}:{f.line_number}" if f.line_number else f.file_path
                observations.append(f"  [{f.rule_id}] {loc}")
                observations.append(f"    {f.description}")
                if f.evidence:
                    observations.append(f"    Evidence: {f.evidence}")
            observations.append("")

        return DomainAnalysisReport(
            domain=self.domain_type,
            success=True,
            observations=observations,
            metadata={
                "target": str(target),
                "risk_score": assessment.score,
                "verdict": assessment.verdict.value,
                "scanned_files": assessment.scanned_files,
                "total_findings": len(assessment.findings),
                "critical": assessment.critical_count,
                "high": assessment.high_count,
                "medium": assessment.medium_count,
                "low": assessment.low_count,
                "findings_detail": [
                    {
                        "rule_id": f.rule_id,
                        "severity": f.severity.value,
                        "category": f.category,
                        "file_path": f.file_path,
                        "line_number": f.line_number,
                        "description": f.description,
                        "evidence": f.evidence,
                    }
                    for f in assessment.findings
                ],
            },
        )
