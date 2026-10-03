"""Session-aware web/API fuzzing for authorized lab targets.

Real web apps sit behind login. This module establishes a session once
(form POST), then fuzzes endpoint parameters with detection payloads and
flags anomalies: HTTP 500s, stack traces / SQL errors in responses, and
response-time spikes.

Only ever touches the operator-supplied target URL (your authorized lab
app). Bounded iterations, per-request timeouts, no crawling.
"""
from __future__ import annotations

import os
import random
import statistics
import time
from urllib.parse import parse_qsl, urlencode

import requests

ERROR_KEYWORDS = (
    # Python
    "Traceback (most recent call last)",
    "IndexError: ",
    "ZeroDivisionError: ",
    # Java
    "Stack trace:",
    "NullPointerException",
    "PSQLException",
    "Exception in thread",
    "java.lang.IllegalArgumentException",
    # SQL databases
    "SQL syntax",
    "mysql_fetch",
    "ODBC Driver",
    "ORA-",
    "SQLite/JDBCDriver",
    "sqlite3.OperationalError",
    "pg_query(): Query failed",
    "Microsoft OLE DB Provider for SQL Server",
    "Unclosed quotation mark",
    # PHP / generic
    "Fatal error",
    "Warning: ",
    "Parse error: ",
    # Unix / Traversal / Command leaks
    "root:x:0:0:",
    "[boot loader]",
    "[operating systems]",
)


def detection_payloads() -> list[str]:
    """Comprehensive benign detection payloads across major vulnerability classes."""
    return [
        # SQL Injection probes
        "'",
        '"',
        "'; --",
        "') OR ('1'='1",
        "' OR '1'='1",
        '" OR "1"="1',
        "1' ORDER BY 1--+",
        # Template Injection (SSTI)
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
        # Directory / Path Traversal
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "../../../../../../../../etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        # Command Injection delimiters
        "; id",
        "| id",
        "`id`",
        "$(id)",
        "& whoami",
        # XSS / HTML Injection
        "<script>alert(1)</script>",
        '"><img src=x onerror=alert(1)>',
        "javascript:alert(1)",
        # Format Strings & Null Bytes
        "%s%s%s%s%n",
        "%x%x%x%x",
        "\x00",
        # Header / CRLF Injection
        "\r\nTest-Header: aera-injected",
        "%0d%0aSet-Cookie: aera=1",
        # Numeric & Buffer Overflows
        "A" * 100,
        "A" * 5000,
        "-1",
        "0",
        "999999999999999999999",
        "-9223372036854775808",
    ]


class WebFuzzer:
    def __init__(self, *, timeout_s: int = 15, user_agent: str = "AERA-webfuzz/0.6"):
        self.session = requests.Session()
        self.session.headers["User-Agent"] = user_agent
        self.timeout_s = timeout_s
        self.authenticated = False

    def login(self, login_url: str, data: str, *, check: str = "") -> bool:
        """POST form credentials; verify via `check` string in a follow-up GET."""
        fields = dict(parse_qsl(data, keep_blank_values=True))
        resp = self.session.post(login_url, data=fields, timeout=self.timeout_s,
                                 allow_redirects=True)
        if check:
            probe = self.session.get(login_url, timeout=self.timeout_s)
            self.authenticated = check in probe.text or check in resp.text
        else:
            self.authenticated = resp.status_code < 400
        return self.authenticated

    def _baseline(self, method: str, url: str, params: dict) -> dict:
        times, statuses, lengths = [], [], []
        for _ in range(3):
            t0 = time.monotonic()
            r = self._send(method, url, params)
            dt = time.monotonic() - t0
            times.append(dt)
            statuses.append(r.status_code)
            lengths.append(len(r.content))
        return {
            "median_time": statistics.median(times),
            "status": statistics.mode(statuses),
            "median_len": statistics.median(lengths),
        }

    def _send(self, method: str, url: str, params: dict) -> requests.Response:
        if method.upper() == "GET":
            return self.session.get(url, params=params, timeout=self.timeout_s)
        return self.session.post(url, data=params, timeout=self.timeout_s)

    def fuzz_params(self, url: str, params: list[str], *,
                    method: str = "GET", iterations: int = 200,
                    seed: int = 0) -> list[dict]:
        """Fuzz each named parameter; return anomaly findings."""
        rng = random.Random(seed)
        payloads = detection_payloads()
        base_params = {p: "aera" for p in params}
        baseline = self._baseline(method, url, base_params)
        findings: list[dict] = []
        for i in range(iterations):
            param = rng.choice(params)
            mutated = dict(base_params)
            mutated[param] = rng.choice(payloads)
            t0 = time.monotonic()
            try:
                r = self._send(method, url, mutated)
            except requests.RequestException as exc:
                findings.append(self._finding(
                    url, method, param, mutated[param], "request-error",
                    f"request failed: {exc}", i))
                continue
            dt = time.monotonic() - t0
            body = r.text[:20000]
            if r.status_code >= 500:
                findings.append(self._finding(
                    url, method, param, mutated[param], "http-500",
                    f"HTTP {r.status_code} (baseline {baseline['status']})", i))
            elif any(k in body for k in ERROR_KEYWORDS):
                kw = next(k for k in ERROR_KEYWORDS if k in body)
                findings.append(self._finding(
                    url, method, param, mutated[param], "error-disclosure",
                    f"error keyword in response: {kw!r}", i))
            elif (baseline["median_time"] > 0.05
                  and dt > 5 * baseline["median_time"]):
                findings.append(self._finding(
                    url, method, param, mutated[param], "time-anomaly",
                    f"{dt:.2f}s vs baseline {baseline['median_time']:.2f}s", i))
        return findings

    @staticmethod
    def _finding(url: str, method: str, param: str, payload: str,
                 kind: str, evidence: str, iteration: int) -> dict:
        return {
            "endpoint": url,
            "method": method.upper(),
            "param": param,
            "payload_preview": payload[:80],
            "kind": kind,
            "evidence": evidence,
            "iteration": iteration,
            "severity": "HIGH" if kind in ("http-500", "error-disclosure") else "MEDIUM",
        }


def run_webfuzz(url: str, params: list[str], *,
                method: str = "GET", iterations: int = 200,
                login_url: str | None = None, login_data: str = "",
                login_check: str = "", seed: int = 0) -> dict:
    """Establish session (optional), fuzz, return findings + session status."""
    fuzzer = WebFuzzer()
    logged_in = None
    if login_url:
        logged_in = fuzzer.login(login_url, login_data or os.environ.get(
            "AERA_LAB_LOGIN_DATA", ""), check=login_check)
    findings = fuzzer.fuzz_params(url, params, method=method,
                                  iterations=iterations, seed=seed)
    return {"url": url, "authenticated": logged_in,
            "findings": findings, "iterations": iterations}
