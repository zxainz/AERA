"""Pattern-based static analysis + optional LLM deep review.

RULES are deliberately simple regex checks for well-known dangerous
constructs. They are a triage aid, not a dataflow analyzer: expect false
positives, which is exactly what the LLM review step and the fuzzing
stage exist to filter out.
"""
from __future__ import annotations

import re

RULES = [
    # ---- C / C++ ----
    {"id": "C-GETS", "languages": ("c", "cpp"),
     "pattern": r"\bgets\s*\(",
     "severity": "CRITICAL", "title": "gets() — unbounded input, always unsafe",
     "fix": "Use fgets() with an explicit buffer size."},
    {"id": "C-STRCPY", "languages": ("c", "cpp"),
     "pattern": r"\bstrcpy\s*\(",
     "severity": "HIGH", "title": "Unbounded strcpy()",
     "fix": "Use strncpy()/strlcpy() with explicit bounds, or validate lengths first."},
    {"id": "C-STRCAT", "languages": ("c", "cpp"),
     "pattern": r"\bstrcat\s*\(",
     "severity": "HIGH", "title": "Unbounded strcat()",
     "fix": "Use strncat()/strlcat() with explicit bounds."},
    {"id": "C-SPRINTF", "languages": ("c", "cpp"),
     "pattern": r"\bsprintf\s*\(",
     "severity": "HIGH", "title": "sprintf() without bounds checking",
     "fix": "Use snprintf() with the destination size."},
    {"id": "C-SCANF-S", "languages": ("c", "cpp"),
     "pattern": r"\bscanf\s*\([^)]*\"%s\"",
     "severity": "HIGH", "title": 'scanf("%s") without field width',
     "fix": 'Add a field width, e.g. scanf("%63s", buf).'},
    {"id": "C-SYSTEM", "languages": ("c", "cpp"),
     "pattern": r"\bsystem\s*\(",
     "severity": "HIGH", "title": "system() — shell command execution",
     "fix": "Avoid the shell; use exec-family calls with argument arrays."},
    {"id": "C-POPEN", "languages": ("c", "cpp"),
     "pattern": r"\bpopen\s*\(",
     "severity": "MEDIUM", "title": "popen() — shell command execution",
     "fix": "Avoid the shell where possible; sanitize any interpolated input."},
    # ---- Python ----
    {"id": "PY-EVAL", "languages": ("python",),
     "pattern": r"\beval\s*\(",
     "severity": "CRITICAL", "title": "eval() on potentially untrusted input",
     "fix": "Use ast.literal_eval() for data, or refactor to avoid eval."},
    {"id": "PY-EXEC", "languages": ("python",),
     "pattern": r"\bexec\s*\(",
     "severity": "CRITICAL", "title": "exec() on potentially untrusted input",
     "fix": "Refactor to avoid dynamic code execution."},
    {"id": "PY-OS-SYSTEM", "languages": ("python",),
     "pattern": r"\bos\.system\s*\(",
     "severity": "HIGH", "title": "os.system() — shell injection risk",
     "fix": "Use subprocess.run() with an argument list and shell=False."},
    {"id": "PY-SHELL-TRUE", "languages": ("python",),
     "pattern": r"shell\s*=\s*True",
     "severity": "HIGH", "title": "subprocess with shell=True",
     "fix": "Use shell=False with an argument list."},
    {"id": "PY-PICKLE", "languages": ("python",),
     "pattern": r"\bpickle\.loads?\s*\(",
     "severity": "HIGH", "title": "pickle deserialization of untrusted data",
     "fix": "Use a safe format (JSON); never unpickle untrusted input."},
    {"id": "PY-YAML-LOAD", "languages": ("python",),
     "pattern": r"\byaml\.load\s*\(",
     "severity": "MEDIUM", "title": "yaml.load without SafeLoader",
     "fix": "Use yaml.safe_load()."},
    # ---- JavaScript ----
    {"id": "JS-EVAL", "languages": ("javascript",),
     "pattern": r"\beval\s*\(",
     "severity": "CRITICAL", "title": "eval() on potentially untrusted input",
     "fix": "Use JSON.parse() for data; avoid dynamic code execution."},
    {"id": "JS-NEW-FUNCTION", "languages": ("javascript",),
     "pattern": r"\bnew\s+Function\s*\(",
     "severity": "HIGH", "title": "new Function() — dynamic code execution",
     "fix": "Refactor to avoid constructing functions from strings."},
    {"id": "JS-INNERHTML", "languages": ("javascript",),
     "pattern": r"\binnerHTML\s*=",
     "severity": "MEDIUM", "title": "innerHTML assignment — XSS sink",
     "fix": "Use textContent or sanitize HTML before assignment."},
    {"id": "JS-EXEC", "languages": ("javascript",),
     "pattern": r"\bexec\s*\(",
     "severity": "HIGH", "title": "child_process.exec with string command",
     "fix": "Use execFile() with an argument array."},
]

_COMPILED = [
    {**rule, "regex": re.compile(rule["pattern"])} for rule in RULES
]


def scan_text(language: str, rel_path: str, text: str) -> list[dict]:
    """Return findings for one file."""
    findings = []
    lines = text.splitlines()
    for rule in _COMPILED:
        if language not in rule["languages"]:
            continue
        for match in rule["regex"].finditer(text):
            line_no = text.count("\n", 0, match.start()) + 1
            snippet = lines[line_no - 1].strip()[:200] if line_no <= len(lines) else ""
            findings.append({
                "rule_id": rule["id"],
                "title": rule["title"],
                "severity": rule["severity"],
                "fix": rule["fix"],
                "file": rel_path,
                "line": line_no,
                "snippet": snippet,
            })
    return findings


def scan_codebase(target, *, engine: str = "auto") -> list[dict]:
    """Scan every file in a CodebaseTarget. Returns flat finding list.

    engine: "auto" (semgrep if installed, else regex), "semgrep", "regex".
    """
    if engine in ("auto", "semgrep"):
        try:
            from .semgrep import SemgrepError, run_semgrep, semgrep_to_findings
            return semgrep_to_findings(run_semgrep(target.root))
        except SemgrepError:
            if engine == "semgrep":
                raise
        except (OSError, ValueError):
            if engine == "semgrep":
                raise
    findings: list[dict] = []
    for f in target.iter_files():
        findings.extend(scan_text(f["language"], f["path"], f["text"]))
    return findings


REVIEW_SYSTEM_PROMPT = """\
You are a defensive application-security reviewer. Given a static-analysis
finding and the surrounding code, decide whether it is a REAL,
exploitable-in-practice issue or a FALSE POSITIVE. Reply in exactly this
format:

VERDICT: REAL or FALSE_POSITIVE
WHY: one or two sentences.
CRASH PATH: if REAL, describe how untrusted input could reach this line;
if FALSE_POSITIVE, say what makes it safe.
"""


def review_finding(llm, finding: dict, file_text: str) -> dict:
    """Ask the LLM to confirm or dismiss one finding. Returns review dict."""
    lines = file_text.splitlines()
    start = max(0, finding["line"] - 11)
    end = min(len(lines), finding["line"] + 10)
    context = "\n".join(
        f"{i + 1:4d}: {lines[i]}" for i in range(start, end)
    )
    response = llm.complete(
        REVIEW_SYSTEM_PROMPT,
        f"Finding: {finding['rule_id']} — {finding['title']} "
        f"(severity {finding['severity']})\n"
        f"File: {finding['file']}, line {finding['line']}\n\n"
        f"Code context:\n{context}",
    )
    verdict = "UNCERTAIN"
    upper = response.upper()
    if "FALSE_POSITIVE" in upper and "VERDICT: REAL" not in upper:
        verdict = "FALSE_POSITIVE"
    elif "VERDICT: REAL" in upper:
        verdict = "REAL"
    return {"finding": finding, "verdict": verdict, "review": response.strip()}
