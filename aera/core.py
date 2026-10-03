"""Main AERA pipeline: authorize -> fetch CVE -> analyze -> draft PoC -> test -> report.

Every stage is gated on a valid authorization token, and every action is
audit-logged. Sandbox testing can be disabled via AERA_SANDBOX_ENABLED=false
(for analysis-only runs), but is on by default.

v2 improvements:
- vuln_type="auto" (default): inferred from the CVE's CWEs.
- PoC self-healing: a crashing or verdict-less PoC is fed back to the model
  for a fix, up to AERA_POC_RETRIES times (default 1).
- verify_fix(): re-run a saved PoC later to confirm a patch worked.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from .audit import AuditLogger
from .authorization import AuthorizationManager
from .codebase import CodebaseTarget
from .coverage import CoverageError, run_coverage_campaign
from .fuzz import SandboxFuzzRunner, run_campaign, seeds_for_findings
from .grammar import GENERATORS
from .intel import enrich as enrich_intel
from .llm import LLMProvider, OpenAICompatibleProvider, provider_from_env
from .report_generator import generate_codebase_report, generate_markdown_report
from .sandbox import SandboxError, SandboxManager
from .sarif import write_sarif
from .static import review_finding, scan_codebase
from .triage import dedupe, reproduce
from .utils import CVEFetchError, detect_vuln_type, get_cve_details

ANALYSIS_SYSTEM_PROMPT = """\
You are a defensive security research assistant. Your job is to analyze a
vulnerability report and explain, for authorized defenders:
1. The root cause in plain terms.
2. The preconditions an attacker would need (access, version, config).
3. Why the vulnerable code/config behaves this way (educational depth).
4. Which mitigations and patches actually fix it, and why.
You do NOT provide weaponized exploit code. You describe mechanisms so
defenders can validate and remediate.
"""

POC_SYSTEM_PROMPT = """\
You are a defensive security research assistant helping an authorized tester
validate a vulnerability in an ISOLATED lab container. Produce a minimal,
clearly-commented proof-of-concept script (Python) that DEMONSTRATES the
vulnerability's mechanism against a local test target -- e.g. triggering
the vulnerable code path and printing observable evidence.

Rules:
- Target ONLY the local lab container (127.0.0.1 / localhost), never external hosts.
- Keep it minimal and readable: this is for validation and education, not weaponization.
- Comment each step explaining what it does and why.
- No persistence, no lateral movement, no obfuscation, no anti-analysis tricks.
- End by printing a clear verdict line: "VULNERABLE: <evidence>" or "NOT VULNERABLE".
"""

POC_FIX_PROMPT = """\
The previous proof-of-concept attempt FAILED when executed in the isolated
lab container. Diagnose the failure from the output below and return the
COMPLETE corrected Python script (not a diff, the full script).

Previous attempt output:
--- STDOUT ---
{stdout}
--- STDERR ---
{stderr}
--- exit code: {exit_code} ---

Same rules as before: localhost only, minimal, clearly commented, and end
with a verdict line: "VULNERABLE: <evidence>" or "NOT VULNERABLE".
"""


def _needs_fix(test_result: dict) -> bool:
    """True when the PoC run is worth retrying with model feedback."""
    if test_result.get("error"):
        return False  # infrastructure failure -- retrying the PoC won't help
    if test_result.get("exit_code", -1) != 0:
        return True  # crashed
    return test_result.get("verdict") == "unknown"  # ran, but no verdict line


def build_poc_prompt(cve: dict, analysis: str, lab_note: str = "",
                     target_info: str = "") -> str:
    """Assemble the PoC-generation prompt (pure: easy to unit-test).

    `target_info` holds tester-observed facts about the real target
    (banners, headers, tech stack). It tunes the PoC to the actual target
    while the sandbox rules (localhost-only) still apply.
    """
    prompt = (
        f"Write a minimal validation PoC for:\n\nCVE: {cve['id']}\n"
        f"Description: {cve['description']}\nCWEs: {cve['cwes']}\n"
        f"Analysis: {analysis[:4000]}{lab_note}"
    )
    if target_info.strip():
        prompt += (
            "\n\nTarget facts observed by the tester (tune the PoC to this "
            "technology/behavior; the sandbox's localhost-only rule still "
            "applies):\n" + target_info.strip()[:2000]
        )
    return prompt


def _call_catches(fn, data: bytes) -> bool:
    """True if calling fn(data) raises (used for in-process reproduce checks)."""
    try:
        fn(data)
        return False
    except Exception:  # noqa: BLE001 - any escape counts as a crash here
        return True


def _clean_code_fence(code: str) -> str:
    """Extract code from markdown code fences if wrapped by the LLM."""
    code = code.strip()
    if code.startswith("```"):
        lines = code.splitlines()
        if len(lines) >= 2 and lines[-1].strip() == "```":
            return "\n".join(lines[1:-1]).strip()
    return code


class AutonomousExploitResearchAssistant:
    def __init__(
        self,
        api_key: str | None = None,
        *,
        llm: LLMProvider | None = None,
        sandbox_enabled: bool | None = None,
    ) -> None:
        if api_key:
            os.environ["AERA_LLM_API_KEY"] = api_key
            if llm is None:
                llm = OpenAICompatibleProvider(api_key=api_key)
        self.authorization = AuthorizationManager()
        self.audit = AuditLogger()
        self._llm = llm  # built lazily: `verify_fix` needs no API key
        self.sandbox_enabled = (
            os.environ.get("AERA_SANDBOX_ENABLED", "true").lower() == "true"
            if sandbox_enabled is None
            else sandbox_enabled
        )
        self._sandbox: SandboxManager | None = None

    @property
    def glm(self) -> LLMProvider:
        """Alias for PDF specification compatibility."""
        return self.llm

    @property
    def docker(self):
        """Alias for PDF specification compatibility."""
        return self.sandbox.client

    @property
    def llm(self) -> LLMProvider:
        if self._llm is None:
            self._llm = provider_from_env()
        return self._llm

    @llm.setter
    def llm(self, value: LLMProvider) -> None:
        self._llm = value

    @property
    def sandbox(self) -> SandboxManager:
        if self._sandbox is None:
            self._sandbox = SandboxManager()
        return self._sandbox

    async def process_vulnerability(
        self,
        cve_id: str | dict,
        user_token: str,
        *,
        cve_data: dict | None = None,
        vuln_type: str = "auto",
        intel: bool = True,
        lab_context: bool = True,
        target_info: str = "",
    ) -> dict:
        """Run the full pipeline. Raises AuthorizationError / CVEFetchError.

        Supports CVE IDs or custom vulnerability findings (e.g. bug bounty reports).
        `target_info`: free-text facts the tester observed about the real
        target (server banner, headers, tech stack). It is injected into
        the PoC prompt so the first draft is tuned to the actual target;
        audit-logged like everything else.
        """
        # Step 1: verify authorization (fail-closed)
        claims = self.authorization.validate(user_token)
        actor = claims.get("sub", claims.get("user_id", "unknown"))
        cid_str = cve_id if isinstance(cve_id, str) else cve_id.get("id", "CUSTOM-VULN")
        self.audit.log("pipeline_started", actor, cve_id=cid_str)

        # Step 2: CVE / Finding details
        if isinstance(cve_id, dict):
            cve = cve_id
        elif cve_data is not None:
            cve = cve_data
        else:
            cve = await asyncio.to_thread(get_cve_details, cve_id)
        cid = cve.get("id", cid_str)
        self.audit.log("cve_fetched", actor, cve_id=cid)

        # Step 2b: threat-intel enrichment (advisory, fail-open)
        intel_data: dict | None = None
        if intel and cid.startswith("CVE-"):
            intel_data = await asyncio.to_thread(enrich_intel, cid)
            self.audit.log("intel_enriched", actor, cve_id=cid)
        intel_note = ""
        if intel_data:
            kev = intel_data.get("kev")
            epss = intel_data.get("epss") or {}
            intel_note = (
                f"\nThreat intel for prioritization: "
                f"CISA KEV listed: {'YES' if kev else 'no'}; "
                f"EPSS score: {epss.get('score', 'n/a')} "
                f"(percentile {epss.get('percentile', 'n/a')}). "
                f"Weigh this when recommending patch priority."
            )

        # Step 2c: resolve lab type + fingerprint (grounds the PoC)
        if vuln_type == "auto":
            vuln_type = detect_vuln_type(cve)
            self.audit.log(
                "vuln_type_detected", actor, cve_id=cve["id"], vuln_type=vuln_type
            )
        lab_note = ""
        if self.sandbox_enabled and lab_context:
            try:
                lab = await asyncio.to_thread(self.sandbox.describe_lab, vuln_type)
                runtime = lab.get("runtime", {})
                lab_note = (
                    f"\nLab container facts (the ONLY target you may assume): "
                    f"image={lab.get('image')}, os/arch={lab.get('os')}/{lab.get('arch')}, "
                    f"kernel={runtime.get('kernel')}, {runtime.get('python')}, "
                    f"user={runtime.get('user')}, exposed_ports={lab.get('exposed_ports')}."
                )
                self.audit.log("lab_fingerprinted", actor, cve_id=cve["id"])
            except SandboxError as exc:
                self.audit.log(
                    "lab_fingerprint_failed", actor, cve_id=cve["id"], error=str(exc)
                )

        # Step 3: LLM analysis
        analysis = await asyncio.to_thread(
            self.llm.complete,
            ANALYSIS_SYSTEM_PROMPT,
            f"Analyze this CVE for defensive research:\n\n{cve}{intel_note}",
        )
        self.audit.log("analysis_done", actor, cve_id=cve["id"])

        # Steps 4+5: draft PoC and test, with self-healing retries
        poc: str | None = None
        test_result: dict | None = None
        attempts: list[dict] = []
        if self.sandbox_enabled:
            max_attempts = 1 + int(os.environ.get("AERA_POC_RETRIES", "1"))
            if target_info.strip():
                self.audit.log("target_info_used", actor, cve_id=cve["id"])
            base_prompt = build_poc_prompt(cve, analysis, lab_note, target_info)
            user_prompt = base_prompt
            for attempt in range(1, max_attempts + 1):
                raw_poc = await asyncio.to_thread(
                    self.llm.complete, POC_SYSTEM_PROMPT, user_prompt
                )
                poc = _clean_code_fence(raw_poc)
                self.audit.log(
                    "poc_drafted", actor, cve_id=cve["id"], attempt=attempt
                )
                try:
                    test_result = await asyncio.to_thread(
                        self.sandbox.test_poc, vuln_type, poc, actor=actor
                    )
                except SandboxError as exc:
                    test_result = {"error": str(exc)}
                    self.audit.log(
                        "poc_test_failed", actor, cve_id=cve["id"], error=str(exc)
                    )
                    break
                self.audit.log(
                    "poc_tested", actor, cve_id=cve["id"], attempt=attempt,
                    exit_code=test_result.get("exit_code"),
                    verdict=test_result.get("verdict"),
                )
                attempts.append(
                    {"attempt": attempt, "exit_code": test_result.get("exit_code"),
                     "verdict": test_result.get("verdict")}
                )
                if not _needs_fix(test_result) or attempt == max_attempts:
                    break
                # Self-heal: show the model what went wrong and ask for a fix.
                user_prompt = POC_FIX_PROMPT.format(
                    stdout=test_result.get("stdout", "")[:2000],
                    stderr=test_result.get("stderr", "")[:2000],
                    exit_code=test_result.get("exit_code"),
                )
                self.audit.log(
                    "poc_retrying", actor, cve_id=cve["id"], attempt=attempt + 1
                )

        # Step 6: educational report
        report_md = generate_markdown_report(
            cve, analysis, poc, test_result, intel_data, attempts=attempts
        )
        self.audit.log("report_generated", actor, cve_id=cve["id"])

        return {
            "cve": cve,
            "analysis": analysis,
            "poc": poc,
            "exploit": poc,  # PDF specification compatibility
            "test_result": test_result,
            "attempts": attempts,
            "intel": intel_data,
            "report_markdown": report_md,
        }

    async def verify_fix(
        self, saved: str | os.PathLike | dict, user_token: str, *, vuln_type: str = "auto"
    ) -> dict:
        """Re-run a previously saved PoC to confirm a patch fixed the issue.

        `saved` is a batch-output JSON path (or its parsed dict). No LLM
        involved, so no API key is needed.
        """
        claims = self.authorization.validate(user_token)
        actor = claims.get("sub", "unknown")
        if isinstance(saved, dict):
            data = saved
        else:
            data = json.loads(Path(saved).read_text(encoding="utf-8"))
        poc = data.get("poc")
        cve = data.get("cve") or {}
        cve_id = cve.get("id", "unknown")
        if not poc:
            raise ValueError(f"No PoC found in saved result for {cve_id}.")
        if vuln_type == "auto":
            vuln_type = detect_vuln_type(cve)
        self.audit.log("fix_verification_started", actor, cve_id=cve_id)
        test_result = await asyncio.to_thread(
            self.sandbox.test_poc, vuln_type, poc, actor=actor
        )
        self.audit.log(
            "fix_verification_done", actor, cve_id=cve_id,
            verdict=test_result.get("verdict"),
            exit_code=test_result.get("exit_code"),
        )
        return {
            "cve_id": cve_id,
            "verdict": test_result.get("verdict"),
            "test_result": test_result,
        }

    # ------------------------------------------------------------------
    # Codebase pipeline: the five-function framework
    #  1. Vulnerability Analysis  (ingest + static scan [+ LLM review])
    #  2. Automated Test Gen      (seeds from findings + mutation)
    #  3. Isolated Execution      (sandboxed fuzz campaign)
    #  4. Verification & Triage   (reproduce + dedupe crashes)
    #  5. Reporting & Remediation (structured report)
    # ------------------------------------------------------------------

    def _run_fuzz_campaign(self, target: CodebaseTarget, seeds: list[bytes],
                           iterations: int, image: str,
                           target_cmd: list[str]) -> list[dict]:
        """Synchronous fuzz+triage block (runs inside asyncio.to_thread)."""
        with SandboxFuzzRunner(
            self.sandbox, image=image, target_dir=target.root, argv=target_cmd
        ) as runner:
            raw_crashes = run_campaign(runner.run_once, seeds, iterations)
            unique = dedupe(raw_crashes)
            for bug in unique:
                bug["reproducible"] = reproduce(
                    runner.run_once, bug["example"]["input"], times=3
                )
        return unique

    async def analyze_codebase(
        self,
        path: str,
        user_token: str,
        *,
        target_cmd: list[str] | None = None,
        fuzz: bool = False,
        iterations: int = 200,
        llm_review: bool = False,
        max_reviews: int = 10,
        image: str | None = None,
        engine: str = "auto",
        sarif_path: str | None = None,
        grammar: str | None = None,
        coverage: bool = False,
        pyfunc: str | None = None,
        dyn_verify: bool = False,
    ) -> dict:
        """Run the five-function pipeline over a local source tree.

        - `target_cmd`: how to run the target, e.g. ["./vuln"] (stdin) or
          ["python3", "harness.py", "{input}"]. Required when fuzz=True.
        - `engine`: "auto" (semgrep if installed, else built-in rules),
          "semgrep", or "regex".
        - `grammar`: "json" or "http" — seed the campaign with structured
          inputs on top of finding-derived seeds.
        - `coverage`: coverage-guided in-process fuzzing of a Python
          function; requires `pyfunc="module:func"`. Needs Python 3.12+.
        - `sarif_path`: also write findings+crashes as SARIF 2.1.0.
        - Findings, crashes, and every stage are audit-logged.
        """
        claims = self.authorization.validate(user_token)
        actor = claims.get("sub", "unknown")
        self.audit.log("codebase_scan_started", actor, path=str(path))

        # 1. Vulnerability Analysis: ingest + static scan
        target = await asyncio.to_thread(CodebaseTarget, path)
        stats = target.stats()
        findings = await asyncio.to_thread(scan_codebase, target, engine=engine)
        self.audit.log("static_scan_done", actor,
                       files=stats["files"], findings=len(findings),
                       engine=engine)

        # 1b. Optional LLM deep review of the top findings
        reviews: list[dict] = []
        if llm_review and findings:
            severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
            top = sorted(findings,
                         key=lambda f: severity_rank.get(f["severity"], 3))[:max_reviews]
            texts = {f["path"]: f["text"] for f in target.iter_files()}
            for finding in top:
                review = await asyncio.to_thread(
                    review_finding, self.llm, finding,
                    texts.get(finding["file"], ""),
                )
                reviews.append(review)
            self.audit.log("llm_review_done", actor, reviewed=len(reviews))

        # 1c. Optional dynamic verification of top static findings
        if dyn_verify and findings:
            from .dynverify import verify_findings

            try:
                findings = await asyncio.to_thread(
                    verify_findings, findings, target.root,
                    self.llm, self.sandbox, actor=actor,
                )
                n_conf = sum(1 for f in findings
                             if f.get("dynamic_verdict") == "confirmed")
                self.audit.log("dyn_verify_done", actor, confirmed=n_conf)
            except Exception as exc:  # noqa: BLE001 - best-effort layer
                self.audit.log("dyn_verify_failed", actor, error=str(exc))

        # 2-4. Test generation + isolated execution + triage
        crashes: list[dict] = []
        coverage_info: dict | None = None
        if coverage:
            if not pyfunc or ":" not in pyfunc:
                raise ValueError(
                    'coverage=True requires pyfunc="module:function"')
            crashes, coverage_info = await asyncio.to_thread(
                self._run_coverage_campaign, pyfunc,
                seeds_for_findings(findings), iterations, actor,
            )
        elif fuzz:
            if not target_cmd:
                raise ValueError(
                    "fuzz=True requires target_cmd, e.g. ['./vuln'] or "
                    "['python3', 'harness.py', '{input}']"
                )
            seeds = seeds_for_findings(findings)
            if grammar:
                if grammar not in GENERATORS:
                    raise ValueError(f"Unknown grammar {grammar!r}; "
                                     f"choose from {sorted(GENERATORS)}")
                import random as _random
                gen, grng = GENERATORS[grammar](), _random.Random(0)
                seeds = [gen.generate(grng) for _ in range(16)] + seeds
                self.audit.log("grammar_seeds_done", actor, grammar=grammar)
            img = image or self.sandbox.templates.get("binary",
                                                      SandboxManager.FALLBACK_IMAGE)
            self.audit.log("fuzz_campaign_started", actor,
                           iterations=iterations, seeds=len(seeds))
            crashes = await asyncio.to_thread(
                self._run_fuzz_campaign, target, seeds, iterations, img,
                target_cmd,
            )
            self.audit.log("fuzz_campaign_done", actor,
                           unique_bugs=len(crashes),
                           reproducible=sum(1 for c in crashes if c["reproducible"]))

        # SARIF export (findings + crashes)
        if sarif_path:
            await asyncio.to_thread(write_sarif, sarif_path, findings, crashes)
            self.audit.log("sarif_written", actor, path=str(sarif_path))

        # 5. Reporting
        report_md = generate_codebase_report(
            stats, findings, reviews, crashes, iterations if (fuzz or coverage) else 0
        )
        self.audit.log("codebase_report_generated", actor, path=str(path))

        return {
            "stats": stats,
            "findings": findings,
            "reviews": reviews,
            "crashes": crashes,
            "coverage": coverage_info,
            "report_markdown": report_md,
        }

    def _run_coverage_campaign(self, pyfunc: str, seeds: list[bytes],
                              iterations: int, actor: str) -> tuple[list[dict], dict]:
        """Coverage-guided in-process campaign over a Python function."""
        import importlib

        module_name, func_name = pyfunc.split(":", 1)
        try:
            module = importlib.import_module(module_name)
        except ImportError as exc:
            raise CoverageError(f"Cannot import {module_name!r}: {exc}") from exc
        fn = getattr(module, func_name, None)
        if not callable(fn):
            raise CoverageError(f"{pyfunc!r} is not a callable")
        filenames = [module.__file__] if getattr(module, "__file__", None) else []
        self.audit.log("coverage_campaign_started", actor, pyfunc=pyfunc,
                       iterations=iterations)
        result = run_coverage_campaign(fn, seeds, iterations, filenames=filenames)
        unique = dedupe(result["crashes"])
        for bug in unique:
            data = bug["example"]["input"]
            bug["reproducible"] = all(
                _call_catches(fn, data) for _ in range(3)
            )
        self.audit.log("coverage_campaign_done", actor,
                       unique_bugs=len(unique),
                       lines_covered=result["lines_covered"])
        return unique, {"lines_covered": result["lines_covered"],
                        "corpus_size": result["corpus_size"]}
