# AERA Plan v2 — Improvements Over the Original Design

This document records what changed between the original plan (Google Doc)
and the implementation, and why.

## Bugs found during implementation

1. **Sandbox exit codes were meaningless.** The runner script ended with
   `echo EXIT:$?`, so `sh -c` always exited 0 — every PoC "passed."
   Fixed: the real exit code is now parsed from the `EXIT:` marker in
   stdout (`aera/sandbox.py::parse_run_output`).
2. **`enrich()` silently dropped a passed-in KEV catalog.** `KEVCatalog`
   defines `__len__`, so `kev or KEVCatalog()` evaluated a valid-but-empty
   catalog as falsy. Fixed with an explicit `is not None` check.

## Robustness upgrades

3. **PoC self-healing loop.** A PoC that crashes (nonzero exit) or prints no
   verdict is fed back to the model with its stdout/stderr and retried, up
   to `AERA_POC_RETRIES` times (default 1 extra attempt). A clean
   "NOT VULNERABLE" is *not* retried — that's a valid negative result.
   Every attempt is audit-logged and listed in the report.
4. **LLM retries with exponential backoff.** One transient API failure no
   longer kills a pipeline run or batch item (`max_retries=3`).
5. **NVD API key support** (`AERA_NVD_API_KEY`) for heavy batch use; the
   public 5-req/30s limit is otherwise respected with backoff.
6. **Verdict extraction.** The PoC's own `VULNERABLE:` / `NOT VULNERABLE`
   line is parsed into `test_result["verdict"]` and shown prominently in
   reports and the dashboard.

## Workflow upgrades

7. **Vuln-type auto-detection.** `vuln_type="auto"` (now the default)
   infers `binary` vs `web` from the CVE's CWEs. `network` stays manual.
8. **`aera verify` — patch verification.** Re-run a saved PoC from a
   batch JSON to confirm a patch actually fixed the issue. Needs no LLM
   key: `aera verify batch-out/CVE-2021-44228.json --token <TOKEN>`.
   Exit code 0 means "not vulnerable anymore."
9. **Analysis-only mode** (`--no-sandbox`): skips PoC drafting *and*
   testing — triage without generating or executing anything.
10. **Dashboard sorted by severity** (CRITICAL first), not alphabetically.

## Deliberate non-goals (unchanged from v1)

- No network scanning, no live-target execution path.
- Authorization gate, sandbox isolation, and audit logging remain
  non-negotiable (see CONTRIBUTING.md).
- No success-rate promises: PoC quality depends on the model and the
  target; the tool reports verdicts honestly, including negatives.

## Still requires the operator's lab

- LLM API key (Z.ai GLM default; any OpenAI-compatible endpoint works).
- Docker daemon + real vulnerable-app images (`AERA_IMAGE_*`).
- First end-to-end run to validate prompt quality against real CVEs —
  expected to be an iterative loop, not one shot.

## v0.4.0 — the five-function framework

The codebase pipeline maps 1:1 to the five functions:

| Function | Module | What it really does |
|---|---|---|
| 1. Vulnerability Analysis | `codebase.py` + `static.py` | Ingests a local source tree; 19 regex rules (C/C++/Python/JS) flag dangerous constructs; optional LLM review confirms/dismisses each finding |
| 2. Automated Test Generation | `fuzz.py` | Seeds derived from static findings + mutation engine (bit flips, swaps, splices, interesting values) |
| 3. Isolated Execution | `fuzz.SandboxFuzzRunner` | Network-isolated container, target mounted read-only, one container per campaign |
| 4. Verification & Triaging | `triage.py` | Crash = signal or sanitizer/traceback keyword; 3× reproduce check; signature dedup |
| 5. Reporting & Remediation | `report_generator` | Findings table, per-rule remediation, crash list with repro hex, fix guidance |

Honest scope: pattern rules are triage aids (not dataflow analysis), and the
fuzzer is mutation-based (not coverage-guided). Both are proven working in
tests — the fuzzer found a planted crash — but neither claims parity with
CodeQL/AFL++.

## v0.5.0 — the 7 advanced upgrades

| # | Upgrade | Module | Proof |
|---|---|---|---|
| 1 | Coverage-guided fuzzing | `coverage.py` | Edge coverage via sys.monitoring; nested-branch target cracked on 3/3 RNG seeds; deterministic branch-edge unit test |
| 2 | Semgrep engine | `semgrep.py` | Primary when installed, regex fallback; JSON→finding mapping tested with mocked binary |
| 3 | Sanitizer builds | `sanitizers.py` | `aera build-asan`; real gcc+ASan run parsed `stack-buffer-overflow` (found & fixed the FORTIFY pre-emption gotcha) |
| 4 | Minimization + severity | `minimize.py` | ddmin shrinks `xxBADxx`→`BAD`; SIGSEGV-write→CRITICAL … traceback→LOW |
| 5 | SARIF 2.1.0 | `sarif.py` | Validated structure; crash results included |
| 6 | Continuous mode | `watch.py` | `aera watch --once` exits 1 on new HIGH+; diff proven live |
| 7 | Grammar generation | `grammar.py` | JSON + HTTP generators; campaign-tested |

Notable debugging from the loop: line coverage couldn't see branch
combinations (corpus stalled at 5) — switched to edge coverage; glibc
FORTIFY pre-empted ASan — builder now passes `-U_FORTIFY_SOURCE`;
`sys.monitoring` tool ids are 0–5 only (claim 3, fallback 4).
