# AERA — Project Details

**AERA (Autonomous Exploit Research Assistant)** — v0.3.0
An AI-assisted pipeline for **authorized** vulnerability research and validation.

---

## 1. What it is

AERA takes a CVE ID as input and produces a complete, educational
vulnerability research report. It is built for defensive security
professionals — penetration testers, vulnerability researchers, SOC analysts,
and security trainers — who need to validate vulnerability reports quickly
in controlled lab environments instead of doing every step by hand.

It is **not** an attack tool: it cannot scan networks, cannot reach the
internet from its test sandbox, requires an authorization token for every
run, and logs everything it does.

## 2. Problem it solves

Security teams drown in CVE feeds. For each CVE they must: read the NVD
entry, check whether it's actively exploited, understand the root cause,
decide patch priority, and — for the important ones — validate the flaw in
a lab. That loop takes 30–90 minutes per CVE by hand. AERA automates the
mechanical parts (data gathering, intel enrichment, report drafting, lab
execution) so the human spends time on judgment, not plumbing.

## 3. What it does — the pipeline

```
aera analyze CVE-2021-44228
        │
        ▼
┌──────────────────┐
│ 1. AUTHORIZE      │  JWT token validated: scope, expiry, research domain.
│                   │  Invalid token → run refused, event logged.
├──────────────────┤
│ 2. FETCH CVE      │  Pulls the NVD record: description, CVSS v3.1,
│                   │  CWE types, affected products (CPE), references.
├──────────────────┤
│ 3. ENRICH INTEL   │  EPSS exploit-probability score + CISA KEV lookup
│                   │  ("is this being exploited in the wild right now?").
│                   │  Fail-open: pipeline continues if sources are down.
├──────────────────┤
│ 4. DETECT +       │  Infers lab type (web/binary) from CWEs; fingerprints
│    FINGERPRINT    │  the lab container (OS, arch, Python, ports) so the
│                   │  PoC is written for the real environment.
├──────────────────┤
│ 5. AI ANALYSIS    │  LLM explains root cause, attacker preconditions,
│                   │  and mitigations — written for defenders.
├──────────────────┤
│ 6. DRAFT PoC      │  LLM writes a minimal, commented validation script
│                   │  (localhost only, no persistence, no obfuscation).
├──────────────────┤
│ 7. SANDBOX TEST   │  PoC runs in a throwaway Docker container:
│                   │  no network, CPU/RAM capped, destroyed afterwards.
│                   │  Exit code + verdict (VULNERABLE / NOT VULNERABLE)
│                   │  are parsed from the output.
├──────────────────┤
│ 8. SELF-HEAL      │  If the PoC crashes or prints no verdict, the failure
│    (optional)     │  output goes back to the model for a fix; retested.
│                   │  Configurable via AERA_POC_RETRIES.
├──────────────────┤
│ 9. REPORT         │  Markdown report: CVE summary, threat intel, analysis,
│                   │  PoC source, test results, remediation guidance.
└──────────────────┘
        │
        ▼
  report-CVE-2021-44228.md  +  audit log entry
```

## 4. Feature list

| Feature | Description |
|---|---|
| Single-CVE pipeline | `aera analyze` — full pipeline for one CVE |
| Batch processing | `aera batch` — many CVEs, concurrency-limited, checkpointed (interrupted runs resume without redoing paid LLM calls) |
| Threat intel | EPSS scores + CISA KEV catalog in every report; drives patch priority |
| Sandboxed PoC testing | Docker, `network_mode="none"`, resource limits, guaranteed cleanup |
| PoC self-healing | Crashed PoCs are auto-fixed and retested |
| Patch verification | `aera verify` — re-run a saved PoC later to confirm a fix worked |
| Lab fingerprinting | Container facts fed into PoC generation |
| Vuln-type auto-detection | `binary` vs `web` inferred from CWEs |
| HTML dashboard | Severity breakdown, top CWEs/vendors, KEV hits, per-CVE table |
| Analysis-only mode | `--no-sandbox`: triage with zero code generated or executed |
| Authorization gate | JWT, short expiry, domain-bound, fail-closed |
| Audit logging | Append-only JSONL record of every action |
| Pluggable LLM | OpenAI-compatible client; Z.ai/GLM default, or local Ollama (NDA-safe) via `AERA_LLM_PROVIDER=ollama` |
| CLI + Python API | `aera` command and importable package |
| Recon → CVEs (v0.6) | `aera recon` — nmap XML or version list → candidate CVEs via NVD |
| Session-aware web fuzzing (v0.6) | `aera webfuzz` — login once, fuzz params, flag 500s/traces/time spikes |
| Execution-verified findings (v0.6) | `scan-code --dyn-verify` — LLM-written trigger scripts confirm static findings in the sandbox |
| Attack-path chaining (v0.6) | `aera chains` — capability-tagged findings linked into exploit chains |
| KEV watch (v0.6) | `aera kev-watch` — alert when new KEV entries hit your client stack |
| Client-ready reports (v0.6) | `aera client-report` — exec summary, business impact, remediation roadmap |
| Target-aware PoCs (v0.6) | `analyze --target-info` — banner/tech facts tune the PoC draft |

## 5. Architecture — module map

```
aera/
├── core.py             Orchestrator: process_vulnerability(), verify_fix()
├── authorization.py    JWT mint/validate (fail-closed, env secret)
├── sandbox.py          Docker runner: test_poc(), describe_lab(),
│                       isolated_environment() (network off, always cleaned)
├── fingerprint.py      Image + runtime fact collection
├── llm.py              LLMProvider ABC + OpenAICompatibleProvider
│                       (retries with backoff)
├── intel.py            get_epss(), KEVCatalog, enrich() (fail-open)
├── batch.py            BatchRunner: concurrency, checkpoints, outputs
├── patterns.py         summarize() + render_html_dashboard()
├── report_generator.py Educational Markdown reports
├── audit.py            Append-only JSONL audit log
├── utils.py            NVD fetching (+API key), detect_vuln_type()
├── cli.py              token / analyze / batch / verify / dashboard
├── recon.py            parse_nmap_xml(), parse_version_list(), candidate_cves()
├── webfuzz.py          WebFuzzer: login(), fuzz_params(), anomaly detection
├── dynverify.py        verify_findings(), parse_trigger_verdict()
├── chains.py           build_chains(), nodes_from_cves/findings()
├── kevwatch.py         check_kev() against the CISA KEV JSON feed
└── ...                 (codebase pipeline: codebase/static/fuzz/coverage/
                        triage/minimize/semgrep/sanitizers/sarif/watch/grammar)
```

Supporting: `tests/` (38 tests), `examples/`, `docs/`,
`.github/workflows/security-scan.yml` (pytest + bandit + pip-audit),
`setup.py` (`pip install -e .`).

## 6. Data sources

| Source | Used for | Key needed | Cost |
|---|---|---|---|
| NVD API | CVE details, CVSS, CWE, CPE | No (optional `AERA_NVD_API_KEY` raises rate limit) | Free |
| FIRST EPSS API | Exploit-probability score | No | Free |
| CISA KEV CSV | Actively-exploited list (cached locally) | No | Free |
| LLM (Z.ai GLM default) | Analysis + PoC drafting | **Yes** (`AERA_LLM_API_KEY`) | Paid per use |
| Docker Hub / your registry | Vulnerable lab images | No (your images) | Free |

## 7. Safety and ethical design

- **Authorization required** — no token, no run. Tokens expire (default 24h),
  are scope-limited (`exploit_research`), and domain-bound.
- **Sandbox-only execution** — PoCs execute exclusively in network-isolated
  containers that are destroyed after each run. There is no code path for
  live targets.
- **No reconnaissance tooling** — no scanners, no network probing.
- **Validation-grade output** — PoCs are minimal, commented, localhost-only;
  no persistence, lateral movement, obfuscation, or anti-analysis.
- **Audit everything** — every stage logs actor, timestamp, and outcome.
- **Fail-closed security, fail-open intel** — auth/sandbox failures stop the
  run; intel-source outages only degrade the report.

Full policy: `docs/ETHICAL_USAGE.md`.

## 8. Version history

- **v0.1.0** — Core pipeline, JWT auth, Docker sandbox, audit log, reports.
- **v0.2.0** — Batch processing with checkpoints, lab fingerprinting,
  EPSS/KEV intel, pattern analysis + HTML dashboard, CLI, packaging, CI.
- **v0.3.0** — Fixed sandbox exit-code bug and KEV catalog bug; PoC
  self-healing loop; vuln-type auto-detection; `aera verify` patch
  verification; LLM retries; NVD API key; severity-sorted dashboard.
- **v0.4.0** — Five-function codebase framework: `codebase.py` (ingestion),
  `static.py` (19 built-in rules + LLM review), `fuzz.py` (mutation fuzzing,
  sandbox runner), `triage.py` (dedupe + reproduce), `scan-code` CLI.
- **v0.5.0** — 7 advanced upgrades: `coverage.py` (edge-coverage-guided
  in-process fuzzing via sys.monitoring), `semgrep.py` (Semgrep engine +
  regex fallback), `sanitizers.py` (`aera build-asan`), `minimize.py`
  (delta-debugging + severity), `sarif.py` (SARIF 2.1.0), `watch.py`
  (continuous mode + CI gate), `grammar.py` (JSON/HTTP generators).
- **v0.6.0** — Pentester workflow: local LLM via Ollama (`AERA_LLM_PROVIDER`,
  no data leaves the lab); `aera recon` (nmap XML/version list → candidate
  CVEs, proven live against NVD); `aera webfuzz` (session-aware endpoint
  fuzzing, proven live against a lab app); `--dyn-verify` (sandbox trigger
  scripts confirm static findings); `aera chains` (attack-path chaining);
  `aera kev-watch` (new KEV entries matching your client stack, proven live
  against the CISA feed); `aera client-report` (exec summary + remediation
  roadmap); target-aware PoCs (`--target-info`). 117/118 tests pass
  (1 Docker test skips without a daemon).

## 9. Honest limitations

- PoC quality depends on the LLM and the target — no success-rate promises.
- Static rules are pattern-based (triage aid), not dataflow analysis —
  expect false positives; the LLM review, dynamic verification, and fuzzing
  stages filter them.
- The fuzzer is mutation-based with an optional coverage-guided mode
  (Python 3.12+); it won't match AFL++/libFuzzer on hard targets.
- The sandbox and LLM paths need the operator's environment (API key,
  Docker, lab images) and a first real end-to-end run to validate.
- Intel enrichment is advisory; a CVE not in KEV can still be dangerous.
- Auto vuln-type detection covers `web`/`binary`; `network` is manual.
- `aera recon` candidate CVEs are version-match heuristics — always confirm
  with `aera batch` triage before testing.

## 10. Roadmap ideas (not yet built)

- NVD API key already supported; add Shodan/Censys-style exposure context.
- Multi-model fallback (try a second model if the first fails).
- PDF export of reports.
