# AERA — Complete Usage Guide

## 1. Requirements

- **Python 3.11+**
- **Docker** installed with the daemon running (`docker info` must succeed)
- **An LLM API key** — Z.ai/GLM by default (set `AERA_LLM_API_KEY`); any
  OpenAI-compatible endpoint works via `AERA_LLM_BASE_URL` / `AERA_LLM_MODEL`
- **Vulnerable lab images** — AERA does not ship these; you provide them
  (e.g. per-CVE vulhub images)

## 2. Installation

```bash
# 1. Get the code (unzip the release, then:)
cd aera

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. Install (editable) with dev tools
pip install -e ".[dev]"

# 4. Verify the install
aera --help
pytest tests/ -q                 # expect: 37 passed, 1 skipped (Docker test
                                 # runs only when a daemon is available)
```

## 3. Configuration

```bash
cp .env.example .env
```

Edit `.env`. Reference:

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `AERA_JWT_SECRET` | **yes** | — | Token signing secret. Generate: `python3 -c "import secrets; print(secrets.token_hex(32))"`. AERA refuses to start without it. |
| `AERA_DOMAINS` | **yes** | — | Comma-separated authorized research domains, e.g. `lab.example.com` |
| `AERA_LLM_API_KEY` | **yes** | — | LLM API key |
| `AERA_LLM_BASE_URL` | no | `https://api.z.ai/api/paas/v4` | Any OpenAI-compatible chat endpoint |
| `AERA_LLM_MODEL` | no | `glm-4.5` | Model name |
| `AERA_SANDBOX_ENABLED` | no | `true` | Set `false` for analysis-only operation |
| `AERA_IMAGE_WEB` | no | example vulhub image | Your lab's web-app image |
| `AERA_IMAGE_BINARY` | no | `alpine:3.20` | Your lab's binary-analysis image |
| `AERA_IMAGE_NETWORK` | no | `alpine:3.20` | Your lab's network-service image |
| `AERA_NVD_API_KEY` | no | — | Raises NVD rate limit for heavy batch use |
| `AERA_POC_RETRIES` | no | `1` | Extra self-heal attempts after a failed PoC run |
| `AERA_KEV_CACHE` | no | `.cache/kev.csv` | CISA KEV cache location |
| `AERA_AUDIT_LOG` | no | `aera-audit.log` | Audit log location |

**Lab images:** pull or build the vulnerable apps you test against, then
point AERA at them:

```bash
docker pull vulhub/struts2:2.3.15
# .env → AERA_IMAGE_WEB=vulhub/struts2:2.3.15
```

## 4. Tokens

Every run needs a JWT authorization token (scope `exploit_research`,
domain-bound, expiring):

```bash
# Mint an 8-hour token
aera token --user you@lab.example.com --domain lab.example.com --hours 8
# → prints the token; save it for the commands below
```

Tokens are validated on every command. Expired, wrong-scope, or
foreign-domain tokens are rejected and the rejection is audit-logged.

## 5. Command reference

### `aera analyze` — full pipeline for one CVE

```bash
aera analyze CVE-2021-44228 --token <TOKEN> --out report.md
aera analyze CVE-2021-44228 --token <TOKEN> --vuln-type binary
aera analyze CVE-2023-4966  --token <TOKEN> --no-sandbox   # analysis only
```

Options: `--vuln-type {auto,web,binary,network}` (default `auto` — inferred
from CWEs), `--out PATH` (default `report-<CVE>.md`), `--no-sandbox`
(skips PoC drafting and testing entirely), `--target-info TEXT` /
`--target-info-file PATH` (tester-observed banner/tech facts used to tune
the PoC draft to the real target; audit-logged).

### `aera batch` — many CVEs at once

```bash
printf 'CVE-2021-44228\nCVE-2023-4966\n' > cves.txt
aera batch cves.txt --token <TOKEN> --out batch-out --concurrency 2 --vuln-type auto
```

- One CVE per line in the input file (`#` lines ignored).
- Concurrency-limited (default 3); one failure never kills the batch.
- **Checkpointed:** `batch-out/checkpoint.json` records finished CVEs, so a
  rerun skips them (no repeated LLM charges).
- Outputs per CVE: `<CVE>.md` (report) + `<CVE>.json` (machine-readable),
  plus `batch-out/dashboard.html`.

### `aera verify` — confirm a patch worked

```bash
aera verify batch-out/CVE-2021-44228.json --token <TOKEN>
# Verdict: not_vulnerable  → exit code 0 (patch worked)
# Verdict: vulnerable      → exit code 1 (still exploitable)
```

Re-runs the saved PoC in the sandbox. Needs no LLM key.

### `aera dashboard` — rebuild the dashboard

```bash
aera dashboard batch-out
```

Regenerates `dashboard.html` from saved `CVE-*.json` files.

### `aera token` — mint tokens (see section 4)

### `aera recon` — versions → candidate CVEs (v0.6)

```bash
aera recon nmap.xml --token <TOKEN> --out recon/
# or: printf 'Apache httpd 2.4.49\nOpenSSH 8.9\n' > versions.txt
aera recon versions.txt --token <TOKEN> --out recon/
```

Parses nmap XML (open ports only) or a `product version` text list, queries
NVD with fallback queries, and writes `recon/recon.json` (per-service
candidates with match scores) plus `recon/cves.txt` — deduped CVE IDs ready
for `aera batch`. NVD rate limits are respected (7s between calls without
`AERA_NVD_API_KEY`).

### `aera webfuzz` — session-aware endpoint fuzzing (v0.6)

```bash
aera webfuzz --url http://lab:8080/search --token <TOKEN> \
  --method GET --params q,page --iterations 200 \
  --login-url http://lab:8080/login \
  --login-data 'user=$AERA_LAB_USER&pass=$AERA_LAB_PASS' \
  --login-check Logout --out webfuzz.json
```

Logs in once (form POST), then fuzzes the named parameters with detection
payloads. Flags HTTP 500s, stack-trace/SQL-error disclosure, and
response-time spikes vs. a 3-request baseline. Only ever touches the URL
you give it — point it at your authorized lab target.

### `aera chains` — attack-path chaining (v0.6)

```bash
aera chains --cve-dir batch-out --token <TOKEN> --out chains.md
aera chains --cve-dir batch-out --sarif results.sarif --token <TOKEN> --scope webapp
```

Tags findings/CVEs with attacker capabilities (credential, auth-bypass,
code-exec, …) and links them into multi-stage chains within one scope.
Output is a candidate list — verify each link live before reporting.

### `aera kev-watch` — KEV alerts for your client stack (v0.6)

```bash
# stack.json: {"products": [{"vendor": "Citrix", "product": "NetScaler"}],
#              "cves": ["CVE-2021-44228"]}
aera kev-watch --stack stack.json --token <TOKEN> --once
aera kev-watch --stack stack.json --token <TOKEN> --interval 86400
```

Polls the CISA KEV feed and reports only *new* entries matching your stack
(by product/vendor name or CVE ID). State in `--state` (default
`.kev-state.json`) dedupes alerts. `--once` exits 2 when alerts fired —
usable as a CI/scheduled check.

### `aera client-report` — client-facing report (v0.6)

```bash
aera client-report batch-out --token <TOKEN> --out client-report.md
```

Renders an executive summary (risk rating, KEV/confirmed counts, top 3
priorities), prioritized findings with business-impact statements, and a
remediation roadmap — template-based, works offline.

### Local LLM via Ollama (v0.6, NDA-safe)

```bash
ollama pull llama3.1 && ollama serve
export AERA_LLM_PROVIDER=ollama          # AERA_LLM_MODEL defaults to llama3.1
# AERA_LLM_API_KEY is not needed for local providers
```

All LLM calls (analysis, PoC drafting, `--llm-review`, `--dyn-verify`) stay
on your machine. `aera scan-code --dyn-verify` additionally needs Docker:
it writes LLM-generated trigger scripts that import the real vulnerable
file (mounted read-only) and marks findings `confirmed` / `unproven`.

## 6. Common workflows

**Triage a new CVE (safe, nothing executes):**
```bash
aera analyze CVE-2024-XXXX --token $T --no-sandbox
```

**Validate and get a PoC:**
```bash
aera analyze CVE-2024-XXXX --token $T --out report.md
# → check report.md: intel, analysis, PoC source, sandbox verdict
```

**Weekly batch + dashboard:**
```bash
aera batch this-week.txt --token $T --out batch-out
xdg-open batch-out/dashboard.html
```

**Patch verification loop:**
```bash
aera batch critical.txt --token $T --out batch-out
# ... apply patches in the lab ...
aera verify batch-out/CVE-2024-XXXX.json --token $T
```

**Scan your own codebase (static analysis):**
```bash
aera scan-code ./myapp --token $T --out codebase-report.md
```

**Scan + fuzz your own code (sandboxed):**
```bash
# target: how to run your program; "{input}" = fuzz input path, else stdin
aera scan-code ./myapp --token $T --fuzz --target ./vuln --iterations 500
aera scan-code ./myapp --token $T --fuzz --target python3 harness.py "{input}" --llm-review
```

**Coverage-guided fuzzing (pure-Python function, in-process, 3.12+):**
```bash
aera scan-code ./mylib --token $T --coverage --pyfunc mypkg.parser:parse --iterations 6000
```

**Grammar-aware fuzzing (structured inputs):**
```bash
aera scan-code ./myapp --token $T --fuzz --target ./json_parser --grammar json --iterations 1000
```

**Static analysis engine choice + SARIF export:**
```bash
aera scan-code ./myapp --token $T --engine semgrep --sarif results.sarif
# --engine: auto (semgrep if installed, else built-in rules) | semgrep | regex
```

**Confirm static findings dynamically (sandboxed trigger scripts):**
```bash
aera scan-code ./myapp --token $T --dyn-verify
# findings gain dynamic_verdict: confirmed | unproven | skipped
```

**Web-app pentest loop (recon → triage → validate → report):**
```bash
aera recon nmap.xml --token $T --out recon/          # versions -> CVEs
aera batch recon/cves.txt --token $T --out batch-out # triage by KEV/EPSS
aera analyze CVE-2021-41773 --token $T \
  --target-info "Server: Apache/2.4.49" --out cve.md # target-tuned PoC
aera webfuzz --url http://lab:8080/search --token $T --params q,page \
  --login-url http://lab:8080/login \
  --login-data 'user=$AERA_LAB_USER&pass=$AERA_LAB_PASS' --login-check Logout
aera chains --cve-dir batch-out --token $T --out chains.md
aera client-report batch-out --token $T --out client-report.md
```

**Retainer: watch KEV for a client stack (cron/CI):**
```bash
# stack.json: {"products": [{"vendor": "Citrix", "product": "NetScaler"}]}
aera kev-watch --stack stack.json --token $T --once   # exit 2 if alerts
```

**Sanitizer build, then fuzz the instrumented binary:**
```bash
aera build-asan src/vuln.c -o /tmp/vuln_asan --cc gcc
aera scan-code ./myapp --token $T --fuzz --target /tmp/vuln_asan --iterations 1000
```

**Continuous mode (CI gate):**
```bash
aera watch ./myapp --token $T --once --fail-on high   # exit 1 on new HIGH+
aera watch ./myapp --token $T --interval 300          # loop until Ctrl-C
```

> Fuzz only code you own or are explicitly authorized to test. The target
> directory is mounted read-only into a network-isolated container; crashes
> (signals, sanitizer/traceback keywords) are reported, deduped by
> signature, and re-run 3× to confirm reproducibility. Plain nonzero exits
> (input validation) are not counted as crashes.

**Python API** (same capabilities programmatically):
```python
import asyncio
from aera import AutonomousExploitResearchAssistant, BatchRunner

async def main():
    aera = AutonomousExploitResearchAssistant()
    token = aera.authorization.generate_token("you@lab.example.com", "lab.example.com", hours=8)
    result = await aera.process_vulnerability("CVE-2021-44228", token)
    print(result["test_result"]["verdict"])   # vulnerable | not_vulnerable | unknown
    print(result["report_markdown"][:500])

asyncio.run(main())
```

## 7. Understanding outputs

**Markdown report sections:** CVE Summary → Threat Intel (KEV status, EPSS)
→ Defensive Analysis → Validation PoC → Sandbox Test Result (exit code,
verdict, per-attempt history, stdout/stderr) → Remediation Guidance.

**Verdicts:** `vulnerable` (PoC demonstrated the flaw), `not_vulnerable`
(PoC ran clean and reported negative), `unknown` (crashed or no verdict
line — triggers self-heal retries).

**`batch-out/*.json`:** machine-readable result per CVE (cve, analysis,
poc, test_result, intel) — feed these to your own tooling.

**Audit log** (`aera-audit.log`): JSON lines — `pipeline_started`,
`cve_fetched`, `intel_enriched`, `vuln_type_detected`, `lab_fingerprinted`,
`analysis_done`, `poc_drafted`, `poc_tested`, `poc_retrying`,
`report_generated`, `batch_*`, `fix_verification_*`, `token_minted_cli`.

## 8. Environment variables quick reference

`AERA_JWT_SECRET`, `AERA_DOMAINS`, `AERA_LLM_API_KEY` (required, except the
key is optional when `AERA_LLM_PROVIDER=ollama`).
`AERA_LLM_BASE_URL`, `AERA_LLM_MODEL`, `AERA_LLM_PROVIDER`
(`zai`/`ollama`/`custom`), `AERA_SANDBOX_ENABLED`,
`AERA_IMAGE_WEB/BINARY/NETWORK`, `AERA_IMAGE_PYTHON`, `AERA_NVD_API_KEY`,
`AERA_POC_RETRIES`, `AERA_KEV_CACHE`, `AERA_AUDIT_LOG` (optional — see table
in section 3).

## 9. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `AERA_JWT_SECRET is not set` | Fill it in `.env`; AERA refuses to start without it by design |
| `Invalid token` / `expired` | Mint a fresh token with `aera token`; check `--domain` matches `AERA_DOMAINS` |
| `Cannot connect to the Docker daemon` | Start Docker; sandbox + `describe_lab` need it |
| `ImageNotFound` / pull failed | Check `AERA_IMAGE_*` names/tags in `.env` |
| NVD `403`/`429` | Public rate limit hit; wait, or set `AERA_NVD_API_KEY` |
| LLM errors / timeouts | Verify base URL, key, model with a manual `curl` to `<base>/chat/completions`; client retries 3× with backoff |
| PoC keeps failing after retries | Increase `AERA_POC_RETRIES`; check the stderr in the report — the model may need a better lab image |
| `verdict: unknown` on all runs | The lab image likely lacks what's needed (e.g. no `python3`); fingerprint output in the audit log shows why |

## 10. Safety reminders

- Only test systems you have **explicit written permission** to test.
- PoCs run **only** in the network-isolated sandbox — never copy them to
  live targets.
- Do not weaken the auth gate, sandbox isolation, or audit logging
  (see `CONTRIBUTING.md` and `docs/ETHICAL_USAGE.md`).
- Follow responsible disclosure for anything new you confirm.
