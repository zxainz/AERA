<div align="center">

# AERA: Autonomous Exploit Research Assistant

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security: Fail-Closed](https://img.shields.io/badge/security-fail--closed-red.svg)](docs/ETHICAL_USAGE.md)
[![Sandbox: Docker](https://img.shields.io/badge/sandbox-network--isolated-green.svg)](aera/sandbox.py)
[![Tests: 100% Passed](https://img.shields.io/badge/tests-116%20passed-brightgreen.svg)](tests/)

**An AI-assisted, ethical security pipeline for authorized vulnerability validation, self-healing PoC testing in isolated Docker sandboxes, threat-intel prioritization, and defensive reporting.**

[Key Features](#-key-features) • [Architecture](#-architecture) • [Quick Start](#-quick-start) • [CLI Reference](#-cli-reference) • [Python API](#-python-api) • [Configuration](#-configuration-env) • [Legal & Ethics](#-legal-disclaimer)

</div>

---

> ⚠️ **IMPORTANT: Authorized Defensive Research Only.** You must have explicit written permission for every target and system you test. All PoC executions occur exclusively in network-isolated containers. See [docs/ETHICAL_USAGE.md](docs/ETHICAL_USAGE.md).

---

## 🔬 What is AERA?

AERA (Autonomous Exploit Research Assistant) automates the end-to-end vulnerability research and validation lifecycle:

1. **Validate Vulnerability Reports**: Validates CVE disclosures, bug bounty findings, and local codebase alerts.
2. **Threat-Intel Enrichment**: Automatically queries FIRST EPSS (Exploit Prediction Scoring System) probability scores and CISA's Known Exploited Vulnerabilities (KEV) catalog.
3. **Safe PoC Drafting & Self-Healing**: Prompts LLMs (Z.ai GLM, OpenAI-compatible APIs, or local Ollama) to produce minimal, non-weaponized validation scripts. Crashes or failures are automatically diagnosed and fed back to the model for iterative correction.
4. **Network-Isolated Sandbox Testing**: Executes validation scripts exclusively inside ephemeral Docker containers running with `network_mode="none"` and strict CPU/RAM limits.
5. **AppSec & Pentesting Workflow**: Execution-verified static findings (`--dyn-verify`), session-aware web parameter fuzzing (`webfuzz`), and multi-hop attack path chaining (`chains`).
6. **Defensive Documentation**: Generates structured Markdown reports, SARIF 2.1.0 output, and interactive HTML dashboards.

---

## 🛡️ Built-in Safeguards

| Safeguard | Implementation |
|---|---|
| **Fail-Closed Authorization** | Signed JWT tokens with 24-hour expiry, `exploit_research` scope, and strict domain binding. Refuses to start without a secret. |
| **Air-Gapped Sandbox** | Containers execute strictly with `network_mode="none"`, 512MB RAM / 50% CPU quotas, and guaranteed context-manager destruction. |
| **Self-Healing PoC Loop** | Crashes and failed assertions are diagnosed from stdout/stderr and retried iteratively (`AERA_POC_RETRIES`). |
| **No Persistence / Obfuscation** | Prompts strictly enforce non-destructive, non-weaponized, localhost-only validation scripts. |
| **Continuous Audit Logging** | Append-only JSONL log with built-in real-time alerts for suspicious access patterns and velocity spikes. |
| **Patch Verification** | `aera verify` re-tests saved PoCs against updated environments without re-incurring LLM token costs. |

---

## 🏗️ Architecture

```
[Target / CVE Input]
        │
        ▼
[Authorization Gate (JWT)] ──(Fail-Closed)──► Refused if unauthorized
        │
        ▼
[Threat Intel Enrichment] ◄── NVD CPEs, FIRST EPSS, CISA KEV
        │
        ▼
[Lab Fingerprinting] ◄────── Inspect container OS, kernel, & runtime facts
        │
        ▼
[LLM Analysis & PoC Drafting] ◄── Z.ai GLM / OpenAI / Ollama (NDA-Safe)
        │
        ▼
[Isolated Docker Sandbox] ──(network_mode="none", 512MB RAM, 50% CPU)
        │
   (Crash / Error?) ───────► [Self-Healing Feedback Loop (AERA_POC_RETRIES)]
        │
        ▼
[Defensive Reports & Dashboards] ──► Markdown, SARIF 2.1.0, HTML Dashboard
```

---

## 🚀 Quick Start

### Prerequisites
* **Python 3.11+**
* **Docker** (running, for sandbox execution)
* **LLM API Key** (Z.ai GLM, OpenAI-compatible, or a free local [Ollama](https://ollama.com/) instance)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/zxainz/AERA.git && cd AERA

# 2. Install dependencies in editable mode
pip install -e ".[dev]"

# 3. Configure environment
cp .env.example .env
# Edit .env and set AERA_JWT_SECRET, AERA_DOMAINS, and your LLM key

# 4. Verify test suite (116 passed)
pytest tests/ -q
```

---

## 💻 CLI Reference

### 1. Mint Authorization Token
```bash
aera token --user researcher@lab.example.com --domain lab.example.com --hours 24
```

### 2. Analyze Single CVE & Validate PoC
```bash
# Full pipeline with threat-intel, Docker sandbox, and self-healing
aera analyze CVE-2021-44228 --token <TOKEN> --vuln-type web --out report.md

# Analysis-only mode (no Docker required)
aera analyze CVE-2023-4966 --token <TOKEN> --no-sandbox
```

### 3. Batch Processing & HTML Dashboard
```bash
printf 'CVE-2021-44228\nCVE-2023-4966\n' > cves.txt
aera batch cves.txt --token <TOKEN> --out batch-out --concurrency 2
aera dashboard batch-out
```

### 4. Patch Verification (Confirm Fix)
```bash
# Re-runs a saved PoC against the patched container (exit 0 = confirmed fixed)
aera verify batch-out/CVE-2021-44228.json --token <TOKEN>
```

### 5. Codebase Scanning & Dynamic Verification
```bash
# Static scan with SARIF export
aera scan-code ./myapp --token <TOKEN> --engine semgrep --sarif results.sarif

# Dynamic verification (mounts repo read-only into sandbox and triggers flaws)
aera scan-code ./myapp --token <TOKEN> --dyn-verify

# Sandboxed fuzzing campaign
aera scan-code ./myapp --token <TOKEN> --fuzz --target ./vuln --iterations 500
```

### 6. Attack Path Chaining & Recon
```bash
# Map Nmap XML scan to candidate CVEs
aera recon nmap.xml --token <TOKEN> --out recon/

# Link isolated findings into multi-hop exploit paths
aera chains --cve-dir batch-out --token <TOKEN> --out chains.md

# Monitor client stack against newly disclosed CISA KEV entries
aera kev-watch --stack stack.json --token <TOKEN> --once
```

---

## 🐍 Python API

AERA can be integrated directly into security pipelines:

```python
import asyncio
from aera import AutonomousExploitResearchAssistant

async def main():
    # 1. Initialize assistant
    aera = AutonomousExploitResearchAssistant(api_key="your-api-key")

    # 2. Mint short-lived research token
    token = aera.authorization.generate_token(
        user_id="researcher@company.com",
        domain="company.com",
        hours=8
    )

    # 3. Process vulnerability (NVD CVE or custom bug bounty finding)
    result = await aera.process_vulnerability(
        cve_id="CVE-2021-44228",
        user_token=token,
        vuln_type="web"
    )

    print("Threat Intel:", result["intel"])
    print("Verdict:", result["test_result"]["verdict"])
    print("Report:\n", result["report_markdown"])

if __name__ == "__main__":
    asyncio.run(main())
```

---

## ⚙️ Configuration (.env)

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `AERA_JWT_SECRET` | **Yes** | — | Secret key for signing and validating tokens |
| `AERA_DOMAINS` | **Yes** | — | Comma-separated list of authorized research domains |
| `AERA_LLM_API_KEY` | Conditional | — | API key (not required if `AERA_LLM_PROVIDER=ollama`) |
| `AERA_LLM_PROVIDER` | No | `zai` | Provider: `zai` (GLM), `ollama` (local/offline), or `custom` |
| `AERA_LLM_MODEL` | No | `glm-4.5` | Model name (e.g. `glm-4.5`, `llama3.1`, `gpt-4o`) |
| `AERA_LLM_BASE_URL` | No | `https://api.z.ai/api/paas/v4` | LLM API endpoint URL |
| `AERA_SANDBOX_ENABLED` | No | `true` | Enable/disable Docker container execution |
| `AERA_POC_RETRIES` | No | `1` | Number of self-healing retries for crashing PoCs |
| `AERA_IMAGE_WEB` | No | `vulhub/struts2:2.3.15` | Default web lab target container image |
| `AERA_IMAGE_BINARY` | No | `alpine:3.20` | Default binary lab target container image |
| `AERA_AUDIT_LOG` | No | `aera-audit.log` | Path to append-only JSONL audit log |

---

## 📁 Repository Structure

```
AERA/
├── .github/
│   └── workflows/
│       └── security-scan.yml     # Automated CI: pytest, bandit, pip-audit
├── aera/
│   ├── core.py                   # Main pipeline & self-healing loop
│   ├── authorization.py          # Fail-closed JWT token manager
│   ├── sandbox.py                # Network-isolated Docker runner
│   ├── dynverify.py              # Dynamic finding execution verification
│   ├── intel.py                  # FIRST EPSS & CISA KEV enrichment
│   ├── chains.py                 # Multi-hop attack path chaining
│   ├── webfuzz.py                # Session-aware web & API parameter fuzzing
│   ├── recon.py                  # Nmap XML & banner to candidate CVE parser
│   ├── audit.py                  # Append-only audit logger & alert detector
│   ├── llm.py                    # Pluggable LLM client (GLM, Ollama, OpenAI)
│   ├── report_generator.py       # Educational Markdown report builder
│   ├── static.py                 # AST & Semgrep static analysis engine
│   └── ...
├── docs/
│   ├── ETHICAL_USAGE.md          # Binding ethical usage policy
│   ├── SETUP_GUIDE.md            # Detailed environment setup
│   └── API_REFERENCE.md          # Complete Python API documentation
├── examples/
│   ├── basic_usage.py            # Single CVE validation script
│   ├── cve_analysis.py           # Analysis-only triage example
│   ├── batch_processing.py       # Multi-CVE batch processing
│   └── demo_run.py               # Complete end-to-end interactive demo
├── tests/                        # 20 unit test suites (116 tests, 100% pass)
├── requirements.txt              # Production & test dependencies
├── setup.py                      # Package configuration (v0.6.0)
└── LICENSE                       # MIT License
```

---

## ⚖️ Legal Disclaimer

This tool is provided for educational and research purposes only. The authors:

1. **Do not condone or support unauthorized use** of this tool
2. **Are not responsible for misuse** of this tool
3. **Assume no liability** for any damages caused by misuse
4. **Require proper authorization** for all testing activities

Users are solely responsible for ensuring their use of this tool complies with:
- Computer Fraud and Abuse Act (CFAA)
- Computer Misuse Act (CMA)
- General Data Protection Regulation (GDPR)
- All other applicable laws and regulations

By using this tool, you agree to these terms and accept full responsibility for your actions. See [docs/ETHICAL_USAGE.md](docs/ETHICAL_USAGE.md).
