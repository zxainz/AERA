# AERA Setup Guide

## 1. Prerequisites

- Python 3.11+
- Docker installed and the daemon running (`docker info` should succeed)
- An LLM API key (default endpoint is Z.ai / GLM; any OpenAI-compatible
  endpoint works via `AERA_LLM_BASE_URL` / `AERA_LLM_MODEL`)
- Vulnerable lab images. AERA does **not** ship these -- build or pull your
  own (e.g. per-CVE vulhub images) and point AERA at them (step 4).

## 2. Install

```bash
git clone <your-repo-url> aera && cd aera
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

This installs the `aera` command.

## 3. Configure

```bash
cp .env.example .env
```

Edit `.env`:

| Variable | What to put |
|---|---|
| `AERA_JWT_SECRET` | long random string, e.g. `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `AERA_DOMAINS` | your lab domain(s), comma-separated, e.g. `lab.example.com` |
| `AERA_LLM_API_KEY` | your model API key |
| `AERA_LLM_BASE_URL` | only if not using Z.ai (must be OpenAI-compatible) |
| `AERA_LLM_MODEL` | only if not using the default model |
| `AERA_IMAGE_WEB` / `AERA_IMAGE_BINARY` / `AERA_IMAGE_NETWORK` | your lab images (see step 4) |

## 4. Lab images

AERA runs PoCs inside throwaway containers from these images. Examples:

```bash
# pull a known-vulnerable app image for your lab, then reference it:
docker pull vulhub/struts2:2.3.15
# .env: AERA_IMAGE_WEB=vulhub/struts2:2.3.15
```

Use one image per vulnerability class you test. AERA fingerprints the image
at runtime and feeds the facts (OS, arch, interpreters, ports) into PoC
generation.

## 5. First run (analysis only -- safe)

```bash
# mint a token (valid 8h, bound to your domain)
aera token --user you@lab.example.com --domain lab.example.com
# analyze a CVE: no PoC generated, nothing executed
aera analyze CVE-2023-4966 --token <TOKEN> --no-sandbox
```

## 6. First full run (sandboxed PoC)

```bash
aera analyze CVE-2021-44228 --token <TOKEN> --vuln-type web --out report.md
```

Check `report.md` and `aera-audit.log`. The PoC ran inside a container with
no network access; the container was destroyed afterwards.

## 7. Batch

```bash
printf 'CVE-2021-44228\nCVE-2023-4966\n' > cves.txt
aera batch cves.txt --token <TOKEN> --out batch-out --concurrency 2
# dashboard: batch-out/dashboard.html (or rebuild later: aera dashboard batch-out)
```

## 8. Verify a patch

After patching, re-run the saved PoC to confirm the fix (no LLM key needed):

```bash
aera verify batch-out/CVE-2021-44228.json --token <TOKEN>
# exit 0 + "NOT VULNERABLE" means the patch worked
```

## Troubleshooting

- `AERA_JWT_SECRET is not set` -- you skipped step 3; AERA refuses to start
  without it, by design.
- `Cannot connect to the Docker daemon` -- start Docker; sandbox tests
  (`pytest tests/test_sandbox.py`) need it too.
- `ImageNotFound` -- AERA tried to pull your configured lab image and failed;
  check the name/tag in `.env`.
- NVD `403/429` -- you hit the public rate limit (5 req / 30s). Add an
  `NVD_API_KEY` via `AERA_NVD_API_KEY`... (not yet wired -- batch runs include
  backoff; for heavy use, request an NVD API key and ask to wire it in).
- LLM errors -- verify `AERA_LLM_BASE_URL`, key, and model name with a manual
  `curl` to `<base>/chat/completions` first.
