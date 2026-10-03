# AERA API Reference

## `aera.AutonomousExploitResearchAssistant`

```python
aera = AutonomousExploitResearchAssistant(
    llm=None,               # LLMProvider; default OpenAICompatibleProvider()
    sandbox_enabled=None,   # default from AERA_SANDBOX_ENABLED (true)
)
```

### `await aera.process_vulnerability(cve_id, user_token, *, vuln_type="web", intel=True, lab_context=True)`

Runs the full pipeline. Returns a dict:

| Key | Contents |
|---|---|
| `cve` | normalized NVD record (id, description, cvss_v3, cwes, cpes, references) |
| `analysis` | defensive LLM analysis text |
| `poc` | minimal validation PoC (Python source) |
| `test_result` | sandbox run record, or `None` if sandbox disabled |
| `intel` | `{"epss": {...}, "kev": {...}}` (either may be `None`) |
| `report_markdown` | full educational report |

Raises `AuthorizationError` (bad/expired token) or `CVEFetchError`
(CVE not found).

## `aera.BatchRunner(aera, *, max_concurrency=3, output_dir="batch-out")`

### `await runner.run(cve_ids, user_token, *, vuln_types=None)`

Processes many CVEs with a concurrency cap. Checkpointed:
`output_dir/checkpoint.json` records finished IDs so reruns skip them.
Writes `<CVE>.md` and `<CVE>.json` per CVE. Returns a list of
`{"cve_id", "ok", "result" | "error"}`.

## `aera.authorization.AuthorizationManager`

- `generate_token(user_id, domain, hours=24) -> str`
- `validate(token) -> dict` -- raises `AuthorizationError` on any problem.

## `aera.sandbox.SandboxManager`

- `test_poc(vuln_type, poc_script, *, actor="unknown") -> dict`
- `describe_lab(vuln_type) -> dict` -- image + runtime fingerprint.
- `isolated_environment(vuln_type)` -- context manager; network disabled,
  resource-limited, always cleaned up.

## `aera.intel`

- `get_epss(cve_id) -> dict | None`
- `KEVCatalog(cache_path=None, max_age_hours=24)` -- `.lookup(cve_id)`
- `enrich(cve_id, *, kev=None) -> {"epss", "kev"}` -- never raises.

## `aera.patterns`

- `summarize(results) -> dict` -- severity/CWE/vendor/KEV/EPSS aggregates.
- `render_html_dashboard(summary, results, out_path) -> Path`

## `aera.llm`

- `LLMProvider` -- subclass and implement `complete(system_prompt, user_prompt)`.
- `OpenAICompatibleProvider(api_key=None, base_url=None, model=None, timeout_s=300)`

## CLI

```
aera token --user U --domain D [--hours H]
aera analyze CVE-ID --token T [--vuln-type web|binary|network] [--out PATH]
aera batch cves.txt --token T [--out DIR] [--concurrency N]
aera dashboard DIR
```

See `docs/SETUP_GUIDE.md` for the full walkthrough.
