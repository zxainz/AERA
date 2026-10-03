"""CVE data fetching (NVD API, public -- 5 req / 30s without an API key)."""
from __future__ import annotations

import os
import time

import requests

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Memory-corruption / binary-exploitation weakness types.
BINARY_CWES = {
    "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-126",
    "CWE-127", "CWE-787", "CWE-788", "CWE-789", "CWE-190", "CWE-191",
    "CWE-193", "CWE-415", "CWE-416", "CWE-401", "CWE-476", "CWE-704",
    "CWE-843",
}


class CVEFetchError(Exception):
    """Raised when CVE details cannot be retrieved."""


def detect_vuln_type(cve: dict) -> str:
    """Infer the lab environment class from the CVE's CWEs.

    Returns "binary" for memory-corruption flaws, otherwise "web".
    ("network" stays a manual choice -- it overlaps too much with "web"
    to infer reliably.)
    """
    if set(cve.get("cwes", [])) & BINARY_CWES:
        return "binary"
    return "web"


def get_cve_details(cve_id: str, *, retries: int = 3) -> dict:
    """Return a normalized CVE record: id, description, CVSS, CWE, references."""
    headers: dict[str, str] = {}
    nvd_key = os.environ.get("AERA_NVD_API_KEY")
    if nvd_key:
        headers["apiKey"] = nvd_key  # raises the NVD rate limit substantially
    last_exc: Exception | None = None
    for attempt in range(retries):
        try:
            resp = requests.get(
                NVD_BASE,
                params={"cveId": cve_id.strip().upper()},
                headers=headers,
                timeout=30,
            )
            resp.raise_for_status()
            vulns = resp.json().get("vulnerabilities", [])
            if not vulns:
                raise CVEFetchError(f"{cve_id}: no record found in NVD.")
            cve = vulns[0]["cve"]
            descriptions = {
                d["lang"]: d["value"] for d in cve.get("descriptions", [])
            }
            metrics = cve.get("metrics", {})
            cvss31 = (metrics.get("cvssMetricV31") or [{}])[0].get("cvssData", {})
            weaknesses = [
                w["description"][0]["value"]
                for w in cve.get("weaknesses", [])
                if w.get("description")
            ]
            cpes: list[str] = []
            for config in cve.get("configurations", []):
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        criteria = match.get("criteria")
                        if criteria:
                            cpes.append(criteria)
            return {
                "id": cve["id"],
                "description": descriptions.get("en", ""),
                "cvss_v3": {
                    "score": cvss31.get("baseScore"),
                    "severity": cvss31.get("baseSeverity"),
                    "vector": cvss31.get("vectorString"),
                },
                "cwes": weaknesses,
                "cpes": cpes[:20],
                "references": [r["url"] for r in cve.get("references", [])][:10],
                "published": cve.get("published"),
            }
        except (requests.RequestException, CVEFetchError) as exc:
            last_exc = exc
            time.sleep(7 * (attempt + 1))  # respect NVD rate limits
    raise CVEFetchError(f"Failed to fetch {cve_id}: {last_exc}")
