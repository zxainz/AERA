"""Recon: turn discovered versions into candidate CVEs.

A pentester's recon ends with a version inventory (nmap XML, or a plain
"product version" list). This module maps each version to candidate CVEs via
the NVD keyword search, scores them by version-match evidence, and writes a
`cves.txt` ready for `aera batch`.

Public data only (NVD API); no scanning is performed by this module.
"""
from __future__ import annotations

import os
import re
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import requests

from .utils import NVD_BASE

RESULTS_PER_PRODUCT = 20


def parse_nmap_xml(path: str | os.PathLike) -> list[dict]:
    """Extract {host, port, protocol, service, product, version} from nmap XML."""
    services: list[dict] = []
    tree = ET.parse(str(path))
    for host in tree.getroot().iter("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        host_id = (
            addr_el.get("addr")
            if addr_el is not None
            else (host.find("hostname").get("name") if host.find("hostname") is not None else "unknown")
        )
        for port in host.iter("port"):
            state = port.find("state")
            if state is not None and state.get("state") != "open":
                continue
            svc = port.find("service")
            if svc is None:
                continue
            services.append({
                "host": host_id,
                "port": port.get("portid"),
                "protocol": port.get("protocol"),
                "service": svc.get("name"),
                "product": (svc.get("product") or "").strip(),
                "version": (svc.get("version") or "").strip(),
            })
    return services


_VERSION_LINE = re.compile(
    r"^\s*(?P<product>[A-Za-z0-9][\w .+()/-]*?)\s*[:=]{1,2}\s*(?P<version>[\w.+-]+)\s*$"
)
_BARE_LINE = re.compile(
    r"^\s*(?P<product>[A-Za-z0-9][\w .+()/-]*?)\s+(?P<version>\d[\w.+-]*)\s*$"
)


def parse_version_list(text: str) -> list[dict]:
    """Parse lines like 'nginx 1.18.0', 'apache:2.4.49', 'openssl==1.1.1k'."""
    services: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _VERSION_LINE.match(line) or _BARE_LINE.match(line)
        if m:
            services.append({
                "host": "target",
                "port": "",
                "protocol": "",
                "service": m.group("product").strip().lower().split()[0],
                "product": m.group("product").strip(),
                "version": m.group("version").strip(),
            })
    return services


def _nvd_headers() -> dict[str, str]:
    headers: dict[str, str] = {}
    key = os.environ.get("AERA_NVD_API_KEY")
    if key:
        headers["apiKey"] = key
    return headers


def _nvd_search(query: str, max_results: int) -> list[dict]:
    """One NVD keyword search; returns raw vulnerability entries."""
    resp = requests.get(
        NVD_BASE,
        params={"keywordSearch": query, "resultsPerPage": max_results},
        headers=_nvd_headers(),
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json().get("vulnerabilities", [])


def candidate_cves(product: str, version: str, *,
                   max_results: int = RESULTS_PER_PRODUCT) -> list[dict]:
    """Query NVD for CVEs mentioning product+version; score by evidence.

    NVD keyword search is phrase-strict, so fall back from the full
    "product version" query to shorter ones ("Apache 2.4.49", then the
    product alone) until something matches.

    Scoring: +2 if the exact version appears in the description, +1 if the
    product does. Results are advisory candidates for `aera batch` triage.
    """
    if not product:
        return []
    tokens = product.split()
    queries = [f"{product} {version}".strip()]
    if len(tokens) > 1 and version:
        queries.append(f"{tokens[0]} {version}".strip())
    queries.append(product)
    vulns: list[dict] = []
    try:
        for q in queries:
            vulns = _nvd_search(q, max_results)
            if vulns:
                break
    except requests.RequestException:
        return []
    # Respect NVD rate limits: 5 req/30s without a key.
    time.sleep(0.7 if os.environ.get("AERA_NVD_API_KEY") else 7)

    scored: list[dict] = []
    for v in vulns:
        cve = v.get("cve", {})
        cve_id = cve.get("id", "")
        descs = {d.get("lang"): d.get("value", "") for d in cve.get("descriptions", [])}
        desc = descs.get("en", "")
        score = 0
        if version and version in desc:
            score += 2
        if product.lower() in desc.lower() or tokens[0].lower() in desc.lower():
            score += 1
        scored.append({
            "cve_id": cve_id,
            "score": score,
            "description": desc[:220],
            "published": cve.get("published", ""),
        })
    scored.sort(key=lambda r: (-r["score"], r["published"]))
    return scored


def run_recon(services: list[dict]) -> list[dict]:
    """Map every versioned service to candidate CVEs."""
    results: list[dict] = []
    for svc in services:
        product, version = svc.get("product", ""), svc.get("version", "")
        cands = candidate_cves(product, version) if product else []
        results.append({**svc, "candidate_cves": cands})
    return results


def write_recon_outputs(results: list[dict], out_dir: str | os.PathLike) -> dict:
    """Write recon.json (full detail) and cves.txt (deduped IDs for batch)."""
    import json

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "recon.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    seen: list[str] = []
    for r in results:
        for c in r["candidate_cves"]:
            if c["score"] > 0 and c["cve_id"] not in seen:
                seen.append(c["cve_id"])
    (out / "cves.txt").write_text("\n".join(seen) + ("\n" if seen else ""),
                                  encoding="utf-8")
    return {"recon_json": str(out / "recon.json"),
            "cves_txt": str(out / "cves.txt"),
            "cve_count": len(seen)}
