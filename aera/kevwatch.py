"""KEV watch: alert when a newly-exploited CVE hits YOUR client's stack.

You fingerprinted the client's versions once during the engagement. This
watches the CISA KEV JSON feed and reports only entries that are (a) new
since the last check and (b) match the stack -- by product/vendor name or
by CVE ID. Built for retainer clients: run it on a schedule, get pinged
only when something relevant becomes actively exploited.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import requests

KEV_JSON_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


class KEVWatchError(Exception):
    """Raised when the KEV feed cannot be fetched."""


def fetch_kev_feed(*, timeout_s: int = 60) -> list[dict]:
    """Return the raw KEV vulnerability entries."""
    try:
        resp = requests.get(KEV_JSON_URL, timeout=timeout_s)
        resp.raise_for_status()
        return resp.json().get("vulnerabilities", [])
    except requests.RequestException as exc:
        raise KEVWatchError(f"Could not fetch KEV feed: {exc}") from exc


def load_stack(path: str | os.PathLike) -> dict:
    """Stack file: {"products": [{"vendor","product","version"}], "cves": [...]}."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {
        "products": [
            {"vendor": str(p.get("vendor", "")).lower(),
             "product": str(p.get("product", "")).lower(),
             "version": str(p.get("version", ""))}
            for p in data.get("products", [])
        ],
        "cves": {c.strip().upper() for c in data.get("cves", [])},
    }


def load_state(path: str | os.PathLike) -> dict:
    p = Path(path)
    if not p.exists():
        return {"last_check": None, "seen": []}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"last_check": None, "seen": []}


def save_state(path: str | os.PathLike, state: dict) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(state, indent=2), encoding="utf-8")


def _matches(entry: dict, stack: dict) -> str | None:
    """Return a match reason, or None if the entry doesn't hit the stack."""
    cve_id = (entry.get("cveID") or "").strip().upper()
    if cve_id in stack["cves"]:
        return f"CVE {cve_id} is in your tracked list"
    vendor = (entry.get("vendorProject") or "").lower()
    product = (entry.get("product") or "").lower()
    for p in stack["products"]:
        if p["product"] and p["product"] in product:
            return (f"product match: {entry.get('product')} "
                    f"(stack: {p['product']} {p['version']})".strip())
        if p["vendor"] and p["vendor"] in vendor:
            return f"vendor match: {entry.get('vendorProject')}"
    return None


def check_kev(stack_path: str | os.PathLike,
              state_path: str | os.PathLike) -> dict:
    """One watch cycle. Returns {"alerts": [...], "new_total": N}."""
    stack = load_stack(stack_path)
    state = load_state(state_path)
    seen = set(state.get("seen", []))
    feed = fetch_kev_feed()
    alerts: list[dict] = []
    for entry in feed:
        cve_id = (entry.get("cveID") or "").strip().upper()
        if not cve_id or cve_id in seen:
            continue
        seen.add(cve_id)
        reason = _matches(entry, stack)
        if reason:
            alerts.append({
                "cve_id": cve_id,
                "name": entry.get("vulnerabilityName", ""),
                "vendor": entry.get("vendorProject", ""),
                "product": entry.get("product", ""),
                "date_added": entry.get("dateAdded", ""),
                "due_date": entry.get("dueDate", ""),
                "required_action": entry.get("requiredAction", ""),
                "match_reason": reason,
            })
    state["seen"] = sorted(seen)
    state["last_check"] = datetime.now(timezone.utc).isoformat()
    save_state(state_path, state)
    return {"alerts": alerts, "feed_total": len(feed)}
