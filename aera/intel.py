"""Threat-intel enrichment for AERA.

Two public, no-key sources:
- EPSS (https://api.first.org) -- probability a CVE gets exploited in the wild.
- CISA KEV catalog -- CVEs known to be actively exploited; cached locally.

Enrichment is ADVISORY and fail-open: if intel sources are unreachable, the
pipeline continues without them and the report notes the gap.
"""
from __future__ import annotations

import csv
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

EPSS_API = "https://api.first.org/data/v1/epss"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
)


class IntelError(Exception):
    """Raised when an intel source cannot be used."""


def get_epss(cve_id: str, *, timeout_s: int = 20) -> dict | None:
    """Return {'score', 'percentile', 'date'} or None if unavailable."""
    try:
        resp = requests.get(
            EPSS_API, params={"cve": cve_id.strip().upper()}, timeout=timeout_s
        )
        resp.raise_for_status()
        rows = resp.json().get("data", [])
        if not rows:
            return None
        row = rows[0]
        return {
            "score": float(row["epss"]),
            "percentile": float(row["percentile"]),
            "date": row.get("date"),
        }
    except (requests.RequestException, KeyError, ValueError, TypeError):
        return None


class KEVCatalog:
    """CISA Known Exploited Vulnerabilities catalog with a local CSV cache."""

    def __init__(
        self,
        *,
        cache_path: str | os.PathLike | None = None,
        max_age_hours: int = 24,
    ) -> None:
        self.cache_path = Path(
            cache_path or os.environ.get("AERA_KEV_CACHE", ".cache/kev.csv")
        )
        self.max_age = timedelta(hours=max_age_hours)
        self._index: dict[str, dict] | None = None

    def _is_fresh(self) -> bool:
        if not self.cache_path.exists():
            return False
        mtime = datetime.fromtimestamp(
            self.cache_path.stat().st_mtime, tz=timezone.utc
        )
        return datetime.now(timezone.utc) - mtime < self.max_age

    def refresh(self) -> None:
        resp = requests.get(KEV_URL, timeout=60)
        resp.raise_for_status()
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_bytes(resp.content)
        self._index = None

    def _load(self) -> dict[str, dict]:
        if self._index is None:
            if not self._is_fresh():
                self.refresh()  # may raise requests.RequestException
            index: dict[str, dict] = {}
            with self.cache_path.open(newline="", encoding="utf-8") as fh:
                for row in csv.DictReader(fh):
                    cve = (row.get("cveID") or "").strip().upper()
                    if cve:
                        index[cve] = row
            self._index = index
        return self._index

    def lookup(self, cve_id: str) -> dict | None:
        """Return the KEV row for a CVE, or None (also on source failure)."""
        try:
            return self._load().get(cve_id.strip().upper())
        except (requests.RequestException, OSError):
            return None

    def __len__(self) -> int:
        try:
            return len(self._load())
        except (requests.RequestException, OSError):
            return 0


def enrich(cve_id: str, *, kev: KEVCatalog | None = None) -> dict:
    """Return {'epss': ..., 'kev': ...}; each may be None. Never raises."""
    # NOTE: `is not None` on purpose -- KEVCatalog defines __len__, so a
    # catalog whose cache is unreachable would be falsy and `or` would
    # silently discard it.
    catalog = kev if kev is not None else KEVCatalog()
    return {
        "epss": get_epss(cve_id),
        "kev": catalog.lookup(cve_id),
    }
