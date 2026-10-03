"""Isolated Docker sandbox for PoC testing.

Hard rules:
- Containers ALWAYS run with network_mode="none" (no external network).
- CPU and memory limits are always applied.
- Containers are always stopped and removed after a run (context manager).

The vulnerable-app images are configurable because every lab's images
differ (e.g. specific vulhub per-CVE images). Map them via
AERA_IMAGE_<TYPE> env vars or pass `templates` explicitly.
"""
from __future__ import annotations

import base64
import os
import re
import shlex
from contextlib import contextmanager
from datetime import datetime, timezone

# The runner script always ends with `echo EXIT:$?`, so the *real* PoC exit
# code is parsed out of stdout -- `exec_run` itself would always report 0.
_EXIT_RE = re.compile(r"^EXIT:(-?\d+)\s*$", re.M)


_NOT_VULN_RE = re.compile(
    r"(?:\bNOT[ _-]VULNERABLE\b|verdict\s*:\s*not[ _-]vulnerable|\*\*NOT[ _-]VULNERABLE\*\*|\[NOT[ _-]VULNERABLE\])",
    re.IGNORECASE,
)
_VULN_RE = re.compile(
    r"(?:\bVULNERABLE\s*:|\bVERDICT\s*:\s*VULNERABLE\b|\[VULNERABLE\]|\*\*VULNERABLE\*\*|\*\*VULNERABLE:\*\*)",
    re.IGNORECASE,
)


def parse_run_output(stdout: str) -> tuple[int, str, str]:
    """Return (exit_code, cleaned_stdout, verdict).

    verdict is one of "vulnerable", "not_vulnerable", "unknown", parsed from
    the PoC's own verdict line (robust to markdown bolding, casing, and prefixes).
    """
    match = _EXIT_RE.search(stdout)
    exit_code = int(match.group(1)) if match else -1
    cleaned = _EXIT_RE.sub("", stdout).strip()
    verdict = "unknown"
    if _NOT_VULN_RE.search(cleaned):
        verdict = "not_vulnerable"
    elif _VULN_RE.search(cleaned):
        verdict = "vulnerable"
    return exit_code, cleaned, verdict


class SandboxError(Exception):
    """Raised when the sandbox cannot run or a run is rejected."""


class SandboxManager:
    DEFAULT_TEMPLATES = {
        "web": "vulhub/struts2:2.3.15",   # example -- point at YOUR lab images
        "web_app": "vulhub/struts2:2.3.15", # PDF-compatible alias
        "binary": "alpine:3.20",
        "network": "alpine:3.20",
    }
    FALLBACK_IMAGE = "alpine:3.20"

    @staticmethod
    def _normalize_vuln_type(vuln_type: str) -> str:
        if vuln_type == "web_app":
            return "web"
        return vuln_type

    def __init__(
        self,
        *,
        templates: dict[str, str] | None = None,
        mem_limit: str = "512m",
        cpu_quota: int = 50_000,  # 50% of one CPU (cpu_period=100000)
        run_timeout_s: int = 120,
    ) -> None:
        try:
            import docker  # local import: sandbox is optional without docker
        except ImportError as exc:
            raise SandboxError(
                "The 'docker' package is not installed (pip install docker)."
            ) from exc
        self._docker = docker
        self.client = docker.from_env()
        merged = dict(self.DEFAULT_TEMPLATES)
        for key in merged:
            env_val = os.environ.get(f"AERA_IMAGE_{key.upper()}")
            if env_val:
                merged[key] = env_val
        if templates:
            merged.update(templates)
        self.templates = merged
        self.mem_limit = mem_limit
        self.cpu_quota = cpu_quota
        self.run_timeout_s = run_timeout_s

    @contextmanager
    def isolated_environment(self, vuln_type: str):
        """Yield a network-isolated container; always clean up afterwards."""
        norm_type = self._normalize_vuln_type(vuln_type)
        image = self.templates.get(norm_type, self.FALLBACK_IMAGE)
        container = self.client.containers.run(
            image,
            command="sleep 3600",
            detach=True,
            remove=False,
            network_mode="none",  # <-- no external network, ever
            mem_limit=self.mem_limit,
            cpu_period=100_000,
            cpu_quota=self.cpu_quota,
        )
        try:
            yield container
        finally:
            for action in (lambda: container.stop(timeout=5),
                           lambda: container.remove(force=True)):
                try:
                    action()
                except Exception:  # noqa: BLE001 - cleanup must not fail loudly
                    pass

    def describe_lab(self, vuln_type: str) -> dict:
        """Fingerprint the isolated lab environment a PoC would run in.

        Combines static image facts with runtime facts from a throwaway
        container. The container is destroyed afterwards, as always.
        """
        from .fingerprint import fingerprint_container, fingerprint_image

        norm_type = self._normalize_vuln_type(vuln_type)
        image = self.templates.get(norm_type, self.FALLBACK_IMAGE)
        try:
            info = fingerprint_image(self.client, image)
        except self._docker.errors.ImageNotFound:
            try:
                self.client.images.pull(image)
            except self._docker.errors.APIError as exc:
                raise SandboxError(
                    f"Lab image {image!r} not available locally and pull failed: {exc}"
                ) from exc
            info = fingerprint_image(self.client, image)
        with self.isolated_environment(norm_type) as container:
            info["runtime"] = fingerprint_container(container)
        return info

    def test_poc(self, vuln_type: str, poc_script: str, *, actor: str = "unknown") -> dict:
        """Run a PoC script inside the isolated container.

        The script is base64-encoded into the container to avoid shell
        quoting issues. Nothing leaves the container: no network, no mounts.
        Supports both Python and shell scripts with robust interpreter detection.
        """
        if not poc_script.strip():
            raise SandboxError("Empty PoC script refused.")
        norm_type = self._normalize_vuln_type(vuln_type)
        encoded = base64.b64encode(poc_script.encode("utf-8")).decode("ascii")
        is_shell = poc_script.strip().startswith(("#!/bin/sh", "#!/bin/bash"))
        target_file = "/tmp/poc.sh" if is_shell else "/tmp/poc.py"
        run_cmd = (
            f"sh {target_file}"
            if is_shell
            else f"(command -v python3 >/dev/null 2>&1 && python3 {target_file} || (command -v python >/dev/null 2>&1 && python {target_file} || (echo 'ERROR: python interpreter not found in container' >&2; exit 127)))"
        )
        runner = (
            f"echo " + shlex.quote(encoded) + f" | (base64 -d 2>/dev/null || base64 -D 2>/dev/null || cat >/dev/null) > {target_file} && "
            f"(command -v timeout >/dev/null 2>&1 && timeout {self.run_timeout_s} {run_cmd} || {run_cmd}); "
            f"echo EXIT:$?"
        )
        with self.isolated_environment(norm_type) as container:
            exec_result = container.exec_run(["sh", "-c", runner], demux=True)
            stdout, stderr = exec_result.output or (b"", b"")
            raw_stdout = (stdout or b"").decode("utf-8", errors="replace")
            exit_code, cleaned_stdout, verdict = parse_run_output(raw_stdout)
            return {
                "exit_code": exit_code,
                "stdout": cleaned_stdout,
                "stderr": (stderr or b"").decode("utf-8", errors="replace"),
                "verdict": verdict,
                "success": exit_code == 0,  # PDF backwards-compatibility
                "output": cleaned_stdout,   # PDF backwards-compatibility
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "container_id": container.short_id,
                "vuln_type": norm_type,
                "actor": actor,
            }

    def test_exploit(self, *args, **kwargs) -> dict:
        """Alias for PDF specification compatibility: test_exploit(container_or_vuln, code)."""
        if len(args) == 2 and isinstance(args[1], str):
            target = args[0] if isinstance(args[0], str) else "web"
            return self.test_poc(target, args[1], **kwargs)
        if len(args) == 1 and isinstance(args[0], str):
            return self.test_poc("web", args[0], **kwargs)
        return self.test_poc("web", "", **kwargs)
