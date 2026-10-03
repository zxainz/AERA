"""Execution-verified findings: prove a static finding is really triggerable.

Static analysis lies -- every pentester knows it. For each HIGH/CRITICAL
Python finding, the LLM writes a minimal *trigger script* that imports the
actual vulnerable file (mounted read-only at /target in the sandbox) and
attempts to exercise the flaw. The script prints:

    TRIGGERED: <evidence>      -- the flaw demonstrably fires
    NOT TRIGGERED: <reason>    -- could not be triggered in isolation

Findings keep their static verdict but gain a `dynamic_verdict` field:
"confirmed" | "unproven" | "skipped". Only confirmed findings should be
treated as high-confidence.
"""
from __future__ import annotations

import base64
import os
import shlex
from pathlib import Path

TRIGGER_SYSTEM_PROMPT = """\
You are a defensive security research assistant. Write a minimal Python
trigger script that attempts to exercise a suspected vulnerability in a
target file, to confirm whether the static-analysis finding is real.

Rules:
- The target source tree is mounted READ-ONLY at /target inside an
  isolated container with no network. Import or read from /target/<path>.
- The vulnerable file path below is relative to /target.
- Attempt to trigger the flaw with clearly non-destructive inputs
  (e.g. harmless marker strings, arithmetic checks). No filesystem writes
  outside /tmp, no network, no subprocess of untrusted commands beyond
  what the target code itself does.
- End by printing EXACTLY one verdict line:
    TRIGGERED: <one-line evidence>
  or
    NOT TRIGGERED: <one-line reason>
- Keep it under 60 lines, clearly commented.
"""

PYTHON_TRIGGERABLE = {
    "PY-EVAL", "PY-EXEC", "PY-OS-SYSTEM", "PY-SHELL-TRUE",
    "PY-PICKLE", "PY-YAML-LOAD",
}


import re

_NOT_TRIGGERED_RE = re.compile(
    r"(?:\bNOT[ _-]TRIGGERED\b|verdict\s*:\s*not[ _-]triggered|\*\*NOT[ _-]TRIGGERED\*\*|\[NOT[ _-]TRIGGERED\])",
    re.IGNORECASE,
)
_TRIGGERED_RE = re.compile(
    r"(?:\bTRIGGERED\s*:|\bVERDICT\s*:\s*TRIGGERED\b|\[TRIGGERED\]|\*\*TRIGGERED\*\*|\*\*TRIGGERED:\*\*)",
    re.IGNORECASE,
)


def parse_trigger_verdict(stdout: str) -> str:
    """Map trigger-script output to triggered | not_triggered | unknown."""
    for line in stdout.splitlines():
        s = line.strip()
        if _NOT_TRIGGERED_RE.search(s):
            return "not_triggered"
        if _TRIGGERED_RE.search(s):
            return "triggered"
    return "unknown"


def _run_trigger(sandbox, image: str, target_dir: str,
                 script: str, actor: str) -> dict:
    """Run the trigger script with /target mounted read-only; parse output."""
    encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
    runner = (
        "echo " + shlex.quote(encoded) + " | base64 -d > /tmp/trigger.py"
        " && timeout 60 python3 /tmp/trigger.py; echo EXIT:$?"
    )
    container = sandbox.client.containers.run(
        image,
        command="sleep 600",
        detach=True,
        remove=False,
        network_mode="none",
        mem_limit=sandbox.mem_limit,
        cpu_period=100_000,
        cpu_quota=sandbox.cpu_quota,
        volumes={str(Path(target_dir).resolve()): {"bind": "/target", "mode": "ro"}},
    )
    try:
        exec_result = container.exec_run(["sh", "-c", runner], demux=True)
        stdout, stderr = exec_result.output or (b"", b"")
        out = (stdout or b"").decode("utf-8", errors="replace")
        err = (stderr or b"").decode("utf-8", errors="replace")
    finally:
        for action in (lambda: container.stop(timeout=5),
                       lambda: container.remove(force=True)):
            try:
                action()
            except Exception:  # noqa: BLE001 - cleanup must not fail loudly
                pass
    verdict = parse_trigger_verdict(out)
    # A crash also counts as evidence the code path is live.
    if verdict == "unknown" and "EXIT:" in out:
        try:
            code = int(out.split("EXIT:")[1].split()[0])
            if code not in (0,):
                verdict = "triggered"
        except (ValueError, IndexError):
            pass
    return {"verdict": verdict, "stdout": out[:3000], "stderr": err[:1500]}


def verify_findings(findings: list[dict], target_root: str | os.PathLike,
                    llm, sandbox, *, image: str | None = None,
                    max_verify: int = 5, actor: str = "unknown") -> list[dict]:
    """Attempt dynamic confirmation of top findings. Returns new finding dicts."""
    img = image or os.environ.get("AERA_IMAGE_PYTHON", "python:3.12-alpine")
    root = Path(target_root)
    ranked = {"CRITICAL": 0, "HIGH": 1}
    candidates = sorted(
        (f for f in findings if f.get("severity") in ranked),
        key=lambda f: ranked[f["severity"]],
    )[:max_verify]
    candidate_ids = {id(f) for f in candidates}

    verified: list[dict] = []
    for finding in findings:
        out = dict(finding)
        if id(finding) not in candidate_ids:
            out["dynamic_verdict"] = "skipped"
            out["dynamic_reason"] = "below verification threshold"
            verified.append(out)
            continue
        if finding.get("rule_id") not in PYTHON_TRIGGERABLE:
            out["dynamic_verdict"] = "skipped"
            out["dynamic_reason"] = (
                f"rule {finding.get('rule_id')} has no Python trigger template")
            verified.append(out)
            continue
        rel = finding.get("file", "")
        src = root / rel
        if not src.exists():
            out["dynamic_verdict"] = "skipped"
            out["dynamic_reason"] = "source file not found"
            verified.append(out)
            continue
        lines = src.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(0, finding.get("line", 1) - 16)
        end = min(len(lines), finding.get("line", 1) + 15)
        context = "\n".join(f"{i + 1:4d}: {lines[i]}" for i in range(start, end))
        prompt = (
            f"Finding: {finding['rule_id']} -- {finding['title']} "
            f"(severity {finding['severity']})\n"
            f"File: /target/{rel}, line {finding.get('line')}\n"
            f"Flagged snippet: {finding.get('snippet')}\n\n"
            f"Code context:\n{context}\n\n"
            "Write the trigger script now (Python code only, no explanation)."
        )
        try:
            script = llm.complete(TRIGGER_SYSTEM_PROMPT, prompt)
            # Strip markdown fences if the model wrapped the code.
            if "```" in script:
                parts = script.split("```")
                script = parts[1] if len(parts) > 1 else script
                script = script.removeprefix("python").strip()
            result = _run_trigger(sandbox, img, str(root), script, actor)
        except Exception as exc:  # noqa: BLE001 - verification is best-effort
            out["dynamic_verdict"] = "skipped"
            out["dynamic_reason"] = f"verification error: {exc}"
            verified.append(out)
            continue
        out["dynamic_verdict"] = (
            "confirmed" if result["verdict"] == "triggered" else "unproven"
        )
        out["dynamic_reason"] = result["stdout"].splitlines()[:3]
        out["trigger_stdout"] = result["stdout"][:1500]
        verified.append(out)
    return verified
