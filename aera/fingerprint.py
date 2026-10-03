"""Lab-environment fingerprinting.

Before drafting a PoC, AERA describes the isolated lab container it will run
in (OS, architecture, interpreters, exposed ports). This grounds the generated
PoC in the actual test environment instead of guessing.
"""
from __future__ import annotations


def fingerprint_image(client, image: str) -> dict:
    """Static facts from the Docker image config."""
    img = client.images.get(image)
    cfg = img.attrs.get("Config", {}) or {}
    return {
        "image": image,
        "os": img.attrs.get("Os"),
        "arch": img.attrs.get("Architecture"),
        "env": cfg.get("Env", []),
        "exposed_ports": list((cfg.get("ExposedPorts") or {}).keys()),
        "cmd": cfg.get("Cmd"),
        "working_dir": cfg.get("WorkingDir"),
    }


def fingerprint_container(container) -> dict:
    """Runtime facts from inside a running container."""

    def run(cmd: str) -> str:
        result = container.exec_run(["sh", "-c", cmd])
        out = result.output
        if isinstance(out, tuple):  # demux=True returns (stdout, stderr)
            out = b"\n".join(part or b"" for part in out)
        return (out or b"").decode("utf-8", errors="replace").strip()

    os_release = run("cat /etc/os-release 2>/dev/null | head -6")
    return {
        "kernel": run("uname -srm"),
        "os_release": os_release,
        "python": run("python3 --version 2>&1 || echo 'no python3'"),
        "user": run("whoami"),
        "shell": run("echo $0"),
        "tcp_listeners": run(
            "cat /proc/net/tcp 2>/dev/null | tail -n +2 | wc -l"
        ),
    }
