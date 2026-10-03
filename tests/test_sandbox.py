"""Sandbox tests. Skipped automatically when Docker is unavailable."""
import pytest

docker = pytest.importorskip("docker")


def _docker_available() -> bool:
    try:
        docker.from_env().ping()
        return True
    except Exception:  # noqa: BLE001
        return False


requires_docker = pytest.mark.skipif(
    not _docker_available(), reason="Docker daemon not available"
)


@requires_docker
def test_poc_runs_isolated_and_cleans_up():
    from aera.sandbox import SandboxManager

    mgr = SandboxManager(templates={"binary": "alpine:3.20"})
    before = {c.id for c in mgr.client.containers.list(all=True)}
    result = mgr.test_poc("binary", 'print("VULNERABLE: marker-123")')
    assert "marker-123" in result["stdout"]
    after = {c.id for c in mgr.client.containers.list(all=True)}
    assert before == after, "sandbox container was not cleaned up"


@requires_docker
def test_no_network_inside_sandbox():
    from aera.sandbox import SandboxManager

    mgr = SandboxManager(templates={"binary": "alpine:3.20"})
    result = mgr.test_poc(
        "binary",
        "import socket\n"
        "s = socket.create_connection(('8.8.8.8', 53), timeout=5)\n"
        "print('NETWORK REACHABLE')",
    )
    assert "NETWORK REACHABLE" not in result["stdout"]
    assert result["exit_code"] != 0
