"""Mutation-based input generation + crash-detecting execution.

This is a deliberately simple fuzzer: random mutations over seed inputs,
run against a target, with crashes detected via exit signals and
sanitizer/traceback keywords in stderr. It will find crashes in simple
buggy programs; it is not a coverage-guided fuzzer and makes no claim
to be one.

Execution backends:
- SandboxFuzzRunner: runs the target inside a network-isolated Docker
  container with the target directory mounted read-only. DEFAULT.
- LocalRunner: runs the target as a local subprocess. TESTS AND DEV ONLY.
"""
from __future__ import annotations

import base64
import random
import shlex
import subprocess
from pathlib import Path

from .sandbox import parse_run_output

# Inputs likely to trigger classic bug classes.
INTERESTING = [
    b"\x00", b"\xff", b"\x7f",
    b"A" * 128, b"A" * 4096,
    b"%s%p%x%n",
    b"../" * 16,
    b"\n" * 64,
    b"'" * 32, b'"' * 32,
    b"0", b"-1", b"9999999999999999999",
]

CRASH_KEYWORDS = (
    "traceback",
    "addresssanitizer",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "stack smashing",
    "segmentation fault",
    "use-after-free",
    "double free",
    "heap-use-after-free",
    "assertion",
)


def mutate(data: bytes, rng: random.Random) -> bytes:
    """Apply 1-3 random mutations to data."""
    if not data:
        data = b"seed"
    buf = bytearray(data)
    for _ in range(rng.randint(1, 3)):
        choice = rng.randrange(5)
        if choice == 0 and buf:
            buf[rng.randrange(len(buf))] = rng.randrange(256)
        elif choice == 1 and len(buf) > 1:
            i, j = rng.randrange(len(buf)), rng.randrange(len(buf))
            buf[i], buf[j] = buf[j], buf[i]
        elif choice == 2:
            i = rng.randrange(len(buf) + 1)
            buf[i:i] = rng.choice(INTERESTING)
        elif choice == 3 and buf:
            i = rng.randrange(len(buf))
            del buf[i:i + rng.randint(1, 8)]
        else:
            i = rng.randrange(len(buf) + 1)
            buf[i:i] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 16)))
    return bytes(buf)


def seeds_for_findings(findings: list[dict]) -> list[bytes]:
    """Turn static findings into targeted seed inputs."""
    seeds: list[bytes] = [b"hello", b"", b"A" * 16]
    for f in findings:
        rid = f.get("rule_id", "")
        if rid.startswith("C-"):
            seeds.append(b"A" * 2000)          # overflow long input
            seeds.append(b"%s%p%x%n" * 64)      # format-string probe
        if rid in ("PY-EVAL", "PY-EXEC", "JS-EVAL"):
            seeds.append(b"__import__('os').system('id')")
        if rid in ("PY-OS-SYSTEM", "PY-SHELL-TRUE", "JS-EXEC", "C-SYSTEM", "C-POPEN"):
            seeds.append(b";id;")
            seeds.append(b"$(id)")
    # dedupe, preserve order
    seen, unique = set(), []
    for s in seeds:
        if s not in seen:
            seen.add(s)
            unique.append(s)
    return unique


def classify_result(exit_code: int, stdout: str, stderr: str, data: bytes) -> dict:
    """Decide whether a run crashed. Signals and sanitizer/traceback
    keywords count; plain nonzero exits do not (usually input validation)."""
    signal = None
    if exit_code < 0:
        signal = -exit_code
    elif exit_code > 128 and exit_code != 124:
        signal = exit_code - 128  # shell convention: 128 + signal
    timed_out = exit_code == 124  # `timeout` kill
    haystack = (stderr + "\n" + stdout).lower()
    keyword = next((k for k in CRASH_KEYWORDS if k in haystack), None)
    is_crash = signal is not None or keyword is not None
    return {
        "input": data,
        "exit_code": exit_code,
        "signal": signal,
        "timed_out": timed_out,
        "crash": is_crash,
        "keyword": keyword,
        "stderr": stderr[:2000],
        "stdout": stdout[:500],
    }


class LocalRunner:
    """Runs the target as a local subprocess. TESTS AND DEV ONLY.

    argv may contain "{input}" (replaced with a temp input path);
    otherwise input goes to stdin.
    """

    def __init__(self, argv: list[str], *, timeout_s: int = 5,
                 cwd: str | Path | None = None) -> None:
        self.argv = list(argv)
        self.timeout_s = timeout_s
        self.cwd = str(cwd) if cwd else None

    def run_once(self, data: bytes) -> dict:
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        try:
            args = [a.replace("{input}", tmp_path) for a in self.argv]
            use_stdin = not any("{input}" in a for a in self.argv)
            proc = subprocess.run(
                args,
                input=data if use_stdin else None,
                capture_output=True,
                timeout=self.timeout_s,
                cwd=self.cwd,
            )
            code = proc.returncode
            stdout = proc.stdout.decode("utf-8", errors="replace")
            stderr = proc.stderr.decode("utf-8", errors="replace")
        except subprocess.TimeoutExpired as exc:
            code, stdout, stderr = 124,
            (exc.stdout or b"").decode("utf-8", errors="replace"),
            (exc.stderr or b"").decode("utf-8", errors="replace")
        finally:
            Path(tmp_path).unlink(missing_ok=True)
        return classify_result(code, stdout, stderr, data)


class SandboxFuzzRunner:
    """Runs the target inside a network-isolated Docker container.

    The target directory is mounted read-only at /target. One container
    lives for the whole campaign (use as a context manager).
    """

    def __init__(self, sandbox, *, image: str, target_dir: str | Path,
                 argv: list[str], timeout_s: int = 5) -> None:
        self.sandbox = sandbox
        self.image = image
        self.target_dir = str(Path(target_dir).resolve())
        self.argv = list(argv)
        self.timeout_s = timeout_s
        self.container = None

    def __enter__(self) -> "SandboxFuzzRunner":
        self.container = self.sandbox.client.containers.run(
            self.image,
            command="sleep 3600",
            detach=True,
            remove=False,
            network_mode="none",
            mem_limit=self.sandbox.mem_limit,
            cpu_period=100_000,
            cpu_quota=self.sandbox.cpu_quota,
            volumes={self.target_dir: {"bind": "/target", "mode": "ro"}},
        )
        return self

    def __exit__(self, *exc_info) -> None:
        container, self.container = self.container, None
        if container is None:
            return
        for action in (lambda: container.stop(timeout=5),
                       lambda: container.remove(force=True)):
            try:
                action()
            except Exception:  # noqa: BLE001 - cleanup must not fail loudly
                pass

    def run_once(self, data: bytes) -> dict:
        encoded = base64.b64encode(data).decode("ascii")
        args = [a.replace("{input}", "/tmp/in.bin") for a in self.argv]
        redir = ""
        if not any("{input}" in a for a in self.argv):
            redir = " < /tmp/in.bin"
        cmd = (
            "echo " + shlex.quote(encoded) + " | base64 -d > /tmp/in.bin"
            f" && cd /target && timeout {self.timeout_s} "
            + " ".join(shlex.quote(a) for a in args)
            + redir + "; echo EXIT:$?"
        )
        result = self.container.exec_run(["sh", "-c", cmd], demux=True)
        stdout, stderr = result.output or (b"", b"")
        raw = (stdout or b"").decode("utf-8", errors="replace")
        code, cleaned, _ = parse_run_output(raw)
        err = (stderr or b"").decode("utf-8", errors="replace")
        return classify_result(code, cleaned, err, data)


def run_campaign(run_once, seeds: list[bytes], iterations: int,
                 *, rng_seed: int = 0) -> list[dict]:
    """Mutate seeds for `iterations` runs; return the crashes found."""
    rng = random.Random(rng_seed)
    crashes: list[dict] = []
    corpus = list(seeds) or [b"seed"]
    for i in range(iterations):
        data = mutate(corpus[i % len(corpus)], rng)
        info = run_once(data)
        if info["crash"]:
            crashes.append(info)
            if len(corpus) < 64:
                corpus.append(data)  # crashes become future mutation parents
    return crashes
