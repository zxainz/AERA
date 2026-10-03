"""Grammar-aware input generation for structured formats.

Blind mutation wastes most runs on inputs that die in the parser.
These generators produce *mostly-valid* structured inputs with hostile
features (deep nesting, huge values, weird strings, smuggled syntax),
so runs reach the interesting code past the parser.
"""
from __future__ import annotations

import json
import random
from abc import ABC, abstractmethod


class Generator(ABC):
    @abstractmethod
    def generate(self, rng: random.Random) -> bytes:
        """Produce one input."""


class JsonGenerator(Generator):
    """Random JSON: nesting, big values, hostile strings, unicode."""

    def generate(self, rng: random.Random) -> bytes:
        return json.dumps(self._value(rng, 0), ensure_ascii=False).encode("utf-8")

    def _key(self, rng: random.Random) -> str:
        return "".join(rng.choice("abAB09_-$") for _ in range(rng.randint(1, 12)))

    def _string(self, rng: random.Random) -> str:
        alphabet = ["A", "\x00", "é", "\\", '"', "\n", "\t", "../", "%s", "😀"]
        return "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 48)))

    def _value(self, rng: random.Random, depth: int):
        if depth > 4:
            return rng.choice([1, "x", None, True, 0])
        choice = rng.randrange(7)
        if choice == 0:
            return {self._key(rng): self._value(rng, depth + 1)
                    for _ in range(rng.randint(0, 5))}
        if choice == 1:
            return [self._value(rng, depth + 1) for _ in range(rng.randint(0, 8))]
        if choice == 2:
            return self._string(rng)
        if choice == 3:
            return rng.choice([0, -1, 2**62, -(2**62), 10**30])
        if choice == 4:
            return rng.choice([True, False, None])
        if choice == 5:
            return 1.5e300 * rng.choice([1, -1])
        return self._string(rng) * rng.randint(1, 4)


class HttpGenerator(Generator):
    """Random HTTP/1.1 requests: odd methods, long paths, header games."""

    METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH",
               "TRACE", "CONNECT", "FOO", "get", ""]

    def generate(self, rng: random.Random) -> bytes:
        method = rng.choice(self.METHODS)
        path_chars = "abcXYZ019/%2e%2f..;?=&%00"
        path = "/" + "".join(rng.choice(path_chars)
                             for _ in range(rng.randint(1, 64)))
        headers = "".join(
            f"X-Fuzz-{rng.randint(0, 99)}: {'A' * rng.randint(0, 200)}\r\n"
            for _ in range(rng.randint(0, 6))
        )
        if rng.randrange(4) == 0:
            headers += "Content-Length: -1\r\n"
        body = bytes(rng.randrange(256) for _ in range(rng.randint(0, 256)))
        head = (f"{method} {path} HTTP/1.1\r\n"
                f"Host: target\r\n{headers}\r\n").encode("latin-1")
        return head + body


GENERATORS: dict[str, type[Generator]] = {
    "json": JsonGenerator,
    "http": HttpGenerator,
}


def run_grammar_campaign(run_once, generator: Generator, iterations: int, *,
                         rng_seed: int = 0) -> list[dict]:
    """Feed grammar-generated inputs to run_once; return crashes."""
    rng = random.Random(rng_seed)
    crashes: list[dict] = []
    for _ in range(iterations):
        info = run_once(generator.generate(rng))
        if info.get("crash"):
            crashes.append(info)
    return crashes
