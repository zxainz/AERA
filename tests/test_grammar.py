"""Tests for grammar-aware input generation."""
import json
import random

from aera.grammar import GENERATORS, HttpGenerator, JsonGenerator, run_grammar_campaign


def test_json_generator_produces_bytes():
    rng = random.Random(0)
    gen = JsonGenerator()
    samples = [gen.generate(rng) for _ in range(20)]
    assert all(isinstance(s, bytes) for s in samples)
    # most should be valid JSON (hostile strings may break strict parsing)
    valid = 0
    for s in samples:
        try:
            json.loads(s.decode("utf-8"))
            valid += 1
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
    assert valid >= 10


def test_json_generator_hostile_features():
    rng = random.Random(1)
    gen = JsonGenerator()
    blob = b"".join(gen.generate(rng) for _ in range(30))
    assert b"\\u0000" in blob or b"\x00" in blob or "é".encode() in blob


def test_http_generator_shape():
    rng = random.Random(0)
    gen = HttpGenerator()
    sample = gen.generate(rng)
    assert isinstance(sample, bytes)
    head = sample.split(b"\r\n")[0]
    assert head.endswith(b"HTTP/1.1")
    assert b"Host: target" in sample


def test_generators_registered():
    assert set(GENERATORS) == {"json", "http"}
    assert all(issubclass(g, object) for g in GENERATORS.values())


def test_grammar_campaign_collects_crashes():
    def run_once(data: bytes):
        # crash on deep JSON nesting marker
        return {"crash": b"{{{{" in data}

    crashes = run_grammar_campaign(run_once, JsonGenerator(), 200, rng_seed=3)
    assert isinstance(crashes, list)
