# Remove the backticks
from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Iterable

DIM = 384  # default embedding size

_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-.:/#]+")


def _tokens(text: str) -> Iterable[str]:
    for tok in _TOKEN_RE.findall(text.lower()):
        if tok:
            yield tok


def feature_hash_embed(texts: list[str], dim: int = DIM) -> list[list[float]]:
    """
    Deterministic, dependency-free "embedding" using feature hashing.
    Not SOTA, but good enough for wiring + tests. Returns L2-normalized vectors.
    """
    vecs: list[list[float]] = []
    for t in texts:
        v = [0.0] * dim
        for tok in _tokens(t):
            # two independent hash buckets for a touch of dispersion
            h1 = int(hashlib.md5(tok.encode("utf-8")).hexdigest(), 16)
            h2 = int(hashlib.sha1(tok.encode("utf-8")).hexdigest(), 16)
            i1 = h1 % dim
            i2 = h2 % dim
            # signed increments
            v[i1] += 1.0 if (h1 & 1) else -1.0
            v[i2] += 1.0 if (h2 & 1) else -1.0
        # L2 normalize
        norm = math.sqrt(sum(x * x for x in v)) or 1.0
        v = [x / norm for x in v]
        vecs.append(v)
    return vecs


def embed_query(text: str, dim: int = DIM) -> list[float]:
    return feature_hash_embed([text], dim=dim)[0]


def embed_chunks(chunks: list[str], dim: int = DIM) -> list[list[float]]:
    return feature_hash_embed(chunks, dim=dim)
